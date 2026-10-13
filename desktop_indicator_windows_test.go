package main

import (
	"bytes"
	"fmt"
	"image"
	"image/jpeg"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDesktopIndicatorLabels(t *testing.T) {
	for _, s := range []string{"AI viewing", "AI controlling", "AI idle", "AI thinking"} {
		if !indicatorLabelValid(s) {
			t.Fatal(s)
		}
	}
	for _, s := range []string{"", "<script>", "AI controlling\n", "operator-provided text"} {
		if indicatorLabelValid(s) {
			t.Fatal(s)
		}
	}
}

// Launched explicitly as the logged-on test user, never by the shipped service.
// It changes no application state and writes only into the supplied test folder.
func runIndicatorFixture(dir string) (result error) {
	defer func() {
		_ = os.WriteFile(filepath.Join(dir, "result.txt"), []byte(fmt.Sprintf("result=%v\n", result)), 0600)
	}()
	if p := desktopUser32.NewProc("SetProcessDpiAwarenessContext"); p.Find() == nil {
		p.Call(^uintptr(3))
	}
	bounds, w, h, err := desktopGeometry()
	if err != nil {
		return err
	}
	guard := desktopGuard{Bounds: bounds, Width: w, Height: h}
	capture := func(name string) (image.Image, error) {
		data, err := captureDesktopJPEG(guard)
		if err != nil {
			return nil, err
		}
		if err = os.WriteFile(filepath.Join(dir, name+".jpg"), data, 0600); err != nil {
			return nil, err
		}
		return jpeg.Decode(bytes.NewReader(data))
	}
	before, err := capture("before")
	if err != nil {
		return err
	}
	foreground := desktopUser("GetForegroundWindow")
	unregister, err := registerIndicatorClass()
	if err != nil {
		return err
	}
	defer unregister()
	defer destroyIndicatorWindows()
	monitors, err := getIndicatorMonitors()
	if err != nil {
		return err
	}
	if err = createIndicatorWindows(monitors, "AI viewing"); err != nil {
		return err
	}
	time.Sleep(100 * time.Millisecond)
	if desktopUser("GetForegroundWindow") != foreground {
		return fmt.Errorf("indicator stole focus")
	}
	excluded, err := capture("excluded")
	if err != nil {
		return err
	}
	for hwnd := range indicatorWindows {
		if desktopUser("IsWindowVisible", hwnd) == 0 {
			return fmt.Errorf("indicator is not visible")
		}
		if desktopUser("SetWindowDisplayAffinity", hwnd, 0) == 0 {
			return fmt.Errorf("cannot expose indicator for test preview")
		}
	}
	included, err := capture("preview")
	if err != nil {
		return err
	}
	// Compare beneath each badge and sample border pixels. Exclusion must reveal
	// the original app, not an opaque or blank rectangle. Small JPEG differences
	// are expected because the screenshot's quality may vary with total size.
	var total int64
	var samples int64
	var purple int
	for _, m := range monitors {
		sx, sy := float64(w)/float64(bounds.Width), float64(h)/float64(bounds.Height)
		right := int(float64(int(m.Rect.Right)-bounds.X) * sx)
		top := int(float64(int(m.Rect.Top)-bounds.Y) * sy)
		for y := top + 20; y < min(h, top+50); y++ {
			for x := max(0, right-235); x < right-20; x++ {
				a, b, c, _ := before.At(x, y).RGBA()
				d, e, f, _ := excluded.At(x, y).RGBA()
				abs := func(v int64) int64 {
					if v < 0 {
						return -v
					}
					return v
				}
				total += abs(int64(a>>8)-int64(d>>8)) + abs(int64(b>>8)-int64(e>>8)) + abs(int64(c>>8)-int64(f>>8))
				samples += 3
			}
		}
		for x := max(0, right-300); x < right-10; x++ {
			r, g, b, _ := included.At(x, top).RGBA()
			if r>>8 > 70 && r>>8 < 200 && g>>8 < 160 && b>>8 > 160 {
				purple++
			}
		}
	}
	if samples == 0 || float64(total)/float64(samples) > 4 {
		return fmt.Errorf("capture exclusion altered underlying pixels: average difference %.2f", float64(total)/float64(samples))
	}
	if purple < 100 {
		return fmt.Errorf("purple border not rendered in preview: %d pixels", purple)
	}
	if desktopUser("GetForegroundWindow") != foreground {
		return fmt.Errorf("indicator changed focus")
	}
	return nil
}
