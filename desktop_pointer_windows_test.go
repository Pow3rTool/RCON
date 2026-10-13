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
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestDesktopPointerWindowsLayoutAndMonitorBounds(t *testing.T) {
	if unsafe.Sizeof(indicatorMouseEvent{}) != 32 || unsafe.Offsetof(indicatorMouseEvent{}.Extra) != 24 {
		t.Fatal("MSLLHOOKSTRUCT layout")
	}
	now := time.Now()
	p := desktopPointerState{Point: desktopPointerPoint{-1800, 100, now}, Buttons: 1}
	w := indicatorWindow{dpi: 144, screen: desktopRect{-1920, 0, 0, 1080}}
	r := indicatorPointerBounds(p, &w, now)
	if r.Left != 75 || r.Top != 55 || r.Right != 243 || r.Bottom != 166 {
		t.Fatal("negative-origin / DPI bounds", r)
	}
	w.screen = desktopRect{0, 0, 1920, 1080}
	r = indicatorPointerBounds(p, &w, now)
	if r.Right > r.Left {
		t.Fatal("pointer painted on the wrong monitor", r)
	}
}

var pointerFixtureDowns, pointerFixtureUps int
var pointerFixtureProc = windows.NewCallback(func(hwnd, message, wparam, lparam uintptr) uintptr {
	switch message {
	case 0x21:
		return 3 // MA_NOACTIVATE: testing must not steal application focus
	case 0x201, 0x204, 0x207:
		pointerFixtureDowns++
		return 0
	case 0x202, 0x205, 0x208:
		pointerFixtureUps++
		return 0
	}
	return desktopUser("DefWindowProcW", hwnd, message, wparam, lparam)
})

// Only invoked explicitly. All clicks land on an inert test-owned canvas.
func runPointerFixture(dir string) (result error) {
	defer func() {
		_ = os.WriteFile(filepath.Join(dir, "pointer-result.txt"), []byte(fmt.Sprintf("result=%v\n", result)), 0600)
	}()
	windowsRoot = filepath.Join(dir, "pointer-root")
	for _, sub := range []string{"state", "logs"} {
		if err := os.MkdirAll(filepath.Join(windowsRoot, sub), 0700); err != nil {
			return err
		}
	}
	if p := desktopUser32.NewProc("SetProcessDpiAwarenessContext"); p.Find() == nil {
		p.Call(^uintptr(3))
	}
	foreground := desktopUser("GetForegroundWindow")
	if foreground == 0 {
		return fmt.Errorf("no rendered foreground desktop for pointer fixture")
	}
	if len(desktopPressed()) != 0 {
		return fmt.Errorf("release existing input before pointer fixture")
	}
	original := struct{ X, Y int32 }{}
	desktopUser("GetCursorPos", uintptr(unsafe.Pointer(&original)))
	defer desktopUser("SetCursorPos", uintptr(original.X), uintptr(original.Y))
	monitors, err := getIndicatorMonitors()
	if err != nil {
		return err
	}
	m := monitors[0].Work
	x, y := m.Left+80, m.Top+100
	class := windows.StringToUTF16("Pow3rTool.RCON.PointerFixture")
	background := desktopGDI("CreateSolidBrush", 0xdddddd)
	defer desktopGDI("DeleteObject", background)
	wc := struct {
		Size, Style                                                uint32
		Proc                                                       uintptr
		ClassExtra, WindowExtra                                    int32
		Instance, Icon, Cursor, Background, Menu, Class, SmallIcon uintptr
	}{Proc: pointerFixtureProc, Cursor: desktopUser("LoadCursorW", 0, 32512), Background: background, Class: uintptr(unsafe.Pointer(&class[0]))}
	wc.Size = uint32(unsafe.Sizeof(wc))
	if desktopUser("RegisterClassExW", uintptr(unsafe.Pointer(&wc))) == 0 {
		return fmt.Errorf("register fixture")
	}
	defer desktopUser("UnregisterClassW", uintptr(unsafe.Pointer(&class[0])), 0)
	title := windows.StringToUTF16("RCON pointer test canvas")
	hwnd := desktopUser("CreateWindowExW", 0x08000088, uintptr(unsafe.Pointer(&class[0])), uintptr(unsafe.Pointer(&title[0])), 0x90000000, uintptr(x), uintptr(y), 640, 400, 0, 0, 0, 0)
	if hwnd == 0 {
		return fmt.Errorf("create fixture")
	}
	defer desktopUser("DestroyWindow", hwnd)
	pump := func(ms int) {
		end := time.Now().Add(time.Duration(ms) * time.Millisecond)
		for time.Now().Before(end) {
			interactionPump()
			indicatorPointerTick()
			time.Sleep(5 * time.Millisecond)
		}
	}
	pump(100)
	bounds, width, height, err := desktopGeometry()
	if err != nil {
		return err
	}
	guard := desktopGuard{Bounds: bounds, Width: width, Height: height}
	capture := func(name string) (image.Image, error) {
		raw, e := captureDesktopJPEG(guard)
		if e != nil {
			return nil, e
		}
		if e = os.WriteFile(filepath.Join(dir, name+".jpg"), raw, 0600); e != nil {
			return nil, e
		}
		return jpeg.Decode(bytes.NewReader(raw))
	}
	baseline, err := capture("pointer-before")
	if err != nil {
		return err
	}
	unregister, err := registerIndicatorClass()
	if err != nil {
		return err
	}
	defer unregister()
	defer destroyIndicatorWindows()
	if err = createIndicatorWindows(monitors, "AI controlling"); err != nil {
		return err
	}
	pump(50)
	point := func(px, py int32) uintptr { return uintptr(uint64(uint32(px)) | uint64(uint32(py))<<32) }
	if desktopUser("WindowFromPoint", point(x+200, y+180)) != hwnd {
		return fmt.Errorf("fixture not under test coordinates; all clicks withheld")
	}
	imageXY := func(px, py int32) (int, int) {
		return int(px-int32(bounds.X)) * width / bounds.Width, int(py-int32(bounds.Y)) * height / bounds.Height
	}
	px, py := imageXY(x+200, y+180)
	// Untagged local movement must leave the visual model untouched.
	desktopUser("SetCursorPos", uintptr(x+160), uintptr(y+150))
	pump(50)
	if !indicatorPointerFrame.Point.At.IsZero() {
		return fmt.Errorf("human movement was labeled as AI")
	}
	if err = sendDesktopAction(desktopCommand{DesktopAction: DesktopAction{Action: "double_click", X: &px, Y: &py}}, guard); err != nil {
		return err
	}
	pump(60)
	if pointerFixtureDowns != 2 || pointerFixtureUps != 2 || indicatorPointerFrame.PulseCount != 2 || indicatorPointerFrame.Buttons != 0 {
		return fmt.Errorf("double-click did not pass through or was not visualized: down=%d up=%d pulses=%d", pointerFixtureDowns, pointerFixtureUps, indicatorPointerFrame.PulseCount)
	}
	defer desktopMouse(4, 0, 0, 0, true)
	if err = desktopMouse(2, 0, 0, 0, false); err != nil {
		return err
	}
	for i := 1; i <= 14; i++ {
		mx, my := imageXY(x+200+int32(i)*12, y+180+int32(i)*3)
		if err = desktopMove(mx, my, guard); err != nil {
			return err
		}
		pump(20)
	}
	if indicatorPointerFrame.Buttons != 1 || indicatorPointerFrame.TrailCount < 8 {
		return fmt.Errorf("held drag state/trail absent")
	}
	excluded, err := capture("pointer-excluded")
	if err != nil {
		return err
	}
	for handle := range indicatorWindows {
		desktopUser("SetWindowDisplayAffinity", handle, 0)
	}
	pump(30)
	included, err := capture("pointer-preview")
	if err != nil {
		return err
	}
	for handle := range indicatorWindows {
		desktopUser("SetWindowDisplayAffinity", handle, 0x11)
	}
	// Compare only the inert canvas interior, never clocks or animated app pixels.
	l, t := imageXY(x+100, y+80)
	r, b := imageXY(x+560, y+320)
	var clean, marked, samples int64
	abs := func(a int64) int64 {
		if a < 0 {
			return -a
		}
		return a
	}
	for iy := t; iy < b; iy++ {
		for ix := l; ix < r; ix++ {
			a, b, c, _ := baseline.At(ix, iy).RGBA()
			d, e, f, _ := excluded.At(ix, iy).RGBA()
			u, v, w, _ := included.At(ix, iy).RGBA()
			clean += abs(int64(a>>8)-int64(d>>8)) + abs(int64(b>>8)-int64(e>>8)) + abs(int64(c>>8)-int64(f>>8))
			marked += abs(int64(a>>8)-int64(u>>8)) + abs(int64(b>>8)-int64(v>>8)) + abs(int64(c>>8)-int64(w>>8))
			samples += 3
		}
	}
	if samples == 0 || float64(clean)/float64(samples) > 2 || marked < clean+10000 {
		return fmt.Errorf("pointer capture exclusion/preview failed: clean=%d marked=%d samples=%d", clean, marked, samples)
	}
	interactionIndicator("AI thinking")
	pump(2000)
	if !indicatorPointerFrame.visible(time.Now()) || indicatorPointerFrame.Buttons != 1 {
		return fmt.Errorf("held pointer faded during thinking")
	}
	if err = desktopMouse(4, 0, 0, 0, true); err != nil {
		return err
	}
	pump(50)
	if indicatorPointerFrame.Buttons != 0 {
		return fmt.Errorf("release marker stuck")
	}
	pump(1850)
	if indicatorPointerFrame.visible(time.Now()) {
		return fmt.Errorf("idle pointer did not expire")
	}
	if err = desktopMove(px, py, guard); err != nil {
		return err
	}
	pump(50)
	indicatorSetLabel(desktopPausedLabel)
	pump(50)
	if indicatorPointerFrame.visible(time.Now()) {
		return fmt.Errorf("paused pointer not cleared")
	}
	indicatorSetLabel("")
	pump(30)
	if desktopUser("GetForegroundWindow") != foreground {
		return fmt.Errorf("pointer fixture or overlay stole foreground")
	}
	return nil
}
