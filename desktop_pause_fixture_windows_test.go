package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

func runOutsideEscapeFixture(dir string) (result error) {
	defer func() {
		_ = os.WriteFile(filepath.Join(dir, "escape-result.txt"), []byte(fmt.Sprintf("result=%v\n", result)), 0600)
	}()
	if err := desktopDefault(); err != nil {
		return err
	}
	count := 3
	if b, e := os.ReadFile(filepath.Join(dir, "escape-count.txt")); e == nil {
		if n, e := strconv.Atoi(strings.TrimSpace(string(b))); e == nil && n >= 1 && n <= 3 {
			count = n
		}
	}
	var events []uint32
	for i := 0; i < count; i++ {
		events = append(events, 0, 2)
	}
	for _, flags := range events {
		i := desktopInput{Type: 1}
		*(*desktopKeyboardInput)(unsafe.Pointer(&i.Data)) = desktopKeyboardInput{VK: 27, Flags: flags}
		if desktopUser("SendInput", 1, uintptr(unsafe.Pointer(&i)), unsafe.Sizeof(i)) != 1 {
			return fmt.Errorf("outside Escape fixture SendInput failed")
		}
		time.Sleep(25 * time.Millisecond)
	}
	return nil
}

// Explicitly launched test fixture; never present in the shipped executable.
// The pause record lives in a private test root, and all input is released.
func runPauseFixture(dir string) (result error) {
	defer func() {
		_ = os.WriteFile(filepath.Join(dir, "pause-result.txt"), []byte(fmt.Sprintf("result=%v\n", result)), 0600)
	}()
	windowsRoot = filepath.Join(dir, "private-root")
	if err := os.MkdirAll(filepath.Join(windowsRoot, "state"), 0700); err != nil {
		return err
	}
	if p := desktopUser32.NewProc("SetProcessDpiAwarenessContext"); p.Find() == nil {
		p.Call(^uintptr(3))
	}
	if desktopUser("GetForegroundWindow") == 0 {
		return fmt.Errorf("restore the RDP display for fixture")
	}
	foreground := desktopUser("GetForegroundWindow")
	original := struct{ X, Y int32 }{}
	desktopUser("GetCursorPos", uintptr(unsafe.Pointer(&original)))
	rawKey := func(vk uint16, up bool, tag uintptr) error {
		i := desktopInput{Type: 1}
		k := (*desktopKeyboardInput)(unsafe.Pointer(&i.Data))
		*k = desktopKeyboardInput{VK: vk, Extra: tag}
		if up {
			k.Flags = 2
		}
		if desktopUser("SendInput", 1, uintptr(unsafe.Pointer(&i)), unsafe.Sizeof(i)) != 1 {
			return fmt.Errorf("fixture key injection failed")
		}
		return nil
	}
	rawMouse := func(flags uint32, tag uintptr) error {
		i := desktopInput{}
		*(*desktopMouseInput)(unsafe.Pointer(&i.Data)) = desktopMouseInput{Flags: flags, Extra: tag}
		if desktopUser("SendInput", 1, uintptr(unsafe.Pointer(&i)), unsafe.Sizeof(i)) != 1 {
			return fmt.Errorf("fixture mouse injection failed")
		}
		return nil
	}
	pump := func() {
		end := time.Now().Add(200 * time.Millisecond)
		for time.Now().Before(end) {
			interactionPump()
			time.Sleep(10 * time.Millisecond)
		}
	}
	interactionExternalInput.Store(false)
	stop, err := startInteractionMonitor()
	if err != nil {
		return err
	}
	defer stop()
	if err = rawKey(27, false, desktopInputTag); err != nil {
		return err
	}
	if err = rawKey(27, true, desktopInputTag); err != nil {
		return err
	}
	pump()
	if interactionExternalInput.Load() {
		return fmt.Errorf("marked robot Escape paused")
	}
	if err = rawKey(0x87, true, 0); err != nil {
		return err
	}
	if err = rawMouse(1, 0); err != nil {
		return err
	}
	pump()
	if interactionExternalInput.Load() {
		return fmt.Errorf("no-op input paused")
	}
	for tap := 0; tap < 3; tap++ {
		if err = rawKey(27, false, 0); err != nil {
			return err
		}
		if err = rawKey(27, true, 0); err != nil {
			return err
		}
		pump()
	}
	if !interactionExternalInput.Load() {
		return fmt.Errorf("outside Escape did not interrupt")
	}
	if err = latchDesktopPause(desktopSession{ID: 2, LogonID: "fixture"}); err != nil {
		return err
	}
	p, err := readDesktopPause()
	if err != nil || p == nil {
		return fmt.Errorf("pause absent: %v", err)
	}
	indicatorPauseID = p.ID
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
	if err = createIndicatorWindows(monitors, desktopPausedLabel); err != nil {
		return err
	}
	pump()
	if desktopUser("GetForegroundWindow") != foreground {
		return fmt.Errorf("paused badge stole focus")
	}
	bounds, w, h, err := desktopGeometry()
	if err != nil {
		return err
	}
	for hwnd := range indicatorWindows {
		desktopUser("SetWindowDisplayAffinity", hwnd, 0)
	}
	if b, err := captureDesktopJPEG(desktopGuard{Bounds: bounds, Width: w, Height: h}); err == nil {
		_ = os.WriteFile(filepath.Join(dir, "paused-preview.jpg"), b, 0600)
	} else {
		return err
	}
	for hwnd := range indicatorWindows {
		desktopUser("SetWindowDisplayAffinity", hwnd, 0x11)
	}
	defer desktopUser("SetCursorPos", uintptr(original.X), uintptr(original.Y))
	for hwnd, window := range indicatorWindows {
		var rect desktopRect
		desktopUser("GetClientRect", hwnd, uintptr(unsafe.Pointer(&rect)))
		badge := indicatorBadge(rect, window.dpi, window.label)
		pt := struct{ X, Y int32 }{(badge.Left + badge.Right) / 2, (badge.Top + badge.Bottom) / 2}
		desktopUser("ClientToScreen", hwnd, uintptr(unsafe.Pointer(&pt)))
		desktopUser("SetCursorPos", uintptr(pt.X), uintptr(pt.Y))
		pump()
		if err = rawMouse(2, desktopInputTag); err != nil {
			return err
		}
		if err = rawMouse(4, desktopInputTag); err != nil {
			return err
		}
		pump()
		if p, _ := readDesktopPause(); p == nil {
			return fmt.Errorf("robot click cleared pause")
		}
		if err = rawMouse(2, 0); err != nil {
			return err
		}
		if err = rawMouse(4, 0); err != nil {
			return err
		}
		pump()
		if p, err := readDesktopPause(); p != nil || err != nil {
			return fmt.Errorf("local badge click did not resume: %v", err)
		}
		if window.label != "" || desktopUser("IsWindowVisible", hwnd) != 0 {
			return fmt.Errorf("resume did not hide indicator")
		}
		break
	}
	if desktopUser("GetForegroundWindow") != foreground {
		return fmt.Errorf("resume click stole application focus")
	}
	return nil
}
