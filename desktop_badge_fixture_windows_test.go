package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unsafe"
)

// Explicit test executable mode. Uses a private pause record and only clicks its
// own overlay; never sends Escape or edits the foreground engineering app.
func runBadgeFixture(dir string) (result error) {
	defer func() {
		_ = os.WriteFile(filepath.Join(dir, "badge-result.txt"), []byte(fmt.Sprintf("result=%v\n", result)), 0600)
	}()
	windowsRoot = filepath.Join(dir, "badge-root")
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
		return fmt.Errorf("restore RDP before badge test")
	}
	original := struct{ X, Y int32 }{}
	desktopUser("GetCursorPos", uintptr(unsafe.Pointer(&original)))
	defer desktopUser("SetCursorPos", uintptr(original.X), uintptr(original.Y))
	if err := latchDesktopPause(desktopSession{ID: 2, LogonID: "fixture"}); err != nil {
		return err
	}
	pause, err := readDesktopPause()
	if err != nil || pause == nil {
		return fmt.Errorf("pause absent: %v", err)
	}
	defer clearDesktopPause(pause.ID)
	indicatorPauseID = pause.ID
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
	pump := func() {
		end := time.Now().Add(200 * time.Millisecond)
		for time.Now().Before(end) {
			interactionPump()
			time.Sleep(10 * time.Millisecond)
		}
	}
	pump()
	for hwnd, window := range indicatorWindows {
		var rect desktopRect
		desktopUser("GetClientRect", hwnd, uintptr(unsafe.Pointer(&rect)))
		b := indicatorBadge(rect, window.dpi, window.label)
		pt := struct{ X, Y int32 }{(b.Left + b.Right) / 2, (b.Top + b.Bottom) / 2}
		desktopUser("ClientToScreen", hwnd, uintptr(unsafe.Pointer(&pt)))
		desktopUser("SetCursor", desktopUser("LoadCursorW", 0, 32514)) // deliberately start with IDC_WAIT
		desktopUser("SetCursorPos", uintptr(pt.X), uintptr(pt.Y))
		pump()
		desktopUser("SendMessageW", hwnd, 0x20, hwnd, 1|(0x200<<16))
		if desktopUser("GetCursor") != desktopUser("LoadCursorW", 0, 32649) {
			return fmt.Errorf("paused badge did not select hand cursor")
		}
		// Verify pointer routing before generating any click.
		point := uintptr(uint64(uint32(pt.X)) | uint64(uint32(pt.Y))<<32)
		if desktopUser("WindowFromPoint", point) != hwnd {
			return fmt.Errorf("test badge is not at cursor; click withheld")
		}
		click := func(tag uintptr) error {
			for _, flag := range []uint32{2, 4} {
				i := desktopInput{}
				*(*desktopMouseInput)(unsafe.Pointer(&i.Data)) = desktopMouseInput{Flags: flag, Extra: tag}
				if desktopUser("SendInput", 1, uintptr(unsafe.Pointer(&i)), unsafe.Sizeof(i)) != 1 {
					return fmt.Errorf("test badge click failed")
				}
			}
			pump()
			return nil
		}
		if err = click(desktopInputTag); err != nil {
			return err
		}
		if p, _ := readDesktopPause(); p == nil {
			return fmt.Errorf("robot click cleared pause")
		}
		if err = click(0); err != nil {
			return err
		}
		if p, e := readDesktopPause(); p != nil || e != nil {
			return fmt.Errorf("local click did not clear pause: %v", e)
		}
		if window.label != "" || desktopUser("IsWindowVisible", hwnd) != 0 {
			return fmt.Errorf("clearing pause did not hide indicator")
		}
		indicatorSetLabel("AI viewing")
		pump()
		if desktopUser("IsWindowVisible", hwnd) == 0 {
			return fmt.Errorf("fresh activity did not restore indicator")
		}
		if desktopUser("GetForegroundWindow") != foreground {
			return fmt.Errorf("badge stole application focus")
		}
		break
	}
	return nil
}
