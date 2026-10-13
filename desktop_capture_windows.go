package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"math"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var desktopUser32 = windows.NewLazySystemDLL("user32.dll")
var desktopGDI32 = windows.NewLazySystemDLL("gdi32.dll")
var desktopDWM = windows.NewLazySystemDLL("dwmapi.dll")

//go:uintptrescapes
func desktopUser(name string, args ...uintptr) uintptr {
	r, _, _ := desktopUser32.NewProc(name).Call(args...)
	return r
}

//go:uintptrescapes
func desktopGDI(name string, args ...uintptr) uintptr {
	r, _, _ := desktopGDI32.NewProc(name).Call(args...)
	return r
}
func desktopDefault() error {
	h := desktopUser("OpenInputDesktop", 0, 0, 0x0001) // DESKTOP_READOBJECTS
	if h == 0 {
		return errors.New("input desktop unavailable; reconnect or unlock Windows")
	}
	defer desktopUser("CloseDesktop", h)
	var name [256]uint16
	var n uint32
	if desktopUser("GetUserObjectInformationW", h, 2, uintptr(unsafe.Pointer(&name[0])), uintptr(len(name)*2), uintptr(unsafe.Pointer(&n))) == 0 || windows.UTF16ToString(name[:]) != "Default" {
		return errors.New("locked or secure desktop; no capture or input")
	}
	return nil
}
func desktopMetric(n int) int { return int(int32(desktopUser("GetSystemMetrics", uintptr(n)))) }
func desktopGeometry() (desktopBounds, int, int, error) {
	b := desktopBounds{desktopMetric(76), desktopMetric(77), desktopMetric(78), desktopMetric(79)}
	if b.Width < 100 || b.Height < 100 || b.Width > 16000 || b.Height > 16000 || int64(b.Width)*int64(b.Height) > 16000000 {
		return b, 0, 0, errors.New("desktop geometry unavailable or too large")
	}
	scale := math.Min(1, 1600/float64(b.Width))
	scale = math.Min(scale, 2400/float64(b.Height))
	return b, int(math.Round(float64(b.Width) * scale)), int(math.Round(float64(b.Height) * scale)), nil
}
func desktopState(session desktopSession) (desktopGuard, error) {
	g := desktopGuard{SessionID: session.ID, LogonID: session.LogonID}
	if err := desktopDefault(); err != nil {
		return g, err
	}
	sessions, err := desktopSessions()
	if err != nil {
		return g, err
	}
	live, err := selectDesktopSession(sessions, session.ID)
	if err != nil || live.LogonID != session.LogonID {
		return g, errors.New("active logon session changed")
	}
	g.Bounds, g.Width, g.Height, err = desktopGeometry()
	if err != nil {
		return g, err
	}
	input := struct{ Size, Tick uint32 }{Size: 8}
	if desktopUser("GetLastInputInfo", uintptr(unsafe.Pointer(&input))) == 0 {
		return g, errors.New("last input unavailable")
	}
	g.InputTick = input.Tick
	g.Foreground = uint64(desktopUser("GetForegroundWindow"))
	if g.Foreground == 0 {
		return g, errors.New("no usable foreground desktop; restore the RDP display or use the local console")
	}
	return g, nil
}
func desktopPressed() []int {
	keys := []int{}
	for vk := 1; vk < 256; vk++ {
		if desktopUser("GetAsyncKeyState", uintptr(vk))&0x8000 != 0 {
			keys = append(keys, vk)
		}
	}
	return keys
}
func captureDesktopJPEG(g desktopGuard) ([]byte, error) {
	if flush := desktopDWM.NewProc("DwmFlush"); flush.Find() == nil {
		flush.Call()
	}
	screen := desktopUser("GetDC", 0)
	if screen == 0 {
		return nil, errors.New("screen DC unavailable")
	}
	defer desktopUser("ReleaseDC", 0, screen)
	dc := desktopGDI("CreateCompatibleDC", screen)
	if dc == 0 {
		return nil, errors.New("memory DC unavailable")
	}
	defer desktopGDI("DeleteDC", dc)
	// A DIB section exposes the captured pixels directly; it avoids converting
	// a device-dependent bitmap with GetDIBits (which varies by display driver).
	info := struct {
		Size                        uint32
		Width, Height               int32
		Planes, BitCount            uint16
		Compression, SizeImage      uint32
		XPels, YPels                int32
		ColorsUsed, ColorsImportant uint32
		Colors                      [1]uint32
	}{Size: 40, Width: int32(g.Bounds.Width), Height: -int32(g.Bounds.Height), Planes: 1, BitCount: 32}
	var bits unsafe.Pointer
	bmp, _, createErr := desktopGDI32.NewProc("CreateDIBSection").Call(screen, uintptr(unsafe.Pointer(&info)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if bmp == 0 || bits == nil {
		return nil, fmt.Errorf("screen DIB unavailable: %v", createErr)
	}
	defer desktopGDI("DeleteObject", bmp)
	old := desktopGDI("SelectObject", dc, bmp)
	if old == 0 || old == ^uintptr(0) {
		return nil, errors.New("cannot select capture bitmap")
	}
	defer desktopGDI("SelectObject", dc, old)
	success, _, captureErr := desktopGDI32.NewProc("BitBlt").Call(dc, 0, 0, uintptr(g.Bounds.Width), uintptr(g.Bounds.Height), screen, uintptr(g.Bounds.X), uintptr(g.Bounds.Y), 0x40CC0020)
	if success == 0 {
		return nil, fmt.Errorf("desktop capture failed: %v", captureErr)
	}
	desktopGDI("GdiFlush")
	pixels := unsafe.Slice((*byte)(bits), g.Bounds.Width*g.Bounds.Height*4)
	// Bilinear downsampling in Go keeps capture independent of GPU/driver
	// StretchBlt support (including RDP and hardware-accelerated desktops).
	rgba := image.NewRGBA(image.Rect(0, 0, g.Width, g.Height))
	for y := 0; y < g.Height; y++ {
		fy := (float64(y)+0.5)*float64(g.Bounds.Height)/float64(g.Height) - 0.5
		y0 := int(fy)
		y1 := min(y0+1, g.Bounds.Height-1)
		wy := fy - float64(y0)
		for x := 0; x < g.Width; x++ {
			fx := (float64(x)+0.5)*float64(g.Bounds.Width)/float64(g.Width) - 0.5
			x0 := int(fx)
			x1 := min(x0+1, g.Bounds.Width-1)
			wx := fx - float64(x0)
			dst := (y*g.Width + x) * 4
			for c := 0; c < 3; c++ {
				a := float64(pixels[(y0*g.Bounds.Width+x0)*4+2-c])*(1-wx) + float64(pixels[(y0*g.Bounds.Width+x1)*4+2-c])*wx
				b := float64(pixels[(y1*g.Bounds.Width+x0)*4+2-c])*(1-wx) + float64(pixels[(y1*g.Bounds.Width+x1)*4+2-c])*wx
				rgba.Pix[dst+c] = uint8(a*(1-wy) + b*wy + 0.5)
			}
			rgba.Pix[dst+3] = 255
		}
	}
	var out bytes.Buffer
	for _, quality := range []int{80, 65, 50, 35} {
		out.Reset()
		if err := jpeg.Encode(&out, rgba, &jpeg.Options{Quality: quality}); err != nil {
			return nil, err
		}
		if out.Len() <= 600000 {
			return out.Bytes(), nil
		}
	}
	return nil, errors.New("desktop image exceeds response limit")
}

type desktopRect struct{ Left, Top, Right, Bottom int32 }

func imageDesktopRect(r desktopRect, g desktopGuard) [4]int {
	sx := float64(g.Width) / float64(g.Bounds.Width)
	sy := float64(g.Height) / float64(g.Bounds.Height)
	return [4]int{int(math.Round((float64(r.Left) - float64(g.Bounds.X)) * sx)), int(math.Round((float64(r.Top) - float64(g.Bounds.Y)) * sy)), int(math.Round((float64(r.Right) - float64(g.Bounds.X)) * sx)), int(math.Round((float64(r.Bottom) - float64(g.Bounds.Y)) * sy))}
}
func desktopWindow(hwnd uintptr, g desktopGuard) map[string]any {
	var title [512]uint16
	var class [256]uint16
	var pid uint32
	var rect, client, visible desktopRect
	desktopUser("GetWindowTextW", hwnd, uintptr(unsafe.Pointer(&title[0])), uintptr(len(title)))
	desktopUser("GetClassNameW", hwnd, uintptr(unsafe.Pointer(&class[0])), uintptr(len(class)))
	desktopUser("GetWindowThreadProcessId", hwnd, uintptr(unsafe.Pointer(&pid)))
	desktopUser("GetWindowRect", hwnd, uintptr(unsafe.Pointer(&rect)))
	desktopUser("GetClientRect", hwnd, uintptr(unsafe.Pointer(&client)))
	desktopUser("MapWindowPoints", hwnd, 0, uintptr(unsafe.Pointer(&client)), 2)
	visible = rect
	if p := desktopDWM.NewProc("DwmGetWindowAttribute"); p.Find() == nil {
		p.Call(hwnd, 9, uintptr(unsafe.Pointer(&visible)), unsafe.Sizeof(visible))
	}
	dpi := uintptr(96)
	if p := desktopUser32.NewProc("GetDpiForWindow"); p.Find() == nil {
		dpi, _, _ = p.Call(hwnd)
	}
	return map[string]any{"hwnd": fmt.Sprintf("0x%x", hwnd), "pid": pid, "title": windows.UTF16ToString(title[:]), "class": windows.UTF16ToString(class[:]), "dpi": dpi, "minimized": desktopUser("IsIconic", hwnd) != 0, "maximized": desktopUser("IsZoomed", hwnd) != 0, "rect": imageDesktopRect(rect, g), "client_rect": imageDesktopRect(client, g), "visible_rect": imageDesktopRect(visible, g)}
}
func desktopWindows(g desktopGuard) []map[string]any {
	result := []map[string]any{}
	// GetTopWindow/GetWindow avoids allocating a new Go syscall callback on each capture.
	h := desktopUser("GetTopWindow", 0)
	for n := 0; h != 0 && n < 1000 && len(result) < 40; n++ {
		if desktopUser("IsWindowVisible", h) != 0 && desktopUser("GetWindowTextLengthW", h) > 0 {
			window := desktopWindow(h, g)
			if window["class"] != desktopIndicatorClass {
				result = append(result, window)
			}
		}
		h = desktopUser("GetWindow", h, 2)
	}
	return result
}
func desktopCursor(g desktopGuard) map[string]any {
	info := struct {
		Size, Flags uint32
		Handle      uintptr
		X, Y        int32
	}{}
	info.Size = uint32(unsafe.Sizeof(info))
	if desktopUser("GetCursorInfo", uintptr(unsafe.Pointer(&info))) == 0 {
		return map[string]any{"available": false}
	}
	shape := "custom_or_unknown"
	for id, name := range map[int]string{32512: "arrow", 32513: "ibeam", 32514: "wait", 32515: "cross", 32642: "size_nwse", 32643: "size_nesw", 32644: "size_we", 32645: "size_ns", 32646: "size_all", 32648: "no", 32649: "hand", 32650: "app_starting"} {
		if desktopUser("LoadCursorW", 0, uintptr(id)) == info.Handle {
			shape = name
			break
		}
	}
	return map[string]any{"available": true, "visible": info.Flags&1 != 0, "handle": fmt.Sprintf("0x%x", info.Handle), "shape": shape, "x": int(math.Round(float64(int(info.X)-g.Bounds.X) * float64(g.Width) / float64(g.Bounds.Width))), "y": int(math.Round(float64(int(info.Y)-g.Bounds.Y) * float64(g.Height) / float64(g.Bounds.Height))), "drawn_in_image": false}
}
func desktopSnapshot(session desktopSession) (desktopWorkerResponse, error) {
	return desktopSnapshotMode(session, false)
}
func desktopSnapshotMode(session desktopSession, interaction bool) (desktopWorkerResponse, error) {
	var result desktopWorkerResponse
	before, err := desktopState(session)
	if err != nil {
		return result, err
	}
	data, err := captureDesktopJPEG(before)
	if err != nil {
		return result, err
	}
	windowsList := desktopWindows(before)
	cursor := desktopCursor(before)
	after, err := desktopState(session)
	if err != nil {
		return result, err
	}
	if before.Bounds != after.Bounds {
		return result, errors.New("desktop geometry changed while capturing; observe again")
	}
	actionable := before.Foreground == after.Foreground
	after.FrameID = desktopID()
	after.Created = time.Now().UTC()
	hash := sha256.Sum256(data)
	obs := map[string]any{"frame_id": after.FrameID, "actionable": actionable, "captured_at": after.Created, "session_id": session.ID, "session_user": session.User, "session_station": session.Station, "image_width": after.Width, "image_height": after.Height, "sha256": hex.EncodeToString(hash[:]), "last_input_tick": after.InputTick, "desktop_rect": map[string]int{"x": after.Bounds.X, "y": after.Bounds.Y, "width": after.Bounds.Width, "height": after.Bounds.Height}, "windows": windowsList, "cursor": cursor, "pressed_virtual_keys": desktopPressed(), "foreground": desktopWindow(uintptr(after.Foreground), after), "capabilities": map[string]any{"worker_version": "rcon-native-1", "transport": "native", "key_grammar": "chord-v1", "actions": []string{"click", "double_click", "move", "scroll", "drag", "key", "type"}, "buttons": []string{"left", "right", "middle"}, "wheel_axes": []string{"vertical", "horizontal"}, "cross_call_held_input": true, "interaction_protocol": "held-v1", "interruption_policy": "external-escape-triple", "pause_escape_count": 3, "pause_escape_window_ms": 1500, "pause_scope": "logged-on-session-including-idle", "resume_policy": "local-badge-click", "input_timestamp_policy": "diagnostic-only", "interaction_max_lease_ms": 60000, "interaction_max_frames": 6, "window_geometry": true, "cursor_metadata": true, "session_selection": true, "visual_indicator": true, "visual_pointer": "tagged-v1"}}
	result.Result = map[string]any{"ok": true, "observation": obs, "image": map[string]any{"mimeType": "image/jpeg", "data": base64.StdEncoding.EncodeToString(data)}}
	pause, pauseErr := readDesktopPause()
	obs["control_paused"] = pause != nil || pauseErr != nil
	result.Result["paused"] = pause != nil || pauseErr != nil
	if pause != nil {
		obs["pause_id"] = pause.ID
		obs["pause_reason"] = pause.Reason
	}
	if pauseErr != nil {
		obs["pause_error"] = pauseErr.Error()
	}

	if actionable {
		result.Guard = after
	} else {
		obs["input_refusal_reason"] = "foreground changed during capture; observe the current desktop before acting"
	}
	return result, nil
}
func performDesktopOperation(req desktopWorkerRequest) desktopWorkerResponse {
	c := req.Command
	status := "not_sent"
	fail := func(err error) desktopWorkerResponse {
		out := desktopFailure(c.ID, status, err)
		if interactionExternalInput.Load() {
			if e := latchDesktopPause(req.Session); e != nil {
				out["pause_error"] = e.Error()
			}
		}
		if pause, e := readDesktopPause(); pause != nil || e != nil {
			out["paused"] = true
		}
		return desktopWorkerResponse{Result: out}
	}
	if p := desktopUser32.NewProc("SetProcessDpiAwarenessContext"); p.Find() == nil {
		p.Call(^uintptr(3))
	} // PER_MONITOR_AWARE_V2 (-4)
	if c.Op == "act" {
		interactionExternalInput.Store(false)
		stopMonitor, err := startInteractionMonitor()
		if err != nil {
			return fail(err)
		}
		defer stopMonitor()
		defer func() {
			if interactionExternalInput.Load() {
				_ = latchDesktopPause(req.Session)
			}
		}()
		live, err := desktopState(req.Session)
		if err != nil {
			return fail(err)
		}
		if err = validateDesktopGuard(c, req.Previous, live); err != nil {
			return fail(err)
		}
		if len(desktopPressed()) != 0 {
			return fail(errors.New("physical key or button held; release input and observe again"))
		}
		status = "unknown"
		if err = sendDesktopAction(c, live); err != nil {
			return fail(err)
		}
		status = "sent"
		if err := waitDesktopQuiet(req.Session); err != nil {
			return fail(err)
		}
	}
	if c.WaitMS > 0 {
		time.Sleep(time.Duration(c.WaitMS) * time.Millisecond)
	}
	out, err := desktopSnapshot(req.Session)
	if err != nil {
		return fail(err)
	}
	out.Result["id"] = c.ID
	out.Result["input_status"] = status
	return out
}

// Give normal UI composition time to catch up after a gesture. This is a
// bounded settling period, not proof that an asynchronous app task completed.
func waitDesktopQuiet(session desktopSession) error {
	last, err := desktopState(session)
	if err != nil {
		return err
	}
	quiet := time.Now()
	deadline := quiet.Add(3 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		live, err := desktopState(session)
		if err != nil {
			return err
		}
		if last.Foreground != live.Foreground || last.Bounds != live.Bounds {
			quiet = time.Now()
			last = live
		}
		if time.Since(quiet) >= 800*time.Millisecond {
			return nil
		}
	}
	return nil // still permit inspection; snapshot decides whether input is safe
}
