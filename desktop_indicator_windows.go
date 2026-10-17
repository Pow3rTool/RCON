package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const desktopIndicatorClass = "Pow3rTool.RCON.DesktopIndicator"
const desktopIndicatorLease = 30 * time.Second
const desktopIndicatorPurple = 0xff88b3 // COLORREF for #b388ff

type desktopIndicatorMessage struct{ Label string }
type desktopIndicatorAck struct {
	OK    bool
	Error string
}
type desktopIndicatorUpdate struct {
	label string
	reply chan error
}
type desktopIndicatorClient struct {
	session desktopSession
	updates chan desktopIndicatorUpdate
	done    chan struct{}
	cancel  context.CancelFunc
	err     error // published by closing done
}

// Accessed only with desktopManager locked. The worker has no input capability.
var activeDesktopIndicator *desktopIndicatorClient

func indicatorLabelValid(label string) bool {
	return label == desktopPausedLabel || label == "AI viewing" || label == "AI controlling" || label == "AI idle" || label == "AI thinking"
}
func readIndicatorAck(decoder *json.Decoder) error {
	var ack desktopIndicatorAck
	if err := decoder.Decode(&ack); err != nil {
		return err
	}
	if !ack.OK {
		return fmt.Errorf("indicator unavailable: %s", ack.Error)
	}
	return nil
}
func setDesktopIndicator(session desktopSession, label string) error {
	if pause, err := readDesktopPause(); err == nil && pause != nil {
		label = desktopPausedLabel
	}
	if !indicatorLabelValid(label) {
		return errors.New("invalid indicator state")
	}
	client := activeDesktopIndicator
	if client != nil {
		select {
		case <-client.done:
			client = nil
		default:
		}
	}
	if client != nil && (client.session.ID != session.ID || client.session.LogonID != session.LogonID) {
		client.cancel()
		select {
		case <-client.done:
		case <-time.After(5 * time.Second):
			return errors.New("previous indicator did not stop")
		}
		client = nil
	}
	if client == nil {
		ctx, cancel := context.WithCancel(context.Background())
		client = &desktopIndicatorClient{session: session, updates: make(chan desktopIndicatorUpdate), done: make(chan struct{}), cancel: cancel}
		activeDesktopIndicator = client
		ready := make(chan error, 1)
		go func() {
			defer close(client.done)
			defer cancel()
			readySent := false
			client.err = withDesktopWorker(ctx, desktopWorkerRequest{Session: session, Indicator: label}, func(conn net.Conn) error {
				encoder := json.NewEncoder(conn)
				decoder := json.NewDecoder(io.LimitReader(conn, 1024*1024))
				_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
				if err := readIndicatorAck(decoder); err != nil {
					return err
				}
				ready <- nil
				readySent = true
				timer := time.NewTimer(desktopIndicatorLease)
				defer timer.Stop()
				for {
					select {
					case <-ctx.Done():
						return ctx.Err()
					case <-timer.C:
						pause, e := readDesktopPause()
						if e != nil || pause == nil {
							return e
						}
						_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
						if e = encoder.Encode(desktopIndicatorMessage{Label: desktopPausedLabel}); e != nil {
							return e
						}
						if e = readIndicatorAck(decoder); e != nil {
							return e
						}
						timer.Reset(15 * time.Second)
					case update := <-client.updates:
						_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
						err := encoder.Encode(desktopIndicatorMessage{Label: update.label})
						if err == nil {
							err = readIndicatorAck(decoder)
						}
						update.reply <- err
						if err != nil {
							return err
						}
						timer.Reset(desktopIndicatorLease)
					}
				}
			})
			if !readySent {
				ready <- client.err
			}
		}()
		select {
		case err := <-ready:
			return err
		case <-time.After(10 * time.Second):
			cancel()
			return errors.New("indicator start timed out")
		}
	}
	update := desktopIndicatorUpdate{label: label, reply: make(chan error, 1)}
	select {
	case client.updates <- update:
	case <-client.done:
		return errors.New("indicator stopped; observe again")
	case <-time.After(5 * time.Second):
		client.cancel()
		return errors.New("indicator update timed out")
	}
	select {
	case err := <-update.reply:
		return err
	case <-time.After(6 * time.Second):
		client.cancel()
		return errors.New("indicator acknowledgement timed out")
	}
}

type indicatorMonitor struct {
	Rect desktopRect
	Work desktopRect
}
type indicatorWindow struct {
	hwnd, font          uintptr
	label               string
	dpi                 int32
	screen, pointerRect desktopRect
}

var indicatorWindows = map[uintptr]*indicatorWindow{}
var indicatorPauseID string
var indicatorResumeClicked bool
var indicatorMouseDown uintptr

func indicatorBadge(bounds desktopRect, dpi int32, label string) desktopRect {
	scale := func(n int32) int32 { return max(1, n*dpi/96) }
	width := int32(244)
	if strings.HasPrefix(label, "AI thinking") {
		width = 310
	}
	if label == desktopPausedLabel {
		width = 370
	}
	right, top := bounds.Right-scale(16), scale(16)
	return desktopRect{right - scale(width), top, right, top + scale(34)}
}
func indicatorSetLabel(label string) {
	indicatorPointerLabel(label)
	for hwnd, w := range indicatorWindows {
		if w.label == label {
			continue
		}
		w.label = label
		if label == "" {
			desktopUser("ShowWindow", hwnd, 0)
			desktopUser("SetCursor", desktopUser("LoadCursorW", 0, 32512))
			continue
		}
		desktopUser("ShowWindow", hwnd, 4) // SW_SHOWNOACTIVATE
		style := desktopUser("GetWindowLongPtrW", hwnd, ^uintptr(19))
		if label == desktopPausedLabel {
			style &^= 0x20
		} else {
			style |= 0x20
		}
		desktopUser("SetWindowLongPtrW", hwnd, ^uintptr(19), style)
		desktopUser("InvalidateRect", hwnd, 0, 0)
		desktopUser("UpdateWindow", hwnd)
	}
}

var indicatorMonitors []indicatorMonitor
var indicatorMonitorCallback = windows.NewCallback(func(monitor, dc, rect, data uintptr) uintptr {
	info := struct {
		Size       uint32
		Rect, Work desktopRect
		Flags      uint32
	}{}
	info.Size = uint32(unsafe.Sizeof(info))
	if len(indicatorMonitors) >= 16 || desktopUser("GetMonitorInfoW", monitor, uintptr(unsafe.Pointer(&info))) == 0 {
		return 0
	}
	indicatorMonitors = append(indicatorMonitors, indicatorMonitor{info.Rect, info.Work})
	return 1
})

func getIndicatorMonitors() ([]indicatorMonitor, error) {
	indicatorMonitors = nil
	if desktopUser("EnumDisplayMonitors", 0, 0, indicatorMonitorCallback, 0) == 0 || len(indicatorMonitors) == 0 {
		return nil, errors.New("monitor enumeration failed")
	}
	return slices.Clone(indicatorMonitors), nil
}

var indicatorWindowProc = windows.NewCallback(func(hwnd, message, wparam, lparam uintptr) uintptr {
	switch message {
	case 0x0020: // WM_SETCURSOR: the only clickable area is the paused badge.
		if w := indicatorWindows[hwnd]; w != nil && w.label == desktopPausedLabel && lparam&0xffff == 1 {
			desktopUser("SetCursor", desktopUser("LoadCursorW", 0, 32649)) // IDC_HAND
			return 1
		}
	case 0x0084:
		if w := indicatorWindows[hwnd]; w != nil && w.label == desktopPausedLabel {
			point := struct{ X, Y int32 }{int32(int16(lparam & 0xffff)), int32(int16((lparam >> 16) & 0xffff))}
			desktopUser("ScreenToClient", hwnd, uintptr(unsafe.Pointer(&point)))
			var bounds desktopRect
			desktopUser("GetClientRect", hwnd, uintptr(unsafe.Pointer(&bounds)))
			b := indicatorBadge(bounds, w.dpi, w.label)
			if point.X >= b.Left && point.X < b.Right && point.Y >= b.Top && point.Y < b.Bottom {
				return 1
			}
		}
		return ^uintptr(0) // HTTRANSPARENT
	case 0x0201: // A local down/up on the paused badge; marked RCON clicks cannot resume.
		if w := indicatorWindows[hwnd]; w != nil && w.label == desktopPausedLabel && desktopUser("GetMessageExtraInfo") != desktopInputTag {
			indicatorMouseDown = hwnd
		}
		return 0
	case 0x0202:
		if w := indicatorWindows[hwnd]; w != nil && w.label == desktopPausedLabel && indicatorMouseDown == hwnd && desktopUser("GetMessageExtraInfo") != desktopInputTag {
			var bounds desktopRect
			desktopUser("GetClientRect", hwnd, uintptr(unsafe.Pointer(&bounds)))
			b := indicatorBadge(bounds, w.dpi, w.label)
			x, y := int32(int16(lparam&0xffff)), int32(int16((lparam>>16)&0xffff))
			if x < b.Left || x >= b.Right || y < b.Top || y >= b.Bottom {
				indicatorMouseDown = 0
				return 0
			}
			if clearDesktopPause(indicatorPauseID) == nil {
				indicatorResumeClicked = true
				indicatorSetLabel("")
			}
		}
		indicatorMouseDown = 0
		return 0
	case 0x0021:
		return 3 // MA_NOACTIVATE
	case 0x0014:
		return 1 // background painted with the frame
	case 0x000f:
		paintIndicator(hwnd)
		return 0
	}
	return desktopUser("DefWindowProcW", hwnd, message, wparam, lparam)
})

func paintIndicator(hwnd uintptr) {
	ps := struct {
		DC                 uintptr
		Erase              int32
		Paint              desktopRect
		Restore, IncUpdate int32
		Reserved           [32]byte
	}{}
	dc := desktopUser("BeginPaint", hwnd, uintptr(unsafe.Pointer(&ps)))
	if dc == 0 {
		return
	}
	defer desktopUser("EndPaint", hwnd, uintptr(unsafe.Pointer(&ps)))
	window := indicatorWindows[hwnd]
	if window == nil {
		return
	}
	var bounds desktopRect
	desktopUser("GetClientRect", hwnd, uintptr(unsafe.Pointer(&bounds)))
	fill := func(rect desktopRect, color uintptr) {
		brush := desktopGDI("CreateSolidBrush", color)
		if brush != 0 {
			desktopUser("FillRect", dc, uintptr(unsafe.Pointer(&rect)), brush)
			desktopGDI("DeleteObject", brush)
		}
	}
	fill(bounds, 0) // transparent color key
	scale := func(n int32) int32 { return max(1, n*window.dpi/96) }
	line := scale(2)
	fill(desktopRect{0, 0, bounds.Right, line}, desktopIndicatorPurple)
	fill(desktopRect{0, bounds.Bottom - line, bounds.Right, bounds.Bottom}, desktopIndicatorPurple)
	fill(desktopRect{0, 0, line, bounds.Bottom}, desktopIndicatorPurple)
	fill(desktopRect{bounds.Right - line, 0, bounds.Right, bounds.Bottom}, desktopIndicatorPurple)
	paintIndicatorPointer(dc, window)
	// Only the paused badge is clickable; ordinary activity stays click-through.
	badge := indicatorBadge(bounds, window.dpi, window.label)
	fill(badge, 0x2f1b24)
	fill(desktopRect{badge.Left, badge.Top, badge.Left + scale(3), badge.Bottom}, desktopIndicatorPurple)
	text := windows.StringToUTF16("RCON · " + window.label)
	textRect := desktopRect{badge.Left + scale(13), badge.Top, badge.Right - scale(10), badge.Bottom}
	desktopGDI("SetBkMode", dc, 1)
	desktopGDI("SetTextColor", dc, 0xffeff0)
	old := desktopGDI("SelectObject", dc, window.font)
	desktopUser("DrawTextW", dc, uintptr(unsafe.Pointer(&text[0])), uintptr(len(text)-1), uintptr(unsafe.Pointer(&textRect)), 0x0024) // single line, centered vertically
	desktopGDI("SelectObject", dc, old)
}
func destroyIndicatorWindows() {
	for hwnd, window := range indicatorWindows {
		desktopUser("DestroyWindow", hwnd)
		desktopGDI("DeleteObject", window.font)
		delete(indicatorWindows, hwnd)
	}
}
func createIndicatorWindows(monitors []indicatorMonitor, label string) error {
	destroyIndicatorWindows()
	indicatorPointerLabel(label)
	class := windows.StringToUTF16(desktopIndicatorClass)
	title := windows.StringToUTF16("RCON AI activity")
	fontName := windows.StringToUTF16("Segoe UI")
	for _, monitor := range monitors {
		r := monitor.Rect
		// NOACTIVATE | LAYERED | TOOLWINDOW | TRANSPARENT | TOPMOST.
		style := uintptr(0x080800a8)
		if label == desktopPausedLabel {
			style &^= 0x20
		}
		hwnd := desktopUser("CreateWindowExW", style, uintptr(unsafe.Pointer(&class[0])), uintptr(unsafe.Pointer(&title[0])), 0x80000000, uintptr(r.Left), uintptr(r.Top), uintptr(r.Right-r.Left), uintptr(r.Bottom-r.Top), 0, 0, 0, 0)
		if hwnd == 0 {
			return errors.New("cannot create indicator window")
		}
		window := &indicatorWindow{hwnd: hwnd, label: label, dpi: 96, screen: r}
		indicatorWindows[hwnd] = window
		if p := desktopUser32.NewProc("GetDpiForWindow"); p.Find() == nil {
			dpi, _, _ := p.Call(hwnd)
			if dpi != 0 {
				window.dpi = int32(dpi)
			}
		}
		window.font = desktopGDI("CreateFontW", uintptr(-int32(16)*window.dpi/96), 0, 0, 0, 500, 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(&fontName[0])))
		if window.font == 0 {
			return errors.New("cannot create indicator font")
		}
		if desktopUser("SetLayeredWindowAttributes", hwnd, 0, 255, 1) == 0 {
			return errors.New("cannot set indicator transparency")
		}
		// Excluding the indicator prevents it obscuring app pixels in model frames.
		// Visibility is advisory; display affinity is not a security boundary.
		if desktopUser("SetWindowDisplayAffinity", hwnd, 0x11) == 0 {
			return errors.New("cannot exclude indicator from capture")
		}
		showFlags := uintptr(0x0050)
		if label == "" {
			showFlags = 0x0010
		}
		if desktopUser("SetWindowPos", hwnd, ^uintptr(0), uintptr(r.Left), uintptr(r.Top), uintptr(r.Right-r.Left), uintptr(r.Bottom-r.Top), showFlags) == 0 {
			return errors.New("cannot show indicator")
		}
		desktopUser("InvalidateRect", hwnd, 0, 0)
		desktopUser("UpdateWindow", hwnd)
	}
	return nil
}
func runDesktopIndicator(conn net.Conn, request desktopWorkerRequest) (result error) {
	ready := false
	defer func() {
		if !ready && result != nil {
			_ = json.NewEncoder(conn).Encode(desktopIndicatorAck{Error: result.Error()})
		}
	}()
	if pause, err := readDesktopPause(); err == nil && pause != nil {
		indicatorPauseID = pause.ID
		request.Indicator = desktopPausedLabel
	}
	if !indicatorLabelValid(request.Indicator) {
		return errors.New("invalid indicator state")
	}
	if p := desktopUser32.NewProc("SetProcessDpiAwarenessContext"); p.Find() == nil {
		p.Call(^uintptr(3))
	}
	if _, err := desktopIndicatorState(request.Session); err != nil {
		return err
	}
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
	if err = createIndicatorWindows(monitors, request.Indicator); err != nil {
		return err
	}
	encoder := json.NewEncoder(conn)
	if err = encoder.Encode(desktopIndicatorAck{OK: true}); err != nil {
		return err
	}
	ready = true
	messages := make(chan desktopIndicatorMessage)
	readError := make(chan error, 1)
	stopped := make(chan struct{})
	defer close(stopped)
	go func() {
		decoder := json.NewDecoder(io.LimitReader(conn, 1024*1024))
		for {
			var message desktopIndicatorMessage
			if err := decoder.Decode(&message); err != nil {
				readError <- err
				return
			}
			select {
			case messages <- message:
			case <-stopped:
				return
			}
		}
	}()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	expires := time.Now().Add(desktopIndicatorLease + 5*time.Second)
	checked := time.Now()
	label := request.Indicator
	for {
		select {
		case err := <-readError:
			return err
		case message := <-messages:
			if !indicatorLabelValid(message.Label) {
				return errors.New("invalid indicator update")
			}
			// Revalidate the session before acknowledging visibility for another action.
			if _, err := desktopIndicatorState(request.Session); err != nil {
				return err
			}
			if message.Label == "AI viewing" || message.Label == "AI controlling" || message.Label == "AI thinking" {
				indicatorResumeClicked = false
			}
			previousLabel := label
			label = message.Label
			if pause, err := readDesktopPause(); err == nil && pause != nil {
				indicatorPauseID = pause.ID
				label = desktopPausedLabel
			} else if label == desktopPausedLabel || (label == "AI idle" && (previousLabel == "" || indicatorResumeClicked)) {
				label = ""
			}
			indicatorSetLabel(label)
			expires = time.Now().Add(desktopIndicatorLease + 5*time.Second)
			if err := encoder.Encode(desktopIndicatorAck{OK: true}); err != nil {
				return err
			}
		case now := <-tick.C:
			if indicatorResumeClicked {
				indicatorResumeClicked = false
				label = ""
				indicatorSetLabel("")
			}
			if pause, e := readDesktopPause(); e == nil && pause != nil {
				indicatorPauseID = pause.ID
				if label != desktopPausedLabel {
					label = desktopPausedLabel
					indicatorSetLabel(label)
				}
				expires = now.Add(desktopIndicatorLease + 5*time.Second)
			} else if e == nil && label == desktopPausedLabel {
				label = ""
				indicatorSetLabel(label)
			}
			if label == "AI idle" {
				indicatorSetLabel(desktopCountdownLabel(label, expires.Add(-5*time.Second), now))
			}
			if !now.Before(expires) {
				return nil
			}
			// MSG contains a pointer-sized LPARAM/WPARAM, POINT and a private DWORD.
			msg := struct {
				Window         uintptr
				Message        uint32
				WParam, LParam uintptr
				Time           uint32
				X, Y           int32
				Private        uint32
			}{}
			for desktopUser("PeekMessageW", uintptr(unsafe.Pointer(&msg)), 0, 0, 0, 1) != 0 {
				desktopUser("TranslateMessage", uintptr(unsafe.Pointer(&msg)))
				desktopUser("DispatchMessageW", uintptr(unsafe.Pointer(&msg)))
			}
			indicatorPointerTick()
			if now.Sub(checked) >= 500*time.Millisecond {
				if _, err := desktopIndicatorState(request.Session); err != nil {
					return err
				}
				current, err := getIndicatorMonitors()
				if err != nil {
					return err
				}
				if !slices.Equal(monitors, current) {
					if err = createIndicatorWindows(current, label); err != nil {
						return err
					}
					monitors = current
				}
				checked = now
			}
		}
	}
}
func registerIndicatorClass() (func(), error) {
	class := windows.StringToUTF16(desktopIndicatorClass)
	wc := struct {
		Size, Style                                                uint32
		Proc                                                       uintptr
		ClassExtra, WindowExtra                                    int32
		Instance, Icon, Cursor, Background, Menu, Class, SmallIcon uintptr
	}{Proc: indicatorWindowProc, Cursor: desktopUser("LoadCursorW", 0, 32512), Class: uintptr(unsafe.Pointer(&class[0]))}
	wc.Size = uint32(unsafe.Sizeof(wc))
	if desktopUser("RegisterClassExW", uintptr(unsafe.Pointer(&wc))) == 0 {
		return nil, errors.New("cannot register indicator window class")
	}
	stopPointer, err := startIndicatorPointerMonitor()
	if err != nil {
		// Pointer decoration is advisory; retain the mandatory activity banner.
		desktopEvent("pointer-monitor-unavailable", map[string]any{"error": err.Error()})
	}
	return func() {
		if stopPointer != nil {
			stopPointer()
		}
		desktopUser("UnregisterClassW", uintptr(unsafe.Pointer(&class[0])), 0)
	}, nil
}

// An empty local console (for example just after first-profile setup) can have
// no foreground window. The overlay may still render so desktop_launch can open
// an app. Capture and input keep their strict foreground guard. RDP remains strict.
func desktopIndicatorState(session desktopSession) (desktopGuard, error) {
	g, err := desktopState(session)
	if errors.Is(err, errDesktopNoForeground) && strings.EqualFold(session.Station, "Console") && windows.WTSGetActiveConsoleSessionId() == session.ID {
		return g, nil
	}
	return g, err
}
