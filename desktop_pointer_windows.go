package main

import (
	"errors"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type indicatorMouseEvent struct {
	X, Y              int32
	Data, Flags, Time uint32
	Extra             uintptr
}

var indicatorPointer struct {
	sync.Mutex
	enabled bool
	state   desktopPointerState
}

// Paint state belongs exclusively to the window thread. The hook only updates
// the small fixed-size model under a short lock; it never paints or performs IO.
var indicatorPointerFrame desktopPointerState
var indicatorPointerPaintTime time.Time
var indicatorPointerLastTick time.Time

var indicatorMouseHook = windows.NewCallback(func(code int32, message uintptr, event *indicatorMouseEvent) uintptr {
	if code >= 0 && event.Flags&1 != 0 && event.Extra == desktopInputTag {
		indicatorPointer.Lock()
		if indicatorPointer.enabled {
			indicatorPointer.state.feed(uint32(message), event.Flags, event.Extra, event.X, event.Y, time.Now())
		}
		indicatorPointer.Unlock()
	}
	return desktopUser("CallNextHookEx", 0, uintptr(code), message, uintptr(unsafe.Pointer(event)))
})

func startIndicatorPointerMonitor() (func(), error) {
	indicatorPointerFrame = desktopPointerState{}
	indicatorPointerLastTick = time.Time{}
	indicatorPointer.Lock()
	indicatorPointer.state = desktopPointerState{}
	indicatorPointer.enabled = true
	indicatorPointer.Unlock()
	ready := make(chan error, 1)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		defer close(done)
		module, _, _ := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetModuleHandleW").Call(0)
		hook := desktopUser("SetWindowsHookExW", 14, indicatorMouseHook, module, 0)
		if hook == 0 {
			ready <- errors.New("cannot monitor RCON pointer events")
			return
		}
		defer desktopUser("UnhookWindowsHookEx", hook)
		ready <- nil
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				interactionPump()
			}
		}
	}()
	if err := <-ready; err != nil {
		return nil, err
	}
	return func() { close(stop); <-done }, nil
}

func indicatorPointerLabel(label string) {
	indicatorPointer.Lock()
	indicatorPointer.enabled = label != "" && label != desktopPausedLabel
	if !indicatorPointer.enabled {
		indicatorPointer.state = desktopPointerState{}
	}
	indicatorPointer.Unlock()
}

// Only call from the window thread, never the keyboard/mouse hook pump.
func indicatorPointerTick() {
	now := time.Now()
	if now.Sub(indicatorPointerLastTick) < 20*time.Millisecond {
		return
	}
	indicatorPointerLastTick = now
	indicatorPointer.Lock()
	frame := indicatorPointer.state
	indicatorPointer.Unlock()
	indicatorPointerFrame, indicatorPointerPaintTime = frame, now
	for hwnd, w := range indicatorWindows {
		r := desktopRect{}
		if w.label != "" && w.label != desktopPausedLabel && frame.visible(now) {
			r = indicatorPointerBounds(frame, w, now)
		}
		// Invalidate both the old and new footprints so no trails survive expiry.
		for _, dirty := range []desktopRect{w.pointerRect, r} {
			if dirty.Right > dirty.Left && dirty.Bottom > dirty.Top {
				desktopUser("InvalidateRect", hwnd, uintptr(unsafe.Pointer(&dirty)), 0)
			}
		}
		w.pointerRect = r
		if r.Right > r.Left || desktopUser("GetUpdateRect", hwnd, 0, 0) != 0 {
			desktopUser("UpdateWindow", hwnd)
		}
	}
}

func indicatorPointerBounds(p desktopPointerState, w *indicatorWindow, now time.Time) desktopRect {
	s := func(v int32) int32 { return v * w.dpi / 96 }
	x, y := p.Point.X-w.screen.Left, p.Point.Y-w.screen.Top
	r := desktopRect{x - s(30), y - s(30), x + s(82), y + s(44)}
	add := func(pt desktopPointerPoint, radius int32) {
		x, y := pt.X-w.screen.Left, pt.Y-w.screen.Top
		r.Left = min(r.Left, x-s(radius))
		r.Top = min(r.Top, y-s(radius))
		r.Right = max(r.Right, x+s(radius))
		r.Bottom = max(r.Bottom, y+s(radius))
	}
	for _, pt := range p.Trail[:p.TrailCount] {
		if now.Sub(pt.At) < desktopPointerTrailLifetime {
			add(pt, 5)
		}
	}
	for _, pt := range p.Pulses[:p.PulseCount] {
		if now.Sub(pt.At) < desktopPointerPulseLifetime {
			add(pt, 30)
		}
	}
	r.Left = max(0, r.Left)
	r.Top = max(0, r.Top)
	r.Right = min(w.screen.Right-w.screen.Left, r.Right)
	r.Bottom = min(w.screen.Bottom-w.screen.Top, r.Bottom)
	return r
}

func paintIndicatorPointer(dc uintptr, w *indicatorWindow) {
	p, now := indicatorPointerFrame, indicatorPointerPaintTime
	if w.label == "" || w.label == desktopPausedLabel || !p.visible(now) {
		return
	}
	s := func(v int32) int32 { return v * w.dpi / 96 }
	color := func(base uintptr, strength float64) uintptr {
		strength = max(0, min(1, strength))
		return uintptr(float64(base&255)*strength) | uintptr(float64((base>>8)&255)*strength)<<8 | uintptr(float64((base>>16)&255)*strength)<<16
	}
	ellipse := func(pt desktopPointerPoint, radius int32, strength float64) {
		x, y := pt.X-w.screen.Left, pt.Y-w.screen.Top
		pen := desktopGDI("CreatePen", 0, uintptr(max(1, s(2))), color(desktopIndicatorPurple, strength))
		if pen == 0 {
			return
		}
		defer desktopGDI("DeleteObject", pen)
		oldPen := desktopGDI("SelectObject", dc, pen)
		defer desktopGDI("SelectObject", dc, oldPen)
		oldBrush := desktopGDI("SelectObject", dc, desktopGDI("GetStockObject", 5))
		defer desktopGDI("SelectObject", dc, oldBrush) // NULL_BRUSH
		desktopGDI("Ellipse", dc, uintptr(x-s(radius)), uintptr(y-s(radius)), uintptr(x+s(radius)), uintptr(y+s(radius)))
	}
	for _, pt := range p.Trail[:p.TrailCount] {
		age := now.Sub(pt.At)
		if age >= 0 && age < desktopPointerTrailLifetime {
			ellipse(pt, 2, 0.65*(1-float64(age)/float64(desktopPointerTrailLifetime)))
		}
	}
	for _, pt := range p.Pulses[:p.PulseCount] {
		age := now.Sub(pt.At)
		if age >= 0 && age < desktopPointerPulseLifetime {
			f := float64(age) / float64(desktopPointerPulseLifetime)
			ellipse(pt, 8+int32(18*f), 1-f)
		}
	}
	x, y := p.Point.X-w.screen.Left, p.Point.Y-w.screen.Top
	strength := p.strength(now)
	// A narrow arrow with a bright outline remains readable on light and dark CAD
	// canvases. Its tip is exactly at the injected event's desktop coordinate.
	points := [7]struct{ X, Y int32 }{{x, y}, {x + s(4), y + s(25)}, {x + s(10), y + s(19)}, {x + s(15), y + s(30)}, {x + s(20), y + s(27)}, {x + s(15), y + s(17)}, {x + s(24), y + s(16)}}
	pen := desktopGDI("CreatePen", 0, uintptr(max(1, s(2))), color(0xffeff6, strength))
	brush := desktopGDI("CreateSolidBrush", color(desktopIndicatorPurple, strength))
	if pen == 0 || brush == 0 {
		if pen != 0 {
			desktopGDI("DeleteObject", pen)
		}
		if brush != 0 {
			desktopGDI("DeleteObject", brush)
		}
		return
	}
	oldPen := desktopGDI("SelectObject", dc, pen)
	oldBrush := desktopGDI("SelectObject", dc, brush)
	desktopGDI("Polygon", dc, uintptr(unsafe.Pointer(&points[0])), uintptr(len(points)))
	desktopGDI("SelectObject", dc, oldPen)
	desktopGDI("SelectObject", dc, oldBrush)
	desktopGDI("DeleteObject", pen)
	desktopGDI("DeleteObject", brush)
	if p.Buttons != 0 {
		label := ""
		for _, b := range []struct {
			bit  uint8
			name string
		}{{1, "L"}, {2, "R"}, {4, "M"}} {
			if p.Buttons&b.bit != 0 {
				label += b.name
			}
		}
		text := windows.StringToUTF16(label)
		r := desktopRect{x + s(28), y + s(10), x + s(80), y + s(32)}
		background := desktopGDI("CreateSolidBrush", 0x2f1b24)
		if background != 0 {
			desktopUser("FillRect", dc, uintptr(unsafe.Pointer(&r)), background)
			desktopGDI("DeleteObject", background)
		}
		desktopGDI("SetBkMode", dc, 1)
		desktopGDI("SetTextColor", dc, desktopIndicatorPurple)
		old := desktopGDI("SelectObject", dc, w.font)
		desktopUser("DrawTextW", dc, uintptr(unsafe.Pointer(&text[0])), uintptr(len(text)-1), uintptr(unsafe.Pointer(&r)), 0x0025)
		desktopGDI("SelectObject", dc, old)
	}
}
