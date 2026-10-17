package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	utf16codec "unicode/utf16"
	"unsafe"
)

type desktopMouseInput struct {
	DX, DY            int32
	Data, Flags, Time uint32
	Extra             uintptr
}
type desktopKeyboardInput struct {
	VK, Scan    uint16
	Flags, Time uint32
	Extra       uintptr
}

// INPUT contains a C union. Store its bytes, not a MOUSEINPUT-typed Go
// struct: KEYBDINPUT.Extra overlaps MOUSEINPUT padding, which Go is allowed
// to discard when passing/copying a struct by value.
type desktopInputData struct {
	_     [0]uintptr
	Bytes [unsafe.Sizeof(desktopMouseInput{})]byte
}
type desktopInput struct {
	Type uint32
	Data desktopInputData
}

func desktopSend(i *desktopInput, release bool) error {
	if !release {
		if err := desktopPauseError(); err != nil {
			return err
		}
		if interactionExternalInput.Load() {
			return errors.New("outside Escape triple-press; input cancelled")
		}
		if err := desktopDefault(); err != nil {
			return err
		}
	}
	if desktopUser("SendInput", 1, uintptr(unsafe.Pointer(i)), unsafe.Sizeof(*i)) != 1 {
		return errors.New("SendInput failed; input outcome may be partial")
	}
	return nil
}
func desktopMouse(flags, data uint32, x, y int32, release bool) error {
	i := desktopInput{}
	*(*desktopMouseInput)(unsafe.Pointer(&i.Data)) = desktopMouseInput{DX: x, DY: y, Data: data, Flags: flags, Extra: desktopInputTag}
	return desktopSend(&i, release)
}
func desktopMove(x, y int, g desktopGuard) error {
	// SendInput absolute coordinates are relative to the entire virtual desktop,
	// including monitors left of or above the primary monitor.
	dx := int32(float64(x) * float64(g.Bounds.Width) / float64(g.Width) * 65535 / float64(g.Bounds.Width-1))
	dy := int32(float64(y) * float64(g.Bounds.Height) / float64(g.Height) * 65535 / float64(g.Bounds.Height-1))
	return desktopMouse(0xC001, 0, dx, dy, false) // MOVE | ABSOLUTE | VIRTUALDESK
}

// A physical keyboard reports a scan code with every virtual key. Apps that
// identify keys physically (winit/Rust UIs, games, some terminals) ignore a key
// whose scan code is 0, so derive it from the foreground thread's layout.
func desktopScan(vk uint16) (uint16, uint32) {
	layout := desktopUser("GetKeyboardLayout", desktopUser("GetWindowThreadProcessId", desktopUser("GetForegroundWindow"), 0))
	sc := desktopUser("MapVirtualKeyExW", uintptr(vk), 4, layout) // MAPVK_VK_TO_VSC_EX
	flags := uint32(0)
	if prefix := sc >> 8; prefix == 0xE0 || prefix == 0xE1 {
		flags = 1 // KEYEVENTF_EXTENDEDKEY
	}
	return uint16(sc & 0xFF), flags
}
func desktopKey(vk, scan uint16, flags uint32, release bool) error {
	if vk != 0 && scan == 0 && flags&4 == 0 { // not KEYEVENTF_UNICODE text
		var extended uint32
		scan, extended = desktopScan(vk)
		flags |= extended
	}
	i := desktopInput{Type: 1}
	k := (*desktopKeyboardInput)(unsafe.Pointer(&i.Data))
	*k = desktopKeyboardInput{VK: vk, Scan: scan, Flags: flags, Extra: desktopInputTag}
	if release {
		k.Flags |= 2
	}
	return desktopSend(&i, release)
}
func desktopVK(name string) (uint16, uint32) {
	keys := map[string]uint16{"CTRL": 0x11, "CONTROL": 0x11, "ALT": 0x12, "SHIFT": 0x10, "WIN": 0x5B, "ENTER": 0x0D, "RETURN": 0x0D, "ESC": 0x1B, "ESCAPE": 0x1B, "TAB": 9, "SPACE": 0x20, "BACKSPACE": 8, "DELETE": 0x2E, "DEL": 0x2E, "INSERT": 0x2D, "INS": 0x2D, "HOME": 0x24, "END": 0x23, "PAGEUP": 0x21, "PGUP": 0x21, "PAGEDOWN": 0x22, "PGDN": 0x22, "UP": 0x26, "DOWN": 0x28, "LEFT": 0x25, "RIGHT": 0x27}
	vk := keys[name]
	if len(name) == 1 {
		vk = uint16(name[0])
	} else if strings.HasPrefix(name, "F") {
		n, _ := strconv.Atoi(name[1:])
		vk = uint16(0x6F + n)
	}
	flags := uint32(0)
	if (vk >= 0x21 && vk <= 0x2E) || vk == 0x5B {
		flags = 1
	}
	return vk, flags
}
func desktopChord(chord string) (err error) {
	type key struct {
		vk    uint16
		flags uint32
	}
	held := []key{}
	defer func() {
		for i := len(held) - 1; i >= 0; i-- {
			if e := desktopKey(held[i].vk, 0, held[i].flags, true); e != nil && err == nil {
				err = e
			}
		}
	}()
	for _, part := range strings.Split(strings.ToUpper(chord), "+") {
		vk, flags := desktopVK(strings.TrimSpace(part))
		if vk == 0 {
			return errors.New("invalid key")
		}
		// Track before attempting the down event: even uncertain dispatch receives up.
		held = append(held, key{vk, flags})
		if err = desktopKey(vk, 0, flags, false); err != nil {
			return err
		}
	}
	return nil
}
func desktopType(text string) error {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	for _, ch := range utf16codec.Encode([]rune(text)) {
		if ch == '\n' || ch == '\r' {
			if err := desktopChord("ENTER"); err != nil {
				return err
			}
			continue
		}
		if ch == '\t' {
			if err := desktopChord("TAB"); err != nil {
				return err
			}
			continue
		}
		down := desktopKey(0, ch, 4, false)
		up := desktopKey(0, ch, 4, true)
		if down != nil {
			return down
		}
		if up != nil {
			return up
		}
	}
	return nil
}
func sendDesktopAction(c desktopCommand, g desktopGuard) (err error) {
	if c.Action == "key" {
		return desktopChord(c.Key)
	}
	if c.Action == "type" {
		return desktopType(c.Text)
	}
	if c.X == nil || c.Y == nil {
		return errors.New("pointer missing")
	}
	if err = desktopMove(*c.X, *c.Y, g); err != nil {
		return err
	}
	down, up := uint32(2), uint32(4)
	switch c.Button {
	case "right":
		down, up = 8, 16
	case "middle":
		down, up = 32, 64
	}
	click := func() (err error) {
		defer func() {
			if e := desktopMouse(up, 0, 0, 0, true); err == nil {
				err = e
			}
		}()
		return desktopMouse(down, 0, 0, 0, false)
	}
	switch c.Action {
	case "move":
		return nil
	case "click":
		return click()
	case "double_click":
		if err = click(); err != nil {
			return err
		}
		time.Sleep(80 * time.Millisecond)
		return click()
	case "scroll":
		flags := uint32(0x800)
		if c.Axis == "horizontal" {
			flags = 0x1000
		}
		return desktopMouse(flags, uint32(int32(c.Steps*120)), 0, 0, false)
	case "drag":
		defer func() {
			if e := desktopMouse(up, 0, 0, 0, true); err == nil {
				err = e
			}
		}()
		if err = desktopMouse(down, 0, 0, 0, false); err != nil {
			return err
		}
		n := c.DurationMS / 20
		for i := 1; i <= n; i++ {
			time.Sleep(20 * time.Millisecond)
			x := *c.X + (*c.ToX-*c.X)*i/n
			y := *c.Y + (*c.ToY-*c.Y)*i/n
			if err = desktopMove(x, y, g); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("unsupported action %q", c.Action)
}
