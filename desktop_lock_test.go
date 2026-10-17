package main

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestWindowsSessionLockInformation(t *testing.T) {
	b := make([]byte, 20)
	binary.LittleEndian.PutUint32(b, 1)
	binary.LittleEndian.PutUint32(b[8:], 7)
	if locked, e := parseDesktopLockState(b, 7); e != nil || !locked {
		t.Fatal(locked, e)
	}
	binary.LittleEndian.PutUint32(b[16:], 1)
	if locked, e := parseDesktopLockState(b, 7); e != nil || locked {
		t.Fatal(locked, e)
	}
	if _, e := parseDesktopLockState(b, 8); e == nil {
		t.Fatal("wrong session accepted")
	}
	if _, e := parseDesktopLockState(b[:19], 7); e == nil {
		t.Fatal("short WTS reply accepted")
	}
	binary.LittleEndian.PutUint32(b[16:], 0xffffffff)
	if _, e := parseDesktopLockState(b, 7); e == nil {
		t.Fatal("unknown state accepted")
	}
}
func TestDesktopLockProtocol(t *testing.T) {
	id := strings.Repeat("a", 32)
	if e := validateDesktopCommand(desktopCommand{ID: id, Op: "lock", SessionID: 7}); e != nil {
		t.Fatal(e)
	}
	for _, c := range []desktopCommand{{ID: id, Op: "lock", FrameID: id}, {ID: id, Op: "lock", Force: true}, {ID: id, Op: "lock", WaitMS: 1}, {ID: id, Op: "lock", DesktopAction: DesktopAction{Action: "key", Key: "ENTER"}}} {
		if validateDesktopCommand(c) == nil {
			t.Fatal("ambiguous lock accepted")
		}
	}
}
