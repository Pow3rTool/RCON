package main

import (
	"encoding/binary"
	"errors"
)

// WTSINFOEXW begins with Level, 4-byte padding (8-byte union alignment), then
// WTSINFOEX_LEVEL1_W's SessionId, SessionState and SessionFlags.
func parseDesktopLockState(b []byte, session uint32) (bool, error) {
	if len(b) < 20 || binary.LittleEndian.Uint32(b[:4]) != 1 || binary.LittleEndian.Uint32(b[8:12]) != session {
		return false, errors.New("invalid WTS session lock information")
	}
	switch binary.LittleEndian.Uint32(b[16:20]) {
	case 0:
		return true, nil
	case 1:
		return false, nil
	default:
		return false, errors.New("Windows session lock state is unknown")
	}
}
