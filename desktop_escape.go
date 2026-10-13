package main

import (
	"fmt"
	"time"
)

// Only distinct outside Escape presses count. Ignore RCON input entirely so
// a robot's key-up cannot turn a held physical key's autorepeat into a tap.
type desktopEscapeSequence struct {
	down  bool
	first time.Time
	count int
}

func (s *desktopEscapeSequence) feed(message, vk, flags uint32, extra uintptr, now time.Time) bool {
	if vk != 27 || (extra == 0x52434f4e && flags&0x10 != 0) {
		return false
	}
	if message == 0x101 || message == 0x105 {
		s.down = false
		return false
	}
	if (message != 0x100 && message != 0x104) || flags&0x80 != 0 || s.down {
		return false
	}
	s.down = true
	if s.count == 0 || now.Sub(s.first) > 1500*time.Millisecond || now.Before(s.first) {
		s.first = now
		s.count = 0
	}
	s.count++
	if s.count < 3 {
		return false
	}
	s.count = 0
	return true
}

func desktopCountdownLabel(state string, expires, now time.Time) string {
	seconds := max(0, int((expires.Sub(now)+time.Second-1)/time.Second))
	switch state {
	case "AI thinking":
		return fmt.Sprintf("AI thinking · releases in %ds", seconds)
	case "AI idle":
		return fmt.Sprintf("AI waiting · idle in %ds", seconds)
	default:
		return state
	}
}
