package main

import (
	"testing"
	"time"
)

func TestDesktopEscapeSequence(t *testing.T) {
	for _, tc := range []struct {
		name string
		gaps []time.Duration
		own  bool
		up   bool
		want bool
	}{
		{"single", []time.Duration{0}, false, true, false},
		{"double", []time.Duration{0, 200 * time.Millisecond}, false, true, false},
		{"triple", []time.Duration{0, 200 * time.Millisecond, 400 * time.Millisecond}, false, true, true},
		{"slow", []time.Duration{0, time.Second, 2 * time.Second}, false, true, false},
		{"autorepeat", []time.Duration{0, 100 * time.Millisecond, 200 * time.Millisecond, 300 * time.Millisecond}, false, false, false},
		{"robot", []time.Duration{0, 100 * time.Millisecond, 200 * time.Millisecond}, true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var s desktopEscapeSequence
			start := time.Now()
			got := false
			for _, gap := range tc.gaps {
				flags := uint32(0)
				tag := uintptr(0)
				if tc.own {
					flags = 0x10
					tag = 0x52434f4e
				}
				got = s.feed(0x100, 27, flags, tag, start.Add(gap)) || got
				if tc.up {
					s.feed(0x101, 27, flags|0x80, tag, start.Add(gap))
				}
			}
			if got != tc.want {
				t.Fatalf("trigger=%v want %v", got, tc.want)
			}
		})
	}
}
func TestDesktopEscapeOwnReleaseDoesNotCountRepeat(t *testing.T) {
	var s desktopEscapeSequence
	now := time.Now()
	s.feed(0x100, 27, 0, 0, now)
	for i := 0; i < 4; i++ {
		s.feed(0x101, 27, 0x90, 0x52434f4e, now)
		if s.feed(0x100, 27, 0, 0, now) {
			t.Fatal("robot keyup counted autorepeat")
		}
	}
}

func TestDesktopCountdownUsesDeadline(t *testing.T) {
	now := time.Now()
	if got := desktopCountdownLabel("AI thinking", now.Add(1500*time.Millisecond), now); got != "AI thinking · releases in 2s" {
		t.Fatal(got)
	}
	if got := desktopCountdownLabel("AI thinking", now.Add(-time.Second), now); got != "AI thinking · releases in 0s" {
		t.Fatal(got)
	}
	if got := desktopCountdownLabel("AI interrupted", now, now); got != "AI interrupted" {
		t.Fatal(got)
	}
}
