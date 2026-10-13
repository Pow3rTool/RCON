package main

import (
	"testing"
	"time"
)

func TestDesktopPointerOnlyTracksOwnInput(t *testing.T) {
	var p desktopPointerState
	now := time.Now()
	for _, event := range []struct {
		flags uint32
		tag   uintptr
	}{{0, 0}, {1, 0}, {0, desktopInputTag}, {1, 123}} {
		if p.feed(0x200, event.flags, event.tag, 100, 200, now) || p.visible(now) {
			t.Fatal("outside movement became AI movement")
		}
	}
	if !p.feed(0x200, 1, desktopInputTag, -900, 50, now) || p.Point.X != -900 {
		t.Fatal("lost tagged movement or negative monitor origin")
	}
	before := p
	p.feed(0x201, 0, 0, 500, 500, now)
	if p != before {
		t.Fatal("human click changed AI state")
	}
}

func TestDesktopPointerHeldLifetimeAndRelease(t *testing.T) {
	var p desktopPointerState
	now := time.Now()
	p.feed(0x201, 1, desktopInputTag, 10, 20, now)
	p.feed(0x204, 1, desktopInputTag, 10, 20, now)
	if p.Buttons != 3 || !p.visible(now.Add(2*time.Minute)) || p.strength(now.Add(time.Minute)) != 1 {
		t.Fatal("held state faded")
	}
	p.feed(0x202, 1, desktopInputTag, 15, 25, now.Add(time.Minute))
	if p.Buttons != 2 {
		t.Fatal("left release cleared another held button")
	}
	p.feed(0x205, 1, desktopInputTag, 15, 25, now.Add(time.Minute))
	if p.Buttons != 0 || p.strength(now.Add(time.Minute+time.Second)) >= 1 {
		t.Fatal("release did not fade")
	}
	if p.visible(now.Add(time.Minute + 2*time.Second)) {
		t.Fatal("idle pointer did not expire")
	}
	p.feed(0x207, 1, desktopInputTag, 20, 30, now.Add(2*time.Minute))
	if p.Buttons != 4 || p.PulseCount != 1 {
		t.Fatal("new activity inherited stale history")
	}
}

func TestDesktopPointerHistoryBoundedAndDoubleClickVisible(t *testing.T) {
	var p desktopPointerState
	now := time.Now()
	for i := 0; i < 1000; i++ {
		p.feed(0x200, 1, desktopInputTag, int32(i), 50, now.Add(time.Duration(i)*time.Millisecond))
	}
	if p.TrailCount != 24 || p.Trail[23].X != 999 {
		t.Fatal("trail bounds/latest point")
	}
	for i := 0; i < 2; i++ {
		p.feed(0x201, 1, desktopInputTag, 999, 50, now.Add(time.Second+time.Duration(i)*80*time.Millisecond))
		p.feed(0x202, 1, desktopInputTag, 999, 50, now.Add(time.Second+time.Duration(i)*80*time.Millisecond))
	}
	if p.PulseCount != 2 || p.Buttons != 0 {
		t.Fatal("double-click lost its pulses")
	}
	for i := 0; i < 100; i++ {
		p.feed(0x201, 1, desktopInputTag, 999, 50, now.Add(1200*time.Millisecond))
		p.feed(0x202, 1, desktopInputTag, 999, 50, now.Add(1200*time.Millisecond))
	}
	if p.PulseCount != 6 {
		t.Fatal("pulse history grew")
	}
}
