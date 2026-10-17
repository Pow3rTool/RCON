package main

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestDesktopGuardRejectsChangedState(t *testing.T) {
	x, y := 10, 20
	c := desktopCommand{ID: strings.Repeat("a", 32), Op: "act", SessionID: 2, FrameID: strings.Repeat("b", 32), DesktopAction: DesktopAction{Action: "click", X: &x, Y: &y}}
	g := desktopGuard{FrameID: c.FrameID, SessionID: 2, LogonID: "logon", Created: time.Now(), Bounds: desktopBounds{-100, 0, 1920, 1080}, Width: 1600, Height: 900, InputTick: 50, Foreground: 123}
	if err := validateDesktopGuard(c, g, g); err != nil {
		t.Fatal(err)
	}
	resynchronized := g
	resynchronized.InputTick += 11000
	if err := validateDesktopGuard(c, g, resynchronized); err != nil {
		t.Fatal("diagnostic-only input timestamp blocked unchanged context", err)
	}
	for name, modify := range map[string]func(*desktopGuard){"session": func(g *desktopGuard) { g.SessionID++ }, "logon": func(g *desktopGuard) { g.LogonID = "new" }, "focus": func(g *desktopGuard) { g.Foreground++ }, "geometry": func(g *desktopGuard) { g.Bounds.X++ }, "scale": func(g *desktopGuard) { g.Width++ }} {
		t.Run(name, func(t *testing.T) {
			live := g
			modify(&live)
			if validateDesktopGuard(c, g, live) == nil {
				t.Fatal("accepted changed desktop")
			}
		})
	}
	expired := g
	expired.Created = time.Now().Add(-181 * time.Second)
	if validateDesktopGuard(c, expired, g) == nil {
		t.Fatal("accepted expired frame")
	}
	consumed := g
	consumed.FrameID = ""
	if validateDesktopGuard(c, consumed, g) == nil {
		t.Fatal("accepted consumed frame")
	}
	x = -1
	if validateDesktopGuard(c, g, g) == nil {
		t.Fatal("accepted negative coordinate")
	}
	x = g.Width
	if validateDesktopGuard(c, g, g) == nil {
		t.Fatal("accepted coordinate at right edge")
	}
}
func TestDesktopProtocolRejectsUnboundedOrAmbiguousInput(t *testing.T) {
	id := strings.Repeat("a", 32)
	valid := desktopCommand{ID: id, Op: "observe"}
	if err := validateDesktopCommand(valid); err != nil {
		t.Fatal(err)
	}
	for _, c := range []desktopCommand{{ID: id, Op: "shell"}, {ID: id, Op: "observe", WaitMS: 3001}, {ID: id, Op: "observe", DesktopAction: DesktopAction{Text: "ignored?"}}, {ID: id, Op: "act", FrameID: id, DesktopAction: DesktopAction{Action: "key", Key: "ENTER"}}, {ID: id, Op: "act", SessionID: 2, FrameID: id, DesktopAction: DesktopAction{Action: "key", Key: "CTRL+CTRL+A"}}, {ID: id, Op: "act", SessionID: 2, FrameID: id, DesktopAction: DesktopAction{Action: "type", Text: strings.Repeat("a", 1001)}}} {
		if validateDesktopCommand(c) == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
}
func TestDesktopForegroundExpectation(t *testing.T) {
	id := strings.Repeat("a", 32)
	run := &DesktopWindowMatch{Class: "#32770", Title: "run"}
	if err := matchDesktopForeground(run, "#32770", "Run"); err != nil {
		t.Fatal(err)
	}
	if err := matchDesktopForeground(&DesktopWindowMatch{Title: "pcb editor"}, "wxWindowNR", "*a120fc-bridge — PCB Editor"); err != nil {
		t.Fatal("title substring should match case-insensitively", err)
	}
	if err := matchDesktopForeground(nil, "anything", "at all"); err != nil {
		t.Fatal("no expectation must not block input", err)
	}
	err := matchDesktopForeground(run, "StencilWindow", "secret-title")
	if err == nil {
		t.Fatal("typed into the wrong window")
	}
	if strings.Contains(err.Error(), "secret-title") || !strings.Contains(err.Error(), "StencilWindow") {
		t.Fatal("refusal must name the class but keep the title out of the node log:", err)
	}
	if matchDesktopForeground(run, "#32770", "Save As") == nil {
		t.Fatal("class match alone accepted a mismatched title")
	}
	key := func(m *DesktopWindowMatch) desktopCommand {
		return desktopCommand{ID: id, Op: "act", SessionID: 2, FrameID: id, DesktopAction: DesktopAction{Action: "type", Text: "notepad", ExpectForeground: m}}
	}
	if err := validateDesktopCommand(key(run)); err != nil {
		t.Fatal(err)
	}
	for _, m := range []*DesktopWindowMatch{{}, {Class: strings.Repeat("c", 257)}, {Title: strings.Repeat("t", 513)}} {
		if validateDesktopCommand(key(m)) == nil {
			t.Fatalf("accepted expectation %+v", m)
		}
	}
	if validateDesktopCommand(desktopCommand{ID: id, Op: "observe", DesktopAction: DesktopAction{ExpectForeground: run}}) == nil {
		t.Fatal("observe accepted an input guard")
	}
}
func TestDesktopSettleRidesOutActivation(t *testing.T) {
	g := desktopGuard{Foreground: 0x10}
	// Taskbar restore: old window, a gap with no foreground, then the restored one.
	sequence := []uint64{0x10, 0x10, 0, 0, 0x20}
	calls := 0
	state := func() (desktopGuard, error) {
		live := g
		if calls < len(sequence) {
			live.Foreground = sequence[calls]
		} else {
			live.Foreground = 0x20
		}
		calls++
		if live.Foreground == 0 {
			return live, errDesktopNoForeground
		}
		return live, nil
	}
	if err := waitDesktopSettled(state, time.Millisecond, 20*time.Millisecond, 2*time.Second); err != nil {
		t.Fatal("transient activation gap failed a sent gesture:", err)
	}
	if calls <= len(sequence) {
		t.Fatal("returned before the restored window settled", calls)
	}
	broken := errors.New("active logon session changed")
	if err := waitDesktopSettled(func() (desktopGuard, error) { return g, broken }, time.Millisecond, 20*time.Millisecond, time.Second); err != broken {
		t.Fatal("real failures must still surface", err)
	}
	stuck := func() (desktopGuard, error) { return desktopGuard{}, errDesktopNoForeground }
	start := time.Now()
	if err := waitDesktopSettled(stuck, time.Millisecond, 5*time.Millisecond, 50*time.Millisecond); err != nil || time.Since(start) < 50*time.Millisecond {
		t.Fatal("a desktop with no foreground should wait out the limit and leave the verdict to the snapshot", err)
	}
}
