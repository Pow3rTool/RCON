package main

import (
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
