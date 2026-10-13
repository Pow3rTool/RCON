package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDesktopDiagnosticLogOmitsInputAndRotates(t *testing.T) {
	path := windowsPath("logs", "desktop-pause.jsonl")
	defer os.Remove(path)
	defer os.Remove(path + ".1")
	defer os.Remove(path + ".2")
	_ = os.Remove(path)
	desktopAuditCall(desktopCommand{ID: desktopID(), Op: "act", DesktopAction: DesktopAction{Action: "type", Text: "do-not-log-this-input"}}, map[string]any{"ok": true, "input_status": "sent"})
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "do-not-log") || strings.Contains(string(raw), "\"text\"") {
		t.Fatal("typed input leaked")
	}
	var row map[string]any
	if err = json.Unmarshal(raw, &row); err != nil {
		t.Fatal(err)
	}
	if row["action"] != "desktop-call" || row["pid"] == nil {
		t.Fatal(row)
	}
	for i := 0; i < 4; i++ {
		if err = os.WriteFile(path, bytes.Repeat([]byte("x"), desktopLogLimit), 0600); err != nil {
			t.Fatal(err)
		}
		desktopEvent("escape-tap", map[string]any{"burst_count": 3, "pause_requested": true})
	}
	for _, suffix := range []string{"", ".1", ".2"} {
		info, err := os.Stat(path + suffix)
		if err != nil || info.Size() > desktopLogLimit {
			t.Fatal(suffix, info, err)
		}
	}
	if _, err := os.Stat(path + ".3"); !os.IsNotExist(err) {
		t.Fatal("unbounded rotation")
	}
}

func TestDesktopEscapeLogCountsTapsWithoutAutorepeatOrOwnInput(t *testing.T) {
	desktopEscapeEvents = make(chan desktopEscapeEvent, 64)
	defer func() {
		desktopEscapeEvents = nil
		interactionEscapeSequence = desktopEscapeSequence{}
		interactionExternalInput.Store(false)
	}()
	interactionEscapeSequence = desktopEscapeSequence{}
	now := time.Now()
	for i := 0; i < 7; i++ {
		e := interactionKeyboardEvent{VK: 27}
		recordInteractionKey(0x100, &e, now.Add(time.Duration(i)*100*time.Millisecond))
		recordInteractionKey(0x100, &e, now.Add(time.Duration(i)*100*time.Millisecond)) // autorepeat
		e.Flags = 0x80
		recordInteractionKey(0x101, &e, now)
	}
	own := interactionKeyboardEvent{VK: 27, Flags: 0x10, Extra: desktopInputTag}
	recordInteractionKey(0x100, &own, now)
	own.Flags |= 0x80
	recordInteractionKey(0x101, &own, now)
	if len(desktopEscapeEvents) != 7 {
		t.Fatal("incorrect tap count", len(desktopEscapeEvents))
	}
	for i := 0; i < 7; i++ {
		tap := <-desktopEscapeEvents
		if tap.Count != i%3+1 || tap.PauseRequested != (i%3 == 2) {
			t.Fatal(i, tap)
		}
	}
}
