package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDesktopOutsideEscapePolicy(t *testing.T) {
	for _, c := range []struct {
		name               string
		message, vk, flags uint32
		tag                uintptr
		stop               bool
	}{
		{"physical Escape", 0x100, 27, 0, 0, true},
		{"RDP Escape", 0x100, 27, 0x10, 0, true},
		{"robot Escape", 0x100, 27, 0x10, desktopInputTag, false},
		{"Escape release synchronization", 0x101, 27, 0x80, 0, false},
		{"other key", 0x100, 65, 0, 0, false},
		{"other key release", 0x101, 65, 0x80, 0, false},
		{"mouse move", 0x200, 0, 0, 0, false},
		{"unmarked Escape with coincidental extra", 0x100, 27, 0, desktopInputTag, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := desktopStopKey(c.message, c.vk, c.flags, c.tag); got != c.stop {
				t.Fatalf("stop=%v want %v", got, c.stop)
			}
		})
	}
}

func TestDesktopInteractionOutsideEscapeReleasesAndLatches(t *testing.T) {
	if os.Getenv("RCON_TEST_PAUSE") != "1" {
		t.Skip("opt-in native held-input interruption using the registered test-only outside Escape fixture")
	}
	defer func() {
		if p, _ := readDesktopPause(); p != nil {
			_ = clearDesktopPause(p.ID)
		}
	}()
	obs := nativeDesktop(desktopCommand{ID: desktopID(), Op: "observe"})
	if obs["ok"] != true {
		t.Fatal(obs)
	}
	o := obs["observation"].(map[string]any)
	sid := uint32(o["session_id"].(float64))
	id := desktopID()
	begin := nativeDesktop(desktopCommand{ID: desktopID(), Op: "interact", SessionID: sid, FrameID: o["frame_id"].(string), Interaction: &DesktopInteraction{ID: id, Operation: "begin", Events: []DesktopInputEvent{{Type: "key_down", Key: "CTRL"}}}})
	defer nativeDesktop(desktopCommand{ID: desktopID(), Op: "interact", SessionID: sid, Interaction: &DesktopInteraction{ID: id, Operation: "cancel"}})
	if begin["ok"] != true {
		t.Fatal(begin)
	}
	if out, err := exec.Command("schtasks.exe", "/Run", "/TN", "RconEscapeFixture-20261005").CombinedOutput(); err != nil {
		t.Fatalf("fixture: %v %s", err, out)
	}
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if p, _ := readDesktopPause(); p != nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if p, err := readDesktopPause(); p == nil || err != nil {
		t.Fatalf("pause absent: %v", err)
	}
	time.Sleep(250 * time.Millisecond)
	end := nativeDesktop(desktopCommand{ID: desktopID(), Op: "interact", SessionID: sid, Interaction: &DesktopInteraction{ID: id, Operation: "observe"}})
	if end["released"] != true || !strings.Contains(fmt.Sprint(end["error"]), "outside Escape") {
		t.Fatalf("missing explicit release/cause: %v", end)
	}
	blocked := nativeDesktop(desktopCommand{ID: desktopID(), Op: "interact", SessionID: sid, FrameID: begin["observation"].(map[string]any)["frame_id"].(string), Interaction: &DesktopInteraction{ID: desktopID(), Operation: "begin"}})
	if blocked["paused"] != true || blocked["ok"] != false {
		t.Fatalf("retry bypassed pause: %v", blocked)
	}
	final := nativeDesktop(desktopCommand{ID: desktopID(), Op: "observe", SessionID: sid})
	if final["ok"] != true {
		t.Fatal(final)
	}
	for _, k := range final["observation"].(map[string]any)["pressed_virtual_keys"].([]any) {
		if k == float64(17) || k == float64(162) || k == float64(163) {
			t.Fatal("Ctrl stuck after interruption")
		}
	}
	t.Log("outside Escape released Ctrl, retained its reason, blocked retry, and allowed paused observation")
}
func TestDesktopPausePersistsUntilExactBadgeResume(t *testing.T) {
	old := windowsRoot
	windowsRoot = t.TempDir()
	defer func() { windowsRoot = old }()
	if err := os.MkdirAll(filepath.Join(windowsRoot, "state"), 0700); err != nil {
		t.Fatal(err)
	}
	session := desktopSession{ID: 2, LogonID: "test"}
	if err := latchDesktopPause(session); err != nil {
		t.Fatal(err)
	}
	p, err := readDesktopPause()
	if err != nil || p == nil {
		t.Fatal(p, err)
	}
	if err := latchDesktopPause(session); err != nil {
		t.Fatal(err)
	}
	if err := clearDesktopPause(desktopID()); err == nil {
		t.Fatal("stale badge cleared pause")
	}
	if q, _ := readDesktopPause(); q == nil || q.ID != p.ID {
		t.Fatal("pause changed on retry")
	}
	for _, op := range []string{"begin", "continue"} {
		if !desktopInputPaused(desktopCommand{Op: "interact", Interaction: &DesktopInteraction{Operation: op}}) {
			t.Fatal(op)
		}
	}
	for _, op := range []string{"observe", "release", "cancel"} {
		if desktopInputPaused(desktopCommand{Op: "interact", Interaction: &DesktopInteraction{Operation: op}}) {
			t.Fatal(op)
		}
	}
	if err := clearDesktopPause(p.ID); err != nil {
		t.Fatal(err)
	}
	if q, err := readDesktopPause(); q != nil || err != nil {
		t.Fatal(q, err)
	}
}

func TestDesktopSafetyIdleAndPersistentPause(t *testing.T) {
	if os.Getenv("RCON_TEST_PAUSE") != "1" {
		t.Skip("native idle pause test")
	}
	dir := os.Getenv("RCON_ESCAPE_FIXTURE_DIR")
	if dir == "" {
		t.Fatal("RCON_ESCAPE_FIXTURE_DIR required")
	}
	stop := startDesktopSafetySupervisor()
	defer stop()
	sessions, err := desktopSessions()
	if err != nil || len(sessions) != 1 {
		t.Fatal(sessions, err)
	}
	if err := ensureDesktopSafety(sessions[0]); err != nil {
		t.Fatal(err)
	}
	trigger := func(n int) {
		t.Helper()
		_ = os.Remove(filepath.Join(dir, "escape-result.txt"))
		if err := os.WriteFile(filepath.Join(dir, "escape-count.txt"), []byte(fmt.Sprint(n)), 0644); err != nil {
			t.Fatal(err)
		}
		if out, e := exec.Command("schtasks.exe", "/Run", "/TN", "RconEscapeFixture-20261005").CombinedOutput(); e != nil {
			t.Fatal(e, string(out))
		}
		until := time.Now().Add(6 * time.Second)
		for time.Now().Before(until) {
			if b, e := os.ReadFile(filepath.Join(dir, "escape-result.txt")); e == nil {
				if !strings.Contains(string(b), "result=<nil>") {
					t.Fatal(string(b))
				}
				time.Sleep(150 * time.Millisecond)
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal("fixture did not finish")
	}
	defer os.Remove(filepath.Join(dir, "escape-count.txt"))
	defer func() {
		if p, _ := readDesktopPause(); p != nil {
			_ = clearDesktopPause(p.ID)
		}
	}()
	trigger(1)
	if p, e := readDesktopPause(); p != nil || e != nil {
		t.Fatal("single Escape paused", p, e)
	}
	time.Sleep(1600 * time.Millisecond)
	trigger(2)
	if p, e := readDesktopPause(); p != nil || e != nil {
		t.Fatal("double Escape paused", p, e)
	}
	time.Sleep(1600 * time.Millisecond)
	trigger(3)
	pause, err := readDesktopPause()
	if pause == nil || err != nil {
		t.Fatal("idle triple did not persist", pause, err)
	}
	t.Log("idle single/double ignored, triple latched; waiting past former gesture lease")
	time.Sleep(65 * time.Second)
	if current, e := readDesktopPause(); e != nil || current == nil || current.ID != pause.ID {
		t.Fatal("pause expired", current, e)
	}
	blocked := nativeDesktop(desktopCommand{ID: desktopID(), Op: "interact", SessionID: sessions[0].ID, Interaction: &DesktopInteraction{ID: desktopID(), Operation: "begin"}})
	if blocked["paused"] != true || blocked["ok"] != false {
		t.Fatal("pause admission bypass", blocked)
	}
	// Restart the passive worker without deleting durable state.
	desktopSafety.Lock()
	c := desktopSafety.clients[sessions[0].ID]
	c.cancel()
	desktopSafety.Unlock()
	select {
	case <-c.done:
	case <-time.After(6 * time.Second):
		t.Fatal("watcher did not stop")
	}
	if err := ensureDesktopSafety(sessions[0]); err != nil {
		t.Fatal(err)
	}
	if current, _ := readDesktopPause(); current == nil || current.ID != pause.ID {
		t.Fatal("watcher restart cleared pause")
	}
	t.Log("pause survived 65 seconds and watcher restart; new input still blocked")
}

func TestDesktopSafetyWatcherLifecycle(t *testing.T) {
	if os.Getenv("RCON_TEST_PAUSE") != "1" {
		t.Skip("native watcher test")
	}
	sessions, err := desktopSessions()
	if err != nil || len(sessions) != 1 {
		t.Fatal(sessions, err)
	}
	session := sessions[0]
	if err := ensureDesktopSafety(session); err != nil {
		t.Fatal(err)
	}
	desktopSafety.Lock()
	c := desktopSafety.clients[session.ID]
	desktopSafety.Unlock()
	c.cancel()
	select {
	case <-c.done:
	case <-time.After(6 * time.Second):
		t.Fatal("watcher cancellation leaked worker")
	}
	if err := ensureDesktopSafety(session); err != nil {
		t.Fatal(err)
	}
	desktopSafety.Lock()
	next := desktopSafety.clients[session.ID]
	desktopSafety.Unlock()
	if next == c {
		t.Fatal("dead worker reused")
	}
	next.cancel()
	select {
	case <-next.done:
	case <-time.After(6 * time.Second):
		t.Fatal("replacement watcher did not stop")
	}
	t.Log("passive watcher starts without foreground desktop, cancels and restarts")
}
