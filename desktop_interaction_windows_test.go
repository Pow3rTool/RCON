package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"
)

func TestDesktopInteractionHeldStateValidation(t *testing.T) {
	w := desktopInteractionWorker{guard: desktopGuard{Width: 100, Height: 100}, keys: []interactionHeldKey{{VK: 17, Name: "CTRL"}}, buttons: []string{"left"}}
	p := 150
	for _, events := range [][]DesktopInputEvent{
		{{Type: "key_down", Key: "CTRL"}}, {{Type: "key_press", Key: "CTRL"}}, {{Type: "key_up", Key: "ALT"}},
		{{Type: "button_down", Button: "left"}}, {{Type: "button_up", Button: "right"}}, {{Type: "move", X: &p, Y: &p}},
	} {
		if err := w.validateEvents(events); err == nil {
			t.Fatalf("unsafe events accepted: %+v", events)
		}
	}
	if err := w.validateEvents([]DesktopInputEvent{{Type: "key_press", Key: "TAB"}, {Type: "key_up", Key: "CTRL"}, {Type: "button_up", Button: "left"}}); err != nil {
		t.Fatal(err)
	}
}
func TestDesktopInteractionLifecycle(t *testing.T) {
	if os.Getenv("RCON_TEST_INTERACTION") != "1" {
		t.Skip("opt-in real session test: holds CTRL, moves cursor, captures frames, releases")
	}
	observe := func() map[string]any {
		out := nativeDesktop(desktopCommand{ID: desktopID(), Op: "observe"})
		if out["ok"] != true {
			t.Fatalf("observe: %v", out)
		}
		return out["observation"].(map[string]any)
	}
	held := func(obs map[string]any) bool {
		for _, v := range obs["pressed_virtual_keys"].([]any) {
			if v == float64(17) || v == float64(162) || v == float64(163) {
				return true
			}
		}
		return false
	}
	begin := func(lease int, events []DesktopInputEvent) (map[string]any, string, uint32) {
		obs := observe()
		id := desktopID()
		sid := uint32(obs["session_id"].(float64))
		c := desktopCommand{ID: desktopID(), Op: "interact", FrameID: obs["frame_id"].(string), SessionID: sid, Interaction: &DesktopInteraction{ID: id, Operation: "begin", LeaseMS: lease, Events: events}}
		out := nativeDesktop(c)
		if out["ok"] != true {
			t.Fatalf("begin: %v", out)
		}
		t.Logf("thinking id=%s expires=%v held=%v", id, out["expires_at"], out["held_keys"])
		return out, id, sid
	}
	cleanup := func(id string, sid uint32) {
		nativeDesktop(desktopCommand{ID: desktopID(), Op: "interact", SessionID: sid, Interaction: &DesktopInteraction{ID: id, Operation: "cancel"}})
	}
	out, id, sid := begin(60000, []DesktopInputEvent{{Type: "key_down", Key: "CTRL"}, {Type: "capture"}})
	defer cleanup(id, sid)
	if out["interaction_state"] != "thinking" || !held(out["observation"].(map[string]any)) {
		t.Fatal("CTRL not held at checkpoint")
	}
	if dir := os.Getenv("RCON_TEST_INTERACTION_OUTPUT"); dir != "" {
		_ = os.MkdirAll(dir, 0700)
		raw, _ := json.Marshal(out)
		_ = os.WriteFile(filepath.Join(dir, "thinking.json"), raw, 0600)
		im := out["image"].(map[string]any)
		b, _ := base64.StdEncoding.DecodeString(im["data"].(string))
		_ = os.WriteFile(filepath.Join(dir, "thinking.jpg"), b, 0600)
	}
	// Stale input must end the interaction and release CTRL, rather than execute.
	bad := nativeDesktop(desktopCommand{ID: desktopID(), Op: "interact", SessionID: sid, FrameID: desktopID(), Interaction: &DesktopInteraction{ID: id, Operation: "continue", Events: []DesktopInputEvent{{Type: "key_press", Key: "TAB"}}}})
	if bad["ok"] != false || bad["released"] != true {
		t.Fatal("stale checkpoint did not release", bad)
	}
	time.Sleep(300 * time.Millisecond)
	if held(observe()) {
		t.Fatal("CTRL stuck after refusal")
	}
	// Autonomous timeout, without any follow-up input or API call.
	_, id, sid = begin(1000, []DesktopInputEvent{{Type: "key_down", Key: "CTRL"}})
	time.Sleep(2200 * time.Millisecond)
	if held(observe()) {
		t.Fatal("CTRL stuck after timeout")
	}
	t.Log("timeout released CTRL")
	// Simulate service connection loss; the worker must survive the pipe close
	// long enough to send key-up, not get killed with a job handle.
	_, id, sid = begin(60000, []DesktopInputEvent{{Type: "key_down", Key: "CTRL"}})
	desktopManager.Lock()
	client := activeDesktopInteraction
	client.cancel()
	desktopManager.Unlock()
	select {
	case <-client.done:
	case <-time.After(5 * time.Second):
		t.Fatal("pipe did not close")
	}
	time.Sleep(1200 * time.Millisecond)
	if held(observe()) {
		t.Fatal("CTRL stuck after pipe loss")
	}
	t.Log("pipe loss released CTRL")
	// A sampled pointer move does not click or edit the foreground app.
	obs := observe()
	cursor := obs["cursor"].(map[string]any)
	x, y := int(cursor["x"].(float64)), int(cursor["y"].(float64))
	x = max(0, min(x, int(obs["image_width"].(float64))-1))
	y = max(0, min(y, int(obs["image_height"].(float64))-1))
	to := x + 40
	if to >= int(obs["image_width"].(float64)) {
		to = x - 40
	}
	to = max(0, to)
	out, id, sid = begin(60000, []DesktopInputEvent{{Type: "move", X: &to, Y: &y, DurationMS: 600, Samples: 3}, {Type: "move", X: &x, Y: &y, DurationMS: 200}})
	if len(out["frames"].([]any)) != 3 {
		t.Fatal("missing movement frames")
	}
	last := -1.0
	for _, f := range out["frames"].([]any) {
		o := f.(map[string]any)["observation"].(map[string]any)
		elapsed := o["elapsed_ms"].(float64)
		if elapsed <= last || o["actionable"] != false {
			t.Fatal("bad intermediate frame", o)
		}
		last = elapsed
	}
	end := nativeDesktop(desktopCommand{ID: desktopID(), Op: "interact", SessionID: sid, Interaction: &DesktopInteraction{ID: id, Operation: "release"}})
	if end["released"] != true {
		t.Fatal(end)
	}
	t.Log(fmt.Sprintf("three intermediate motion frames + final checkpoint; release confirmed"))
}

func TestDesktopInteractionKiCadMenu(t *testing.T) {
	if os.Getenv("RCON_TEST_KICAD_MENU") != "1" {
		t.Skip("opt-in Ctrl+Tab menu test; changes view only")
	}
	call := func(c desktopCommand) map[string]any {
		out := nativeDesktop(c)
		if out["ok"] != true {
			t.Fatalf("%+v", out)
		}
		return out
	}
	obs := call(desktopCommand{ID: desktopID(), Op: "observe"})["observation"].(map[string]any)
	if !strings.Contains(obs["foreground"].(map[string]any)["title"].(string), "PCB Editor") {
		t.Fatal("PCB Editor is not foreground")
	}
	id := desktopID()
	sid := uint32(obs["session_id"].(float64))
	defer nativeDesktop(desktopCommand{ID: desktopID(), Op: "interact", SessionID: sid, Interaction: &DesktopInteraction{ID: id, Operation: "cancel"}})
	out := call(desktopCommand{ID: desktopID(), Op: "interact", SessionID: sid, FrameID: obs["frame_id"].(string), Interaction: &DesktopInteraction{ID: id, Operation: "begin", Events: []DesktopInputEvent{{Type: "key_down", Key: "CTRL"}, {Type: "wait", DurationMS: 150}, {Type: "key_press", Key: "TAB"}, {Type: "wait", DurationMS: 300}}}})
	t.Log("first Tab checkpoint held", out["held_keys"])
	time.Sleep(10000 * time.Millisecond)
	out = call(desktopCommand{ID: desktopID(), Op: "interact", SessionID: sid, FrameID: out["observation"].(map[string]any)["frame_id"].(string), Interaction: &DesktopInteraction{ID: id, Operation: "continue", Events: []DesktopInputEvent{{Type: "key_press", Key: "TAB"}, {Type: "wait", DurationMS: 200}}}})
	t.Log("second Tab checkpoint held", out["held_keys"])
	// Reverse the highlight and release, leaving the original preset selected.
	out = call(desktopCommand{ID: desktopID(), Op: "interact", SessionID: sid, FrameID: out["observation"].(map[string]any)["frame_id"].(string), Interaction: &DesktopInteraction{ID: id, Operation: "continue", Events: []DesktopInputEvent{{Type: "key_down", Key: "SHIFT"}, {Type: "key_press", Key: "TAB"}, {Type: "key_up", Key: "SHIFT"}, {Type: "wait", DurationMS: 200}}}})
	call(desktopCommand{ID: desktopID(), Op: "interact", SessionID: sid, Interaction: &DesktopInteraction{ID: id, Operation: "release"}})
}

//go:noinline
func copiedDesktopInputForTest(i desktopInput) desktopInput { return i }
func TestDesktopKeyboardMarkerSurvivesUnionCopy(t *testing.T) {
	input := desktopInput{Type: 1}
	key := (*desktopKeyboardInput)(unsafe.Pointer(&input.Data))
	marker := ^uintptr(0) - 12345
	*key = desktopKeyboardInput{VK: 9, Flags: 2, Extra: marker}
	copied := copiedDesktopInputForTest(input)
	actual := (*desktopKeyboardInput)(unsafe.Pointer(&copied.Data))
	if actual.Extra != marker || actual.VK != 9 || actual.Flags != 2 {
		t.Fatalf("keyboard INPUT union corrupted on copy: got %+v, marker %x", *actual, marker)
	}
}
