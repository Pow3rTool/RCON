package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"unsafe"
)

func TestDesktopSessionSelection(t *testing.T) {
	sessions := []desktopSession{{ID: 1}, {ID: 2}}
	if _, err := selectDesktopSession(sessions, 0); err == nil {
		t.Fatal("ambiguous session chosen")
	}
	if s, err := selectDesktopSession(sessions, 2); err != nil || s.ID != 2 {
		t.Fatal(s, err)
	}
	if s, err := selectDesktopSession(sessions[:1], 0); err != nil || s.ID != 1 {
		t.Fatal(s, err)
	}
	if _, err := selectDesktopSession(nil, 0); err == nil {
		t.Fatal("no session accepted")
	}
}
func TestDesktopNativeInputLayout(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) == 8 && unsafe.Sizeof(desktopInput{}) != 40 {
		t.Fatal("wrong INPUT layout", unsafe.Sizeof(desktopInput{}))
	}
}
func TestDesktopNativeIntegration(t *testing.T) {
	if os.Getenv("RCON_TEST_DESKTOP") != "1" {
		t.Skip("opt-in native capture and reversible cursor move")
	}
	observe := func() map[string]any {
		c := desktopCommand{ID: desktopID(), Op: "observe"}
		out := nativeDesktop(c)
		if out["ok"] != true {
			t.Fatalf("observe: %v", out)
		}
		image := out["image"].(map[string]any)
		data, err := base64.StdEncoding.DecodeString(image["data"].(string))
		if err != nil || len(data) < 1000 {
			t.Fatal("invalid image", err)
		}
		if path := os.Getenv("RCON_TEST_DESKTOP_OUTPUT"); path != "" {
			if err = os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
		}
		return out["observation"].(map[string]any)
	}
	obs := observe()
	raw, _ := json.Marshal(obs)
	t.Log(string(raw))
	sid := uint32(obs["session_id"].(float64))
	x, y := 0, 0
	// Moving to the existing cursor position tests SendInput without changing apps.
	cursor := obs["cursor"].(map[string]any)
	x, y = int(cursor["x"].(float64)), int(cursor["y"].(float64))
	if x < 0 || y < 0 || x >= int(obs["image_width"].(float64)) || y >= int(obs["image_height"].(float64)) {
		x, y = 20, 20
	}
	c := desktopCommand{ID: desktopID(), Op: "act", SessionID: sid, FrameID: obs["frame_id"].(string), DesktopAction: DesktopAction{Action: "move", X: &x, Y: &y}}
	out := nativeDesktop(c)
	if out["ok"] != true || out["input_status"] != "sent" {
		t.Fatalf("cursor move: %v", out)
	}
	if replay := nativeDesktop(c); replay["ok"] == true {
		t.Fatal("duplicate input dispatched")
	}
	c.ID = desktopID()
	if replay := nativeDesktop(c); replay["ok"] == true {
		t.Fatal("consumed frame dispatched")
	}
	observe()
}
