package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

const desktopLogLimit = 1 << 20

// All writers serialize rotation and one-line append across native workers.
// Keyboard callbacks never call this: their records use a bounded queue.
func desktopEvent(action string, fields map[string]any) {
	if fields == nil {
		fields = map[string]any{}
	}
	fields["at"], fields["action"], fields["pid"] = time.Now().UTC(), action, os.Getpid()
	_ = withDesktopNamedLock("DesktopLog", func() error {
		path := windowsPath("logs", "desktop-pause.jsonl")
		if stat, err := os.Stat(path); err == nil && stat.Size() >= desktopLogLimit {
			_ = os.Remove(path + ".2")
			_ = os.Rename(path+".1", path+".2")
			if err = os.Rename(path, path+".1"); err != nil {
				return err
			}
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return err
		}
		defer f.Close()
		return json.NewEncoder(f).Encode(fields)
	})
}
func desktopAuditCall(c desktopCommand, result map[string]any) {
	f := map[string]any{"request_id": c.ID, "op": c.Op, "session_id": c.SessionID}
	if c.Interaction != nil {
		f["operation"] = c.Interaction.Operation
		f["interaction_id"] = c.Interaction.ID
	}
	for _, k := range []string{"ok", "input_status", "interaction_id", "interaction_state", "released", "paused", "pause_error", "error"} {
		if v, ok := result[k]; ok {
			f[k] = v
		}
	}
	// Keep pathological error text bounded and never serialize tool input arrays.
	if s, ok := f["error"].(string); ok && len(s) > 4096 {
		f["error"] = fmt.Sprintf("%.4096s [truncated]", s)
	}
	desktopEvent("desktop-call", f)
}
