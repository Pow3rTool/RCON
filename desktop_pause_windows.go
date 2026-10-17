package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"runtime"
	"time"
)

const desktopPausedLabel = "AI interrupted · click to resume"

type desktopPause struct {
	ID        string
	SessionID uint32
	LogonID   string
	Reason    string
	At        time.Time
}

func desktopPausePath() string { return windowsPath("state", "desktop-paused.json") }
func readDesktopPause() (*desktopPause, error) {
	raw, err := readSmallFile(desktopPausePath(), 4096)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p desktopPause
	if err = json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	if !desktopIDPattern.MatchString(p.ID) {
		return nil, errors.New("invalid desktop pause record")
	}
	return &p, nil
}
func latchDesktopPause(session desktopSession) error {
	return withDesktopPauseLock(func() error {
		if p, err := readDesktopPause(); err != nil || p != nil {
			return err
		}
		p := desktopPause{ID: desktopID(), SessionID: session.ID, LogonID: session.LogonID, Reason: "outside Escape triple-press", At: time.Now().UTC()}
		raw, err := json.Marshal(p)
		if err != nil {
			return err
		}
		if err := replaceFileAtomic(desktopPausePath(), raw, 0600); err != nil {
			return err
		}
		desktopPauseAudit("paused", p.ID, p.SessionID)
		return nil
	})
}

// Called only by the private indicator worker's badge click handler. There is
// deliberately no remote resume operation. An old badge cannot clear a new pause.
func clearDesktopPause(id string) error {
	return withDesktopPauseLock(func() error {
		p, err := readDesktopPause()
		if err != nil {
			return err
		}
		if p == nil || p.ID != id {
			return errors.New("pause changed; observe again")
		}
		if err := os.Remove(desktopPausePath()); err != nil {
			return err
		}
		desktopEvent("local-badge-resume", map[string]any{"pause_id": p.ID, "session_id": p.SessionID, "paused_ms": time.Since(p.At).Milliseconds()})
		return nil
	})
}
func desktopInputPaused(c desktopCommand) bool {
	// attach_console changes which session the console shows and launch starts
	// programs on the user's desktop, so a human's pause blocks them too.
	return c.Op == "act" || c.Op == "attach_console" || c.Op == "launch" || (c.Interaction != nil && c.Op == "interact" && (c.Interaction.Operation == "begin" || c.Interaction.Operation == "continue"))
}

// Serialize writers across the service, watchdogs and UI worker. Locking the OS
// thread is required because a Win32 mutex is owned by the acquiring thread.
func withDesktopPauseLock(fn func() error) error { return withDesktopNamedLock("Pause", fn) }

func withDesktopNamedLock(kind string, fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	hash := sha256.Sum256([]byte(windowsRoot))
	h, err := windows.CreateMutex(nil, false, windows.StringToUTF16Ptr(fmt.Sprintf(`Global\Pow3rTool-RCON-%s-%x`, kind, hash[:12])))
	if err != nil && err != windows.ERROR_ALREADY_EXISTS {
		return err
	}
	defer windows.CloseHandle(h)
	status, err := windows.WaitForSingleObject(h, 5000)
	if err != nil {
		return err
	}
	if status != windows.WAIT_OBJECT_0 && status != windows.WAIT_ABANDONED {
		return errors.New("pause-state lock timed out")
	}
	defer windows.ReleaseMutex(h)
	return fn()
}
func desktopPauseError() error {
	p, err := readDesktopPause()
	if err != nil {
		return fmt.Errorf("desktop pause state unavailable; input blocked: %w", err)
	}
	if p != nil {
		return fmt.Errorf("AI interrupted by %s (pause_id=%s); local badge click required", p.Reason, p.ID)
	}
	return nil
}
func desktopPauseAudit(action, id string, session uint32) {
	desktopEvent(action, map[string]any{"pause_id": id, "session_id": session})
}
