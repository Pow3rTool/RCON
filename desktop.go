package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// The broker handles caller authorization; the node independently validates all
// requests and binds input to a fresh observation of the selected logon session.
type DesktopAction struct {
	Action     string `json:"action"`
	Label      string `json:"label,omitempty"`
	Target     string `json:"target,omitempty"`
	X          *int   `json:"x,omitempty"`
	Y          *int   `json:"y,omitempty"`
	ToX        *int   `json:"to_x,omitempty"`
	ToY        *int   `json:"to_y,omitempty"`
	Button     string `json:"button,omitempty"`
	Axis       string `json:"axis,omitempty"`
	Steps      int    `json:"steps,omitempty"`
	DurationMS int    `json:"duration_ms,omitempty"`
	Key        string `json:"key,omitempty"`
	Text       string `json:"text,omitempty"`
	// Optional intent guard, checked against the live foreground just before input.
	ExpectForeground *DesktopWindowMatch `json:"expect_foreground,omitempty"`
}

// The frame guard only proves the foreground did not change since the frame.
// This names the window the caller means to reach (for example the Run dialog
// after WIN+R), so keys and text never land in whatever else took focus.
type DesktopWindowMatch struct {
	Class string `json:"class,omitempty"` // exact window class, case-insensitive
	Title string `json:"title,omitempty"` // case-insensitive substring of the title
}

type desktopCommand struct {
	ID        string `json:"id"`
	Op        string `json:"op"`
	SessionID uint32 `json:"session_id,omitempty"`
	FrameID   string `json:"frame_id,omitempty"`
	WaitMS    int    `json:"wait_ms,omitempty"`
	DesktopAction
	Interaction *DesktopInteraction `json:"interaction,omitempty"`
}
type desktopBounds struct{ X, Y, Width, Height int }
type desktopGuard struct {
	FrameID       string
	SessionID     uint32
	LogonID       string
	Created       time.Time
	Bounds        desktopBounds
	Width, Height int
	InputTick     uint32
	Foreground    uint64
}

func desktopID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

var desktopIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

func validateDesktopCommand(c desktopCommand) error {
	if !desktopIDPattern.MatchString(c.ID) {
		return errors.New("invalid request id")
	}
	if c.WaitMS < 0 || c.WaitMS > 3000 {
		return errors.New("wait_ms must be 0..3000")
	}
	if c.Op != "interact" && c.Interaction != nil {
		return errors.New("interaction fields require interact")
	}
	switch c.Op {
	case "interact":
		if c.DesktopAction != (DesktopAction{}) {
			return errors.New("interaction cannot contain legacy action fields")
		}
		if err := validateDesktopInteraction(c.Interaction); err != nil {
			return err
		}
		if !desktopIDPattern.MatchString(c.Interaction.ID) {
			return errors.New("valid interaction_id required")
		}
		if (c.Interaction.Operation == "begin" || c.Interaction.Operation == "continue") && (!desktopIDPattern.MatchString(c.FrameID) || c.SessionID == 0) {
			return errors.New("begin/continue require frame_id and session_id")
		}
	case "observe":
		if c.FrameID != "" || c.DesktopAction != (DesktopAction{}) {
			return errors.New("observe cannot contain input")
		}
	case "act":
		if !desktopIDPattern.MatchString(c.FrameID) || c.SessionID == 0 {
			return errors.New("act requires frame_id and session_id")
		}
		if c.Target != "" {
			return errors.New("node input requires explicit coordinates")
		}
		return validateDesktopAction(c.DesktopAction)
	default:
		return errors.New("unsupported desktop operation")
	}
	return nil
}
func validateDesktopGuard(c desktopCommand, old, live desktopGuard) error {
	if old.FrameID != c.FrameID || old.FrameID == "" {
		return errors.New("frame unavailable or consumed; observe again")
	}
	if time.Since(old.Created) > 180*time.Second || time.Until(old.Created) > time.Second {
		return errors.New("frame expired; observe again")
	}
	if old.SessionID != live.SessionID || old.LogonID != live.LogonID {
		return errors.New("logon session changed; observe again")
	}
	if old.Bounds != live.Bounds || old.Width != live.Width || old.Height != live.Height {
		return errors.New("desktop geometry changed; observe again")
	}
	if old.Foreground != live.Foreground {
		return fmt.Errorf("desktop foreground changed (%x -> %x); observe again", old.Foreground, live.Foreground)
	}
	// GetLastInputInfo includes RDP synchronization and other input that need
	// not change app state. It is diagnostic metadata, not an ownership gate.
	// Active workers monitor an explicit outside Escape press instead.
	for _, p := range [][2]*int{{c.X, c.Y}, {c.ToX, c.ToY}} {
		if p[0] != nil && (*p[0] < 0 || *p[0] >= old.Width || p[1] == nil || *p[1] < 0 || *p[1] >= old.Height) {
			return errors.New("pointer outside observed image")
		}
	}
	return nil
}

// The error names the class but not the title: titles are application content
// and stay out of the node's desktop log.
func matchDesktopForeground(m *DesktopWindowMatch, class, title string) error {
	if m == nil {
		return nil
	}
	if (m.Class == "" || strings.EqualFold(m.Class, class)) && (m.Title == "" || strings.Contains(strings.ToLower(title), strings.ToLower(m.Title))) {
		return nil
	}
	return fmt.Errorf("foreground window (class %q) does not match expect_foreground; input not sent, observe again", class)
}

var errDesktopNoForeground = errors.New("no usable foreground desktop; restore the RDP display or use the local console")

// Polls until focus and geometry hold still for settle, or limit passes. This is
// a bounded settling period, not proof that an asynchronous app task completed.
// Activating a window (taskbar restore, a dialog opening) briefly leaves no
// foreground window; that counts as motion, not failure, so a gesture that was
// sent does not come back as an error with no frame.
func waitDesktopSettled(state func() (desktopGuard, error), poll, settle, limit time.Duration) error {
	last, err := state()
	if err != nil && !errors.Is(err, errDesktopNoForeground) {
		return err
	}
	quiet := time.Now()
	deadline := quiet.Add(limit)
	for time.Now().Before(deadline) {
		time.Sleep(poll)
		live, err := state()
		if err != nil && !errors.Is(err, errDesktopNoForeground) {
			return err
		}
		if err != nil || last.Foreground != live.Foreground || last.Bounds != live.Bounds {
			quiet = time.Now()
			last = live
		}
		if err == nil && time.Since(quiet) >= settle {
			return nil
		}
	}
	return nil // still permit inspection; snapshot decides whether input is safe
}
func desktopFailure(id, status string, err error) map[string]any {
	return map[string]any{"id": id, "ok": false, "input_status": status, "error": err.Error()}
}
func desktopHandler(w http.ResponseWriter, r *http.Request) {
	var c desktopCommand
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 24000))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF {
		writeJSON(w, 400, desktopFailure(c.ID, "not_sent", errors.New("invalid desktop request")))
		return
	}
	if err := validateDesktopCommand(c); err != nil {
		writeJSON(w, 400, desktopFailure(c.ID, "not_sent", err))
		return
	}
	start := time.Now()
	auditRecord("desktop_dispatch", fmt.Sprintf("op=%s session=%d action=%s frame=%s text_bytes=%d", c.Op, c.SessionID, c.Action, c.FrameID, len(c.Text)), -1, 0, c.ID)
	out := nativeDesktop(c)
	// Text, window titles, and image data stay out of the node audit.
	detail := fmt.Sprintf("op=%s session=%d action=%s frame=%s text_bytes=%d input_status=%v", c.Op, c.SessionID, c.Action, c.FrameID, len(c.Text), out["input_status"])
	rc := 0
	if out["ok"] != true {
		rc = 1
	}
	auditRecord("desktop", detail, rc, time.Since(start).Seconds(), c.ID)
	writeJSON(w, 200, out)
}

var desktopBaseKey = regexp.MustCompile(`^(?:[A-Z0-9]|F(?:[1-9]|1[0-9]|2[0-4])|ENTER|RETURN|ESC|ESCAPE|TAB|SPACE|BACKSPACE|DELETE|DEL|INSERT|INS|HOME|END|PAGEUP|PGUP|PAGEDOWN|PGDN|UP|DOWN|LEFT|RIGHT)$`)

func validDesktopChord(key string) bool {
	if len(key) == 0 || len(key) > 64 || strings.IndexFunc(key, func(r rune) bool { return r > 127 }) >= 0 {
		return false
	}
	parts := strings.Split(strings.ToUpper(key), "+")
	if len(parts) > 5 {
		return false
	}
	seen := map[string]bool{}
	for i, raw := range parts {
		part := strings.TrimSpace(raw)
		if part == "CONTROL" {
			part = "CTRL"
		}
		modifier := part == "CTRL" || part == "ALT" || part == "SHIFT" || part == "WIN"
		if i == len(parts)-1 {
			return desktopBaseKey.MatchString(part) || (len(parts) == 1 && modifier)
		}
		if !modifier || seen[part] {
			return false
		}
		seen[part] = true
	}
	return false
}

func validateDesktopAction(a DesktopAction) error {
	if len(a.Label) > 200 || len(a.Target) > 500 {
		return errors.New("label or target too long")
	}
	if a.Button != "" && a.Button != "left" && a.Button != "right" && a.Button != "middle" {
		return errors.New("invalid mouse button")
	}
	pointer := a.Action == "click" || a.Action == "double_click" || a.Action == "move" || a.Action == "scroll" || a.Action == "drag"
	if pointer {
		if a.Target != "" {
			if a.X != nil || a.Y != nil {
				return errors.New("use target or coordinates, not both")
			}
		} else if a.X == nil || a.Y == nil {
			return errors.New("pointer action requires x/y or target")
		}
		if a.Key != "" || a.Text != "" {
			return errors.New("pointer action cannot include key/text")
		}
	} else if a.Target != "" || a.X != nil || a.Y != nil || a.Button != "" {
		return errors.New("key/type cannot include a pointer target")
	}
	if a.Action != "drag" && (a.ToX != nil || a.ToY != nil || a.DurationMS != 0) {
		return errors.New("drag fields require drag")
	}
	if a.Action != "scroll" && (a.Axis != "" || a.Steps != 0) {
		return errors.New("scroll fields require scroll")
	}
	if m := a.ExpectForeground; m != nil {
		if m.Class == "" && m.Title == "" {
			return errors.New("expect_foreground requires class and/or title")
		}
		if len(m.Class) > 256 || len(m.Title) > 512 {
			return errors.New("expect_foreground class or title too long")
		}
	}
	switch a.Action {
	case "click", "double_click", "move":
	case "scroll":
		if (a.Axis != "vertical" && a.Axis != "horizontal") || a.Steps == 0 || a.Steps < -20 || a.Steps > 20 {
			return errors.New("scroll requires axis and signed steps in -20..20")
		}
	case "drag":
		if a.ToX == nil || a.ToY == nil || a.DurationMS < 100 || a.DurationMS > 3000 {
			return errors.New("drag requires to_x/to_y and duration_ms 100..3000")
		}
	case "key":
		if !validDesktopChord(a.Key) || a.Text != "" {
			return errors.New("invalid key chord: use CTRL/ALT/SHIFT/WIN modifiers plus A-Z, 0-9, F1-F24 or a named navigation key (example CTRL+TAB); no held input across calls")
		}
	case "type":
		if a.Text == "" || len(a.Text) > 1000 || a.Key != "" {
			return errors.New("type requires 1..1000 bytes of text")
		}
	default:
		return errors.New("unsupported desktop action")
	}
	return nil
}
