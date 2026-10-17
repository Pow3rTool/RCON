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
	// wait only: the condition, and the window it refers to. DurationMS is the timeout.
	Until  string              `json:"until,omitempty"`
	Window *DesktopWindowMatch `json:"window,omitempty"`
}

// The conditions a wait can poll for without taking screenshots.
var desktopWaitConditions = map[string]bool{"window": true, "window_gone": true, "foreground": true, "foreground_changed": true, "cursor_idle": true}

// Runs Windows PowerShell 5.1 as the session's logged-on user. Wait captures
// output, bounded so the broker's receipt deadline is never at risk.
type DesktopLaunch struct {
	Command   string `json:"command"`
	Directory string `json:"directory,omitempty"`
	Wait      bool   `json:"wait,omitempty"`
	TimeoutMS int    `json:"timeout_ms,omitempty"`
}

const desktopLaunchMaxTimeoutMS = 45000

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
	// attach_console only: allow disconnecting a connected client or console user.
	Force  bool           `json:"force,omitempty"`
	Launch *DesktopLaunch `json:"launch,omitempty"`
}

// Every logged-on session, including ones no tool can drive right now, so a
// caller sees why a desktop is unavailable instead of guessing at Win32 errors.
type desktopSessionState struct {
	ID      uint32 `json:"session_id"`
	User    string `json:"user"`
	Station string `json:"station,omitempty"`
	State   string `json:"state"` // active, disconnected, connected, ...
	Console bool   `json:"console"`
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
	if c.Force && c.Op != "attach_console" {
		return errors.New("force only applies to attach_console")
	}
	if (c.Launch != nil) != (c.Op == "launch") {
		return errors.New("launch requires its launch fields and nothing else does")
	}
	switch c.Op {
	case "lock":
		if c.FrameID != "" || c.WaitMS != 0 || c.DesktopAction != (DesktopAction{}) {
			return errors.New("lock takes only an optional session_id")
		}
	case "recover":
		if c.SessionID != 0 || c.FrameID != "" || c.WaitMS != 0 || c.DesktopAction != (DesktopAction{}) {
			return errors.New("recover takes no session, frame or input; it only signs in the configured recovery account when nobody is logged on")
		}
	case "wait":
		if c.FrameID != "" || c.Action != "wait" {
			return errors.New("wait takes a wait action and no frame")
		}
		return validateDesktopAction(c.DesktopAction)
	case "launch":
		if c.FrameID != "" || c.DesktopAction != (DesktopAction{}) {
			return errors.New("launch takes no frame or input")
		}
		return validateDesktopLaunch(*c.Launch)
	case "attach_console":
		if c.SessionID == 0 || c.FrameID != "" || c.DesktopAction != (DesktopAction{}) {
			return errors.New("attach_console requires session_id and no frame or input")
		}
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
		if c.Action == "wait" {
			return errors.New("wait is its own operation, not an act")
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

func desktopWindowMatches(m *DesktopWindowMatch, class, title string) bool {
	return (m.Class == "" || strings.EqualFold(m.Class, class)) && (m.Title == "" || strings.Contains(strings.ToLower(title), strings.ToLower(m.Title)))
}

// The error names the class but not the title: titles are application content
// and stay out of the node's desktop log.
func matchDesktopForeground(m *DesktopWindowMatch, class, title string) error {
	if m == nil || desktopWindowMatches(m, class, title) {
		return nil
	}
	return fmt.Errorf("foreground window (class %q) does not match expect_foreground; input not sent, observe again", class)
}

type desktopWindowInfo struct {
	HWND         uint64
	Class, Title string
}

// One poll of a wait: windows are the visible, uncloaked top-level windows;
// start is the foreground when the wait began.
func desktopWaitMet(a DesktopAction, foreground desktopWindowInfo, windows []desktopWindowInfo, start uint64, cursorBusy bool) bool {
	present := false
	for _, w := range windows {
		if a.Window != nil && desktopWindowMatches(a.Window, w.Class, w.Title) {
			present = true
		}
	}
	switch a.Until {
	case "window":
		return present
	case "window_gone":
		return !present
	case "foreground":
		return foreground.HWND != 0 && desktopWindowMatches(a.Window, foreground.Class, foreground.Title)
	case "foreground_changed":
		return foreground.HWND != 0 && foreground.HWND != start
	case "cursor_idle":
		return !cursorBusy
	}
	return false
}

func validateDesktopLaunch(l DesktopLaunch) error {
	if l.Command == "" || len(l.Command) > 8000 || strings.ContainsRune(l.Command, 0) {
		return errors.New("launch command must be 1..8000 bytes")
	}
	if len(l.Directory) > 1024 || strings.ContainsRune(l.Directory, 0) {
		return errors.New("launch directory too long")
	}
	if l.Wait && (l.TimeoutMS < 1000 || l.TimeoutMS > desktopLaunchMaxTimeoutMS) {
		return fmt.Errorf("launch with wait needs timeout_ms 1000..%d; use remote_jobs for longer work", desktopLaunchMaxTimeoutMS)
	}
	if !l.Wait && l.TimeoutMS != 0 {
		return errors.New("timeout_ms applies only with wait")
	}
	return nil
}

var errDesktopNoForeground = errors.New("no usable foreground desktop; restore the RDP display or use the local console")

// Explains why a desktop cannot be observed or driven: a stable code and what
// would fix it. Returns "" for failures that are not about desktop availability.
func desktopUnavailable(all []desktopSessionState, id uint32, failure string) (string, string) {
	switch {
	case strings.Contains(failure, errDesktopNoForeground.Error()):
		for _, s := range all {
			if s.ID == id && strings.HasPrefix(strings.ToUpper(s.Station), "RDP-") {
				return "rdp_display_suppressed", "This session's RDP client is minimized or not drawing, so Windows renders nothing, not even for the user's own programs. Ask its user to restore the window (or set RemoteDesktop_SuppressWhenMinimized=2, a DWORD under HKCU\\Software\\Microsoft\\Terminal Server Client, on their client), or call desktop_attach_console with force=true, which disconnects that client and shows the session on the console."
			}
		}
		return "no_foreground", "No window has focus (display switching, off or blank). Observe again in a moment; if it persists, check the console."
	case strings.Contains(failure, "locked or secure desktop"), strings.Contains(failure, "input desktop unavailable"):
		return "locked_or_secure_desktop", "The session is locked or showing a secure desktop (UAC, sign-in). These tools cannot unlock or answer it; a human must."
	case !strings.Contains(failure, "no active logged-on Windows session") && !strings.Contains(failure, "select an active session_id"):
		return "", ""
	}
	var requested *desktopSessionState
	active, disconnected := 0, 0
	for i, s := range all {
		if id != 0 && s.ID == id {
			requested = &all[i]
		}
		switch s.State {
		case "active":
			active++
		case "disconnected":
			disconnected++
		}
	}
	disconnectedHint := "The session is logged on but disconnected, so it has no display. Reconnect its RDP client, or call desktop_attach_console with its session_id to show it on the console (same user and running programs)."
	switch {
	case requested != nil && requested.State == "disconnected":
		return "session_disconnected", disconnectedHint
	case requested != nil && requested.State != "active":
		return "session_not_active", "That session is " + requested.State + ", not active. Pick an active session_id from sessions."
	case requested == nil && id != 0:
		return "session_not_found", "No logged-on session has that session_id; pick one from sessions."
	case id == 0 && active > 1:
		return "session_ambiguous", "Several sessions are active; pass session_id from sessions."
	case id == 0 && active == 0 && disconnected > 0:
		return "session_disconnected", disconnectedHint
	case id == 0 && active == 0:
		return "no_user_session", "Nobody is logged on. These tools do not log in; a human must sign in at the console or over RDP."
	}
	return "", ""
}

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
	if a.Action != "drag" && (a.ToX != nil || a.ToY != nil || (a.DurationMS != 0 && a.Action != "wait")) {
		return errors.New("drag fields require drag")
	}
	if a.Action != "wait" && (a.Until != "" || a.Window != nil) {
		return errors.New("until/window require a wait")
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
	case "wait":
		if !desktopWaitConditions[a.Until] {
			return errors.New("wait until must be window, window_gone, foreground, foreground_changed or cursor_idle")
		}
		needsWindow := a.Until == "window" || a.Until == "window_gone" || a.Until == "foreground"
		if needsWindow != (a.Window != nil) {
			return errors.New("window, window_gone and foreground need window {class,title}; the others take none")
		}
		if m := a.Window; m != nil && ((m.Class == "" && m.Title == "") || len(m.Class) > 256 || len(m.Title) > 512) {
			return errors.New("wait window needs a class and/or title (class <= 256, title <= 512 bytes)")
		}
		if a.DurationMS < 100 || a.DurationMS > 15000 || a.Key != "" || a.Text != "" || a.ExpectForeground != nil {
			return errors.New("wait takes duration_ms 100..15000 as its timeout and no keys, text or expect_foreground")
		}
	default:
		return errors.New("unsupported desktop action")
	}
	return nil
}
