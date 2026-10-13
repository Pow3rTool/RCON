package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Only desktopManager owns the service-side pointer and sends commands.
var activeDesktopInteraction *desktopInteractionClient

type desktopInteractionEnd struct {
	ID        string
	SessionID uint32
	Reason    string
	Released  bool
	Paused    bool
	At        time.Time
}

var endedDesktopInteractions = map[string]desktopInteractionEnd{}

func rememberDesktopEnd(c *desktopInteractionClient) {
	if c.end == nil {
		return
	}
	for id, e := range endedDesktopInteractions {
		if time.Since(e.At) > 180*time.Second {
			delete(endedDesktopInteractions, id)
		}
	}
	if len(endedDesktopInteractions) >= 16 {
		for id := range endedDesktopInteractions {
			delete(endedDesktopInteractions, id)
			break
		}
	}
	endedDesktopInteractions[c.id] = *c.end
}
func desktopEndedReceipt(id string, e desktopInteractionEnd) map[string]any {
	out := desktopFailure(id, "not_sent", errors.New(e.Reason))
	out["interaction_id"], out["interaction_state"], out["released"], out["paused"], out["ended_at"] = e.ID, "ended", e.Released, e.Paused, e.At
	return out
}

type desktopInteractionClient struct {
	id      string
	session desktopSession
	conn    net.Conn
	replies chan desktopWorkerResponse
	done    chan struct{}
	cancel  context.CancelFunc
	err     error
	end     *desktopInteractionEnd // published by closing done
}

func (c *desktopInteractionClient) receive() (desktopWorkerResponse, error) {
	select {
	case r := <-c.replies:
		return r, nil
	case <-c.done:
		select {
		case r := <-c.replies:
			return r, nil
		default:
		}
		return desktopWorkerResponse{}, fmt.Errorf("interaction ended and input release requested: %w", c.err)
	case <-time.After(35 * time.Second):
		c.cancel()
		return desktopWorkerResponse{}, errors.New("interaction response timed out; input release requested")
	}
}
func startDesktopInteraction(req desktopWorkerRequest) *desktopInteractionClient {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	c := &desktopInteractionClient{id: req.Command.Interaction.ID, session: req.Session, replies: make(chan desktopWorkerResponse, 1), done: make(chan struct{}), cancel: cancel}
	go func() {
		c.err = withDesktopWorker(ctx, req, func(conn net.Conn) error {
			c.conn = conn
			// Keep reading so a worker expiry/EOF is noticed even with no new HTTP call.
			_ = conn.SetDeadline(time.Time{})
			dec := json.NewDecoder(io.LimitReader(conn, 128<<20))
			for {
				var response desktopWorkerResponse
				if err := dec.Decode(&response); err != nil {
					return err
				}
				if response.End != nil {
					if response.End.ID != c.id || response.End.SessionID != c.session.ID {
						return errors.New("invalid terminal interaction receipt")
					}
					c.end = response.End
					return errors.New(c.end.Reason)
				}
				select {
				case c.replies <- response:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		})
		cancel()
		close(c.done)
		desktopManager.Lock()
		defer desktopManager.Unlock()
		rememberDesktopEnd(c)
		if c.end != nil {
			desktopEvent("interaction-ended", map[string]any{"interaction_id": c.id, "session_id": c.session.ID, "reason": c.end.Reason, "released": c.end.Released, "paused": c.end.Paused})
		}
		if activeDesktopInteraction == c {
			activeDesktopInteraction = nil
			delete(desktopManager.frames, c.session.ID)
			_ = setDesktopIndicator(c.session, "AI idle")
		}
	}()
	return c
}
func nativeDesktopInteraction(command desktopCommand) map[string]any {
	fail := func(err error) map[string]any { return desktopFailure(command.ID, "not_sent", err) }
	spec := command.Interaction
	c := activeDesktopInteraction
	if c != nil {
		select {
		case <-c.done:
			rememberDesktopEnd(c)
			activeDesktopInteraction = nil
			c = nil
		default:
		}
	}
	var response desktopWorkerResponse
	var err error
	if spec.Operation == "begin" {
		if c != nil {
			return fail(errors.New("an interaction already owns this desktop"))
		}
		sessions, e := desktopSessions()
		if e != nil {
			return fail(e)
		}
		session, e := selectDesktopSession(sessions, command.SessionID)
		if e != nil {
			return fail(e)
		}
		if e := ensureDesktopSafety(session); e != nil {
			return fail(e)
		}
		previous := desktopManager.frames[session.ID]
		if previous.FrameID != command.FrameID || previous.LogonID != session.LogonID {
			return fail(errors.New("frame unavailable, consumed, or session changed; observe again"))
		}
		delete(desktopManager.frames, session.ID)
		if activeDesktopIndicator != nil {
			activeDesktopIndicator.cancel()
			select {
			case <-activeDesktopIndicator.done:
			case <-time.After(6 * time.Second):
				return fail(errors.New("previous indicator failed to stop"))
			}
			activeDesktopIndicator = nil
		}
		c = startDesktopInteraction(desktopWorkerRequest{Command: command, Previous: previous, Session: session, Interaction: true})
		activeDesktopInteraction = c
	} else {
		if c == nil || c.id != spec.ID {
			if end, ok := endedDesktopInteractions[spec.ID]; ok && time.Since(end.At) <= 180*time.Second {
				return desktopEndedReceipt(command.ID, end)
			}
			return fail(errors.New("interaction unavailable; its terminal receipt is no longer retained; observe again"))
		}
		if command.SessionID != 0 && command.SessionID != c.session.ID {
			return fail(errors.New("interaction session mismatch"))
		}
		_ = c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		err = json.NewEncoder(c.conn).Encode(command)
	}
	if err == nil {
		response, err = c.receive()
	}
	if err != nil {
		c.cancel()
		select {
		case <-c.done:
			if c.end != nil {
				rememberDesktopEnd(c)
				return desktopEndedReceipt(command.ID, *c.end)
			}
		default:
		}
		return desktopFailure(command.ID, "unknown", err)
	}
	if response.Result == nil || response.Result["id"] != command.ID {
		c.cancel()
		return desktopFailure(command.ID, "unknown", errors.New("invalid interaction receipt; releasing input"))
	}
	if response.Guard.FrameID != "" {
		desktopManager.frames[c.session.ID] = response.Guard
	}
	if response.Result["interaction_state"] != "thinking" {
		c.cancel()
		activeDesktopInteraction = nil
		_ = setDesktopIndicator(c.session, "AI idle")
	}
	return response.Result
}

// RCON marks its SendInput events. Only an outside Escape key-down requests
// interruption; pointer noise, redundant key-ups, and other keys do not.
// Foreground/session/geometry checks and bounded leases are independent.
var interactionExternalInput atomic.Bool
var interactionExternalEvent atomic.Uint64
var interactionExternalTagLowMatches atomic.Bool

type interactionKeyboardEvent struct {
	VK, Scan, Flags, Time uint32
	Extra                 uintptr
}
type interactionMouseEvent struct {
	X, Y              int32
	Data, Flags, Time uint32
	Extra             uintptr
}

var interactionEscapeSequence desktopEscapeSequence

var interactionKeyboardHook = windows.NewCallback(func(code int32, wparam uintptr, event *interactionKeyboardEvent) uintptr {
	if code >= 0 {
		recordInteractionKey(uint32(wparam), event, time.Now())
	}
	return desktopUser("CallNextHookEx", 0, uintptr(code), wparam, uintptr(unsafe.Pointer(event)))
})

func recordInteractionKey(message uint32, event *interactionKeyboardEvent, now time.Time) {
	wasDown := interactionEscapeSequence.down
	stop := interactionEscapeSequence.feed(message, event.VK, event.Flags, event.Extra, now)
	if !wasDown && desktopStopKey(message, event.VK, event.Flags, event.Extra) && desktopEscapeEvents != nil {
		count := interactionEscapeSequence.count
		if stop {
			count = 3
		}
		select {
		case desktopEscapeEvents <- desktopEscapeEvent{At: now.UTC(), Count: count, PauseRequested: stop, Injected: event.Flags&0x10 != 0}:
		default:
			desktopEscapeEventsDropped.Add(1)
		}
	}
	if stop {
		interactionExternalTagLowMatches.Store(uint32(event.Extra) == uint32(desktopInputTag))
		interactionExternalEvent.Store(uint64(message) | uint64(event.Flags)<<32)
		interactionExternalInput.Store(true)
	}
}

// Accept real and foreign-injected Escape, but not RCON's marked Escape.
func desktopStopKey(message, vk, flags uint32, extra uintptr) bool {
	return vk == 0x1b && (message == 0x100 || message == 0x104) && flags&0x80 == 0 && !(extra == desktopInputTag && flags&0x10 != 0)
}

// Hook callbacks run on their own pumping OS thread: JPEG compression or a
// slow pipe write must not starve the low-level hook and make Windows remove it.
func startInteractionMonitor() (func(), error) {
	ready := make(chan error, 1)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		defer close(done)
		module, _, _ := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetModuleHandleW").Call(0)
		interactionEscapeSequence = desktopEscapeSequence{}
		kh := desktopUser("SetWindowsHookExW", 13, interactionKeyboardHook, module, 0)
		if kh != 0 {
			defer desktopUser("UnhookWindowsHookEx", kh)
		}
		if kh == 0 {
			ready <- errors.New("cannot monitor outside Escape; no input started")
			return
		}
		ready <- nil
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				interactionPump()
			}
		}
	}()
	if err := <-ready; err != nil {
		return nil, err
	}
	return func() { close(stop); <-done }, nil
}
func interactionPump() {
	msg := struct {
		Window         uintptr
		Message        uint32
		WParam, LParam uintptr
		Time           uint32
		X, Y           int32
		Private        uint32
	}{}
	for desktopUser("PeekMessageW", uintptr(unsafe.Pointer(&msg)), 0, 0, 0, 1) != 0 {
		desktopUser("TranslateMessage", uintptr(unsafe.Pointer(&msg)))
		desktopUser("DispatchMessageW", uintptr(unsafe.Pointer(&msg)))
	}
}
func interactionIndicator(label string) {
	indicatorPointerLabel(label)
	for hwnd, w := range indicatorWindows {
		if w.label == label {
			continue
		}
		w.label = label
		desktopUser("InvalidateRect", hwnd, 0, 0)
		desktopUser("UpdateWindow", hwnd)
	}
}

type interactionHeldKey struct {
	VK    uint16
	Flags uint32
	Name  string
}
type desktopInteractionWorker struct {
	session           desktopSession
	id                string
	guard             desktopGuard
	keys              []interactionHeldKey
	buttons           []string
	expires, deadline time.Time
	start             time.Time
	frames            []map[string]any
	status            string
}

func (w *desktopInteractionWorker) release() error {
	var all error
	for i := len(w.buttons) - 1; i >= 0; i-- {
		_, up := interactionButton(w.buttons[i])
		all = errors.Join(all, desktopMouse(up, 0, 0, 0, true))
	}
	for i := len(w.keys) - 1; i >= 0; i-- {
		k := w.keys[i]
		all = errors.Join(all, desktopKey(k.VK, 0, k.Flags, true))
	}
	// Retry release once on failure. Never report a confirmed release if it fails.
	if all != nil {
		var retry error
		for _, b := range w.buttons {
			_, up := interactionButton(b)
			retry = errors.Join(retry, desktopMouse(up, 0, 0, 0, true))
		}
		for _, k := range w.keys {
			retry = errors.Join(retry, desktopKey(k.VK, 0, k.Flags, true))
		}
		if retry != nil {
			return errors.Join(all, retry)
		}
	}
	w.buttons = nil
	w.keys = nil
	return nil
}
func interactionButton(b string) (uint32, uint32) {
	switch b {
	case "right":
		return 8, 16
	case "middle":
		return 32, 64
	default:
		return 2, 4
	}
}
func (w *desktopInteractionWorker) check(focus bool) error {
	interactionPump()
	indicatorPointerTick()
	if err := desktopPauseError(); err != nil {
		return err
	}
	if interactionExternalInput.Load() {
		return fmt.Errorf("outside Escape triple-press (message=0x%x flags=0x%x own_tag_low32=%v); interaction cancelled", uint32(interactionExternalEvent.Load()), uint32(interactionExternalEvent.Load()>>32), interactionExternalTagLowMatches.Load())
	}
	if time.Now().After(w.expires) || time.Now().After(w.deadline) {
		return errors.New("interaction timed out")
	}
	live, err := desktopState(w.session)
	if err != nil {
		return err
	}
	if live.Bounds != w.guard.Bounds || live.Width != w.guard.Width || live.Height != w.guard.Height {
		return errors.New("desktop geometry changed")
	}
	if focus && live.Foreground != w.guard.Foreground {
		return fmt.Errorf("foreground changed while waiting for a decision: before=%v after=%v", desktopWindow(uintptr(w.guard.Foreground), w.guard), desktopWindow(uintptr(live.Foreground), live))
	}
	return nil
}
func (w *desktopInteractionWorker) wait(ms int) error {
	end := time.Now().Add(time.Duration(ms) * time.Millisecond)
	for time.Now().Before(end) {
		if err := w.check(false); err != nil {
			return err
		}
		time.Sleep(min(20*time.Millisecond, time.Until(end)))
	}
	return w.check(false)
}
func (w *desktopInteractionWorker) held() ([]string, []string) {
	keys := []string{}
	for _, k := range w.keys {
		keys = append(keys, k.Name)
	}
	return keys, slices.Clone(w.buttons)
}
func (w *desktopInteractionWorker) snapshot(phase string) (desktopWorkerResponse, error) {
	if err := w.check(false); err != nil {
		return desktopWorkerResponse{}, err
	}
	r, err := desktopSnapshotMode(w.session, true)
	if err != nil {
		return r, err
	}
	if err = w.check(false); err != nil {
		return r, err
	}
	obs := r.Result["observation"].(map[string]any)
	keys, buttons := w.held()
	obs["interaction_id"] = w.id
	obs["held_keys"] = keys
	obs["held_buttons"] = buttons
	obs["elapsed_ms"] = time.Since(w.start).Milliseconds()
	obs["phase"] = phase
	if phase != "checkpoint" {
		obs["actionable"] = false
		r.Guard = desktopGuard{}
		obs["input_refusal_reason"] = "intermediate motion frame; continue only from the final interaction checkpoint"
	}
	return r, nil
}
func (w *desktopInteractionWorker) capture(phase string) error {
	r, err := w.snapshot(phase)
	if err != nil {
		return err
	}
	w.frames = append(w.frames, map[string]any{"observation": r.Result["observation"], "image": r.Result["image"]})
	return nil
}
func (w *desktopInteractionWorker) validateEvents(events []DesktopInputEvent) error {
	keys := map[uint16]bool{}
	for _, k := range w.keys {
		keys[k.VK] = true
	}
	buttons := map[string]bool{}
	for _, b := range w.buttons {
		buttons[b] = true
	}
	for _, e := range events {
		vk, _ := desktopVK(strings.ToUpper(strings.TrimSpace(e.Key)))
		switch e.Type {
		case "key_down":
			if keys[vk] {
				return errors.New("key already held")
			}
			keys[vk] = true
		case "key_up":
			if !keys[vk] {
				return errors.New("key is not owned by this interaction")
			}
			delete(keys, vk)
		case "key_press":
			if keys[vk] {
				return errors.New("cannot tap an already held key")
			}
		case "button_down":
			if buttons[e.Button] {
				return errors.New("button already held")
			}
			buttons[e.Button] = true
		case "button_up":
			if !buttons[e.Button] {
				return errors.New("button is not owned by this interaction")
			}
			delete(buttons, e.Button)
		case "move":
			if *e.X >= w.guard.Width || *e.Y >= w.guard.Height {
				return errors.New("pointer outside observed image")
			}
		}
		if len(keys) > 8 {
			return errors.New("at most eight held keys")
		}
	}
	return nil
}
func (w *desktopInteractionWorker) event(e DesktopInputEvent) error {
	if err := w.check(false); err != nil {
		return err
	}
	name := strings.ToUpper(strings.TrimSpace(e.Key))
	if name == "CONTROL" {
		name = "CTRL"
	}
	vk, flags := desktopVK(name)
	switch e.Type {
	case "key_down", "key_press":
		w.keys = append(w.keys, interactionHeldKey{vk, flags, name})
		if err := desktopKey(vk, 0, flags, false); err != nil {
			return err
		}
		if e.Type == "key_press" {
			if err := w.wait(80); err != nil {
				return err
			}
			if err := desktopKey(vk, 0, flags, true); err != nil {
				return err
			}
			w.keys = w.keys[:len(w.keys)-1]
		}
	case "key_up":
		if err := desktopKey(vk, 0, flags, true); err != nil {
			return err
		}
		w.keys = slices.DeleteFunc(w.keys, func(k interactionHeldKey) bool { return k.VK == vk })
	case "button_down":
		w.buttons = append(w.buttons, e.Button)
		down, _ := interactionButton(e.Button)
		return desktopMouse(down, 0, 0, 0, false)
	case "button_up":
		_, up := interactionButton(e.Button)
		if err := desktopMouse(up, 0, 0, 0, true); err != nil {
			return err
		}
		w.buttons = slices.DeleteFunc(w.buttons, func(b string) bool { return b == e.Button })
	case "wait":
		return w.wait(e.DurationMS)
	case "capture":
		return w.capture("during_input")
	case "move":
		if e.DurationMS == 0 {
			return desktopMove(*e.X, *e.Y, w.guard)
		}
		var pt struct{ X, Y int32 }
		if desktopUser("GetCursorPos", uintptr(unsafe.Pointer(&pt))) == 0 {
			return errors.New("cursor position unavailable")
		}
		x := int(pt.X-int32(w.guard.Bounds.X)) * w.guard.Width / w.guard.Bounds.Width
		y := int(pt.Y-int32(w.guard.Bounds.Y)) * w.guard.Height / w.guard.Bounds.Height
		n := max(1, e.DurationMS/20)
		sample := 1
		start := time.Now()
		for step := 1; step <= n; step++ {
			due := start.Add(time.Duration(e.DurationMS*step/n) * time.Millisecond)
			if wait := time.Until(due); wait > 0 {
				if err := w.wait(int(wait.Milliseconds()) + 1); err != nil {
					return err
				}
			}
			if err := w.check(false); err != nil {
				return err
			}
			if err := desktopMove(x+(*e.X-x)*step/n, y+(*e.Y-y)*step/n, w.guard); err != nil {
				return err
			}
			if sample <= e.Samples && step*e.Samples >= sample*n {
				if err := w.capture("during_move"); err != nil {
					return err
				}
				sample++
			}
		}
	}
	return nil
}
func (w *desktopInteractionWorker) command(c desktopCommand) (r desktopWorkerResponse, terminal bool) {
	w.frames = nil
	w.start = time.Now()
	w.status = "not_sent"
	fail := func(err error) (desktopWorkerResponse, bool) {
		releaseErr := w.release()
		out := desktopFailure(c.ID, w.status, errors.Join(err, releaseErr))
		out["interaction_id"] = w.id
		out["interaction_state"] = "cancelled"
		out["released"] = releaseErr == nil
		paused, _ := readDesktopPause()
		if interactionExternalInput.Load() || paused != nil {
			if e := latchDesktopPause(w.session); e != nil {
				out["pause_error"] = e.Error()
				out["error"] = fmt.Sprint(out["error"]) + "; pause persistence failed: " + e.Error()
			}
			out["paused"] = true
		}
		out["frames"] = w.frames
		return desktopWorkerResponse{Result: out}, true
	}
	if err := validateDesktopCommand(c); err != nil {
		return fail(err)
	}
	spec := c.Interaction
	if spec.ID != w.id || c.SessionID != w.session.ID {
		return fail(errors.New("interaction identity mismatch"))
	}
	if spec.Operation == "release" || spec.Operation == "cancel" {
		w.status = "sent"
		if err := w.release(); err != nil {
			return fail(err)
		}
		// A release is allowed regardless of frame freshness or foreground changes.
		_ = w.wait(120)
		r, err := desktopSnapshot(w.session)
		if err != nil {
			r = desktopWorkerResponse{Result: map[string]any{"ok": true, "capture_error": err.Error()}}
		}
		r.Result["id"] = c.ID
		r.Result["input_status"] = "sent"
		r.Result["interaction_id"] = w.id
		r.Result["interaction_state"] = "released"
		r.Result["released"] = true
		return r, true
	}
	if err := w.check(spec.Operation != "begin"); err != nil {
		return fail(err)
	}
	if spec.Operation != "observe" && c.FrameID != w.guard.FrameID {
		return fail(errors.New("stale or consumed interaction checkpoint"))
	}
	if err := w.validateEvents(spec.Events); err != nil {
		return fail(err)
	}
	lease := spec.LeaseMS
	if lease == 0 {
		lease = 60000
	}
	w.expires = minTime(time.Now().Add(time.Duration(lease)*time.Millisecond), w.deadline)
	interactionIndicator("AI controlling")
	for _, event := range spec.Events {
		w.status = "unknown"
		if err := w.event(event); err != nil {
			return fail(err)
		}
		w.status = "sent"
	}
	if err := w.wait(120); err != nil {
		return fail(err)
	}
	r, err := w.snapshot("checkpoint")
	if err != nil {
		return fail(err)
	}
	if r.Guard.FrameID == "" {
		return fail(errors.New("foreground changed while capturing interaction checkpoint"))
	}
	w.guard = r.Guard
	// Thinking time starts after the checkpoint has been captured.
	w.expires = minTime(time.Now().Add(time.Duration(lease)*time.Millisecond), w.deadline)
	interactionIndicator(desktopCountdownLabel("AI thinking", w.expires, time.Now()))
	keys, buttons := w.held()
	r.Result["id"] = c.ID
	r.Result["input_status"] = w.status
	r.Result["interaction_id"] = w.id
	r.Result["interaction_state"] = "thinking"
	r.Result["held_keys"] = keys
	r.Result["held_buttons"] = buttons
	r.Result["expires_at"] = w.expires.UTC()
	r.Result["frames"] = w.frames
	return r, false
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
func runDesktopInteraction(conn net.Conn, req desktopWorkerRequest) (result error) {
	started := false
	defer func() {
		if !started && result != nil {
			_ = json.NewEncoder(conn).Encode(desktopWorkerResponse{Result: desktopFailure(req.Command.ID, "not_sent", result)})
		}
	}()
	if p := desktopUser32.NewProc("SetProcessDpiAwarenessContext"); p.Find() == nil {
		p.Call(^uintptr(3))
	}
	live, err := desktopState(req.Session)
	if err != nil {
		return json.NewEncoder(conn).Encode(desktopWorkerResponse{Result: desktopFailure(req.Command.ID, "not_sent", err)})
	}
	if err = validateDesktopGuard(req.Command, req.Previous, live); err != nil {
		return json.NewEncoder(conn).Encode(desktopWorkerResponse{Result: desktopFailure(req.Command.ID, "not_sent", err)})
	}
	if len(desktopPressed()) != 0 {
		return json.NewEncoder(conn).Encode(desktopWorkerResponse{Result: desktopFailure(req.Command.ID, "not_sent", errors.New("release existing keys/buttons before beginning an interaction"))})
	}
	w := &desktopInteractionWorker{session: req.Session, id: req.Command.Interaction.ID, guard: req.Previous, expires: time.Now().Add(60 * time.Second), deadline: time.Now().Add(5 * time.Minute)}
	defer func() {
		releaseErr := w.release()
		paused := interactionExternalInput.Load()
		if p, _ := readDesktopPause(); p != nil {
			paused = true
		}
		if paused {
			result = errors.Join(result, latchDesktopPause(w.session))
		}
		if started && result != nil {
			end := desktopInteractionEnd{ID: w.id, SessionID: w.session.ID, Reason: errors.Join(result, releaseErr).Error(), Released: releaseErr == nil, Paused: paused, At: time.Now().UTC()}
			_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			_ = json.NewEncoder(conn).Encode(desktopWorkerResponse{End: &end})
		}
	}()
	interactionExternalInput.Store(false)
	stopMonitor, err := startInteractionMonitor()
	if err != nil {
		return err
	}
	defer stopMonitor()
	unregister, err := registerIndicatorClass()
	if err != nil {
		return err
	}
	defer unregister()
	defer destroyIndicatorWindows()
	monitors, err := getIndicatorMonitors()
	if err != nil {
		return err
	}
	if err = createIndicatorWindows(monitors, "AI controlling"); err != nil {
		return err
	}
	commands := make(chan desktopCommand)
	readErrors := make(chan error, 1)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		dec := json.NewDecoder(io.LimitReader(conn, 1<<20))
		dec.DisallowUnknownFields()
		for {
			var c desktopCommand
			if err := dec.Decode(&c); err != nil {
				readErrors <- err
				return
			}
			select {
			case commands <- c:
			case <-stop:
				return
			}
		}
	}()
	send := func(c desktopCommand) (bool, error) {
		response, terminal := w.command(c)
		_ = conn.SetWriteDeadline(time.Now().Add(8 * time.Second))
		err := json.NewEncoder(conn).Encode(response)
		return terminal, err
	}
	started = true
	terminal, err := send(req.Command)
	if terminal || err != nil {
		return err
	}
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	checked := time.Now()
	for {
		select {
		case err := <-readErrors:
			return err
		case c := <-commands:
			terminal, err := send(c)
			if terminal || err != nil {
				return err
			}
		case <-tick.C:
			interactionIndicator(desktopCountdownLabel("AI thinking", w.expires, time.Now()))
			if err := desktopPauseError(); err != nil {
				return err
			}
			interactionPump()
			indicatorPointerTick()
			if interactionExternalInput.Load() {
				return fmt.Errorf("outside Escape triple-press (message=0x%x flags=0x%x own_tag_low32=%v); releasing held input", uint32(interactionExternalEvent.Load()), uint32(interactionExternalEvent.Load()>>32), interactionExternalTagLowMatches.Load())
			}
			if time.Now().After(w.expires) || time.Now().After(w.deadline) {
				return errors.New("interaction expired; releasing held input")
			}
			if time.Since(checked) > 200*time.Millisecond {
				if err := w.check(true); err != nil {
					return err
				}
				checked = time.Now()
			}
		}
	}
}
