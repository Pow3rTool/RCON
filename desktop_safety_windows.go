package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// A separate native worker per active logon keeps the stop gesture armed across
// tool calls, indicator expiry and interaction teardown. No input is injected.
type desktopSafetyClient struct {
	session desktopSession
	cancel  context.CancelFunc
	done    chan struct{}
	ready   chan struct{}
	err     error
}

var desktopSafety = struct {
	sync.Mutex
	clients map[uint32]*desktopSafetyClient
}{clients: map[uint32]*desktopSafetyClient{}}

type desktopEscapeEvent struct {
	At                       time.Time
	Count                    int
	PauseRequested, Injected bool
}

var desktopEscapeEvents chan desktopEscapeEvent
var desktopEscapeEventsDropped atomic.Uint64

type desktopSafetyMessage struct {
	Pause bool
	Ready bool
}

func ensureDesktopSafety(session desktopSession) error {
	desktopSafety.Lock()
	c := desktopSafety.clients[session.ID]
	if c != nil {
		select {
		case <-c.done:
			c = nil
		default:
		}
		if c != nil && c.session.LogonID != session.LogonID {
			c.cancel()
			c = nil
		}
	}
	if c == nil {
		ctx, cancel := context.WithCancel(context.Background())
		c = &desktopSafetyClient{session: session, cancel: cancel, done: make(chan struct{}), ready: make(chan struct{})}
		desktopSafety.clients[session.ID] = c
		go func(c *desktopSafetyClient) {
			defer close(c.done)
			defer c.cancel()
			c.err = withDesktopWorker(ctx, desktopWorkerRequest{Session: session, Safety: true}, func(conn net.Conn) error {
				closeOnCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
				defer closeOnCancel()
				_ = conn.SetDeadline(time.Time{})
				decoder := json.NewDecoder(conn)
				ready := false
				for {
					_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
					var m desktopSafetyMessage
					if err := decoder.Decode(&m); err != nil {
						return err
					}
					if !ready {
						if !m.Ready {
							return errors.New("invalid pause watcher handshake")
						}
						close(c.ready)
						ready = true
					}
					if m.Pause {
						log.Printf("desktop: outside Escape triple-press latched pause in session %d", session.ID)
					}
				}
			})
		}(c)
	}
	desktopSafety.Unlock()
	select {
	case <-c.done:
		return fmt.Errorf("desktop pause watcher unavailable: %w", c.err)
	case <-c.ready:
		return nil
	case <-time.After(8 * time.Second):
		return errors.New("desktop pause watcher start timed out")
	}
}
func startDesktopSafetySupervisor() func() {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		tick := time.NewTicker(500 * time.Millisecond)
		defer tick.Stop()
		defer func() {
			desktopSafety.Lock()
			defer desktopSafety.Unlock()
			for _, c := range desktopSafety.clients {
				c.cancel()
			}
		}()
		for {
			sessions, err := desktopSessions()
			if err == nil {
				live := map[uint32]bool{}
				for _, session := range sessions {
					live[session.ID] = true
					_ = ensureDesktopSafety(session)
				}
				desktopSafety.Lock()
				for id, c := range desktopSafety.clients {
					if !live[id] {
						c.cancel()
						delete(desktopSafety.clients, id)
					}
				}
				desktopSafety.Unlock()
				if pause, e := readDesktopPause(); e == nil && pause != nil && desktopManager.TryLock() {
					// Active gesture owns its own overlay; it will stop on the durable latch.
					if activeDesktopInteraction == nil {
						if session, e := selectDesktopSession(sessions, pause.SessionID); e == nil {
							_ = setDesktopIndicator(session, desktopPausedLabel)
						}
					}
					desktopManager.Unlock()
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
	}()
	return cancel
}
func runDesktopSafetyWorker(conn net.Conn, req desktopWorkerRequest) (result error) {
	desktopEscapeEvents = make(chan desktopEscapeEvent, 64)
	desktopEvent("escape-watcher-started", map[string]any{"session_id": req.Session.ID})
	defer func() {
		reason := "service pipe closed"
		if result != nil {
			reason = result.Error()
		}
		desktopEvent("escape-watcher-stopped", map[string]any{"session_id": req.Session.ID, "reason": reason})
	}()
	// Hook remains independent of foreground HWND and image rendering. A minimized
	// RDP viewer must not turn the universal pause gesture off.
	stop, err := startInteractionMonitor()
	if err != nil {
		return err
	}
	defer stop()
	logDone := make(chan struct{})
	defer close(logDone)
	go func() {
		for {
			select {
			case <-logDone:
				return
			case tap := <-desktopEscapeEvents:
				paused, _ := readDesktopPause()
				fields := map[string]any{"session_id": req.Session.ID, "event_at": tap.At, "burst_count": tap.Count, "pause_requested": tap.PauseRequested, "injected": tap.Injected, "pause_active_at_log": paused != nil}
				if paused != nil {
					fields["pause_id"] = paused.ID
				}
				desktopEvent("escape-tap", fields)
				if dropped := desktopEscapeEventsDropped.Swap(0); dropped > 0 {
					desktopEvent("escape-log-overflow", map[string]any{"session_id": req.Session.ID, "dropped": dropped})
				}
			}
		}
	}()
	encoder := json.NewEncoder(conn)
	if err = encoder.Encode(desktopSafetyMessage{Ready: true}); err != nil {
		return err
	}
	closed := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, conn); close(closed) }()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	heartbeat := time.Now()
	for {
		select {
		case <-closed:
			return nil
		case <-tick.C:

			if interactionExternalInput.Swap(false) {
				// Persist in the session worker before notifying the service. This also
				// stops in-flight SendInput independently of broker/service scheduling.
				if err = latchDesktopPause(req.Session); err != nil {
					return err
				}
				_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
				if err = encoder.Encode(desktopSafetyMessage{Pause: true}); err != nil {
					return err
				}
			}
			if time.Since(heartbeat) >= time.Second {
				sessions, e := desktopSessions()
				if e != nil {
					return e
				}
				live, e := selectDesktopSession(sessions, req.Session.ID)
				if e != nil || live.LogonID != req.Session.LogonID {
					return errors.New("pause watcher logon ended")
				}
				_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
				if err = encoder.Encode(desktopSafetyMessage{}); err != nil {
					return err
				}
				heartbeat = time.Now()
			}
		}
	}
}
