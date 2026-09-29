// Upgrade drain. While a staged upgrade waits for the node to go idle, every
// request that changes the node — /run, /jobs, file writes and edits, and
// certificate renewal — is refused with a retryable 503, and the upgrade waits
// for the ones already admitted. The service is stopped only when nothing is
// mid-command or mid-write: file writes happen in place and are not atomic, so
// stopping mid-write would leave a partial file. Reads stay available.
//
// Ordering: a request reserves its in-flight slot BEFORE checking the drain
// flag, and JobStore.Start checks the flag under the same lock that registers
// the job. So once beginDrain returns, every piece of work either shows up in
// the idle check or is refused — nothing slips between the two.
package main

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

var (
	drainMu      sync.Mutex
	drainMessage string
	inflightWork atomic.Int64
)

// errDraining is returned by JobStore.Start while an upgrade is draining the node.
type errDraining struct{ reason string }

func (e errDraining) Error() string {
	return fmt.Sprintf("node is draining for an upgrade (%s) — this is temporary, not a denial: "+
		"retry in a few minutes", e.reason)
}

// beginDrain starts refusing new work. False if a drain is already in progress.
func beginDrain(reason string) bool {
	drainMu.Lock()
	defer drainMu.Unlock()
	if drainMessage != "" {
		return false
	}
	drainMessage = reason
	return true
}

func endDrain() {
	drainMu.Lock()
	drainMessage = ""
	drainMu.Unlock()
}

// drainReason is non-empty while the node refuses new work.
func drainReason() string {
	drainMu.Lock()
	defer drainMu.Unlock()
	return drainMessage
}

// admitWork reserves an in-flight slot for a node-changing request, or reports
// why the node is refusing work. The caller must call release exactly once when
// admitted.
func admitWork() (release func(), refused string) {
	inflightWork.Add(1)
	if r := drainReason(); r != "" {
		inflightWork.Add(-1)
		return nil, r
	}
	return func() { inflightWork.Add(-1) }, ""
}

// gated wraps a node-changing handler so an upgrade can drain it.
func gated(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		release, refused := admitWork()
		if refused != "" {
			writeJSON(w, 503, map[string]any{"error": errDraining{refused}.Error(), "retryable": true, "draining": true})
			return
		}
		defer release()
		h(w, r)
	}
}

// nodeIdle reports whether no job is running and no node-changing request is in flight.
func nodeIdle(store *JobStore) bool {
	return store.Running() == 0 && inflightWork.Load() == 0
}

// waitIdle polls until the node is idle or maxWait elapses.
func waitIdle(store *JobStore, maxWait time.Duration) bool {
	deadline := time.Now().Add(maxWait)
	for {
		if nodeIdle(store) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(time.Second)
	}
}
