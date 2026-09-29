package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDrainRefusesNewWorkUntilEnded(t *testing.T) {
	if !beginDrain("upgrading to test") {
		t.Fatal("could not begin drain")
	}
	defer endDrain()
	if beginDrain("second") {
		t.Fatal("a second drain started while one was active")
	}
	store := NewJobStore()
	if _, err := store.Start("echo refused", "rid"); err == nil {
		t.Fatal("job started while draining")
	} else if _, ok := err.(errDraining); !ok {
		t.Fatalf("drain refusal has the wrong type: %v", err)
	}
	// Every node-changing route is gated: commands, file writes/edits, cert renewal.
	h := mux("test", store, t.TempDir(), "localhost:3")
	for _, path := range []string{"/run", "/write", "/write-metadata", "/edit", "/renew/apply"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", path, strings.NewReader(`{}`)))
		if w.Code != 503 || !strings.Contains(w.Body.String(), `"retryable":true`) {
			t.Fatalf("%s while draining: %d %s", path, w.Code, w.Body.String())
		}
	}
	if inflightWork.Load() != 0 {
		t.Fatal("refused requests leaked in-flight slots")
	}
	endDrain()
	if drainReason() != "" {
		t.Fatal("drain did not end")
	}
	if _, err := store.Start("echo ok", "rid"); err != nil {
		t.Fatalf("job refused after drain ended: %v", err)
	}
}

func TestWaitIdleSeesInFlightWork(t *testing.T) {
	store := NewJobStore()
	// An admitted write that is still running must hold off the upgrade.
	entered, finish := make(chan struct{}), make(chan struct{})
	slow := gated(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-finish
	})
	go slow(httptest.NewRecorder(), httptest.NewRequest("POST", "/write", nil))
	<-entered
	if nodeIdle(store) || waitIdle(store, 1500*time.Millisecond) {
		t.Fatal("node reported idle with a write in flight")
	}
	close(finish)
	if !waitIdle(store, 3*time.Second) {
		t.Fatal("node never went idle")
	}
	if _, err := store.Start(shellCommand("sleep 2", "Start-Sleep 2"), "rid"); err != nil {
		t.Fatal(err)
	}
	if store.Running() != 1 || nodeIdle(store) {
		t.Fatal("running job not counted")
	}
	if !waitIdle(store, 10*time.Second) {
		t.Fatal("job never finished")
	}
}
