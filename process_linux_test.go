//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCancelKillsTermIgnoringChildAfterShellExits(t *testing.T) {
	dir := t.TempDir()
	ready := filepath.Join(dir, "ready")
	escaped := filepath.Join(dir, "escaped")
	// The child stays in the shell's process group, ignores TERM, and closes
	// inherited output pipes. It exits on its own after four seconds.
	command := fmt.Sprintf("(trap '' TERM; printf ready > '%s'; sleep 4; printf escaped > '%s') >/dev/null 2>&1 & wait", ready, escaped)
	job, err := NewJobStore().Start(command, "test-cancellation")
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			job.Cancel()
			t.Fatal("child did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	job.Cancel()
	time.Sleep(4500 * time.Millisecond)
	state, _ := job.snapshotState()
	if _, err := os.Stat(escaped); err == nil {
		t.Fatalf("child survived cancellation and wrote a marker; job state=%s", state)
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
}
