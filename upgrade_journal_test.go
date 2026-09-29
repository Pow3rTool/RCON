package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDecideUpgrade(t *testing.T) {
	j := upgradeJournal{From: "v1", To: "v2", Switched: true}
	for _, test := range []struct {
		name       string
		running    string
		attempts   int
		atDeadline bool
		healthy    bool
		want       upgradeAction
	}{
		{"new release starts", "v2", 1, false, false, upgradeWatch},
		{"new release at the attempt limit", "v2", upgradeMaxAttempts, false, false, upgradeWatch},
		{"new release crash-looping", "v2", upgradeMaxAttempts + 1, false, false, upgradeRollBack},
		{"new release healthy at deadline", "v2", 1, true, true, upgradeCommit},
		{"new release unhealthy at deadline", "v2", 1, true, false, upgradeRollBack},
		{"previous release running", "v1", 0, false, false, upgradeAbandon},
		{"previous release, even if healthy", "v1", 0, true, true, upgradeAbandon},
		{"unrelated release", "v3", 0, false, false, upgradeStale},
	} {
		j.Attempts = test.attempts
		if got := decideUpgrade(j, test.running, test.atDeadline, test.healthy); got != test.want {
			t.Errorf("%s: got %d, want %d", test.name, got, test.want)
		}
	}
	// A rollback under way wins over everything for the new release, and the
	// previous release still just settles.
	j.RollingBack = true
	for _, test := range []struct {
		running          string
		atDeadline, good bool
		want             upgradeAction
	}{
		{"v2", false, false, upgradeRollBack},
		{"v2", true, true, upgradeRollBack},
		{"v1", false, false, upgradeAbandon},
	} {
		if got := decideUpgrade(j, test.running, test.atDeadline, test.good); got != test.want {
			t.Errorf("rolling back, %s deadline=%v healthy=%v: got %d, want %d",
				test.running, test.atDeadline, test.good, got, test.want)
		}
	}
}

func TestReplaceFileAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device-cert.pem")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := replaceFileAtomic(path, []byte("new content"), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "new content" {
		t.Fatalf("content %q %v", b, err)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("temp file left behind: %v", entries)
	}
	if err := replaceFileAtomic(filepath.Join(t.TempDir(), "missing", "x"), []byte("x"), 0o600); err == nil {
		t.Fatal("wrote into a missing directory")
	}
}
