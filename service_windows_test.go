package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsJoinTokenCleanupPreservesIdentity(t *testing.T) {
	requireElevatedWindows(t)
	dir := filepath.Join(t.TempDir(), "identity")
	if err := ensureIdentityDir(dir); err != nil {
		t.Fatal(err)
	}
	want := windowsServiceConfig{XConnect: "https://example.invalid", Broker: "example.invalid:3", Name: "test", CAPin: "synthetic-pin", Token: "synthetic-token"}
	if err := saveWindowsServiceConfig(dir, want); err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(dir, "enrollment.json")
	if err := os.WriteFile(identity, []byte(`{"state":"pending"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := clearWindowsJoinToken(dir); err != nil {
		t.Fatal(err)
	}
	want.Token = ""
	got, err := loadWindowsServiceConfig(dir)
	if err != nil || got != want {
		t.Fatalf("configuration fields were lost: %v", err)
	}
	b, err := os.ReadFile(identity)
	if err != nil || string(b) != `{"state":"pending"}` {
		t.Fatal("identity metadata changed")
	}
	if err := clearWindowsJoinToken(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "service.json"), []byte("malformed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := clearWindowsJoinToken(dir); err == nil {
		t.Fatal("ignored invalid configuration")
	}
}

func TestWindowsUninstallUsesSCMDataDirectory(t *testing.T) {
	got, err := windowsServiceIdentityDir(`"C:\Program Files\Agent\rcon.exe" service --etc "C:\ProgramData\Custom Agent"`)
	if err != nil || got != `C:\ProgramData\Custom Agent` {
		t.Fatalf("custom directory: %q %v", got, err)
	}
	for _, cmd := range []string{`rcon.exe run`, `rcon.exe service --etc relative`, `rcon.exe service --unknown x`, `rcon.exe service extra`} {
		if _, err := windowsServiceIdentityDir(cmd); err == nil {
			t.Fatalf("accepted ambiguous command %q", cmd)
		}
	}
}
