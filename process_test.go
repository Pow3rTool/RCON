package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func shellCommand(linux, windows string) string {
	if runtime.GOOS == "windows" {
		return windows
	}
	return linux
}
func invokeRun(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	runHandler(w, httptest.NewRequest("POST", "/run", bytes.NewReader(raw)))
	if w.Code != 200 {
		t.Fatalf("run status %d: %s", w.Code, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}
func TestChildEnvScrubsCredentialsCaseInsensitively(t *testing.T) {
	t.Setenv("rcon_join_token", "do-not-inherit")
	t.Setenv("RCON_CA_PIN", "pin")
	for _, item := range childEnv() {
		name, _, _ := strings.Cut(item, "=")
		if sensitiveEnvKeys[strings.ToUpper(name)] {
			t.Fatalf("leaked environment key %s", name)
		}
	}
}
func TestCappedBufferBoundsAllocationAndReportsWrites(t *testing.T) {
	b := cappedBuffer{limit: 4}
	if n, err := b.Write([]byte("123456")); n != 6 || err != nil {
		t.Fatalf("write: %d %v", n, err)
	}
	_, _ = b.Write([]byte("more"))
	if string(b.Bytes()) != "1234" || !b.truncated {
		t.Fatalf("buffer: %q", b.Bytes())
	}
}
func TestRunExitCodeAndStreams(t *testing.T) {
	out := invokeRun(t, map[string]any{"command": shellCommand(
		"printf hello; printf error >&2; exit 7",
		"[Console]::Out.Write('hello'); [Console]::Error.Write('error'); exit 7"),
		"cwd": t.TempDir()})
	if out["rc"] != float64(7) || !strings.Contains(out["stdout"].(string), "hello") || !strings.Contains(out["stderr"].(string), "error") {
		t.Fatalf("result: %#v", out)
	}
}
func TestRunSessionWorkingDirectory(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "space directory")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	command := shellCommand("cd 'space directory'; printf ok", "Set-Location -LiteralPath 'space directory'; Write-Output ok")
	out := invokeRun(t, map[string]any{"command": command, "cwd": dir, "session": t.Name()})
	if out["rc"] != float64(0) || filepath.Clean(out["cwd"].(string)) != sub {
		t.Fatalf("cwd: %#v", out)
	}
	out = invokeRun(t, map[string]any{"command": shellCommand("pwd", "$PWD.Path"), "session": t.Name()})
	if !strings.Contains(out["stdout"].(string), sub) {
		t.Fatalf("session: %#v", out)
	}
}
func TestRunTimeoutKillsDescendants(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "escaped.txt")
	cmd := shellCommand("(sleep 2; printf escaped > escaped.txt) & wait",
		"Start-Process -FilePath $PSHOME\\powershell.exe -ArgumentList '-NoProfile','-Command',\"Start-Sleep 2; Set-Content -LiteralPath '$env:__TS_CWD\\escaped.txt' escaped\" -NoNewWindow; Start-Sleep 30")
	out := invokeRun(t, map[string]any{"command": cmd, "cwd": dir, "timeout": 1})
	if out["timed_out"] != true || out["rc"] != float64(124) {
		t.Fatalf("timeout: %#v", out)
	}
	time.Sleep(2500 * time.Millisecond)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("descendant escaped cancellation: %v", err)
	}
}
func TestJobCancellation(t *testing.T) {
	s := NewJobStore()
	j, err := s.Start(shellCommand("sleep 30", "Start-Sleep 30"), "test")
	if err != nil {
		t.Fatal(err)
	}
	j.Cancel()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		state, _ := j.snapshotState()
		if state == "exited" {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("job did not stop")
}
func TestHealthPlatformCapabilities(t *testing.T) {
	w := httptest.NewRecorder()
	mux("test", NewJobStore(), t.TempDir(), "localhost:3").ServeHTTP(w, httptest.NewRequest("GET", "/health", nil))
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out["goos"] != runtime.GOOS || out["shell"] != commandShell {
		t.Fatalf("health: %#v", out)
	}
}
func TestCommandContextAlreadyCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c, tree, err := newShellCommand(ctx, "echo should-not-run", t.TempDir(), "", false)
	if err != nil {
		t.Fatal(err)
	}
	defer tree.Close()
	if err := c.Start(); err == nil {
		_ = tree.Kill()
		_ = c.Wait()
		t.Fatal("started cancelled command")
	}
}
