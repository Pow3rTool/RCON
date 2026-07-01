// RCON /run — full exec_daemon.py parity: timeout, separate stdout/stderr, dur,
// truncated flag, and cheap cwd-snapshot sessions (a `cd` persists per session
// without holding a shell process — only the cwd string is carried, never env).
// One-shot + bounded; long-running work belongs on /jobs.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"sync"
	"syscall"
	"time"
)

// session_id -> cwd. No process is held, so there's nothing to leak; just a path.
var sessions sync.Map

func defaultCwd() string {
	if u, err := user.Current(); err == nil && u.HomeDir != "" {
		return u.HomeDir
	}
	return "/"
}

// sensitiveEnvKeys are stripped from EVERY child process environment. This is
// defense-in-depth, NOT a security boundary: RCON is a trusted-operator admin
// agent that intentionally runs commands as root on behalf of an operator who
// already has (or could grant themselves) direct SSH+root on this box — it does
// not try to contain that operator. The scrub only keeps the fleet join token out
// of casual child env / `ps` / logs (accidental exposure); a deliberate root
// command can still read /proc/<ppid>/environ or /etc/rcon/enroll.env, and that is
// out of scope by design. Join tokens are also TTL- and use-capped, so a leaked
// one is short-lived. See the "not an operator-containment boundary" note in
// ARCHITECTURE.
var sensitiveEnvKeys = map[string]bool{
	"RCON_JOIN_TOKEN": true, // fleet enrollment credential — root-equivalent
	"RCON_CA_PIN":     true, // bootstrap CA pin (not secret, but no child needs it)
}

// childEnv returns the parent environment with credential-bearing vars removed,
// plus any extra KEY=VALUE entries — the env every command we exec must use.
func childEnv(extra ...string) []string {
	base := os.Environ()
	out := make([]string, 0, len(base)+len(extra))
	for _, kv := range base {
		if i := strings.IndexByte(kv, '='); i >= 0 && sensitiveEnvKeys[kv[:i]] {
			continue
		}
		out = append(out, kv)
	}
	return append(out, extra...)
}

// runWrapper cd's into the session cwd, runs the command via eval (full bash
// metachar semantics), then snapshots the resulting cwd to __TS_STATE so the
// next call in the session resumes there.
const runWrapper = `cd "$__TS_CWD" 2>/dev/null; eval "$__TS_CMD"; __rc=$?; pwd > "$__TS_STATE" 2>/dev/null; exit $__rc`

func runHandler(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Command string  `json:"command"`
		Cmd     string  `json:"cmd"` // alias (the bridge/CLI uses this)
		Timeout float64 `json:"timeout"`
		Session string  `json:"session"`
		Cwd     string  `json:"cwd"`
		Rid     string  `json:"rid"` // XConnect correlation id (cross-ref to Witchhunt)
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON body: " + err.Error()})
		return
	}
	command := body.Command
	if command == "" {
		command = body.Cmd
	}
	if command == "" {
		writeJSON(w, 400, map[string]any{"error": "command required"})
		return
	}
	timeout := body.Timeout
	if timeout <= 0 {
		timeout = 60
	}
	// Cap the synchronous /run timeout so one call can't tie up the tunnel forever.
	// Configurable (RCON_RUN_MAX_SEC, default 3600s); 0 disables the cap. We CLAMP
	// rather than reject — the command still runs, just bounded — and tell the caller
	// so the LLM knows to split genuinely long work onto /jobs instead of retrying.
	timeoutCapped := false
	maxTO := runMaxTimeout()
	if maxTO > 0 && timeout > maxTO {
		timeout = maxTO
		timeoutCapped = true
	}
	cwd := body.Cwd
	if cwd == "" && body.Session != "" {
		if v, ok := sessions.Load(body.Session); ok {
			cwd, _ = v.(string)
		}
	}
	if cwd == "" {
		cwd = defaultCwd()
	}

	stateFile := ""
	if f, err := os.CreateTemp("", "rcon-cwd-"); err == nil {
		stateFile = f.Name()
		_ = f.Close()
		defer os.Remove(stateFile)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout*float64(time.Second)))
	defer cancel()
	c := exec.CommandContext(ctx, "/bin/bash", "-c", runWrapper)
	c.Env = childEnv("__TS_CWD="+cwd, "__TS_CMD="+command, "__TS_STATE="+stateFile)
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // own process group
	// On timeout, kill the WHOLE group (children too), not just the shell.
	c.Cancel = func() error {
		if c.Process != nil {
			return syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
	var outBuf, errBuf bytes.Buffer
	c.Stdout, c.Stderr = &outBuf, &errBuf

	t0 := time.Now()
	err := c.Run()
	dur := time.Since(t0).Seconds()
	timedOut := ctx.Err() == context.DeadlineExceeded

	rc := 0
	switch {
	case timedOut:
		rc = 124
	case err != nil:
		if ee, ok := err.(*exec.ExitError); ok {
			rc = ee.ExitCode()
		} else {
			rc = -1
		}
	}

	newCwd := cwd
	if stateFile != "" {
		if v, e := os.ReadFile(stateFile); e == nil {
			if s := strings.TrimSpace(string(v)); s != "" {
				newCwd = s
			}
		}
	}
	if body.Session != "" {
		sessions.Store(body.Session, newCwd)
	}
	auditRecord("run", command, rc, dur, body.Rid) // node-side tamper-evident record

	out, errb := outBuf.Bytes(), errBuf.Bytes()
	truncated := false
	if len(out) > outputCap {
		out, truncated = out[:outputCap], true
	}
	if len(errb) > outputCap {
		errb, truncated = errb[:outputCap], true
	}
	stderr := string(errb)
	if timedOut {
		stderr += "\n(killed: exceeded timeout)"
	}
	if timeoutCapped {
		stderr += fmt.Sprintf("\n(note: requested timeout exceeded this node's /run max of %.0fs and was capped to it — this is a bound, not a denial; for genuinely long-running work use /jobs)", maxTO)
	}
	writeJSON(w, 200, map[string]any{
		"rc": rc, "stdout": string(out), "stderr": stderr,
		"dur": dur, "truncated": truncated, "cwd": newCwd, "timed_out": timedOut,
		"timeout_used": timeout, "timeout_capped": timeoutCapped,
	})
}

// runMaxTimeout is the ceiling (seconds) for a single synchronous /run. Beyond it,
// work belongs on /jobs. Configurable via RCON_RUN_MAX_SEC; 0 = no cap.
func runMaxTimeout() float64 {
	return float64(envInt("RCON_RUN_MAX_SEC", 3600))
}
