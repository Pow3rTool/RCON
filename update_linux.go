//go:build linux

// RCON self-update — receive an Orthanc-SIGNED binary relayed down the tunnel by
// XConnect, verify it against the BAKED release public key (XConnect is only a
// relay — it can never vouch for code), gate it through --selftest, atomically
// swap, and re-exec. A post-update watchdog rolls back to the previous binary if
// the new one can't establish a healthy tunnel — so a bad update self-heals
// instead of locking us out of the box.
package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// Baked at build time:
//   -ldflags "-X main.version=v0.2.0 -X main.releasePubKeyB64=<raw-b64-ed25519-pub>"

// protocolVersion is the WIRE-CONTRACT version of the RCON tool surface +
// control RPCs (run/jobs/read/edit/write/renew/update/health) — NOT the release
// version. Bump it ONLY on a breaking, non-additive change to that contract.
// Additive changes (new verbs/fields) do NOT bump it; callers feature-detect.
// Reported in /health so XConnect/Orthanc can enforce a minimum-supported floor
// (a node below the floor is allowed to self-update/renew but not serve verbs).

const watchdogWindow = 90 * time.Second

var lastHealthy atomic.Int64 // unix secs of the last broker /health hit

func markHealthy() { lastHealthy.Store(time.Now().Unix()) }

// runSelfTest: a candidate binary proves it loads its identity and can reach the
// broker, then exits 0. Non-disruptive (plain TCP reach, not a full tunnel) so it
// doesn't fight the running instance. The pre-swap gate against a broken build.
func runSelfTest(etc, broker string) {
	if _, _, err := buildTLS(etc); err != nil {
		fmt.Fprintf(os.Stderr, "selftest: identity load failed: %v\n", err)
		os.Exit(1)
	}
	c, err := net.DialTimeout("tcp", broker, 5*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "selftest: broker %s unreachable: %v\n", broker, err)
		os.Exit(1)
	}
	_ = c.Close()
	fmt.Printf("selftest OK: version %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
	os.Exit(0)
}

func updateApply(etc, broker string, _ *JobStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req, status, err := decodeReleaseRequest(w, r)
		if err != nil {
			writeJSON(w, status, map[string]any{"error": err.Error()})
			return
		}
		if req.Version == version {
			writeJSON(w, 200, map[string]any{"applied": false, "reason": "already on " + version})
			return
		}
		// (1) content hash + (2) signature over version|goos|goarch|sha256 —
		// BAKED pubkey only (shared with every platform: update_common.go).
		bin, status, err := verifyRelease(req)
		if err != nil {
			writeJSON(w, status, map[string]any{"error": err.Error()})
			return
		}
		// (3) write candidate next to the running exe
		exe, err := os.Executable()
		if err != nil {
			writeJSON(w, 500, map[string]any{"error": "cannot locate self"})
			return
		}
		newPath := exe + ".new"
		if err := os.WriteFile(newPath, bin, 0o755); err != nil {
			writeJSON(w, 500, map[string]any{"error": "write candidate: " + err.Error()})
			return
		}
		// (4) selftest gate
		if out, err := exec.Command(newPath, "--selftest", "--etc", etc, "--broker", broker).CombinedOutput(); err != nil {
			_ = os.Remove(newPath)
			log.Printf("update: selftest FAILED for %s: %v — keeping %s", req.Version, err, version)
			writeJSON(w, 422, map[string]any{"error": "candidate failed selftest", "detail": string(out)})
			return
		}
		// (5) atomic swap: current -> .prev, new -> current
		if err := os.Rename(exe, exe+".prev"); err != nil {
			_ = os.Remove(newPath)
			writeJSON(w, 500, map[string]any{"error": "swap(prev): " + err.Error()})
			return
		}
		if err := os.Rename(newPath, exe); err != nil {
			_ = os.Rename(exe+".prev", exe) // best-effort restore
			writeJSON(w, 500, map[string]any{"error": "swap(new): " + err.Error()})
			return
		}
		log.Printf("update: %s -> %s verified + selftested; swapping + re-exec", version, req.Version)
		writeJSON(w, 200, map[string]any{"applied": true, "from": version, "to": req.Version})
		// (6) re-exec after the response flushes; tunnel drops, we reconnect new.
		go func() {
			time.Sleep(500 * time.Millisecond)
			env := append(os.Environ(), "RCON_UPDATED_FROM="+version)
			if err := syscall.Exec(exe, os.Args, env); err != nil {
				log.Printf("update: re-exec failed: %v", err)
			}
		}()
	}
}

// updateWatchdog runs in a freshly self-updated process: if no healthy tunnel
// (a broker /health hit) lands within watchdogWindow, restore + re-exec the
// previous binary. Self-healing rollback — the anti-lockout backstop.
func updateWatchdog() {
	deadline := time.Now().Add(watchdogWindow)
	for time.Now().Before(deadline) {
		time.Sleep(3 * time.Second)
		if lastHealthy.Load() > 0 {
			log.Printf("update: %s healthy (broker reached) — committing", version)
			return
		}
	}
	log.Printf("update: NO healthy tunnel within %s — ROLLING BACK", watchdogWindow)
	exe, err := os.Executable()
	if err != nil {
		log.Printf("update: rollback can't locate self: %v", err)
		return
	}
	prev := exe + ".prev"
	if _, err := os.Stat(prev); err != nil {
		log.Printf("update: no previous binary to roll back to: %v", err)
		return
	}
	_ = os.Rename(exe, exe+".failed") // keep the bad one for forensics
	if err := os.Rename(prev, exe); err != nil {
		log.Printf("update: rollback restore failed: %v", err)
		return
	}
	// drop the marker so the restored binary doesn't watchdog-loop
	var env []string
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "RCON_UPDATED_FROM=") {
			env = append(env, e)
		}
	}
	_ = syscall.Exec(exe, os.Args, env)
}
