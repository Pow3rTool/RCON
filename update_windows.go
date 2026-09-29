// Windows upgrades. RCON never overwrites the executable it is running from.
//
// A relayed release is verified (update_common.go), written to its own
// C:\RCON\releases\<version>\ directory, and self-tested. The node then drains
// (drain.go) and hands off to a detached `rcon.exe swap` started from the
// CURRENT, known-good binary, which:
//
//  1. takes the upgrade lock and writes the pending-upgrade journal
//     (upgrade_journal.go) before changing anything;
//  2. points the service at the new release while the old one keeps running;
//  3. terminates the drained service process. The Service Control Manager's
//     recovery action restarts the service with the new command, so the
//     service never depends on the swapper surviving to start it again;
//  4. waits for the new release's service process to report a healthy broker
//     tunnel, then commits, or records the failure, points the service back at
//     the previous release and restarts into it.
//
// If the swapper dies or the machine reboots part-way, the journal lets the
// next RCON process to start — new release or previous — finish the job.
// No reboot is involved, and no file is replaced while it runs.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	upgradeDrainMax     = 30 * time.Minute // running work gets this long to finish
	upgradeHealthWindow = 2 * time.Minute  // new release must reach the broker within this
	upgradeHandoffGrace = 10 * time.Minute // resume service if the swapper neither exits nor takes over
	serviceStopTimeout  = 60 * time.Second
	releasesRetained    = 3   // the running release, the one it replaced, and one more
	selfRestartExitCode = 200 // service-specific exit code that triggers SCM recovery
)

// Held from a verified apply until the drain ends or the swapper takes over.
var upgrading atomic.Bool

// Set once this process has recorded its health marker.
var healthRecorded atomic.Bool

// Receives a reason when this service should exit with a failure so SCM's
// recovery action restarts it with the currently configured command.
var selfRestart = make(chan string, 1)

func requestSelfRestart(reason string) {
	select {
	case selfRestart <- reason:
	default:
	}
}

// release.json, written beside each staged binary so the swapper can re-verify
// the signature itself instead of trusting whatever is on disk.
type releaseManifest struct {
	Version   string `json:"version"`
	GOOS      string `json:"goos"`
	GOARCH    string `json:"goarch"`
	SHA256    string `json:"sha256"`
	Signature string `json:"signature"`
}

type healthMarker struct {
	Version string    `json:"version"`
	PID     int       `json:"pid"`
	At      time.Time `json:"at"`
}

func releaseExe(ver string) string { return windowsPath("releases", ver, "rcon.exe") }
func healthMarkerPath() string     { return windowsPath("state", "healthy.json") }
func upgradeResultPath() string    { return windowsPath("state", "upgrade-result.json") }
func journalPath() string          { return windowsPath("state", "upgrade-pending.json") }
func nowStamp() string             { return time.Now().UTC().Format(time.RFC3339) }

// markHealthy records that this process reached the broker. An upgrade commits
// only after the new version's service process writes it.
func markHealthy() {
	if healthRecorded.Load() {
		return
	}
	b, _ := json.Marshal(healthMarker{Version: version, PID: os.Getpid(), At: time.Now().UTC()})
	if err := replaceFileAtomic(healthMarkerPath(), b, 0o600); err != nil {
		log.Printf("update: cannot record health marker: %v", err)
		return
	}
	healthRecorded.Store(true)
}

// The swapper and the journal are the watchdog on Windows.
func updateWatchdog() {}

// lastUpgradeReport surfaces the most recent upgrade outcome in /health.
func lastUpgradeReport() map[string]any {
	r, err := readUpgradeResult()
	if err != nil {
		return nil
	}
	return map[string]any{"from": r.From, "to": r.To, "ok": r.OK, "rolled_back": r.RolledBack, "reason": r.Reason, "at": r.At}
}

func updateApply(etc, broker string, store *JobStore) http.HandlerFunc {
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
		if !validReleaseVersion(req.Version) {
			writeJSON(w, 400, map[string]any{"error": "release version is not a safe directory name"})
			return
		}
		// A version that already failed its health check here is not retried
		// automatically; otherwise every reconnect would re-offer it and flap.
		if prev, err := readUpgradeResult(); err == nil && !prev.OK && prev.RolledBack && prev.To == req.Version {
			writeJSON(w, 409, map[string]any{"retryable": false, "error": fmt.Sprintf(
				"%s failed its health check on this node and was rolled back; publish a newer release, "+
					"or delete %s to allow %s again", req.Version, upgradeResultPath(), req.Version)})
			return
		}
		if journalExists() {
			writeJSON(w, 409, map[string]any{"error": "a previous upgrade is still being settled on this node", "retryable": true})
			return
		}
		bin, status, err := verifyRelease(req)
		if err != nil {
			writeJSON(w, status, map[string]any{"error": err.Error()})
			return
		}
		if !upgrading.CompareAndSwap(false, true) {
			writeJSON(w, 409, map[string]any{"error": "an upgrade is already in progress", "retryable": true})
			return
		}
		handedOff := false
		defer func() {
			if !handedOff {
				upgrading.Store(false)
			}
		}()
		exe, err := stageRelease(req, bin)
		if err != nil {
			writeJSON(w, 500, map[string]any{"error": "stage release: " + err.Error()})
			return
		}
		if out, err := selftestCandidate(exe, etc, broker); err != nil {
			log.Printf("update: selftest FAILED for %s: %v — staying on %s", req.Version, err, version)
			writeJSON(w, 422, map[string]any{"error": "candidate failed selftest", "detail": out})
			return
		}
		if !beginDrain("upgrading to " + req.Version) {
			writeJSON(w, 409, map[string]any{"error": "node is already draining", "retryable": true})
			return
		}
		handedOff = true // handOffUpgrade now owns `upgrading` and the drain
		if nodeIdle(store) {
			writeJSON(w, 200, map[string]any{"applied": true, "from": version, "to": req.Version, "mode": "handoff"})
		} else {
			writeJSON(w, 202, map[string]any{"applied": false, "staged": true, "draining": true,
				"from": version, "to": req.Version, "running_jobs": store.Running(),
				"work_in_flight": inflightWork.Load(), "drain_max_sec": int(upgradeDrainMax.Seconds())})
		}
		log.Printf("update: %s verified, staged and selftested; draining before hand-off", req.Version)
		go handOffUpgrade(store, req.Version)
	}
}

func handOffUpgrade(store *JobStore, to string) {
	resume := func(why string) {
		log.Printf("update: %s — resuming normal service on %s", why, version)
		endDrain()
		upgrading.Store(false)
	}
	if !waitIdle(store, upgradeDrainMax) {
		resume(fmt.Sprintf("node still busy after %s; upgrade to %s deferred (it stays staged and is "+
			"offered again on the next reconnect or operator update nudge)", upgradeDrainMax, to))
		return
	}
	time.Sleep(500 * time.Millisecond) // let the apply response flush before the tunnel drops
	cmd, err := startSwapper(version, to)
	if err != nil {
		resume("could not start the upgrade swapper: " + err.Error())
		return
	}
	log.Printf("update: handed off to swapper (%s -> %s); it terminates this process when it takes over", version, to)
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	select {
	case err := <-exited:
		// Still running means the swapper gave up. Settle anything it left.
		log.Printf("update: swapper exited (%v) without taking over; see %s", err, windowsPath("logs", "upgrade.log"))
		go settleJournal(false) // this process never stopped; retries until settled
		resume("upgrade to " + to + " did not proceed")
	case <-time.After(upgradeHandoffGrace):
		resume("swapper still running after " + upgradeHandoffGrace.String() + " without taking over")
	}
}

// stageRelease writes the verified binary and its manifest to the version's
// own protected directory. An existing binary is reused only if it is identical.
func stageRelease(req releaseRequest, bin []byte) (string, error) {
	exe := releaseExe(req.Version)
	dir := filepath.Dir(exe)
	if err := ensureIdentityDir(dir); err != nil {
		return "", err
	}
	if existing, err := os.ReadFile(exe); err == nil {
		sum := sha256.Sum256(existing)
		if hex.EncodeToString(sum[:]) != req.SHA256 {
			return "", fmt.Errorf("%s already holds a different binary; refusing to replace it", exe)
		}
	} else if !os.IsNotExist(err) {
		return "", err
	} else if err := replaceFileAtomic(exe, bin, 0o755); err != nil {
		return "", err
	}
	m, _ := json.MarshalIndent(releaseManifest{Version: req.Version, GOOS: req.GOOS, GOARCH: req.GOARCH,
		SHA256: req.SHA256, Signature: req.Signature}, "", "  ")
	if err := replaceFileAtomic(filepath.Join(dir, "release.json"), m, 0o600); err != nil {
		return "", err
	}
	return exe, nil
}

func selftestCandidate(exe, etc, broker string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "--selftest", "--etc", etc, "--broker", broker)
	cmd.Env = childEnv()
	out, err := cmd.CombinedOutput()
	if len(out) > 4096 {
		out = out[:4096]
	}
	return string(out), err
}

// startSwapper launches the current binary as a detached process outside any
// Job Object RCON controls, so it survives this process being terminated.
func startSwapper(from, to string) (*exec.Cmd, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	base := uint32(windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS)
	var lastErr error
	// Break away from any job the service itself sits in when that job allows
	// it; the swapper independently refuses to run inside a kill-on-close job.
	for _, flags := range []uint32{base | windows.CREATE_BREAKAWAY_FROM_JOB, base} {
		cmd := exec.Command(exe, "swap", "--from", from, "--to", to)
		cmd.Env = childEnv()
		cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: flags, HideWindow: true}
		if lastErr = cmd.Start(); lastErr == nil {
			return cmd, nil
		}
	}
	return nil, lastErr
}

// runSwap is `rcon.exe swap --from <running> --to <staged>`, started only by
// the service's hand-off. Only the upgrade-lock holder records results or
// touches the journal, so a swapper that can't get the lock just exits.
func runSwap(args []string) {
	fs := flag.NewFlagSet("swap", flag.ExitOnError)
	from := fs.String("from", "", "version of the running service")
	to := fs.String("to", "", "staged release version to switch to")
	_ = fs.Parse(args)
	if err := ensureIdentityDir(windowsPath("logs")); err == nil {
		if f, err := os.OpenFile(windowsPath("logs", "upgrade.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
			defer f.Close()
			log.SetOutput(f)
		}
	}
	if err := ensureIdentityDir(windowsPath("state")); err != nil {
		log.Printf("swap: %v", err)
		os.Exit(1)
	}
	unlock, ok, err := tryUpgradeLock()
	if err != nil || !ok {
		log.Printf("swap: %s -> %s not attempted: upgrade lock unavailable (%v)", *from, *to, err)
		os.Exit(1)
	}
	res := upgradeResult{From: *from, To: *to}
	if err := swapService(*from, *to, &res); err != nil {
		res.Reason = err.Error()
		log.Printf("swap: %s -> %s FAILED: %v", *from, *to, err)
	}
	res.At = nowStamp()
	if err := writeUpgradeResult(res); err != nil {
		log.Printf("swap: cannot record result: %v", err)
	}
	unlock()
	if !res.OK {
		os.Exit(1)
	}
}

// swapService runs with the upgrade lock held: read-only checks, then the
// shared state-changing sequence (swapUpgrade).
func swapService(from, to string, res *upgradeResult) error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return fmt.Errorf("must run elevated; the RCON service starts the swapper itself")
	}
	if !validReleaseVersion(to) || !validReleaseVersion(from) {
		return fmt.Errorf("invalid version (from %q, to %q)", from, to)
	}
	if killable, err := inKillOnCloseJob(); err != nil || killable {
		if err == nil {
			err = fmt.Errorf("swapper runs inside a kill-on-close job and would die with the service")
		}
		return fmt.Errorf("refusing before touching anything: %w", err)
	}
	if journalExists() {
		return fmt.Errorf("an earlier upgrade journal is still unresolved; restarting the service settles it")
	}
	target := releaseExe(to)
	if err := verifyStagedRelease(to, target); err != nil {
		return fmt.Errorf("staged release %s: %w", to, err)
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	h := &windowsUpgradeHost{}
	defer h.Close()
	s, err := h.service()
	if err != nil {
		return err
	}
	cfg, err := s.Config()
	if err != nil {
		return err
	}
	prev := cfg.BinaryPathName
	argv, err := windows.DecomposeCommandLine(prev)
	if err != nil || len(argv) < 2 || argv[1] != "service" {
		return fmt.Errorf("unrecognized service command %q", prev)
	}
	// The service must be running THIS binary: it is both the rollback target
	// and the only release known to work on this node.
	if !samePath(argv[0], self) || !samePath(self, releaseExe(from)) {
		return fmt.Errorf("service runs %s, not the swapper's own release %s", argv[0], self)
	}
	if err := ensureRestartOnFailure(s); err != nil {
		return fmt.Errorf("configure service recovery: %w (nothing changed)", err)
	}
	_ = os.Remove(healthMarkerPath())
	j := upgradeJournal{From: from, To: to, PrevCommand: prev, NextCommand: serviceCommandLine(target, argv[1:]),
		Started: time.Now().UTC()}
	if err := swapUpgrade(h, j, self, target, res); err != nil {
		return err
	}
	log.Printf("swap: %s is healthy — committed (previous %s kept for rollback)", to, from)
	pruneReleases(from, to)
	return nil
}

// serviceStartupRecovery runs first when the service starts: before the
// configuration, directory checks and log file, any of which can fail. So a
// new release that fails anywhere in startup is still counted, and its crash
// loop rolled back. True means stop now so the service restarts.
func serviceStartupRecovery() (restart bool) {
	if !journalExists() {
		return false
	}
	// The journal is acted on only from a directory that passes trust checks.
	if err := ensureIdentityDir(windowsPath("state")); err != nil {
		return false
	}
	if ensureIdentityDir(windowsPath("logs")) == nil {
		if f, err := os.OpenFile(windowsPath("logs", "upgrade.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
			log.SetOutput(f)
			defer func() { log.SetOutput(os.Stderr); f.Close() }()
		}
	}
	unlock, ok, err := tryUpgradeLock()
	if err != nil || !ok {
		return false // a live swapper is timing this start itself
	}
	defer unlock()
	h := &windowsUpgradeHost{}
	defer h.Close()
	return startupRecovery(h, version)
}

// armPendingUpgrade runs once the service is up. A journal means an upgrade
// was in flight when this process started.
func armPendingUpgrade() {
	go func() {
		for {
			j, err := readJournal()
			switch {
			case os.IsNotExist(err):
				return
			case err == nil && j.To == version:
				watchAsNewRelease()
				return
			case err == nil, errors.Is(err, errUnreadableJournal):
				settleJournal(true) // previous or unrelated release running
				return
			}
			time.Sleep(10 * time.Second) // transient read error: try again
		}
	}()
}

// watchAsNewRelease is the fallback watchdog for a new release started under a
// journal. A live swapper holds the lock and decides itself; this acts once the
// lock is free, i.e. the swapper died or the machine rebooted, and keeps
// retrying while the journal names this release.
func watchAsNewRelease() {
	time.Sleep(upgradeHealthWindow + 30*time.Second)
	for {
		j, err := readJournal()
		if os.IsNotExist(err) || errors.Is(err, errUnreadableJournal) || (err == nil && j.To != version) {
			return // settled, or not this release's to settle
		}
		if unlock, ok, err := tryUpgradeLock(); err == nil && ok {
			h := &windowsUpgradeHost{}
			restart := newReleaseDeadline(h, version, healthRecorded.Load())
			h.Close()
			unlock()
			if restart {
				requestSelfRestart("rolled back after a failed upgrade")
				return
			}
		}
		time.Sleep(30 * time.Second)
	}
}

// settleJournal settles a journal while the previous release (or an unrelated
// one) runs. It waits for a live swapper to finish, and retries until the
// journal is settled: nothing is dropped because a step failed.
func settleJournal(freshStart bool) {
	for attempt := 0; journalExists(); attempt++ {
		unlock, ok, err := tryUpgradeLock()
		if err == nil && ok {
			h := &windowsUpgradeHost{}
			err = settleAsPrevious(h, version, freshStart)
			h.Close()
			unlock()
			if err == nil {
				return
			}
			if errors.Is(err, errJournalNeedsOperator) {
				log.Printf("update: %v", err)
				return
			}
		}
		if err != nil && attempt%20 == 0 {
			log.Printf("update: settling the upgrade journal: %v (retrying)", err)
		}
		time.Sleep(30 * time.Second)
	}
}

// windowsUpgradeHost is the upgradeHost for the real service and C:\RCON\state.
type windowsUpgradeHost struct {
	m *mgr.Mgr
	s *mgr.Service
}

func (h *windowsUpgradeHost) service() (*mgr.Service, error) {
	if h.s != nil {
		return h.s, nil
	}
	m, err := mgr.Connect()
	if err != nil {
		return nil, err
	}
	s, err := m.OpenService(windowsServiceName)
	if err != nil {
		m.Disconnect()
		return nil, err
	}
	h.m, h.s = m, s
	return s, nil
}

func (h *windowsUpgradeHost) Close() {
	if h.s != nil {
		h.s.Close()
		h.m.Disconnect()
		h.m, h.s = nil, nil
	}
}

func (h *windowsUpgradeHost) ReadJournal() (upgradeJournal, error) { return readJournal() }
func (h *windowsUpgradeHost) WriteJournal(j upgradeJournal) error  { return writeJournal(j) }
func (h *windowsUpgradeHost) RemoveJournal() error                 { return removeJournal() }
func (h *windowsUpgradeHost) ReadResult() (upgradeResult, error)   { return readUpgradeResult() }
func (h *windowsUpgradeHost) WriteResult(r upgradeResult) error    { return writeUpgradeResult(r) }
func (h *windowsUpgradeHost) Now() time.Time                       { return time.Now() }

func (h *windowsUpgradeHost) ServiceCommand() (string, error) {
	s, err := h.service()
	if err != nil {
		return "", err
	}
	cfg, err := s.Config()
	return cfg.BinaryPathName, err
}

func (h *windowsUpgradeHost) SetServiceCommand(command string) error {
	s, err := h.service()
	if err != nil {
		return err
	}
	return setServiceCommand(s, command)
}

func (h *windowsUpgradeHost) RestartService(exe string) (time.Time, error) {
	s, err := h.service()
	if err != nil {
		return time.Time{}, err
	}
	return restartIntoConfigured(s, exe)
}

func (h *windowsUpgradeHost) AwaitHealthy(ver string, since time.Time) error {
	s, err := h.service()
	if err != nil {
		return err
	}
	return awaitHealthy(s, ver, since)
}

// ValidCommand: a journal's commands must run a release's own executable as
// the service, so a damaged journal can never point the service elsewhere.
func (h *windowsUpgradeHost) ValidCommand(command, ver string) bool {
	argv, err := windows.DecomposeCommandLine(command)
	return err == nil && validReleaseVersion(ver) && len(argv) >= 2 && argv[1] == "service" &&
		samePath(argv[0], releaseExe(ver))
}

// verifyStagedRelease re-checks what the service is about to run: a trusted,
// private, single-link file whose hash and signature match its manifest.
func verifyStagedRelease(ver, exe string) error {
	for _, p := range []struct {
		path string
		dir  bool
	}{{filepath.Dir(exe), true}, {exe, false}} {
		h, err := openTrustedPath(p.path, true, p.dir)
		if err != nil {
			return fmt.Errorf("%s: %w", p.path, err)
		}
		windows.CloseHandle(h)
	}
	raw, err := readSmallFile(filepath.Join(filepath.Dir(exe), "release.json"), 64<<10)
	if err != nil {
		return err
	}
	var m releaseManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("release.json: %w", err)
	}
	if m.Version != ver || m.GOOS != runtime.GOOS || m.GOARCH != runtime.GOARCH {
		return fmt.Errorf("release.json describes %s %s/%s", m.Version, m.GOOS, m.GOARCH)
	}
	bin, err := os.ReadFile(exe)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(bin)
	if hex.EncodeToString(sum[:]) != m.SHA256 {
		return fmt.Errorf("binary does not match its signed sha256")
	}
	if _, err := verifyReleaseSignature(m.Version, m.GOOS, m.GOARCH, m.SHA256, m.Signature); err != nil {
		return err
	}
	return nil
}

// serviceCommandLine rebuilds an SCM command with a new executable and the
// original arguments. The executable is always quoted.
func serviceCommandLine(exe string, args []string) string {
	parts := []string{`"` + exe + `"`}
	for _, a := range args {
		parts = append(parts, syscall.EscapeArg(a))
	}
	return strings.Join(parts, " ")
}

func samePath(a, b string) bool {
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

func setServiceCommand(s *mgr.Service, command string) error {
	p, err := windows.UTF16PtrFromString(command)
	if err != nil {
		return err
	}
	return windows.ChangeServiceConfig(s.Handle, windows.SERVICE_NO_CHANGE, windows.SERVICE_NO_CHANGE,
		windows.SERVICE_NO_CHANGE, p, nil, nil, nil, nil, nil, nil)
}

// ensureRestartOnFailure makes SCM restart the service after any failure,
// including a clean exit with an error code. Upgrades rely on it.
func ensureRestartOnFailure(s *mgr.Service) error {
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 10 * time.Second}}, 86400); err != nil {
		return err
	}
	return s.SetRecoveryActionsOnNonCrashFailures(true)
}

// restartIntoConfigured terminates the running service process (expected to be
// exe) and starts the service again with its configured command. Termination
// is a failure to SCM, so its recovery action restarts the service even if
// this process dies before its own StartService call.
func restartIntoConfigured(s *mgr.Service, exe string) (time.Time, error) {
	st, err := s.Query()
	if err != nil {
		return time.Time{}, err
	}
	if pid := st.ProcessId; pid != 0 {
		if err := terminateProcess(pid, exe); err != nil {
			return time.Time{}, fmt.Errorf("terminate service process %d: %w", pid, err)
		}
		deadline := time.Now().Add(serviceStopTimeout)
		for {
			if st, err = s.Query(); err != nil {
				return time.Time{}, err
			}
			if st.State == svc.Stopped || (st.ProcessId != 0 && st.ProcessId != pid) {
				break
			}
			if time.Now().After(deadline) {
				return time.Time{}, fmt.Errorf("service did not stop within %s", serviceStopTimeout)
			}
			time.Sleep(250 * time.Millisecond)
		}
	}
	began := time.Now()
	if err := s.Start(); err != nil && err != windows.ERROR_SERVICE_ALREADY_RUNNING {
		log.Printf("swap: start: %v (service recovery restarts it)", err)
	}
	return began, nil
}

// terminateProcess ends pid only if it is still running exe, so a recycled PID
// can never take down an unrelated process.
func terminateProcess(pid uint32, exe string) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return err
	}
	if image := windows.UTF16ToString(buf[:n]); !samePath(image, exe) {
		return fmt.Errorf("process %d runs %s, not %s", pid, image, exe)
	}
	if err := windows.TerminateProcess(h, selfRestartExitCode); err != nil {
		return err
	}
	_, _ = windows.WaitForSingleObject(h, 30000)
	return nil
}

// awaitHealthy waits for the service process itself (matched by PID) running
// version ver to record a broker health check made after `since`.
func awaitHealthy(s *mgr.Service, ver string, since time.Time) error {
	deadline := time.Now().Add(upgradeHealthWindow)
	for time.Now().Before(deadline) {
		time.Sleep(2 * time.Second)
		st, err := s.Query()
		if err != nil || st.ProcessId == 0 {
			continue // stopped or restarting under SCM recovery; keep waiting
		}
		raw, err := readSmallFile(healthMarkerPath(), 4<<10)
		if err != nil {
			continue
		}
		var m healthMarker
		if json.Unmarshal(raw, &m) == nil && m.Version == ver && m.PID == int(st.ProcessId) &&
			m.At.After(since.Add(-5*time.Second)) {
			return nil
		}
	}
	return fmt.Errorf("%s did not report a healthy broker tunnel within %s", ver, upgradeHealthWindow)
}

// pruneReleases keeps the two releases involved in the last swap plus the
// newest other ones, up to releasesRetained. Only plain directories with valid
// version names are ever removed; anything unexpected is left alone.
func pruneReleases(keep ...string) {
	dir := windowsPath("releases")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type release struct {
		name string
		mod  time.Time
	}
	var others []release
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() || !validReleaseVersion(name) {
			continue
		}
		kept := false
		for _, k := range keep {
			kept = kept || strings.EqualFold(name, k)
		}
		if kept {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if a, ok := info.Sys().(*syscall.Win32FileAttributeData); !ok || a.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			continue
		}
		others = append(others, release{name, info.ModTime()})
	}
	sort.Slice(others, func(i, j int) bool { return others[i].mod.After(others[j].mod) })
	for i, r := range others {
		if i < releasesRetained-len(keep) {
			continue
		}
		if err := os.RemoveAll(filepath.Join(dir, r.name)); err != nil {
			log.Printf("update: prune %s: %v", r.name, err)
		} else {
			log.Printf("update: pruned old release %s", r.name)
		}
	}
}

// tryUpgradeLock takes an exclusive byte-range lock on a file in the protected
// state directory. Only SYSTEM and Administrators can create or open that file,
// so an ordinary user can't squat the lock (a named mutex can be pre-created by
// anyone). Windows releases the lock when the holder exits, and the file stays
// openable for ensureIdentityDir's read-only walk.
func tryUpgradeLock() (unlock func(), ok bool, err error) {
	p, err := windows.UTF16PtrFromString(windowsPath("state", "upgrade.lock"))
	if err != nil {
		return nil, false, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, false, err
	}
	ol := new(windows.Overlapped)
	if err := windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ol); err != nil {
		windows.CloseHandle(h)
		if err == windows.ERROR_LOCK_VIOLATION {
			return nil, false, nil
		}
		return nil, false, err
	}
	return func() {
		_ = windows.UnlockFileEx(h, 0, 1, 0, ol)
		windows.CloseHandle(h)
	}, true, nil
}

var procIsProcessInJob = windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob")

// inKillOnCloseJob reports whether this process sits in a Job Object that
// would terminate it when the service (the job's likely owner) exits.
func inKillOnCloseJob() (bool, error) {
	var in int32
	if ok, _, err := procIsProcessInJob.Call(uintptr(windows.CurrentProcess()), 0, uintptr(unsafe.Pointer(&in))); ok == 0 {
		return false, fmt.Errorf("IsProcessInJob: %w", err)
	}
	if in == 0 {
		return false, nil
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	if err := windows.QueryInformationJobObject(0, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil); err != nil {
		return false, fmt.Errorf("in a job whose limits cannot be read: %w", err)
	}
	return info.BasicLimitInformation.LimitFlags&windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE != 0, nil
}

func readJournal() (upgradeJournal, error) {
	var j upgradeJournal
	raw, err := readSmallFile(journalPath(), 64<<10)
	if err != nil {
		return j, err
	}
	if err := json.Unmarshal(raw, &j); err != nil {
		return j, fmt.Errorf("%w: %v", errUnreadableJournal, err)
	}
	return j, nil
}

// pendingUpgradeReport surfaces an unsettled upgrade in /health.
func pendingUpgradeReport() map[string]any {
	if !journalExists() {
		return nil
	}
	j, err := readJournal()
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	return map[string]any{"from": j.From, "to": j.To, "switched": j.Switched, "rolling_back": j.RollingBack,
		"attempts": j.Attempts, "started": stamp(j.Started)}
}

// journalExists counts an unreadable journal as present: it still marks an
// upgrade nobody has settled.
func journalExists() bool {
	_, err := os.Lstat(journalPath())
	return !os.IsNotExist(err)
}

func writeJournal(j upgradeJournal) error {
	b, _ := json.MarshalIndent(j, "", "  ")
	return replaceFileAtomic(journalPath(), b, 0o600)
}

func removeJournal() error {
	if err := os.Remove(journalPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("cannot remove upgrade journal: %w", err)
	}
	return nil
}

func readUpgradeResult() (upgradeResult, error) {
	var r upgradeResult
	raw, err := readSmallFile(upgradeResultPath(), 64<<10)
	if err != nil {
		return r, err
	}
	return r, json.Unmarshal(raw, &r)
}

// writeUpgradeResult must only be called with the upgrade lock held.
func writeUpgradeResult(r upgradeResult) error {
	b, _ := json.MarshalIndent(r, "", "  ")
	return replaceFileAtomic(upgradeResultPath(), b, 0o600)
}

func readSmallFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err == nil && int64(len(b)) > limit {
		err = fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	return b, err
}
