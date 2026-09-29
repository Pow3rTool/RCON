package main

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"time"
)

// crashNow stands in for the calling process dying at an arbitrary step.
type crashNow struct{}

const simFrom, simTo = "v1", "v2"

var simNow = time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)

func simExe(v string) string     { return `C:\RCON\releases\` + v + `\rcon.exe` }
func simCommand(v string) string { return `"` + simExe(v) + `" service --etc C:\RCON\etc` }

// upgradeSim is an in-memory node for the upgrade flows: the journal, the last
// result, the service command, and which release's service process is running.
// It can make any operation fail, or stop the caller at any operation.
type upgradeSim struct {
	t                *testing.T
	journal          *upgradeJournal
	result           *upgradeResult
	command          string
	running          string          // release whose process is running; "" when stopped
	healthy          map[string]bool // releases that can reach the broker
	crashAt          int             // stop the caller at this operation (1-based); 0 = never
	failWhen         func(op string, nth int) bool
	crashesAtStartup bool // the new release dies during startup, after recovery ran
	newRan           bool // the new release's process ran at some point
	ops              int
	counts           map[string]int
	trace            []string
}

func newUpgradeSim(t *testing.T, newHealthy bool) *upgradeSim {
	old := upgradeRetryDelay
	upgradeRetryDelay = 0
	t.Cleanup(func() { upgradeRetryDelay = old })
	return &upgradeSim{t: t, command: simCommand(simFrom), running: simFrom,
		healthy: map[string]bool{simFrom: true, simTo: newHealthy}, counts: map[string]int{}}
}

func (s *upgradeSim) op(name string) error {
	s.ops++
	s.counts[name]++
	s.trace = append(s.trace, name)
	if s.crashAt != 0 && s.ops == s.crashAt {
		panic(crashNow{})
	}
	if s.failWhen != nil && s.failWhen(name, s.counts[name]) {
		return fmt.Errorf("injected %s failure", name)
	}
	return nil
}

func (s *upgradeSim) ReadJournal() (upgradeJournal, error) {
	if err := s.op("ReadJournal"); err != nil {
		return upgradeJournal{}, err
	}
	if s.journal == nil {
		return upgradeJournal{}, fs.ErrNotExist
	}
	return *s.journal, nil
}

func (s *upgradeSim) WriteJournal(j upgradeJournal) error {
	if err := s.op("WriteJournal"); err != nil {
		return err
	}
	s.journal = &j
	return nil
}

func (s *upgradeSim) RemoveJournal() error {
	if err := s.op("RemoveJournal"); err != nil {
		return err
	}
	s.journal = nil
	return nil
}

func (s *upgradeSim) ReadResult() (upgradeResult, error) {
	if err := s.op("ReadResult"); err != nil {
		return upgradeResult{}, err
	}
	if s.result == nil {
		return upgradeResult{}, fs.ErrNotExist
	}
	return *s.result, nil
}

func (s *upgradeSim) WriteResult(r upgradeResult) error {
	if err := s.op("WriteResult"); err != nil {
		return err
	}
	s.result = &r
	return nil
}

func (s *upgradeSim) ServiceCommand() (string, error) {
	if err := s.op("ServiceCommand"); err != nil {
		return "", err
	}
	return s.command, nil
}

func (s *upgradeSim) SetServiceCommand(c string) error {
	if err := s.op("SetServiceCommand"); err != nil {
		return err
	}
	s.command = c
	return nil
}

func (s *upgradeSim) RestartService(exe string) (time.Time, error) {
	if err := s.op("RestartService"); err != nil {
		return time.Time{}, err
	}
	if s.running != "" && simExe(s.running) != exe {
		return time.Time{}, fmt.Errorf("service runs %s, not %s", s.running, exe)
	}
	s.start()
	return simNow, nil
}

func (s *upgradeSim) AwaitHealthy(v string, _ time.Time) error {
	if err := s.op("AwaitHealthy"); err != nil {
		return err
	}
	if s.running == v && s.healthy[v] {
		return nil
	}
	return fmt.Errorf("%s did not report a healthy broker tunnel", v)
}

func (s *upgradeSim) ValidCommand(c, v string) bool { return c == simCommand(v) }
func (s *upgradeSim) Now() time.Time                { return simNow }

// start is the service manager starting whatever release is configured.
func (s *upgradeSim) start() {
	s.running = ""
	for _, v := range []string{simFrom, simTo} {
		if s.command == simCommand(v) {
			s.running = v
		}
	}
	if s.running == simTo {
		s.newRan = true
	}
}

// boot is the service manager (re)starting the service with no swapper alive:
// the configured release runs its startup recovery first. A release that asks
// to exit, or dies during startup, is started again.
func (s *upgradeSim) boot() {
	for i := 0; i < 20; i++ {
		s.start()
		if startupRecovery(s, s.running) {
			continue
		}
		if s.running == simTo && s.crashesAtStartup {
			continue
		}
		return
	}
	s.t.Fatal("service restart loop never ended")
}

// runSwapper plays the swapper: the shared sequence, then runSwap's final result
// write. It reports whether the swapper died part-way.
func (s *upgradeSim) runSwapper() (died bool) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(crashNow); !ok {
				panic(r)
			}
			died = true
		}
	}()
	j := upgradeJournal{From: simFrom, To: simTo, PrevCommand: simCommand(simFrom),
		NextCommand: simCommand(simTo), Started: simNow}
	res := upgradeResult{From: simFrom, To: simTo}
	if err := swapUpgrade(s, j, simExe(simFrom), simExe(simTo), &res); err != nil {
		res.Reason = err.Error()
	}
	res.At = stamp(simNow)
	_ = s.WriteResult(res)
	return false
}

// afterSwapper plays out the rest once no swapper is alive, the way each
// release's own recovery and the service manager would, until the journal is
// settled. prevNeverStopped: the previous release kept running throughout.
func (s *upgradeSim) afterSwapper(prevNeverStopped bool) {
	s.crashAt = 0
	fresh := !prevNeverStopped
	for i := 0; i < 50 && s.journal != nil; i++ {
		switch s.running {
		case simTo:
			if newReleaseDeadline(s, simTo, s.healthy[simTo]) {
				s.boot()
				fresh = true
			}
		case simFrom:
			_ = settleAsPrevious(s, simFrom, fresh)
		default:
			s.boot()
			fresh = true
		}
	}
	if s.journal != nil {
		s.t.Fatalf("journal never settled: %+v", *s.journal)
	}
}

func (s *upgradeSim) assertSettled(label, wantRunning string, wantBlocked bool) {
	s.t.Helper()
	if s.journal != nil {
		s.t.Fatalf("%s: journal left behind: %+v", label, *s.journal)
	}
	if s.running != wantRunning || s.command != simCommand(wantRunning) {
		s.t.Fatalf("%s: running %q with command %q, want %s", label, s.running, s.command, wantRunning)
	}
	blocked := s.result != nil && s.result.blocks(simTo)
	if blocked != wantBlocked {
		s.t.Fatalf("%s: %s blocked=%v, want %v (result %+v)", label, simTo, blocked, wantBlocked, s.result)
	}
}

func TestUpgradeWithoutInterruption(t *testing.T) {
	s := newUpgradeSim(t, true)
	s.runSwapper()
	s.assertSettled("healthy release", simTo, false)
	if s.result == nil || !s.result.OK {
		t.Fatalf("commit not recorded: %+v", s.result)
	}
	s = newUpgradeSim(t, false)
	s.runSwapper()
	if s.journal == nil || !s.journal.RollingBack {
		t.Fatal("rollback journal removed before the previous release settled it")
	}
	s.afterSwapper(false)
	s.assertSettled("failed release", simFrom, true)
}

// The swapper can die after any single operation. Whatever runs next must
// leave the node on a working release, with a failed release blocked from
// being offered again, and nothing left pending.
func TestUpgradeSurvivesSwapperDeathAtEveryStep(t *testing.T) {
	for _, healthy := range []bool{true, false} {
		clean := newUpgradeSim(t, healthy)
		clean.runSwapper()
		for k := 1; k <= clean.ops; k++ {
			s := newUpgradeSim(t, healthy)
			s.crashAt = k
			if !s.runSwapper() {
				t.Fatalf("healthy=%v: no death at step %d", healthy, k)
			}
			label := fmt.Sprintf("healthy=%v, swapper died at step %d (%s)", healthy, k, s.trace[len(s.trace)-1])
			s.afterSwapper(!s.newRan)
			want := simFrom
			if healthy && s.newRan {
				want = simTo
			}
			s.assertSettled(label, want, !healthy && s.newRan)
		}
	}
}

// Regression: the swapper dies after pointing the service back but before
// stopping the failed release. That release must still find the journal.
func TestRollbackJournalOutlivesSwapper(t *testing.T) {
	clean := newUpgradeSim(t, false)
	clean.runSwapper()
	restarts := 0
	for i, op := range clean.trace {
		if op == "RestartService" {
			if restarts++; restarts == 2 {
				s := newUpgradeSim(t, false)
				s.crashAt = i + 1
				s.runSwapper()
				if s.running != simTo || s.command != simCommand(simFrom) || s.journal == nil || !s.journal.RollingBack {
					t.Fatalf("state after the crash: running %s, command %s, journal %+v", s.running, s.command, s.journal)
				}
				s.afterSwapper(false)
				s.assertSettled("died before stopping the failed release", simFrom, true)
				return
			}
		}
	}
	t.Fatal("rollback restart not found in the swapper's trace")
}

// A new release that dies during startup with no swapper alive must be counted
// and rolled back, however early it dies after its recovery step.
func TestNewReleaseCrashLoopRollsBack(t *testing.T) {
	s := newUpgradeSim(t, true)
	s.journal = &upgradeJournal{From: simFrom, To: simTo, PrevCommand: simCommand(simFrom),
		NextCommand: simCommand(simTo), Switched: true, Started: simNow}
	s.command, s.running = simCommand(simTo), ""
	s.crashesAtStartup = true
	s.boot()
	if s.running != simFrom {
		t.Fatalf("crash loop not rolled back; running %q", s.running)
	}
	if s.journal == nil || s.journal.Attempts != upgradeMaxAttempts+1 {
		t.Fatalf("attempts: %+v", s.journal)
	}
	s.afterSwapper(false)
	s.assertSettled("crash loop", simFrom, true)
	if !strings.Contains(s.result.Reason, "started 4 times") {
		t.Fatalf("reason: %q", s.result.Reason)
	}
}

// A step that fails must keep the journal so it is retried, never drop it.
func TestRecoveryStepFailuresKeepTheJournal(t *testing.T) {
	rollingBack := func(s *upgradeSim, command, running string) {
		s.journal = &upgradeJournal{From: simFrom, To: simTo, PrevCommand: simCommand(simFrom),
			NextCommand: simCommand(simTo), Switched: true, RollingBack: true, Reason: "failed", Started: simNow}
		s.command, s.running = command, running
	}
	for _, test := range []struct {
		name, failOp, command string
	}{
		{"previous release can't read the service command", "ServiceCommand", simCommand(simFrom)},
		{"previous release can't point the service back", "SetServiceCommand", simCommand(simTo)},
		{"previous release can't record the blocked release", "WriteResult", simCommand(simFrom)},
		{"previous release can't remove the journal", "RemoveJournal", simCommand(simFrom)},
	} {
		s := newUpgradeSim(t, false)
		rollingBack(s, test.command, simFrom)
		s.failWhen = func(op string, nth int) bool { return op == test.failOp && nth == 1 }
		if err := settleAsPrevious(s, simFrom, true); err == nil || s.journal == nil {
			t.Fatalf("%s: err %v, journal %v", test.name, err, s.journal)
		}
		if err := settleAsPrevious(s, simFrom, true); err != nil {
			t.Fatalf("%s: retry: %v", test.name, err)
		}
		s.assertSettled(test.name, simFrom, true)
	}

	// The new release can't point the service back: it keeps running, keeps the
	// journal (now marked as rolling back), and succeeds on a later attempt.
	s := newUpgradeSim(t, false)
	s.journal = &upgradeJournal{From: simFrom, To: simTo, PrevCommand: simCommand(simFrom),
		NextCommand: simCommand(simTo), Switched: true, Started: simNow}
	s.command, s.running = simCommand(simTo), simTo
	s.failWhen = func(op string, nth int) bool { return op == "SetServiceCommand" && nth == 1 }
	if newReleaseDeadline(s, simTo, false) || s.journal == nil || !s.journal.RollingBack {
		t.Fatalf("new release gave up the journal: %+v", s.journal)
	}
	if !newReleaseDeadline(s, simTo, false) || s.command != simCommand(simFrom) {
		t.Fatal("rollback not retried")
	}
	s.boot()
	s.afterSwapper(false)
	s.assertSettled("new release retried its rollback", simFrom, true)

	// The swapper can't record the failure anywhere (every result write and the
	// rollback mark fail). The previous release still infers it and blocks it.
	s = newUpgradeSim(t, false)
	s.failWhen = func(op string, nth int) bool {
		return op == "WriteResult" || (op == "WriteJournal" && nth >= 3)
	}
	s.runSwapper()
	s.failWhen = nil
	s.afterSwapper(false)
	s.assertSettled("no failure record written", simFrom, true)
}

// A journal whose commands don't run the named releases is never applied to
// the service; it is left for an operator.
func TestJournalWithForeignCommandIsNotApplied(t *testing.T) {
	s := newUpgradeSim(t, false)
	s.journal = &upgradeJournal{From: simFrom, To: simTo, PrevCommand: `"C:\Temp\other.exe" service`,
		NextCommand: simCommand(simTo), Switched: true, Started: simNow}
	s.command, s.running = simCommand(simTo), simTo
	if newReleaseDeadline(s, simTo, false) || s.command != simCommand(simTo) {
		t.Fatal("new release applied a foreign command")
	}
	s.running = simFrom
	if err := settleAsPrevious(s, simFrom, true); !errors.Is(err, errJournalNeedsOperator) {
		t.Fatalf("settle: %v", err)
	}
	if s.journal == nil || s.command != simCommand(simTo) {
		t.Fatal("foreign journal was acted on or dropped")
	}
}
