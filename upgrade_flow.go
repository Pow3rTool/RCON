// Upgrade flows, shared by the swapper and by whichever release starts next.
// They touch the outside world only through upgradeHost, so tests can stop
// them at any step or make any step fail (upgrade_flow_test.go). Every caller
// holds the upgrade lock.
//
// Invariants the flows keep:
//   - the journal is written before anything changes, and stays until the
//     outcome no longer depends on it;
//   - once the new release has run and failed, a record that blocks it from
//     being offered again is durable before the journal goes away;
//   - an operation that fails leaves the journal in place to be retried.
package main

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"time"
)

var (
	errUnreadableJournal    = errors.New("unreadable upgrade journal")
	errJournalNeedsOperator = errors.New("upgrade journal needs an operator")
)

type upgradeHost interface {
	ReadJournal() (upgradeJournal, error) // fs.ErrNotExist when there is none
	WriteJournal(upgradeJournal) error
	RemoveJournal() error // nil if it is already gone
	ReadResult() (upgradeResult, error)
	WriteResult(upgradeResult) error
	ServiceCommand() (string, error)
	SetServiceCommand(string) error
	// RestartService ends the service process (which must be running exe) and
	// starts the service again with its configured command.
	RestartService(exe string) (time.Time, error)
	// AwaitHealthy waits for the service process running version to report a
	// healthy broker tunnel made after since.
	AwaitHealthy(version string, since time.Time) error
	// ValidCommand reports whether command runs release version as the service.
	ValidCommand(command, version string) bool
	Now() time.Time
}

var upgradeRetryDelay = time.Second

// persist retries a state write a few times: these records are what let the
// next process recover, and what stop a failed release being offered again.
func persist(what string, write func() error) error {
	var err error
	for i := 0; i < 3; i++ {
		if err = write(); err == nil {
			return nil
		}
		time.Sleep(upgradeRetryDelay)
	}
	log.Printf("update: cannot record %s: %v", what, err)
	return err
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func resultBefore(r upgradeResult, t time.Time) bool {
	at, err := time.Parse(time.RFC3339, r.At)
	return err != nil || at.Before(t.Truncate(time.Second))
}

// swapUpgrade is the swapper's state-changing sequence, run after every
// read-only check has passed. fromExe/toExe are the two releases' executables.
func swapUpgrade(h upgradeHost, j upgradeJournal, fromExe, toExe string, res *upgradeResult) error {
	if err := h.WriteJournal(j); err != nil {
		return fmt.Errorf("record pending upgrade: %w (nothing changed)", err)
	}
	if err := h.SetServiceCommand(j.NextCommand); err != nil {
		if rerr := h.RemoveJournal(); rerr != nil {
			log.Printf("update: %v (the running previous release settles the journal)", rerr)
		}
		return fmt.Errorf("point service at %s: %w (nothing changed; %s kept running)", j.To, err, j.From)
	}
	j.Switched = true
	if persist("the switch", func() error { return h.WriteJournal(j) }) != nil {
		log.Printf("update: continuing; recovery also reads the service command")
	}
	began, err := h.RestartService(fromExe)
	if err != nil {
		// The previous release never stopped: put its command back.
		if rerr := h.SetServiceCommand(j.PrevCommand); rerr != nil {
			return fmt.Errorf("restart into %s: %v; restoring %s's command also failed: %w (the journal stays for recovery)",
				j.To, err, j.From, rerr)
		}
		if rerr := h.RemoveJournal(); rerr != nil {
			j.Switched = false // the new release never ran
			_ = h.WriteJournal(j)
			log.Printf("update: %v (the running previous release settles the journal)", rerr)
		}
		return fmt.Errorf("restart into %s: %w (%s kept running)", j.To, err, j.From)
	}
	failure := h.AwaitHealthy(j.To, began)
	if failure == nil {
		res.OK = true
		if err := h.RemoveJournal(); err != nil {
			log.Printf("update: %v (the new release settles the journal)", err)
		}
		return nil
	}
	return rollBackAsSwapper(h, j, toExe, failure, res)
}

// rollBackAsSwapper records the failure, points the service back at the
// previous release, and restarts into it. The journal is kept, marked as
// rolling back, until the previous release runs and settles it: if this
// process dies part-way, the new release still finds it must yield.
func rollBackAsSwapper(h upgradeHost, j upgradeJournal, toExe string, failure error, res *upgradeResult) error {
	log.Printf("update: %v — rolling back to %s", failure, j.From)
	j.RollingBack, j.Reason = true, failure.Error()
	_ = persist("the rollback", func() error { return h.WriteJournal(j) })
	res.RolledBack, res.Reason, res.At = true, failure.Error(), stamp(h.Now())
	_ = persist("the failed release", func() error { return h.WriteResult(*res) })
	if err := h.SetServiceCommand(j.PrevCommand); err != nil {
		return fmt.Errorf("%v; restoring %s's command FAILED: %w (the journal stays; %s rolls itself back)",
			failure, j.From, err, j.To)
	}
	began, err := h.RestartService(toExe)
	if err != nil {
		return fmt.Errorf("%v; pointed the service back at %s, but restarting it failed: %w (service recovery retries)",
			failure, j.From, err)
	}
	if err := h.AwaitHealthy(j.From, began); err != nil {
		return fmt.Errorf("%v; rolled back to %s, which has not reported healthy yet: %w", failure, j.From, err)
	}
	return fmt.Errorf("%v; rolled back to %s", failure, j.From)
}

// startupRecovery runs first when the service process starts, before
// configuration or logging (both can fail fatally), and only when no swapper
// holds the lock. For a new release it counts the start. True means the
// process must exit now so the service restarts into the previous release: a
// crash loop, or a rollback already under way.
func startupRecovery(h upgradeHost, running string) (restart bool) {
	j, err := h.ReadJournal()
	if err != nil || j.To != running {
		return false
	}
	j.Attempts++
	_ = persist("this start", func() error { return h.WriteJournal(j) })
	if decideUpgrade(j, running, false, false) != upgradeRollBack {
		return false
	}
	reason := j.Reason
	if !j.RollingBack {
		reason = fmt.Sprintf("%s started %d times without settling", running, j.Attempts)
	}
	return rollBackAsNewRelease(h, j, reason)
}

// newReleaseDeadline runs in a new release once its health window has passed
// and no swapper is deciding. True means the process must exit so the service
// restarts into the previous release. A journal it cannot act on yet stays.
func newReleaseDeadline(h upgradeHost, running string, healthy bool) (restart bool) {
	j, err := h.ReadJournal()
	if err != nil || j.To != running {
		return false
	}
	switch decideUpgrade(j, running, true, healthy) {
	case upgradeCommit:
		_ = persist("the commit", func() error {
			return h.WriteResult(upgradeResult{From: j.From, To: j.To, OK: true,
				Reason: "committed by the new release (swapper absent)", At: stamp(h.Now())})
		})
		if err := h.RemoveJournal(); err != nil {
			log.Printf("update: %v (retrying)", err)
		}
		return false
	case upgradeRollBack:
		reason := j.Reason
		if reason == "" {
			reason = "no healthy broker tunnel within the health window (swapper absent)"
		}
		return rollBackAsNewRelease(h, j, reason)
	}
	return false
}

// rollBackAsNewRelease runs in the new release. It marks the journal as
// rolling back, records the failure, and points the service at the previous
// release. True means the caller must exit so the service restarts into it.
// The journal stays for the previous release to settle.
func rollBackAsNewRelease(h upgradeHost, j upgradeJournal, reason string) bool {
	if !h.ValidCommand(j.PrevCommand, j.From) {
		log.Printf("update: journal's previous command %q does not run %s; not acting on it", j.PrevCommand, j.From)
		return false
	}
	log.Printf("update: rolling back %s -> %s: %s", j.To, j.From, reason)
	if !j.RollingBack {
		j.RollingBack, j.Reason = true, reason
		_ = persist("the rollback", func() error { return h.WriteJournal(j) })
	}
	_ = persist("the failed release", func() error {
		return h.WriteResult(upgradeResult{From: j.From, To: j.To, RolledBack: true, Reason: reason, At: stamp(h.Now())})
	})
	cur, err := h.ServiceCommand()
	if err != nil {
		log.Printf("update: cannot read the service command: %v (retrying)", err)
		return false
	}
	if cur != j.PrevCommand {
		if err := h.SetServiceCommand(j.PrevCommand); err != nil {
			log.Printf("update: cannot point the service back at %s: %v (retrying)", j.From, err)
			return false
		}
	}
	return true
}

// settleAsPrevious runs in the previous release while a journal exists.
// freshStart means this process started while the journal existed; otherwise
// it kept running through a hand-off that never took over. Any error keeps the
// journal for the caller to retry.
func settleAsPrevious(h upgradeHost, running string, freshStart bool) error {
	j, err := h.ReadJournal()
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if errors.Is(err, errUnreadableJournal) {
		// Journals are written atomically, so this is damage or tampering: there
		// is nothing to act on, and it would block every future upgrade.
		log.Printf("update: removing %v", err)
		return h.RemoveJournal()
	}
	if err != nil {
		return err
	}
	switch decideUpgrade(j, running, false, false) {
	case upgradeStale:
		log.Printf("update: dropping stale upgrade journal (%s -> %s); %s is running", j.From, j.To, running)
		return h.RemoveJournal()
	case upgradeAbandon:
	default:
		return nil // the new release settles its own journal
	}
	if !h.ValidCommand(j.PrevCommand, j.From) || !h.ValidCommand(j.NextCommand, j.To) {
		return fmt.Errorf("%w: its commands do not run releases %s and %s; check the service "+
			"configuration, then remove the journal", errJournalNeedsOperator, j.From, j.To)
	}
	cur, err := h.ServiceCommand()
	if err != nil {
		return fmt.Errorf("read the service command: %w", err)
	}
	switch cur {
	case j.NextCommand:
		if err := h.SetServiceCommand(j.PrevCommand); err != nil {
			return fmt.Errorf("point the service back at %s: %w", j.From, err)
		}
		log.Printf("update: pointed the service back at %s", j.From)
	case j.PrevCommand:
	default:
		log.Printf("update: the service command was changed outside the upgrade; leaving it")
	}
	// Starting fresh while the service had been switched means it was switched
	// back after the new release ran: that release failed.
	if j.RollingBack || (freshStart && j.Switched) {
		// Only drop the journal once the record that blocks the release is on disk.
		if r, err := h.ReadResult(); err != nil || !r.blocks(j.To) {
			reason := j.Reason
			if reason == "" {
				reason = j.To + " was replaced by " + j.From + " after it had taken over"
			}
			if err := h.WriteResult(upgradeResult{From: j.From, To: j.To, RolledBack: true,
				Reason: reason, At: stamp(h.Now())}); err != nil {
				return fmt.Errorf("record the failed release: %w", err)
			}
		}
	} else if r, err := h.ReadResult(); err != nil || r.To != j.To || resultBefore(r, j.Started) {
		_ = h.WriteResult(upgradeResult{From: j.From, To: j.To, At: stamp(h.Now()),
			Reason: "upgrade interrupted before " + j.To + " took over; " + j.From + " kept running"})
	}
	if err := h.RemoveJournal(); err != nil {
		return err
	}
	log.Printf("update: settled upgrade %s -> %s", j.From, j.To)
	return nil
}
