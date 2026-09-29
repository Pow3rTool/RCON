// The pending-upgrade journal makes a Windows upgrade recoverable by whichever
// RCON process runs next — the swapper, the new release, or the previous one —
// even if the swapper dies or the machine reboots part-way. It exists while an
// upgrade is in flight, is only ever changed under the upgrade lock, and is
// removed only once the outcome no longer depends on it: after a commit, or
// after a rollback once the previous release is running again.
//
// The rule every process applies when it finds a journal (decideUpgrade):
//
//	running == To   new release: count the start and give it the health window,
//	                then commit if it reached the broker, otherwise roll back.
//	                A crash loop, or a rollback already under way, rolls back now.
//	running == From previous release: the upgrade did not take effect (or was
//	                rolled back). Keep the service pointed here, make sure a
//	                failed release stays blocked, and drop the journal.
//	neither         stale journal from some other pair of versions: drop it.
package main

import "time"

type upgradeJournal struct {
	From        string    `json:"from"`
	To          string    `json:"to"`
	PrevCommand string    `json:"prev_command"` // service command line running From
	NextCommand string    `json:"next_command"` // service command line running To
	Switched    bool      `json:"switched"`     // the service was pointed at To
	RollingBack bool      `json:"rolling_back"` // To failed; the service goes back to From
	Reason      string    `json:"reason,omitempty"`
	Attempts    int       `json:"attempts"` // starts of To counted without the swapper
	Started     time.Time `json:"started"`
}

// upgradeResult is the last upgrade's outcome, reported in /health. A result
// with RolledBack set blocks that release from being offered again.
type upgradeResult struct {
	From       string `json:"from"`
	To         string `json:"to"`
	OK         bool   `json:"ok"`
	RolledBack bool   `json:"rolled_back,omitempty"`
	Reason     string `json:"reason,omitempty"`
	At         string `json:"at"`
}

func (r upgradeResult) blocks(ver string) bool { return r.To == ver && r.RolledBack && !r.OK }

type upgradeAction int

const (
	upgradeStale    upgradeAction = iota // journal isn't about the running release: drop it
	upgradeWatch                         // new release: keep running, decide at the deadline
	upgradeCommit                        // new release reached the broker: keep it
	upgradeRollBack                      // new release failed: point the service back and restart into From
	upgradeAbandon                       // previous release is running: keep it configured, drop the journal
)

// A new release that keeps restarting without settling is rolled back.
const upgradeMaxAttempts = 3

func decideUpgrade(j upgradeJournal, running string, atDeadline, healthy bool) upgradeAction {
	switch running {
	case j.To:
		if j.RollingBack {
			return upgradeRollBack
		}
		if atDeadline {
			if healthy {
				return upgradeCommit
			}
			return upgradeRollBack
		}
		if j.Attempts > upgradeMaxAttempts {
			return upgradeRollBack
		}
		return upgradeWatch
	case j.From:
		return upgradeAbandon
	}
	return upgradeStale
}
