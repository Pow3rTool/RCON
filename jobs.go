package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// envInt reads an int env var with a default (shared by the /run + /jobs caps).
func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// maxConcurrentJobs caps simultaneously-RUNNING async jobs on this node so a
// runaway agent can't exhaust processes/goroutines. Default is generous (an admin
// may legitimately fan out many parallel tasks — well past 16); configurable via
// RCON_MAX_JOBS; 0 = unlimited. Exceeding it is a *temporary* 429, never a denial.
func maxConcurrentJobs() int { return envInt("RCON_MAX_JOBS", 64) }

// A Job decouples a long-running command from any single tunnel/stream. It runs
// in its OWN process group (so cancel reaps cleanly), buffers output against a
// monotonic cursor (so a client can reattach after a blip and resume with no
// loss/dupes), and survives tunnel drops — only an explicit cancel kills it.
type Job struct {
	ID       string
	Cmd      string
	RID      string // XConnect correlation id (cross-ref to the central Witchhunt)
	mu       sync.Mutex
	buf      []byte // output, capped; cursor = index into this
	truncated bool
	state    string // "running" | "exited"
	exit     int
	pgid     int
	started  time.Time
	ended    time.Time
}

const jobBufCap = 4 << 20 // 4 MB buffered per job before truncation

func (j *Job) append(p []byte) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.truncated {
		return
	}
	if len(j.buf)+len(p) > jobBufCap {
		p = p[:jobBufCap-len(j.buf)]
		j.truncated = true
	}
	j.buf = append(j.buf, p...)
}

// Read returns buffered output from `from`, plus the new cursor and whether this
// is the end (process exited and nothing more will arrive).
func (j *Job) Read(from, max int) (data []byte, next int, eof bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if from < 0 || from > len(j.buf) {
		from = len(j.buf)
	}
	end := len(j.buf)
	if max > 0 && end-from > max {
		end = from + max
	}
	data = append([]byte(nil), j.buf[from:end]...)
	next = end
	eof = j.state == "exited" && next == len(j.buf)
	return
}

func (j *Job) snapshotState() (string, int) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.state, j.exit
}

// Dur is the job's wall-clock seconds: total once exited, else elapsed-so-far.
func (j *Job) Dur() float64 {
	j.mu.Lock()
	defer j.mu.Unlock()
	end := j.ended
	if end.IsZero() {
		end = time.Now()
	}
	return end.Sub(j.started).Seconds()
}

func (j *Job) finish(state string, exit int) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.state, j.exit, j.ended = state, exit, time.Now()
}

func (j *Job) Cancel() {
	if j.pgid > 0 {
		// Kill the whole process group: SIGTERM, then SIGKILL shortly after.
		syscall.Kill(-j.pgid, syscall.SIGTERM)
		go func(pgid int) {
			time.Sleep(3 * time.Second)
			syscall.Kill(-pgid, syscall.SIGKILL)
		}(j.pgid)
	}
}

type JobStore struct {
	mu   sync.Mutex
	jobs map[string]*Job
	seq  int
}

func NewJobStore() *JobStore {
	s := &JobStore{jobs: map[string]*Job{}}
	go s.reapLoop()
	return s
}

// Start launches an async job. Returns an error (→ HTTP 429) when the running-job
// cap is hit; this is a transient backpressure signal, not an authorization denial
// — a slot frees as jobs finish, so the caller should slow down and retry.
//
// NB: jobs are principal-free BY DESIGN. RCON never sees the OBO principal (that
// lives at XConnect/Orthanc), so job IDs aren't principal-scoped — RCON trusts
// XConnect to have authorized the caller, and WHO ran a job is recovered via the
// rid <-> Witchhunt link, not on the node. Same trusted-operator model as the
// file/exec verbs (see ARCHITECTURE); a per-principal job ACL here would be
// theater against a caller XConnect already let through.
func (s *JobStore) Start(cmdStr, rid string) (*Job, error) {
	s.mu.Lock()
	if cap := maxConcurrentJobs(); cap > 0 {
		running := 0
		for _, j := range s.jobs {
			if st, _ := j.snapshotState(); st == "running" {
				running++
			}
		}
		if running >= cap {
			s.mu.Unlock()
			return nil, fmt.Errorf("node at its concurrent-job limit (%d running) — this is a temporary "+
				"rate limit, not a denial: a slot frees as running jobs finish, so wait a moment and retry "+
				"(operator can raise it with RCON_MAX_JOBS)", cap)
		}
	}
	s.seq++
	id := "job-" + time.Now().UTC().Format("150405") + "-" + itoa(s.seq)
	j := &Job{ID: id, Cmd: cmdStr, RID: rid, state: "running", started: time.Now(), exit: -1}
	s.jobs[id] = j
	s.mu.Unlock()

	cmd := exec.Command("/bin/bash", "-lc", cmdStr)
	cmd.Env = childEnv()                                  // scrub the join token from the child (see run.go)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // own process group
	stdout, _ := cmd.StdoutPipe()
	cmd.Stderr = cmd.Stdout // merge; bounded by the buffer cap
	if err := cmd.Start(); err != nil {
		j.append([]byte("failed to start: " + err.Error() + "\n"))
		j.finish("exited", 127)
		auditRecord("job", cmdStr, 127, 0, rid) // start failed — single record
		return j, nil
	}
	j.pgid = cmd.Process.Pid          // group leader == child pid
	auditRecord("job", cmdStr, -1, 0, rid) // node-side record (rc/dur unknown at start)

	go func() {
		r := bufio.NewReader(stdout)
		b := make([]byte, 32<<10)
		for {
			n, err := r.Read(b)
			if n > 0 {
				j.append(b[:n])
			}
			if err != nil {
				break
			}
		}
		exit := 0
		if err := cmd.Wait(); err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				exit = ee.ExitCode()
			} else {
				exit = -1
			}
		}
		j.finish("exited", exit)
		// Completion record carries the real rc + node-side duration.
		auditRecord("job", cmdStr, exit, j.Dur(), rid)
	}()
	return j, nil
}

func (s *JobStore) Get(id string) *Job {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.jobs[id]
}

// reapLoop frees buffers of jobs that finished a while ago. Running jobs are
// NEVER reaped for being unattended — that's the whole point.
func (s *JobStore) reapLoop() {
	const ttl = 10 * time.Minute
	for {
		time.Sleep(time.Minute)
		now := time.Now()
		s.mu.Lock()
		for id, j := range s.jobs {
			st, _ := j.snapshotState()
			if st == "exited" && !j.ended.IsZero() && now.Sub(j.ended) > ttl {
				delete(s.jobs, id)
			}
		}
		s.mu.Unlock()
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
