package main

import (
	"context"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

type unixProcessTree struct {
	mu          sync.Mutex
	cmd         *exec.Cmd
	cancelTimer *time.Timer
}

func (t *unixProcessTree) Started(c *exec.Cmd) error { return nil }
func (t *unixProcessTree) Kill() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cmd != nil && t.cmd.Process != nil {
		return syscall.Kill(-t.cmd.Process.Pid, syscall.SIGKILL)
	}
	return nil
}
func (t *unixProcessTree) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cancelTimer != nil {
		t.cancelTimer.Stop()
		// Wait may reap the group leader before TERM-ignoring descendants exit.
		// Finish cancellation before forgetting the group, with no delayed kill
		// left behind to target a subsequently reused PID.
		if t.cmd != nil && t.cmd.Process != nil {
			_ = syscall.Kill(-t.cmd.Process.Pid, syscall.SIGKILL)
		}
		t.cancelTimer = nil
	}
	t.cmd = nil
}
func (t *unixProcessTree) Cancel() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cmd == nil || t.cmd.Process == nil || t.cancelTimer != nil {
		return nil
	}
	pid := t.cmd.Process.Pid
	err := syscall.Kill(-pid, syscall.SIGTERM)
	t.cancelTimer = time.AfterFunc(3*time.Second, func() {
		t.mu.Lock()
		defer t.mu.Unlock()
		if t.cmd != nil && t.cmd.Process != nil && t.cmd.Process.Pid == pid {
			_ = syscall.Kill(-pid, syscall.SIGKILL)
		}
	})
	return err
}
func newShellCommand(ctx context.Context, command, cwd, state string, job bool) (*exec.Cmd, processTree, error) {
	c := exec.CommandContext(ctx, "/bin/bash", "-c", runWrapper)
	c.Env = childEnv("__TS_CWD="+cwd, "__TS_CMD="+command, "__TS_STATE="+state)
	if job {
		c = exec.CommandContext(ctx, "/bin/bash", "-lc", command)
		c.Env = childEnv()
	}
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	t := &unixProcessTree{cmd: c}
	c.Cancel = t.Kill
	c.WaitDelay = 3 * time.Second
	return c, t, nil
}
