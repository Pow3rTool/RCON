package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The fixed wrapper waits for a pipe gate BEFORE executing operator code.
// Started assigns PowerShell to its Job Object before opening that gate, so
// descendants cannot escape cancellation in the Start/Assign race.
const powershellWrapper = `
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding
if ([Console]::In.ReadLine() -ne 'rcon-start') { exit 125 }
$rc = 0
try {
  Set-Location -LiteralPath $env:__TS_CWD -ErrorAction Stop
  $global:LASTEXITCODE = 0
  . ([ScriptBlock]::Create($env:__TS_CMD))
  $ok = $?
  if ($global:LASTEXITCODE -ne 0) { $rc = $global:LASTEXITCODE }
  elseif (-not $ok) { $rc = 1 }
} catch {
  [Console]::Error.WriteLine(($_ | Out-String))
  $rc = 1
} finally {
  if ($env:__TS_STATE) {
    [IO.File]::WriteAllText($env:__TS_STATE, $PWD.Path, (New-Object System.Text.UTF8Encoding($false)))
  }
}
exit $rc
`

type windowsProcessTree struct {
	mu                  sync.Mutex
	job                 windows.Handle
	readGate, writeGate *os.File
}

func (t *windowsProcessTree) Started(c *exec.Cmd) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	p, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(c.Process.Pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(p)
	if err := windows.AssignProcessToJobObject(t.job, p); err != nil {
		return fmt.Errorf("assign process tree: %w", err)
	}
	_, err = t.writeGate.WriteString("rcon-start\n")
	_ = t.writeGate.Close()
	_ = t.readGate.Close()
	return err
}
func (t *windowsProcessTree) Kill() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.job != 0 {
		return windows.TerminateJobObject(t.job, 124)
	}
	return nil
}
func (t *windowsProcessTree) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.readGate != nil {
		_ = t.readGate.Close()
	}
	if t.writeGate != nil {
		_ = t.writeGate.Close()
	}
	if t.job != 0 {
		_ = windows.CloseHandle(t.job)
		t.job = 0
	}
}
func (t *windowsProcessTree) Cancel() error { return t.Kill() }
func powershellPath() string {
	root, err := windows.GetSystemDirectory()
	if err != nil {
		return ""
	}
	return filepath.Join(root, "WindowsPowerShell", "v1.0", "powershell.exe")
}
func newShellCommand(ctx context.Context, command, cwd, state string, job bool) (*exec.Cmd, processTree, error) {
	h, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, nil, err
	}
	t := &windowsProcessTree{job: h}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err = windows.SetInformationJobObject(h, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		t.Close()
		return nil, nil, err
	}
	t.readGate, t.writeGate, err = os.Pipe()
	if err != nil {
		t.Close()
		return nil, nil, err
	}
	c := exec.CommandContext(ctx, powershellPath(), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", powershellWrapper)
	c.Env = childEnv("__TS_CWD="+cwd, "__TS_CMD="+command, "__TS_STATE="+state)
	c.Stdin = t.readGate
	c.Cancel = t.Kill
	c.WaitDelay = 3 * time.Second
	return c, t, nil
}
