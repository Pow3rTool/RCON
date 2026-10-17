package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	utf16codec "unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Same contract as remote_run's wrapper: UTF-8 output, and $LASTEXITCODE or a
// failed last statement folded into the exit code. Progress is silenced first:
// a user's first module load otherwise writes CLIXML progress records to stderr. The operator command arrives
// in an environment variable, never on the visible command line, and is removed
// from the environment before it runs so programs it starts do not inherit it.
const desktopLaunchWrapper = `
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding
$command = $env:__RCON_LAUNCH
Remove-Item Env:__RCON_LAUNCH -ErrorAction SilentlyContinue
$rc = 0
try {
  $global:LASTEXITCODE = 0
  . ([ScriptBlock]::Create($command))
  $ok = $?
  if ($global:LASTEXITCODE -ne 0) { $rc = $global:LASTEXITCODE }
  elseif (-not $ok) { $rc = 1 }
} catch {
  [Console]::Error.WriteLine(($_ | Out-String))
  $rc = 1
}
exit $rc
`

const desktopLaunchOutputCap = 1 << 20

func desktopLaunchEncoded() string {
	u := utf16codec.Encode([]rune(desktopLaunchWrapper))
	b := make([]byte, len(u)*2)
	for i, v := range u {
		b[2*i], b[2*i+1] = byte(v), byte(v>>8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func desktopEnvironmentBlock(env []string) []uint16 {
	return utf16codec.Encode([]rune(strings.Join(env, "\x00") + "\x00\x00"))
}

// Keeps the first cap bytes and keeps draining, so a chatty child never blocks.
type desktopCappedOutput struct {
	data      []byte
	truncated bool
}

func (o *desktopCappedOutput) drain(r io.Reader) {
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
		if room := desktopLaunchOutputCap - len(o.data); n > 0 {
			if n > room {
				n, o.truncated = room, true
			}
			o.data = append(o.data, buf[:n]...)
		}
		if err != nil {
			return
		}
	}
}

// Runs Windows PowerShell 5.1 as the session's logged-on user: their own token
// (the same filtered, non-elevated token Explorer runs with), environment,
// profile directory and desktop. Never SYSTEM, and nothing here can elevate.
// Without Wait it returns once PowerShell starts; GUI programs it opens stay on
// the user's desktop. With Wait it captures output and kills the whole process
// tree at the timeout.
func launchDesktopUser(session desktopSession, l DesktopLaunch) (map[string]any, error) {
	var self windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_ADJUST_PRIVILEGES, &self); err != nil {
		return nil, fmt.Errorf("OpenProcessToken: %w", err)
	}
	defer self.Close()
	for _, p := range []string{"SeTcbPrivilege", "SeAssignPrimaryTokenPrivilege", "SeIncreaseQuotaPrivilege"} {
		_ = desktopEnablePrivilege(self, p)
	}
	var token windows.Token
	if err := windows.WTSQueryUserToken(session.ID, &token); err != nil {
		return nil, fmt.Errorf("WTSQueryUserToken: %w", err)
	}
	defer token.Close()
	env, err := token.Environ(false)
	if err != nil {
		return nil, fmt.Errorf("user environment: %w", err)
	}
	block := desktopEnvironmentBlock(append(env, "__RCON_LAUNCH="+l.Command))
	dir := l.Directory
	if dir == "" {
		if dir, err = token.GetUserProfileDirectory(); err != nil {
			return nil, fmt.Errorf("user profile: %w", err)
		}
	}
	exe := powershellPath()
	cmd := syscall.EscapeArg(exe) + " -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + desktopLaunchEncoded()
	flags := uint32(windows.CREATE_SUSPENDED | windows.CREATE_UNICODE_ENVIRONMENT | windows.CREATE_NO_WINDOW)
	desktop := windows.StringToUTF16Ptr(`winsta0\default`)
	var proc windows.ProcessInformation
	start := time.Now()

	if !l.Wait {
		startup := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{})), Desktop: desktop}
		if err = windows.CreateProcessAsUser(token, windows.StringToUTF16Ptr(exe), windows.StringToUTF16Ptr(cmd), nil, nil, false, flags, &block[0], windows.StringToUTF16Ptr(dir), &startup, &proc); err != nil {
			return nil, fmt.Errorf("CreateProcessAsUser: %w", err)
		}
		defer windows.CloseHandle(proc.Process)
		defer windows.CloseHandle(proc.Thread)
		if _, err = windows.ResumeThread(proc.Thread); err != nil {
			windows.TerminateProcess(proc.Process, 1)
			return nil, fmt.Errorf("ResumeThread: %w", err)
		}
		return map[string]any{"ok": true, "input_status": "sent", "started": true, "pid": proc.ProcessId, "user": session.User}, nil
	}

	inheritable := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1}
	var outR, outW, errR, errW windows.Handle
	if err = windows.CreatePipe(&outR, &outW, inheritable, 0); err != nil {
		return nil, fmt.Errorf("CreatePipe: %w", err)
	}
	if err = windows.CreatePipe(&errR, &errW, inheritable, 0); err != nil {
		windows.CloseHandle(outR)
		windows.CloseHandle(outW)
		return nil, fmt.Errorf("CreatePipe: %w", err)
	}
	stdin, err := windows.CreateFile(windows.StringToUTF16Ptr("NUL"), windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, inheritable, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		for _, h := range []windows.Handle{outR, outW, errR, errW} {
			windows.CloseHandle(h)
		}
		return nil, fmt.Errorf("open NUL: %w", err)
	}
	childEnds := []windows.Handle{stdin, outW, errW}
	closeChildEnds := sync.OnceFunc(func() {
		for _, h := range childEnds {
			windows.CloseHandle(h)
		}
	})
	defer closeChildEnds()
	windows.SetHandleInformation(outR, windows.HANDLE_FLAG_INHERIT, 0)
	windows.SetHandleInformation(errR, windows.HANDLE_FLAG_INHERIT, 0)

	// Inherit exactly the three standard handles, nothing else the service holds.
	attrs, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return nil, fmt.Errorf("NewProcThreadAttributeList: %w", err)
	}
	defer attrs.Delete()
	if err = attrs.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&childEnds[0]), uintptr(len(childEnds))*unsafe.Sizeof(childEnds[0])); err != nil {
		return nil, fmt.Errorf("handle list: %w", err)
	}
	startup := windows.StartupInfoEx{ProcThreadAttributeList: attrs.List()}
	startup.Cb = uint32(unsafe.Sizeof(startup))
	startup.Desktop = desktop
	startup.Flags = windows.STARTF_USESTDHANDLES
	startup.StdInput, startup.StdOutput, startup.StdErr = stdin, outW, errW

	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("CreateJobObject: %w", err)
	}
	defer windows.CloseHandle(job) // kill-on-close: nothing outlives a waited launch
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return nil, fmt.Errorf("SetInformationJobObject: %w", err)
	}
	err = windows.CreateProcessAsUser(token, windows.StringToUTF16Ptr(exe), windows.StringToUTF16Ptr(cmd), nil, nil, true, flags|windows.EXTENDED_STARTUPINFO_PRESENT, &block[0], windows.StringToUTF16Ptr(dir), &startup.StartupInfo, &proc)
	runtime.KeepAlive(childEnds)
	if err != nil {
		windows.CloseHandle(outR)
		windows.CloseHandle(errR)
		return nil, fmt.Errorf("CreateProcessAsUser: %w", err)
	}
	defer windows.CloseHandle(proc.Process)
	defer windows.CloseHandle(proc.Thread)
	if err = windows.AssignProcessToJobObject(job, proc.Process); err != nil {
		windows.TerminateProcess(proc.Process, 1)
		windows.CloseHandle(outR)
		windows.CloseHandle(errR)
		return nil, fmt.Errorf("AssignProcessToJobObject: %w", err)
	}
	closeChildEnds() // pipes reach EOF when the child tree exits
	var stdout, stderr desktopCappedOutput
	var readers sync.WaitGroup
	for _, r := range []struct {
		h windows.Handle
		o *desktopCappedOutput
	}{{outR, &stdout}, {errR, &stderr}} {
		readers.Add(1)
		go func(h windows.Handle, o *desktopCappedOutput) {
			defer readers.Done()
			o.drain(desktopHandleReader(h))
		}(r.h, r.o)
	}
	if _, err = windows.ResumeThread(proc.Thread); err != nil {
		windows.TerminateJobObject(job, 1)
	}
	timedOut := false
	if event, _ := windows.WaitForSingleObject(proc.Process, uint32(l.TimeoutMS)); event == uint32(windows.WAIT_TIMEOUT) {
		timedOut = true
		windows.TerminateJobObject(job, 124)
	}
	done := make(chan struct{})
	go func() { readers.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		// A background grandchild still holds the pipes; end the tree.
		windows.TerminateJobObject(job, 124)
		<-done
	}
	windows.CloseHandle(outR)
	windows.CloseHandle(errR)
	var code uint32
	_ = windows.GetExitCodeProcess(proc.Process, &code)
	return map[string]any{"ok": true, "input_status": "sent", "pid": proc.ProcessId, "user": session.User,
		"exit_code": code, "timed_out": timedOut, "stdout": string(stdout.data), "stderr": string(stderr.data),
		"truncated": stdout.truncated || stderr.truncated, "duration_ms": time.Since(start).Milliseconds()}, nil
}

type desktopHandleReader windows.Handle

func (h desktopHandleReader) Read(p []byte) (int, error) {
	var n uint32
	err := windows.ReadFile(windows.Handle(h), p, &n, nil)
	if err == windows.ERROR_BROKEN_PIPE || (err == nil && n == 0) {
		return int(n), io.EOF
	}
	return int(n), err
}
