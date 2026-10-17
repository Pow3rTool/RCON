package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	utf16codec "unicode/utf16"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

const supportsDesktop = true
const desktopPipePrefix = `\\.\pipe\Pow3rTool-RCON-desktop-`

// Workers live only for one operation, in a kill-on-close Job Object. No
// executable copies, scripts, scheduled tasks, or user-writable IPC files.
var desktopManager = struct {
	sync.Mutex
	frames map[uint32]desktopGuard
	seen   map[string]time.Time
}{frames: map[uint32]desktopGuard{}, seen: map[string]time.Time{}}

type desktopSession struct {
	ID      uint32 `json:"session_id"`
	Station string `json:"station"`
	User    string `json:"user"`
	LogonID string `json:"logon_id"`
}
type desktopWorkerRequest struct {
	Safety      bool `json:",omitempty"`
	Root        string
	Command     desktopCommand
	Previous    desktopGuard
	Session     desktopSession
	Indicator   string `json:",omitempty"`
	Interaction bool   `json:",omitempty"`
}
type desktopWorkerResponse struct {
	Result map[string]any
	Guard  desktopGuard
	End    *desktopInteractionEnd `json:",omitempty"`
}

func desktopSystem() bool {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	return err == nil && u.User.Sid.IsWellKnown(windows.WinLocalSystemSid)
}
func desktopSessions() ([]desktopSession, error) {
	var rows *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &rows, &count); err != nil {
		return nil, err
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(rows)))
	result := []desktopSession{}
	for _, r := range unsafe.Slice(rows, count) {
		if r.SessionID == 0 || r.State != windows.WTSActive {
			continue
		}
		var token windows.Token
		if err := windows.WTSQueryUserToken(r.SessionID, &token); err != nil {
			continue
		}
		// TOKEN_STATISTICS begins with TokenId and AuthenticationId (two LUIDs).
		var stats [128]byte
		var n uint32
		err := windows.GetTokenInformation(token, windows.TokenStatistics, &stats[0], uint32(len(stats)), &n)
		user, e := token.GetTokenUser()
		token.Close()
		if err != nil || e != nil {
			continue
		}
		account, domain, _, e := user.User.Sid.LookupAccount("")
		if e != nil {
			account = user.User.Sid.String()
		} else if domain != "" {
			account = domain + `\` + account
		}
		result = append(result, desktopSession{r.SessionID, windows.UTF16PtrToString(r.WindowStationName), account, fmt.Sprintf("%x", stats[8:16])})
	}
	return result, nil
}
func selectDesktopSession(sessions []desktopSession, id uint32) (desktopSession, error) {
	if id == 0 && len(sessions) == 1 {
		return sessions[0], nil
	}
	for _, s := range sessions {
		if s.ID == id {
			return s, nil
		}
	}
	if len(sessions) == 0 {
		return desktopSession{}, errors.New("no active logged-on Windows session; log in or reconnect first")
	}
	return desktopSession{}, errors.New("select an active session_id from sessions")
}
func nativeDesktop(c desktopCommand) (result map[string]any) {
	requested := c // attach_console continues as an observe; log what was asked
	defer func() { desktopAuditCall(requested, result) }()
	selected := c.SessionID
	var attached map[string]any
	defer func() {
		annotateDesktopUnavailable(result, selected)
		// A failure after attaching still changed which session the console shows.
		for k, v := range attached {
			if result != nil {
				result[k] = v
			}
		}
	}()
	fail := func(err error) map[string]any { return desktopFailure(c.ID, "not_sent", err) }
	if !desktopSystem() {
		return fail(errors.New("desktop requires the LocalSystem RCON service"))
	}
	if !desktopManager.TryLock() {
		return fail(errors.New("desktop busy"))
	}
	defer desktopManager.Unlock()
	now := time.Now()
	for id, t := range desktopManager.seen {
		if now.Sub(t) > 180*time.Second {
			delete(desktopManager.seen, id)
		}
	}
	for id, f := range desktopManager.frames {
		if now.Sub(f.Created) > 180*time.Second {
			delete(desktopManager.frames, id)
		}
	}
	if _, ok := desktopManager.seen[c.ID]; ok {
		return fail(errors.New("duplicate request refused; inspect the previous receipt and observe before retrying"))
	}
	if len(desktopManager.seen) >= 1024 {
		return fail(errors.New("desktop request limit reached; wait for old receipts to expire"))
	}
	desktopManager.seen[c.ID] = now
	if desktopInputPaused(c) {
		pause, err := readDesktopPause()
		if err != nil {
			return fail(fmt.Errorf("desktop pause state unavailable; input blocked: %w", err))
		}
		if pause != nil {
			if sessions, e := desktopSessions(); e == nil {
				if session, e := selectDesktopSession(sessions, c.SessionID); e == nil {
					_ = setDesktopIndicator(session, desktopPausedLabel)
				}
			}
			out := fail(errors.New("AI interrupted; click the top-right RCON badge to resume remote input"))
			out["paused"] = true
			return out
		}
	}
	if c.Op == "interact" {
		return nativeDesktopInteraction(c)
	}
	if activeDesktopInteraction != nil {
		select {
		case <-activeDesktopInteraction.done:
			activeDesktopInteraction = nil
		default:
			return fail(errors.New("desktop interaction active; continue or release it before other gestures"))
		}
	}
	if c.Op == "recover" {
		return recoverDesktop(c)
	}
	if c.Op == "attach_console" {
		note, failure := attachDesktopConsole(c)
		if failure != nil {
			return failure
		}
		attached = note
		// Report the result as a fresh observation of the attached session.
		c.Op, c.Force, c.WaitMS = "observe", false, 1000
	}
	sessions, err := desktopSessions()
	if err != nil {
		return fail(err)
	}
	session, err := selectDesktopSession(sessions, c.SessionID)
	if err != nil {
		out := fail(err)
		out["sessions"] = sessions
		return out
	}
	selected = session.ID
	if err := ensureDesktopSafety(session); err != nil {
		return fail(err)
	}
	if c.Op == "lock" {
		delete(desktopManager.frames, session.ID)
		response, err := callDesktopWorker(desktopWorkerRequest{Command: c, Session: session})
		if err != nil {
			return desktopFailure(c.ID, "unknown", err)
		}
		return response.Result
	}
	if c.Op == "launch" {
		// A started program appears on the user's desktop, so the indicator shows;
		// a waited command is headless, like remote_run.
		if !c.Launch.Wait {
			if err := setDesktopIndicator(session, "AI controlling"); err != nil {
				return fail(fmt.Errorf("desktop indicator: %w", err))
			}
			defer func() { _ = setDesktopIndicator(session, "AI idle") }()
		}
		sum := sha256.Sum256([]byte(c.Launch.Command))
		started := time.Now()
		detail := fmt.Sprintf("session=%d wait=%v command_bytes=%d command_sha256=%x", session.ID, c.Launch.Wait, len(c.Launch.Command), sum[:8])
		out, err := launchDesktopUser(session, *c.Launch)
		if err != nil {
			auditRecord("desktop_launch", detail, 1, time.Since(started).Seconds(), c.ID)
			return fail(err)
		}
		auditRecord("desktop_launch", fmt.Sprintf("%s exit=%v timed_out=%v", detail, out["exit_code"], out["timed_out"]), 0, time.Since(started).Seconds(), c.ID)
		out["id"] = c.ID
		return out
	}
	previous := desktopManager.frames[session.ID]
	if c.Op == "act" {
		if previous.FrameID != c.FrameID || previous.LogonID != session.LogonID {
			return fail(errors.New("frame unavailable, consumed, or session changed; observe again"))
		}
		delete(desktopManager.frames, session.ID) // consume before dispatch, including uncertain outcomes
	}
	// Every fresh observation supersedes the previous actionable frame, even
	// when human activity makes the new screenshot unsuitable for input.
	delete(desktopManager.frames, session.ID)
	c.SessionID = session.ID
	label := "AI viewing"
	if c.Op == "act" {
		label = "AI controlling"
	}
	err = setDesktopIndicator(session, label)
	// Activation and console attach briefly leave no foreground window, and
	// taking a session from a live RDP client passes through the secure desktop
	// (measured: about a second). An observation waits that out; input never retries.
	transient, tries := func(err error) bool {
		return err != nil && (c.Op == "observe" || c.Op == "wait") && (strings.Contains(err.Error(), errDesktopNoForeground.Error()) ||
			(attached != nil && strings.Contains(err.Error(), "locked or secure desktop")))
	}, 8
	if attached != nil {
		tries = 24
	}
	for i := 0; transient(err) && i < tries; i++ {
		time.Sleep(250 * time.Millisecond)
		err = setDesktopIndicator(session, label)
	}
	if err != nil {
		return fail(fmt.Errorf("desktop indicator: %w", err))
	}
	defer func() { _ = setDesktopIndicator(session, "AI idle") }()
	response, err := callDesktopWorker(desktopWorkerRequest{Command: c, Previous: previous, Session: session})
	if err != nil {
		status := "not_sent"
		if c.Op == "act" {
			status = "unknown"
		}
		return desktopFailure(c.ID, status, fmt.Errorf("desktop worker: %w; observe before retrying", err))
	}
	if response.Guard.FrameID != "" {
		desktopManager.frames[session.ID] = response.Guard
	}
	response.Result["id"] = c.ID
	return response.Result
}
func desktopEnablePrivilege(token windows.Token, name string) error {
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(name), &luid); err != nil {
		return err
	}
	p := windows.Tokenprivileges{PrivilegeCount: 1, Privileges: [1]windows.LUIDAndAttributes{{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}}}
	return windows.AdjustTokenPrivileges(token, false, &p, 0, nil, nil)
}
func callDesktopWorker(request desktopWorkerRequest) (desktopWorkerResponse, error) {
	var response desktopWorkerResponse
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	err := withDesktopWorker(ctx, request, func(conn net.Conn) error {
		if err := json.NewDecoder(io.LimitReader(conn, 1100000)).Decode(&response); err != nil {
			return err
		}
		if response.Result == nil || response.Result["id"] != request.Command.ID {
			return errors.New("invalid worker receipt")
		}
		return nil
	})
	return response, err
}

// Both operation and indicator workers use the same private, session-bound
// launch path. Closing the service's job handle always tears the worker down.
func withDesktopWorker(ctx context.Context, request desktopWorkerRequest, exchange func(net.Conn) error) error {
	request.Root = windowsRoot
	pipe := desktopPipePrefix + desktopID()
	listener, err := winio.ListenPipe(pipe, &winio.PipeConfig{SecurityDescriptor: "D:P(D;;GA;;;NU)(A;;GA;;;SY)", InputBufferSize: 65536, OutputBufferSize: 65536})
	if err != nil {
		return fmt.Errorf("ListenPipe: %w", err)
	}
	defer listener.Close()
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("os.Executable: %w", err)
	}
	var source windows.Token
	if err = windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE|windows.TOKEN_ADJUST_PRIVILEGES, &source); err != nil {
		return fmt.Errorf("OpenProcessToken: %w", err)
	}
	defer source.Close()
	if err = desktopEnablePrivilege(source, "SeTcbPrivilege"); err != nil {
		return fmt.Errorf("desktopEnablePrivilege: %w", err)
	}
	var token windows.Token
	if err = windows.DuplicateTokenEx(source, windows.TOKEN_ALL_ACCESS, nil, windows.SecurityImpersonation, windows.TokenPrimary, &token); err != nil {
		return fmt.Errorf("DuplicateTokenEx: %w", err)
	}
	defer token.Close()
	sid := request.Session.ID
	if err = windows.SetTokenInformation(token, windows.TokenSessionId, (*byte)(unsafe.Pointer(&sid)), 4); err != nil {
		return fmt.Errorf("SetTokenInformation: %w", err)
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return fmt.Errorf("CreateJobObject: %w", err)
	}
	defer windows.CloseHandle(job)
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	// Interaction workers must survive service death long enough to release input
	// on pipe EOF. They have their own bounded lease and absolute deadline.
	if request.Interaction {
		limits.BasicLimitInformation.LimitFlags = 0
	}
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return fmt.Errorf("SetInformationJobObject: %w", err)
	}
	// An explicit minimal environment prevents device or operator credentials
	// reaching the interactive process. Handle inheritance across sessions is off.
	root, err := windows.GetWindowsDirectory()
	if err != nil {
		return fmt.Errorf("GetWindowsDirectory: %w", err)
	}
	env := utf16codec.Encode([]rune("SystemRoot=" + root + "\x00WINDIR=" + root + "\x00\x00"))
	cmd := syscall.EscapeArg(exe) + " desktop-worker " + syscall.EscapeArg(pipe) + " " + strconv.Itoa(os.Getpid())
	startup := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{})), Desktop: windows.StringToUTF16Ptr(`winsta0\default`), Flags: 0x80} // STARTF_FORCEOFFFEEDBACK: no app-starting cursor
	var proc windows.ProcessInformation
	err = windows.CreateProcessAsUser(token, windows.StringToUTF16Ptr(exe), windows.StringToUTF16Ptr(cmd), nil, nil, false, windows.CREATE_SUSPENDED|windows.CREATE_UNICODE_ENVIRONMENT|windows.CREATE_NO_WINDOW, &env[0], windows.StringToUTF16Ptr(filepath.Dir(exe)), &startup, &proc)
	if err != nil {
		return fmt.Errorf("CreateProcessAsUser: %w", err)
	}
	defer windows.CloseHandle(proc.Process)
	defer windows.CloseHandle(proc.Thread)
	if err = windows.AssignProcessToJobObject(job, proc.Process); err != nil {
		windows.TerminateProcess(proc.Process, 1)
		return fmt.Errorf("AssignProcessToJobObject: %w", err)
	}
	if _, err = windows.ResumeThread(proc.Thread); err != nil {
		return fmt.Errorf("ResumeThread: %w", err)
	}
	conn, err := listener.Accept()
	if err != nil {
		return fmt.Errorf("listener.Accept: %w", err)
	}
	defer conn.Close()
	stopConn := context.AfterFunc(ctx, func() { conn.Close() })
	defer stopConn()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	fd, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return errors.New("pipe handle unavailable")
	}
	var pid uint32
	if err = windows.GetNamedPipeClientProcessId(windows.Handle(fd.Fd()), &pid); err != nil || pid != proc.ProcessId {
		return errors.New("desktop worker PID mismatch")
	}
	if err = json.NewEncoder(conn).Encode(request); err != nil {
		return fmt.Errorf("Encode: %w", err)
	}
	return exchange(conn)
}
func runDesktopWorker(args []string) error {
	// Keep all USER/GDI calls on one OS thread in the selected desktop.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if len(args) != 2 || !strings.HasPrefix(args[0], desktopPipePrefix) || !desktopSystem() {
		return errors.New("private desktop worker requires SYSTEM and a service pipe")
	}
	parent, err := strconv.ParseUint(args[1], 10, 32)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	conn, err := winio.DialPipeContext(ctx, args[0])
	if err != nil {
		return err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	fd, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return errors.New("pipe handle unavailable")
	}
	var pid uint32
	if err = windows.GetNamedPipeServerProcessId(windows.Handle(fd.Fd()), &pid); err != nil || pid != uint32(parent) {
		return errors.New("desktop service PID mismatch")
	}
	var req desktopWorkerRequest
	d := json.NewDecoder(io.LimitReader(conn, 30000))
	d.DisallowUnknownFields()
	if err = d.Decode(&req); err != nil {
		return err
	}
	if req.Indicator == "" && !req.Safety {
		if err = validateDesktopCommand(req.Command); err != nil {
			return err
		}
	}
	var sid uint32
	if err = windows.ProcessIdToSessionId(uint32(os.Getpid()), &sid); err != nil || sid == 0 || sid != req.Session.ID {
		return errors.New("desktop worker session mismatch")
	}
	if req.Root != "" {
		if !filepath.IsAbs(req.Root) {
			return errors.New("invalid private worker root")
		}
		windowsRoot = req.Root
	}
	if req.Safety {
		_ = conn.SetDeadline(time.Time{})
		return runDesktopSafetyWorker(conn, req)
	}
	if req.Indicator != "" {
		_ = conn.SetDeadline(time.Time{})
		return runDesktopIndicator(conn, req)
	}
	if req.Interaction {
		_ = conn.SetDeadline(time.Time{})
		return runDesktopInteraction(conn, req)
	}
	response := performDesktopOperation(req)
	return json.NewEncoder(conn).Encode(response)
}
