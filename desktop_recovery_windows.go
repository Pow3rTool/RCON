package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const recoveryCLSID = "{264B7708-953D-470A-80B9-209F008623B2}"
const recoveryProviderKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\` + recoveryCLSID
const recoveryClassKey = `SOFTWARE\Classes\CLSID\` + recoveryCLSID + `\InprocServer32`
const recoveryPipePrefix = `\\.\pipe\Pow3rTool-RCON-recovery-v1-`

// Populated only in releases built with the native provider. Plain Go builds
// retain all existing desktop features, but cannot enable recovery.
var recoveryProviderDLL []byte
var recoveryNet = windows.NewLazySystemDLL("netapi32.dll")

type recoveryAccount struct {
	User     string `json:"user"`
	SID      string `json:"sid"`
	Provider string `json:"provider"`
	SHA256   string `json:"sha256"`
}
type recoveryUserInfo struct {
	Name, Password         *uint16
	PasswordAge, Privilege uint32
	HomeDir, Comment       *uint16
	Flags                  uint32
	ScriptPath             *uint16
}

func recoveryNetStatus(name string, args ...uintptr) error {
	r, _, _ := recoveryNet.NewProc(name).Call(args...)
	if r != 0 {
		return fmt.Errorf("%s status %d", name, r)
	}
	return nil
}
func recoveryFlags(disabled bool) error {
	flags := uint32(0x200 | 0x10000) // NORMAL_ACCOUNT | DONT_EXPIRE_PASSWD
	if disabled {
		flags |= 2
	}
	return recoveryNetStatus("NetUserSetInfo", 0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(desktopRecoveryUser))), 1008, uintptr(unsafe.Pointer(&flags)), 0)
}
func recoverySetPassword(p []uint16) error {
	info := struct{ Password *uint16 }{&p[0]}
	return recoveryNetStatus("NetUserSetInfo", 0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(desktopRecoveryUser))), 1003, uintptr(unsafe.Pointer(&info)), 0)
}
func recoveryAccountSID() (string, error) {
	sid, _, _, err := windows.LookupSID("", desktopRecoveryUser)
	if err != nil {
		return "", err
	}
	return sid.String(), nil
}
func loadRecoveryAccount() (recoveryAccount, error) {
	var cfg recoveryAccount
	b, err := os.ReadFile(windowsPath("state", "recovery-account.json"))
	if err != nil {
		return cfg, errors.New("recovery is not enabled; an administrator must run rcon.exe recovery-enable")
	}
	if json.Unmarshal(b, &cfg) != nil || cfg.User != desktopRecoveryUser || cfg.SID == "" {
		return cfg, errors.New("invalid recovery account configuration")
	}
	sid, err := recoveryAccountSID()
	if err != nil || sid != cfg.SID {
		return cfg, errors.New("recovery account SID changed; refusing to reset an unowned account")
	}
	return cfg, nil
}

// Capabilities describe the binary, not mutable opt-in state. The broker caches
// these on connect; recoverDesktop checks local enablement on every request.
func desktopRecoveryAvailable() bool { return len(recoveryProviderDLL) != 0 }

// Explicit local opt-in, never executed as a side effect of observing a node.
func enableDesktopRecovery() (recoveryAccount, error) {
	var cfg recoveryAccount
	if !desktopSystem() {
		return cfg, errors.New("recovery-enable requires LocalSystem")
	}
	if len(recoveryProviderDLL) == 0 {
		return cfg, errors.New("this build has no recovery provider; use build.sh on a host with MinGW")
	}
	if err := ensureIdentityDir(windowsPath("state")); err != nil {
		return cfg, err
	}
	if existing, err := loadRecoveryAccount(); err == nil {
		cfg = existing
	} else {
		if _, err := os.Stat(windowsPath("state", "recovery-account.json")); !os.IsNotExist(err) {
			return cfg, errors.New("existing recovery configuration is invalid; inspect it before enabling")
		}
		if _, err := recoveryAccountSID(); err == nil {
			return cfg, errors.New("rcon-operator already exists and is not owned by RCON; refusing to adopt it")
		}
		p, err := recoveryPassword()
		if err != nil {
			return cfg, err
		}
		defer clear(p)
		u := recoveryUserInfo{Name: windows.StringToUTF16Ptr(desktopRecoveryUser), Password: &p[0], Privilege: 1,
			Comment: windows.StringToUTF16Ptr("RCON recovery desktop; transient credentials, disposable saved sign-ins"), Flags: 0x200 | 0x10000 | 2}
		if err := recoveryNetStatus("NetUserAdd", 0, 1, uintptr(unsafe.Pointer(&u)), 0); err != nil {
			return cfg, err
		}
		cfg.User = desktopRecoveryUser
		cfg.SID, err = recoveryAccountSID()
		if err != nil {
			return cfg, err
		}
		// Explicit Users membership, never Administrators or Remote Desktop Users.
		usersSID, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
		if err != nil {
			return cfg, err
		}
		group, _, _, err := usersSID.LookupAccount("")
		if err != nil {
			return cfg, err
		}
		memberSID, err := windows.StringToSid(cfg.SID)
		if err != nil {
			return cfg, err
		}
		member := struct{ SID *windows.SID }{memberSID}
		r, _, _ := recoveryNet.NewProc("NetLocalGroupAddMembers").Call(0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(group))), 0, uintptr(unsafe.Pointer(&member)), 1)
		if r != 0 && r != 1378 {
			return cfg, fmt.Errorf("add recovery user to Users: status %d", r)
		}
		// Save ownership before installing the provider, so a retry can complete.
		b, _ := json.Marshal(cfg)
		if err := saveRecoveryMetadata(b); err != nil {
			return cfg, err
		}
	}
	sum := sha256.Sum256(recoveryProviderDLL)
	cfg.SHA256 = hex.EncodeToString(sum[:])
	dir := windowsPath("recovery", cfg.SHA256[:16])
	if err := ensureIdentityDir(dir); err != nil {
		return cfg, err
	}
	cfg.Provider = filepath.Join(dir, "rcon-recovery.dll")
	if current, err := os.ReadFile(cfg.Provider); err != nil || sha256.Sum256(current) != sum {
		if err := os.WriteFile(cfg.Provider, recoveryProviderDLL, 0600); err != nil {
			return cfg, err
		}
	}
	for path, values := range map[string]map[string]string{
		recoveryClassKey:    {"": cfg.Provider, "ThreadingModel": "Apartment"},
		recoveryProviderKey: {"": "RCON recovery"},
	} {
		k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, path, registry.SET_VALUE)
		if err != nil {
			return cfg, err
		}
		for name, value := range values {
			if err := k.SetStringValue(name, value); err != nil {
				k.Close()
				return cfg, err
			}
		}
		k.Close()
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	if err := saveRecoveryMetadata(b); err != nil {
		return cfg, err
	}
	desktopEvent("recovery-enabled", map[string]any{"account": cfg.User, "sid": cfg.SID, "provider_sha256": cfg.SHA256})
	return cfg, nil
}

func recoveryVerifyProvider(cfg recoveryAccount) error {
	enabled, err := registry.OpenKey(registry.LOCAL_MACHINE, recoveryProviderKey, registry.QUERY_VALUE)
	if err != nil {
		return errors.New("recovery provider is disabled; run recovery-enable")
	}
	disabled, _, valueErr := enabled.GetIntegerValue("Disabled")
	enabled.Close()
	if valueErr != nil && valueErr != windows.ERROR_FILE_NOT_FOUND {
		return errors.New("invalid recovery provider enablement")
	}
	if disabled != 0 {
		return errors.New("recovery provider is disabled by Windows policy")
	}
	b, err := os.ReadFile(cfg.Provider)
	if err != nil {
		return errors.New("recovery provider missing; run recovery-enable")
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != cfg.SHA256 {
		return errors.New("recovery provider hash mismatch")
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, recoveryClassKey, registry.QUERY_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	path, _, err := k.GetStringValue("")
	if err != nil || !strings.EqualFold(path, cfg.Provider) {
		return errors.New("recovery provider registration mismatch")
	}
	return nil
}

func recoveryVerifyClient(conn net.Conn, session uint32) error {
	fd, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return errors.New("recovery pipe has no handle")
	}
	var pid, sid uint32
	if err := windows.GetNamedPipeClientProcessId(windows.Handle(fd.Fd()), &pid); err != nil {
		return err
	}
	if err := windows.ProcessIdToSessionId(pid, &sid); err != nil || sid != session {
		return errors.New("recovery client session mismatch")
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	var token windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token); err != nil {
		return err
	}
	defer token.Close()
	u, err := token.GetTokenUser()
	if err != nil || !u.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return errors.New("recovery client is not SYSTEM")
	}
	var path [1024]uint16
	n := uint32(len(path))
	if err := windows.QueryFullProcessImageName(h, 0, &path[0], &n); err != nil {
		return err
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return err
	}
	if !strings.EqualFold(windows.UTF16ToString(path[:n]), filepath.Join(system, "LogonUI.exe")) {
		return errors.New("recovery client is not Windows LogonUI")
	}
	return nil
}

func recoverDesktop(c desktopCommand) (result map[string]any) {
	fail := func(err error) map[string]any { return desktopFailure(c.ID, "not_sent", err) }
	cfg, err := loadRecoveryAccount()
	if err != nil {
		return fail(err)
	}
	if err := recoveryVerifyProvider(cfg); err != nil {
		return fail(err)
	}
	host, err := os.Hostname()
	if err != nil {
		return fail(err)
	}
	if len(windows.StringToUTF16(host)) > 64 {
		return fail(errors.New("computer name exceeds recovery protocol limit"))
	}
	own := host + `\` + cfg.User
	all, err := desktopAllSessions()
	if err != nil {
		return fail(err)
	}
	existing, err := recoverySessionDecision(all, own)
	if err != nil {
		out := fail(err)
		out["sessions"] = all
		return out
	}
	unlocking := false
	startingLogonID := ""
	if existing != nil {
		if !existing.Console || existing.State != "active" {
			return fail(errors.New("recovery user already has a non-console session; inspect or attach it first"))
		}
		locked, e := desktopSessionLocked(existing.ID)
		if e != nil {
			return fail(e)
		}
		if !locked {
			return map[string]any{"ok": true, "id": c.ID, "session_id": existing.ID, "user": own, "reused": true, "password_retained": false}
		}
		live, e := recoveryLiveSession(existing.ID, own)
		if e != nil {
			return fail(e)
		}
		startingLogonID = live.LogonID
		unlocking = true
	}
	console := windows.WTSGetActiveConsoleSessionId()
	if console == 0 || console == 0xffffffff {
		return fail(errors.New("no Windows console session is available yet"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	listener, err := winio.ListenPipe(fmt.Sprintf("%s%d", recoveryPipePrefix, console), &winio.PipeConfig{SecurityDescriptor: "D:P(D;;GA;;;NU)(A;;GA;;;SY)", InputBufferSize: 512, OutputBufferSize: 512})
	if err != nil {
		return fail(fmt.Errorf("recovery pipe: %w", err))
	}
	defer listener.Close()
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	// Don't rotate anything until an authentic sign-in provider has connected.
	conn, err := listener.Accept()
	if err != nil {
		return fail(errors.New("Windows sign-in provider did not connect within 35 seconds; show the sign-in screen or restart after enabling recovery"))
	}
	defer conn.Close()
	if err := recoveryVerifyClient(conn, console); err != nil {
		return fail(err)
	}
	all, err = desktopAllSessions()
	if err != nil {
		return fail(err)
	}
	current, e := recoverySessionDecision(all, own)
	if e != nil {
		return fail(e)
	}
	if !unlocking && current != nil {
		return fail(errors.New("a user signed in while recovery was pending; no password changed"))
	}
	if unlocking {
		if current == nil || current.ID != console || !current.Console || current.State != "active" {
			return fail(errors.New("recovery session changed while unlock was pending"))
		}
		live, e := recoveryLiveSession(console, own)
		if e != nil || live.LogonID != startingLogonID {
			return fail(errors.New("recovery logon changed while unlock was pending"))
		}
		locked, e := desktopSessionLocked(console)
		if e != nil || !locked {
			return fail(errors.New("recovery session is no longer locked; no password changed"))
		}
	}
	if pause, err := readDesktopPause(); err != nil || pause != nil {
		return fail(errors.New("desktop is paused; recovery cancelled"))
	}
	p, err := recoveryPassword()
	if err != nil {
		return fail(err)
	}
	defer clear(p)
	if err := recoverySetPassword(p); err != nil {
		return fail(err)
	}
	if err := recoveryFlags(false); err != nil {
		return fail(err)
	}
	defer func() {
		if err := recoveryFlags(true); err != nil {
			desktopEvent("recovery-disable-failed", map[string]any{"error": err.Error()})
			result["ok"] = false
			result["account_disabled"] = false
			result["error"] = "Recovery account could not be disabled; inspect the node before retrying"
		} else {
			result["account_disabled"] = true
		}
	}()
	// Fixed binary packet; never JSON, tool arguments, environment, disk or logs.
	packet := make([]byte, 274)
	defer clear(packet)
	binary.LittleEndian.PutUint32(packet[0:4], 0x52434c31)
	binary.LittleEndian.PutUint32(packet[4:8], console)
	tick, _, _ := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetTickCount64").Call()
	binary.LittleEndian.PutUint64(packet[8:16], uint64(tick)+10000)
	put := func(offset int, s []uint16) {
		for i, v := range s {
			binary.LittleEndian.PutUint16(packet[offset+2*i:], v)
		}
	}
	put(16, windows.StringToUTF16(cfg.User))
	put(80, windows.StringToUTF16(host))
	put(208, p)
	_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
	if n, err := conn.Write(packet); err != nil || n != len(packet) {
		return fail(errors.New("credential handoff failed"))
	}
	clear(packet)
	clear(p)
	conn.Close()
	listener.Close()
	desktopEvent("recovery-signin-requested", map[string]any{"request_id": c.ID, "session_id": console, "account": cfg.User, "unlock": unlocking})
	for ctx.Err() == nil {
		sessions, err := desktopSessions()
		if err == nil {
			for _, s := range sessions {
				if strings.EqualFold(s.User, own) && s.ID == console {
					locked, e := desktopSessionLocked(s.ID)
					if e != nil || locked {
						continue
					}
					if unlocking && s.LogonID != startingLogonID {
						return desktopFailure(c.ID, "unknown", errors.New("logon identity changed during unlock; inspect the session"))
					}
					if unlocking {
						desktopEvent("recovery-unlock-complete", map[string]any{"request_id": c.ID, "session_id": s.ID, "account": cfg.User})
						return map[string]any{"ok": true, "id": c.ID, "session_id": s.ID, "user": own, "unlocked": true, "session_preserved": true, "password_retained": false, "next": "Observe the resumed desktop before sending input"}
					}
					desktopEvent("recovery-signin-complete", map[string]any{"request_id": c.ID, "session_id": s.ID, "account": cfg.User})
					return map[string]any{"ok": true, "id": c.ID, "session_id": s.ID, "user": own, "created": true, "desktop_state": "session_created", "password_retained": false, "next": "Use desktop_observe, then desktop_launch once the desktop is ready"}
				}
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return desktopFailure(c.ID, "unknown", errors.New("Windows sign-in did not complete before the deadline; inspect sessions before retrying"))
}

// Metadata only; credentials never pass through this function.
func saveRecoveryMetadata(b []byte) error {
	path := windowsPath("state", "recovery-account.json")
	f, err := os.CreateTemp(filepath.Dir(path), ".recovery-account-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// The SAM retains only Windows' verifier. Close the short enable window after
// crashes too; disabling the account does not terminate an existing logon token.
func reconcileDesktopRecovery() {
	if _, err := os.Stat(windowsPath("state", "recovery-account.json")); os.IsNotExist(err) {
		return
	}
	if _, err := loadRecoveryAccount(); err != nil {
		desktopEvent("recovery-startup-refused", map[string]any{"error": err.Error()})
		return
	}
	if err := recoveryFlags(true); err != nil {
		desktopEvent("recovery-disable-failed", map[string]any{"error": err.Error()})
	}
}
func disableDesktopRecovery() error {
	if !desktopSystem() {
		return errors.New("recovery-disable requires LocalSystem")
	}
	if _, err := loadRecoveryAccount(); err != nil {
		return err
	}
	if err := recoveryFlags(true); err != nil {
		return err
	}
	if err := registry.DeleteKey(registry.LOCAL_MACHINE, recoveryProviderKey); err != nil && err != windows.ERROR_FILE_NOT_FOUND {
		return err
	}
	// Retain ownership metadata and the profile so re-enabling is safe.
	desktopEvent("recovery-disabled", map[string]any{"account": desktopRecoveryUser})
	return nil
}

func recoveryLiveSession(id uint32, own string) (desktopSession, error) {
	all, err := desktopSessions()
	if err != nil {
		return desktopSession{}, err
	}
	s, err := selectDesktopSession(all, id)
	if err != nil {
		return s, err
	}
	if !strings.EqualFold(s.User, own) {
		return desktopSession{}, errors.New("recovery session user changed")
	}
	return s, nil
}
