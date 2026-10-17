package main

import (
	"errors"
	"golang.org/x/sys/windows"
	"time"
	"unsafe"
)

func desktopSessionLocked(session uint32) (bool, error) {
	var buf *byte
	var size uint32
	r, _, err := desktopWTS.NewProc("WTSQuerySessionInformationW").Call(0, uintptr(session), 25, uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&size)))
	if r == 0 {
		return false, err
	}
	if buf == nil {
		return false, errors.New("empty WTS lock information")
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(buf)))
	if size < 20 {
		return false, errors.New("short WTS lock information")
	}
	return parseDesktopLockState(unsafe.Slice(buf, 20), session)
}

func performDesktopLock(req desktopWorkerRequest) desktopWorkerResponse {
	status := "not_sent"
	fail := func(err error) desktopWorkerResponse {
		return desktopWorkerResponse{Result: desktopFailure(req.Command.ID, status, err)}
	}
	sessions, err := desktopSessions()
	if err != nil {
		return fail(err)
	}
	live, err := selectDesktopSession(sessions, req.Session.ID)
	if err != nil || live.LogonID != req.Session.LogonID {
		return fail(errors.New("active logon session changed"))
	}
	if err := desktopPauseError(); err != nil {
		return fail(err)
	}
	locked, err := desktopSessionLocked(req.Session.ID)
	if err != nil {
		return fail(err)
	}
	result := func(reused bool) desktopWorkerResponse {
		desktopEvent("session-locked", map[string]any{"request_id": req.Command.ID, "session_id": req.Session.ID, "user": req.Session.User, "already_locked": reused})
		return desktopWorkerResponse{Result: map[string]any{"ok": true, "id": req.Command.ID, "session_id": req.Session.ID, "user": req.Session.User, "locked": true, "verified": true, "already_locked": reused, "input_status": status, "apps_preserved": true}}
	}
	if locked {
		return result(true)
	}
	if err := desktopDefault(); err != nil {
		return fail(err)
	}
	r, _, err := desktopUser32.NewProc("LockWorkStation").Call()
	if r == 0 {
		return fail(err)
	}
	status = "sent"
	for until := time.Now().Add(5 * time.Second); time.Now().Before(until); {
		locked, err = desktopSessionLocked(req.Session.ID)
		if err == nil && locked {
			return result(false)
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fail(errors.New("lock requested but Windows has not confirmed it; inspect the session before retrying"))
}
