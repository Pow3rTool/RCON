package main

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var desktopWTS = windows.NewLazySystemDLL("wtsapi32.dll")

var desktopWTSStates = map[uint32]string{
	windows.WTSActive: "active", windows.WTSConnected: "connected", windows.WTSConnectQuery: "connecting",
	windows.WTSShadow: "shadowing", windows.WTSDisconnected: "disconnected", windows.WTSIdle: "idle",
	windows.WTSListen: "listening", windows.WTSReset: "resetting", windows.WTSDown: "down", windows.WTSInit: "initializing",
}

func desktopWTSString(id, class uint32) string {
	var buf *uint16
	var n uint32
	r, _, _ := desktopWTS.NewProc("WTSQuerySessionInformationW").Call(0, uintptr(id), uintptr(class), uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&n)))
	if r == 0 || buf == nil {
		return ""
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(buf)))
	return windows.UTF16PtrToString(buf)
}

// Unlike desktopSessions, this includes disconnected sessions, which have a
// user but no display, so failures can say what state the desktop is in.
func desktopAllSessions() ([]desktopSessionState, error) {
	var rows *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &rows, &count); err != nil {
		return nil, err
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(rows)))
	console := windows.WTSGetActiveConsoleSessionId()
	result := []desktopSessionState{}
	for _, r := range unsafe.Slice(rows, count) {
		user := desktopWTSString(r.SessionID, 5) // WTSUserName
		if r.SessionID == 0 || user == "" {
			continue
		}
		if domain := desktopWTSString(r.SessionID, 7); domain != "" { // WTSDomainName
			user = domain + `\` + user
		}
		state, ok := desktopWTSStates[r.State]
		if !ok {
			state = fmt.Sprintf("state_%d", r.State)
		}
		result = append(result, desktopSessionState{r.SessionID, user, windows.UTF16PtrToString(r.WindowStationName), state, r.SessionID == console})
	}
	return result, nil
}

// Adds desktop_state, remedy and every logged-on session to a failure that is
// about desktop availability; leaves other failures untouched.
func annotateDesktopUnavailable(result map[string]any, id uint32) {
	if result == nil || result["ok"] != false || result["desktop_state"] != nil {
		return
	}
	failure, _ := result["error"].(string)
	all, err := desktopAllSessions()
	if err != nil {
		return
	}
	if state, remedy := desktopUnavailable(all, id, failure); state != "" {
		result["desktop_state"], result["remedy"], result["sessions"] = state, remedy, all
	}
}

// The tscon primitive: show a logged-on session on another session's terminal.
// As LocalSystem no password is needed. The session keeps its user and running
// programs; whatever client or session held the target terminal is disconnected.
func desktopConnectSession(id, target uint32) error {
	empty := windows.StringToUTF16Ptr("")
	r, _, err := desktopWTS.NewProc("WTSConnectSessionW").Call(uintptr(id), uintptr(target), uintptr(unsafe.Pointer(empty)), 1)
	if r == 0 {
		return fmt.Errorf("WTSConnectSession: %w", err)
	}
	return nil
}

// Moves a logged-on session onto the console display so it renders without an
// RDP client. Without force it only takes sessions nobody is viewing. Returns a
// note describing what changed, or a failure receipt.
func attachDesktopConsole(c desktopCommand) (map[string]any, map[string]any) {
	fail := func(err error, all []desktopSessionState) map[string]any {
		out := desktopFailure(c.ID, "not_sent", err)
		if all != nil {
			out["sessions"] = all
		}
		return out
	}
	all, err := desktopAllSessions()
	if err != nil {
		return nil, fail(err, nil)
	}
	var target *desktopSessionState
	for i := range all {
		if all[i].ID == c.SessionID {
			target = &all[i]
		}
	}
	if target == nil {
		return nil, fail(fmt.Errorf("session %d has no logged-on user", c.SessionID), all)
	}
	note := map[string]any{"attached_console": true, "previous_state": target.State, "previous_station": target.Station}
	if target.Console && target.State == "active" {
		note["attached_console"], note["already_on_console"] = false, true
		return note, nil
	}
	console := windows.WTSGetActiveConsoleSessionId()
	if console == 0xFFFFFFFF {
		return nil, fail(errors.New("no console session is available"), all)
	}
	if !c.Force {
		if target.State == "active" || target.State == "connected" {
			return nil, fail(fmt.Errorf("session %d is connected through %s; force=true disconnects that client and moves the session to the console", target.ID, target.Station), all)
		}
		for _, s := range all {
			if s.ID == console && s.ID != target.ID && s.State == "active" {
				return nil, fail(fmt.Errorf("the console shows session %d (%s); force=true disconnects it", s.ID, s.User), all)
			}
		}
	}
	if err := desktopConnectSession(target.ID, console); err != nil {
		return nil, fail(err, all)
	}
	auditRecord("desktop_attach_console", fmt.Sprintf("session=%d from_state=%s from_station=%s force=%v", target.ID, target.State, target.Station, c.Force), 0, 0, c.ID)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if sessions, err := desktopSessions(); err == nil {
			for _, s := range sessions {
				if s.ID == target.ID && strings.EqualFold(s.Station, "Console") {
					return note, nil
				}
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	note["warning"] = "session did not report active on the console within 10 seconds"
	return note, nil
}
