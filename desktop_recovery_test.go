package main

import (
	"strings"
	"testing"
)

func TestRecoveryPasswordShapeAndDiversity(t *testing.T) {
	seen := map[string]bool{}
	for n := 0; n < 256; n++ {
		p, err := recoveryPassword()
		if err != nil {
			t.Fatal(err)
		}
		if len(p) != 33 || p[32] != 0 {
			t.Fatal("password length")
		}
		var upper, lower, digit, special bool
		key := make([]byte, 32)
		for i, c := range p[:32] {
			if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", rune(c)) {
				t.Fatal("bad alphabet")
			}
			key[i] = byte(c)
			upper = upper || c >= 'A' && c <= 'Z'
			lower = lower || c >= 'a' && c <= 'z'
			digit = digit || c >= '0' && c <= '9'
			special = special || c == '-' || c == '_'
		}
		if !upper || !lower || !digit || !special {
			t.Fatal("complexity")
		}
		if seen[string(key)] {
			t.Fatal("duplicate generated password")
		}
		seen[string(key)] = true
		clear(p)
		clear(key)
	}
}
func TestRecoveryNeverReplacesHumanSessions(t *testing.T) {
	robot := desktopSessionState{ID: 2, User: `HOST\rcon-operator`, State: "active", Console: true}
	if s, e := recoverySessionDecision(nil, robot.User); e != nil || s != nil {
		t.Fatal(s, e)
	}
	if s, e := recoverySessionDecision([]desktopSessionState{robot}, robot.User); e != nil || s.ID != 2 {
		t.Fatal(s, e)
	}
	for _, state := range []string{"active", "disconnected", "connected"} {
		human := desktopSessionState{ID: 3, User: `HOST\human`, State: state}
		for _, sessions := range [][]desktopSessionState{{human}, {robot, human}, {human, robot}} {
			if _, e := recoverySessionDecision(sessions, robot.User); e == nil {
				t.Fatal("accepted human", state)
			}
		}
	}
	if _, e := recoverySessionDecision([]desktopSessionState{robot, robot}, robot.User); e == nil {
		t.Fatal("duplicate")
	}
}
func TestRecoveryRequestCannotTargetArbitraryAccountOrSession(t *testing.T) {
	id := strings.Repeat("a", 32)
	if err := validateDesktopCommand(desktopCommand{ID: id, Op: "recover"}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []desktopCommand{
		{ID: id, Op: "recover", SessionID: 2}, {ID: id, Op: "recover", Force: true}, {ID: id, Op: "recover", WaitMS: 1},
		{ID: id, Op: "recover", FrameID: id}, {ID: id, Op: "recover", DesktopAction: DesktopAction{Text: "password"}},
		{ID: id, Op: "recover", Launch: &DesktopLaunch{Command: "ignored"}},
	} {
		if validateDesktopCommand(c) == nil {
			t.Fatal("accepted ambiguous request")
		}
	}
}
