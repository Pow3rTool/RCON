package main

import (
	"crypto/rand"
	"errors"
	"strings"
)

const desktopRecoveryUser = "rcon-operator"

// Exactly 32 ASCII characters from a 64-character alphabet. Retry candidates so
// complexity requirements don't introduce fixed characters or modulo bias.
func recoveryPassword() ([]uint16, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var raw [32]byte
	defer clear(raw[:])
	for {
		if _, err := rand.Read(raw[:]); err != nil {
			return nil, err
		}
		p := make([]uint16, 33)
		var upper, lower, digit, special bool
		for i, b := range raw {
			c := alphabet[b&63]
			p[i] = uint16(c)
			upper = upper || (c >= 'A' && c <= 'Z')
			lower = lower || (c >= 'a' && c <= 'z')
			digit = digit || (c >= '0' && c <= '9')
			special = special || c == '-' || c == '_'
		}
		if upper && lower && digit && special {
			return p, nil
		}
		clear(p)
	}
}

// Never disturb a human, even if disconnected or locked. An existing robot
// session is reused rather than resetting its password or starting a duplicate.
func recoverySessionDecision(all []desktopSessionState, own string) (*desktopSessionState, error) {
	var found *desktopSessionState
	for i := range all {
		if !strings.EqualFold(all[i].User, own) {
			return nil, errors.New("a user is already logged on; use the existing session or wait for sign-out")
		}
		if found != nil {
			return nil, errors.New("multiple recovery sessions exist; inspect sessions first")
		}
		copy := all[i]
		found = &copy
	}
	return found, nil
}
