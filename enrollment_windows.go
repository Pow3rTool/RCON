package main

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

type pendingWindowsEnrollment struct {
	ID       string `json:"enrollment_id"`
	XConnect string `json:"xconnect"`
	KeyHash  string `json:"public_key_sha256"`
}

func pendingEnrollmentID(etc, xc string, key crypto.Signer) (string, error) {
	b, err := os.ReadFile(filepath.Join(etc, "pending-enrollment.json"))
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var p pendingWindowsEnrollment
	if err := json.Unmarshal(b, &p); err != nil {
		return "", err
	}
	pub, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return "", err
	}
	if p.ID == "" || p.XConnect != xc || p.KeyHash != shaBytes(pub) {
		return "", fmt.Errorf("pending enrollment does not match the configured endpoint/device key; operator intervention required")
	}
	return p.ID, nil
}
func savePendingEnrollment(etc, xc, id string, key crypto.Signer) error {
	pub, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return err
	}
	b, err := json.Marshal(pendingWindowsEnrollment{ID: id, XConnect: xc, KeyHash: shaBytes(pub)})
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(etc, "pending-enrollment.json"), b, 0o600)
}
func clearWindowsJoinToken(etc string) error {
	cfg, err := loadWindowsServiceConfig(etc)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if cfg.Token == "" {
		return nil
	}
	cfg.Token = ""
	return saveWindowsServiceConfig(etc, cfg)
}

func purgePlatformJoinToken(etc string) {
	if err := clearWindowsJoinToken(etc); err != nil {
		log.Printf("enroll: cannot purge join token: %v", err)
		return
	}
	_ = os.Unsetenv("RCON_JOIN_TOKEN")
	log.Printf("enroll: purged join token from protected service configuration")
}
