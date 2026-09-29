package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const commandShell = "bash"
const supportsSelfUpdate = true
const supportsPOSIXMetadata = true

func pendingEnrollmentID(etc, xc string, key crypto.Signer) (string, error) { return "", nil }
func savePendingEnrollment(etc, xc, id string, key crypto.Signer) error     { return nil }
func purgePlatformJoinToken(etc string)                                     {}

func lastUpgradeReport() map[string]any     { return nil }
func pendingUpgradeReport() map[string]any  { return nil }
func defaultIdentityDir() string            { return "/etc/rcon" }
func defaultAuditPath() string              { return "/var/lib/rcon/audit.log" }
func platformCommand(args []string) bool    { return false }
func installService(etc, broker, xc string) { installLinuxService(etc, broker, xc) }
func ensureIdentityDir(path string) error   { return os.MkdirAll(path, 0o700) }
func platformOSVersion() string {
	b, _ := os.ReadFile("/etc/os-release")
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
		}
	}
	return "linux"
}
func addFileMetadata(out map[string]any, info os.FileInfo) {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		out["uid"], out["gid"] = st.Uid, st.Gid
	}
}
func loadDeviceKey(etc string) (crypto.Signer, error) { return loadPEMDeviceKey(etc) }
func loadDeviceCertificate(etc string) (tls.Certificate, error) {
	return tls.LoadX509KeyPair(filepath.Join(etc, "device-cert.pem"), filepath.Join(etc, "device-key.pem"))
}
func createDeviceKey(etc string) (crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	err = os.WriteFile(filepath.Join(etc, "device-key.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600)
	return key, err
}
