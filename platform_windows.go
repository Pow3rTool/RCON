package main

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
)

const commandShell = "powershell"
const supportsSelfUpdate = true
const supportsPOSIXMetadata = false

// RCON owns exactly one tree, fixed on purpose: no known-folder lookups and no
// environment-dependent paths. Every directory in it is created with a
// protected SYSTEM/Administrators-only DACL (ensureIdentityDir) — never the
// DACL a new folder would otherwise inherit from C:\, which grants
// Authenticated Users modify rights on everything below it.
//
//	C:\RCON\releases\<version>\rcon.exe   the service runs one of these
//	C:\RCON\etc\                          device cert, trust bundle, service.json
//	C:\RCON\logs\                         service.log, audit.log, upgrade.log
//	C:\RCON\state\                        upgrade lock/journal, health marker, last result
const defaultWindowsRoot = `C:\RCON`

// A variable only so tests can point it at a temporary tree; nothing else sets it.
var windowsRoot = defaultWindowsRoot

func windowsPath(elem ...string) string {
	return filepath.Join(append([]string{windowsRoot}, elem...)...)
}
func defaultIdentityDir() string { return windowsPath("etc") }
func defaultAuditPath() string   { return windowsPath("logs", "audit.log") }
func platformOSVersion() string {
	v := windows.RtlGetVersion()
	return fmt.Sprintf("Windows %d.%d build %d", v.MajorVersion, v.MinorVersion, v.BuildNumber)
}
func addFileMetadata(out map[string]any, info os.FileInfo) {
	delete(out, "mode") // POSIX mode bits do not describe a Windows DACL.
	out["permissions"] = "windows_acl"
}
func loadDeviceCertificate(etc string) (tls.Certificate, error) {
	if err := ensureIdentityDir(etc); err != nil {
		return tls.Certificate{}, err
	}
	key, err := loadDeviceKey(etc)
	if err != nil {
		return tls.Certificate{}, err
	}
	raw, err := os.ReadFile(filepath.Join(etc, "device-cert.pem"))
	if err != nil {
		return tls.Certificate{}, err
	}
	cert := tls.Certificate{PrivateKey: key}
	for len(raw) > 0 {
		var b *pem.Block
		b, raw = pem.Decode(raw)
		if b == nil {
			break
		}
		if b.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, b.Bytes)
		}
	}
	if len(cert.Certificate) == 0 {
		return cert, fmt.Errorf("no certificates in device-cert.pem")
	}
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return cert, err
	}
	pub, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return cert, err
	}
	got, err := x509.MarshalPKIXPublicKey(cert.Leaf.PublicKey)
	if err != nil || string(pub) != string(got) {
		return cert, fmt.Errorf("certificate does not match CNG device key")
	}
	return cert, nil
}
func runSelfTest(etc, broker string) {
	pub, err := base64.StdEncoding.DecodeString(releasePubKeyB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		log.Fatal("selftest: missing/invalid baked release verification key")
	}
	// The same startup path the service runs before connecting to SCM.
	_, f, err := servicePreflight(etc)
	if err != nil {
		log.Fatalf("selftest: %v", err)
	}
	_ = f.Close()
	if _, _, err := buildTLS(etc); err != nil {
		log.Fatalf("selftest: %v", err)
	}
	conn, err := net.DialTimeout("tcp", broker, 5*time.Second)
	if err != nil {
		log.Fatalf("selftest: %v", err)
	}
	_ = conn.Close()
	fmt.Printf("selftest OK: %s (%s)\n", version, platformOSVersion())
}
func installService(etc, broker, xc string) {
	log.Fatal("Windows: use 'rcon.exe install' from an elevated PowerShell prompt; enroll --install-service is not supported")
}
