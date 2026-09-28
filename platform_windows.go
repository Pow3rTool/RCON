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
	"net/http"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
)

const commandShell = "powershell"
const supportsSelfUpdate = false
const supportsPOSIXMetadata = false

func windowsDataDir() string {
	path, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		log.Fatalf("locate ProgramData: %v", err)
	}
	return filepath.Join(path, "Pow3rTool", "RCON")
}
func defaultIdentityDir() string { return windowsDataDir() }
func defaultAuditPath() string   { return filepath.Join(windowsDataDir(), "audit.log") }
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
func markHealthy()    {}
func updateWatchdog() {}
func updateApply(etc, broker string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotImplemented, map[string]any{
			"error": "Windows lab build requires a manual service stop/replace/start upgrade", "applied": false})
	}
}
func runSelfTest(etc, broker string) {
	pub, err := base64.StdEncoding.DecodeString(releasePubKeyB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		log.Fatal("selftest: missing/invalid baked release verification key")
	}
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
