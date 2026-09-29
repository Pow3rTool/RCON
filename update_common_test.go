package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"runtime"
	"testing"
)

// testReleaseKey installs a throwaway release key for the test's duration.
func testReleaseKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	old := releasePubKeyB64
	releasePubKeyB64 = base64.StdEncoding.EncodeToString(pub)
	t.Cleanup(func() { releasePubKeyB64 = old })
	return priv
}

func signedRelease(priv ed25519.PrivateKey, ver string, bin []byte) releaseRequest {
	sum := sha256.Sum256(bin)
	sha := hex.EncodeToString(sum[:])
	sig := ed25519.Sign(priv, []byte(fmt.Sprintf("%s|%s|%s|%s", ver, runtime.GOOS, runtime.GOARCH, sha)))
	return releaseRequest{Version: ver, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, SHA256: sha,
		Signature: base64.StdEncoding.EncodeToString(sig), BinaryB64: base64.StdEncoding.EncodeToString(bin)}
}

func TestVerifyReleaseAcceptsOnlySignedManifest(t *testing.T) {
	priv := testReleaseKey(t)
	bin := []byte("release payload")
	good := signedRelease(priv, "v1.2.3", bin)
	if got, status, err := verifyRelease(good); err != nil || status != 0 || string(got) != string(bin) {
		t.Fatalf("signed release rejected: %d %v", status, err)
	}
	for name, mutate := range map[string]func(*releaseRequest){
		"other version":  func(r *releaseRequest) { r.Version = "v9.9.9" },
		"other platform": func(r *releaseRequest) { r.GOARCH = "riscv64" },
		"other binary": func(r *releaseRequest) {
			other := signedRelease(priv, "v1.2.3", []byte("tampered"))
			r.BinaryB64, r.SHA256 = other.BinaryB64, other.SHA256
		},
		"hash mismatch":  func(r *releaseRequest) { r.BinaryB64 = base64.StdEncoding.EncodeToString([]byte("x")) },
		"bad signature":  func(r *releaseRequest) { r.Signature = base64.StdEncoding.EncodeToString(make([]byte, 64)) },
		"no signature":   func(r *releaseRequest) { r.Signature = "" },
		"invalid base64": func(r *releaseRequest) { r.BinaryB64 = "!!" },
	} {
		req := good
		mutate(&req)
		if _, status, err := verifyRelease(req); err == nil || status == 0 {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func TestVerifyReleaseWithoutBakedKeyFailsClosed(t *testing.T) {
	priv := testReleaseKey(t)
	req := signedRelease(priv, "v1.2.3", []byte("x"))
	releasePubKeyB64 = ""
	if _, status, err := verifyRelease(req); err == nil || status != 500 {
		t.Fatalf("keyless build verified a release: %d %v", status, err)
	}
}

func TestValidReleaseVersion(t *testing.T) {
	for _, v := range []string{"v0.4.0", "v0.4.0-windows-lab.1", "dev", "1.2.3+build.7", "v1_rc2"} {
		if !validReleaseVersion(v) {
			t.Fatalf("rejected %q", v)
		}
	}
	for _, v := range []string{"", ".", "..", "v1..2", `..\x`, "../x", `a\b`, "a/b", "v1.", "-v1", "v1 ",
		"CON", "con", "nul.txt", "COM1", "LPT9.1", "C:x", "a:b", string(make([]byte, 80))} {
		if validReleaseVersion(v) {
			t.Fatalf("accepted %q", v)
		}
	}
}
