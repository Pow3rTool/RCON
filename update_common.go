// Release verification shared by every platform's /update/apply. XConnect is
// only a relay: the binary is trusted solely because the Ed25519 signature over
// version|goos|goarch|sha256 verifies against the release key BAKED into this
// build at compile time.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"runtime"
	"strings"
)

// A release JSON carries a base64 binary; bound what a relay can make us buffer.
const maxUpdateBody = 128 << 20

type releaseRequest struct {
	Version   string `json:"version"`
	GOOS      string `json:"goos"`
	GOARCH    string `json:"goarch"`
	SHA256    string `json:"sha256"`
	Signature string `json:"signature"`
	BinaryB64 string `json:"binary_b64"`
}

// decodeReleaseRequest parses the relayed release and fills in this node's
// platform when the relay omitted it. A mismatched platform is refused here.
func decodeReleaseRequest(w http.ResponseWriter, r *http.Request) (releaseRequest, int, error) {
	var req releaseRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxUpdateBody)).Decode(&req); err != nil {
		return req, 400, fmt.Errorf("bad body")
	}
	if req.GOOS == "" {
		req.GOOS = runtime.GOOS
	}
	if req.GOARCH == "" {
		req.GOARCH = runtime.GOARCH
	}
	if req.GOOS != runtime.GOOS || req.GOARCH != runtime.GOARCH {
		return req, 400, fmt.Errorf("arch mismatch for this node")
	}
	return req, 0, nil
}

// verifyRelease returns the binary only if its content hash matches and the
// signature verifies against the baked release key.
func verifyRelease(req releaseRequest) ([]byte, int, error) {
	bin, err := base64.StdEncoding.DecodeString(req.BinaryB64)
	if err != nil || len(bin) == 0 {
		return nil, 400, fmt.Errorf("bad binary_b64")
	}
	sum := sha256.Sum256(bin)
	if hex.EncodeToString(sum[:]) != req.SHA256 {
		return nil, 400, fmt.Errorf("sha256 mismatch")
	}
	if status, err := verifyReleaseSignature(req.Version, req.GOOS, req.GOARCH, req.SHA256, req.Signature); err != nil {
		return nil, status, err
	}
	return bin, 0, nil
}

// verifyReleaseSignature checks the manifest signature with the BAKED key only.
func verifyReleaseSignature(ver, goos, goarch, sha, signature string) (int, error) {
	pub, err := base64.StdEncoding.DecodeString(releasePubKeyB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return 500, fmt.Errorf("no/invalid baked release pubkey")
	}
	sig, _ := base64.StdEncoding.DecodeString(signature)
	manifest := []byte(fmt.Sprintf("%s|%s|%s|%s", ver, goos, goarch, sha))
	if !ed25519.Verify(ed25519.PublicKey(pub), manifest, sig) {
		log.Printf("update: SIGNATURE INVALID for %s — refusing", ver)
		return 403, fmt.Errorf("signature verification failed")
	}
	return 0, nil
}

// Version strings name on-disk release directories on Windows. The signature
// covers the version, but a signed "..\x" must still never become a path.
// Alphanumeric at both ends (Windows silently drops trailing dots/spaces), no
// "..", and never a DOS device name such as CON or COM1.
var releaseVersionRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._+-]{0,62}[A-Za-z0-9])?$`)
var dosDeviceRE = regexp.MustCompile(`(?i)^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(\.|$)`)

func validReleaseVersion(v string) bool {
	return releaseVersionRE.MatchString(v) && !strings.Contains(v, "..") && !dosDeviceRE.MatchString(v)
}
