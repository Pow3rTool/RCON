// RCON cert renewal — XConnect drives it over the existing tunnel (no phone-home,
// no re-approval). Key-continuity: we reuse the SAME device key, so Orthanc
// re-signs the same SPIFFE identity. GET /renew/csr returns a fresh CSR for our
// key; POST /renew/apply writes the new cert and forces a reconnect so the new
// cert takes effect. The dial loop re-reads etc/ on every reconnect.
package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// curConn is the live reverse-tunnel conn; closing it makes the dial loop
// reconnect (and re-read the renewed cert). Set in dialAndServe.
var (
	curConnMu sync.Mutex
	curConn   io.Closer
)

func setCurConn(c io.Closer) { curConnMu.Lock(); curConn = c; curConnMu.Unlock() }
func clearCurConn()          { curConnMu.Lock(); curConn = nil; curConnMu.Unlock() }
func dropCurConn() {
	curConnMu.Lock()
	c := curConn
	curConnMu.Unlock()
	if c != nil {
		_ = c.Close()
	}
}

func loadPEMDeviceKey(etc string) (crypto.Signer, error) {
	raw, err := os.ReadFile(filepath.Join(etc, "device-key.pem"))
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(raw)
	if blk == nil {
		return nil, fmt.Errorf("no PEM block in device-key.pem")
	}
	if k, e := x509.ParseECPrivateKey(blk.Bytes); e == nil {
		return k, nil
	}
	if k, e := x509.ParsePKCS8PrivateKey(blk.Bytes); e == nil {
		if signer, ok := k.(crypto.Signer); ok {
			return signer, nil
		}
	}
	return nil, fmt.Errorf("unsupported device key format")
}

// renewCSR: GET /renew/csr -> {csr} for our existing key (key continuity).
func renewCSR(etc string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key, err := loadDeviceKey(etc)
		if err != nil {
			writeJSON(w, 500, map[string]any{"error": "load key: " + err.Error()})
			return
		}
		der, err := x509.CreateCertificateRequest(rand.Reader,
			&x509.CertificateRequest{Subject: pkix.Name{CommonName: "rcon-renew"}}, key)
		if err != nil {
			writeJSON(w, 500, map[string]any{"error": "build CSR: " + err.Error()})
			return
		}
		csr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
		writeJSON(w, 200, map[string]any{"csr": csr})
	}
}

// renewApply: POST /renew/apply {certificate, trust_bundle?} -> verify + write + reconnect.
//
// This path is reachable from XConnect/admin, which (by design) holds NO signing
// authority — so a renewed cert must NOT be able to repoint this node's control
// plane. Before writing, the replacement cert must:
//  1. carry OUR existing device public key (key-continuity), and
//  2. name the SAME SPIFFE id as our current cert, and
//  3. chain to our CURRENT trust bundle.
//
// And we explicitly REFUSE a trust-bundle change over this path: CA rotation is
// an out-of-band operation, not something a renew can silently perform (otherwise
// a compromised XConnect could swap the node's trust anchor → permanent takeover).
func renewApply(etc string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Certificate string `json:"certificate"`
			TrustBundle string `json:"trust_bundle"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Certificate == "" {
			writeJSON(w, 400, map[string]any{"error": "certificate required"})
			return
		}
		blk, _ := pem.Decode([]byte(body.Certificate))
		if blk == nil {
			writeJSON(w, 400, map[string]any{"error": "certificate not PEM"})
			return
		}
		crt, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": "certificate parse: " + err.Error()})
			return
		}
		if time.Now().After(crt.NotAfter) {
			writeJSON(w, 400, map[string]any{"error": "refusing an already-expired cert"})
			return
		}

		// (1) Key continuity — the new cert must be for OUR device key.
		key, err := loadDeviceKey(etc)
		if err != nil {
			writeJSON(w, 500, map[string]any{"error": "load device key: " + err.Error()})
			return
		}
		ourPub, e1 := x509.MarshalPKIXPublicKey(key.Public())
		newPub, e2 := x509.MarshalPKIXPublicKey(crt.PublicKey)
		if e1 != nil || e2 != nil || !bytes.Equal(ourPub, newPub) {
			writeJSON(w, 400, map[string]any{"error": "refusing renew: cert is not for our device key (key-continuity violation)"})
			return
		}

		// (2) Same SPIFFE identity as the cert we currently hold.
		curRaw, err := os.ReadFile(filepath.Join(etc, "device-cert.pem"))
		if err != nil {
			writeJSON(w, 500, map[string]any{"error": "read current cert: " + err.Error()})
			return
		}
		curBlk, _ := pem.Decode(curRaw)
		if curBlk == nil {
			writeJSON(w, 500, map[string]any{"error": "current cert not PEM"})
			return
		}
		curCrt, err := x509.ParseCertificate(curBlk.Bytes)
		if err != nil {
			writeJSON(w, 500, map[string]any{"error": "parse current cert: " + err.Error()})
			return
		}
		if firstURI(crt) == "" || firstURI(crt) != firstURI(curCrt) {
			writeJSON(w, 400, map[string]any{"error": fmt.Sprintf("refusing renew: SPIFFE id changed (%q != %q)", firstURI(crt), firstURI(curCrt))})
			return
		}

		// (3) Chains to our CURRENT trust bundle (anchor unchanged).
		bundleRaw, err := os.ReadFile(filepath.Join(etc, "trust-bundle.pem"))
		if err != nil {
			writeJSON(w, 500, map[string]any{"error": "read trust bundle: " + err.Error()})
			return
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(bundleRaw) {
			writeJSON(w, 500, map[string]any{"error": "no certs in trust bundle"})
			return
		}
		if _, err := crt.Verify(x509.VerifyOptions{
			Roots: pool, Intermediates: pool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); err != nil {
			writeJSON(w, 400, map[string]any{"error": "refusing renew: cert does not chain to current trust bundle: " + err.Error()})
			return
		}

		// Refuse a trust-bundle change over renew (CA rotation is out of band).
		if tb := strings.TrimSpace(body.TrustBundle); tb != "" && tb != strings.TrimSpace(string(bundleRaw)) {
			writeJSON(w, 400, map[string]any{"error": "refusing renew: trust-bundle changes are not accepted over /renew/apply"})
			return
		}

		if err := os.WriteFile(filepath.Join(etc, "device-cert.pem"), []byte(body.Certificate), 0o644); err != nil {
			writeJSON(w, 500, map[string]any{"error": "write cert: " + err.Error()})
			return
		}
		// trust-bundle.pem is intentionally NOT rewritten here.
		log.Printf("renew: applied new cert (not_after %s) — reconnecting to use it", crt.NotAfter.Format(time.RFC3339))
		writeJSON(w, 200, map[string]any{"applied": true, "not_after": crt.NotAfter.Format(time.RFC3339)})
		// Reconnect so the new cert is used; the dial loop re-reads etc/.
		go func() { time.Sleep(300 * time.Millisecond); dropCurConn() }()
	}
}
