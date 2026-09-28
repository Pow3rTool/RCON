// RCON enrollment — the fresh-box bootstrap.
//
//	rcon enroll --token <join-token> --xconnect https://<xconnect-fqdn>
//
// Generates a device key + CSR, self-registers against XConnect's certless
// /bootstrap door (the join token is the only credential), then polls until an
// operator approves — writing device-key/cert + trust-bundle into --etc. After
// that, `rcon` (serve) connects normally. Idempotent with --if-needed so it can
// be an Ansible ExecStartPre: a box "sits waiting for approval" then connects.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func runEnroll(args []string) {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	etc := fs.String("etc", defaultIdentityDir(), "identity directory")
	xc := fs.String("xconnect", "", "XConnect bootstrap base URL, e.g. https://<xconnect-fqdn> (required; nginx /bootstrap)")
	token := fs.String("token", os.Getenv("RCON_JOIN_TOKEN"), "join token (the only credential a fresh box needs); defaults to $RCON_JOIN_TOKEN so it stays off the command line")
	name := fs.String("name", "", "requested node name (defaults to hostname)")
	insecure := fs.Bool("insecure", false, "unsupported: bootstrap requires verified HTTPS; install your CA in the OS trust store")
	caPin := fs.String("ca-pin", os.Getenv("RCON_CA_PIN"), "out-of-band CA pin (sha256:<hex of root SPKI>); defaults to $RCON_CA_PIN")
	ifNeeded := fs.Bool("if-needed", false, "no-op if a valid device cert is already present (for ExecStartPre)")
	poll := fs.Duration("poll", 5*time.Second, "approval poll interval")
	timeout := fs.Duration("timeout", 0, "give up after this long waiting for approval (0 = wait forever)")
	installSvc := fs.Bool("install-service", false, "after approval, install + enable a systemd service (rcon.service)")
	brokerFlag := fs.String("broker", "", "broker address for the installed service (default: <xconnect-host>:3)")
	_ = fs.Parse(args)

	if *xc == "" {
		log.Fatalf("enroll: --xconnect (XConnect bootstrap base URL, e.g. https://<xconnect-fqdn>) is required")
	}

	if *ifNeeded && haveValidCert(*etc) {
		log.Printf("enroll: --if-needed: valid device cert already present in %s — skipping enrollment", *etc)
		if *installSvc {
			installService(*etc, *brokerFlag, *xc) // still (idempotently) ensure the service
		}
		return
	}
	if *token == "" {
		log.Fatalf("enroll: --token (join token) is required")
	}
	reqName := *name
	if reqName == "" {
		reqName, _ = os.Hostname()
	}
	if err := enrollAndAwait(*etc, *xc, *token, reqName, *insecure, *caPin, *poll, *timeout); err != nil {
		log.Fatalf("enroll: %v", err)
	}
	if *installSvc {
		installService(*etc, *brokerFlag, *xc)
	}
}

// enrollAndAwait runs the full bootstrap: generate+persist a device key, register
// against XConnect's certless /bootstrap door (the join token is the only
// credential), then poll until an operator approves — writing device-cert +
// trust-bundle into etc. Blocks until approved unless timeout>0. Returns nil once
// the cert is on disk. Shared by `rcon enroll` (interactive/foreground) and serve's
// --enroll-if-needed, so the systemd service can do the waiting in-process instead
// of a foreground CLI (and without blocking boot — see runInstall).
func enrollAndAwait(etc, xc, token, reqName string, insecure bool, caPin string, poll, timeout time.Duration) error {
	if err := validateBootstrapURL(xc, insecure); err != nil {
		return err
	}
	xc = strings.TrimRight(xc, "/")
	if token == "" {
		return fmt.Errorf("--token (join token) is required")
	}
	if reqName == "" {
		reqName, _ = os.Hostname()
	}

	// 1. Device keypair (EC P-256, matches the reference enroll contract).
	if err := ensureIdentityDir(etc); err != nil {
		return err
	}
	key, err := createDeviceKey(etc)
	if err != nil {
		return fmt.Errorf("keygen: %w", err)
	}
	// 2. Bare CSR — Orthanc assigns the SPIFFE id at approval and puts it in the
	//    signed cert's SAN; the CSR is just proof-of-possession of the key.
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: reqName}}, key)
	if err != nil {
		return fmt.Errorf("build CSR: %w", err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))

	client := bootstrapClient()

	// 3. Register → PENDING.
	enrollID, err := pendingEnrollmentID(etc, xc, key)
	if err != nil {
		return err
	}
	if enrollID == "" {
		reg, err := bootCall(client, "POST", xc+"/bootstrap/enroll", map[string]any{
			"join_token": token, "csr": csrPEM, "name": reqName})
		if err != nil {
			return fmt.Errorf("register: %w", err)
		}
		enrollID, _ = reg["enrollment_id"].(string)
		if enrollID == "" {
			return fmt.Errorf("no enrollment_id in response: %v", reg)
		}
		if err := savePendingEnrollment(etc, xc, enrollID, key); err != nil {
			return err
		}
	}
	log.Printf("enroll: %q → enrollment %s. Waiting for operator approval…", reqName, enrollID)

	// 4. Poll until approved (or revoked / timeout).
	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	for {
		st, err := bootCall(client, "GET", fmt.Sprintf("%s/bootstrap/cert?id=%s", xc, enrollID), nil)
		if err != nil {
			log.Printf("enroll: poll: %v (retrying)", err)
		} else {
			switch s, _ := st["state"].(string); s {
			case "active":
				cert, _ := st["certificate"].(string)
				bundle, _ := st["trust_bundle"].(string)
				if cert == "" || bundle == "" {
					return fmt.Errorf("active but cert/trust_bundle missing in response")
				}
				// Out-of-band trust check: if a CA pin was supplied, the received
				// bundle MUST match it. This is additional to verified HTTPS;
				// checking the returned CA cannot protect a token already sent.
				if err := verifyCAPin([]byte(bundle), caPin); err != nil {
					return err
				}
				writeOrDie(filepath.Join(etc, "device-cert.pem"), []byte(cert), 0o644)
				writeOrDie(filepath.Join(etc, "trust-bundle.pem"), []byte(bundle), 0o644)
				meta, _ := json.MarshalIndent(map[string]any{
					"enrollment_id": enrollID, "spiffe_id": st["spiffe_id"],
					"bound_name": st["bound_name"], "state": "active"}, "", " ")
				writeOrDie(filepath.Join(etc, "enrollment.json"), meta, 0o644)
				// Purge the fleet join token now that we hold a cert. The token is a
				// FLEET credential (it can register OTHER boxes into PENDING), so a
				// copy sitting on an already-enrolled node is pure downside — leaking
				// it (via /read of enroll.env, or a future env re-load) buys rogue-box
				// enrollment. It has served its one purpose here.
				purgeJoinToken(etc)
				log.Printf("enroll: APPROVED → identity %v written to %s. Ready to connect.", st["spiffe_id"], etc)
				return nil
			case "revoked":
				return fmt.Errorf("enrollment was revoked — aborting")
			}
		}
		if timeout > 0 && time.Now().After(deadline) {
			return fmt.Errorf("gave up waiting for approval after %s", timeout)
		}
		time.Sleep(poll)
	}
}

// installService writes + enables a systemd unit so the agent runs as a service
// (survives logout/reboot). Derives the broker from the --xconnect host (:3) when
// --broker isn't given. Needs root (writing /etc/systemd + systemctl); logs and
// returns on failure rather than aborting a successful enrollment.
func installLinuxService(etc, broker, xc string) {
	if broker == "" {
		if u, err := url.Parse(xc); err == nil && u.Hostname() != "" {
			broker = u.Hostname() + ":3"
		} else {
			log.Printf("install-service: can't derive broker from %q — pass --broker; skipping", xc)
			return
		}
	}
	exe, err := os.Executable()
	if err != nil {
		log.Printf("install-service: can't locate self: %v; skipping", err)
		return
	}
	unit := fmt.Sprintf(`[Unit]
Description=Pow3rtool RCON agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%s --etc %s --broker %s
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`, exe, etc, broker)
	const path = "/etc/systemd/system/rcon.service"
	if err := os.WriteFile(path, []byte(unit), 0o644); err != nil {
		log.Printf("install-service: write %s failed (need root?): %v", path, err)
		return
	}
	for _, a := range [][]string{{"daemon-reload"}, {"enable", "--now", "rcon"}} {
		if out, err := exec.Command("systemctl", a...).CombinedOutput(); err != nil {
			log.Printf("install-service: systemctl %v failed: %v: %s", a, err, string(out))
			return
		}
	}
	log.Printf("install-service: rcon.service installed + enabled (ExecStart=%s --etc %s --broker %s)", exe, etc, broker)
}

func haveValidCert(etc string) bool {
	raw, err := os.ReadFile(filepath.Join(etc, "device-cert.pem"))
	if err != nil {
		return false
	}
	blk, _ := pem.Decode(raw)
	if blk == nil {
		return false
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return false
	}
	return time.Now().Before(c.NotAfter)
}

func validateBootstrapURL(raw string, insecure bool) error {
	if insecure {
		return fmt.Errorf("--insecure is no longer supported: install the bootstrap server CA in the OS trust store; --ca-pin does not protect the join token in transit")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return fmt.Errorf("--xconnect must be an HTTPS base URL without credentials, query, or fragment")
	}
	return nil
}

func bootstrapClient() *http.Client {
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{}, // OS trust roots, including enterprise CAs.
		// Even a 307/308 must not forward the join-token body to another URL.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func bootCall(c *http.Client, method, url string, body map[string]any) (map[string]any, error) {
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		return nil, err
	}
	// Also guard direct callers; polling URLs may contain a query string.
	if req.URL.Scheme != "https" || req.URL.Hostname() == "" || req.URL.User != nil {
		return nil, fmt.Errorf("bootstrap requires verified HTTPS")
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if out != nil {
			if e, ok := out["error"]; ok {
				return out, fmt.Errorf("HTTP %d: %v", resp.StatusCode, e)
			}
		}
		return out, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return out, nil
}

// purgeJoinToken rewrites enroll.env WITHOUT the RCON_JOIN_TOKEN line, once
// enrollment has produced a cert. Best-effort — never blocks enrollment. Note the
// honest limit: the CURRENT process's /proc/self/environ still holds the token
// until the next restart re-loads the now-tokenless file; the persistent on-disk
// copy (the thing a /read or a later boot would surface) is what this removes.
func purgeJoinToken(etc string) {
	purgePlatformJoinToken(etc)
	p := filepath.Join(etc, "enroll.env")
	data, err := os.ReadFile(p)
	if err != nil {
		return // no enroll.env (e.g. interactive enroll) — nothing to purge
	}
	kept := make([]string, 0)
	changed := false
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "RCON_JOIN_TOKEN=") {
			changed = true
			continue
		}
		kept = append(kept, line)
	}
	if !changed {
		return
	}
	if err := os.WriteFile(p, []byte(strings.Join(kept, "\n")), 0o600); err != nil {
		log.Printf("enroll: WARNING could not purge join token from %s: %v", p, err)
		return
	}
	log.Printf("enroll: purged join token from %s (fleet credential no longer needed on this node)", p)
}

func writeOrDie(path string, data []byte, mode os.FileMode) {
	if err := os.WriteFile(path, data, mode); err != nil {
		log.Fatalf("enroll: write %s: %v", path, err)
	}
}

// verifyCAPin checks the received trust bundle against an operator-supplied,
// out-of-band CA pin (sha256 of a CA cert's SubjectPublicKeyInfo). This defeats
// an enrollment-time MITM that hands back its own trust bundle: even over an
// unverified TLS channel, a substituted CA won't match the pin. An operator can
// pin the long-lived ROOT and survive intermediate rotation. Empty pin = no check
// (legacy TOFU; warned). Accepts "sha256:<hex>" or bare "<hex>".
//
// Beyond matching the pin, EVERY other cert in the bundle must belong to the same
// PKI as the pinned anchor — it must chain to the pinned cert, or be an ancestor
// the pinned cert chains up to (so pinning either the root or the intermediate
// works). Otherwise a MITM could smuggle its OWN extra self-signed anchor in
// alongside the legitimate pinned one; the whole bundle is written to
// trust-bundle.pem and loaded as roots, so an unrelated extra would become a
// permanent trust anchor (and a permanent MITM position). Unrelated certs =
// refuse to enroll.
func verifyCAPin(bundlePEM []byte, pin string) error {
	want := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(pin), "sha256:")))
	if want == "" {
		return nil
	}
	var certs []*x509.Certificate
	var saw []string
	rest := bundlePEM
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return fmt.Errorf("trust-bundle contains an unparseable certificate — refusing to enroll: %w", err)
		}
		certs = append(certs, c)
		sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
		saw = append(saw, hex.EncodeToString(sum[:]))
	}
	var pinned *x509.Certificate
	for i, c := range certs {
		if saw[i] == want {
			pinned = c
			break
		}
	}
	if pinned == nil {
		return fmt.Errorf("trust-bundle CA pin mismatch: none of %v matches --ca-pin %q (possible MITM — refusing to enroll)", saw, want)
	}
	// All bundle certs available as intermediates for chain building.
	inter := x509.NewCertPool()
	for _, c := range certs {
		inter.AddCert(c)
	}
	chainsTo := func(leaf, anchor *x509.Certificate) bool {
		r := x509.NewCertPool()
		r.AddCert(anchor)
		_, err := leaf.Verify(x509.VerifyOptions{
			Roots: r, Intermediates: inter,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		return err == nil
	}
	for _, c := range certs {
		if c.Equal(pinned) {
			continue
		}
		// Accept only certs in the pinned anchor's chain (either direction).
		if !chainsTo(c, pinned) && !chainsTo(pinned, c) {
			sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
			return fmt.Errorf("trust-bundle contains a cert (spki %s) unrelated to the pinned CA "+
				"— refusing to enroll (possible injected trust anchor)", hex.EncodeToString(sum[:]))
		}
	}
	return nil
}
