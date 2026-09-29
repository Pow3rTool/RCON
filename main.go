// RCON — Pow3rtool resident agent (minimal Go reverse-dial stub).
//
// Dials XConnect's broker over mutually-pinned mTLS, then reverses the HTTP/2
// roles (RCON becomes the h2 SERVER on the conn it dialed) and serves the
// bounded admin tool surface back DOWN the tunnel. Holds only its own device
// key + the pinned CA anchor. Implements the full exec_daemon.py contract
// (run/read/edit/write + jobs + self-update); reference/ is now superseded.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http2"
)

const outputCap = 1 << 20 // 1 MB, matches the reference daemon

func main() {
	if platformCommand(os.Args[1:]) {
		return
	}
	runAgent(os.Args[1:])
}

func runAgent(args []string) {
	// Subcommands: `rcon enroll …` self-registers a fresh box (interactive);
	// `rcon install …` configures + enables the systemd service NON-blockingly
	// (the fleet path); default (no subcommand) connects/serves.
	if len(args) > 0 {
		switch args[0] {
		case "enroll":
			runEnroll(args[1:])
			return
		case "install":
			runInstall(args[1:])
			return
		}
	}

	etc := flag.String("etc", defaultIdentityDir(), "identity dir (device certificate/key reference, trust-bundle)")
	broker := flag.String("broker", "127.0.0.1:3", "XConnect broker address to reverse-dial")
	selftest := flag.Bool("selftest", false, "load identity + reach the broker, then exit (self-update gate)")
	showVer := flag.Bool("version", false, "print version and exit")
	// In-process self-enroll: with --enroll-if-needed and no valid cert yet, register
	// + WAIT for operator approval here, then serve — all in one process. This lets
	// the systemd unit be Type=simple so the start job completes at fork and the box's
	// boot is NEVER blocked waiting for approval (the wait is asynchronous to boot).
	enrollIfNeeded := flag.Bool("enroll-if-needed", false, "serve: self-enroll (register + wait for approval) in-process if no valid cert, then serve")
	joinToken := flag.String("token", os.Getenv("RCON_JOIN_TOKEN"), "serve: join token for --enroll-if-needed; defaults to $RCON_JOIN_TOKEN so it stays off the command line")
	xconnectURL := flag.String("xconnect", "", "serve: XConnect bootstrap base URL for --enroll-if-needed")
	insecure := flag.Bool("insecure", false, "unsupported for enrollment: install the bootstrap CA in the OS trust store")
	caPin := flag.String("ca-pin", os.Getenv("RCON_CA_PIN"), "serve: out-of-band CA pin (sha256:<hex>); defaults to $RCON_CA_PIN")
	enrollName := flag.String("name", "", "serve: requested node name for --enroll-if-needed (default hostname)")
	auditLog := flag.String("audit-log", defaultAuditPath(), "serve: local tamper-evident (hash-chained) action audit log")
	flag.CommandLine.Parse(args)

	if *showVer {
		fmt.Println(version)
		return
	}

	// --selftest: a candidate binary proves it can load identity + reach the
	// broker before the running instance ever swaps to it. Exit 0 = healthy.
	if *selftest {
		runSelfTest(*etc, *broker)
		return
	}

	// In-process self-enroll (fleet path): block here until approved, then fall
	// through to serve. No-op once a valid cert is present (post-approval reboots
	// go straight to serving). Type=simple means systemd already considers us
	// "started", so this wait never blocks the boot transaction.
	if *enrollIfNeeded && !haveValidCert(*etc) {
		log.Printf("rcon: no valid device cert in %s — self-enrolling, will WAIT for operator approval…", *etc)
		if err := enrollAndAwait(*etc, *xconnectURL, *joinToken, *enrollName, *insecure, *caPin, 5*time.Second, 0); err != nil {
			log.Fatalf("rcon: self-enroll failed: %v", err)
		}
	}

	cfg, mySVID, err := buildTLS(*etc)
	if err != nil {
		log.Fatalf("rcon: %v", err)
	}
	log.Printf("rcon: identity %s — version %s (%s/%s)", mySVID, version, runtime.GOOS, runtime.GOARCH)

	initAudit(*auditLog) // node-side tamper-evident record (independent of XConnect's audit)
	store := NewJobStore()
	handler := mux(mySVID, store, *etc, *broker)

	// If we were just re-exec'd by a self-update, arm a watchdog that rolls back
	// to the previous binary unless we establish a healthy tunnel quickly.
	if from := os.Getenv("RCON_UPDATED_FROM"); from != "" {
		log.Printf("rcon: post-update watchdog armed (was %s, now %s)", from, version)
		go updateWatchdog()
	}

	for { // reconnect with jittered backoff (anti-herd)
		// Re-read identity each reconnect so a renewed cert takes effect without
		// a restart (renew/apply writes the cert then drops the tunnel).
		if c, _, e := buildTLS(*etc); e == nil {
			cfg = c
		} else {
			log.Printf("rcon: cert reload failed, keeping previous: %v", e)
		}
		if err := dialAndServe(*broker, cfg, handler); err != nil {
			log.Printf("rcon: tunnel ended: %v", err)
		}
		d := time.Duration(float64(5*time.Second) * (0.5 + rand.Float64()))
		log.Printf("rcon: reconnecting in %s", d.Round(time.Millisecond))
		time.Sleep(d)
	}
}

// buildTLS loads the device identity and returns the reverse-dial TLS config
// (pins OUR CA, requires the broker to be a system/xconnect of OUR tenant —
// system trust store ignored) plus our SVID. Shared by serve and --selftest.
func buildTLS(etc string) (*tls.Config, string, error) {
	cert, err := loadDeviceCertificate(etc)
	if err != nil {
		return nil, "", fmt.Errorf("load device keypair: %w", err)
	}
	bundle, err := os.ReadFile(filepath.Join(etc, "trust-bundle.pem"))
	if err != nil {
		return nil, "", fmt.Errorf("read trust bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(bundle) {
		return nil, "", fmt.Errorf("no certs in trust bundle")
	}
	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	mySVID := firstURI(leaf)
	myTenant := tenantOf(mySVID)
	verify := func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		sleaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		inter := x509.NewCertPool()
		for _, raw := range rawCerts[1:] {
			if c, e := x509.ParseCertificate(raw); e == nil {
				inter.AddCert(c)
			}
		}
		if _, err := sleaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			return fmt.Errorf("broker cert not anchored to our CA: %w", err)
		}
		// Structural SPIFFE check (not a substring match): the broker SVID must be
		// exactly <tenant>/system/xconnect/<id> in OUR tenant — so a node/other-role
		// SVID with "system/xconnect" anywhere in it can't slip through.
		if err := verifyBrokerSVID(firstURI(sleaf), myTenant); err != nil {
			return err
		}
		return nil
	}
	return &tls.Config{
		Certificates:          []tls.Certificate{cert},
		InsecureSkipVerify:    true, // replaced by the pin+SPIFFE check above
		VerifyPeerCertificate: verify,
		NextProtos:            []string{"h2"},
		MinVersion:            tls.VersionTLS13, // broker link is ours end-to-end — 1.3 only
	}, mySVID, nil
}

func dialAndServe(addr string, cfg *tls.Config, h http.Handler) error {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 15 * time.Second}, "tcp", addr, cfg)
	if err != nil {
		return err
	}
	log.Printf("rcon: tunnel up to %s — serving tool surface back down it", addr)
	setCurConn(conn) // renew/apply closes this to force a cert-reloading reconnect
	defer clearCurConn()
	// We dialed as TLS client, but become the HTTP/2 SERVER on this conn.
	// PINGs detect a silently-stalled tunnel (spanning-tree blip) within ~30s so
	// we reconnect instead of clinging to a dead socket.
	srv := &http2.Server{ReadIdleTimeout: 15 * time.Second, PingTimeout: 15 * time.Second}
	srv.ServeConn(conn, &http2.ServeConnOpts{Handler: h})
	return fmt.Errorf("ServeConn returned (tunnel closed)")
}

func mux(svid string, store *JobStore, etc, broker string) http.Handler {
	m := http.NewServeMux()

	m.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		markHealthy() // feeds the post-update rollback watchdog
		res := map[string]any{
			"ok": true, "node": svid, "version": version, "protocol": protocolVersion,
			"goos": runtime.GOOS, "goarch": runtime.GOARCH,
			"shell": commandShell, "os_version": platformOSVersion(),
			"capabilities": map[string]bool{"self_update": supportsSelfUpdate, "posix_metadata": supportsPOSIXMetadata},
			"time":         time.Now().UTC().Format(time.RFC3339)}
		// Additive fields: callers that don't know them ignore them.
		if d := drainReason(); d != "" {
			res["draining"] = d
		}
		if u := lastUpgradeReport(); u != nil {
			res["last_upgrade"] = u
		}
		if p := pendingUpgradeReport(); p != nil {
			res["pending_upgrade"] = p
		}
		writeJSON(w, 200, res)
	})

	// Self-update: XConnect relays an Orthanc-SIGNED binary down the tunnel.
	m.HandleFunc("POST /update/apply", updateApply(etc, broker, store))

	// File primitives (ported from reference/exec_daemon.py). read→edit→write,
	// with the read-before-write hash guard (optimistic concurrency).
	// Everything that changes the node is gated() so an upgrade can drain it (drain.go).
	m.HandleFunc("POST /read", readFile)
	m.HandleFunc("POST /edit", gated(editFile))
	m.HandleFunc("POST /write", gated(writeFile))
	// Metadata writes use a distinct additive endpoint so a newer XConnect
	// routed to an older RCON fails closed with 404 instead of having the old
	// JSON decoder silently ignore owner/group/mode and report a false success.
	m.HandleFunc("POST /write-metadata", gated(writeFile))

	// Cert renewal (XConnect-driven, over the tunnel): CSR out, signed cert in.
	m.HandleFunc("GET /renew/csr", renewCSR(etc))
	m.HandleFunc("POST /renew/apply", gated(renewApply(etc)))

	// Fast, synchronous one-shot (full exec_daemon /run contract: timeout,
	// separate stdout/stderr, dur, truncated, session-cwd). Lose-and-retry on a
	// blip; use /jobs for anything long-running.
	m.HandleFunc("POST /run", gated(runHandler))

	// Long-running job: survives tunnel blips, reattach by cursor, explicit cancel.
	m.HandleFunc("POST /jobs", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Cmd string `json:"cmd"`
			Rid string `json:"rid"` // XConnect correlation id (cross-ref to Witchhunt)
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]any{"error": "invalid JSON body: " + err.Error()})
			return
		}
		if body.Cmd == "" {
			writeJSON(w, 400, map[string]any{"error": "cmd required"})
			return
		}
		j, err := store.Start(body.Cmd, body.Rid)
		if err != nil {
			// Transient backpressure (concurrent-job cap or upgrade drain), not an
			// authz denial — retryable so the caller/LLM waits instead of giving up.
			if _, ok := err.(errDraining); ok {
				writeJSON(w, 503, map[string]any{"error": err.Error(), "retryable": true, "draining": true})
				return
			}
			writeJSON(w, 429, map[string]any{"error": err.Error(), "retryable": true})
			return
		}
		writeJSON(w, 200, map[string]any{"job_id": j.ID, "state": "running"})
	})

	// Reattach: GET /jobs/{id}?from=<cursor> resumes output from the cursor.
	m.HandleFunc("GET /jobs/{id}", func(w http.ResponseWriter, r *http.Request) {
		j := store.Get(r.PathValue("id"))
		if j == nil {
			writeJSON(w, 404, map[string]any{"error": "no such job"})
			return
		}
		from, _ := strconv.Atoi(r.URL.Query().Get("from"))
		data, next, eof := j.Read(from, 256<<10)
		state, exit := j.snapshotState()
		res := map[string]any{
			"job_id": j.ID, "state": state, "from": from, "next": next,
			"eof": eof, "output": string(data), "dur": j.Dur(),
		}
		if state == "exited" {
			res["exit"] = exit
		}
		writeJSON(w, 200, res)
	})

	m.HandleFunc("POST /jobs/{id}/cancel", func(w http.ResponseWriter, r *http.Request) {
		j := store.Get(r.PathValue("id"))
		if j == nil {
			writeJSON(w, 404, map[string]any{"error": "no such job"})
			return
		}
		j.Cancel()
		state, _ := j.snapshotState()
		writeJSON(w, 200, map[string]any{"job_id": j.ID, "cancelled": true, "state": state})
	})

	return m
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func firstURI(c *x509.Certificate) string {
	for _, u := range c.URIs {
		return u.String()
	}
	return ""
}

func tenantOf(svid string) string {
	u, err := url.Parse(svid)
	if err != nil {
		return ""
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

// verifyBrokerSVID structurally validates the broker's SPIFFE id: it must be a
// spiffe:// URI whose path is exactly <tenant>/system/xconnect/<id> in our tenant.
// This replaces a fragile strings.Contains(..., "/system/xconnect/") that a
// crafted SVID (e.g. .../node/system/xconnect-ish/...) could otherwise satisfy.
func verifyBrokerSVID(svid, myTenant string) error {
	u, err := url.Parse(svid)
	if err != nil || u.Scheme != "spiffe" {
		return fmt.Errorf("broker SVID %q is not a spiffe id", svid)
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 4 || parts[0] != myTenant || parts[1] != "system" || parts[2] != "xconnect" {
		return fmt.Errorf("broker SVID %q is not an xconnect for tenant %s", svid, myTenant)
	}
	return nil
}
