// RCON service install — the NON-INTERACTIVE fleet path.
//
//	rcon install --token <join-token> --xconnect https://<xconnect-fqdn>
//
// Configures + enables a systemd service and RETURNS IMMEDIATELY. The unit is
// Type=simple and its ExecStart self-enrolls (registers, then waits for operator
// approval IN-PROCESS) before serving — so the systemd start job completes the
// instant the process forks. That means:
//
//   - the box's boot is NEVER blocked waiting for approval/connect (the wait is
//     asynchronous to the boot transaction),
//   - `systemctl start --no-block` returns at once at install time,
//   - the unit is only WantedBy=multi-user.target (a weak, UNORDERED Wants) with
//     deliberately NO Before=multi-user.target — nothing in boot waits on us.
//
// Contrast with `rcon enroll --install-service`, which blocks the foreground until
// approved, then installs. `install` is the one-shot, walk-away fleet command.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func runInstall(args []string) {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	etc := fs.String("etc", "/etc/rcon", "identity dir for device-cert/key + trust-bundle")
	xc := fs.String("xconnect", "", "XConnect bootstrap base URL, e.g. https://<xconnect-fqdn> (required)")
	token := fs.String("token", "", "join token (required) — the only credential a fresh box needs")
	broker := fs.String("broker", "", "broker address for the service (default: <xconnect-host>:3)")
	name := fs.String("name", "", "requested node name (default hostname)")
	insecure := fs.Bool("insecure", false, "skip TLS verify on the bootstrap fetch (ONLY for a self-signed origin; pair with --ca-pin). The broker tunnel is always pinned mTLS regardless")
	caPin := fs.String("ca-pin", "", "out-of-band CA pin (sha256:<hex>) verifying the enrollment trust bundle — defeats enrollment-time MITM")
	unitPath := fs.String("unit", "/etc/systemd/system/rcon.service", "systemd unit path to write")
	_ = fs.Parse(args)

	if *xc == "" || *token == "" {
		log.Fatalf("install: --xconnect and --token are both required")
	}
	if *insecure && strings.TrimSpace(*caPin) == "" {
		log.Fatalf("install: refusing --insecure without --ca-pin sha256:<fp> — enrollment would be " +
			"MITM-able and the attacker becomes this node's permanent control plane. " +
			"Pass --ca-pin (from the console) or drop --insecure to use verified TLS.")
	}
	brokerAddr := *broker
	if brokerAddr == "" {
		if u, err := url.Parse(*xc); err == nil && u.Hostname() != "" {
			brokerAddr = u.Hostname() + ":3"
		} else {
			log.Fatalf("install: can't derive broker from --xconnect %q — pass --broker", *xc)
		}
	}
	reqName := *name
	if reqName == "" {
		reqName, _ = os.Hostname()
	}
	exe, err := os.Executable()
	if err != nil {
		log.Fatalf("install: can't locate self: %v", err)
	}

	// 1. enroll.env (0600) — the credentials + targets the unit reads.
	if err := os.MkdirAll(*etc, 0o700); err != nil {
		log.Fatalf("install: mkdir %s: %v", *etc, err)
	}
	envPath := filepath.Join(*etc, "enroll.env")
	env := fmt.Sprintf("RCON_JOIN_TOKEN=%s\nRCON_XCONNECT_URL=%s\nRCON_BROKER=%s\nRCON_NAME=%s\nRCON_CA_PIN=%s\n",
		*token, *xc, brokerAddr, reqName, *caPin)
	if err := os.WriteFile(envPath, []byte(env), 0o600); err != nil {
		log.Fatalf("install: write %s: %v", envPath, err)
	}

	// 2. The unit. Type=simple + in-process --enroll-if-needed => the start job
	//    finishes at fork, so boot never waits on approval/connect.
	// The join token + CA pin are read from the environment (EnvironmentFile),
	// NEVER placed on the command line — so the fleet credential never lands in
	// `ps` / journald / `systemctl show`. Only the non-secret --insecure flag is
	// baked into ExecStart.
	extra := ""
	if *insecure {
		extra += " --insecure"
	}
	unit := fmt.Sprintf(`[Unit]
Description=Pow3rtool RCON agent (self-enrolling)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=%s
# ExecStart self-enrolls (waits for approval) if there's no cert yet, then serves
# — all in ONE process. Type=simple => the systemd start job completes at fork, so
# the boot transaction is never blocked waiting for an operator to approve us.
ExecStart=%s --etc %s --broker ${RCON_BROKER} --enroll-if-needed --xconnect ${RCON_XCONNECT_URL} --name ${RCON_NAME}%s
Restart=always
RestartSec=5
# RCON is a privileged root admin agent BY DESIGN (full rationale in
# dist/rcon.service). NoNewPrivileges/ProtectSystem/cap-drop are deliberately left
# at their permissive defaults — they would only be false containment against a
# root agent and would break real admin work (dmesg/sysctl/modprobe/gdb/tcpdump).
# RestrictRealtime is the one directive that costs a sysadmin nothing, so we take it.
RestrictRealtime=true

[Install]
WantedBy=multi-user.target
`, envPath, exe, *etc, extra)
	if err := os.WriteFile(*unitPath, []byte(unit), 0o644); err != nil {
		log.Fatalf("install: write %s (need root?): %v", *unitPath, err)
	}

	// 3. Enable for boot + start NON-BLOCKING. --no-block is essential: without it
	//    `systemctl start` waits for the unit to finish activating, which for a
	//    fresh box means waiting for approval — exactly the blocking we're avoiding.
	unitName := filepath.Base(*unitPath)
	for _, a := range [][]string{
		{"daemon-reload"},
		{"enable", unitName},
		{"start", "--no-block", unitName},
	} {
		if out, err := exec.Command("systemctl", a...).CombinedOutput(); err != nil {
			log.Fatalf("install: systemctl %s failed: %v: %s", strings.Join(a, " "), err, string(out))
		}
	}
	log.Printf("install: %s installed + started (non-blocking). Node %q is registering and will WAIT "+
		"for operator approval, then connect — boot is not blocked. Approve it in the Orthanc console.",
		unitName, reqName)
}
