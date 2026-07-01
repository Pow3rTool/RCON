# Deploying RCON to a node

Static, zero-dependency Go binary. `dist/rcon-linux-amd64` (x86-64) ·
`dist/rcon-linux-arm64` (aarch64). The installer auto-detects arch.

## Fleet path (recommended) — one line, non-blocking, walk away

The box installs, registers, and the **service waits for approval on its own** —
no foreground CLI sitting and polling. Pass the join token via the **environment**
(never the URL, so it stays out of nginx logs):

```bash
curl -fsS https://<xconnect-fqdn>/bootstrap/install.sh | RCON_JOIN_TOKEN=pjt_… sh
```

> **TLS is verified** (no `-k`). The bootstrap vhost has real public TLS, so an
> on-path attacker can't substitute the installer, the binary, or the trust
> bundle. Only fall back to `-k`/`--insecure` for a genuinely self-signed origin —
> and if you do, **pin the CA out-of-band** with `--ca-pin sha256:<hex>` (copy it
> from the console alongside the join token) so enrollment can't be MITM'd.

That pulls the right-arch binary and runs `rcon install`, which:
- writes `/etc/rcon/enroll.env` (token + xconnect URL + broker),
- installs a `Type=simple` systemd unit and `systemctl enable` + `start --no-block`,
- **returns immediately.**

The node is now `PENDING`. Approve it (console, or `manage.py approve_enrollment`)
whenever — the service self-enrolls and connects on its own. Reboot-safe.

### Two-step (binary already on the box, or no install.sh addon yet)
```bash
sudo rcon install \
  --token pjt_… \
  --xconnect https://<xconnect-fqdn> \
  --name <node-name>
```
Same result: configures + starts the service non-blocking; approve in the console.

### Why it doesn't hang boot
The unit is `Type=simple`, and `ExecStart` does the enroll-and-wait **in-process**
(`--enroll-if-needed`). systemd considers the unit *started* the instant the
process forks, so the **start job completes immediately** — boot reaches "running"
and never waits on approval. The unit is only `WantedBy=multi-user.target` (a weak,
**unordered** Wants) with deliberately **no** `Before=multi-user.target`, and the
installer uses `start --no-block`. Pre-approval reboot, post-approval reboot, first
install — boot is never blocked. The node just sits `active (running)`, waiting,
then connects when approved. With a valid cert present, the enroll step is a no-op.

## Interactive path (watch the first box onboard)

`rcon enroll` blocks in the foreground, polling until you approve — handy when you
want to watch one box come up:
```bash
sudo rcon enroll --token pjt_… --xconnect https://<xconnect-fqdn> \
  --etc /etc/rcon --name <node-name>
# TLS is verified by default. For a self-signed origin only: add --insecure AND
# --ca-pin sha256:<hex> (out-of-band CA pin) so the trust bundle can't be swapped.
# (add --install-service to write+enable the unit AFTER approval)
```

## Pushing a new client version to existing nodes (signed self-update)

You do **not** re-run the installer to upgrade — nodes self-update over the tunnel.
On the control plane (Orthanc), publish + sign each arch, then point the cohort at it:

```bash
# 1. publish + Ed25519-sign each arch (writes a signed Release)
manage.py publish_release v0.3.0 --binary dist/rcon-linux-amd64 --os linux --arch amd64
manage.py publish_release v0.3.0 --binary dist/rcon-linux-arm64 --os linux --arch arm64

# 2. promote the cohort(s) — per os/arch — to that version
manage.py promote_release stable v0.3.0 --os linux --arch amd64
manage.py promote_release stable v0.3.0 --os linux --arch arm64
manage.py promote_release canary v0.3.0 --os linux --arch amd64   # if you run a canary cohort
```

On its next connect, each node pulls the signed binary down the tunnel, **verifies
the Ed25519 signature against its baked pubkey**, runs `--selftest`, atomically
swaps, and re-execs — with a watchdog that **rolls back** if the new binary can't
reconnect. A node whose channel has no target (or that already runs the target
version) is a no-op. (A *keyless* binary can't verify and won't self-update — those
must be reinstalled via the fleet path above.)

## Network requirements (egress only — the box dials OUT, nothing inbound)
- **TCP 443** to `<xconnect-fqdn>` — enrollment (`/bootstrap`).
- **TCP 3** to `<xconnect-fqdn>` — the broker tunnel. **Unusual low port — confirm
  the VM's egress / security group allows it.**
