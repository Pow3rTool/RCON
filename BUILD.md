# Building the RCON agent

The public repository distributes source code, not executable downloads or ZIP
packages. Build and sign artifacts inside your own deployment environment. The
release/promotion commands below describe an operator's internal fleet workflow.
For Windows, use your organization's enterprise code-signing policy; this project
does not require a public signing service or a new certificate authority.

How to compile the agent and cut a release that nodes will accept as a signed
self-update. **Build on a build host** (anything with the Go toolchain + the
RCON source) — *not* on the control- or data-plane VMs; those run
prebuilt binaries by design (smaller attack surface).

## Prerequisites
- **Go 1.26+** (matches `go.mod`). Install from go.dev; e.g.
  `curl -LO https://go.dev/dl/go1.26.8.linux-amd64.tar.gz && sudo tar -C /usr/local -xzf go*.tar.gz`
  → `go` at `/usr/local/go/bin/go`.
- The RCON source mounted (or a clone).
- `release-pubkey.txt` present in `RCON/` (your Ed25519 **release public key**).
  Export it from your own control plane:
  `manage.py export_release_pubkey > /opt/rcon/release-pubkey.txt`.
  Export only the public key; keep the private signing key on the control plane.

## Compile
```bash
cd /opt/rcon
./build.sh v0.3.0                 # → dist/rcon-linux-amd64, dist/rcon-linux-arm64
./build.sh v0.3.0 linux/amd64     # a single platform
./build.sh v0.4.0-windows-lab.1 windows/amd64 # Windows lab executable (.exe)
```
`build.sh` bakes the **version** and the **release pubkey** into the binary,
builds **static** (`CGO_ENABLED=0` — no libc dependency on the target), and runs
two guards that fail the build loudly:
1. **pubkey baked** — a binary with no baked pubkey *cannot verify self-updates*
   and silently bricks the update path (this bug bit us once; the guard exists so
   it can't again).
2. **static** — refuses a dynamically-linked binary.

The version string is what shows in `rcon --version`, the node's `/health`, and
the self-update version comparison — **bump it every release** or self-update
won't trigger.

## Cut a release (on the control plane)
Compiling produces binaries; **publishing signs + registers them**, and
**promoting points a cohort at the version**:
```bash
# 1. sign + register the artifact (Ed25519 over version|os|arch|sha256)
manage.py publish_release v0.3.0 --binary /opt/rcon/dist/rcon-linux-amd64
manage.py publish_release v0.3.0 --binary /opt/rcon/dist/rcon-linux-arm64 --arch arm64

# 2. promote to a cohort — only nodes on that channel converge
manage.py promote_release canary v0.3.0      # scream-test group first
# …confirm the canary fleet is healthy on v0.3.0, then:
manage.py promote_release stable v0.3.0       # everyone else
```
(A node's cohort is `Enrollment.update_channel`, default `stable`; set it in the
console or DB. `--version` is a positional arg — Django reserves the `--version`
flag.)

## How it reaches nodes
- **Fresh install:** `…/bootstrap/binary` (and `install.sh`) serve from XConnect's
  `--bootstrap-bin-dir` (the `dist/` you built). The served binary must be keyed,
  or the node can't later self-update — `build.sh` guarantees it.
- **Self-update:** XConnect checks a connected node's version against its channel
  target on connect (and the operator can force it with `/update?node=`); if
  behind, it relays the **signed** binary down the tunnel. The node verifies the
  signature against its baked pubkey → `--selftest` → atomic swap → re-exec, with
  keep-previous + watchdog auto-rollback.

## Gotchas
- **Never hand-roll `go build` for a release.** Use `build.sh` — the inline
  `-ldflags` approach is how the empty-pubkey (un-updatable) binary shipped.
- **A keyless binary can't be fixed by self-update** (it can't verify the update).
  Recovery is out-of-band: re-fetch a keyed binary (e.g. over the fabric:
  `remote_run` a `curl …/bootstrap/binary` + service restart) — see history.
- **Cross-arch:** `build.sh` cross-compiles (pure Go, `CGO_ENABLED=0`), so one
  build host produces every target. No need for Go on the runtime VMs.
- **Windows**: the lab build uses a LocalSystem service, PowerShell 5.1, software
  CNG keys, and Windows Job Objects. See WINDOWS.md. Automatic self-update is
  explicitly unsupported; do not promote Windows builds to Linux channels.
- Set `RCON_BUILD_DIR` to an isolated output directory for regression builds
  without replacing bootstrap artifacts. macOS is not implemented.
