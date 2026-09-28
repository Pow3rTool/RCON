# RCON — Resident AIgent (fastpath execution)

The agent that runs on every managed host. Holds **only its own device key** — no
cluster/DB creds, nothing reusable elsewhere. Exposes a small, structured,
bounded set of admin primitives designed to be driven by non-human operators
(LLM agents), modelled on a coding agent's own toolset.

RCON dials *out* to **XConnect** over mutually-pinned mTLS and serves channels
back down the tunnel (the Go agent does this today; the Python `reference/`
listens directly, pre-broker).

## Tool surface
`run` · `jobs` · `read` · `edit` · `write` (+ `stream`/`tail`, and
`list_remote_hosts`/`whoami` on the Caller/MCP side).
Live in Go today: **`run`** (one-shot, bounded) and **`jobs`** (long-running,
reattachable). `read`/`edit`/`write` return `501` — spec is `reference/`.

## Safety contracts
- **read-before-edit hash guard** — edit/write require the hash from a prior read; rejected if the file changed since (optimistic concurrency, safe across concurrent agents/humans)
- **explicit write metadata** — `write` optionally accepts `owner` (local name or UID),
  `group` (local name or GID), and an octal permission `mode`; all are resolved before
  content changes, special mode bits are refused, and the response reports the
  resulting numeric ownership and mode
- **output caps at every layer** — a 100MB log can't tank the caller
- **orphan-process reap** — each call runs in its own process group, swept after completion (`sleep 1000 &` can't outlive the RPC)
- **token scrubbed from child env** — a `run` can't echo the device token back out
- **stateless one-shots + cheap cwd-snapshot sessions** — `cd` persists per session without holding a shell process

## Go agent (the product)
`main.go` + `jobs.go` are the real agent. It mutually-pins (verifies the broker
is a `system/xconnect` of *its* tenant, anchored to the pinned CA — system trust
store ignored), reverse-dials XConnect's broker (`tcp/3`), then runs
`http2.Server.ServeConn` to *become* the HTTP/2 server back down the tunnel:

- **`/health`**, **`/run`** — real `bash -lc`, 1 MB output cap.
- **`/jobs`** — long-running work in its own **process group**; merged output
  buffered to a cursor; `GET /jobs/{id}?from=` reattaches with no loss/dupe across
  a tunnel blip; `POST /jobs/{id}/cancel` kills the group (SIGTERM→SIGKILL).
- **Resilience:** HTTP/2 PING keepalives (stall detection ~30s) + full-jitter
  reconnect; a tunnel drop never kills a running job, only an explicit cancel does.

Identity (device-cert/key + trust-bundle) lives in `etc/`. Build:
`/usr/local/go/bin/go build -o rcon .`; runs as `rcon.service`. **Static, zero-dep,
cross-compiles** — `linux/amd64` and `linux/arm64` verified
(`CGO_ENABLED=0 GOOS=… GOARCH=… go build`). Proven end-to-end: the full turnstone
→ OBO → XConnect → RCON chain executes here.

**Next:** `read`/`edit`/`write` (read-before-write hash guard) to the
`reference/exec_daemon.py` contract, with `smoke_test.py` as the conformance
suite; then the **fleet bootstrap** (`rcon enroll` self-registration + poll-for-
approval) and **signed self-update**. See [`../ARCHITECTURE.md`](../ARCHITECTURE.md).

## `reference/` — Python spec, **NOT deployed**
> ⚠️ **Spec only. Do not wire these into a live config.** (`remote_shell_mcp.py`
> once got attached to a running turnstone and caused confusion — it is a
> reference, not a component.) Nothing runs from here; it's the precise contract
> the Go agent is built against, kept until the file verbs are ported.

| File | Role |
|------|------|
| `exec_daemon.py` | the agent contract (HTTP/JSON + SSE): `run`/`read`/`edit`/`write`, hash-guard, sessions/cwd, byte caps |
| `remote_shell_mcp.py` | the original MCP client that drove it |
| `smoke_test.py` | **conformance suite** — to run against the Go agent |

See [`../ARCHITECTURE.md`](../ARCHITECTURE.md) for the full fabric design.

## Local identity path

Linux defaults to `/etc/rcon`. Existing installations using a different location
must retain their explicit `--etc` argument when upgrading. Windows uses its
protected ProgramData directory; see [WINDOWS.md](WINDOWS.md).
