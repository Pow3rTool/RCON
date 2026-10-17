# Windows build

First target: **64-bit Windows 10 / Windows Server 2016 or newer** with built-in
Windows PowerShell 5.1. No Go, Python, domain join, TPM, Intune, or inbound WinRM
port is required: standalone machines are the expected case. This is still a lab
preview, not a production-qualified Windows release.

## Install

1. Build from reviewed source following [BUILD.md](BUILD.md). Apply your
   organization's signing policy internally; no public binaries are distributed.
2. Copy `rcon.exe` to the machine and either:
   - **double-click it.** It asks for Administrator rights, then prompts for the
     XConnect URL, node name, optional CA pin, and the join token (typed with echo
     off); or
   - from an **elevated** PowerShell prompt run
     `.\rcon.exe install --xconnect https://YOUR-XCONNECT-HOST --name YOUR-VM-NAME`.
     It prompts for the join token with echo off. `Install-RCON.ps1` wraps the
     same command.
3. Approve the pending node in Orthanc and grant the intended operator access.
   The service starts immediately and waits for approval in the background.

If you built the native test executable, you can run it first:
`& .\rcon-tests.exe '-test.v' '-test.timeout=90s'`.

HTTPS bootstrap verification is on. If the broker is not the bootstrap hostname
on TCP port 3, pass `--broker HOST:PORT`. The machine must be able to reach both.
Install an internal HTTPS CA in the machine trust store before enrollment.
HTTP, `--insecure`, and bootstrap redirects are refused before forwarding a token.
Use `--ca-pin sha256:...` for an additional out-of-band enrollment trust check.
There is no need to disable antivirus or change firewall policy for the installer.

## Layout

RCON owns one fixed tree. It does not use Program Files, ProgramData, known-folder
lookups, or environment variables to find its files.

| Path | Contents |
| --- | --- |
| `C:\RCON\releases\<version>\rcon.exe` | Installed releases; the service runs one of them |
| `C:\RCON\etc\` | Device certificate, trust bundle, `service.json` |
| `C:\RCON\logs\` | `service.log`, `audit.log` (hash-chained), `upgrade.log` |
| `C:\RCON\state\` | Upgrade lock and journal, health marker, last upgrade result |

- Every directory is created with a **protected** DACL: SYSTEM and Administrators
  only, nothing inherited. A folder created under `C:\` the ordinary way inherits
  modify rights for Authenticated Users, which would let any signed-in user replace
  a binary that runs as SYSTEM. Don't create `C:\RCON` by hand: an existing
  `C:\RCON` owned by a normal user or granting anyone else access is refused.
- Reparse points, hard-linked files, and foreign owners anywhere in the tree are
  refused, never repaired silently.
- Service: `Pow3rToolRCON`, delayed automatic start, **LocalSystem**.
- Private device key: non-exportable, machine-scoped P-256 key in the Microsoft
  Software Key Storage Provider (CNG), accessible to SYSTEM/local Administrators.
  No private-key PEM. The **public** certificate and pinned CA bundle remain PEM
  files for protocol compatibility; Windows root trust does not replace RCON's
  broker CA/SPIFFE validation.
- The CNG key's name is pinned in `service.json` (`key_name`), so the identity
  directory can move without orphaning the key. Copying the directory to another
  computer does not copy the key.
- Persisted CNG keys are checked on reuse for trusted ownership, private ACLs,
  and non-exportability. An unsafe existing key is rejected, never repaired
  silently or replaced with a new identity.
- A pending enrollment is resumed after a service restart without generating a
  new device key. Do not clone an already-enrolled VM as another node.

Useful commands:

```powershell
Get-Service Pow3rToolRCON
Get-Content 'C:\RCON\logs\service.log' -Tail 60
Get-Content 'C:\RCON\logs\upgrade.log' -Tail 60
Restart-Service Pow3rToolRCON
```

## Remote commands

Use **PowerShell 5.1**, not Bash or PowerShell 7 syntax:

```powershell
whoami
Get-Service | Select-Object -First 10 Name,Status
Get-WinEvent -LogName System -MaxEvents 10 | Format-List
Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber
```

No profile or interactive desktop is loaded. `&&` is not a PowerShell 5.1 operator.
Text is returned as UTF-8; native console programs can have their own encodings.
Run/jobs have bounded output. Windows Job Objects cancel descendants as well as
the shell. Jobs survive tunnel disconnects, **not service restarts/reboots**.
Session working-directory snapshots are supported for filesystem locations.

No run-as, token impersonation, domain integration, or GUI automation is included.
This is still unrestricted local administration, not a sandbox: SYSTEM commands
can access the network and can perform anything their OS identity permits.

## Upgrades

Windows nodes upgrade through the same signed release channel as Linux, published
per OS (`publish_release ... --os windows`, `promote_release ... --os windows`; see
BUILD.md). XConnect offers the channel target when a node connects and when an
operator requests an update in Orthanc. **No reboot is involved**: the service
restarts, and the node is offline for a few seconds.

RCON never overwrites the executable it is running from:

1. **Verify.** The release must match this node's OS/architecture, its content
   hash, and the Ed25519 signature over `version|goos|goarch|sha256` against the
   release key baked into the running build. XConnect is only a relay.
2. **Stage.** The binary and its signed manifest go to
   `C:\RCON\releases\<version>\`, and the candidate must pass `--selftest`
   before anything else happens. The self-test runs the service's own startup
   steps (configuration, protected directories, log file), loads the identity,
   and reaches the broker, so the running release never hands off to a candidate
   that can't start on this node.
3. **Drain.** Everything that changes the node (`run`, `jobs`, file writes and
   edits, certificate renewal) gets a retryable HTTP 503, and the upgrade waits
   for the requests already admitted. File writes are made in place, so the
   service is never stopped mid-write. Reads stay available. If the node is still
   busy after 30 minutes, the upgrade is deferred: the release stays staged and
   is offered again on the next reconnect or operator update request.
4. **Hand off.** The running release starts a detached `rcon.exe swap` from its
   own, known-good binary. The swapper takes the upgrade lock, refuses to run if
   it would die with the service, and re-verifies the staged binary's signature.
5. **Switch.** Before changing anything, the swapper writes a pending-upgrade
   journal. It points the service at the new release while the old one is still
   running, then terminates the drained service process. Service recovery
   restarts the service with the new command, so the service comes back even if
   the swapper dies at that moment. Windows logs this as an unexpected
   termination; that is expected during an upgrade.
6. **Commit or roll back.** The new release's service process must report a
   healthy broker tunnel within 2 minutes. Otherwise the swapper marks the
   journal as rolling back, records the failure, points the service back at the
   previous release, and restarts into it. The failure is recorded before the
   previous release runs again, so the same release can't be re-offered in
   between. The journal stays until the previous release is running and has
   settled it.

If the swapper dies or the machine reboots part-way, whichever release starts
next finishes the job from the journal:
- **The new release** runs its recovery step first, before configuration or
  logging, so a start that fails anywhere is still counted. It gives itself the
  same health window, then commits or rolls itself back. A rollback already
  under way, or a crash loop (a fourth start without settling), rolls back
  immediately.
- **The previous release** makes sure the service still points at itself and
  drops the journal. If the new release had run and failed, it first makes sure
  that release stays blocked; otherwise the interruption is recorded and the
  upgrade can be offered again.

A recovery step that fails (the service manager unreachable, a state file that
can't be written) leaves the journal in place and is retried. A journal whose
service commands don't run RCON's own release executables is never applied to
the service; it is reported and left for an operator. While a journal exists,
the node reports it as `pending_upgrade` in `/health` and refuses new upgrades.

Upgrades rely on the service's recovery settings (restart after any failure),
which install and every upgrade set. Don't remove them. Only one upgrade runs at
a time: the lock is `C:\RCON\state\upgrade.lock`, which only SYSTEM and
Administrators can open.

The outcome is recorded in `C:\RCON\state\upgrade-result.json`, reported as
`last_upgrade` in the node's `/health`, and logged in `C:\RCON\logs\upgrade.log`.
A version that failed its health check and was rolled back is **not retried
automatically**, so a bad release can't flap on every reconnect. Publish a newer
release, or delete `upgrade-result.json` to allow the same version again. The
three most recent releases are kept; older release directories are pruned.

Manual fallback, if a node can't reach the release channel: copy the new
`rcon.exe` to `C:\RCON\releases\<version>\` from an elevated prompt, then

```powershell
Stop-Service Pow3rToolRCON
sc.exe config Pow3rToolRCON binPath= '"C:\RCON\releases\<version>\rcon.exe" service --etc C:\RCON\etc'
Start-Service Pow3rToolRCON
```

## Uninstall / reinstall

```powershell
& 'C:\RCON\releases\<version>\rcon.exe' uninstall
```

Uninstall stops/removes the Windows service and clears any retained join token.
Releases, identity, CNG key, remaining config, and logs under `C:\RCON` are kept
for recovery. A token-cleanup failure prevents service deletion and reports an
error. Revoke the node in Orthanc when retiring it. To reattach an already
approved installation without re-enrollment:

```powershell
New-Service -Name Pow3rToolRCON -DisplayName 'Pow3rTool RCON' -StartupType Automatic -BinaryPathName '"C:\RCON\releases\<version>\rcon.exe" service --etc C:\RCON\etc'
Start-Service Pow3rToolRCON
```

For an unapproved installation, supply a valid join token in the protected
configuration before reattaching.

## Moving from the preview layout

Preview builds installed to `C:\Program Files\Pow3rTool\RCON` with data in
`C:\ProgramData\Pow3rTool\RCON`, and they cannot upgrade themselves. A node can
move to the new layout **keeping its identity** (no re-enrollment, no Orthanc
approval), from an elevated prompt:

1. Create `C:\RCON` with RCON's protected ACL (not with Explorer or `mkdir`, which
   inherit modify rights for all signed-in users from `C:\`), and put the new
   build in `C:\RCON\releases\<version>\rcon.exe`:

   ```powershell
   $sec = New-Object System.Security.AccessControl.DirectorySecurity
   $sec.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
   [void][System.IO.Directory]::CreateDirectory('C:\RCON', $sec)
   ```
2. Point the service at the new build, still using the old identity directory,
   and turn on restart-after-any-failure:

   ```powershell
   Stop-Service Pow3rToolRCON
   Get-CimInstance Win32_Service -Filter "Name='Pow3rToolRCON'" | Invoke-CimMethod -MethodName Change -Arguments @{ PathName = '"C:\RCON\releases\<version>\rcon.exe" service --etc C:\ProgramData\Pow3rTool\RCON' }
   sc.exe failure Pow3rToolRCON reset= 86400 actions= restart/10000
   sc.exe failureflag Pow3rToolRCON 1
   Start-Service Pow3rToolRCON
   ```
   If it doesn't connect, point the service back at the preview binary.
3. Adopt the identity into `C:\RCON\etc`:
   `& 'C:\RCON\releases\<version>\rcon.exe' adopt-identity --from C:\ProgramData\Pow3rTool\RCON`.
   The device key is non-exportable and can't be copied or renamed, so its name is
   pinned in the new `service.json` instead. The command refuses to finish unless
   the copy loads the same certificate and key, and it doesn't touch the service.
4. Point the service at `--etc C:\RCON\etc` and restart it. Check
   `C:\RCON\logs\service.log` shows the same node identity with the tunnel up.
5. Delete `C:\Program Files\Pow3rTool` and `C:\ProgramData\Pow3rTool`. Keep the
   machine key (`Pow3rTool-RCON-<hash>`): the node still uses it. The preview left
   no other registry entries besides the service itself.

Re-enrolling instead (uninstall, revoke the old node, fresh install with a new
join token) also works if you want a new identity.

## Known preview limits

- Native service/CNG/upgrade behavior must be exercised on Windows; Linux
  cross-compiling alone is not proof of a successful Windows installation. Include
  test output, `service.log` and `upgrade.log` when reporting problems.
- POSIX owner/group/mode changes fail explicitly without writing file content.
  Use explicit Windows ACL commands instead.
- File read/edit/write are UTF-8/text oriented. Use PowerShell for UTF-16 or
  application-specific encoding; edits to NUL-containing files are refused.
- File primitives accept ordinary files on local drives. UNC paths, mapped
  network drives, device names, alternate data streams, absolute symlinks and
  junctions are refused. Relative links staying within the drive are supported.
  Use an explicitly authorized PowerShell command for network-file operations.
- Reads and hash checks are bounded at 10 MB. Edit/write keep the checked file
  handle through modification; the hash guard is optimistic concurrency, not a
  lock against other processes changing the same open file.
- Service, upgrade, and audit logs do not rotate; monitor `C:\RCON\logs`.
  Desktop diagnostics rotate separately as described below.


## Native desktop operations

Windows RCON advertises `capabilities.desktop=true` and handles `POST /desktop`
on its existing authenticated reverse tunnel. XConnect requires the existing
`full` grant for observation and input. Its MCP tools require an explicit node;
`session_id` is optional for observation/tasks when exactly one logged-on session
is active. A node running an older RCON receives an upgrade-required response.
No desktop-specific Orthanc grant or per-host allow-list is used.

The service launches the same executable with the private `desktop-worker`
subcommand in the selected session, using a duplicated SYSTEM token. The worker
is suspended until assigned to a kill-on-close Job Object. A random local named
pipe permits SYSTEM only, rejects remote clients, and verifies both process IDs.
Each worker receives a minimal environment. Capture/input workers perform one
operation and exit; the activity-indicator worker lives for a bounded idle lease.
There is no PowerShell helper, scheduled task, copied executable, or GUI TCP port.
The service installation's protected ACLs are unchanged. The worker remains
SYSTEM, so these tools require full machine authority, not a restricted GUI grant.

During desktop operations, a native click-through, non-activating overlay draws a
2-DIP purple (#b388ff) border around each monitor and a top-right RCON status badge.
The badge distinguishes AI viewing, AI controlling, AI thinking, AI idle, and AI interrupted. It is advisory,
not proof of application success or a security boundary. It expires after 30
seconds without another operation; the worker independently expires after 35
seconds, and service termination closes its kill-on-close job. Session/logon,
lock, and display changes are checked while it is visible. Only the interrupted badge accepts a local click to resume; it has no separate
network endpoint. If the indicator cannot be shown, the operation is
refused. Windows capture exclusion keeps the overlay out of the model's frames;
it does not flash off around each screenshot. The overlay is also omitted from
window metadata. The public desktop capability reports `visual_indicator=true`.

Capture uses GDI and returns a bounded JPEG plus physical desktop geometry,
window rectangles, DPI, and cursor metadata. Coordinates for input use the image
pixels in that exact frame. Each gesture releases its own keys/buttons before
returning. The native endpoint validates the action independently of XConnect.
A screenshot taken during foreground changes remains available for inspection
with `actionable=false`; it cannot authorize gestures. Frames expire after 180 seconds and bind to the session's logon identity, screen
geometry, and foreground window. The last-input tick is diagnostic-only; RDP
key-state synchronization can advance it without a meaningful action. Input consumes the frame before
dispatch, including uncertain outcomes; changed or consumed frames require a new
observation. Screenshots and typed text are omitted from node audit records.

The frame guard proves only that focus did not move since the frame. A gesture
may also carry `expect_foreground` (`class`, exact; `title`, substring; both
case-insensitive), checked against the live foreground immediately before
SendInput. A mismatch is refused with `input_status: not_sent`; the error names
the window class but not its title, which stays out of the node log. Use it for
keys or text that follow a window-opening step (WIN+R → class `#32770`, title
`Run`), where the previous step's result becomes the next frame's baseline.
Nodes that support it report `foreground_expectation=true`.

Keyboard events carry the scan code a physical keyboard would send (mapped
through the foreground thread's layout), not only the virtual key; apps that
identify keys physically, such as winit-based UIs, ignore scan code 0. Nodes
report `key_scan_codes=true`. The window list omits DWM-cloaked windows (hidden
Store apps such as Settings or the Text Input Application), and minimized windows
are listed by identity only, without their off-screen rectangles.

An existing unlocked and rendered Windows desktop is required. This capability
does not log in, unlock, or accept UAC prompts.

When no desktop can be observed or driven, the failure carries `desktop_state`,
a one-line `remedy`, and every logged-on session with its user, station, state
and whether it is on the console. Measured on Windows 10 (October 2026):

- `rdp_display_suppressed`: the session is Active over RDP but its client is
  minimized. The client asks the server to stop sending output, and Windows then
  has no foreground window and refuses screen capture even to the user's own
  programs. Setting `RemoteDesktop_SuppressWhenMinimized=2` (DWORD, under
  `HKCU\Software\Microsoft\Terminal Server Client`) on the client machine keeps
  it rendering while minimized.
- `session_disconnected`: the RDP client was closed without signing out. The
  session keeps running but has no input desktop or display.
- `locked_or_secure_desktop`, `no_user_session`, `session_ambiguous`,
  `session_not_found`, `session_not_active`, `no_foreground` cover the rest.

`attach_console` (MCP `desktop_attach_console`) is the `tscon <id> /dest:console`
primitive, through `WTSConnectSession` as LocalSystem. It moves the same logon
session, with the same user and running programs, onto the console display,
which renders without any client; a later RDP connection takes it back.
Without `force` it refuses a session still connected over RDP and a console
already showing another user's active session; `force` disconnects that client or
user. A durable pause blocks it like input. The result is a fresh observation of
the attached session at the console's resolution. The node audit records each
attach with the session's previous state and station.
An RDP session can report Active while its display is unusable; restore its viewer
or deliberately transfer it to the local console. Session 0 is never selected.
Multiple active sessions require an explicit selection. A sent receipt confirms
input dispatch, not application success. Observe after timeouts before deciding
whether to retry; restarting the service invalidates all previous frames.

Native integration tests opt in with `RCON_TEST_DESKTOP=1`. Run the test binary as
SYSTEM outside a session-0 command Job Object: Windows forbids cross-session
children inside that inherited job. The test captures and sends a reversible
cursor gesture, then verifies duplicate-request and consumed-frame refusal.
`RCON_TEST_DESKTOP_OUTPUT` optionally writes the JPEG to a protected local file.
Temporary task scheduling may be used to launch the test harness; product runtime
uses only the native worker and never Task Scheduler.

The opt-in test executable also supports `indicator-fixture OUTPUT_DIRECTORY`,
run as the logged-on user on a rendered desktop. It compares application pixels
before and during capture exclusion, temporarily includes the overlay to save a
visual preview, and checks that showing it did not change focus. This command
exists only in the test binary, not the shipped RCON executable.


## Interactive desktop input (held-v1)

Upgraded Windows nodes advertise `interaction_protocol: held-v1`. XConnect's
`desktop_interact` exposes a caller-owned interaction with a 60-second default
lease (1–60 seconds configurable per call) and a five-minute absolute lifetime.
Ordinary `desktop_act`/`desktop_task` still release all input within each gesture.

Begin with a fresh ordinary `desktop_observe` frame. Send a bounded list of
`key_down`, `key_up`, `key_press`, `button_down`, `button_up`, `move`, `wait`, or
`capture` events. Keys are individual names; use separate events for modifiers.
For KiCad's preset switcher: `key_down CTRL`, `key_press TAB`, `wait 200`; inspect
the returned menu while Ctrl stays held. Continue with the returned interaction
ID and final frame ID, or release to commit the selection. Cancellation releases
owned input too; application key-up behavior still applies.

Timed moves accept 1–4 intermediate samples. Each response has at most six JPEGs
including the final checkpoint, under 3.6 MB decoded in total. Images carry
elapsed time, cursor, held-input, and phase metadata. Only the final checkpoint
can authorize another action; intermediate frames are inspection-only. Capture
cost can lengthen gestures; this is sampled feedback, not a real-time video loop.

The purple indicator displays **AI controlling** during events and **AI thinking**
while waiting for the next model decision, then **AI idle** after release. It
remains excluded from screenshots and does not steal focus. Normal activity
badges are click-through. Outside Escape latches **AI interrupted · click to
resume**; that badge alone becomes clickable. Held input is released, and new
input requests remain blocked until a local badge click clears the protected
`state/desktop-paused.json` record. The pause survives service restarts.
Observations and cleanup remain available; remote retries cannot resume it.

The same RCON executable hosts a session-bound interaction worker. A private
SYSTEM-only pipe with mutual PID checks carries bounded requests. Unlike ordinary
short-lived workers, its job does not kill it when the service disappears: pipe
EOF lets it send key-up/button-up before exiting. It also independently enforces
its lease and lifetime. A stopped process cannot itself run cleanup; a hard worker
crash or hung Windows input subsystem still requires operator recovery.

Marked SendInput events and a low-level keyboard hook distinguish RCON Escape
from outside Escape. Three distinct outside Escape presses within 1.5 seconds pause control; mouse activity,
other keys, redundant releases, timestamp changes, and image animation do not.
Secure desktop/session/geometry changes or unexpected
foreground changes between decisions end the interaction and release held input.
Authorization and ownership are checked on each broker call. Expired, consumed,
and non-final checkpoints cannot be used to continue. After an uncertain result,
release or allow the lease to expire, then observe; never replay events blindly.

Validation: `RCON_TEST_INTERACTION=1` opts into TestDesktopInteractionLifecycle
on an active rendered session, launched as SYSTEM outside a containing job. It
holds only CTRL, checks stale-frame/timeout/pipe-loss cleanup, and samples a
reversible pointer move. The regular native suite skips live input by default.


The native service now supervises a passive keyboard watcher in each active logon
session. Triple Escape also works while idle, after the purple indicator hides,
and across desktop calls. A held Escape key's autorepeat and RCON-tagged Escape
never count as taps. No keyboard text is collected or stored. Logoff stops that
session's watcher; a new logon starts another. This does not log in or unlock Windows.
The durable pause is independent of gesture leases. A local badge click clears it;
resume requires a new observation and new interaction, never replaying held input.
Pause/resume transitions are recorded in logs/desktop-pause.jsonl without pixels.
AI thinking shows the seconds until owned input releases (maximum 60 seconds per
checkpoint, five minutes per interaction). AI waiting shows the 30-second inactivity window until the indicator
hides; it does not assert whether the model has finished thinking. The paused badge has no timeout. The listener remains armed after idle hides.

Clearing the local pause hides the indicator immediately; it does not fabricate a
new waiting period or resume an ended gesture. A later desktop call shows activity
again. The paused badge uses the standard hand pointer; private worker startup
suppresses Windows app-starting cursor feedback. The Escape watcher stays armed.

Client diagnostics are local to `logs/desktop-pause.jsonl`, with two rotated files
and a 1 MiB target per file. They include each distinct outside Escape tap (burst
count, whether a pause was requested, pause state when logged), watcher lifecycle,
pause IDs, banner clicks with elapsed pause time, and desktop-call receipts.
Hooks enqueue bounded diagnostic records without doing file IO. Logs never include
other key values, typed text, input event arrays, or screenshot bytes.

### Purple AI pointer

The native indicator also visualizes RCON's own tagged mouse events: a purple
arrow at the injected position, expanding button-down rings, a short fading
movement trail, and L/R/M markers while those buttons are held. It is automatic
for both ordinary gestures and held interactions; no extra MCP calls are needed.
The pointer fades after 1.8 seconds without mouse activity, but remains visible
while a button is held. Pausing or dismissing the indicator clears it. It does
not follow human mouse input and does not replace the application's real cursor.

Rendering uses the same nonactivating, click-through, capture-excluded window as
the border. Model frames retain unobscured application pixels and ordinary cursor
metadata. Native event positions are mapped per monitor, including negative
desktop origins and per-monitor DPI. A dedicated mouse-hook thread keeps capture
and drawing work out of the hook. Its bounded history is RAM-only. Failure to
install this advisory visual hook is logged as pointer-monitor-unavailable and
does not change the existing mandatory activity-banner or input safety rules.

The opt-in test executable supports `pointer-fixture OUTPUT_DIRECTORY`. It draws
a temporary inert canvas, sends test input only onto that canvas, verifies tagged
input tracking/click-through/held state/pause cleanup and capture exclusion, saves
preview evidence, and restores the original pointer position. It requires a
rendered logged-on desktop and is not part of unattended regression tests.
