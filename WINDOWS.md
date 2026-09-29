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
- Log rotation is not implemented; monitor `C:\RCON\logs`.
