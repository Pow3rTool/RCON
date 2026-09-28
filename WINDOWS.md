# Windows lab build

First target: **64-bit Windows 10 / Windows Server 2016 or newer** with built-in
Windows PowerShell 5.1. No Go, Python, domain join, TPM, or inbound WinRM port is
required. This is a lab preview, not a production-qualified Windows release.

## Install

1. Build from reviewed source following [BUILD.md](BUILD.md). Apply your enterprise
   signing policy internally; no public binaries are distributed. Stage the
   executable and optional test tools in an Administrator-controlled directory.
2. Open **Windows PowerShell as Administrator**, then change to that folder.
3. If you built the native test executable, optionally run it first:

   `& .\rcon-tests.exe '-test.v' '-test.timeout=90s'`

4. Set the one-time join token without placing it in command history:

   ```powershell
   $token = Read-Host 'Orthanc join token' -AsSecureString
   $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($token)
   try {
       $env:RCON_JOIN_TOKEN = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
       .\rcon.exe install --xconnect https://YOUR-XCONNECT-HOST --name YOUR-VM-NAME
   } finally {
       Remove-Item Env:RCON_JOIN_TOKEN -ErrorAction SilentlyContinue
       [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
       $token.Dispose()
   }
   ```

   Or use `Install-RCON.ps1 -XConnect https://YOUR-XCONNECT-HOST -Name YOUR-VM-NAME`
   if your script-execution policy permits it. No execution-policy changes are
   needed to run the executable directly.

5. Approve the pending node in Orthanc and grant the intended operator access.
   The service starts immediately and waits for approval in the background.

HTTPS bootstrap verification is on. If the broker is not the bootstrap hostname
on TCP port 3, pass `--broker HOST:PORT`. The desktop must be able to reach both.
Install an internal HTTPS CA in the machine trust store before enrollment.
HTTP, `--insecure`, and bootstrap redirects are refused before forwarding a token.
Use `--ca-pin sha256:...` for an additional out-of-band enrollment trust check.
There is no need to disable antivirus or change firewall policy for the installer.

## Service and identity

- Service: `Pow3rToolRCON`, delayed automatic start, **LocalSystem**.
- Installed binary: `C:\Program Files\Pow3rTool\RCON\rcon.exe`.
- Data/logs: `C:\ProgramData\Pow3rTool\RCON\`.
- `service.log`: startup, enrollment, connection failures.
- `audit.log`: hash-chained local action log; request IDs correlate central audit.
- `service.json`: protected configuration; join token removed after enrollment.
- Private device key: non-exportable, machine-scoped P-256 key in the Microsoft
  Software Key Storage Provider (CNG), accessible to SYSTEM/local Administrators.
  No private-key PEM. The **public** certificate and pinned CA bundle remain PEM
  files for protocol compatibility; Windows root trust does not replace RCON's
  broker CA/SPIFFE validation.
- The CNG key name is derived from the absolute data-directory path. Keep that
  directory in place. Copying its files to another computer does not copy the key.
- Identity/program directories and their ancestors must have trusted owners.
  Reparse points, user-owned paths, writable ancestors, and publicly accessible
  identity files are refused. The installer does not take over unsafe paths.
  Investigate a refusal before moving the conflicting directory aside; if any
  existing identity material was exposed, revoke and re-enroll the node.
- Persisted CNG keys are checked on reuse for trusted ownership, private ACLs,
  and non-exportability. An unsafe existing key is rejected, never repaired
  silently or replaced with a new identity.
- A pending enrollment is resumed after a service restart without generating a
  new device key. Do not clone an already-enrolled VM as another node.

Useful commands:

```powershell
Get-Service Pow3rToolRCON
Get-Content 'C:\ProgramData\Pow3rTool\RCON\service.log' -Tail 60
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

## Upgrade / uninstall

Windows self-update is **disabled** and advertised as unsupported. Keep the
existing identity and manually replace the executable from an elevated prompt:

```powershell
Stop-Service Pow3rToolRCON
Copy-Item .\rcon.exe 'C:\Program Files\Pow3rTool\RCON\rcon.exe'
Start-Service Pow3rToolRCON
```

Uninstall using your internally built executable:

```powershell
.\rcon.exe uninstall
```

Uninstall stops/removes the Windows service and clears any retained join token
from its configured data directory. Binary, identity, CNG key, remaining config,
and logs are retained for recovery. A token-cleanup failure prevents service
deletion and reports an error. Revoke the node in Orthanc when retiring it.
To reattach an already approved installation without re-enrollment:

```powershell
New-Service -Name Pow3rToolRCON -DisplayName 'Pow3rTool RCON' -StartupType Automatic -BinaryPathName '"C:\Program Files\Pow3rTool\RCON\rcon.exe" service --etc "C:\ProgramData\Pow3rTool\RCON"'
Start-Service Pow3rToolRCON
```

For an unapproved installation, supply a valid join token in the protected
configuration before reattaching. Internal signing should precede checksum and
manifest generation. Do not promote a Windows build to a Linux release channel.

## Known preview limits

- Native service/CNG behavior must be exercised on Windows; Linux cross-compiling
  alone is not proof of a successful Windows installation. Include test output
  and service.log when reporting problems.
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
- No installer rollback or automatic executable upgrade yet.
- Log rotation is not implemented; monitor the lab data directory.
