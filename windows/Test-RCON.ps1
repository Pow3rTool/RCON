#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'rcon.exe') --version
if ($LASTEXITCODE -ne 0) { throw 'Executable did not start.' }
# Tests use temporary directories and a disposable CNG key, not the installed
# service's identity. They intentionally create/cancel harmless child processes.
& (Join-Path $PSScriptRoot 'rcon-tests.exe') '-test.v' '-test.timeout=90s'
if ($LASTEXITCODE -ne 0) { throw "Native Windows smoke tests failed (exit $LASTEXITCODE)." }
