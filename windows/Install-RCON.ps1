#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$XConnect,
    [string]$Broker = '',
    [string]$Name = $env:COMPUTERNAME,
    [string]$CAPin = ''
)
$ErrorActionPreference = 'Stop'
$binary = Join-Path $PSScriptRoot 'rcon.exe'
if (-not (Test-Path -LiteralPath $binary)) { throw "Missing $binary; extract the complete ZIP first." }
$secureToken = Read-Host 'Orthanc join token' -AsSecureString
$tokenPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
try {
    $env:RCON_JOIN_TOKEN = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($tokenPointer)
    $rconArguments = @('install', '--xconnect', $XConnect, '--name', $Name)
    if ($Broker) { $rconArguments += @('--broker', $Broker) }
    if ($CAPin) { $rconArguments += @('--ca-pin', $CAPin) }
    & $binary @rconArguments
    if ($LASTEXITCODE -ne 0) { throw "RCON installation failed (exit $LASTEXITCODE). See the message above." }
} finally {
    Remove-Item Env:RCON_JOIN_TOKEN -ErrorAction SilentlyContinue
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($tokenPointer)
    $secureToken.Dispose()
}
Get-Service -Name Pow3rToolRCON
