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
# rcon.exe prompts for the join token itself with console echo off, so the
# token never reaches the command line, an environment variable, or history.
$rconArguments = @('install', '--xconnect', $XConnect, '--name', $Name)
if ($Broker) { $rconArguments += @('--broker', $Broker) }
if ($CAPin) { $rconArguments += @('--ca-pin', $CAPin) }
& $binary @rconArguments
if ($LASTEXITCODE -ne 0) { throw "RCON installation failed (exit $LASTEXITCODE). See the message above." }
Get-Service -Name Pow3rToolRCON
