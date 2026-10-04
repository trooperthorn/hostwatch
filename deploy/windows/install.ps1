<#
.SYNOPSIS
  Installs the hostwatch Windows agent as the hostwatch-agent service.

.DESCRIPTION
  Creates a virtual environment, installs this checkout with the windows extra, writes the agent
  settings file with an ACL limited to SYSTEM and Administrators, registers the service to run as
  LocalSystem with restart-on-failure recovery, and starts it.

  Run from an elevated PowerShell. Nothing changes until you answer the confirmation; use -DryRun
  to see the steps without changing anything, or -Force to skip the question.

  The ingest key is read as a secure string (prompted when -IngestKey is not given) and is written
  only to the protected settings file. It is never printed, logged or placed on a command line.

.EXAMPLE
  .\install.ps1 -HubUrl https://hub.example.lan:8090 -DryRun
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$HubUrl,
    [string]$HostName = $env:COMPUTERNAME,
    [securestring]$IngestKey,
    [string]$SourcePath = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'hostwatch'),
    [string]$DataDir = (Join-Path $env:ProgramData 'hostwatch'),
    [string]$Python = 'python',
    [switch]$DryRun,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$ServiceName = 'hostwatch-agent'
$Venv = Join-Path $InstallDir 'venv'
$VenvPython = Join-Path $Venv 'Scripts\python.exe'
$EnvFile = Join-Path $DataDir 'agent.env'
# Well-known SIDs, so the ACL does not depend on the Windows display language.
$SidSystem = '*S-1-5-18'
$SidAdmins = '*S-1-5-32-544'

function Step([string]$Message) { Write-Host "==> $Message" }

function Invoke-Native([string]$File, [string[]]$Arguments) {
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$File failed with exit code $LASTEXITCODE" }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $DryRun) { throw 'Run this script from an elevated PowerShell.' }
if ($HubUrl -notmatch '^https?://') { throw 'HubUrl must start with http:// or https://.' }
if ($HostName -notmatch '^[A-Za-z0-9._-]{1,64}$') { throw 'HostName may hold letters, digits, dots, dashes and underscores only.' }
if (-not (Test-Path (Join-Path $SourcePath 'pyproject.toml'))) { throw "No pyproject.toml under $SourcePath." }

Write-Host 'This will:'
Write-Host "  - create a virtual environment in $Venv and install hostwatch with the windows extra"
Write-Host "  - write $EnvFile readable only by SYSTEM and Administrators"
Write-Host "  - register the $ServiceName service as LocalSystem, start it on boot, and restart it after a failure"
Write-Host "  - send host health to $HubUrl as host $HostName"
if ($DryRun) { Write-Host 'Dry run: nothing was changed.'; return }
if (-not $Force) {
    $answer = Read-Host 'Type yes to continue'
    if ($answer -ne 'yes') { Write-Host 'Cancelled. Nothing was changed.'; return }
}

if (-not $IngestKey) { $IngestKey = Read-Host -AsSecureString 'Ingest key or token for this host' }

Step 'Creating the virtual environment'
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Invoke-Native $Python @('-m', 'venv', $Venv)
Invoke-Native $VenvPython @('-m', 'pip', 'install', '--upgrade', 'pip')
Invoke-Native $VenvPython @('-m', 'pip', 'install', "$SourcePath[windows]")
Invoke-Native $VenvPython @((Join-Path $Venv 'Scripts\pywin32_postinstall.py'), '-install')

Step 'Writing the protected settings file'
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
Invoke-Native 'icacls.exe' @($DataDir, '/inheritance:r', '/grant:r', "${SidSystem}:(OI)(CI)F", "${SidAdmins}:(OI)(CI)F")
if (Test-Path $EnvFile) { Remove-Item -LiteralPath $EnvFile -Force }
New-Item -ItemType File -Path $EnvFile | Out-Null
Invoke-Native 'icacls.exe' @($EnvFile, '/inheritance:r', '/grant:r', "${SidSystem}:F", "${SidAdmins}:F")
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($IngestKey)
try {
    $secret = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    $keyName = 'HOSTWATCH_INGEST_KEY'
    if ($secret -notmatch '^hw_') { $keyName = 'HOSTWATCH_INGEST_TOKEN' }
    $lines = @(
        '# hostwatch agent settings. Readable only by SYSTEM and Administrators.',
        'HOSTWATCH_ROLE=agent',
        "HOSTWATCH_HUB_URL=$HubUrl",
        "HOSTWATCH_HOST_NAME=$HostName",
        "HOSTWATCH_DATA_DIR=$DataDir",
        "$keyName=$secret"
    )
    [IO.File]::WriteAllText($EnvFile, (($lines -join "`n") + "`n"), (New-Object Text.UTF8Encoding($false)))
}
finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    Remove-Variable -Name secret, lines -ErrorAction SilentlyContinue
}

Step 'Registering the service'
Invoke-Native $VenvPython @('-m', 'hostwatch.windows.service', '--startup', 'delayed', 'install')
Invoke-Native 'sc.exe' @('config', $ServiceName, 'obj=', 'LocalSystem')
Invoke-Native 'sc.exe' @('failure', $ServiceName, 'reset=', '86400', 'actions=', 'restart/5000/restart/30000/restart/60000')
Invoke-Native 'sc.exe' @('failureflag', $ServiceName, '1')

Step 'Starting the service'
Start-Service -Name $ServiceName
Write-Host "Installed. Logs are in $(Join-Path $DataDir 'agent.log'). Remove it with uninstall.ps1."
