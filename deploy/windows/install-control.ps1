<#
.SYNOPSIS
  Installs the hostwatch control daemon as the hostwatch-control service.

.DESCRIPTION
  This is separate from the collector's install.ps1. It creates its own virtual environment, installs
  this checkout with the windows and control extras, writes control.env with an ACL limited to SYSTEM
  and Administrators, locks control.toml the same way, registers the service as LocalSystem with
  restart-on-failure recovery, and starts it.

  control.toml (the local allowlist and the pinned watchpost public key) must already exist in the
  data folder or be given with -ConfigFile. The daemon refuses to start without it.

  Run from an elevated PowerShell. Nothing changes until you answer the confirmation; use -DryRun
  to see the steps without changing anything, or -Force to skip the question.

  The control key is read as a secure string (prompted when -ControlKey is not given) and is written
  only to the protected settings file. It is never printed, logged or placed on a command line.

.EXAMPLE
  .\install-control.ps1 -WatchpostUrl https://watchpost.example.lan:8443 -DryRun
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$WatchpostUrl,
    [securestring]$ControlKey,
    [string]$ConfigFile,
    [string]$SourcePath = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'hostwatch'),
    [string]$DataDir = (Join-Path $env:ProgramData 'hostwatch'),
    [string]$Python = 'python',
    [switch]$DryRun,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$ServiceName = 'hostwatch-control'
$Venv = Join-Path $InstallDir 'control-venv'
$VenvPython = Join-Path $Venv 'Scripts\python.exe'
$EnvFile = Join-Path $DataDir 'control.env'
$ConfigPath = Join-Path $DataDir 'control.toml'
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
if ($WatchpostUrl -notmatch '^https?://') { throw 'WatchpostUrl must start with http:// or https://.' }
if (-not (Test-Path (Join-Path $SourcePath 'pyproject.toml'))) { throw "No pyproject.toml under $SourcePath." }
if (-not $ConfigFile -and -not (Test-Path $ConfigPath)) {
    throw "No control.toml in $DataDir. Create it first, or pass -ConfigFile."
}

Write-Host 'This will:'
Write-Host "  - create a virtual environment in $Venv and install hostwatch with the windows and control extras"
Write-Host "  - write $EnvFile and lock $ConfigPath so only SYSTEM and Administrators can read or change them"
Write-Host "  - leave the ACL of $DataDir alone if it already exists (it is shared with the agent); lock it only when this script creates it"
Write-Host "  - register the $ServiceName service as LocalSystem, start it on boot, and restart it after a failure"
Write-Host "  - let $WatchpostUrl ask this host to run actions that control.toml allows"
if ($DryRun) { Write-Host 'Dry run: nothing was changed.'; return }
if (-not $Force) {
    $answer = Read-Host 'Type yes to continue'
    if ($answer -ne 'yes') { Write-Host 'Cancelled. Nothing was changed.'; return }
}

if (-not $ControlKey) { $ControlKey = Read-Host -AsSecureString 'Control key (wpc_) for this host' }

Step 'Creating the virtual environment'
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Invoke-Native $Python @('-m', 'venv', $Venv)
Invoke-Native $VenvPython @('-m', 'pip', 'install', '--upgrade', 'pip')
Invoke-Native $VenvPython @('-m', 'pip', 'install', "$SourcePath[windows,control]")
Invoke-Native $VenvPython @((Join-Path $Venv 'Scripts\pywin32_postinstall.py'), '-install')

Step 'Locking the allowlist and writing the protected settings file'
$dataDirExisted = Test-Path -LiteralPath $DataDir
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
if ($dataDirExisted) {
    Write-Host "  $DataDir already exists and is shared with the agent, so its ACL is left as it is."
} else {
    Invoke-Native 'icacls.exe' @($DataDir, '/inheritance:r', '/grant:r', "${SidSystem}:(OI)(CI)F", "${SidAdmins}:(OI)(CI)F")
}
if ($ConfigFile) { Copy-Item -LiteralPath $ConfigFile -Destination $ConfigPath -Force }
Invoke-Native 'icacls.exe' @($ConfigPath, '/inheritance:r', '/grant:r', "${SidSystem}:F", "${SidAdmins}:F")
if (Test-Path $EnvFile) { Remove-Item -LiteralPath $EnvFile -Force }
New-Item -ItemType File -Path $EnvFile | Out-Null
Invoke-Native 'icacls.exe' @($EnvFile, '/inheritance:r', '/grant:r', "${SidSystem}:F", "${SidAdmins}:F")
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ControlKey)
try {
    $secret = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    if ($secret -notmatch '^wpc_') { throw 'The control key must start with wpc_.' }
    $lines = @(
        '# hostwatch control settings. Readable only by SYSTEM and Administrators.',
        "HOSTWATCH_CONTROL_URL=$WatchpostUrl",
        "HOSTWATCH_CONTROL_DATA_DIR=$DataDir",
        "HOSTWATCH_CONTROL_KEY=$secret"
    )
    [IO.File]::WriteAllText($EnvFile, (($lines -join "`n") + "`n"), (New-Object Text.UTF8Encoding($false)))
}
finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    Remove-Variable -Name secret, lines -ErrorAction SilentlyContinue
}

Step 'Registering the service'
Invoke-Native $VenvPython @('-m', 'hostwatch.control.service', '--startup', 'delayed', 'install')
Step 'Recording the data folder for the service'
# The service must know its data folder before it can find control.env, so the choice is stored as a
# service parameter that the service reads at start.
$ParamKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName\Parameters"
if (-not (Test-Path $ParamKey)) { New-Item -Path $ParamKey -Force | Out-Null }
Set-ItemProperty -Path $ParamKey -Name 'DataDir' -Value $DataDir -Type String
Invoke-Native 'sc.exe' @('config', $ServiceName, 'obj=', 'LocalSystem')
Invoke-Native 'sc.exe' @('failure', $ServiceName, 'reset=', '86400', 'actions=', 'restart/5000/restart/30000/restart/60000')
Invoke-Native 'sc.exe' @('failureflag', $ServiceName, '1')

Step 'Starting the service'
Start-Service -Name $ServiceName
Write-Host "Installed. Logs are in $(Join-Path $DataDir 'control.log'). Remove it with uninstall-control.ps1."
