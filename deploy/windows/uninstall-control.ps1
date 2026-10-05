<#
.SYNOPSIS
  Removes the hostwatch-control service and its virtual environment.

.DESCRIPTION
  Stops and deletes the service and deletes its virtual environment. The data folder is shared with the
  collector and holds the replay state, the unsent result outbox, the logs and the settings files, so it
  is not touched unless -RemoveControlData is given, which deletes only the control files in it.
  Run from an elevated PowerShell. Use -DryRun to see the steps, or -Force to skip the question.
#>
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'hostwatch'),
    [string]$DataDir = (Join-Path $env:ProgramData 'hostwatch'),
    [switch]$RemoveControlData,
    [switch]$DryRun,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$ServiceName = 'hostwatch-control'
$Venv = Join-Path $InstallDir 'control-venv'
$VenvPython = Join-Path $Venv 'Scripts\python.exe'
$ControlFiles = @('control.env', 'control.toml', 'control-state.json', 'control-outbox.db', 'control.log')

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $DryRun) { throw 'Run this script from an elevated PowerShell.' }

Write-Host 'This will:'
Write-Host "  - stop and delete the $ServiceName service"
Write-Host "  - delete the virtual environment in $Venv"
if ($RemoveControlData) { Write-Host "  - delete these files from ${DataDir}: $($ControlFiles -join ', ')" }
else { Write-Host "  - keep the control files in $DataDir (use -RemoveControlData to delete them)" }
if ($DryRun) { Write-Host 'Dry run: nothing was changed.'; return }
if (-not $Force) {
    $answer = Read-Host 'Type yes to continue'
    if ($answer -ne 'yes') { Write-Host 'Cancelled. Nothing was changed.'; return }
}

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Stop-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (Test-Path $VenvPython) {
        & $VenvPython -m hostwatch.control.service remove
    }
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        & sc.exe delete $ServiceName
    }
}
if (Test-Path $Venv) { Remove-Item -LiteralPath $Venv -Recurse -Force }
if ($RemoveControlData) {
    foreach ($name in $ControlFiles) {
        $path = Join-Path $DataDir $name
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
    }
}
Write-Host 'Removed.'
