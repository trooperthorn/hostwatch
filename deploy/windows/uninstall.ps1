<#
.SYNOPSIS
  Removes the hostwatch-agent service and its virtual environment.

.DESCRIPTION
  Stops and deletes the service and deletes the virtual environment. The data directory holds the
  outbox, the logs and the protected settings file, so it is kept unless -RemoveData is given.
  Run from an elevated PowerShell. Use -DryRun to see the steps, or -Force to skip the question.
#>
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'hostwatch'),
    [string]$DataDir = (Join-Path $env:ProgramData 'hostwatch'),
    [switch]$RemoveData,
    [switch]$DryRun,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$ServiceName = 'hostwatch-agent'
$Venv = Join-Path $InstallDir 'venv'
$VenvPython = Join-Path $Venv 'Scripts\python.exe'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $DryRun) { throw 'Run this script from an elevated PowerShell.' }

Write-Host 'This will:'
Write-Host "  - stop and delete the $ServiceName service"
Write-Host "  - delete the virtual environment in $Venv"
if ($RemoveData) { Write-Host "  - delete $DataDir, including the unsent outbox, the logs and the settings file" }
else { Write-Host "  - keep $DataDir (use -RemoveData to delete it)" }
if ($DryRun) { Write-Host 'Dry run: nothing was changed.'; return }
if (-not $Force) {
    $answer = Read-Host 'Type yes to continue'
    if ($answer -ne 'yes') { Write-Host 'Cancelled. Nothing was changed.'; return }
}

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    # A clean stop lets the agent flush its outbox before the service goes away.
    Stop-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (Test-Path $VenvPython) {
        & $VenvPython -m hostwatch.windows.service remove
    }
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        & sc.exe delete $ServiceName
    }
}
if (Test-Path $Venv) { Remove-Item -LiteralPath $Venv -Recurse -Force }
if ($RemoveData -and (Test-Path $DataDir)) { Remove-Item -LiteralPath $DataDir -Recurse -Force }
Write-Host 'Removed.'
