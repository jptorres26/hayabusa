<#
.SYNOPSIS
    Updates the detection rules, checking them before they go live.

.DESCRIPTION
    Fetches hayabusa-rules into a staging directory, scans it for rule features this engine does
    not implement, runs a scan against a known-good sample to prove the new set loads and detects,
    and only then swaps it in. The previous set is kept so a bad update can be rolled back in one
    move.

    Run it from a scheduled task; it is safe to run while the service is up (the swap is a
    directory rename, and a scan already in flight keeps the rules it loaded).

.PARAMETER RulesPath
    The live rules directory. Defaults to the installed one from the machine environment.

.PARAMETER Source
    The rules repository. Defaults to the upstream hayabusa-rules.

.PARAMETER Rollback
    Restore the previous rule set and exit.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string] $RulesPath = $env:HAYABUSA_PY_RULES_DIR,
    [string] $InstallPath = 'C:\Program Files\hayabusa-py',
    [string] $Source = 'https://github.com/Yamato-Security/hayabusa-rules.git',
    [string] $Ref = 'main',
    [switch] $Rollback
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $RulesPath) { $RulesPath = Join-Path $InstallPath 'rules' }
$previous = "$RulesPath.previous"
$staging = "$RulesPath.staging"
$python = Join-Path $InstallPath '.venv\Scripts\python.exe'

if ($Rollback) {
    if (-not (Test-Path $previous)) { throw "there is no previous rule set at $previous" }
    if ($PSCmdlet.ShouldProcess($RulesPath, 'roll back to the previous rule set')) {
        $discard = "$RulesPath.rolledback"
        if (Test-Path $discard) { Remove-Item $discard -Recurse -Force }
        if (Test-Path $RulesPath) { Move-Item $RulesPath $discard }
        Move-Item $previous $RulesPath
        Remove-Item $discard -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host 'rolled back.' -ForegroundColor Green
    }
    return
}

$git = Get-Command git -ErrorAction SilentlyContinue
if (-not $git) { throw 'git is not installed; it is needed to fetch the rules.' }

Write-Host "fetching $Source ($Ref) ..."
if (Test-Path $staging) { Remove-Item $staging -Recurse -Force }
if ($PSCmdlet.ShouldProcess($staging, 'clone the rules')) {
    & git clone --depth 1 --branch $Ref $Source $staging
    if ($LASTEXITCODE -ne 0) { throw "git clone failed with exit code $LASTEXITCODE" }
}

$commit = (& git -C $staging rev-parse --short HEAD).Trim()
Write-Host "fetched $commit"

Write-Host 'checking the new rules against the engine...'
if ($PSCmdlet.ShouldProcess($staging, 'load the rules and report what is unsupported')) {
    Push-Location $InstallPath
    try {
        & $python -m service.check_rules --rules $staging --config (Join-Path $InstallPath 'config')
        if ($LASTEXITCODE -ne 0) {
            throw "the new rule set did not pass its checks; it was NOT installed. Staging kept at $staging"
        }
    } finally {
        Pop-Location
    }
}

if ($PSCmdlet.ShouldProcess($RulesPath, 'swap in the new rule set')) {
    if (Test-Path $previous) { Remove-Item $previous -Recurse -Force }
    if (Test-Path $RulesPath) { Move-Item $RulesPath $previous }
    Move-Item $staging $RulesPath
    Set-Content -Path (Join-Path $RulesPath 'INSTALLED.txt') -Encoding utf8 -Value @(
        "source:    $Source"
        "ref:       $Ref"
        "commit:    $commit"
        "installed: $((Get-Date).ToUniversalTime().ToString('u'))"
    )
    Write-Host "installed rules $commit" -ForegroundColor Green
    Write-Host "the previous set is kept at $previous (roll back with -Rollback)"
}
