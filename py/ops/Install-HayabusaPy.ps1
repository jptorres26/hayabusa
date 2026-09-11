<#
.SYNOPSIS
    Installs the Hayabusa timeline service on a Windows Server host.

.DESCRIPTION
    Creates the install and data directories, syncs the locked Python environment with uv,
    registers the worker as a Windows service, and writes the service configuration to the
    machine environment. Idempotent: running it again upgrades in place.

    What it deliberately does NOT do, because those belong to the organisation's own process:
    open a firewall port, issue a TLS certificate, or configure the reverse proxy that fronts
    this service and authenticates technicians. The app listens on localhost only.

.PARAMETER InstallPath
    Where the code lives. Defaults to C:\Program Files\hayabusa-py.

.PARAMETER DataPath
    Where uploads, results and the job database live. Keep this off the system drive if you can.

.PARAMETER ServiceAccount
    The account the worker runs as. Defaults to the built-in virtual account, which has no
    password and no interactive rights.

.PARAMETER WhatIf
    Show what would happen without changing anything.

.EXAMPLE
    .\Install-HayabusaPy.ps1 -DataPath D:\hayabusa-data
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string] $InstallPath = 'C:\Program Files\hayabusa-py',
    [string] $DataPath = 'D:\hayabusa-py\data',
    [string] $RulesPath,
    [string] $ServiceAccount = 'NT SERVICE\HayabusaPyWorker',
    [int] $Workers = 0,
    [int] $RetentionDays = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ServiceName = 'HayabusaPyWorker'
$SourceRoot = Split-Path -Parent $PSScriptRoot   # the py/ directory next to ops/

function Test-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Set-MachineEnvironment([hashtable] $Values) {
    foreach ($key in $Values.Keys) {
        if ($PSCmdlet.ShouldProcess($key, 'set machine environment variable')) {
            [Environment]::SetEnvironmentVariable($key, [string]$Values[$key], 'Machine')
            Set-Item -Path "Env:$key" -Value ([string]$Values[$key])
        }
    }
}

if (-not (Test-Elevated)) { throw 'Run this from an elevated PowerShell session.' }
if (-not $RulesPath) { $RulesPath = Join-Path $InstallPath 'rules' }

Write-Host "installing from $SourceRoot"

foreach ($path in @($InstallPath, $DataPath, (Join-Path $DataPath 'uploads'), (Join-Path $DataPath 'results'), (Join-Path $DataPath 'work'), (Join-Path $DataPath 'logs'))) {
    if (-not (Test-Path $path)) {
        if ($PSCmdlet.ShouldProcess($path, 'create directory')) {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
        }
    }
}

# uv is the only prerequisite; it installs the pinned Python itself.
$uv = Get-Command uv -ErrorAction SilentlyContinue
if (-not $uv) {
    throw @'
uv is not installed. Install it first (as an administrator), then run this again:
    winget install --id=astral-sh.uv -e
or, on a host without winget, download the MSI from https://github.com/astral-sh/uv/releases
and verify its signature before installing.
'@
}

Write-Host 'copying the application...'
if ($PSCmdlet.ShouldProcess($InstallPath, 'copy application files')) {
    foreach ($item in @('hayabusa_py', 'service', 'ops', 'client', 'pyproject.toml', 'uv.lock', 'README.md')) {
        $source = Join-Path $SourceRoot $item
        if (Test-Path $source) {
            Copy-Item -Path $source -Destination $InstallPath -Recurse -Force
        }
    }
}

Write-Host 'syncing the locked Python environment...'
if ($PSCmdlet.ShouldProcess($InstallPath, 'uv sync --frozen')) {
    Push-Location $InstallPath
    try {
        & uv sync --frozen --all-extras
        if ($LASTEXITCODE -ne 0) { throw "uv sync failed with exit code $LASTEXITCODE" }
    } finally {
        Pop-Location
    }
}

Set-MachineEnvironment @{
    HAYABUSA_PY_DATA_DIR       = $DataPath
    HAYABUSA_PY_RULES_DIR      = $RulesPath
    HAYABUSA_PY_CONFIG_DIR     = (Join-Path $InstallPath 'config')
    HAYABUSA_PY_WORKERS        = $Workers
    HAYABUSA_PY_RETENTION_DAYS = $RetentionDays
}

Write-Host 'registering the worker service...'
$python = Join-Path $InstallPath '.venv\Scripts\python.exe'
if (-not (Test-Path $python) -and -not $WhatIfPreference) {
    throw "the environment was not created: $python is missing"
}

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "  the service already exists; stopping it for the upgrade"
    if ($PSCmdlet.ShouldProcess($ServiceName, 'stop service')) {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    }
}

if ($PSCmdlet.ShouldProcess($ServiceName, 'install/update the service')) {
    Push-Location $InstallPath
    try {
        # pywin32 registers the service itself: no third-party service host is involved.
        & $python -m service.worker --startup auto install
        if ($LASTEXITCODE -ne 0) { throw "service registration failed with exit code $LASTEXITCODE" }
    } finally {
        Pop-Location
    }
    # Recovery: restart on failure rather than leaving the queue unattended.
    & sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/restart/300000 | Out-Null
}

if ($ServiceAccount -and $PSCmdlet.ShouldProcess($ServiceName, "run as $ServiceAccount")) {
    & sc.exe config $ServiceName obj= "$ServiceAccount" | Out-Null
}

Write-Host 'granting the service account access to the data directory...'
if ($PSCmdlet.ShouldProcess($DataPath, "grant modify to $ServiceAccount")) {
    & icacls.exe $DataPath /grant "${ServiceAccount}:(OI)(CI)M" /T /C | Out-Null
}

if ($PSCmdlet.ShouldProcess($ServiceName, 'start service')) {
    Start-Service -Name $ServiceName
    Start-Sleep -Seconds 2
    Get-Service -Name $ServiceName | Format-Table -AutoSize Name, Status, StartType
}

Write-Host ''
Write-Host 'Installed.' -ForegroundColor Green
Write-Host "  code    : $InstallPath"
Write-Host "  data    : $DataPath"
Write-Host "  rules   : $RulesPath"
Write-Host ''
Write-Host 'Still to do, by hand:'
Write-Host '  1. Update-HayabusaRules.ps1  - fetch the detection rules'
Write-Host '  2. run the web app behind your reverse proxy, e.g.'
Write-Host "       $InstallPath\.venv\Scripts\python.exe -m uvicorn service.app:app --host 127.0.0.1 --port 8000"
Write-Host '     The app has no login of its own: the proxy authenticates technicians and passes'
Write-Host '     the identity in an X-Forwarded-User header.'
Write-Host '  3. Test-Deployment.ps1       - end-to-end smoke test'
