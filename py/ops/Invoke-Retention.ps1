<#
.SYNOPSIS
    Deletes uploads and results past the retention window.

.DESCRIPTION
    Uploaded event logs are evidence: they should not sit on the server for ever. This removes
    finished jobs older than the configured window, their uploads and their results, and reports
    what went. Jobs still queued or running are never touched.

    Intended for a daily scheduled task. Use -WhatIf first on a new deployment.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string] $InstallPath = 'C:\Program Files\hayabusa-py',
    [int] $RetentionDays
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$python = Join-Path $InstallPath '.venv\Scripts\python.exe'
if (-not (Test-Path $python)) { throw "the service is not installed at $InstallPath" }
if ($PSBoundParameters.ContainsKey('RetentionDays')) {
    $env:HAYABUSA_PY_RETENTION_DAYS = $RetentionDays
}

$script = @'
import json, sys
from service.config import ServiceConfig
from service.db import JobStore
from service.worker import apply_retention
config = ServiceConfig.from_env()
config.ensure_dirs()
store = JobStore(config.db_path)
dry = "--dry-run" in sys.argv
if dry:
    import time
    cutoff = time.time() - config.retention_days * 86400
    removed = [job.id for job in store.older_than(cutoff)]
else:
    removed = apply_retention(config, store)
print(json.dumps({"retention_days": config.retention_days, "removed": removed, "dry_run": dry}))
'@

Push-Location $InstallPath
try {
    $arguments = @('-c', $script)
    if ($WhatIfPreference) { $arguments += '--dry-run' }
    $output = & $python @arguments
    if ($LASTEXITCODE -ne 0) { throw "retention failed with exit code $LASTEXITCODE" }
    $result = $output | ConvertFrom-Json
    $verb = if ($result.dry_run) { 'would remove' } else { 'removed' }
    Write-Host ("{0} {1} job(s) older than {2} days" -f $verb, $result.removed.Count, $result.retention_days)
    foreach ($id in $result.removed) { Write-Host "  $id" }
} finally {
    Pop-Location
}
