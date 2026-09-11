<#
.SYNOPSIS
    End-to-end smoke test of an installed deployment.

.DESCRIPTION
    Exports a small live log, uploads it through the site, waits for the worker to finish, and
    checks that the results download and that the counts are sane. Run it after installing, after
    a rules update, and as a scheduled health check.

    Exits non-zero on the first failure so a scheduled task can alert on it.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $Uri,
    [int] $TimeoutSeconds = 900,
    [string] $Channel = 'Application'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Fail([string] $Message) {
    Write-Host "FAIL: $Message" -ForegroundColor Red
    exit 1
}

$base = $Uri.TrimEnd('/')
$json = @{ Accept = 'application/json' }

Write-Host '1. the service answers its health check'
try {
    $health = Invoke-RestMethod -Uri "$base/healthz" -Headers $json -TimeoutSec 30
} catch {
    Fail "the health check did not answer: $($_.Exception.Message)"
}
if ($health.status -ne 'ok') { Fail "health check returned '$($health.status)'" }
Write-Host "   ok (jobs: $($health.jobs | ConvertTo-Json -Compress))"

Write-Host "2. exporting a sample of the $Channel log"
$sample = Join-Path ([IO.Path]::GetTempPath()) ("hayabusa-smoke-" + [Guid]::NewGuid().ToString('N') + '.evtx')
& wevtutil.exe epl $Channel $sample '/ow:true' "/q:*[System[TimeCreated[timediff(@SystemTime) <= 604800000]]]"
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $sample)) { Fail "could not export the $Channel log" }
$size = (Get-Item $sample).Length
Write-Host ("   exported {0:N1} MB" -f ($size / 1MB))

Write-Host '3. uploading'
try {
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        $submitted = Invoke-RestMethod -Uri "$base/jobs" -Method Post -Headers $json -Form @{
            file = Get-Item $sample; submitted_by = 'Test-Deployment'
        }
    } else {
        Fail 'this smoke test needs PowerShell 7 on the server'
    }
} catch {
    Fail "the upload was refused: $($_.Exception.Message)"
} finally {
    Remove-Item $sample -Force -ErrorAction SilentlyContinue
}
$jobUrl = "$base$($submitted.url)"
Write-Host "   job $($submitted.job)"

Write-Host '4. waiting for the scan'
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
do {
    Start-Sleep -Seconds 5
    $job = Invoke-RestMethod -Uri $jobUrl -Headers $json -TimeoutSec 30
    Write-Host "   state: $($job.state)"
    if ($job.state -eq 'failed') { Fail "the scan failed: $($job.error)" }
    if ($job.state -eq 'done') { break }
} while ((Get-Date) -lt $deadline)
if ($job.state -ne 'done') { Fail "the scan did not finish within $TimeoutSeconds seconds" }

Write-Host '5. checking the results'
if (-not $job.summary) { Fail 'the finished job has no summary' }
Write-Host ("   {0:N0} events, {1:N0} detections" -f $job.summary.events, $job.summary.detections)
if ($job.summary.events -le 0) { Fail 'the scan read no events' }

$names = @($job.results | ForEach-Object { $_.name })
foreach ($needed in @('timeline.jsonl', 'timeline.csv', 'summary.json')) {
    if ($names -notcontains $needed) { Fail "$needed was not produced" }
}

$csv = Invoke-WebRequest -Uri "$jobUrl/files/timeline.csv" -TimeoutSec 120
if ($csv.StatusCode -ne 200) { Fail "timeline.csv did not download (HTTP $($csv.StatusCode))" }
$lines = ($csv.Content -split "`n").Count
Write-Host "   timeline.csv downloaded ($lines lines)"
if ($job.summary.detections -gt 0 -and $lines -lt 2) { Fail 'the CSV is empty but detections were reported' }

Write-Host '6. a bad upload is refused'
$junk = Join-Path ([IO.Path]::GetTempPath()) ('hayabusa-smoke-junk-' + [Guid]::NewGuid().ToString('N') + '.evtx')
Set-Content -Path $junk -Value 'this is not an event log' -Encoding ascii
try {
    $bad = Invoke-RestMethod -Uri "$base/jobs" -Method Post -Headers $json -Form @{ file = Get-Item $junk }
    $badJob = Invoke-RestMethod -Uri "$base$($bad.url)" -Headers $json
    $deadline = (Get-Date).AddSeconds(120)
    while ($badJob.state -notin @('failed', 'done') -and (Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 5
        $badJob = Invoke-RestMethod -Uri "$base$($bad.url)" -Headers $json
    }
    if ($badJob.state -ne 'failed') { Fail "a file that is not an event log was accepted (state: $($badJob.state))" }
    Write-Host "   refused as expected: $($badJob.error)"
} finally {
    Remove-Item $junk -Force -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host 'All checks passed.' -ForegroundColor Green
exit 0
