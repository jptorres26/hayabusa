<#
.SYNOPSIS
    Exports a host's Windows event logs and uploads them to the Hayabusa timeline service.

.DESCRIPTION
    Runs on any Windows host with Windows PowerShell 5.1 (built in since Windows 8.1 / Server
    2012 R2) or PowerShell 7, so nothing has to be installed on the endpoint. It exports the
    channels worth having for an investigation with `wevtutil epl`, zips them, records a SHA-256,
    and — if a service URL is given — uploads the archive and prints the job page to open.

    Must run elevated: the Security channel is not readable otherwise.

.PARAMETER Uri
    Base URL of the timeline service, e.g. https://hayabusa.example.org. Omit to export only.

.PARAMETER OutputPath
    Where to write the archive. Defaults to the desktop, or the temp directory when there is no
    interactive profile.

.PARAMETER Channel
    Channels to export. Defaults to the standard investigation set; channels that do not exist on
    the host are skipped with a note rather than failing the run.

.PARAMETER Since
    Only export events written in the last N days. Smaller archives upload and scan faster.

.PARAMETER Reference
    Case or ticket reference recorded with the job.

.EXAMPLE
    .\Export-WinEvtx.ps1 -Uri https://hayabusa.example.org -Reference INC0012345

.EXAMPLE
    .\Export-WinEvtx.ps1 -Since 7 -OutputPath D:\evidence
#>
[CmdletBinding()]
param(
    [string] $Uri,
    [string] $OutputPath,
    [string[]] $Channel,
    [int] $Since = 0,
    [string] $Reference = '',
    [switch] $KeepArchive
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$DefaultChannels = @(
    'Security'
    'System'
    'Application'
    'Microsoft-Windows-Sysmon/Operational'
    'Microsoft-Windows-PowerShell/Operational'
    'Windows PowerShell'
    'Microsoft-Windows-TaskScheduler/Operational'
    'Microsoft-Windows-Windows Defender/Operational'
    'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
    'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'
    'Microsoft-Windows-WMI-Activity/Operational'
    'Microsoft-Windows-Bits-Client/Operational'
    'Microsoft-Windows-NTLM/Operational'
    'Microsoft-Windows-AppLocker/EXE and DLL'
    'Microsoft-Windows-CodeIntegrity/Operational'
    'Microsoft-Windows-DNS-Client/Operational'
)

function Test-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-SafeName([string] $Value) {
    return ($Value -replace '[^A-Za-z0-9._-]', '_')
}

if (-not (Test-Elevated)) {
    throw 'Run this from an elevated PowerShell session: the Security log cannot be exported otherwise.'
}

if (-not $Channel -or $Channel.Count -eq 0) { $Channel = $DefaultChannels }
if (-not $OutputPath) {
    $desktop = [Environment]::GetFolderPath('Desktop')
    $OutputPath = if ($desktop -and (Test-Path $desktop)) { $desktop } else { $env:TEMP }
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$label = '{0}-{1}' -f (Get-SafeName $env:COMPUTERNAME), $stamp
$staging = Join-Path ([IO.Path]::GetTempPath()) ("hayabusa-" + [Guid]::NewGuid().ToString('N'))
$archive = Join-Path $OutputPath ($label + '.zip')
New-Item -ItemType Directory -Path $staging -Force | Out-Null

$query = $null
if ($Since -gt 0) {
    # wevtutil takes an XPath; TimeCreated is in milliseconds before now.
    $query = "*[System[TimeCreated[timediff(@SystemTime) <= {0}]]]" -f ([int64]$Since * 86400000)
}

$exported = @()
$skipped = @()
foreach ($name in $Channel) {
    $target = Join-Path $staging ((Get-SafeName $name) + '.evtx')
    $arguments = @('epl', $name, $target, '/ow:true')
    if ($query) { $arguments += "/q:$query" }
    Write-Verbose "wevtutil $($arguments -join ' ')"
    $output = & wevtutil.exe @arguments 2>&1
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $target)) {
        $skipped += ('{0} ({1})' -f $name, ($output -join ' ').Trim())
        continue
    }
    $size = (Get-Item $target).Length
    if ($size -le 69632) {
        # An EVTX with no records is a header plus one empty chunk; sending it wastes everyone's
        # time, so drop it and say so.
        Remove-Item $target -Force
        $skipped += ('{0} (no events in range)' -f $name)
        continue
    }
    $exported += [pscustomobject]@{ Channel = $name; Path = $target; Bytes = $size }
    Write-Host ('exported {0} ({1:N1} MB)' -f $name, ($size / 1MB))
}

foreach ($entry in $skipped) { Write-Host "skipped $entry" -ForegroundColor DarkGray }

if ($exported.Count -eq 0) {
    Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue
    throw 'Nothing was exported. Check that this session is elevated and that the channels exist on this host.'
}

Write-Host 'compressing...'
if (Test-Path $archive) { Remove-Item $archive -Force }
Compress-Archive -Path (Join-Path $staging '*.evtx') -DestinationPath $archive -CompressionLevel Optimal
Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue

$hash = (Get-FileHash -Path $archive -Algorithm SHA256).Hash
$bytes = (Get-Item $archive).Length
Write-Host ''
Write-Host ('archive : {0}' -f $archive)
Write-Host ('size    : {0:N1} MB' -f ($bytes / 1MB))
Write-Host ('sha256  : {0}' -f $hash)
Write-Host ('channels: {0}' -f $exported.Count)

if (-not $Uri) {
    Write-Host ''
    Write-Host 'No -Uri given, so nothing was uploaded. Upload the archive through the site when ready.'
    return
}

$endpoint = ($Uri.TrimEnd('/')) + '/jobs'
Write-Host ''
Write-Host "uploading to $endpoint ..."

# PowerShell 7 sends a file with -Form; 5.1 needs the multipart body built by hand.
if ($PSVersionTable.PSVersion.Major -ge 7) {
    $form = @{ file = Get-Item $archive; submitted_by = $Reference }
    $response = Invoke-RestMethod -Uri $endpoint -Method Post -Form $form -Headers @{ Accept = 'application/json' }
} else {
    Add-Type -AssemblyName System.Net.Http
    $client = New-Object System.Net.Http.HttpClient
    $client.Timeout = [TimeSpan]::FromHours(2)
    $content = New-Object System.Net.Http.MultipartFormDataContent
    $stream = [IO.File]::OpenRead($archive)
    try {
        $fileContent = New-Object System.Net.Http.StreamContent($stream)
        $fileContent.Headers.ContentType = [Net.Http.Headers.MediaTypeHeaderValue]::Parse('application/zip')
        $content.Add($fileContent, 'file', [IO.Path]::GetFileName($archive))
        $content.Add((New-Object System.Net.Http.StringContent($Reference)), 'submitted_by')
        $client.DefaultRequestHeaders.Accept.Add(
            (New-Object Net.Http.Headers.MediaTypeWithQualityHeaderValue('application/json')))
        $result = $client.PostAsync($endpoint, $content).GetAwaiter().GetResult()
        $body = $result.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        if (-not $result.IsSuccessStatusCode) { throw "upload failed: $($result.StatusCode) $body" }
        $response = $body | ConvertFrom-Json
    } finally {
        $stream.Dispose()
        $client.Dispose()
    }
}

$jobUrl = ($Uri.TrimEnd('/')) + $response.url
Write-Host ''
Write-Host 'uploaded. Track the scan here:' -ForegroundColor Green
Write-Host "  $jobUrl"

if (-not $KeepArchive) {
    Remove-Item $archive -Force
    Write-Host "(local archive removed; pass -KeepArchive to keep it)"
}
