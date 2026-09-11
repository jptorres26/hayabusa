# Deploying the Hayabusa timeline service

This is the runbook for standing the service up on a Windows Server, keeping it current, and
recovering it when something goes wrong. It assumes the reader is comfortable on a Windows server
but has not seen this application before.

## What it is, in one paragraph

A technician uploads a Windows event log — one `.evtx` or a `.zip` of several — to an internal
web page. The upload is queued, a worker service scans it against the Sigma and Hayabusa
detection rules, and the technician gets a timeline back as CSV or JSONL plus a summary of what
was found. Nothing is installed on the endpoint the logs came from; the export is done with
`wevtutil`, which is already on every supported version of Windows.

## What has to be decided before installing

**Where the data lives.** Uploaded event logs are evidence and can be large. Put the data
directory on a volume with room for the retention window (default 30 days) — as a rule of thumb,
plan for the largest single upload you will accept, times the number of technicians, times the
days you keep it. Keep it off the system drive.

**Who can reach the site.** The application has no login. It is designed to sit behind the
reverse proxy or gateway that already authenticates staff, and it listens on `127.0.0.1` so it
cannot be reached any other way. The proxy must pass the authenticated identity in an
`X-Forwarded-User` header; that is what the audit line records. Without the header the service
still works, but every job is attributed to `(unknown)`.

**How long results are kept.** `-RetentionDays` on the installer, default 30. This is a data
retention decision, not a technical one — involve whoever owns that policy.

**Whether the organisation accepts AGPL code.** This is a derivative work of Hayabusa, which is
AGPL-3.0, and serving it over a network triggers the source-offer clause. Internally that is
usually straightforward, but it is a decision someone has to make before hosting, not after.

## Prerequisites

- Windows Server 2019 or later, 64-bit, with at least 8 GB RAM. More cores means proportionally
  faster scans: the worker uses all of them by default.
- [uv](https://github.com/astral-sh/uv) installed for all users (`winget install --id=astral-sh.uv -e`).
  It installs the pinned Python itself; no separate Python installation is needed.
- `git`, for fetching detection rules.
- An account to run the worker. The installer defaults to the virtual service account
  `NT SERVICE\HayabusaPyWorker`, which has no password and no interactive rights. It needs modify
  access to the data directory (the installer grants this) and read access to the install
  directory. It does not need to be an administrator.

## Installing

Copy the `py/` directory to the server, open an elevated PowerShell 7 prompt in it, and run:

    .\ops\Install-HayabusaPy.ps1 -DataPath D:\hayabusa-py\data -RetentionDays 30 -WhatIf

`-WhatIf` prints what would change without touching anything — read that output before running it
for real. Then run the same command without `-WhatIf`.

**Expected output:** directories created, `uv sync --frozen` completing, the `HayabusaPyWorker`
service registered and started, and a summary of the three remaining manual steps.

**If it fails:** the most common causes are that `uv` is not on the system PATH for the elevated
session (open a new prompt after installing it), or that the service account cannot write to the
data directory (check the `icacls` line in the output). The installer is idempotent, so fix the
cause and run it again.

Then fetch the detection rules:

    .\ops\Update-HayabusaRules.ps1

and start the web app behind your proxy:

    & 'C:\Program Files\hayabusa-py\.venv\Scripts\python.exe' -m uvicorn service.app:app --host 127.0.0.1 --port 8000

Run that under whatever the organisation uses to keep a process alive — a scheduled task at
startup, or a second Windows service registered the same way as the worker. It is deliberately
not part of the installer, because how a web process is supervised and fronted is a local
decision.

Finally, prove it works end to end:

    .\ops\Test-Deployment.ps1 -Uri https://hayabusa.internal.example.org

**Expected output:** six numbered checks, ending in `All checks passed.` The last check uploads a
file that is not an event log and confirms the service refuses it.

## Keeping it running

**Rules updates.** Schedule `ops\Update-HayabusaRules.ps1` weekly. It clones into a staging
directory, runs the rule gate (`service/check_rules.py`) against it, and only swaps the new set
in if it passes. The gate refuses a set that loses more than 10% of its rules, one where more
than 2% fail to parse, and — if you give it `--sample` — one that no longer detects anything in a
known-good log. The previous set is kept; `-Rollback` restores it in one move.

**Retention.** Schedule `ops\Invoke-Retention.ps1` daily. Run it with `-WhatIf` first on a new
deployment to see what it would remove.

**Health.** `GET /healthz` returns the queue counts and is safe to poll. Schedule
`ops\Test-Deployment.ps1` daily or weekly as a real end-to-end check; it exits non-zero on
failure, so a scheduled task can alert on it.

**Logs.** The worker writes to `<data>\logs\worker.log`. Each job's own scan log, if it produced
one, is downloadable from the job page as `scan.log`.

## When something goes wrong

**A job is stuck in `running`.** The worker heartbeats every 15 seconds while it scans. If the
process dies, the job stops heartbeating and the next loop puts it back in the queue after five
minutes; after three attempts it is failed rather than retried for ever. If jobs are stuck and
the service is running, check `worker.log` — a scan that is simply slow is normal for a large
upload and will show progress lines.

**A job failed with a message about the file.** That is the intended behaviour for a bad upload:
the message on the job page says what was wrong (not an event log, too large, an archive with
nothing usable in it). Nothing needs fixing on the server.

**A job failed with "the scan failed".** That is a bug or an environment problem, not bad input.
`worker.log` has the traceback. The upload is still on disk, so the job can be re-run by
resubmitting the same file once the cause is fixed.

**Every job is failing after a rules update.** Roll back: `ops\Update-HayabusaRules.ps1 -Rollback`,
then restart the worker service. The gate should have caught it, so please capture the gate's
output for the next round of work.

**The disk is filling.** Lower `-RetentionDays` and run `ops\Invoke-Retention.ps1`. If it is
filling faster than retention clears it, lower `HAYABUSA_PY_MAX_UPLOAD_BYTES` (default 2 GB) so
individual uploads are smaller, and ask technicians to export with `-Since 7` rather than whole
channels.

**A log from a crashed host will not read.** This is a known and deliberate limitation. The Rust
`evtx` crate recovers records from damaged chunks; the Windows API does not expose them. The job
fails with the Windows error rather than silently returning a partial timeline. Recovering such a
log needs a tool that reads the format directly — which is exactly the dependency this design
avoids — so the honest answer to the technician is that this file needs different handling.

## Rolling back the application itself

The installer copies files rather than replacing them in place, so rolling back means reinstalling
the previous `py/` directory and restarting the service:

    Stop-Service HayabusaPyWorker
    # restore the previous py/ directory over C:\Program Files\hayabusa-py
    & 'C:\Program Files\hayabusa-py\.venv\Scripts\python.exe' -m uv sync --frozen --all-extras
    Start-Service HayabusaPyWorker

Queued jobs survive: the queue is a SQLite database in the data directory, not in the install
directory. A job that was running when the service stopped is requeued automatically.

## What the service does and does not defend against

It is worth being explicit, because the service accepts files from people and the threat model is
part of the change request.

It **does** enforce: a byte cap on the upload, streamed to disk so a huge POST cannot fill memory;
an archive inspection before extraction (entry count, per-entry and total uncompressed size, and
the compression ratio, which is the decompression-bomb guard); entry names flattened and
re-checked against the destination so no path traversal survives; only files that really begin
with the EVTX signature kept; job identifiers validated as hex UUIDs before they can name a
directory; downloads limited to a fixed set of result names; and an audit line per job recording
the file name, size, SHA-256 and the proxy-supplied identity.

It does **not** do: authentication or authorisation (the proxy does), antivirus scanning of
uploads, or any inspection of the log contents beyond parsing them. It runs the detection rules
over records; the rules themselves come from an upstream repository and are gated on update but
not otherwise audited.

## Change request checklist

For the organisation's change process, the facts usually asked for:

- **What changes:** a new internal web service on one server, reachable only through the existing
  reverse proxy. No changes to endpoints, no agent, no new network path from workstations.
- **Data handled:** Windows event logs uploaded by staff, kept for the retention window, then
  deleted. The logs contain host names, account names and command lines — treat the data
  directory at the same classification as the logs themselves.
- **Accounts created:** one virtual service account for the worker. No domain account, no
  interactive logon rights.
- **Ports opened:** none beyond whatever the proxy already listens on; the app itself binds to
  localhost.
- **Backout:** stop the service, restore the previous install directory, start it. Under ten
  minutes, and no data migration is involved.
- **Failure modes and their blast radius:** a failed scan affects one job; a failed worker affects
  the queue until it restarts (jobs are requeued, none are lost); a full disk stops new uploads
  being accepted rather than corrupting existing results.
- **Licensing:** AGPL-3.0, with the source-offer clause triggered by network use. Needs sign-off.
