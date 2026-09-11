# hayabusa-py

A Python + PowerShell re-creation of [Hayabusa](https://github.com/Yamato-Security/hayabusa)'s
Windows event log detection engine, built to be hosted on a Windows Server so technicians can
upload an EVTX log and get a Sigma-based timeline back without maintaining anything on endpoints.

No Rust ships in the product. EVTX parsing is done by Windows itself through the Event Log API
(`wevtapi` via pywin32), which is why the design works at all: there is no third-party
binary-format parser to keep current. The Rust Hayabusa binary is used only as a dev-time test
oracle — the golden outputs under `tests/golden/` — and `evtx_dump` only to produce reference
records for the differential tests.

**Fidelity, measured against Hayabusa 4.0.0 on the 599-file public sample corpus (47,699 events):**
32,444 / 32,444 record detections and 3 / 3 aggregation detections, with zero missing and zero
extra, through both the crate's own JSON and records reconstructed from event XML — the path the
Windows reader uses. Of the 32,447 rendered JSONL lines, 32,433 are byte-identical to the golden
in the same order; the fourteen that differ come from three records whose empty binary field
cannot be distinguished from an absent one in XML.

**Throughput** on a 2-vCPU container: 368 events/s in one process, 517 across two, against
Hayabusa's 1,041 using both cores — about 2.8× its wall clock single-threaded, inside the 5–20×
the plan budgeted. `tests/differential/perf.py` reproduces the table on any host.

## Layout

    hayabusa_py/
      evtx/      record model and readers: the Windows Event Log API, the XML->record
                 converter it depends on, and JSON/JSONL input
      rules/     rule discovery and filtering, and the rules/config files
      engine/    selection, conditions, 31 pipe modifiers, aggregation, correlation,
                 the (Channel, EventID) rule index, and the process pool
      output/    profiles, details rendering, CSV/JSON/JSONL timelines
      cli.py     `hayabusa-py dfir-timeline`, mirroring Hayabusa's flags
    service/     the hosted side: FastAPI upload site, SQLite job queue, worker service,
                 upload validation, and the rule-update gate
    ops/         PowerShell: install, rules update with rollback, retention, smoke test
    client/      Export-WinEvtx.ps1 — collect and upload from an endpoint (PS 5.1 or 7)
    tests/       unit tests ported from the Rust suites, fixtures, goldens, and the
                 differential/performance harnesses

## Running the scanner

    uv sync --all-extras --dev
    uv run hayabusa-py dfir-timeline -d C:\logs -r .\rules --config .\config -t csv -o timeline.csv

Useful flags beyond Hayabusa's: `-w/--workers` (0 for one process per core) and `--split-over`,
which splits a single large file into `EventRecordID` ranges so one big `Security.evtx` still
uses every core.

On macOS or Linux there is no Event Log API, so the scanner reads records from JSON instead
(`-J`), which is how the engine is developed and tested away from Windows.

## Running the service

    uv run python -m service.worker run          # the queue worker, foreground
    uv run uvicorn service.app:app --port 8000   # the upload site

`ops/Install-HayabusaPy.ps1` does this properly on a server: it syncs the locked environment,
registers the worker as a Windows service through pywin32, and grants the service account access
to the data directory. The app has no login of its own — the reverse proxy in front of it
authenticates technicians and passes the identity in `X-Forwarded-User`, which is what the audit
line records. See `docs/deployment.md`.

## Testing

    uv run pytest                                  # 476 unit tests
    uv run ruff check .
    uv run python tests/differential/run.py --rules <rules> --config-dir <config> --render jsonl
    uv run python tests/differential/perf.py --records-root <records> --rules <rules> --config-dir <config>

The Windows-only paths are covered by CI (`.github/workflows/py.yml`): the `windows-latest` job
exports a live Application log, reads it through the Event Log API, and compares every record of
the sample corpus against the `evtx` crate revision `Cargo.toml` pins.

## License

AGPL-3.0-only, derived from Hayabusa © Yamato Security. Detection rules are under the Detection
Rule License 1.1 and keep their own attribution. Serving this over a network triggers AGPL's
source-offer clause, so the organisation hosting it has to be willing to accept AGPL code — see
the licensing gate in the plan.
