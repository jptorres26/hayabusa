# hayabusa-py

Python + PowerShell re-creation of [Hayabusa](https://github.com/Yamato-Security/hayabusa)'s
Windows event log detection engine, built for hosting on a Windows Server so technicians can
upload EVTX logs and get a Sigma-based timeline back without maintaining anything on endpoints.

No Rust ships in the product. The Rust Hayabusa binary is used only as a dev-time test oracle
(golden outputs under `tests/golden/`) and `evtx_dump` only to generate JSONL record fixtures.

See the plan in the project doc (`hayabusa-py-plan.md`) for phases, threshold and verification.

## Layout

- `hayabusa_py/evtx`   – record model and readers (Windows Event Log API, JSON/JSONL)
- `hayabusa_py/rules`  – rule discovery/filtering and rules/config files
- `hayabusa_py/engine` – selection/condition/matcher/aggregation semantics
- `hayabusa_py/output` – profiles, details rendering, CSV/JSON/JSONL timelines
- `tests/`             – unit tests ported from the Rust suites, fixtures, goldens, differential harness

## Development

    uv sync --group dev
    uv run pytest

License: AGPL-3.0-only (derived from Hayabusa, © Yamato Security). Rules: Detection Rule License 1.1.
