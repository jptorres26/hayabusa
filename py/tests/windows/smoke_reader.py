"""Windows-only smoke test: read a log this machine wrote and check the record shape.

Run with a path to an exported ``.evtx`` (see the CI workflow, which exports the Application
channel with ``wevtutil epl``). Exits non-zero on the first problem, so it can gate CI.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from hayabusa_py.evtx.wevtapi_reader import (  # noqa: E402
    EvtxReadError,
    ReadStats,
    iter_evtx_records,
    record_count,
    record_id_query,
)


def main(argv: list[str]) -> int:
    path = Path(argv[1] if len(argv) > 1 else "live/Application.evtx")
    stats = ReadStats()
    records = list(iter_evtx_records(path, stats=stats))
    print(f"{path}: {stats.records} records, {stats.render_errors} render errors")
    if not records:
        print("FAIL: the exported log had no readable records", file=sys.stderr)
        return 1
    if stats.render_errors:
        print(f"FAIL: {stats.render_errors} record(s) could not be rendered: {stats.first_error}", file=sys.stderr)
        return 1

    counted = record_count(path)
    if counted != len(records):
        print(f"FAIL: EvtGetLogInfo reports {counted} records, the reader returned {len(records)}", file=sys.stderr)
        return 1

    system = records[0]["Event"]["System"]
    timestamp = str(system.get("TimeCreated_attributes", {}).get("SystemTime", ""))
    checks = [
        ("Channel is a string", isinstance(system.get("Channel"), str)),
        ("EventID is an integer", isinstance(system.get("EventID"), int)),
        ("EventRecordID is an integer", isinstance(system.get("EventRecordID"), int)),
        ("Provider name is present", bool(system.get("Provider_attributes", {}).get("Name"))),
        (
            # Hayabusa parses %Y-%m-%dT%H:%M:%S%.fZ; the crate always writes 6 fraction digits,
            # so the reader has to trim the 7 the Windows renderer produces.
            f"the timestamp is in Hayabusa's form (got {timestamp!r})",
            bool(re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z", timestamp)),
        ),
    ]
    failed = [name for name, ok in checks if not ok]
    if failed:
        print(f"FAIL: {', '.join(failed)}\nfirst record System: {system}", file=sys.stderr)
        return 1

    # A record-range query must return a subset in the same order.
    ids = [r["Event"]["System"]["EventRecordID"] for r in records]
    if len(ids) > 4:
        start, stop = ids[1], ids[-1]
        ranged = [
            r["Event"]["System"]["EventRecordID"]
            for r in iter_evtx_records(path, query=record_id_query(start, stop))
        ]
        if ranged != [rid for rid in ids if start <= rid < stop]:
            print(f"FAIL: the record-range query returned {len(ranged)} records, expected the matching subset", file=sys.stderr)
            return 1

    try:
        list(iter_evtx_records(Path(__file__)))
    except EvtxReadError as exc:
        print(f"non-EVTX input is rejected: {exc}")
    else:
        print("FAIL: a non-EVTX file was accepted", file=sys.stderr)
        return 1

    print("OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
