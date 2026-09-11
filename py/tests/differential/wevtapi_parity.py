"""Windows-only: compare the ``wevtapi`` reader's records against the ``evtx`` crate's JSON.

This is the check that cannot run on the development machine. On a Windows runner it reads the
same ``.evtx`` files twice -- once through ``EvtQuery``/``EvtRender`` and ``xml_record``, once
through the ``evtx_dump`` built from the revision Hayabusa pins -- and reports every field that
differs, so a change in either the converter or the API path is caught.

Usage (from py/):
    uv run python tests/differential/wevtapi_parity.py --corpus DIR --json-dump evtx_dump.exe \
        [--limit N] [--max-diff-rate 0.2] [--report out.txt]

Exit status is 1 when the share of records that differ exceeds ``--max-diff-rate`` (the default
tolerates the known type/empty-value ambiguities documented in ``xml_record``), so the script can
be used directly as a CI gate.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))

from hayabusa_py.evtx.wevtapi_reader import ReadStats, iter_evtx_records  # noqa: E402
from tests.differential.xml_parity import diff_paths  # noqa: E402


def crate_records(dump: str, path: Path) -> list[dict]:
    out = subprocess.run(
        [dump, "-o", "jsonl", "--separate-json-attributes", "--no-confirm-overwrite", str(path)],
        capture_output=True,
    )
    return [json.loads(line) for line in out.stdout.decode("utf-8", "replace").splitlines() if line.strip()]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--json-dump", required=True, help="evtx_dump built from the pinned hayabusa-evtx revision")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--max-diff-rate", type=float, default=0.2)
    ap.add_argument("--report", default="")
    args = ap.parse_args()

    files = sorted(Path(args.corpus).rglob("*.evtx"))
    if args.limit:
        files = files[: args.limit]
    total = matched = 0
    kinds: Counter[str] = Counter()
    examples: dict[str, str] = {}
    count_mismatch: list[str] = []
    render_errors = 0

    for path in files:
        expected = crate_records(args.json_dump, path)
        stats = ReadStats()
        ours = list(iter_evtx_records(path, stats=stats))
        render_errors += stats.render_errors
        if len(expected) != len(ours):
            count_mismatch.append(f"{path.name}: crate {len(expected)} records, reader {len(ours)}")
        for exp, got in zip(expected, ours, strict=False):
            total += 1
            if exp == got:
                matched += 1
                continue
            for line in diff_paths(exp, got):
                kind = re.sub(r"\[\d+\]", "[]", re.sub(r":.*", "", line))
                kinds[kind] += 1
                examples.setdefault(kind, f"{path.name}: {line}")

    differing = total - matched
    rate = differing / total if total else 0.0
    lines = [
        f"files: {len(files)}, records: {total}, identical: {matched} ({matched / max(total, 1):.2%})",
        f"differing: {differing} ({rate:.2%}), render errors: {render_errors}",
    ]
    lines += [f"RECORD COUNT MISMATCH  {line}" for line in count_mismatch]
    lines += [f"{n:8d}  {kind}    e.g. {examples[kind]}" for kind, n in kinds.most_common(40)]
    text = "\n".join(lines)
    print(text)
    if args.report:
        Path(args.report).write_text(text + "\n", encoding="utf-8")

    if count_mismatch:
        print(f"FAIL: {len(count_mismatch)} file(s) returned a different number of records", file=sys.stderr)
        return 1
    if rate > args.max_diff_rate:
        print(f"FAIL: {rate:.2%} of records differ (limit {args.max_diff_rate:.2%})", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
