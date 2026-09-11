"""Check ``hayabusa_py.evtx.xml_record`` against the exact evtx crate Hayabusa bundles.

For every ``.evtx`` under the corpus: render XML with the *upstream* ``evtx_dump`` (its XML
expands array values into repeated ``<Data>`` elements, the same shape the Windows renderer
produces) and JSON with the *hayabusa-evtx* ``evtx_dump`` (``--separate-json-attributes``, the
layout the engine consumes). Convert the XML and compare record by record.

Usage: python xml_parity.py --corpus DIR --xml-dump BIN --json-dump BIN [--limit N] [--report FILE]
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from hayabusa_py.evtx.xml_record import xml_to_record  # noqa: E402

_RECORD_RE = re.compile(r"^Record (\d+)\n", re.MULTILINE)


def split_xml_records(text: str) -> list[tuple[int, str]]:
    parts = _RECORD_RE.split(text)
    records = []
    for index in range(1, len(parts), 2):
        records.append((int(parts[index]), parts[index + 1]))
    return records


def json_records(dump: str, path: Path) -> list[dict]:
    out = subprocess.run(
        [dump, "-o", "jsonl", "--separate-json-attributes", "--no-confirm-overwrite", str(path)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return [json.loads(line) for line in out.stdout.splitlines() if line.strip()]


def xml_records(dump: str, path: Path) -> list[tuple[int, str]]:
    out = subprocess.run(
        [dump, "-o", "xml", "--no-confirm-overwrite", str(path)], capture_output=True
    )
    # bytes -> str without universal-newline translation: records contain literal CR LF
    return split_xml_records(out.stdout.decode("utf-8", errors="replace"))


def diff_paths(expected, actual, prefix="") -> list[str]:
    """Human-readable list of leaf differences."""
    if isinstance(expected, dict) and isinstance(actual, dict):
        out = []
        for key in expected.keys() | actual.keys():
            if key not in actual:
                out.append(f"{prefix}{key}: missing (expected {json.dumps(expected[key])[:80]})")
            elif key not in expected:
                out.append(f"{prefix}{key}: extra ({json.dumps(actual[key])[:80]})")
            else:
                out.extend(diff_paths(expected[key], actual[key], f"{prefix}{key}."))
        return out
    if isinstance(expected, list) and isinstance(actual, list) and len(expected) == len(actual):
        out = []
        for index, (e, a) in enumerate(zip(expected, actual, strict=True)):
            out.extend(diff_paths(e, a, f"{prefix}[{index}]."))
        return out
    if expected != actual:
        return [
            f"{prefix[:-1]}: expected {json.dumps(expected)[:80]} got {json.dumps(actual)[:80]}"
        ]
    return []


def walk(obj, dotted):
    for key in dotted.split("."):
        obj = obj.get(key) if isinstance(obj, dict) else None
    return obj


def shape(value) -> str:
    if isinstance(value, list):
        return f"list[{len(value)}]"
    if value is None:
        return "null"
    return type(value).__name__


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--xml-dump", required=True)
    ap.add_argument("--json-dump", required=True)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--report", default="")
    ap.add_argument("--wevtapi", action="store_true", help="run the converter in wevtapi mode")
    args = ap.parse_args()

    files = sorted(Path(args.corpus).rglob("*.evtx"))
    if args.limit:
        files = files[: args.limit]
    total = matched = 0
    kinds: Counter[str] = Counter()
    examples: dict[str, str] = {}
    count_mismatch = []
    for path in files:
        expected = json_records(args.json_dump, path)
        xmls = xml_records(args.xml_dump, path)
        if len(expected) != len(xmls):
            count_mismatch.append((str(path), len(expected), len(xmls)))
        for exp, (record_id, xml_text) in zip(expected, xmls, strict=False):
            total += 1
            try:
                got = xml_to_record(xml_text, wevtapi=args.wevtapi, pretty=True)
            except Exception as exc:  # noqa: BLE001
                kinds[f"exception: {type(exc).__name__}"] += 1
                examples.setdefault(
                    f"exception: {type(exc).__name__}", f"{path} #{record_id}: {exc}"
                )
                continue
            if got == exp:
                matched += 1
                continue
            diffs = diff_paths(exp, got)
            for line in diffs:
                kind = re.sub(r":.*", "", line)
                kind = re.sub(r"\[\d+\]", "[]", kind)
                if kind.endswith(".Data"):
                    e_val = walk(exp, kind)
                    g_val = walk(got, kind)
                    kind += f" (expected {shape(e_val)}, got {shape(g_val)})"
                kinds[kind] += 1
                examples.setdefault(kind, f"{path.name} #{record_id}: {line}")
    lines = [f"records: {total}, identical: {matched} ({matched / max(total, 1):.4%})"]
    if count_mismatch:
        lines.append(f"record-count mismatches: {len(count_mismatch)} (first: {count_mismatch[0]})")
    for kind, n in kinds.most_common(60):
        lines.append(f"{n:8d}  {kind}    e.g. {examples[kind]}")
    text = "\n".join(lines)
    print(text)
    if args.report:
        Path(args.report).write_text(text + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
