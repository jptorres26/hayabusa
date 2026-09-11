"""Differential test: hayabusa-py vs. the Hayabusa 4.0.0 golden output on the same records.

Usage (from py/):
    uv run python tests/differential/run.py --rules /path/to/hayabusa-4.0.0/rules \
        --config-dir /path/to/hayabusa-4.0.0/config [--mode all] [--report out.md] [--no-index]

Records come from the evtx_dump JSONL fixtures under tests/fixtures/records/<corpus>/; the golden
is tests/golden/<corpus>/<mode>/timeline.super-verbose.jsonl. Detections are compared by
(RuleID, EvtxFile, RecordID); aggregation rows (no RecordID) by (RuleID, EvtxFile, Timestamp).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
PY_ROOT = HERE.parent.parent
sys.path.insert(0, str(PY_ROOT))

from hayabusa_py.engine.detect import Detector, load_rule_set  # noqa: E402
from hayabusa_py.engine.timeutil import TimeFormatOptions, format_time  # noqa: E402
from hayabusa_py.evtx.jsonl_reader import iter_fixture_records, iter_jsonl_records  # noqa: E402
from hayabusa_py.rules.config import RulesConfig  # noqa: E402
from hayabusa_py.rules.loader import RuleFilterOptions  # noqa: E402

ISO = TimeFormatOptions(iso_8601=True)


def load_golden(path: Path) -> tuple[set[tuple], set[tuple], dict[tuple, dict]]:
    record_keys: set[tuple] = set()
    agg_keys: set[tuple] = set()
    rows: dict[tuple, dict] = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            if "RecordID" in row:
                key = (row["RuleID"], row["EvtxFile"], str(row["RecordID"]))
                record_keys.add(key)
            else:
                key = (row["RuleID"], row["EvtxFile"], row["Timestamp"])
                agg_keys.add(key)
            rows[key] = row
    return record_keys, agg_keys, rows


def render_and_diff(detections, args, rules_dir: Path, config: RulesConfig) -> str:
    """Render the timeline like ``dfir-timeline -U -O -s -t <fmt> -p <profile> -o file`` and
    compare it line by line with the golden file (all mode)."""
    from hayabusa_py.output.config import OutputConfig
    from hayabusa_py.output.render import render
    from hayabusa_py.output.writers import render_to_string, sort_key

    fmt = args.render
    profile = None if args.profile == "standard" else args.profile
    out_cfg = OutputConfig.load(Path(args.config_dir), rules_dir / "config", profile, time_format=TimeFormatOptions(utc=True, iso_8601=(fmt == "jsonl")), json_timeline=(fmt == "jsonl"), output_to_file=True)
    t0 = time.perf_counter()
    infos = [render(det, out_cfg, config.eventkey_alias) for det in detections]
    infos.sort(key=sort_key)
    text = render_to_string(infos, fmt)
    t_render = time.perf_counter() - t0
    out_path = PY_ROOT / "tests" / "differential" / f"ours.{args.profile}.{fmt}"
    out_path.write_text(text, encoding="utf-8")
    golden_name = f"timeline.{args.profile}.{fmt}"
    golden_path = PY_ROOT / "tests" / "golden" / args.corpus / args.mode / golden_name
    if not golden_path.exists():
        return f"## Render: wrote {out_path.name} ({t_render:.1f}s); no golden {golden_name} to compare"
    golden_lines = golden_path.read_text(encoding="utf-8").splitlines()
    our_lines = text.splitlines()
    if args.limit:
        scanned = {d.record.evtx_filepath for d in detections if d.record is not None}
        golden_lines = [line for line in golden_lines if any(f'"{name}"' in line or f",\"{name}\"" in line or name in line for name in scanned)]
    golden_set = Counter(golden_lines)
    ours_set = Counter(our_lines)
    same = sum((golden_set & ours_set).values())
    only_golden = list((golden_set - ours_set).elements())
    only_ours = list((ours_set - golden_set).elements())
    identical_order = golden_lines == our_lines
    lines = [f"## Render {fmt} / {args.profile}: {len(our_lines)} lines in {t_render:.1f}s (golden {len(golden_lines)})"]
    lines.append(f"- identical lines: {same}; only in golden: {len(only_golden)}; only in ours: {len(only_ours)}; byte-identical order: {identical_order}")
    for g, o in list(zip(only_golden, only_ours, strict=False))[:6]:
        lines.append(f"- golden: {g[:400]}")
        lines.append(f"- ours:   {o[:400]}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rules", required=True)
    parser.add_argument("--config-dir", required=True, help="Hayabusa's config/ directory (expand placeholders)")
    parser.add_argument("--corpus", default="sample-evtx")
    parser.add_argument("--mode", default="all", choices=["all"])
    parser.add_argument("--report", default=None)
    parser.add_argument("--no-index", action="store_true")
    parser.add_argument("--limit", type=int, default=0, help="only the first N fixture files")
    parser.add_argument("--render", default=None, choices=["jsonl", "csv"], help="also render the timeline and diff it against the golden file")
    parser.add_argument("--profile", default="super-verbose")
    parser.add_argument("--records-root", default=None, help="directory of <corpus>/**.evtx.jsonl record files (default tests/fixtures/records)")
    parser.add_argument("--record-format", default="evtx_dump", choices=["evtx_dump", "raw"], help="evtx_dump: normalize the 0.12 JSON layout; raw: records are already in the engine's layout")
    args = parser.parse_args()

    rules_dir = Path(args.rules)
    config = RulesConfig.load(rules_dir / "config", Path(args.config_dir) / "expand")
    options = RuleFilterOptions()  # dfir-timeline defaults with --no-wizard: all statuses, informational+
    t0 = time.perf_counter()
    rule_set = load_rule_set(rules_dir, config, options)
    t_rules = time.perf_counter() - t0
    print(f"rules loaded: {len(rule_set.rules)} (parse errors: {rule_set.parse_error_count}) in {t_rules:.1f}s")

    detector = Detector(rule_set, config, use_index=not args.no_index)
    print(f"index: {detector.index.describe()}")

    records_root = Path(args.records_root) if args.records_root else PY_ROOT / "tests" / "fixtures" / "records"
    read_records = iter_fixture_records if args.record_format == "evtx_dump" else iter_jsonl_records
    fixtures = sorted((records_root / args.corpus).rglob("*.evtx.jsonl"))
    if args.limit:
        fixtures = fixtures[: args.limit]
    ours_records: set[tuple] = set()
    ours_agg: set[tuple] = set()
    detections = []
    t1 = time.perf_counter()
    for fixture in fixtures:
        rel = fixture.relative_to(records_root).as_posix()[: -len(".jsonl")]
        for det in detector.scan_records(rel, read_records(fixture)):
            record_id = det.record.record.get("Event", {}).get("System", {}).get("EventRecordID")
            ours_records.add((det.rule.rule_id, rel, str(record_id)))
            if args.render:
                detections.append(det)
    for det in detector.finish():
        assert det.agg_result is not None
        ours_agg.add((det.rule.rule_id, det.agg_result.agg_record_time_info[0].evtx_file_path if det.agg_result.agg_record_time_info else "", format_time(det.agg_result.start_datetime, False, ISO)))
        if args.render:
            detections.append(det)
    t_scan = time.perf_counter() - t1
    stats = detector.stats
    render_report = ""
    if args.render:
        render_report = render_and_diff(detections, args, rules_dir, config)

    golden_path = PY_ROOT / "tests" / "golden" / args.corpus / args.mode / "timeline.super-verbose.jsonl"
    gold_records, gold_agg, gold_rows = load_golden(golden_path)
    if args.limit:
        scanned = {f.relative_to(PY_ROOT / "tests" / "fixtures" / "records").as_posix()[: -len(".jsonl")] for f in fixtures}
        gold_records = {k for k in gold_records if k[1] in scanned}
        gold_agg = {k for k in gold_agg if k[1] in scanned}

    matched = gold_records & ours_records
    missing = gold_records - ours_records
    extra = ours_records - gold_records
    fidelity = len(matched) / len(gold_records) * 100 if gold_records else 100.0
    extra_pct = len(extra) / len(gold_records) * 100 if gold_records else 0.0

    by_rule_missing = Counter(k[0] for k in missing)
    by_rule_extra = Counter(k[0] for k in extra)
    rule_files = {r.rule_id: r.rule_file_name() for r in rule_set.rules}
    gold_rule_file = {k[0]: v.get("RuleFile", "?") for k, v in gold_rows.items()}

    lines = []
    lines.append(f"# Differential report — {args.corpus} / {args.mode}")
    lines.append("")
    lines.append(f"- rules loaded: {len(rule_set.rules)} (parse errors {rule_set.parse_error_count}); index {detector.index.describe()}")
    lines.append(f"- files: {stats.files}, events: {stats.events}, events with hits: {stats.events_with_hits}")
    lines.append(f"- rule evaluations: {stats.rules_evaluated} ({stats.rules_evaluated / max(stats.events, 1):.0f} per event)")
    lines.append(f"- wall clock: rules {t_rules:.1f}s + scan {t_scan:.1f}s; events/s (scan only): {stats.events / max(t_scan, 1e-9):.0f}")
    lines.append("")
    lines.append(f"## Record detections: golden {len(gold_records)}, ours {len(ours_records)}")
    lines.append(f"- matched: {len(matched)} ({fidelity:.2f}% of golden)")
    lines.append(f"- missing (golden only): {len(missing)}")
    lines.append(f"- extra (ours only): {len(extra)} ({extra_pct:.2f}% of golden)")
    lines.append("")
    lines.append(f"## Aggregation detections: golden {len(gold_agg)}, ours {len(ours_agg)}; matched {len(gold_agg & ours_agg)}")
    lines.append("")
    lines.append("## Missing by rule (top 40)")
    for rule_id, count in by_rule_missing.most_common(40):
        lines.append(f"- {count:6d}  {gold_rule_file.get(rule_id, rule_files.get(rule_id, rule_id))}  ({rule_id})")
    lines.append("")
    lines.append("## Extra by rule (top 40)")
    for rule_id, count in by_rule_extra.most_common(40):
        lines.append(f"- {count:6d}  {rule_files.get(rule_id, rule_id)}  ({rule_id})")
    lines.append("")
    lines.append("## Samples")
    for key in sorted(missing)[:10]:
        lines.append(f"- missing {key}")
    for key in sorted(extra)[:10]:
        lines.append(f"- extra   {key}")
    if render_report:
        lines.append("")
        lines.append(render_report)
    report = "\n".join(lines)
    print(report)
    if args.report:
        Path(args.report).write_text(report + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
