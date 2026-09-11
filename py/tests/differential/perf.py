"""Throughput harness: events/second, wall clock and peak memory, against the Hayabusa baseline.

This is the number threshold #2 is judged on. It times the same corpus through the Python engine
at several worker counts and, when a Hayabusa binary is given, times that too on the same machine
so the comparison is not across hardware.

Usage (from py/):
    uv run python tests/differential/perf.py --records-root ../oracle/fixtures-xml \\
        --corpus sample-evtx --record-format raw \\
        --rules /path/to/rules --config-dir /path/to/config \\
        [--workers 1 2 4 8] [--hayabusa /path/to/hayabusa] [--evtx-dir DIR] [--report perf.md]

``--record-format raw`` reads records that are already in the engine's layout (what the Windows
reader produces); ``evtx_dump`` normalizes the 0.12 fixture layout instead. The Hayabusa run
needs ``--evtx-dir``, the directory of real ``.evtx`` files the records came from.
"""

from __future__ import annotations

import argparse
import json
import platform
import resource
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
PY_ROOT = HERE.parent.parent
sys.path.insert(0, str(PY_ROOT))

from hayabusa_py.engine.detect import Detector, load_rule_set  # noqa: E402
from hayabusa_py.engine.parallel import (  # noqa: E402
    WorkerSetup,
    merge_countdata,
    scan_jobs,
    split_jobs,
)
from hayabusa_py.engine.timeutil import TimeFormatOptions  # noqa: E402
from hayabusa_py.evtx.jsonl_reader import iter_fixture_records, iter_jsonl_records  # noqa: E402
from hayabusa_py.output.config import OutputConfig  # noqa: E402
from hayabusa_py.output.render import render  # noqa: E402
from hayabusa_py.rules.config import RulesConfig  # noqa: E402
from hayabusa_py.rules.loader import RuleFilterOptions  # noqa: E402


def peak_rss_mb() -> float:
    """Peak resident set of this process and its children, in MB."""
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    children = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    scale = 1024 * 1024 if sys.platform == "darwin" else 1024  # ru_maxrss is bytes on macOS
    return max(usage, children) / scale


def count_events(files: list[Path], record_format: str) -> int:
    reader = iter_jsonl_records if record_format == "raw" else iter_fixture_records
    return sum(sum(1 for _ in reader(path)) for path in files)


def run_python(args, files: list[Path], workers: int) -> dict:
    rules_dir = Path(args.rules)
    config_dir = Path(args.config_dir)
    rules_config = rules_dir / "config"

    t0 = time.perf_counter()
    config = RulesConfig.load(rules_config, config_dir / "expand")
    options = RuleFilterOptions()
    rule_set = load_rule_set(rules_dir, config, options)
    rules_seconds = time.perf_counter() - t0

    out_cfg = OutputConfig.load(
        config_dir,
        rules_config,
        "super-verbose",
        time_format=TimeFormatOptions(utc=True, iso_8601=True),
        json_timeline=True,
        output_to_file=True,
    )
    detector = Detector(rule_set, config, use_index=True)

    t1 = time.perf_counter()
    rows = []
    if workers <= 1:
        detections = []
        for path in files:
            reader = iter_jsonl_records if args.record_format == "raw" else iter_fixture_records
            detections.extend(detector.scan_records(str(path), reader(path)))
        detections.extend(detector.finish())
        rows = [render(det, out_cfg, config.eventkey_alias) for det in detections]
    else:
        setup = WorkerSetup(
            rules_path=str(rules_dir),
            rules_config_dir=str(rules_config),
            config_dir=str(config_dir),
            expand_dir=str(config_dir / "expand"),
            filter_options=options,
            profile="super-verbose",
            time_format=TimeFormatOptions(utc=True, iso_8601=True),
            json_timeline=True,
            reader="fixture" if args.record_format != "raw" else "json",
            output_to_file=True,
        )
        jobs = split_jobs([(str(path), str(path)) for path in files], workers=workers)
        fragments = []
        for result in scan_jobs(jobs, setup, workers=workers):
            rows.extend(result.rows)
            fragments.append(result.countdata)
            detector.stats.merge(result.stats)
        merge_countdata(rule_set.rules, fragments)
        rows.extend(render(det, out_cfg, config.eventkey_alias) for det in detector.finish())
    seconds = time.perf_counter() - t1

    return {
        "workers": workers,
        "rules_seconds": round(rules_seconds, 1),
        "scan_seconds": round(seconds, 1),
        "detections": len(rows),
        "peak_rss_mb": round(peak_rss_mb()),
    }


def run_hayabusa(binary: str, evtx_dir: str, out_dir: Path) -> dict | None:
    out = out_dir / "hayabusa-timeline.jsonl"
    started = time.perf_counter()
    proc = subprocess.run(
        [
            # the flags the goldens were generated with (see tests/golden/**/*.cmd)
            binary, "dfir-timeline", "-d", evtx_dir, "-t", "jsonl", "-p", "super-verbose",
            "-U", "-w", "-K", "-q", "-C", "-o", str(out), "-A", "-a", "-O", "-s",
        ],
        capture_output=True,
        text=True,
    )
    seconds = time.perf_counter() - started
    if proc.returncode != 0:
        print(f"hayabusa failed: {proc.stderr.strip()[:400]}", file=sys.stderr)
        return None
    detections = sum(1 for _ in open(out, encoding="utf-8", errors="replace")) if out.exists() else 0
    return {"seconds": round(seconds, 1), "detections": detections}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--records-root", required=True)
    ap.add_argument("--corpus", default="sample-evtx")
    ap.add_argument("--record-format", default="raw", choices=["raw", "evtx_dump"])
    ap.add_argument("--rules", required=True)
    ap.add_argument("--config-dir", required=True)
    ap.add_argument("--workers", type=int, nargs="*", default=[1])
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--hayabusa", default="", help="Hayabusa binary to time on the same machine (all modes, all cores)")
    ap.add_argument("--evtx-dir", default="", help="the .evtx directory the records came from")
    ap.add_argument("--report", default="")
    args = ap.parse_args()

    files = sorted((Path(args.records_root) / args.corpus).rglob("*.evtx.jsonl"))
    if args.limit:
        files = files[: args.limit]
    if not files:
        print("no record files found", file=sys.stderr)
        return 1
    events = count_events(files, args.record_format)

    rows = [run_python(args, files, workers) for workers in args.workers]
    baseline = None
    if args.hayabusa and args.evtx_dir:
        baseline = run_hayabusa(args.hayabusa, args.evtx_dir, Path("."))

    lines = [
        "# hayabusa-py throughput",
        "",
        f"- host: {platform.platform()}, python {platform.python_version()}",
        f"- corpus: {len(files)} files, {events:,} events",
        "",
        "| run | rule load (s) | scan (s) | events/s | detections | peak RSS (MB) |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in rows:
        rate = events / row["scan_seconds"] if row["scan_seconds"] else 0
        label = f"python, {row['workers']} worker" + ("s" if row["workers"] != 1 else "")
        lines.append(
            f"| {label} | {row['rules_seconds']} | {row['scan_seconds']} | {rate:,.0f} | {row['detections']:,} | {row['peak_rss_mb']} |"
        )
    if baseline:
        rate = events / baseline["seconds"] if baseline["seconds"] else 0
        lines.append(
            f"| hayabusa (rust, all cores) | - | {baseline['seconds']} | {rate:,.0f} | {baseline['detections']:,} | - |"
        )
    single = next((row for row in rows if row["workers"] == 1), None)
    if single and baseline and single["scan_seconds"] and baseline["seconds"]:
        lines += ["", f"Python is {single['scan_seconds'] / baseline['seconds']:.1f}x Hayabusa's wall clock on this host."]

    text = "\n".join(lines)
    print(text)
    if args.report:
        Path(args.report).write_text(text + "\n", encoding="utf-8")
        Path(args.report).with_suffix(".json").write_text(
            json.dumps({"events": events, "files": len(files), "python": rows, "hayabusa": baseline}, indent=2),
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
