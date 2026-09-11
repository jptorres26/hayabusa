"""Running one job: prepare the inputs, scan, write the results, summarise.

Kept free of any Windows-service or web-framework detail so it can be exercised anywhere -- the
service wrapper in ``worker.py`` only decides *when* this runs, and the tests drive it directly.
"""

from __future__ import annotations

import json
import os
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from hayabusa_py.engine.detect import Detector, ScanStats, load_rule_set
from hayabusa_py.engine.parallel import (
    WorkerSetup,
    merge_countdata,
    scan_jobs,
    split_jobs,
    worker_count,
)
from hayabusa_py.engine.timeutil import TimeFormatOptions
from hayabusa_py.output.config import OutputConfig
from hayabusa_py.output.render import DetectInfo, render
from hayabusa_py.output.writers import sort_key, write_csv, write_jsonl
from hayabusa_py.rules.config import RulesConfig
from hayabusa_py.rules.loader import LEVELS, RuleFilterOptions
from service.config import ServiceConfig
from service.uploads import StoredUpload, UploadRejected, prepare_inputs

Progress = Callable[[str], None]


@dataclass(slots=True)
class JobOutcome:
    summary: dict[str, Any] = field(default_factory=dict)
    result_dir: Path = Path()
    log_lines: list[str] = field(default_factory=list)


def _write_atomic(path: Path, write: Callable[[Any], None]) -> None:
    """Write through a temporary file so a reader never sees a half-written result."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".part")
    with open(temp, "w", encoding="utf-8", newline="") as handle:
        write(handle)
    os.replace(temp, path)


def summarise(rows: list[DetectInfo], stats: ScanStats, *, files: int, seconds: float) -> dict[str, Any]:
    """The numbers the results page shows, and the ones a technician reports upward."""
    by_level = Counter()
    unique: set[tuple[int, str]] = set()
    by_rule: Counter[str] = Counter()
    by_computer: Counter[str] = Counter()
    for info in rows:
        # LEVELS is ascending (informational..emergency) and info.level is 1-based.
        level_name = LEVELS[info.level - 1] if 1 <= info.level <= 6 else "undefined"
        by_level[level_name] += 1
        unique.add((info.level, info.ruleid))
        by_rule[info.ruletitle] += 1
        if info.computername:
            by_computer[info.computername] += 1
    return {
        "files": files,
        "events": stats.events,
        "events_with_hits": stats.events_with_hits,
        "detections": len(rows),
        "unique_detections": len(unique),
        "by_level": {level: by_level[level] for level in reversed(LEVELS) if by_level.get(level)},
        "top_rules": by_rule.most_common(20),
        "top_computers": by_computer.most_common(20),
        "scan_seconds": round(seconds, 1),
        "cpu_seconds": round(stats.seconds, 1),
    }


def run_job(
    job_id: str,
    stored: StoredUpload,
    config: ServiceConfig,
    *,
    progress: Progress | None = None,
    reader: str = "evtx",
) -> JobOutcome:
    """Scan one upload and write its results. Raises :class:`UploadRejected` for bad input."""
    say = progress or (lambda _message: None)
    log_lines: list[str] = []
    work_dir = config.work_dir / job_id
    result_dir = config.job_result_dir(job_id)

    say("checking the upload")
    if reader == "evtx":
        files, skipped = prepare_inputs(stored, work_dir, config)
    else:
        # JSON/JSONL input (Hayabusa's -J equivalent, and what the tests drive): the upload is
        # already the record file, so there is nothing to unpack or sniff.
        if not stored.path.is_file():
            raise UploadRejected("the uploaded file is no longer on the server")
        files, skipped = [stored.path], []
    if skipped:
        log_lines.extend(f"[WARN] skipped {entry}" for entry in skipped)

    say(f"loading rules for {len(files)} file(s)")
    rules_config_dir = config.rules_dir / "config"
    rules = RulesConfig.load(rules_config_dir, config.config_dir / "expand")
    options = RuleFilterOptions()
    rule_set = load_rule_set(config.rules_dir, rules, options, log_lines.append)
    if not rule_set.rules:
        raise UploadRejected("no detection rules are installed on the server; run ops/Update-HayabusaRules.ps1")

    out_cfg = OutputConfig.load(
        config.config_dir,
        rules_config_dir,
        "super-verbose",
        time_format=TimeFormatOptions(utc=True, iso_8601=True),
        json_timeline=True,
        output_to_file=True,
    )
    detector = Detector(rule_set, rules, use_index=True, log=log_lines.append)
    workers = worker_count(config.workers)

    say(f"scanning with {workers} process(es)")
    started = time.perf_counter()
    rows: list[DetectInfo] = []
    setup = WorkerSetup(
        rules_path=str(config.rules_dir),
        rules_config_dir=str(rules_config_dir),
        config_dir=str(config.config_dir),
        expand_dir=str(config.config_dir / "expand"),
        filter_options=options,
        profile="super-verbose",
        time_format=TimeFormatOptions(utc=True, iso_8601=True),
        json_timeline=True,
        reader=reader,
        output_to_file=True,
        keep_rule_paths=frozenset(rule.rule_path for rule in rule_set.rules),
    )
    jobs = split_jobs(
        [(str(path), path.name) for path in files],
        workers=workers,
        split_over=config.split_over if reader == "evtx" else 0,
        count_records=_record_counter() if reader == "evtx" else None,
    )
    fragments = []
    done = 0
    for result in scan_jobs(jobs, setup, workers=workers):
        rows.extend(result.rows)
        fragments.append(result.countdata)
        log_lines.extend(result.log_lines)
        detector.stats.merge(result.stats)
        if result.error:
            log_lines.append(f"[ERROR] {result.error}")
        done += 1
        say(f"scanned {done}/{len(jobs)}")
    merge_countdata(rule_set.rules, fragments)
    rows.extend(render(det, out_cfg, rules.eventkey_alias) for det in detector.finish())
    rows.sort(key=sort_key)
    seconds = time.perf_counter() - started

    say("writing results")
    result_dir.mkdir(parents=True, exist_ok=True)
    _write_atomic(result_dir / "timeline.jsonl", lambda handle: write_jsonl(handle, rows))
    _write_atomic(result_dir / "timeline.csv", lambda handle: write_csv(handle, rows))
    summary = summarise(rows, detector.stats, files=len(files), seconds=seconds)
    summary["skipped"] = skipped
    _write_atomic(result_dir / "summary.json", lambda handle: json.dump(summary, handle, indent=2))
    if log_lines:
        _write_atomic(result_dir / "scan.log", lambda handle: handle.write("\n".join(log_lines) + "\n"))
    return JobOutcome(summary=summary, result_dir=result_dir, log_lines=log_lines)


def _record_counter() -> Callable[[str], int] | None:
    import sys

    if sys.platform != "win32":
        return None
    from hayabusa_py.evtx.wevtapi_reader import record_count

    return record_count
