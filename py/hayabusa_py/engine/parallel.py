"""Run the scan across processes.

One Python process saturates one core, so a 500 MB upload on an otherwise idle server should use
all of them. The unit of work is a file (or a record-id range of one big file); each worker
builds the rule set and the output configuration once, scans its share, and returns *rendered*
rows rather than records, so what crosses the process boundary is the small flat output rather
than the events themselves.

Aggregation rules (``count()`` and correlation) are the one thing a worker cannot finish on its
own: their windows span files. Workers return their accumulated ``countdata`` instead, the parent
merges it into its own rule set and resolves the windows centrally -- ``judge_timeframe`` sorts
each key's records by time, so the merge is order-independent and the result does not depend on
how the work was split.

The pool uses the default start method, which is ``spawn`` on Windows (the deployment target):
nothing here relies on inheriting state through ``fork``.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from hayabusa_py.engine.detect import Detection, Detector, ScanStats, load_rule_set
from hayabusa_py.engine.timeutil import TimeFormatOptions
from hayabusa_py.output.config import OutputConfig
from hayabusa_py.output.render import DetectInfo, render
from hayabusa_py.rules.config import RulesConfig
from hayabusa_py.rules.loader import RuleFilterOptions


@dataclass(slots=True, frozen=True)
class ScanJob:
    """One unit of work: a whole file, or a half-open ``EventRecordID`` range of one."""

    path: str
    display_path: str
    start: int | None = None
    stop: int | None = None


@dataclass(slots=True)
class WorkerSetup:
    """Everything a worker needs to rebuild the engine, as plain data it can pickle."""

    rules_path: str
    rules_config_dir: str
    config_dir: str
    expand_dir: str
    filter_options: RuleFilterOptions
    profile: str | None = None
    time_format: TimeFormatOptions = field(default_factory=TimeFormatOptions)
    json_timeline: bool = False
    reader: str = "evtx"  # "evtx" | "json" | "fixture"
    # Rule files the parent kept after the channel filter; None means "keep everything the
    # loader returns". Without this a worker would scan with rules the parent had pruned.
    keep_rule_paths: frozenset[str] | None = None
    json_input_flag: bool = False
    no_pwsh_field_extraction: bool = False
    use_index: bool = True
    disable_abbreviation: bool = False
    no_field_data_mapping: bool = False
    output_to_file: bool = True


@dataclass(slots=True)
class JobResult:
    """What one job produced: rendered rows, aggregation state to merge, stats, log lines."""

    rows: list[DetectInfo] = field(default_factory=list)
    countdata: dict[str, dict[str, list[Any]]] = field(default_factory=dict)
    stats: ScanStats = field(default_factory=ScanStats)
    log_lines: list[str] = field(default_factory=list)
    error: str = ""


class _Engine:
    """A worker's engine, built once per process."""

    __slots__ = ("config", "detector", "log_lines", "out_cfg", "rule_set", "setup")

    def __init__(self, setup: WorkerSetup) -> None:
        self.setup = setup
        self.log_lines: list[str] = []
        self.config = RulesConfig.load(Path(setup.rules_config_dir), Path(setup.expand_dir))
        self.rule_set = load_rule_set(
            Path(setup.rules_path), self.config, setup.filter_options, self.log_lines.append
        )
        if setup.keep_rule_paths is not None:
            keep = setup.keep_rule_paths
            self.rule_set.rules = [rule for rule in self.rule_set.rules if rule.rule_path in keep]
        self.detector = Detector(
            self.rule_set,
            self.config,
            use_index=setup.use_index,
            json_input_flag=setup.json_input_flag,
            no_pwsh_field_extraction=setup.no_pwsh_field_extraction,
            log=self.log_lines.append,
        )
        self.out_cfg = OutputConfig.load(
            Path(setup.config_dir),
            Path(setup.rules_config_dir),
            setup.profile,
            time_format=setup.time_format,
            json_timeline=setup.json_timeline,
            disable_abbreviation=setup.disable_abbreviation,
            no_field_data_mapping=setup.no_field_data_mapping,
            output_to_file=setup.output_to_file,
        )

    def read(self, job: ScanJob) -> Iterable[Any]:
        kind = self.setup.reader
        if kind == "fixture":
            from hayabusa_py.evtx.jsonl_reader import iter_fixture_records

            return iter_fixture_records(job.path)
        if kind == "json":
            from hayabusa_py.evtx.jsonl_reader import iter_json_records, normalize_json_input

            return (normalize_json_input(record) for record in iter_json_records(job.path))
        from hayabusa_py.evtx.wevtapi_reader import iter_evtx_records, record_id_query

        query = record_id_query(job.start, job.stop)
        return iter_evtx_records(job.path, query=query, on_error=self.log_lines.append)

    def run(self, job: ScanJob) -> JobResult:
        from hayabusa_py.evtx.errors import EvtxReadError

        self.log_lines.clear()
        self.detector.stats = ScanStats()
        result = JobResult()
        try:
            for detection in self.detector.scan_records(job.display_path, self.read(job)):
                result.rows.append(render(detection, self.out_cfg, self.config.eventkey_alias))
        except EvtxReadError as exc:
            result.error = str(exc)
        result.stats = self.detector.stats
        result.log_lines = list(self.log_lines)
        result.countdata = {
            rule.rule_path: {key: list(values) for key, values in rule.countdata.items()}
            for rule in self.rule_set.rules
            if rule.countdata
        }
        for rule in self.rule_set.rules:
            if rule.countdata:
                rule.countdata = {}
        return result


_ENGINE: _Engine | None = None


def _init_worker(setup: WorkerSetup) -> None:
    global _ENGINE
    _ENGINE = _Engine(setup)


def _run_job(job: ScanJob) -> JobResult:
    assert _ENGINE is not None, "the worker was not initialised"
    return _ENGINE.run(job)


def worker_count(requested: int | None = None) -> int:
    """How many processes to use: the request, else one per available core."""
    if requested and requested > 0:
        return requested
    try:
        return len(os.sched_getaffinity(0))  # respects cgroup/affinity limits
    except AttributeError:  # Windows
        return os.cpu_count() or 1


def split_jobs(files: Iterable[tuple[str, str]], *, workers: int, split_over: int = 0, count_records: Callable[[str], int] | None = None) -> list[ScanJob]:
    """Turn files into jobs, splitting any file over ``split_over`` records into record ranges.

    Splitting matters for the single-big-``Security.evtx`` upload, where file-level parallelism
    would leave every core but one idle. ``count_records`` is the cheap record count (the reader
    provides one); when it is unavailable or fails, the file stays whole.
    """
    jobs: list[ScanJob] = []
    for path, display in files:
        total = 0
        if split_over and count_records is not None:
            try:
                total = count_records(path)
            except Exception:  # noqa: BLE001 - a count that fails just means "do not split"
                total = 0
        if not split_over or total <= split_over or workers <= 1:
            jobs.append(ScanJob(path, display))
            continue
        chunks = min(workers, max(2, total // split_over))
        step = total // chunks + 1
        # EventRecordID is 1-based and may start above 1 in a rotated log; ranges past the end
        # simply return nothing, so covering 1..total+1 is safe.
        for start in range(1, total + 1, step):
            jobs.append(ScanJob(path, display, start, start + step))
    return jobs


def scan_jobs(jobs: list[ScanJob], setup: WorkerSetup, *, workers: int) -> Iterator[JobResult]:
    """Run the jobs across ``workers`` processes, yielding each result as it finishes."""
    if workers <= 1 or len(jobs) <= 1:
        _init_worker(setup)
        for job in jobs:
            yield _run_job(job)
        return
    with ProcessPoolExecutor(max_workers=workers, initializer=_init_worker, initargs=(setup,)) as pool:
        yield from pool.map(_run_job, jobs)


def merge_countdata(rules: Iterable[Any], fragments: Iterable[dict[str, dict[str, list[Any]]]]) -> None:
    """Fold the workers' aggregation state back into the parent's rules, keyed by rule file."""
    by_path: dict[str, Any] = {}
    for rule in rules:
        by_path.setdefault(rule.rule_path, rule)
    for fragment in fragments:
        for rule_path, keys in fragment.items():
            rule = by_path.get(rule_path)
            if rule is None:
                continue
            for key, values in keys.items():
                rule.countdata.setdefault(key, []).extend(values)


def render_aggregations(detections: Iterable[Detection], out_cfg: OutputConfig, config: RulesConfig) -> list[DetectInfo]:
    return [render(detection, out_cfg, config.eventkey_alias) for detection in detections]
