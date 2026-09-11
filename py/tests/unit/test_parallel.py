"""Tests for the pure logic of ``hayabusa_py.engine.parallel``.

Running an actual pool needs a rule set and a corpus, so that is the differential harness's job;
what is unit-tested here is the part that decides *how* work is split and how the workers'
aggregation state folds back together, which is where a parallel run could silently diverge from
a single-process one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from hayabusa_py.engine.detect import ScanStats
from hayabusa_py.engine.parallel import ScanJob, merge_countdata, split_jobs, worker_count


@dataclass
class FakeRule:
    rule_path: str
    countdata: dict[str, list[Any]] = field(default_factory=dict)


def test_files_become_one_job_each_without_splitting() -> None:
    jobs = split_jobs([("a.evtx", "a.evtx"), ("b.evtx", "b.evtx")], workers=4)
    assert jobs == [ScanJob("a.evtx", "a.evtx"), ScanJob("b.evtx", "b.evtx")]


def test_a_small_file_is_not_split() -> None:
    jobs = split_jobs(
        [("a.evtx", "a.evtx")], workers=4, split_over=1000, count_records=lambda _p: 999
    )
    assert jobs == [ScanJob("a.evtx", "a.evtx")]


def test_a_big_file_is_split_into_covering_ranges() -> None:
    jobs = split_jobs(
        [("big.evtx", "big.evtx")], workers=4, split_over=1000, count_records=lambda _p: 10_000
    )
    assert len(jobs) == 4
    assert jobs[0].start == 1
    # the ranges are half-open, contiguous, and reach past the last record
    for earlier, later in zip(jobs, jobs[1:], strict=False):
        assert earlier.stop == later.start
    assert jobs[-1].stop >= 10_000 + 1
    assert all(job.path == "big.evtx" for job in jobs)


def test_splitting_is_skipped_when_it_cannot_help() -> None:
    args = {"split_over": 10, "count_records": lambda _p: 10_000}
    assert len(split_jobs([("big.evtx", "big.evtx")], workers=1, **args)) == 1
    assert len(split_jobs([("big.evtx", "big.evtx")], workers=4, split_over=0)) == 1


def test_an_unusable_record_count_leaves_the_file_whole() -> None:
    def boom(_path: str) -> int:
        raise OSError("the file is not readable yet")

    jobs = split_jobs([("a.evtx", "a.evtx")], workers=4, split_over=10, count_records=boom)
    assert jobs == [ScanJob("a.evtx", "a.evtx")]


def test_merge_countdata_folds_fragments_into_the_parents_rules() -> None:
    rules = [FakeRule("r1.yml"), FakeRule("r2.yml")]
    merge_countdata(
        rules,
        [
            {"r1.yml": {"host-a": ["x"], "host-b": ["y"]}},
            {"r1.yml": {"host-a": ["z"]}, "r2.yml": {"_": ["q"]}},
        ],
    )
    assert rules[0].countdata == {"host-a": ["x", "z"], "host-b": ["y"]}
    assert rules[1].countdata == {"_": ["q"]}


def test_merge_countdata_ignores_rules_the_parent_does_not_have() -> None:
    rules = [FakeRule("r1.yml")]
    merge_countdata(rules, [{"gone.yml": {"k": ["v"]}}])
    assert rules[0].countdata == {}


def test_scan_stats_merge_sums_every_counter() -> None:
    total = ScanStats(files=1, events=10, events_with_hits=2, detections=3, rules_evaluated=40, seconds=1.5)
    total.merge(ScanStats(files=2, events=5, events_with_hits=1, detections=1, rules_evaluated=20, seconds=0.5))
    assert total == ScanStats(files=3, events=15, events_with_hits=3, detections=4, rules_evaluated=60, seconds=2.0)


@pytest.mark.parametrize("requested", [1, 2, 8])
def test_worker_count_honours_an_explicit_request(requested: int) -> None:
    assert worker_count(requested) == requested


def test_worker_count_defaults_to_the_available_cores() -> None:
    assert worker_count(0) >= 1
    assert worker_count(None) >= 1
