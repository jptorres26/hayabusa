"""Tests for the on-disk row spool: the timeline must be identical to sorting in memory."""

from __future__ import annotations

from pathlib import Path

import pytest

from hayabusa_py.output.render import DetectInfo
from hayabusa_py.output.writers import sort_key
from service.spool import RowSpool


def row(time: int, level: int = 3, rule: str = "r", record: str = "1") -> DetectInfo:
    return DetectInfo(
        detected_time=time,
        rule_path=f"{rule}.yml",
        ruleid=rule,
        ruletitle=rule,
        ruleauthor="",
        level=level,
        computername="PC1",
        rec_id=record,
        eventid="4624",
        detail="",
        output_fields=[("Timestamp", "Timestamp", str(time))],
    )


def test_merged_order_matches_sorting_in_memory(tmp_path: Path) -> None:
    batches = [
        [row(30), row(10), row(20)],
        [row(15), row(5)],
        [row(25, level=5), row(25, level=1)],
    ]
    everything = [item for batch in batches for item in batch]
    with RowSpool(tmp_path) as spool:
        for batch in batches:
            spool.add(batch)
        merged = list(spool.merged())
    assert merged == sorted(everything, key=sort_key)
    assert [info.detected_time for info in merged] == [5, 10, 15, 20, 25, 25, 30]


def test_rows_and_files_are_counted(tmp_path: Path) -> None:
    with RowSpool(tmp_path) as spool:
        assert spool.add([row(1), row(2)]) == 2
        assert spool.add([]) == 0
        spool.add([row(3)])
        assert spool.rows == 3
        assert spool.files == 2


def test_an_empty_spool_merges_to_nothing(tmp_path: Path) -> None:
    with RowSpool(tmp_path) as spool:
        assert list(spool.merged()) == []


def test_merging_twice_gives_the_same_rows(tmp_path: Path) -> None:
    """The writers iterate the spool once each, so a second pass must work."""
    with RowSpool(tmp_path) as spool:
        spool.add([row(2), row(1)])
        first = list(spool.merged())
        second = list(spool.merged())
    assert first == second


def test_the_temporary_files_are_removed(tmp_path: Path) -> None:
    spool = RowSpool(tmp_path)
    spool.add([row(1)])
    directory = spool._directory  # noqa: SLF001 - the test is about cleanup
    assert directory.exists()
    spool.close()
    assert not directory.exists()


def test_cleanup_happens_even_when_the_body_raises(tmp_path: Path) -> None:
    captured = {}
    with pytest.raises(RuntimeError):
        with RowSpool(tmp_path) as spool:
            spool.add([row(1)])
            captured["dir"] = spool._directory  # noqa: SLF001
            raise RuntimeError("the scan failed")
    assert not captured["dir"].exists()


def test_a_detection_with_an_aggregation_result_survives_the_round_trip(tmp_path: Path) -> None:
    from hayabusa_py.engine.aggregation import AggResult

    info = row(1)
    info.agg_result = AggResult(data=3, key="host-a", field_values=["a", "b"], start_datetime=1)
    info.details_convert_map = {"#Details": ["a: 1"]}
    with RowSpool(tmp_path) as spool:
        spool.add([info])
        restored = next(iter(spool.merged()))
    assert restored.agg_result.data == 3
    assert restored.agg_result.key == "host-a"
    assert restored.details_convert_map == {"#Details": ["a: 1"]}
