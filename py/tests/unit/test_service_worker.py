"""End-to-end tests for the worker loop and the job runner.

The scan itself runs against JSONL records rather than ``.evtx`` (the Windows reader is not
available here), which exercises everything between claiming a job and writing its results.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from service.config import ServiceConfig
from service.db import DONE, FAILED, JobStore
from service.runner import run_job, summarise
from service.uploads import EVTX_MAGIC, StoredUpload, UploadRejected
from service.worker import Worker, apply_retention

ORACLE = Path("/home/claude/scratch-cli")
RECORDS = Path("/home/claude/oracle/fixtures-xml/sample-evtx")
needs_oracle = pytest.mark.skipif(
    not (ORACLE / "rules").exists() or not RECORDS.exists(),
    reason="the Hayabusa rule set and record fixtures are not present",
)


@pytest.fixture
def config(tmp_path: Path) -> ServiceConfig:
    config = ServiceConfig(
        data_dir=tmp_path / "data",
        rules_dir=ORACLE / "rules",
        config_dir=ORACLE / "config",
        workers=1,
    )
    config.ensure_dirs()
    return config


def stage(config: ServiceConfig, job_id: str, source: Path) -> StoredUpload:
    """Put a record file where the worker expects the upload to be."""
    destination = config.job_upload_dir(job_id) / "upload.bin"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(source.read_bytes())
    return StoredUpload(destination, destination.stat().st_size, "0" * 64, source.name)


def a_record_file() -> Path:
    return next(path for path in sorted(RECORDS.rglob("*.evtx.jsonl")) if path.stat().st_size > 20_000)


# -- the runner ------------------------------------------------------------------------------


@needs_oracle
def test_a_scan_writes_every_result_file(config: ServiceConfig) -> None:
    stored = stage(config, "job1", a_record_file())
    outcome = run_job("job1", stored, config, reader="json")

    results = config.job_result_dir("job1")
    assert (results / "timeline.jsonl").is_file()
    assert (results / "timeline.csv").is_file()
    assert json.loads((results / "summary.json").read_text())["detections"] == outcome.summary["detections"]
    assert outcome.summary["events"] > 0


@needs_oracle
def test_the_timeline_matches_the_summary(config: ServiceConfig) -> None:
    stored = stage(config, "job2", a_record_file())
    outcome = run_job("job2", stored, config, reader="json")
    lines = (config.job_result_dir("job2") / "timeline.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == outcome.summary["detections"]
    assert all(line.startswith("{") for line in lines)


@needs_oracle
def test_results_are_written_atomically(config: ServiceConfig) -> None:
    """No half-written file is ever visible: the parts are renamed into place."""
    stored = stage(config, "job3", a_record_file())
    run_job("job3", stored, config, reader="json")
    assert not list(config.job_result_dir("job3").glob("*.part"))


def test_a_file_that_is_not_a_log_is_rejected(config: ServiceConfig, tmp_path: Path) -> None:
    source = tmp_path / "notes.txt"
    source.write_bytes(b"just some text")
    stored = stage(config, "job4", source)
    with pytest.raises(UploadRejected, match="neither an .evtx file nor a .zip"):
        run_job("job4", stored, config)


def test_summarise_counts_levels_and_rules() -> None:
    from hayabusa_py.engine.detect import ScanStats
    from hayabusa_py.output.render import DetectInfo

    def row(level: int, rule: str, computer: str) -> DetectInfo:
        return DetectInfo(
            detected_time=0, rule_path=f"{rule}.yml", ruleid=rule, ruletitle=rule,
            ruleauthor="", level=level, computername=computer, rec_id="1", eventid="4624",
            detail="", output_fields=[],
        )

    rows = [row(6, "a", "PC1"), row(6, "a", "PC1"), row(1, "b", "PC2")]
    summary = summarise(rows, ScanStats(events=10, events_with_hits=3), files=2, seconds=1.25)
    assert summary["detections"] == 3
    assert summary["unique_detections"] == 2
    assert summary["by_level"] == {"emergency": 2, "informational": 1}
    assert summary["top_rules"][0] == ("a", 2)
    assert summary["top_computers"][0] == ("PC1", 2)
    assert summary["files"] == 2
    assert summary["scan_seconds"] == 1.2


# -- the worker loop -------------------------------------------------------------------------


@needs_oracle
def test_the_worker_takes_a_job_and_finishes_it(config: ServiceConfig, monkeypatch) -> None:
    store = JobStore(config.db_path)
    worker = Worker(config, store=store)
    monkeypatch.setattr(
        "service.worker.run_job",
        lambda job_id, stored, cfg, **kw: __import__("service.runner", fromlist=["run_job"]).run_job(
            job_id, stored, cfg, reader="json", **kw
        ),
    )
    job = store.create(filename="records.jsonl", size_bytes=0, sha256="0" * 64)
    stage(config, job.id, a_record_file())

    assert worker.run_once() is True
    finished = store.get(job.id)
    assert finished.state == DONE
    assert finished.summary["detections"] > 0
    assert not (config.work_dir / job.id).exists()  # the extracted copies are cleaned up


def test_an_empty_queue_is_reported(config: ServiceConfig) -> None:
    assert Worker(config, store=JobStore(config.db_path)).run_once() is False


def test_a_missing_upload_fails_the_job_not_the_worker(config: ServiceConfig) -> None:
    store = JobStore(config.db_path)
    job = store.create(filename="gone.evtx", size_bytes=10, sha256="0" * 64)
    assert Worker(config, store=store).run_once() is True
    assert store.get(job.id).state == FAILED
    assert "no longer on the server" in store.get(job.id).error


def test_a_scan_that_raises_fails_only_that_job(config: ServiceConfig, monkeypatch) -> None:
    store = JobStore(config.db_path)
    job = store.create(filename="a.evtx", size_bytes=8, sha256="0" * 64)
    path = config.job_upload_dir(job.id) / "upload.bin"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(EVTX_MAGIC)

    def explode(*args, **kwargs):
        raise RuntimeError("the rule set is on fire")

    monkeypatch.setattr("service.worker.run_job", explode)
    worker = Worker(config, store=store)
    assert worker.run_once() is True
    assert store.get(job.id).state == FAILED
    assert "the rule set is on fire" in store.get(job.id).error
    assert worker.run_once() is False  # the worker is still healthy


def test_retention_removes_old_jobs_and_their_files(config: ServiceConfig) -> None:
    store = JobStore(config.db_path)
    job = store.create(filename="old.evtx", size_bytes=1, sha256="0" * 64)
    store.claim_next()
    store.finish(job.id, {"detections": 0})
    upload_dir = config.job_upload_dir(job.id)
    result_dir = config.job_result_dir(job.id)
    upload_dir.mkdir(parents=True, exist_ok=True)
    result_dir.mkdir(parents=True, exist_ok=True)
    (upload_dir / "upload.bin").write_bytes(b"x")
    (result_dir / "timeline.csv").write_text("x", encoding="utf-8")

    assert apply_retention(config, store) == []  # nothing is old enough yet

    config.retention_days = 0
    time.sleep(0.01)
    assert apply_retention(config, store) == [job.id]
    assert store.get(job.id) is None
    assert not upload_dir.exists()
    assert not result_dir.exists()


def test_retention_leaves_active_jobs_alone(config: ServiceConfig) -> None:
    store = JobStore(config.db_path)
    queued = store.create(filename="a.evtx", size_bytes=1, sha256="0" * 64)
    config.retention_days = 0
    time.sleep(0.01)
    assert apply_retention(config, store) == []
    assert store.get(queued.id) is not None


def test_two_workers_sharing_a_queue_each_take_different_jobs(config: ServiceConfig, monkeypatch) -> None:
    """Two worker processes is the expected deployment shape; no job may be scanned twice."""
    import threading

    store = JobStore(config.db_path)
    jobs = [store.create(filename=f"{n}.evtx", size_bytes=8, sha256="0" * 64) for n in range(8)]
    for job in jobs:
        path = config.job_upload_dir(job.id) / "upload.bin"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(EVTX_MAGIC)

    ran: list[str] = []
    lock = threading.Lock()

    def fake_run(job_id, stored, cfg, **kwargs):
        with lock:
            ran.append(job_id)
        time.sleep(0.01)
        from service.runner import JobOutcome

        return JobOutcome(summary={"detections": 0})

    monkeypatch.setattr("service.worker.run_job", fake_run)

    def drain() -> None:
        worker = Worker(config, store=JobStore(config.db_path))
        while worker.run_once():
            pass

    threads = [threading.Thread(target=drain) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert sorted(ran) == sorted(job.id for job in jobs)
    assert len(ran) == len(set(ran)), "a job was scanned more than once"
    assert all(store.get(job.id).state == DONE for job in jobs)
    assert all(store.get(job.id).attempts == 1 for job in jobs)
