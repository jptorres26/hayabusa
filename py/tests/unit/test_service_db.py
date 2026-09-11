"""Tests for the job queue -- in particular that two workers cannot take the same job."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from service.db import DONE, FAILED, QUEUED, RUNNING, JobStore


@pytest.fixture
def store(tmp_path: Path) -> JobStore:
    return JobStore(tmp_path / "jobs.sqlite3")


def add(store: JobStore, name: str = "Security.evtx"):  # noqa: ANN201
    return store.create(filename=name, size_bytes=1024, sha256="a" * 64, submitted_by="tester")


def test_a_new_job_is_queued(store: JobStore) -> None:
    job = add(store)
    assert job.state == QUEUED
    assert store.get(job.id) == job
    assert store.counts() == {QUEUED: 1}


def test_claim_takes_the_oldest_job_first(store: JobStore) -> None:
    first = add(store, "first.evtx")
    time.sleep(0.01)
    second = add(store, "second.evtx")
    assert store.claim_next().id == first.id
    assert store.claim_next().id == second.id
    assert store.claim_next() is None


def test_a_claimed_job_is_running_and_counted(store: JobStore) -> None:
    job = add(store)
    claimed = store.claim_next()
    assert claimed.state == RUNNING
    assert claimed.attempts == 1
    assert claimed.started_at is not None
    assert store.get(job.id).state == RUNNING


def test_two_claims_never_return_the_same_job(store: JobStore) -> None:
    add(store)
    assert store.claim_next() is not None
    assert store.claim_next() is None


def test_a_second_store_on_the_same_file_sees_the_claim(tmp_path: Path) -> None:
    """Two workers are two processes, so the exclusion has to hold through the file."""
    path = tmp_path / "jobs.sqlite3"
    one, two = JobStore(path), JobStore(path)
    add(one)
    assert one.claim_next() is not None
    assert two.claim_next() is None


def test_finish_records_the_summary(store: JobStore) -> None:
    job = add(store)
    store.claim_next()
    store.finish(job.id, {"detections": 7})
    done = store.get(job.id)
    assert done.state == DONE
    assert done.summary == {"detections": 7}
    assert done.finished_at is not None


def test_fail_records_the_error(store: JobStore) -> None:
    job = add(store)
    store.claim_next()
    store.fail(job.id, "the archive held no .evtx files")
    failed = store.get(job.id)
    assert failed.state == FAILED
    assert "no .evtx files" in failed.error


def test_cancel_applies_only_before_the_job_starts(store: JobStore) -> None:
    job = add(store)
    assert store.cancel(job.id) is True
    assert store.claim_next() is None

    other = add(store, "other.evtx")
    store.claim_next()
    assert store.cancel(other.id) is False
    assert store.get(other.id).state == RUNNING


def test_a_job_whose_worker_died_is_requeued(store: JobStore) -> None:
    job = add(store)
    store.claim_next()
    assert store.requeue_stale(older_than_seconds=0) == [job.id]
    assert store.get(job.id).state == QUEUED
    assert store.claim_next().attempts == 2


def test_a_job_that_keeps_dying_is_failed(store: JobStore) -> None:
    job = add(store)
    for _ in range(3):
        store.claim_next()
        store.requeue_stale(older_than_seconds=0, max_attempts=3)
    assert store.get(job.id).state == FAILED
    assert "retried too many times" in store.get(job.id).error


def test_a_live_job_is_left_alone(store: JobStore) -> None:
    job = add(store)
    store.claim_next()
    store.heartbeat(job.id)
    assert store.requeue_stale(older_than_seconds=60) == []
    assert store.get(job.id).state == RUNNING


def test_listing_is_newest_first_and_filterable(store: JobStore) -> None:
    first = add(store, "a.evtx")
    time.sleep(0.01)
    second = add(store, "b.evtx")
    store.claim_next()  # first is now running
    assert [job.id for job in store.list()] == [second.id, first.id]
    assert [job.id for job in store.list(state=QUEUED)] == [second.id]
    assert store.counts() == {QUEUED: 1, RUNNING: 1}


def test_retention_only_offers_finished_jobs(store: JobStore) -> None:
    queued = add(store, "queued.evtx")
    running = add(store, "running.evtx")
    store.claim_next()  # claims `queued`, the older one
    finished = add(store, "finished.evtx")
    store.claim_next()
    store.claim_next()
    store.finish(finished.id, {"detections": 0})
    old = store.older_than(time.time() + 1)
    assert [job.id for job in old] == [finished.id]
    assert {queued.id, running.id}.isdisjoint({job.id for job in old})


def test_delete_removes_the_row(store: JobStore) -> None:
    job = add(store)
    store.delete(job.id)
    assert store.get(job.id) is None


def test_an_unknown_job_is_none(store: JobStore) -> None:
    assert store.get("0" * 32) is None
