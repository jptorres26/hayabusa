"""The job queue: one SQLite file, written by the web app and drained by the worker service.

SQLite is enough here — a handful of technicians uploading logs is not a write-heavy workload —
provided two things hold, which this module enforces: WAL mode so a reader never blocks the
writer, and claiming a job as a single conditional UPDATE so two workers can never take the same
one.
"""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1

QUEUED = "queued"
RUNNING = "running"
DONE = "done"
FAILED = "failed"
CANCELLED = "cancelled"
ACTIVE_STATES = (QUEUED, RUNNING)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id              TEXT PRIMARY KEY,
    state           TEXT NOT NULL,
    filename        TEXT NOT NULL,
    size_bytes      INTEGER NOT NULL,
    sha256          TEXT NOT NULL,
    submitted_by    TEXT NOT NULL DEFAULT '',
    created_at      REAL NOT NULL,
    started_at      REAL,
    finished_at     REAL,
    heartbeat_at    REAL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    error           TEXT NOT NULL DEFAULT '',
    summary_json    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS jobs_state_created ON jobs (state, created_at);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


@dataclass(slots=True)
class Job:
    id: str
    state: str
    filename: str
    size_bytes: int
    sha256: str
    submitted_by: str = ""
    created_at: float = 0.0
    started_at: float | None = None
    finished_at: float | None = None
    heartbeat_at: float | None = None
    attempts: int = 0
    error: str = ""
    summary: dict[str, Any] | None = None

    @property
    def is_active(self) -> bool:
        return self.state in ACTIVE_STATES

    @property
    def duration_seconds(self) -> float | None:
        if self.started_at is None:
            return None
        return (self.finished_at or time.time()) - self.started_at


def _row_to_job(row: sqlite3.Row) -> Job:
    summary_text = row["summary_json"]
    try:
        summary = json.loads(summary_text) if summary_text else None
    except json.JSONDecodeError:
        summary = None
    return Job(
        id=row["id"],
        state=row["state"],
        filename=row["filename"],
        size_bytes=row["size_bytes"],
        sha256=row["sha256"],
        submitted_by=row["submitted_by"],
        created_at=row["created_at"],
        started_at=row["started_at"],
        finished_at=row["finished_at"],
        heartbeat_at=row["heartbeat_at"],
        attempts=row["attempts"],
        error=row["error"],
        summary=summary,
    )


class JobStore:
    """Every read and write of the queue goes through here."""

    __slots__ = ("path",)

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = self._raw()
        try:
            # executescript commits implicitly, so the schema is created outside a transaction.
            conn.executescript(_SCHEMA)
            conn.execute(
                "INSERT INTO meta (key, value) VALUES ('schema_version', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (str(SCHEMA_VERSION),),
            )
        finally:
            conn.close()

    def _raw(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        # WAL so a reader (the web app) never blocks the writer (the worker), and a generous
        # busy timeout so a concurrent writer waits rather than failing.
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """One statement group in one write transaction: BEGIN IMMEDIATE takes the write lock up
        front, so two workers serialise here rather than colliding at COMMIT."""
        conn = self._raw()
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            if conn.in_transaction:
                conn.execute("COMMIT")
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    # -- writing -----------------------------------------------------------------------------

    def create(self, *, filename: str, size_bytes: int, sha256: str, submitted_by: str = "") -> Job:
        job = Job(
            id=uuid.uuid4().hex,
            state=QUEUED,
            filename=filename,
            size_bytes=size_bytes,
            sha256=sha256,
            submitted_by=submitted_by,
            created_at=time.time(),
        )
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO jobs (id, state, filename, size_bytes, sha256, submitted_by, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (job.id, job.state, job.filename, job.size_bytes, job.sha256, job.submitted_by, job.created_at),
            )
        return job

    def claim_next(self) -> Job | None:
        """Take the oldest queued job, atomically. Returns None when the queue is empty.

        The state check is part of the UPDATE, so a second worker running the same statement
        matches no rows rather than stealing a job that is already running.
        """
        now = time.time()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id FROM jobs WHERE state = ? ORDER BY created_at LIMIT 1", (QUEUED,)
            ).fetchone()
            if row is None:
                return None
            updated = conn.execute(
                "UPDATE jobs SET state = ?, started_at = ?, heartbeat_at = ?, attempts = attempts + 1"
                " WHERE id = ? AND state = ?",
                (RUNNING, now, now, row["id"], QUEUED),
            )
            if updated.rowcount != 1:
                return None
            claimed = conn.execute("SELECT * FROM jobs WHERE id = ?", (row["id"],)).fetchone()
        return _row_to_job(claimed)

    def heartbeat(self, job_id: str) -> None:
        with self._connect() as conn:
            conn.execute("UPDATE jobs SET heartbeat_at = ? WHERE id = ?", (time.time(), job_id))

    def finish(self, job_id: str, summary: dict[str, Any]) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE jobs SET state = ?, finished_at = ?, summary_json = ?, error = '' WHERE id = ?",
                (DONE, time.time(), json.dumps(summary), job_id),
            )

    def fail(self, job_id: str, error: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE jobs SET state = ?, finished_at = ?, error = ? WHERE id = ?",
                (FAILED, time.time(), error[:4000], job_id),
            )

    def cancel(self, job_id: str) -> bool:
        """Cancel a job that has not started. A running job is left alone."""
        with self._connect() as conn:
            updated = conn.execute(
                "UPDATE jobs SET state = ?, finished_at = ? WHERE id = ? AND state = ?",
                (CANCELLED, time.time(), job_id, QUEUED),
            )
        return updated.rowcount == 1

    def requeue_stale(self, *, older_than_seconds: float, max_attempts: int = 3) -> list[str]:
        """Return jobs whose worker died back to the queue (or fail them if they keep dying).

        A worker heartbeats while it scans; a running job that has stopped heartbeating means the
        process is gone, and without this the job would sit in ``running`` for ever.
        """
        cutoff = time.time() - older_than_seconds
        requeued: list[str] = []
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, attempts FROM jobs WHERE state = ? AND COALESCE(heartbeat_at, started_at, 0) < ?",
                (RUNNING, cutoff),
            ).fetchall()
            for row in rows:
                if row["attempts"] >= max_attempts:
                    conn.execute(
                        "UPDATE jobs SET state = ?, finished_at = ?, error = ? WHERE id = ?",
                        (FAILED, time.time(), "the scan stopped responding and was retried too many times", row["id"]),
                    )
                    continue
                conn.execute(
                    "UPDATE jobs SET state = ?, started_at = NULL, heartbeat_at = NULL WHERE id = ?",
                    (QUEUED, row["id"]),
                )
                requeued.append(row["id"])
        return requeued

    def delete(self, job_id: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM jobs WHERE id = ?", (job_id,))

    # -- reading -----------------------------------------------------------------------------

    def get(self, job_id: str) -> Job | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        return _row_to_job(row) if row else None

    def list(self, *, limit: int = 100, state: str | None = None) -> list[Job]:
        query = "SELECT * FROM jobs"
        params: list[Any] = []
        if state:
            query += " WHERE state = ?"
            params.append(state)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [_row_to_job(row) for row in rows]

    def older_than(self, cutoff: float) -> list[Job]:
        """Finished jobs created before ``cutoff``, for retention."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM jobs WHERE created_at < ? AND state NOT IN (?, ?)",
                (cutoff, QUEUED, RUNNING),
            ).fetchall()
        return [_row_to_job(row) for row in rows]

    def counts(self) -> dict[str, int]:
        with self._connect() as conn:
            rows = conn.execute("SELECT state, COUNT(*) AS n FROM jobs GROUP BY state").fetchall()
        return {row["state"]: row["n"] for row in rows}
