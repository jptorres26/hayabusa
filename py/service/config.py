"""Service configuration, read from the environment so the Windows service and a dev run share
one source of truth.

Every setting has a working default; the installer writes the overrides it needs into the
service's environment (``ops/Install-HayabusaPy.ps1``).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

ENV_PREFIX = "HAYABUSA_PY_"


def _env(name: str, default: str) -> str:
    return os.environ.get(ENV_PREFIX + name, default)


def _env_int(name: str, default: int) -> int:
    try:
        return int(_env(name, str(default)))
    except ValueError:
        return default


@dataclass(slots=True)
class ServiceConfig:
    """Where things live and what the service will accept."""

    data_dir: Path = Path("data")
    rules_dir: Path = Path("rules")
    config_dir: Path = Path("config")

    # Upload limits. The defaults are sized for "one technician exports a host's logs":
    # a 2 GB archive of a few 500 MB channels.
    max_upload_bytes: int = 2 * 1024**3
    max_member_bytes: int = 4 * 1024**3
    max_total_bytes: int = 8 * 1024**3  # everything one archive may expand to, together
    max_members: int = 200
    max_expansion_ratio: int = 200  # uncompressed / compressed, a zip-bomb guard

    # Scanning.
    workers: int = 0  # 0 = one process per core
    split_over: int = 200_000  # records, before one file is split into ranges
    job_timeout_seconds: int = 3 * 60 * 60

    # Housekeeping.
    retention_days: int = 30
    poll_seconds: float = 2.0

    @classmethod
    def from_env(cls) -> ServiceConfig:
        return cls(
            data_dir=Path(_env("DATA_DIR", "data")),
            rules_dir=Path(_env("RULES_DIR", "rules")),
            config_dir=Path(_env("CONFIG_DIR", "config")),
            max_upload_bytes=_env_int("MAX_UPLOAD_BYTES", 2 * 1024**3),
            max_member_bytes=_env_int("MAX_MEMBER_BYTES", 4 * 1024**3),
            max_total_bytes=_env_int("MAX_TOTAL_BYTES", 8 * 1024**3),
            max_members=_env_int("MAX_MEMBERS", 200),
            max_expansion_ratio=_env_int("MAX_EXPANSION_RATIO", 200),
            workers=_env_int("WORKERS", 0),
            split_over=_env_int("SPLIT_OVER", 200_000),
            job_timeout_seconds=_env_int("JOB_TIMEOUT_SECONDS", 3 * 60 * 60),
            retention_days=_env_int("RETENTION_DAYS", 30),
        )

    # -- derived paths -----------------------------------------------------------------------

    @property
    def uploads_dir(self) -> Path:
        return self.data_dir / "uploads"

    @property
    def results_dir(self) -> Path:
        return self.data_dir / "results"

    @property
    def work_dir(self) -> Path:
        return self.data_dir / "work"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "jobs.sqlite3"

    def job_upload_dir(self, job_id: str) -> Path:
        return self.uploads_dir / job_id

    def job_result_dir(self, job_id: str) -> Path:
        return self.results_dir / job_id

    def ensure_dirs(self) -> None:
        for path in (self.data_dir, self.uploads_dir, self.results_dir, self.work_dir):
            path.mkdir(parents=True, exist_ok=True)
