"""The job runner: drains the queue, and (on Windows) registers itself as a service.

The loop is plain Python and runs anywhere, so it can be exercised in tests and run in the
foreground during a deployment check; ``pywin32``'s ``win32serviceutil`` only wraps it for
Windows' service control manager, with no third-party service host involved.

    python -m service.worker run                    # foreground, any platform
    python -m service.worker install|start|stop|remove   # Windows service control
"""

from __future__ import annotations

import logging
import shutil
import sys
import threading
import time
from pathlib import Path

from service.config import ServiceConfig
from service.db import JobStore
from service.runner import run_job
from service.uploads import StoredUpload, UploadRejected, safe_display_name

log = logging.getLogger("hayabusa_py.worker")

HEARTBEAT_SECONDS = 15.0
STALE_AFTER_SECONDS = 300.0


class Worker:
    """Takes one job at a time and runs it to completion."""

    def __init__(self, config: ServiceConfig | None = None, *, store: JobStore | None = None) -> None:
        self.config = config or ServiceConfig.from_env()
        self.config.ensure_dirs()
        self.store = store or JobStore(self.config.db_path)
        self.stopping = threading.Event()

    def stop(self) -> None:
        self.stopping.set()

    def run_forever(self) -> None:
        log.info("worker started, data dir %s", self.config.data_dir)
        while not self.stopping.is_set():
            try:
                requeued = self.store.requeue_stale(older_than_seconds=STALE_AFTER_SECONDS)
                for job_id in requeued:
                    log.warning("job %s stopped responding and was requeued", job_id)
                if not self.run_once():
                    self.stopping.wait(self.config.poll_seconds)
            except Exception:  # noqa: BLE001 - the loop must outlive any single failure
                log.exception("the worker loop hit an unexpected error")
                self.stopping.wait(self.config.poll_seconds)
        log.info("worker stopped")

    def run_once(self) -> bool:
        """Run the next queued job. Returns False when the queue was empty."""
        job = self.store.claim_next()
        if job is None:
            return False
        log.info("job %s started (%s, %d bytes)", job.id, job.filename, job.size_bytes)
        beat = _Heartbeat(self.store, job.id)
        beat.start()
        try:
            stored = StoredUpload(
                path=self.config.job_upload_dir(job.id) / "upload.bin",
                size_bytes=job.size_bytes,
                sha256=job.sha256,
                display_name=safe_display_name(job.filename),
            )
            if not stored.path.is_file():
                raise UploadRejected("the uploaded file is no longer on the server")
            outcome = run_job(job.id, stored, self.config, progress=lambda message: log.info("job %s: %s", job.id, message))
            self.store.finish(job.id, outcome.summary)
            log.info("job %s done: %d detections", job.id, outcome.summary.get("detections", 0))
        except UploadRejected as exc:
            self.store.fail(job.id, str(exc))
            log.info("job %s rejected: %s", job.id, exc)
        except Exception as exc:  # noqa: BLE001 - a failed scan is a failed job, not a dead worker
            self.store.fail(job.id, f"the scan failed: {exc}")
            log.exception("job %s failed", job.id)
        finally:
            beat.stop()
            self._cleanup(job.id)
        return True

    def _cleanup(self, job_id: str) -> None:
        """Drop the extracted copies; the original upload stays until retention removes it."""
        shutil.rmtree(self.config.work_dir / job_id, ignore_errors=True)


class _Heartbeat(threading.Thread):
    """Marks the job alive while it runs, so a crashed worker's job can be requeued."""

    def __init__(self, store: JobStore, job_id: str) -> None:
        super().__init__(daemon=True, name=f"heartbeat-{job_id[:8]}")
        self.store = store
        self.job_id = job_id
        self.done = threading.Event()

    def run(self) -> None:
        while not self.done.wait(HEARTBEAT_SECONDS):
            try:
                self.store.heartbeat(self.job_id)
            except Exception:  # noqa: BLE001 - a missed heartbeat is not worth failing the job
                log.debug("heartbeat failed for %s", self.job_id, exc_info=True)

    def stop(self) -> None:
        self.done.set()


def apply_retention(config: ServiceConfig, store: JobStore) -> list[str]:
    """Delete finished jobs older than the retention window, files included."""
    cutoff = time.time() - config.retention_days * 86400
    removed = []
    for job in store.older_than(cutoff):
        shutil.rmtree(config.job_upload_dir(job.id), ignore_errors=True)
        shutil.rmtree(config.job_result_dir(job.id), ignore_errors=True)
        shutil.rmtree(config.work_dir / job.id, ignore_errors=True)
        store.delete(job.id)
        removed.append(job.id)
    return removed


def _configure_logging(config: ServiceConfig) -> None:
    log_dir = Path(config.data_dir) / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        handlers=[logging.FileHandler(log_dir / "worker.log", encoding="utf-8"), logging.StreamHandler()],
    )


def run() -> int:
    config = ServiceConfig.from_env()
    _configure_logging(config)
    Worker(config).run_forever()
    return 0


# -- Windows service wrapper --------------------------------------------------------------------

if sys.platform == "win32":  # pragma: no cover - exercised by the deployment smoke test
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil

    class HayabusaPyService(win32serviceutil.ServiceFramework):
        _svc_name_ = "HayabusaPyWorker"
        _svc_display_name_ = "Hayabusa timeline worker"
        _svc_description_ = "Scans uploaded Windows event logs with the hayabusa-py engine."

        def __init__(self, args) -> None:  # noqa: ANN001
            super().__init__(args)
            self.stop_event = win32event.CreateEvent(None, 0, 0, None)
            self.worker: Worker | None = None

        def SvcStop(self) -> None:  # noqa: N802 - the SCM entry point
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            if self.worker is not None:
                self.worker.stop()
            win32event.SetEvent(self.stop_event)

        def SvcDoRun(self) -> None:  # noqa: N802 - the SCM entry point
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            config = ServiceConfig.from_env()
            _configure_logging(config)
            self.worker = Worker(config)
            self.worker.run_forever()


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv if argv is None else argv)
    if len(argv) > 1 and argv[1] == "run":
        return run()
    if sys.platform == "win32":  # pragma: no cover
        win32serviceutil.HandleCommandLine(HayabusaPyService, argv=argv)
        return 0
    print("usage: python -m service.worker run   (service control is Windows-only)", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
