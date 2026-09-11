"""The upload site: a technician posts a log, watches the job, downloads the timeline.

Access control is handled upstream of this app (the reverse proxy in front of it), so there is no
login here. What the app does own is everything an upstream proxy cannot check for it: the shape
and size of what gets written to disk, the fact that a job id can only ever name a directory the
service itself created, and an audit line per job.

Deliberately server-rendered and dependency-light: no JavaScript framework, no client-side state,
and the only thing the browser is asked to run is a meta-refresh on the job page.
"""

from __future__ import annotations

import logging
import re
import time
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from service import db
from service.config import ServiceConfig
from service.db import JobStore
from service.uploads import UploadRejected, safe_display_name, store_async_stream

JOB_ID_RE = re.compile(r"^[0-9a-f]{32}$")
RESULT_FILES = {
    "timeline.jsonl": "application/x-ndjson",
    "timeline.csv": "text/csv",
    "summary.json": "application/json",
    "scan.log": "text/plain",
}

audit = logging.getLogger("hayabusa_py.audit")
TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def get_config() -> ServiceConfig:
    return ServiceConfig.from_env()


def get_store(config: Annotated[ServiceConfig, Depends(get_config)]) -> JobStore:
    config.ensure_dirs()
    return JobStore(config.db_path)


ConfigDep = Annotated[ServiceConfig, Depends(get_config)]
StoreDep = Annotated[JobStore, Depends(get_store)]


def create_app(config: ServiceConfig | None = None) -> FastAPI:
    # redirect_slashes off: a path the app does not serve should 404, not bounce the client
    # through a redirect that echoes the path back at it.
    app = FastAPI(title="Hayabusa timeline service", docs_url=None, redoc_url=None, redirect_slashes=False)
    if config is not None:
        app.dependency_overrides[get_config] = lambda: config

    @app.middleware("http")
    async def security_headers(request: Request, call_next):  # noqa: ANN001, ANN202
        response = await call_next(request)
        # The pages are self-contained: no external scripts, styles, frames or form targets.
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        )
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response

    @app.get("/healthz")
    def healthz(store: StoreDep) -> JSONResponse:
        return JSONResponse({"status": "ok", "jobs": store.counts()})

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request, store: StoreDep) -> Any:
        return TEMPLATES.TemplateResponse(
            request, "index.html", {"jobs": store.list(limit=50), "now": time.time()}
        )

    @app.post("/jobs")
    async def submit(
        request: Request,
        config: ConfigDep,
        store: StoreDep,
        file: Annotated[UploadFile, File()],
        submitted_by: Annotated[str, Form()] = "",
    ) -> Any:
        job = store.create(
            filename=safe_display_name(file.filename or "upload"),
            size_bytes=0,
            sha256="",
            submitted_by=_identity(request, submitted_by),
        )
        destination = config.job_upload_dir(job.id) / "upload.bin"
        try:
            stored = await store_async_stream(
                _stream(file), destination, max_bytes=config.max_upload_bytes, filename=file.filename or ""
            )
        except UploadRejected as exc:
            store.fail(job.id, str(exc))
            return _problem(request, str(exc), status=413 if "larger than" in str(exc) else 400)
        with store._connect() as conn:  # noqa: SLF001 - the store is this module's own
            conn.execute(
                "UPDATE jobs SET size_bytes = ?, sha256 = ? WHERE id = ?",
                (stored.size_bytes, stored.sha256, job.id),
            )
        audit.info(
            "job=%s accepted file=%s bytes=%d sha256=%s by=%s",
            job.id, stored.display_name, stored.size_bytes, stored.sha256, job.submitted_by,
        )
        if _wants_json(request):
            return JSONResponse({"job": job.id, "url": f"/jobs/{job.id}"}, status_code=202)
        return RedirectResponse(f"/jobs/{job.id}", status_code=303)

    @app.get("/jobs/{job_id}", response_class=HTMLResponse)
    def job_page(request: Request, job_id: str, config: ConfigDep, store: StoreDep) -> Any:
        job = _require_job(store, job_id)
        results = _available_results(config, job_id)
        if _wants_json(request):
            return JSONResponse(_job_json(job, results))
        return TEMPLATES.TemplateResponse(
            request, "job.html", {"job": job, "results": results, "now": time.time()}
        )

    @app.get("/jobs/{job_id}/files/{name}")
    def download(job_id: str, name: str, config: ConfigDep, store: StoreDep) -> FileResponse:
        _require_job(store, job_id)
        media_type = RESULT_FILES.get(name)
        if media_type is None:
            raise HTTPException(status_code=404, detail="no such result file")
        path = config.job_result_dir(job_id) / name
        if not path.is_file():
            raise HTTPException(status_code=404, detail="that result is not ready")
        return FileResponse(path, media_type=media_type, filename=f"{job_id[:8]}-{name}")

    @app.post("/jobs/{job_id}/cancel")
    def cancel(request: Request, job_id: str, store: StoreDep) -> Any:
        job = _require_job(store, job_id)
        cancelled = store.cancel(job.id)
        audit.info("job=%s cancel requested (applied=%s)", job.id, cancelled)
        if _wants_json(request):
            return JSONResponse({"cancelled": cancelled})
        return RedirectResponse(f"/jobs/{job_id}", status_code=303)

    return app


# -- helpers -----------------------------------------------------------------------------------


async def _stream(file: UploadFile, chunk_size: int = 1024 * 1024):  # noqa: ANN202
    """UploadFile in chunks. Starlette spools to disk past a threshold, so this never
    materialises a multi-gigabyte upload in memory."""
    while True:
        chunk = await file.read(chunk_size)
        if not chunk:
            return
        yield chunk


def _identity(request: Request, submitted_by: str) -> str:
    """Who submitted this, for the audit line.

    The upstream proxy is the only trustworthy source: it authenticates the technician and passes
    the result in a header. A value typed into the form is a label, not an identity, and is
    recorded as such.
    """
    for header in ("x-forwarded-user", "x-authenticated-user", "x-remote-user"):
        value = request.headers.get(header, "").strip()
        if value:
            return _safe_identity(value, 64)
    if submitted_by.strip():
        return f"(unverified) {_safe_identity(submitted_by, 48)}"
    return "(unknown)"


_IDENTITY_RE = re.compile(r"[^A-Za-z0-9._@\\/+ -]+")


def _safe_identity(value: str, limit: int) -> str:
    """A header or form value, safe to write to a log line and render in a page.

    Keeps what real identities are made of (``CORP\\jose``, ``jose@example.org``, a ticket
    reference) and drops everything else, control characters and newlines included, so nothing
    can forge an extra audit line or break out of the HTML it is rendered into.
    """
    cleaned = _IDENTITY_RE.sub("_", value.strip())
    return cleaned[:limit] or "(unknown)"


def _wants_json(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    return "application/json" in accept and "text/html" not in accept


def _require_job(store: JobStore, job_id: str):  # noqa: ANN202
    """A job id is only ever a hex uuid the service generated; anything else is not looked up.

    This is what keeps a path segment from reaching the filesystem: the id is validated by shape
    before it is used to build a directory name.
    """
    if not JOB_ID_RE.match(job_id):
        raise HTTPException(status_code=404, detail="no such job")
    job = store.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="no such job")
    return job


def _available_results(config: ServiceConfig, job_id: str) -> list[tuple[str, int]]:
    directory = config.job_result_dir(job_id)
    found = []
    for name in RESULT_FILES:
        path = directory / name
        if path.is_file():
            found.append((name, path.stat().st_size))
    return found


def _job_json(job, results: list[tuple[str, int]]) -> dict[str, Any]:  # noqa: ANN001
    return {
        "id": job.id,
        "state": job.state,
        "filename": job.filename,
        "size_bytes": job.size_bytes,
        "sha256": job.sha256,
        "submitted_by": job.submitted_by,
        "created_at": job.created_at,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "error": job.error,
        "summary": job.summary,
        "results": [{"name": name, "size_bytes": size} for name, size in results],
    }


def _problem(request: Request, message: str, *, status: int) -> Any:
    if _wants_json(request):
        return JSONResponse({"error": message}, status_code=status)
    return TEMPLATES.TemplateResponse(request, "error.html", {"message": message}, status_code=status)


app = create_app()


def main() -> int:  # pragma: no cover - the console entry point
    import uvicorn

    config = ServiceConfig.from_env()
    config.ensure_dirs()
    uvicorn.run("service.app:app", host="127.0.0.1", port=8000, workers=1)
    return 0


# Jinja needs these to render sizes and times without a filter library.
TEMPLATES.env.filters["mb"] = lambda value: f"{(value or 0) / 1024**2:,.1f}"
TEMPLATES.env.filters["ago"] = lambda value: _ago(value)
TEMPLATES.env.filters["stamp"] = lambda value: time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(value)) if value else "-"


def _ago(value: float | None) -> str:
    if not value:
        return "-"
    seconds = max(0, int(time.time() - value))
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"


__all__ = ["app", "create_app", "db", "main"]
