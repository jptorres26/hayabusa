"""Tests for the upload site: what it accepts, what it refuses, and what a job id may name."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from service.app import create_app, get_store
from service.config import ServiceConfig
from service.db import DONE, FAILED, QUEUED, JobStore
from service.uploads import EVTX_MAGIC

JSON = {"accept": "application/json"}


@pytest.fixture
def config(tmp_path: Path) -> ServiceConfig:
    config = ServiceConfig(data_dir=tmp_path / "data", max_upload_bytes=4096)
    config.ensure_dirs()
    return config


@pytest.fixture
def store(config: ServiceConfig) -> JobStore:
    return JobStore(config.db_path)


@pytest.fixture
def client(config: ServiceConfig, store: JobStore) -> TestClient:
    app = create_app(config)
    app.dependency_overrides[get_store] = lambda: store
    return TestClient(app)


def evtx(size: int = 512) -> bytes:
    return EVTX_MAGIC + b"\x00" * (size - len(EVTX_MAGIC))


def upload(client: TestClient, content: bytes, name: str = "Security.evtx", **kwargs):  # noqa: ANN201
    return client.post(
        "/jobs", files={"file": (name, io.BytesIO(content), "application/octet-stream")}, **kwargs
    )


# -- submitting ------------------------------------------------------------------------------


def test_an_upload_creates_a_queued_job(client: TestClient, store: JobStore, config: ServiceConfig) -> None:
    response = upload(client, evtx(), headers=JSON)
    assert response.status_code == 202
    job_id = response.json()["job"]
    job = store.get(job_id)
    assert job.state == QUEUED
    assert job.filename == "Security.evtx"
    assert job.size_bytes == 512
    assert len(job.sha256) == 64
    assert (config.job_upload_dir(job_id) / "upload.bin").read_bytes() == evtx()


def test_a_browser_upload_redirects_to_the_job_page(client: TestClient) -> None:
    response = upload(client, evtx(), follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"].startswith("/jobs/")


def test_an_oversized_upload_is_refused_and_marked_failed(client: TestClient, store: JobStore) -> None:
    response = upload(client, evtx(8192), headers=JSON)
    assert response.status_code == 413
    assert "larger than" in response.json()["error"]
    assert store.list()[0].state == FAILED


def test_an_oversized_upload_leaves_nothing_on_disk(client: TestClient, store: JobStore, config: ServiceConfig) -> None:
    upload(client, evtx(8192), headers=JSON)
    job = store.list()[0]
    assert not (config.job_upload_dir(job.id) / "upload.bin").exists()


def test_an_empty_upload_is_refused(client: TestClient) -> None:
    response = upload(client, b"", headers=JSON)
    assert response.status_code == 400
    assert "empty" in response.json()["error"]


def test_the_stored_filename_cannot_contain_a_path(client: TestClient, store: JobStore) -> None:
    upload(client, evtx(), name="../../etc/passwd", headers=JSON)
    assert store.list()[0].filename == "passwd"


def test_a_proxy_identity_is_trusted_over_the_form_field(client: TestClient, store: JobStore) -> None:
    client.post(
        "/jobs",
        files={"file": ("a.evtx", io.BytesIO(evtx()), "application/octet-stream")},
        data={"submitted_by": "someone else"},
        headers={**JSON, "x-forwarded-user": "jose@example.org"},
    )
    assert store.list()[0].submitted_by == "jose@example.org"


def test_an_identity_cannot_forge_a_log_line_or_markup(client: TestClient, store: JobStore) -> None:
    client.post(
        "/jobs",
        files={"file": ("a.evtx", io.BytesIO(evtx()), "application/octet-stream")},
        headers={**JSON, "x-forwarded-user": "jose\r\nfake=admin <b>x</b>"},
    )
    recorded = store.list()[0].submitted_by
    assert "\n" not in recorded and "<" not in recorded
    assert recorded.startswith("jose")


def test_a_form_supplied_name_is_marked_unverified(client: TestClient, store: JobStore) -> None:
    client.post(
        "/jobs",
        files={"file": ("a.evtx", io.BytesIO(evtx()), "application/octet-stream")},
        data={"submitted_by": "INC0012345"},
        headers=JSON,
    )
    assert store.list()[0].submitted_by == "(unverified) INC0012345"


# -- viewing ---------------------------------------------------------------------------------


def test_the_job_page_renders(client: TestClient) -> None:
    job_id = upload(client, evtx(), headers=JSON).json()["job"]
    page = client.get(f"/jobs/{job_id}")
    assert page.status_code == 200
    assert "queued" in page.text
    assert "Security.evtx" in page.text


def test_the_index_lists_jobs(client: TestClient) -> None:
    upload(client, evtx(), name="First.evtx", headers=JSON)
    page = client.get("/")
    assert page.status_code == 200
    assert "First.evtx" in page.text


@pytest.mark.parametrize(
    "job_id",
    ["../../etc/passwd", "..%2f..%2fetc", "not-a-uuid", "0" * 31, "g" * 32, "%2e%2e%2f"],
)
def test_a_job_id_that_is_not_a_uuid_is_never_looked_up(client: TestClient, job_id: str) -> None:
    assert client.get(f"/jobs/{job_id}", headers=JSON).status_code == 404


def test_an_unknown_job_is_404(client: TestClient) -> None:
    assert client.get(f"/jobs/{'0' * 32}", headers=JSON).status_code == 404


# -- downloading -----------------------------------------------------------------------------


def test_results_download_once_they_exist(client: TestClient, config: ServiceConfig) -> None:
    job_id = upload(client, evtx(), headers=JSON).json()["job"]
    results = config.job_result_dir(job_id)
    results.mkdir(parents=True)
    (results / "timeline.csv").write_text("Timestamp,RuleTitle\n", encoding="utf-8")

    response = client.get(f"/jobs/{job_id}/files/timeline.csv")
    assert response.status_code == 200
    assert response.text.startswith("Timestamp")
    assert "attachment" in response.headers["content-disposition"]


def test_a_result_that_is_not_ready_is_404(client: TestClient) -> None:
    job_id = upload(client, evtx(), headers=JSON).json()["job"]
    assert client.get(f"/jobs/{job_id}/files/timeline.csv").status_code == 404


@pytest.mark.parametrize("name", ["../../../etc/passwd", "upload.bin", "..%2fsummary.json", "scan.log.bak"])
def test_only_known_result_names_can_be_downloaded(client: TestClient, config: ServiceConfig, name: str) -> None:
    job_id = upload(client, evtx(), headers=JSON).json()["job"]
    config.job_result_dir(job_id).mkdir(parents=True)
    assert client.get(f"/jobs/{job_id}/files/{name}").status_code == 404


def test_a_download_cannot_escape_the_job_directory(client: TestClient, config: ServiceConfig, tmp_path: Path) -> None:
    secret = tmp_path / "secret.txt"
    secret.write_text("do not serve me", encoding="utf-8")
    job_id = upload(client, evtx(), headers=JSON).json()["job"]
    for attempt in (f"../../{secret.name}", f"..%2F..%2F{secret.name}", str(secret)):
        response = client.get(f"/jobs/{job_id}/files/{attempt}")
        assert response.status_code == 404
        assert "do not serve me" not in response.text


# -- cancelling ------------------------------------------------------------------------------


def test_a_queued_job_can_be_cancelled(client: TestClient, store: JobStore) -> None:
    job_id = upload(client, evtx(), headers=JSON).json()["job"]
    assert client.post(f"/jobs/{job_id}/cancel", headers=JSON).json() == {"cancelled": True}
    assert store.get(job_id).state == "cancelled"


def test_a_running_job_is_not_cancelled(client: TestClient, store: JobStore) -> None:
    job_id = upload(client, evtx(), headers=JSON).json()["job"]
    store.claim_next()
    assert client.post(f"/jobs/{job_id}/cancel", headers=JSON).json() == {"cancelled": False}


# -- the rest --------------------------------------------------------------------------------


def test_health_reports_the_queue(client: TestClient) -> None:
    upload(client, evtx(), headers=JSON)
    body = client.get("/healthz").json()
    assert body["status"] == "ok"
    assert body["jobs"] == {QUEUED: 1}


def test_security_headers_are_set(client: TestClient) -> None:
    headers = client.get("/").headers
    assert "default-src 'none'" in headers["content-security-policy"]
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["referrer-policy"] == "no-referrer"


def test_the_job_json_view_reports_the_summary(client: TestClient, store: JobStore) -> None:
    job_id = upload(client, evtx(), headers=JSON).json()["job"]
    store.claim_next()
    store.finish(job_id, {"detections": 12, "events": 100})
    body = client.get(f"/jobs/{job_id}", headers=JSON).json()
    assert body["state"] == DONE
    assert body["summary"]["detections"] == 12


def test_a_zip_upload_is_accepted_for_scanning(client: TestClient, store: JobStore) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("Security.evtx", evtx())
    response = upload(client, buffer.getvalue(), name="logs.zip", headers=JSON)
    assert response.status_code == 202
    assert store.get(response.json()["job"]).filename == "logs.zip"


def test_a_declared_oversize_length_is_refused_before_the_body_is_read(client: TestClient) -> None:
    """The common case should be refused from the header, not after spooling gigabytes."""
    response = client.post(
        "/jobs",
        content=b"x" * 100,
        headers={**JSON, "content-length": "100", "x-test": "1"},
    )
    # a well-formed but tiny body still fails validation; the point of the next call is the header
    assert response.status_code in (400, 413, 422)

    big = client.post(
        "/jobs",
        files={"file": ("a.evtx", io.BytesIO(evtx()), "application/octet-stream")},
        headers={**JSON, "content-length": str(10 * 1024**3)},
    )
    assert big.status_code == 413


def test_the_audit_log_records_the_upload(client: TestClient, caplog) -> None:
    import logging

    with caplog.at_level(logging.INFO, logger="hayabusa_py.audit"):
        upload(client, evtx(), name="Security.evtx", headers=JSON)
    line = "\n".join(record.getMessage() for record in caplog.records)
    assert "accepted" in line
    assert "Security.evtx" in line
    assert "sha256=" in line
