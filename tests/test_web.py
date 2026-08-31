"""Local web workflow integration tests with a deterministic engine double."""

from __future__ import annotations

import json
import re
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

import pii_guard.audit_manager as audit_manager_module
from pii_guard import enhanced_audit
from pii_guard.audit_manager import AuditManager
from pii_guard.local_workflow import RESTORED_NAME, PrivateJobStore, WorkflowError
from pii_guard.web import LocalWebApplication, WebConfig, _error_status, create_server
from tests.pdf_fixtures import build_image_only_pdf, build_text_pdf
from tests.test_local_workflow import FakeEngine

ORIGINAL = "聯絡人王小明，身分證A123456789，手機0912345678。"


@pytest.mark.parametrize("code", ["DELETE_CONFLICT", "JOB_DELETING"])
def test_delete_conflicts_use_http_conflict_status(code: str) -> None:
    assert _error_status(WorkflowError(code, "safe")) == 409


def passing_enhanced_audit(
    _original: str,
    redacted: str,
    mapping: dict[str, str],
    **_kwargs: object,
) -> dict[str, object]:
    time.sleep(0.15)
    return {"passed": True, "redacted_text": redacted, "mapping": mapping}


def blocking_enhanced_audit(*_args: object, **_kwargs: object) -> dict[str, object]:
    time.sleep(10)
    return {"passed": True}


@pytest.fixture()
def running_server(tmp_path: Path):
    store = PrivateJobStore(tmp_path / "jobs", engine=FakeEngine())
    application = LocalWebApplication(store)
    server, url = create_server(application, WebConfig(port=0))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield url.rstrip("/"), server, store
    server.shutdown()
    thread.join(timeout=5)
    server.server_close()


def _url(base: str, path: str) -> str:
    return base + path


def _request(
    base: str,
    path: str,
    *,
    method: str = "GET",
    data: bytes | None = None,
    content_type: str | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 5,
) -> tuple[int, dict[str, object] | bytes]:
    request = urllib.request.Request(_url(base, path), data=data, method=method)
    if content_type:
        request.add_header("Content-Type", content_type)
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read()
            if response.headers.get_content_type() == "application/json":
                return response.status, json.loads(payload.decode("utf-8"))
            return response.status, payload
    except urllib.error.HTTPError as error:
        payload = error.read()
        try:
            decoded: dict[str, object] | bytes = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            decoded = payload
        return error.code, decoded


def _multipart(
    text: str,
    mode: str = "quick",
    *,
    filename: str = "fixture.txt",
    file_content_type: str = "text/plain",
) -> tuple[bytes, str]:
    boundary = "phase1-test-boundary"
    pieces = [
        f'--{boundary}\r\nContent-Disposition: form-data; name="mode"\r\n\r\n{mode}\r\n',
        f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
        f'filename="{filename}"\r\nContent-Type: {file_content_type}\r\n\r\n{text}\r\n',
        f"--{boundary}--\r\n",
    ]
    return "".join(pieces).encode("utf-8"), f"multipart/form-data; boundary={boundary}"


def _multipart_bytes(
    data: bytes,
    *,
    filename: str = "fixture.pdf",
    mode: str = "quick",
    file_content_type: str = "application/pdf",
) -> tuple[bytes, str]:
    boundary = "phase2-pdf-boundary"
    prefix = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="mode"\r\n\r\n'
        f'{mode}\r\n--{boundary}\r\nContent-Disposition: form-data; name="file"; '
        f'filename="{filename}"\r\nContent-Type: {file_content_type}\r\n\r\n'
    ).encode("ascii")
    suffix = f"\r\n--{boundary}--\r\n".encode("ascii")
    return prefix + data + suffix, f"multipart/form-data; boundary={boundary}"


def _assert_public_json_has_no_private_paths(payload: object, store: PrivateJobStore) -> None:
    rendered = json.dumps(payload, ensure_ascii=False)
    assert "private_work_dir" not in rendered
    assert "restored_path" not in rendered
    assert "sha256" not in rendered
    assert re.search(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", rendered) is None
    assert str(store.root) not in rendered
    assert str(Path.home()) not in rendered


def test_page_and_api_never_return_mapping_values(running_server) -> None:
    base, _server, store = running_server
    status, page = _request(base, "/")
    assert status == 200
    assert isinstance(page, bytes)
    assert b"A123456789" not in page
    assert "王小明".encode() not in page
    assert b"enhanced" in page.lower()
    assert str(store.root).encode() not in page
    assert b"~/.local/share/pii-safe-documents/jobs/" in page

    body, content_type = _multipart(ORIGINAL)
    status, result = _request(
        base, "/api/process", method="POST", data=body, content_type=content_type
    )
    assert status == 200
    assert isinstance(result, dict)
    assert result["mode"] == "quick"
    assert "A123456789" not in json.dumps(result, ensure_ascii=False)
    assert "王小明" not in json.dumps(result, ensure_ascii=False)
    assert "mapping" not in result
    assert "original" not in result
    _assert_public_json_has_no_private_paths(result, store)

    job_id = str(result["job_id"])
    status, state = _request(base, f"/api/jobs/{job_id}/state")
    assert status == 200
    assert isinstance(state, dict)
    assert "A123456789" not in json.dumps(state, ensure_ascii=False)
    assert "王小明" not in json.dumps(state, ensure_ascii=False)
    _assert_public_json_has_no_private_paths(state, store)


def test_quick_text_and_pdf_never_touch_ollama(
    running_server,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base, _server, _store = running_server

    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("quick mode touched Ollama")

    monkeypatch.setattr(enhanced_audit, "_verify_local_ollama_listener", forbidden)
    monkeypatch.setattr(enhanced_audit, "_call_ollama", forbidden)

    text_body, text_type = _multipart(ORIGINAL, mode="quick")
    text_status, _ = _request(
        base, "/api/process", method="POST", data=text_body, content_type=text_type
    )
    assert text_status == 200

    pdf_body, pdf_type = _multipart_bytes(build_text_pdf("PAGE ONE"), mode="quick")
    pdf_status, _ = _request(
        base, "/api/process", method="POST", data=pdf_body, content_type=pdf_type
    )
    assert pdf_status == 200


def test_upload_review_download_private_restore_and_delete(
    running_server, monkeypatch: pytest.MonkeyPatch
) -> None:
    base, _server, store = running_server
    body, content_type = _multipart(ORIGINAL)
    _, result = _request(base, "/api/process", method="POST", data=body, content_type=content_type)
    assert isinstance(result, dict)
    job_id = str(result["job_id"])

    # This value was intentionally left out of the fake detector so the review
    # endpoint exercises the manual annotation path.
    status, result = _request(
        base,
        f"/api/jobs/{job_id}/mask",
        method="POST",
        data=json.dumps({"terms": ["聯絡人"]}).encode("utf-8"),
        content_type="application/json",
    )
    assert status == 200
    assert isinstance(result, dict)
    assert result["terms_masked"] == 1
    assert "聯絡人" not in json.dumps(result, ensure_ascii=False)
    _assert_public_json_has_no_private_paths(result, store)

    status, downloaded = _request(base, f"/api/jobs/{job_id}/download")
    assert status == 200
    assert isinstance(downloaded, bytes)
    assert b"A123456789" not in downloaded
    assert "王小明".encode() not in downloaded

    restore_calls: list[str] = []
    real_restore = store.restore_edited_redacted

    def spy_restore(requested_job_id: str, edited_redacted: str | None = None):
        restore_calls.append(requested_job_id)
        return real_restore(requested_job_id, edited_redacted)

    monkeypatch.setattr(store, "restore_edited_redacted", spy_restore)
    status, restored = _request(
        base,
        f"/api/jobs/{job_id}/restore",
        method="POST",
        data=b"{}",
        content_type="application/json",
    )
    assert status == 200
    assert isinstance(restored, dict)
    assert restored["roundtrip_equal"] is True
    assert restore_calls == [job_id]
    _assert_public_json_has_no_private_paths(restored, store)
    restored_path = store.root / job_id / RESTORED_NAME
    assert restored_path.read_text(encoding="utf-8") == ORIGINAL

    status, deleted = _request(base, f"/api/jobs/{job_id}", method="DELETE")
    assert status == 200
    assert deleted == {"deleted": True, "job_id": job_id, "ok": True}
    status, _missing = _request(base, f"/api/jobs/{job_id}/state")
    assert status == 404
    assert not restored_path.exists()


def test_pdf_upload_review_downloads_text_and_escaped_html_then_deletes(
    running_server,
) -> None:
    base, _server, store = running_server
    pdf = build_text_pdf(
        "ID A123456789 <script>alert(1)</script>",
        "PHONE 0912345678",
    )
    body, content_type = _multipart_bytes(pdf)
    status, result = _request(
        base, "/api/process", method="POST", data=body, content_type=content_type
    )
    assert status == 200
    assert isinstance(result, dict)
    assert result["source_format"] == "pdf"
    assert result["page_count"] == 2
    rendered = json.dumps(result, ensure_ascii=False)
    assert "A123456789" not in rendered
    assert "0912345678" not in rendered
    assert "<script>" in rendered
    _assert_public_json_has_no_private_paths(result, store)
    job_id = str(result["job_id"])
    job_dir = store.root / job_id
    assert not (job_dir / "fixture.pdf").exists()
    assert not any(path.suffix.lower() == ".pdf" for path in job_dir.iterdir())

    status, masked = _request(
        base,
        f"/api/jobs/{job_id}/mask",
        method="POST",
        data=json.dumps({"terms": ["PHONE"]}).encode("utf-8"),
        content_type="application/json",
    )
    assert status == 200
    assert isinstance(masked, dict)
    assert masked["source_format"] == "pdf"
    assert masked["page_count"] == 2

    status, text_download = _request(base, f"/api/jobs/{job_id}/download?format=text")
    assert status == 200
    assert isinstance(text_download, bytes)
    assert b"A123456789" not in text_download
    assert b"0912345678" not in text_download
    assert b"<script>" in text_download

    status, html_download = _request(base, f"/api/jobs/{job_id}/download?format=html")
    assert status == 200
    assert isinstance(html_download, bytes)
    html_text = html_download.decode("utf-8")
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_text
    assert "<script" not in html_text.lower()
    assert "http://" not in html_text.lower()
    assert "https://" not in html_text.lower()
    assert "<link" not in html_text.lower()
    assert "不保留原 PDF 版面" in html_text
    assert "去識別化 PDF" in html_text

    html_request = urllib.request.Request(f"{base}/api/jobs/{job_id}/download?format=html")
    with urllib.request.urlopen(html_request, timeout=5) as html_response:
        assert html_response.headers.get_content_type() == "text/html"
        assert html_response.headers["X-Content-Type-Options"] == "nosniff"
        assert html_response.headers["Cache-Control"] == "no-store"
        assert html_response.headers["Content-Security-Policy"].find("script-src 'none'") >= 0
        assert (
            'filename="pii-guard-anonymized.html"' in html_response.headers["Content-Disposition"]
        )

    status, invalid_format = _request(base, f"/api/jobs/{job_id}/download?format=pdf")
    assert status == 400
    assert isinstance(invalid_format, dict)
    assert invalid_format["error_code"] == "INVALID_DOWNLOAD_FORMAT"
    assert "pdf" not in json.dumps(invalid_format, ensure_ascii=False).lower()

    status, restored = _request(
        base,
        f"/api/jobs/{job_id}/restore",
        method="POST",
        data=b"{}",
        content_type="application/json",
    )
    assert status == 200
    assert isinstance(restored, dict)
    assert restored["roundtrip_equal"] is True
    restored_path = job_dir / RESTORED_NAME
    assert restored_path.read_text(encoding="utf-8") == (
        "ID A123456789 <script>alert(1)</script>\n\nPHONE 0912345678"
    )

    status, deleted = _request(base, f"/api/jobs/{job_id}", method="DELETE")
    assert status == 200
    assert deleted == {"deleted": True, "job_id": job_id, "ok": True}
    assert not job_dir.exists()


@pytest.mark.parametrize(
    ("data", "filename", "file_content_type", "error_code"),
    [
        (b"not a PDF", "claimed.pdf", "application/pdf", "PDF_NOT_PDF"),
        (b"%PDF-1.4 spoof", "claimed.txt", "application/pdf", "PDF_FILENAME_MISMATCH"),
        (b"not a PDF", "claimed.exe", "application/octet-stream", "UNSUPPORTED_FORMAT"),
    ],
)
def test_pdf_filename_and_mime_spoofs_are_rejected(
    running_server,
    data: bytes,
    filename: str,
    file_content_type: str,
    error_code: str,
) -> None:
    base, _server, store = running_server
    body, content_type = _multipart_bytes(
        data, filename=filename, file_content_type=file_content_type
    )
    status, result = _request(
        base, "/api/process", method="POST", data=body, content_type=content_type
    )
    assert status == 400
    assert isinstance(result, dict)
    assert result["error_code"] == error_code
    assert "not a PDF" not in json.dumps(result, ensure_ascii=False)
    assert list(store.root.iterdir()) == []


def test_pdf_image_only_upload_is_rejected_without_creating_a_job(running_server) -> None:
    base, _server, store = running_server
    body, content_type = _multipart_bytes(build_image_only_pdf())
    status, result = _request(
        base, "/api/process", method="POST", data=body, content_type=content_type
    )
    assert status == 400
    assert isinstance(result, dict)
    assert result["error_code"] == "PDF_IMAGE_ONLY"
    assert list(store.root.iterdir()) == []


def test_enhanced_mode_withholds_until_passed_and_keeps_quick_responsive(
    tmp_path: Path,
) -> None:
    store = PrivateJobStore(tmp_path / "jobs", engine=FakeEngine())
    manager = AuditManager(store, runner=passing_enhanced_audit)
    application = LocalWebApplication(store, audit_manager=manager)
    server, url = create_server(application, WebConfig(port=0))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = url.rstrip("/")
    try:
        body, content_type = _multipart(ORIGINAL, mode="enhanced")
        status, result = _request(
            base, "/api/process", method="POST", data=body, content_type=content_type
        )
        assert status == 202
        assert isinstance(result, dict)
        assert result["audit_status"] == "queued"
        assert "anonymized_text" not in result
        assert "placeholders" not in result
        job_id = str(result["job_id"])

        download_status, _ = _request(base, f"/api/jobs/{job_id}/download")
        assert download_status == 409
        mask_status, _ = _request(
            base,
            f"/api/jobs/{job_id}/mask",
            method="POST",
            data=json.dumps({"terms": ["聯絡人"]}).encode("utf-8"),
            content_type="application/json",
        )
        assert mask_status == 409
        restore_status, _ = _request(
            base,
            f"/api/jobs/{job_id}/restore",
            method="POST",
            data=b"",
            content_type="application/json",
        )
        assert restore_status == 409

        quick_body, quick_type = _multipart("聯絡人王小明", mode="quick")
        quick_status, quick = _request(
            base,
            "/api/process",
            method="POST",
            data=quick_body,
            content_type=quick_type,
        )
        assert quick_status == 200
        assert isinstance(quick, dict)
        assert quick["mode"] == "quick"

        deadline = time.monotonic() + 8
        state: dict[str, object] = {}
        while time.monotonic() < deadline:
            state_status, payload = _request(base, f"/api/jobs/{job_id}/state")
            assert state_status == 200
            assert isinstance(payload, dict)
            state = payload
            if state.get("audit_status") == "passed":
                break
            assert "anonymized_text" not in state
            time.sleep(0.02)
        assert state["audit_status"] == "passed"
        assert "anonymized_text" in state
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_default_web_manager_never_marks_fresh_job_interrupted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = PrivateJobStore(tmp_path / "jobs", engine=FakeEngine())
    real_manager = AuditManager

    def manager_factory(store_value: object, **kwargs: object) -> AuditManager:
        return real_manager(store_value, runner=passing_enhanced_audit, **kwargs)

    monkeypatch.setattr(audit_manager_module, "AuditManager", manager_factory)
    application = LocalWebApplication(store)
    receipt = application.process(ORIGINAL, "fake.txt", "enhanced")
    job_id = str(receipt["job_id"])
    observed: list[str] = [str(receipt["audit_status"])]
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        state = application.state(job_id)
        observed.append(str(state["audit_status"]))
        if state["audit_status"] == "passed":
            break
        time.sleep(0.01)

    assert observed[-1] == "passed"
    assert "interrupted" not in observed
    application.close()


def test_enhanced_http_cancel_and_restart(tmp_path: Path) -> None:
    store = PrivateJobStore(tmp_path / "jobs", engine=FakeEngine())
    manager = AuditManager(store, runner=blocking_enhanced_audit, timeout_seconds=30)
    application = LocalWebApplication(store, audit_manager=manager)
    server, url = create_server(application, WebConfig(port=0))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = url.rstrip("/")
    try:
        body, content_type = _multipart(ORIGINAL, mode="enhanced")
        status, result = _request(
            base, "/api/process", method="POST", data=body, content_type=content_type
        )
        assert status == 202
        assert isinstance(result, dict)
        job_id = str(result["job_id"])

        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            _, state = _request(base, f"/api/jobs/{job_id}/state")
            assert isinstance(state, dict)
            if state.get("audit_status") == "running":
                break
            time.sleep(0.02)
        assert state["audit_status"] == "running"

        cancel_status, cancelled = _request(
            base,
            f"/api/jobs/{job_id}/audit/cancel",
            method="POST",
            data=b"",
            content_type="application/json",
            timeout=15,
        )
        assert cancel_status == 200
        assert isinstance(cancelled, dict)
        assert cancelled["audit_status"] == "cancelled"
        assert "anonymized_text" not in cancelled

        manager.runner = passing_enhanced_audit
        restart_status, restarted = _request(
            base,
            f"/api/jobs/{job_id}/audit/restart",
            method="POST",
            data=b"",
            content_type="application/json",
        )
        assert restart_status == 202
        assert isinstance(restarted, dict)
        assert restarted["audit_status"] == "queued"

        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            _, state = _request(base, f"/api/jobs/{job_id}/state")
            assert isinstance(state, dict)
            if state.get("audit_status") == "passed":
                break
            time.sleep(0.02)
        assert state["audit_status"] == "passed"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_host_header_and_job_traversal_are_rejected(running_server) -> None:
    base, _server, _store = running_server
    status, _body = _request(base, "/", headers={"Host": "evil.example"})
    assert status == 404
    status, result = _request(base, "/api/jobs/../state")
    assert status in {400, 404}
    assert isinstance(result, dict)
