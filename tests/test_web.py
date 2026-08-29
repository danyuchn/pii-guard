"""Local web workflow integration tests with a deterministic engine double."""

from __future__ import annotations

import json
import re
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from pii_guard.local_workflow import RESTORED_NAME, PrivateJobStore
from pii_guard.web import LocalWebApplication, WebConfig, create_server
from tests.test_local_workflow import FakeEngine

ORIGINAL = "聯絡人王小明，身分證A123456789，手機0912345678。"


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
) -> tuple[int, dict[str, object] | bytes]:
    request = urllib.request.Request(_url(base, path), data=data, method=method)
    if content_type:
        request.add_header("Content-Type", content_type)
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
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


def _multipart(text: str, mode: str = "quick") -> tuple[bytes, str]:
    boundary = "phase1-test-boundary"
    pieces = [
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"mode\"\r\n\r\n{mode}\r\n",
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
        f"filename=\"fixture.txt\"\r\nContent-Type: text/plain\r\n\r\n{text}\r\n",
        f"--{boundary}--\r\n",
    ]
    return "".join(pieces).encode("utf-8"), f"multipart/form-data; boundary={boundary}"


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


def test_enhanced_mode_is_explicitly_unavailable(running_server) -> None:
    base, _server, store = running_server
    body, content_type = _multipart(ORIGINAL, mode="enhanced")
    status, result = _request(
        base, "/api/process", method="POST", data=body, content_type=content_type
    )
    assert status == 400
    assert isinstance(result, dict)
    assert result["error_code"] == "MODE_UNAVAILABLE"
    assert "A123456789" not in json.dumps(result, ensure_ascii=False)
    _assert_public_json_has_no_private_paths(result, store)


def test_host_header_and_job_traversal_are_rejected(running_server) -> None:
    base, _server, _store = running_server
    status, _body = _request(base, "/", headers={"Host": "evil.example"})
    assert status == 404
    status, result = _request(base, "/api/jobs/../state")
    assert status in {400, 404}
    assert isinstance(result, dict)
