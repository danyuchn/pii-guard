"""Enhanced audit lifecycle tests using only deterministic child doubles."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest

from pii_guard.audit_manager import AuditManager, _result_payload
from pii_guard.local_workflow import (
    MANIFEST_NAME,
    RESTORED_NAME,
    PrivateJobStore,
    WorkflowError,
)
from tests.pdf_fixtures import build_text_pdf


class FakeEngine:
    def anonymize(self, text: str) -> tuple[str, dict[str, str]]:
        marker = "王小明"
        placeholder = "<PERSON_1>"
        if marker not in text:
            return text, {}
        return text.replace(marker, placeholder), {placeholder: marker}


def passing_audit(
    original: str,
    redacted: str,
    mapping: dict[str, str],
    **_kwargs: object,
) -> dict[str, object]:
    return {"passed": True, "redacted_text": redacted, "mapping": mapping}


def failing_audit(*_args: object, **_kwargs: object) -> object:
    raise RuntimeError("private model detail must not escape")


def incomplete_audit(
    _original: str,
    redacted: str,
    _mapping: dict[str, str],
    **_kwargs: object,
) -> dict[str, object]:
    return {"passed": True, "redacted_text": redacted, "mapping": {}}


def blocking_audit(*_args: object, **_kwargs: object) -> object:
    time.sleep(10)
    return {"passed": True}


def _store(tmp_path: Path) -> PrivateJobStore:
    return PrivateJobStore(tmp_path / "jobs", engine=FakeEngine())


def _wait_for(
    store: PrivateJobStore, job_id: str, status: str, timeout: float = 8.0
) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = store.public_state(job_id)
        if state.get("audit_status") == status:
            return state
        time.sleep(0.02)
    raise AssertionError(f"timed out waiting for {status}")


def test_pending_enhanced_receipt_has_no_private_text_or_mapping(tmp_path: Path) -> None:
    store = _store(tmp_path)
    manager = AuditManager(store, runner=passing_audit)
    pending = store.prepare_enhanced_from_text("聯絡人王小明。")

    assert pending == {
        "ok": True,
        "job_id": pending["job_id"],
        "mode": "enhanced",
        "audit_status": "queued",
        "source_format": "text",
        "progress": {"completed": 0, "total": 0, "scope": "enhanced_audit"},
    }
    assert "anonymized_text" not in json.dumps(pending, ensure_ascii=False)
    assert "王小明" not in json.dumps(pending, ensure_ascii=False)
    manager.close()


@pytest.mark.parametrize("result", [None, {}, {"passed": True}])
def test_empty_audit_result_fails_closed(result: object) -> None:
    assert _result_payload(result) == {"ok": False, "code": "AUDIT_INVALID_RESULT"}


def test_enhanced_pass_releases_exact_roundtrip(tmp_path: Path) -> None:
    store = _store(tmp_path)
    manager = AuditManager(store, runner=passing_audit)
    pending = store.prepare_enhanced_from_text("聯絡人王小明。")
    job_id = str(pending["job_id"])

    running = manager.start(job_id)
    assert running["audit_status"] == "running"
    assert "anonymized_text" not in running
    passed = _wait_for(store, job_id, "passed")
    assert passed["mode"] == "enhanced"
    assert passed["audit_status"] == "passed"
    assert passed["anonymized_text"] != "聯絡人王小明。"
    assert store.restore_to_private(job_id)["roundtrip_equal"] is True
    manager.close()


def test_second_enhanced_start_is_busy_and_cancel_cleans_attempt(tmp_path: Path) -> None:
    store = _store(tmp_path)
    manager = AuditManager(store, runner=blocking_audit, timeout_seconds=30)
    pending = store.prepare_enhanced_from_text("聯絡人王小明。")
    job_id = str(pending["job_id"])
    manager.start(job_id)
    with pytest.raises(WorkflowError, match="ENHANCED_BUSY"):
        manager.start(job_id)

    cancelled = manager.cancel(job_id)
    assert cancelled["audit_status"] == "cancelled"
    assert not any((store.root / job_id).glob(".attempt-*"))
    assert "anonymized_text" not in cancelled
    manager.close()


def test_failure_retains_quick_baseline_and_explicit_restart_passes(tmp_path: Path) -> None:
    store = _store(tmp_path)
    manager = AuditManager(store, runner=failing_audit)
    pending = store.prepare_enhanced_from_text("聯絡人王小明。")
    job_id = str(pending["job_id"])
    manager.start(job_id)
    failed = _wait_for(store, job_id, "failed")
    assert "anonymized_text" not in failed
    state = store.load_state(job_id)
    assert state.redacted != state.original
    assert not any((store.root / job_id).glob(".attempt-*"))

    manager.runner = passing_audit
    manager.restart(job_id)
    passed = _wait_for(store, job_id, "passed")
    assert passed["audit_status"] == "passed"
    manager.close()


def test_incomplete_mapping_result_fails_closed(tmp_path: Path) -> None:
    store = _store(tmp_path)
    manager = AuditManager(store, runner=incomplete_audit)
    pending = store.prepare_enhanced_from_text("聯絡人王小明。")
    job_id = str(pending["job_id"])

    manager.start(job_id)
    failed = _wait_for(store, job_id, "failed")

    assert failed["error_code"] == "AUDIT_INVALID_RESULT"
    assert "anonymized_text" not in failed
    manager.close()


def test_pdf_page_count_mode_survive_pass_manual_mask_and_restore(tmp_path: Path) -> None:
    store = _store(tmp_path)
    manager = AuditManager(store, runner=passing_audit)
    pending = store.prepare_enhanced_from_pdf_bytes(build_text_pdf("PAGE ONE", "PAGE TWO"))
    job_id = str(pending["job_id"])
    assert pending["source_format"] == "pdf"
    assert pending["page_count"] == 2
    manager.start(job_id)
    _wait_for(store, job_id, "passed")
    reviewed = store.mask_terms(job_id, ["PAGE"])
    assert reviewed["mode"] == "enhanced"
    assert reviewed["audit_status"] == "passed"
    assert reviewed["page_count"] == 2
    restored = store.restore_to_private(job_id)
    assert restored["roundtrip_equal"] is True
    assert (store.root / job_id / RESTORED_NAME).read_text(encoding="utf-8") == (
        "PAGE ONE\n\nPAGE TWO"
    )
    manager.close()


def test_stale_attempt_cannot_commit(tmp_path: Path) -> None:
    store = _store(tmp_path)
    pending = store.prepare_enhanced_from_text("聯絡人王小明。")
    job_id = str(pending["job_id"])
    attempt = store._begin_enhanced_attempt(job_id)
    job_dir = store.root / job_id
    manifest = json.loads((job_dir / MANIFEST_NAME).read_text(encoding="utf-8"))
    manifest["audit_attempt_token"] = "f" * 32
    (job_dir / MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")
    assert store._finish_enhanced_attempt(attempt, status="passed", result={}) is False
    assert store.public_state(job_id)["audit_status"] == "running"


def test_manager_startup_marks_stale_running_job_interrupted(tmp_path: Path) -> None:
    store = _store(tmp_path)
    pending = store.prepare_enhanced_from_text("聯絡人王小明。")
    job_id = str(pending["job_id"])
    store._begin_enhanced_attempt(job_id)

    manager = AuditManager(store, runner=passing_audit)

    state = store.public_state(job_id)
    assert state["audit_status"] == "interrupted"
    assert state["error_code"] == "AUDIT_INTERRUPTED"
    assert "anonymized_text" not in state
    manager.close()


def test_second_manager_cannot_interrupt_live_owner(tmp_path: Path) -> None:
    store = _store(tmp_path)
    first = AuditManager(store, runner=blocking_audit, timeout_seconds=30)
    pending = store.prepare_enhanced_from_text("聯絡人王小明。")
    job_id = str(pending["job_id"])
    first.start(job_id)

    with pytest.raises(WorkflowError, match="ENHANCED_BUSY"):
        AuditManager(store, runner=passing_audit)

    assert store.public_state(job_id)["audit_status"] == "running"
    first.close()


def test_prelaunch_failure_marks_attempt_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    manager = AuditManager(store, runner=passing_audit)
    pending = store.prepare_enhanced_from_text("聯絡人王小明。")
    job_id = str(pending["job_id"])

    def fail_attempt_dir(_attempt: object) -> Path:
        raise OSError("injected")

    monkeypatch.setattr(manager, "_new_attempt_dir", fail_attempt_dir)
    with pytest.raises(WorkflowError, match="AUDIT_UNAVAILABLE"):
        manager.start(job_id)

    state = store.public_state(job_id)
    assert state["audit_status"] == "failed"
    assert state["error_code"] == "AUDIT_UNAVAILABLE"
    manager.close()


def test_monitor_start_failure_stops_child_and_marks_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    manager = AuditManager(store, runner=blocking_audit, timeout_seconds=30)
    pending = store.prepare_enhanced_from_text("聯絡人王小明。")
    job_id = str(pending["job_id"])
    real_start = threading.Thread.start

    def fail_monitor_start(thread: threading.Thread) -> None:
        if thread.name == "pii-guard-enhanced-audit":
            raise RuntimeError("injected monitor failure")
        real_start(thread)

    monkeypatch.setattr(threading.Thread, "start", fail_monitor_start)
    with pytest.raises(WorkflowError, match="AUDIT_UNAVAILABLE"):
        manager.start(job_id)

    state = store.public_state(job_id)
    assert state["audit_status"] == "failed"
    assert state["error_code"] == "AUDIT_UNAVAILABLE"
    assert manager.status()["active"] is False
    manager.close()


def test_close_failure_still_releases_manager_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    first = AuditManager(store, runner=blocking_audit, timeout_seconds=30)
    pending = store.prepare_enhanced_from_text("聯絡人王小明。")
    first.start(str(pending["job_id"]))
    real_finish = store._finish_enhanced_attempt

    def fail_finish(*_args: object, **_kwargs: object) -> bool:
        raise WorkflowError("INJECTED", "injected")

    monkeypatch.setattr(store, "_finish_enhanced_attempt", fail_finish)
    first.close()
    monkeypatch.setattr(store, "_finish_enhanced_attempt", real_finish)

    second = AuditManager(store, runner=passing_audit)
    second.close()


def test_monitor_retries_transient_terminal_publication_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    manager = AuditManager(store, runner=failing_audit)
    pending = store.prepare_enhanced_from_text("聯絡人王小明。")
    job_id = str(pending["job_id"])
    real_finish = store._finish_enhanced_attempt
    calls = 0

    def flaky_finish(*args: object, **kwargs: object) -> bool:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise WorkflowError("INJECTED", "injected transient failure")
        return real_finish(*args, **kwargs)

    monkeypatch.setattr(store, "_finish_enhanced_attempt", flaky_finish)
    manager.start(job_id)

    failed = _wait_for(store, job_id, "failed")
    assert calls == 2
    assert failed["error_code"] == "AUDIT_FAILED"
    assert manager.status()["active"] is False
    manager.close()


def test_persistent_terminal_publication_failure_keeps_manager_owned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    manager = AuditManager(store, runner=failing_audit)
    pending = store.prepare_enhanced_from_text("聯絡人王小明。")
    job_id = str(pending["job_id"])
    real_finish = store._finish_enhanced_attempt

    def fail_finish(*_args: object, **_kwargs: object) -> bool:
        raise WorkflowError("INJECTED", "injected persistent failure")

    monkeypatch.setattr(store, "_finish_enhanced_attempt", fail_finish)
    manager.start(job_id)
    assert manager._monitor is not None
    manager._monitor.join(8)

    assert store.public_state(job_id)["audit_status"] == "running"
    assert manager.status()["active"] is True
    with pytest.raises(WorkflowError, match="AUDIT_UNAVAILABLE"):
        manager.restart(job_id)

    monkeypatch.setattr(store, "_finish_enhanced_attempt", real_finish)
    cancelled = manager.cancel(job_id)
    assert cancelled["audit_status"] == "cancelled"
    assert manager.status()["active"] is False
    manager.close()


def test_rejected_terminal_publication_keeps_manager_owned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    manager = AuditManager(store, runner=failing_audit)
    pending = store.prepare_enhanced_from_text("聯絡人王小明。")
    job_id = str(pending["job_id"])
    real_finish = store._finish_enhanced_attempt

    monkeypatch.setattr(store, "_finish_enhanced_attempt", lambda *_args, **_kwargs: False)
    manager.start(job_id)
    assert manager._monitor is not None
    manager._monitor.join(8)

    assert store.public_state(job_id)["audit_status"] == "running"
    assert manager.status()["active"] is True

    monkeypatch.setattr(store, "_finish_enhanced_attempt", real_finish)
    manager.cancel(job_id)
    manager.close()
