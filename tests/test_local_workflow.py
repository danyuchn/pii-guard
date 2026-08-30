"""Shared quick-mode private job workflow tests."""

from __future__ import annotations

import http.client
import json
import multiprocessing
import re
import stat
import subprocess
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import pii_guard.local_workflow as local_workflow
from pii_guard.local_workflow import (
    LOCK_NAME,
    MANIFEST_NAME,
    MAX_INPUT_BYTES,
    MAX_PDF_BYTES,
    MAX_PDF_PAGES,
    PRIVATE_MAP_NAME,
    REDACTED_NAME,
    RESTORED_NAME,
    SOURCE_NAME,
    PrivateJobStore,
    WorkflowError,
    _extract_pdf_text_local,
    extract_pdf_text,
)
from tests.pdf_fixtures import (
    build_compressed_text_pdf,
    build_image_only_pdf,
    build_text_pdf,
)


class FakeEngine:
    """Deterministic engine double; it has no model or Ollama dependency."""

    replacements = (
        ("王小明", "<PERSON_1>"),
        ("A123456789", "<TW_NATIONAL_ID_1>"),
        ("0912345678", "<TW_MOBILE_1>"),
        ("alice@example.com", "<EMAIL_ADDRESS_1>"),
        ("04595257", "<TW_BUSINESS_ID_1>"),
    )

    def anonymize(self, text: str) -> tuple[str, dict[str, str]]:
        output = text
        mapping: dict[str, str] = {}
        for original, placeholder in self.replacements:
            if original in output:
                output = output.replace(original, placeholder)
                mapping[placeholder] = original
        return output, mapping


class NoisyFakeEngine(FakeEngine):
    """Dependency double that tries to echo input through both output streams."""

    def anonymize(self, text: str) -> tuple[str, dict[str, str]]:
        print(text)
        print(text, file=sys.stderr)
        return super().anonymize(text)


class LeakyFailureEngine:
    """Dependency double that puts source data in an exception message."""

    def anonymize(self, text: str) -> tuple[str, dict[str, str]]:
        raise WorkflowError("DEPENDENCY_FAILURE", f"unsafe detail: {text}")


ORIGINAL = "聯絡人王小明，身分證A123456789，手機0912345678，信箱alice@example.com，統編04595257。"


def _noisy_pdf_worker(input_connection: object, output_connection: object) -> None:
    with local_workflow._silence_pdf_worker_output():
        input_connection.recv_bytes()  # type: ignore[attr-defined]
        print("worker-source-must-not-escape")
        print("worker-source-must-not-escape", file=sys.stderr)
        output_connection.send_bytes(  # type: ignore[attr-defined]
            b'{"ok":true,"page_count":1,"text":"safe"}'
        )


def _sleeping_pdf_worker(input_connection: object, _output_connection: object) -> None:
    with local_workflow._silence_pdf_worker_output():
        input_connection.recv_bytes()  # type: ignore[attr-defined]
        time.sleep(5)


def _leaky_crash_pdf_worker(input_connection: object, _output_connection: object) -> None:
    with local_workflow._silence_pdf_worker_output():
        input_connection.recv_bytes()  # type: ignore[attr-defined]
        try:
            raise RuntimeError("parser metadata must not escape")
        except RuntimeError:
            return


def test_extract_pdf_text_preserves_page_boundaries_and_page_count() -> None:
    extracted = extract_pdf_text(build_text_pdf("PAGE ONE", "PAGE TWO"))

    assert extracted.page_count == 2
    assert extracted.text == "PAGE ONE\n\nPAGE TWO"


def test_pdf_extractor_rejects_signature_and_image_only_uploads() -> None:
    with pytest.raises(WorkflowError, match="PDF_NOT_PDF"):
        extract_pdf_text(b"not a pdf")
    with pytest.raises(WorkflowError, match="PDF_IMAGE_ONLY"):
        extract_pdf_text(build_image_only_pdf())


def test_pdf_extractor_rejects_bounds_with_fixed_safe_errors() -> None:
    with pytest.raises(WorkflowError, match="PDF_TOO_LARGE"):
        extract_pdf_text(b"%PDF-" + b"x" * MAX_PDF_BYTES)
    with pytest.raises(WorkflowError, match="PDF_TOO_MANY_PAGES"):
        extract_pdf_text(build_text_pdf(*(["PAGE"] * (MAX_PDF_PAGES + 1))))
    with pytest.raises(WorkflowError, match="PDF_TEXT_TOO_LARGE"):
        extract_pdf_text(build_text_pdf("x" * (MAX_INPUT_BYTES + 1)))


def test_compressed_pdf_expansion_is_rejected_and_parser_remains_usable() -> None:
    expanded = build_compressed_text_pdf(MAX_INPUT_BYTES + 1024)
    assert len(expanded) < MAX_INPUT_BYTES
    with pytest.raises(WorkflowError, match="PDF_TEXT_TOO_LARGE"):
        extract_pdf_text(expanded)
    assert extract_pdf_text(build_text_pdf("after expansion")).text == "after expansion"


def test_pdf_extractor_rejects_encrypted_document_with_fixed_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import pdfplumber

    class EncryptedDocument:
        encryption = object()
        is_extractable = True

    class EncryptedPdf:
        doc = EncryptedDocument()
        pages: list[object] = []

        def __enter__(self) -> EncryptedPdf:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    monkeypatch.setattr(pdfplumber, "open", lambda *_args, **_kwargs: EncryptedPdf())
    with pytest.raises(WorkflowError, match="PDF_ENCRYPTED"):
        _extract_pdf_text_local(b"%PDF-1.4 encrypted fixture")


def test_concurrent_pdf_workers_suppress_stdout_and_stderr(
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = build_text_pdf("worker input")
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = [
            executor.submit(
                local_workflow._run_pdf_parser,
                source,
                worker_target=_noisy_pdf_worker,
            )
            for _ in range(3)
        ]
        results = [future.result() for future in futures]

    assert results == [
        {"ok": True, "page_count": 1, "text": "safe"},
        {"ok": True, "page_count": 1, "text": "safe"},
        {"ok": True, "page_count": 1, "text": "safe"},
    ]
    captured = capsys.readouterr()
    assert "worker-source-must-not-escape" not in captured.out
    assert "worker-source-must-not-escape" not in captured.err


def test_pdf_parser_timeout_terminates_child_and_next_parse_works(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(local_workflow, "PDF_PARSE_TIMEOUT_SECONDS", 0.5)
    started = time.monotonic()
    with pytest.raises(WorkflowError, match="PDF_PARSE_TIMEOUT"):
        local_workflow._run_pdf_parser(build_text_pdf("slow"), worker_target=_sleeping_pdf_worker)
    assert time.monotonic() - started < 3

    monkeypatch.setattr(local_workflow, "PDF_PARSE_TIMEOUT_SECONDS", 15.0)
    extracted = extract_pdf_text(build_text_pdf("after timeout"))
    assert extracted.text == "after timeout"


def test_pdf_parser_crash_error_traceback_has_no_child_exception_detail() -> None:
    with pytest.raises(WorkflowError) as raised:
        local_workflow._run_pdf_parser(
            build_text_pdf("crash"), worker_target=_leaky_crash_pdf_worker
        )
    assert raised.value.code == "PDF_PARSE_CRASHED"
    assert "parser metadata must not escape" not in "".join(
        traceback.format_exception(raised.value)
    )


def test_pdf_job_keeps_format_metadata_through_manual_review(tmp_path: Path) -> None:
    store = _store(tmp_path)
    public = store.create_quick_from_pdf_bytes(build_text_pdf("ID A123456789", "PHONE 0912345678"))
    job_id = str(public["job_id"])
    assert public["source_format"] == "pdf"
    assert public["page_count"] == 2
    assert "A123456789" not in json.dumps(public, ensure_ascii=False)
    assert not (store.root / job_id / "upload.pdf").exists()

    reviewed = store.mask_terms(job_id, ["PHONE"])
    assert reviewed["source_format"] == "pdf"
    assert reviewed["page_count"] == 2
    state = store.load_state(job_id)
    assert state.manifest["source_format"] == "pdf"
    assert state.manifest["page_count"] == 2
    restored = store.restore_to_private(job_id)
    assert restored["roundtrip_equal"] is True
    assert (store.root / job_id / RESTORED_NAME).read_text(encoding="utf-8") == (
        "ID A123456789\n\nPHONE 0912345678"
    )
    store.delete(job_id)
    assert not (store.root / job_id).exists()


def _store(tmp_path: Path) -> PrivateJobStore:
    return PrivateJobStore(tmp_path / "jobs", engine=FakeEngine())


def _mask_in_child(root: str, job_id: str, term: str, barrier: object) -> None:
    """Run one real cross-process mask operation for the lock regression test."""

    getattr(barrier, "wait")(timeout=10)
    PrivateJobStore(Path(root)).mask_terms(job_id, [term])


def _assert_public_json_has_no_private_paths(payload: object, tmp_path: Path) -> None:
    rendered = json.dumps(payload, ensure_ascii=False)
    assert "private_work_dir" not in rendered
    assert "restored_path" not in rendered
    assert "sha256" not in rendered
    assert re.search(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", rendered) is None
    assert str(tmp_path) not in rendered
    assert str(Path.home()) not in rendered


def test_cli_quick_json_has_no_private_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from pii_guard.cli import build_parser, cmd_quick

    class StubStore:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            return None

        def create_quick_from_path(self, _path: Path) -> dict[str, object]:
            return {
                "ok": True,
                "job_id": "a" * 32,
                "mode": "quick",
                "anonymized_text": "[[PII-aaaaaaaaaa-PERSON-1]]",
                "placeholders": [],
                "replacement_count": 1,
                "roundtrip_verified": True,
            }

    monkeypatch.setattr("pii_guard.local_workflow.PrivateJobStore", StubStore)
    args = build_parser().parse_args(["quick", str(tmp_path / "input.txt")])

    assert cmd_quick(args) == 0
    payload = json.loads(capsys.readouterr().out)
    _assert_public_json_has_no_private_paths(payload, tmp_path)


def test_cli_quick_restore_uses_shared_core_and_writes_private_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from pii_guard.cli import build_parser, cmd_quick_restore

    store = _store(tmp_path)
    public = store.create_quick_from_text(ORIGINAL)
    job_id = str(public["job_id"])
    edited = tmp_path / "edited.txt"
    edited.write_text(
        store.load_state(job_id).redacted.replace("聯絡人", "收件人"),
        encoding="utf-8",
    )
    output = tmp_path / "restored.txt"
    calls: list[str] = []
    original_restore = PrivateJobStore.restore_edited_redacted

    def spy_restore(
        instance: PrivateJobStore,
        requested_job_id: str,
        edited_redacted: str | None = None,
        *,
        output_path: Path | None = None,
        overwrite: bool = True,
    ):
        calls.append(requested_job_id)
        return original_restore(
            instance,
            requested_job_id,
            edited_redacted,
            output_path=output_path,
            overwrite=overwrite,
        )

    monkeypatch.setattr(PrivateJobStore, "restore_edited_redacted", spy_restore)
    args = build_parser().parse_args(
        [
            "quick-restore",
            job_id,
            str(edited),
            "--output",
            str(output),
            "--jobs-root",
            str(store.root),
        ]
    )

    assert cmd_quick_restore(args) == 0
    payload = json.loads(capsys.readouterr().out)
    assert calls == [job_id]
    assert payload == {
        "job_id": job_id,
        "mode": "quick",
        "ok": True,
        "restored": True,
        "roundtrip_equal": False,
    }
    _assert_public_json_has_no_private_paths(payload, tmp_path)
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert output.read_text(encoding="utf-8") == ORIGINAL.replace("聯絡人", "收件人")


def test_quick_job_keeps_mapping_private_and_roundtrips(tmp_path: Path) -> None:
    store = _store(tmp_path)
    public = store.create_quick_from_text(ORIGINAL)
    job_id = str(public["job_id"])
    job_dir = store.root / job_id

    assert public["mode"] == "quick"
    assert public["roundtrip_verified"] is True
    _assert_public_json_has_no_private_paths(public, tmp_path)
    assert "A123456789" not in str(public)
    assert "mapping.private.json" not in json.dumps(public, ensure_ascii=False)
    assert stat.S_IMODE(job_dir.stat().st_mode) == 0o700
    for name in (SOURCE_NAME, REDACTED_NAME, PRIVATE_MAP_NAME, MANIFEST_NAME):
        assert stat.S_IMODE((job_dir / name).stat().st_mode) == 0o600

    state = store.load_state(job_id)
    assert state.redacted != ORIGINAL
    restored = store.restore_to_private(job_id)
    assert restored["roundtrip_equal"] is True
    _assert_public_json_has_no_private_paths(restored, tmp_path)
    assert (job_dir / RESTORED_NAME).read_text(encoding="utf-8") == ORIGINAL


def test_edited_redacted_restore_allows_plain_text_edit(tmp_path: Path) -> None:
    store = _store(tmp_path)
    public = store.create_quick_from_text(ORIGINAL)
    job_id = str(public["job_id"])
    edited = store.load_state(job_id).redacted.replace("聯絡人", "收件人")
    output = tmp_path / "edited-restored.txt"

    result = store.restore_edited_redacted(job_id, edited, output_path=output, overwrite=False)

    assert result.roundtrip_equal is False
    assert output.read_text(encoding="utf-8") == ORIGINAL.replace("聯絡人", "收件人")
    assert stat.S_IMODE(output.stat().st_mode) == 0o600


def test_edited_redacted_literal_placeholder_integrity_fails_closed(tmp_path: Path) -> None:
    store = _store(tmp_path)
    original = "文字中的 <PERSON_9> 應原樣保留，身分證A123456789。"
    public = store.create_quick_from_text(original)
    job_id = str(public["job_id"])
    redacted = store.load_state(job_id).redacted
    edited = redacted.replace("<PERSON_9>", "<PERSON_10>")

    with pytest.raises(WorkflowError, match="PLACEHOLDER_INTEGRITY_FAILED"):
        store.restore_edited_redacted(
            job_id,
            edited,
            output_path=tmp_path / "literal.txt",
            overwrite=False,
        )


def test_edited_redacted_literal_placeholder_sequence_fails_closed(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    original = "文字中的 <PERSON_9> 與 <EMAIL_ADDRESS_4> 應原樣保留，身分證A123456789。"
    public = store.create_quick_from_text(original)
    job_id = str(public["job_id"])
    redacted = store.load_state(job_id).redacted
    first = "<PERSON_9>"
    second = "<EMAIL_ADDRESS_4>"
    sentinel = "[literal-sequence-swap]"
    edited = redacted.replace(first, sentinel, 1).replace(second, first, 1)
    edited = edited.replace(sentinel, second, 1)

    with pytest.raises(WorkflowError, match="PLACEHOLDER_INTEGRITY_FAILED"):
        store.restore_edited_redacted(
            job_id,
            edited,
            output_path=tmp_path / "literal-sequence.txt",
            overwrite=False,
        )


@pytest.mark.parametrize("edit_kind", ["missing", "swapped", "foreign"])
def test_edited_redacted_placeholder_integrity_fails_closed(tmp_path: Path, edit_kind: str) -> None:
    store = _store(tmp_path)
    public = store.create_quick_from_text(ORIGINAL)
    job_id = str(public["job_id"])
    redacted = store.load_state(job_id).redacted
    markers = list(
        dict.fromkeys(match.group(0) for match in re.finditer(r"\[\[PII-[^\]\r\n]+\]\]", redacted))
    )
    assert len(markers) >= 2
    if edit_kind == "missing":
        edited = redacted.replace(markers[0], "", 1)
    elif edit_kind == "swapped":
        sentinel = "[[PII-ffffffff00-SWAP-1]]"
        edited = redacted.replace(markers[0], sentinel, 1)
        edited = edited.replace(markers[1], markers[0], 1)
        edited = edited.replace(sentinel, markers[1], 1)
    else:
        edited = redacted + " [[PII-ffffffff00-FOREIGN-1]]"

    with pytest.raises(WorkflowError, match="PLACEHOLDER_INTEGRITY_FAILED"):
        store.restore_edited_redacted(
            job_id,
            edited,
            output_path=tmp_path / f"{edit_kind}.txt",
            overwrite=False,
        )


def test_manual_mask_is_reversible_but_public_state_has_no_value(tmp_path: Path) -> None:
    store = _store(tmp_path)
    public = store.create_quick_from_text("未被規則抓到的張三要補遮。")
    job_id = str(public["job_id"])

    edited = store.mask_terms(job_id, ["張三"])
    assert edited["terms_masked"] == 1
    _assert_public_json_has_no_private_paths(edited, tmp_path)
    assert "張三" not in str(edited)
    assert "MANUAL-1" in json.dumps(edited, ensure_ascii=False)
    restored = store.restore_to_private(job_id)
    assert restored["roundtrip_equal"] is True
    _assert_public_json_has_no_private_paths(restored, tmp_path)
    assert (store.root / job_id / RESTORED_NAME).read_text(
        encoding="utf-8"
    ) == "未被規則抓到的張三要補遮。"


def test_literal_placeholder_is_not_treated_as_private_mapping(tmp_path: Path) -> None:
    store = _store(tmp_path)
    original = "文字中的 <PERSON_9> 應原樣保留，身分證A123456789。"
    public = store.create_quick_from_text(original)
    state = store.load_state(str(public["job_id"]))
    assert "<PERSON_9>" in state.redacted
    assert "<PERSON_9>" not in state.mapping
    assert store.restore_to_private(str(public["job_id"]))["roundtrip_equal"] is True


def test_job_id_traversal_and_unknown_files_are_rejected(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with pytest.raises(WorkflowError, match="INVALID_JOB_ID"):
        store.public_state("../escape")

    public = store.create_quick_from_text(ORIGINAL)
    job_dir = store.root / str(public["job_id"])
    (job_dir / "unknown.private.txt").write_text("x", encoding="utf-8")
    with pytest.raises(WorkflowError, match="INVALID_JOB"):
        store.delete(str(public["job_id"]))


def test_input_and_private_job_symlinks_are_rejected(tmp_path: Path) -> None:
    store = _store(tmp_path)
    source = tmp_path / "source.txt"
    source.write_text(ORIGINAL, encoding="utf-8")
    source_link = tmp_path / "source-link.txt"
    source_link.symlink_to(source)
    with pytest.raises(WorkflowError, match="INPUT_NOT_FOUND"):
        store.create_quick_from_path(source_link)

    public = store.create_quick_from_text(ORIGINAL)
    job_link_id = "a" * 32
    (store.root / job_link_id).symlink_to(store.root / str(public["job_id"]))
    with pytest.raises(WorkflowError, match="JOB_NOT_FOUND"):
        store.public_state(job_link_id)


def test_delete_removes_single_job_and_not_other_jobs(tmp_path: Path) -> None:
    store = _store(tmp_path)
    first = store.create_quick_from_text(ORIGINAL)
    second = store.create_quick_from_text(ORIGINAL)
    first_dir = store.root / str(first["job_id"])
    second_dir = store.root / str(second["job_id"])
    assert (first_dir / LOCK_NAME).is_file()
    store.delete(str(first["job_id"]))
    assert not first_dir.exists()
    assert second_dir.exists()
    assert store.public_state(str(second["job_id"]))["ok"] is True


def test_quick_path_fails_if_ollama_transport_is_called(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_if_called(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("quick mode must not call Ollama")

    monkeypatch.setattr(http.client, "HTTPConnection", fail_if_called)
    monkeypatch.setattr(subprocess, "run", fail_if_called)
    store = _store(tmp_path)
    public = store.create_quick_from_text(ORIGINAL)
    assert public["roundtrip_verified"] is True


def test_quick_path_discards_dependency_output(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    store = PrivateJobStore(tmp_path / "jobs", engine=NoisyFakeEngine())
    store.create_quick_from_text(ORIGINAL)
    captured = capsys.readouterr()
    assert ORIGINAL not in captured.out
    assert ORIGINAL not in captured.err


def test_quick_path_replaces_dependency_error_with_safe_message(tmp_path: Path) -> None:
    store = PrivateJobStore(tmp_path / "jobs", engine=LeakyFailureEngine())
    with pytest.raises(WorkflowError, match="PII_GUARD_FAILED") as raised:
        store.create_quick_from_text(ORIGINAL)
    assert ORIGINAL not in str(raised.value)


@pytest.mark.parametrize(
    "threshold",
    [float("nan"), float("inf"), float("-inf"), -0.01, 1.01],
)
def test_invalid_score_threshold_is_rejected_before_engine(
    tmp_path: Path, threshold: float
) -> None:
    factory_called = False

    def factory(_model: str, _threshold: float) -> FakeEngine:
        nonlocal factory_called
        factory_called = True
        return FakeEngine()

    with pytest.raises(WorkflowError, match="INVALID_THRESHOLD"):
        PrivateJobStore(
            tmp_path / "jobs",
            engine_factory=factory,
            score_threshold=threshold,
        )
    assert factory_called is False


def test_existing_namespaced_literal_placeholder_roundtrips(tmp_path: Path) -> None:
    store = _store(tmp_path)
    original = "保留 [[PII-deadbeef00-PERSON-9]] 原樣，聯絡人王小明。"
    public = store.create_quick_from_text(original)
    job_id = str(public["job_id"])

    state = store.load_state(job_id)
    assert "[[PII-deadbeef00-PERSON-9]]" in state.redacted
    assert "[[PII-deadbeef00-PERSON-9]]" not in state.mapping
    restored = store.restore_to_private(job_id)
    assert restored["roundtrip_equal"] is True
    assert (store.root / job_id / RESTORED_NAME).read_text(encoding="utf-8") == original


def test_partial_review_commit_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    public = store.create_quick_from_text("未被規則抓到的張三要補遮。")
    job_id = str(public["job_id"])
    original_write = local_workflow._write_private

    def fail_mapping_write(path: Path, data: str, *, replace: bool = False) -> None:
        if replace and path.name == PRIVATE_MAP_NAME:
            raise OSError("injected mapping commit failure")
        original_write(path, data, replace=replace)

    monkeypatch.setattr(local_workflow, "_write_private", fail_mapping_write)
    with pytest.raises(OSError, match="injected mapping commit failure"):
        store.mask_terms(job_id, ["張三"])
    monkeypatch.undo()

    with pytest.raises(WorkflowError, match="INTEGRITY_CHECK_FAILED"):
        store.load_state(job_id)


def test_concurrent_mask_operations_preserve_both_updates(tmp_path: Path) -> None:
    root = tmp_path / "jobs"
    first_store = PrivateJobStore(root, engine=FakeEngine())
    public = first_store.create_quick_from_text("甲乙兩個待補標記。")
    job_id = str(public["job_id"])
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(2)
    processes = [
        context.Process(target=_mask_in_child, args=(str(root), job_id, "甲", barrier)),
        context.Process(target=_mask_in_child, args=(str(root), job_id, "乙", barrier)),
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=15)
    for process in processes:
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)

    assert all(not process.is_alive() for process in processes)
    assert [process.exitcode for process in processes] == [0, 0]
    state = first_store.load_state(job_id)
    assert {value for value in state.mapping.values()} == {"甲", "乙"}
    assert state.redacted.count("-MANUAL-") == 2
