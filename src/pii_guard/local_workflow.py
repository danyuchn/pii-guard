"""Shared private quick-mode workflow for the CLI, web UI, and skill.

The public interfaces in this repository all use this module for the first
stage quick path.  It deliberately keeps the source snapshot and reverse map
inside a mode-0700 job directory while exposing only the redacted text and
opaque marker names to callers.
"""

from __future__ import annotations

import fcntl
import hashlib
import io
import json
import logging
import math
import multiprocessing
import os
import re
import shutil
import stat
import tempfile
import threading
import time
import unicodedata
import uuid
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from dataclasses import dataclass
from multiprocessing.process import BaseProcess
from pathlib import Path
from typing import Final, NoReturn, Protocol

SUPPORTED_SUFFIXES: Final[frozenset[str]] = frozenset(
    {".txt", ".md", ".csv", ".tsv", ".log", ".dat"}
)
PDF_SUFFIX: Final[str] = ".pdf"
MAX_INPUT_BYTES: Final[int] = 64 * 1024
MAX_PDF_BYTES: Final[int] = 4 * 1024 * 1024
MAX_PDF_PAGES: Final[int] = 50
PDF_SIGNATURE: Final[bytes] = b"%PDF-"
PDF_PARSE_TIMEOUT_SECONDS: Final[float] = 15.0
PDF_PARSE_GRACE_SECONDS: Final[float] = 0.5
PDF_WORKER_CPU_SECONDS: Final[int] = 10
PDF_WORKER_ADDRESS_SPACE_BYTES: Final[int] = 512 * 1024 * 1024
MAX_PDF_RESPONSE_BYTES: Final[int] = MAX_INPUT_BYTES + 16 * 1024
MAX_ANNOTATION_TERMS: Final[int] = 500
MAX_TERM_BYTES: Final[int] = 4096
JOB_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{32}$")
PLACEHOLDER_PATTERN: Final[re.Pattern[str]] = re.compile(r"<[A-Z][A-Z0-9_]*_\d+>")
NAMESPACED_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\[\[PII-[0-9a-f]{10}-[A-Z][A-Z0-9_]*-\d+\]\]"
)
ALL_NAMESPACED_PATTERN: Final[re.Pattern[str]] = re.compile(r"\[\[PII-[^\]\r\n]+\]\]")
ALL_LITERAL_PLACEHOLDER_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?:\[\[PII-[0-9a-f]{10}-[A-Z][A-Z0-9_]*-\d+\]\]"
    r"|<[A-Z][A-Z0-9_]*_\d+>)"
)
PLACEHOLDER_TYPE_PATTERN: Final[re.Pattern[str]] = re.compile(r"<([A-Z][A-Z0-9_]*)_(\d+)>")
NAMESPACED_PARTS_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\[\[PII-([0-9a-f]{10})-([A-Z][A-Z0-9_]*)-(\d+)\]\]"
)
WORKFLOW_KIND: Final[str] = "pii-safe-documents-private-job"
WORKFLOW_VERSION: Final[int] = 1
PRIVATE_MAP_NAME: Final[str] = "mapping.private.json"
MANIFEST_NAME: Final[str] = "manifest.safe.json"
REDACTED_NAME: Final[str] = "redacted.txt"
SOURCE_NAME: Final[str] = ".source.private.txt"
RESTORED_NAME: Final[str] = ".restored.private.txt"
LOCK_NAME: Final[str] = ".job.lock"
PRIVATE_MODE: Final[int] = 0o600
JOB_MODE: Final[int] = 0o700


class WorkflowError(Exception):
    """An error safe to expose through a local CLI or HTTP response."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


class Anonymizer(Protocol):
    """Small protocol implemented by :class:`PiiGuardEngine` and test doubles."""

    def anonymize(self, text: str) -> tuple[str, dict[str, str]]: ...


EngineFactory = Callable[[str, float], Anonymizer]


@dataclass(frozen=True)
class JobState:
    """Private state loaded from one validated job directory."""

    job_id: str
    job_dir: Path
    original: str
    redacted: str
    mapping: dict[str, str]
    manifest: dict[str, object]


@dataclass(frozen=True)
class RestoreResult:
    """Private result of restoring an edited redacted quick job.

    ``output_path`` and ``restored_sha256`` are intentionally kept out of
    public receipts.  They are needed by private workers to verify their
    artifact, but exposing them from a web/CLI response would widen the
    general JSON contract beyond job state and safe status.
    """

    job_id: str
    output_path: Path
    restored_sha256: str
    roundtrip_equal: bool


@dataclass(frozen=True)
class PdfTextExtraction:
    """Text extracted from one accepted, text-based PDF upload."""

    text: str
    page_count: int


def default_jobs_root() -> Path:
    """Return the common private job root used by all local interfaces."""

    configured = os.environ.get("PII_GUARD_JOBS_ROOT", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return (Path.home() / ".local/share/pii-safe-documents/jobs").resolve()


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _mapping_text(mapping: Mapping[str, str]) -> str:
    """Serialize a private mapping canonically for writing and hashing."""

    return json.dumps(mapping, ensure_ascii=False, sort_keys=True)


def _validate_score_threshold(value: object) -> float:
    """Validate the detector threshold before constructing any engine."""

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise WorkflowError(
            "INVALID_THRESHOLD",
            "Score threshold must be a finite number from 0 to 1.",
        )
    try:
        threshold = float(value)
    except (OverflowError, ValueError) as exc:
        raise WorkflowError(
            "INVALID_THRESHOLD",
            "Score threshold must be a finite number from 0 to 1.",
        ) from exc
    if not math.isfinite(threshold) or not 0 <= threshold <= 1:
        raise WorkflowError(
            "INVALID_THRESHOLD",
            "Score threshold must be a finite number from 0 to 1.",
        )
    return threshold


def _assert_owner_mode(path: Path, expected_mode: int, *, directory: bool) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise WorkflowError("JOB_NOT_FOUND", "Private job artifact was not found.") from exc
    if path.is_symlink() or (directory and not stat.S_ISDIR(info.st_mode)):
        raise WorkflowError("PERMISSION_CHECK_FAILED", "Private artifact is not safe.")
    if not directory and not stat.S_ISREG(info.st_mode):
        raise WorkflowError("PERMISSION_CHECK_FAILED", "Private artifact is not a file.")
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != expected_mode:
        raise WorkflowError("PERMISSION_CHECK_FAILED", "Private artifact permissions are unsafe.")
    if not directory and info.st_nlink != 1:
        raise WorkflowError("PERMISSION_CHECK_FAILED", "Private artifact has multiple hard links.")


def _ensure_lock_file(job_dir: Path) -> Path:
    """Create and validate the owner-only regular lock file for one job."""

    lock_path = job_dir / LOCK_NAME
    flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(
            lock_path,
            flags | os.O_CREAT | os.O_EXCL,
            PRIVATE_MODE,
        )
    except FileExistsError:
        _assert_owner_mode(lock_path, PRIVATE_MODE, directory=False)
    except OSError as exc:
        raise WorkflowError("LOCK_FAILED", "Private job lock is unavailable.") from exc
    else:
        try:
            os.fchmod(descriptor, PRIVATE_MODE)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    _assert_owner_mode(lock_path, PRIVATE_MODE, directory=False)
    return lock_path


@contextmanager
def _job_lock(job_dir: Path, *, exclusive: bool) -> Iterator[None]:
    """Hold a validated per-job advisory lock across one complete operation."""

    lock_path = _ensure_lock_file(job_dir)
    flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    locked = False
    try:
        try:
            descriptor = os.open(lock_path, flags)
            descriptor_info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(descriptor_info.st_mode)
                or descriptor_info.st_uid != os.getuid()
                or stat.S_IMODE(descriptor_info.st_mode) != PRIVATE_MODE
                or descriptor_info.st_nlink != 1
            ):
                raise WorkflowError("PERMISSION_CHECK_FAILED", "Private job lock is unsafe.")
            path_info = lock_path.lstat()
            if (
                path_info.st_dev != descriptor_info.st_dev
                or path_info.st_ino != descriptor_info.st_ino
            ):
                raise WorkflowError("LOCK_FAILED", "Private job lock changed unexpectedly.")
            operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
            fcntl.flock(descriptor, operation)
            locked = True
            # Recheck the pathname after waiting: a replaced lock path must not let
            # a caller proceed while holding a lock on an unlinked inode.
            current_info = lock_path.lstat()
            if (
                current_info.st_dev != descriptor_info.st_dev
                or current_info.st_ino != descriptor_info.st_ino
            ):
                raise WorkflowError("LOCK_FAILED", "Private job lock changed unexpectedly.")
        except WorkflowError:
            raise
        except OSError as exc:
            raise WorkflowError("LOCK_FAILED", "Private job lock is unavailable.") from exc
        yield
    finally:
        if locked:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
        if descriptor >= 0:
            os.close(descriptor)


def _ensure_jobs_root(root: Path) -> Path:
    expanded = root.expanduser()
    if expanded.exists() and expanded.is_symlink():
        raise WorkflowError("PERMISSION_CHECK_FAILED", "Private jobs root must not be a symlink.")
    expanded.mkdir(parents=True, exist_ok=True, mode=JOB_MODE)
    expanded.chmod(JOB_MODE)
    resolved = expanded.resolve()
    _assert_owner_mode(resolved, JOB_MODE, directory=True)
    return resolved


def _write_private(path: Path, data: str, *, replace: bool = False) -> None:
    """Write an owner-only UTF-8 file atomically.

    New files use an exclusive hard-link to avoid clobbering a path created by
    another process.  Existing files are only replaced inside a validated job
    directory by the review/restore commit path.
    """

    path.parent.mkdir(parents=True, exist_ok=True, mode=JOB_MODE)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, PRIVATE_MODE)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if replace:
            os.replace(temporary, path)
        else:
            os.link(temporary, path, follow_symlinks=False)
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    finally:
        temporary.unlink(missing_ok=True)
    _assert_owner_mode(path, PRIVATE_MODE, directory=False)


def _read_utf8(path: Path, *, max_bytes: int | None = MAX_INPUT_BYTES) -> str:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise WorkflowError("INPUT_NOT_FOUND", "Input path is not available.") from exc
    if path.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise WorkflowError("INPUT_NOT_FOUND", "Input path must be a regular file.")
    if max_bytes is not None and info.st_size > max_bytes:
        raise WorkflowError("INPUT_TOO_LARGE", "Input exceeds the safety size limit.")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise WorkflowError("INPUT_NOT_FOUND", "Input path could not be opened safely.") from exc
    try:
        current = os.fstat(descriptor)
        if not stat.S_ISREG(current.st_mode) or current.st_ino != info.st_ino:
            raise WorkflowError("INPUT_CHANGED", "Input changed during processing.")
        data = os.read(descriptor, (max_bytes + 1) if max_bytes is not None else 1024 * 1024)
    finally:
        os.close(descriptor)
    if max_bytes is not None and len(data) > max_bytes:
        raise WorkflowError("INPUT_TOO_LARGE", "Input exceeds the safety size limit.")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WorkflowError("INPUT_NOT_UTF8", "Input must be UTF-8 plain text.") from exc


_PDF_ERROR_MESSAGES: Final[dict[str, str]] = {
    "PDF_INVALID_UPLOAD": "PDF upload is invalid.",
    "PDF_TOO_LARGE": "PDF upload exceeds the safety size limit.",
    "PDF_NOT_PDF": "PDF signature is invalid.",
    "PDF_UNAVAILABLE": "PDF text extraction is not available in this installation.",
    "PDF_ENCRYPTED": "Encrypted or password-protected PDFs are not supported.",
    "PDF_TOO_MANY_PAGES": "PDF has too many pages for local quick review.",
    "PDF_IMAGE_ONLY": "Scanned or image-only PDFs are not supported.",
    "PDF_NO_TEXT": "PDF contains no extractable text.",
    "PDF_TEXT_TOO_LARGE": "Extracted PDF text exceeds the safety size limit.",
    "PDF_MALFORMED": "PDF could not be parsed safely.",
    "PDF_PARSE_TIMEOUT": "PDF parsing timed out safely.",
    "PDF_PARSE_CRASHED": "PDF parser stopped unexpectedly.",
    "PDF_PARSE_RESOURCE_LIMIT": "PDF parser exceeded the safety resource limit.",
    "PDF_RESPONSE_TOO_LARGE": "PDF parser returned an unsafe response.",
    "PDF_RESPONSE_INVALID": "PDF parser returned an invalid response.",
    "PDF_IPC_FAILED": "PDF parser communication failed safely.",
}


def _raise_pdf_error(code: str) -> NoReturn:
    """Raise only a fixed public-safe PDF error, without parser exception context."""

    safe_code = code if code in _PDF_ERROR_MESSAGES else "PDF_MALFORMED"
    raise WorkflowError(safe_code, _PDF_ERROR_MESSAGES[safe_code]) from None


@contextmanager
def _silence_pdf_worker_output() -> Iterator[None]:
    """Discard parser output inside the isolated worker only."""

    previous_disable = logging.root.manager.disable
    saved_stdout = os.dup(1)
    saved_stderr = os.dup(2)
    null_descriptor = os.open(os.devnull, os.O_WRONLY)
    logging.disable(logging.CRITICAL)
    try:
        os.dup2(null_descriptor, 1)
        os.dup2(null_descriptor, 2)
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            yield
    finally:
        os.dup2(saved_stdout, 1)
        os.dup2(saved_stderr, 2)
        os.close(saved_stdout)
        os.close(saved_stderr)
        os.close(null_descriptor)
        logging.disable(previous_disable)


def _is_pdf_encryption_error(error: BaseException) -> bool:
    """Identify wrapped pdfminer encryption errors without inspecting messages."""

    pending: list[BaseException] = [error]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        identity = id(current)
        if identity in seen:
            continue
        seen.add(identity)
        if type(current).__name__ in {"PDFEncryptionError", "PDFPasswordIncorrect"}:
            return True
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)
        pending.extend(argument for argument in current.args if isinstance(argument, BaseException))
    return False


def _extract_pdf_text_local(data: bytes) -> PdfTextExtraction:
    """Extract PDF text in the worker process; never call this from a public adapter."""

    try:
        import pdfplumber
    except (ImportError, ModuleNotFoundError) as exc:
        raise WorkflowError("PDF_UNAVAILABLE", _PDF_ERROR_MESSAGES["PDF_UNAVAILABLE"]) from exc

    stream = io.BytesIO(data)
    try:
        with pdfplumber.open(
            stream,
            strict_metadata=False,
            raise_unicode_errors=True,
        ) as pdf:
            document = getattr(pdf, "doc", None)
            if document is None:
                raise WorkflowError("PDF_MALFORMED", _PDF_ERROR_MESSAGES["PDF_MALFORMED"])
            if getattr(document, "encryption", None) is not None or not getattr(
                document, "is_extractable", True
            ):
                raise WorkflowError("PDF_ENCRYPTED", _PDF_ERROR_MESSAGES["PDF_ENCRYPTED"])

            try:
                from pdfminer.pdfpage import PDFPage
            except (ImportError, ModuleNotFoundError) as exc:
                raise WorkflowError(
                    "PDF_UNAVAILABLE", _PDF_ERROR_MESSAGES["PDF_UNAVAILABLE"]
                ) from exc
            page_count = 0
            for page_count, _ in enumerate(PDFPage.create_pages(document), start=1):
                if page_count > MAX_PDF_PAGES:
                    raise WorkflowError(
                        "PDF_TOO_MANY_PAGES", _PDF_ERROR_MESSAGES["PDF_TOO_MANY_PAGES"]
                    )

            pages = pdf.pages
            if len(pages) != page_count:
                raise WorkflowError("PDF_MALFORMED", _PDF_ERROR_MESSAGES["PDF_MALFORMED"])

            page_texts: list[str] = []
            has_images = False
            for page in pages:
                extracted = page.extract_text()
                if extracted is None:
                    extracted = ""
                if not isinstance(extracted, str):
                    raise WorkflowError("PDF_MALFORMED", _PDF_ERROR_MESSAGES["PDF_MALFORMED"])
                page_texts.append(extracted)
                try:
                    has_images = has_images or bool(page.images)
                except Exception as exc:
                    raise WorkflowError(
                        "PDF_MALFORMED", _PDF_ERROR_MESSAGES["PDF_MALFORMED"]
                    ) from exc

            if not any(page_text.strip() for page_text in page_texts):
                code = "PDF_IMAGE_ONLY" if has_images else "PDF_NO_TEXT"
                raise WorkflowError(code, _PDF_ERROR_MESSAGES[code])

            extracted_text = unicodedata.normalize("NFKC", "\n\n".join(page_texts))
    finally:
        stream.close()

    try:
        extracted_bytes = extracted_text.encode("utf-8")
    except UnicodeError as exc:
        raise WorkflowError("PDF_MALFORMED", _PDF_ERROR_MESSAGES["PDF_MALFORMED"]) from exc
    if len(extracted_bytes) > MAX_INPUT_BYTES:
        raise WorkflowError("PDF_TEXT_TOO_LARGE", _PDF_ERROR_MESSAGES["PDF_TEXT_TOO_LARGE"])
    return PdfTextExtraction(text=extracted_text, page_count=page_count)


def _set_pdf_worker_limits() -> None:
    """Apply best-effort CPU and address-space limits inside the worker."""

    try:
        import resource
    except ImportError:
        return

    limits = (
        ("RLIMIT_CPU", PDF_WORKER_CPU_SECONDS),
        ("RLIMIT_AS", PDF_WORKER_ADDRESS_SPACE_BYTES),
    )
    for name, requested_soft in limits:
        limit = getattr(resource, name, None)
        if limit is None:
            continue
        try:
            current_soft, current_hard = resource.getrlimit(limit)
            if current_soft == resource.RLIM_INFINITY:
                selected_soft = requested_soft
            else:
                selected_soft = min(current_soft, requested_soft)
            if current_hard != resource.RLIM_INFINITY:
                selected_soft = min(selected_soft, current_hard)
            resource.setrlimit(limit, (selected_soft, current_hard))
        except (OSError, ValueError):
            continue


def _send_pdf_worker_result(connection: object, payload: dict[str, object]) -> None:
    """Send a bounded JSON result without forwarding arbitrary exception data."""

    try:
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    except (TypeError, UnicodeError):
        encoded = b'{"ok":false,"code":"PDF_RESPONSE_INVALID"}'
    if len(encoded) > MAX_PDF_RESPONSE_BYTES:
        encoded = b'{"ok":false,"code":"PDF_RESPONSE_TOO_LARGE"}'
    try:
        connection.send_bytes(encoded)  # type: ignore[attr-defined]
    except (BrokenPipeError, EOFError, OSError):
        return


def _pdf_parser_worker(input_connection: object, output_connection: object) -> None:
    """Spawn-safe target for all untrusted PDF parsing."""

    with _silence_pdf_worker_output():
        try:
            _set_pdf_worker_limits()
            data = input_connection.recv_bytes(MAX_PDF_BYTES + 1)  # type: ignore[attr-defined]
            if len(data) > MAX_PDF_BYTES:
                _send_pdf_worker_result(output_connection, {"ok": False, "code": "PDF_TOO_LARGE"})
            else:
                result = _extract_pdf_text_local(data)
                _send_pdf_worker_result(
                    output_connection,
                    {"ok": True, "page_count": result.page_count, "text": result.text},
                )
        except WorkflowError as error:
            code = error.code if error.code in _PDF_ERROR_MESSAGES else "PDF_MALFORMED"
            _send_pdf_worker_result(output_connection, {"ok": False, "code": code})
        except MemoryError:
            _send_pdf_worker_result(
                output_connection, {"ok": False, "code": "PDF_PARSE_RESOURCE_LIMIT"}
            )
        except BaseException:
            _send_pdf_worker_result(output_connection, {"ok": False, "code": "PDF_MALFORMED"})
        finally:
            for connection in (input_connection, output_connection):
                try:
                    connection.close()  # type: ignore[attr-defined]
                except (OSError, AttributeError):
                    pass


def _stop_pdf_worker(process: BaseProcess) -> None:
    """Terminate then kill a parser child and always reap it."""

    try:
        alive = process.is_alive()
    except AssertionError:
        return
    if alive:
        process.terminate()
        process.join(PDF_PARSE_GRACE_SECONDS)
    try:
        alive = process.is_alive()
    except AssertionError:
        return
    if alive and hasattr(process, "kill"):
        process.kill()
        process.join(PDF_PARSE_GRACE_SECONDS)


def _run_pdf_parser(
    data: bytes,
    *,
    worker_target: Callable[[object, object], None] = _pdf_parser_worker,
) -> dict[str, object]:
    """Run the parser child with bounded input/output channels and a wall deadline."""

    if not isinstance(data, bytes):
        _raise_pdf_error("PDF_INVALID_UPLOAD")
    if len(data) > MAX_PDF_BYTES:
        _raise_pdf_error("PDF_TOO_LARGE")
    context = multiprocessing.get_context("spawn")
    input_read, input_write = context.Pipe(duplex=False)
    output_read, output_write = context.Pipe(duplex=False)
    process = context.Process(
        target=worker_target,
        args=(input_read, output_write),
        daemon=True,
    )
    started = time.monotonic()
    sender_errors: list[BaseException] = []
    process_started = False

    def send_input() -> None:
        try:
            input_write.send_bytes(data)
        except BaseException as error:
            sender_errors.append(error)

    sender: threading.Thread | None = None
    try:
        process.start()
        process_started = True
        input_read.close()
        output_write.close()
        sender = threading.Thread(target=send_input, daemon=True)
        sender.start()
        deadline = started + PDF_PARSE_TIMEOUT_SECONDS
        while sender.is_alive():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _stop_pdf_worker(process)
                _raise_pdf_error("PDF_PARSE_TIMEOUT")
            sender.join(min(remaining, 0.05))
        input_write.close()
        if sender_errors:
            if process.exitcode is not None:
                if process.exitcode < 0:
                    _raise_pdf_error("PDF_PARSE_RESOURCE_LIMIT")
                _raise_pdf_error("PDF_PARSE_CRASHED")
            _raise_pdf_error("PDF_IPC_FAILED")

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _stop_pdf_worker(process)
                _raise_pdf_error("PDF_PARSE_TIMEOUT")
            if output_read.poll(min(remaining, 0.05)):
                break
            if not process.is_alive():
                process.join()
                if process.exitcode is not None and process.exitcode < 0:
                    _raise_pdf_error("PDF_PARSE_RESOURCE_LIMIT")
                _raise_pdf_error("PDF_PARSE_CRASHED")
        try:
            payload = output_read.recv_bytes(MAX_PDF_RESPONSE_BYTES)
        except EOFError:
            # A cleanly closed output pipe without a result is a parser crash,
            # even if the process has not published its exit code yet.
            process.join(PDF_PARSE_GRACE_SECONDS)
            if process.is_alive():
                _stop_pdf_worker(process)
            if process.exitcode is not None and process.exitcode < 0:
                _raise_pdf_error("PDF_PARSE_RESOURCE_LIMIT")
            _raise_pdf_error("PDF_PARSE_CRASHED")
        except (BufferError, OSError):
            if process.exitcode is not None or not process.is_alive():
                process.join()
                if process.exitcode is not None and process.exitcode < 0:
                    _raise_pdf_error("PDF_PARSE_RESOURCE_LIMIT")
                _raise_pdf_error("PDF_PARSE_CRASHED")
            _stop_pdf_worker(process)
            _raise_pdf_error("PDF_RESPONSE_TOO_LARGE")
        if len(payload) > MAX_PDF_RESPONSE_BYTES:
            _stop_pdf_worker(process)
            _raise_pdf_error("PDF_RESPONSE_TOO_LARGE")
        try:
            decoded = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            _stop_pdf_worker(process)
            _raise_pdf_error("PDF_RESPONSE_INVALID")
        if not isinstance(decoded, dict):
            _stop_pdf_worker(process)
            _raise_pdf_error("PDF_RESPONSE_INVALID")
        process.join(PDF_PARSE_GRACE_SECONDS)
        if process.is_alive():
            _stop_pdf_worker(process)
        return decoded
    except WorkflowError:
        raise
    except (OSError, RuntimeError):
        if process_started:
            _stop_pdf_worker(process)
        _raise_pdf_error("PDF_PARSE_CRASHED")
    finally:
        if sender is not None and sender.is_alive():
            input_write.close()
            sender.join(PDF_PARSE_GRACE_SECONDS)
        for connection in (input_read, input_write, output_read, output_write):
            try:
                connection.close()
            except (OSError, AttributeError):
                pass
        if process_started:
            if process.is_alive():
                _stop_pdf_worker(process)
            process.join()
            process.close()


def extract_pdf_text(data: bytes) -> PdfTextExtraction:
    """Safely extract bounded PDF text in a fresh isolated parser process."""

    if not isinstance(data, bytes):
        _raise_pdf_error("PDF_INVALID_UPLOAD")
    if len(data) > MAX_PDF_BYTES:
        _raise_pdf_error("PDF_TOO_LARGE")
    if not data.startswith(PDF_SIGNATURE):
        _raise_pdf_error("PDF_NOT_PDF")

    decoded = _run_pdf_parser(data)
    if decoded.get("ok") is not True:
        code = decoded.get("code")
        _raise_pdf_error(code if isinstance(code, str) else "PDF_RESPONSE_INVALID")
    text = decoded.get("text")
    page_count = decoded.get("page_count")
    if not isinstance(text, str) or not isinstance(page_count, int) or isinstance(page_count, bool):
        _raise_pdf_error("PDF_RESPONSE_INVALID")
    try:
        text_bytes = text.encode("utf-8")
    except UnicodeError:
        _raise_pdf_error("PDF_RESPONSE_INVALID")
    if len(text_bytes) > MAX_INPUT_BYTES:
        _raise_pdf_error("PDF_RESPONSE_TOO_LARGE")
    if not 1 <= page_count <= MAX_PDF_PAGES:
        _raise_pdf_error("PDF_RESPONSE_INVALID")
    return PdfTextExtraction(text=text, page_count=page_count)


def read_source_path(path: Path) -> str:
    """Validate a supported plain-text source without echoing its contents."""

    if path.expanduser().suffix.lower() not in SUPPORTED_SUFFIXES:
        raise WorkflowError(
            "UNSUPPORTED_FORMAT", "Only verified UTF-8 plain-text files are supported."
        )
    return _read_utf8(path.expanduser())


def _protect_literal_placeholders(text: str) -> tuple[str, dict[str, str]]:
    literals = sorted(
        set(PLACEHOLDER_PATTERN.findall(text)) | set(NAMESPACED_PATTERN.findall(text)),
        key=len,
        reverse=True,
    )
    protected = text
    tokens: dict[str, str] = {}
    for index, literal in enumerate(literals):
        token = f"\x00PII_LITERAL_{index}_{uuid.uuid4().hex[:12]}\x00"
        tokens[token] = literal
        protected = protected.replace(literal, token)
    return protected, tokens


def _restore_literals(text: str, tokens: Mapping[str, str]) -> str:
    restored = text
    for token, literal in tokens.items():
        restored = restored.replace(token, literal)
    return restored


def _replace_outside_markers(text: str, value: str, replacement: str) -> str:
    if not value or value not in text:
        return text
    parts = NAMESPACED_PATTERN.split(text)
    for index in range(0, len(parts), 2):
        parts[index] = parts[index].replace(value, replacement)
    return "".join(parts)


def _namespace_anonymized(
    redacted: str,
    raw_mapping: Mapping[str, str],
    job_id: str,
    literal_tokens: Mapping[str, str],
) -> tuple[str, dict[str, str]]:
    if not isinstance(raw_mapping, Mapping) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in raw_mapping.items()
    ):
        raise WorkflowError("INVALID_MAPPING", "Anonymizer returned an invalid mapping.")

    mapping: dict[str, str] = {}
    output = redacted
    for old_placeholder, value in sorted(
        raw_mapping.items(), key=lambda item: len(item[0]), reverse=True
    ):
        match = PLACEHOLDER_TYPE_PATTERN.fullmatch(old_placeholder)
        if match is None or not value:
            raise WorkflowError("INVALID_MAPPING", "Anonymizer returned an invalid mapping.")
        new_placeholder = f"[[PII-{job_id[:10]}-{match.group(1)}-{match.group(2)}]]"
        if old_placeholder not in output or new_placeholder in mapping:
            raise WorkflowError("INVALID_MAPPING", "Anonymizer markers are inconsistent.")
        output = output.replace(old_placeholder, new_placeholder)
        mapping[new_placeholder] = value

    output = _restore_literals(output, literal_tokens)
    # The engine normally replaces every occurrence.  A final deterministic
    # sweep closes that known gap without touching already generated markers.
    for placeholder, value in sorted(mapping.items(), key=lambda item: len(item[1]), reverse=True):
        output = _replace_outside_markers(output, value, placeholder)
    return output, mapping


def _replace_all(text: str, mapping: Mapping[str, str]) -> str:
    restored = text
    for placeholder in sorted(mapping, key=len, reverse=True):
        restored = restored.replace(placeholder, mapping[placeholder])
    return restored


def _entity_counts(mapping: Mapping[str, str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for placeholder in mapping:
        match = NAMESPACED_PARTS_PATTERN.fullmatch(placeholder)
        entity_type = match.group(2) if match else "OTHER"
        counts[entity_type] = counts.get(entity_type, 0) + 1
    return counts


def _manifest_for(
    *,
    job_id: str,
    job_dir: Path,
    original: str,
    redacted: str,
    mapping: Mapping[str, str],
    model: str,
    source_path: Path,
    source_format: str = "text",
    page_count: int | None = None,
    previous: Mapping[str, object] | None = None,
) -> dict[str, object]:
    manifest: dict[str, object] = dict(previous or {})
    manifest.update(
        {
            "kind": WORKFLOW_KIND,
            "version": WORKFLOW_VERSION,
            "job_id": job_id,
            "mode": "quick",
            "source_format": source_format,
            "redacted_file": REDACTED_NAME,
            "replacement_count": len(mapping),
            "entity_counts": _entity_counts(mapping),
            "local_audit": "not-run",
            "local_audit_model": model,
            "original_path": str(source_path),
            "original_sha256": _sha256_text(original),
            "redacted_sha256": _sha256_text(redacted),
            "mapping_sha256": _sha256_text(_mapping_text(mapping)),
            "placeholder_counts": {
                placeholder: redacted.count(placeholder) for placeholder in mapping
            },
            "placeholder_sequence": [
                placeholder
                for placeholder in NAMESPACED_PATTERN.findall(redacted)
                if placeholder in mapping
            ],
            "literal_placeholder_counts": {
                literal: redacted.count(literal)
                for literal in PLACEHOLDER_PATTERN.findall(original)
                + NAMESPACED_PATTERN.findall(original)
            },
            "literal_placeholder_sequence": [
                literal for literal in ALL_LITERAL_PLACEHOLDER_PATTERN.findall(original)
            ],
        }
    )
    if source_format == "pdf":
        manifest["page_count"] = page_count
    else:
        manifest.pop("page_count", None)
    return manifest


def _safe_json(path: Path) -> object:
    try:
        return json.loads(_read_utf8(path, max_bytes=4 * MAX_INPUT_BYTES))
    except json.JSONDecodeError as exc:
        raise WorkflowError("INVALID_JOB", "Private job metadata is invalid.") from exc


def _validate_job_id(job_id: str) -> None:
    if not isinstance(job_id, str) or JOB_ID_PATTERN.fullmatch(job_id) is None:
        raise WorkflowError("INVALID_JOB_ID", "Job ID is invalid.")


def _split_marker(placeholder: str) -> tuple[str, int] | None:
    match = NAMESPACED_PARTS_PATTERN.fullmatch(placeholder)
    if match is None:
        return None
    return match.group(2), int(match.group(3))


_PRIVATE_RESTORE_OUTPUT_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^\.restore-output-[0-9a-f]{32}\.private\.txt$"
)


def _validated_count_map(value: object, *, error_code: str = "INVALID_MANIFEST") -> dict[str, int]:
    if not isinstance(value, dict) or not all(
        isinstance(key, str)
        and isinstance(count, int)
        and not isinstance(count, bool)
        and count >= 0
        for key, count in value.items()
    ):
        raise WorkflowError(error_code, "Private placeholder counts are invalid.")
    return dict(value)


def _validated_literal_markers(
    manifest: Mapping[str, object], original: str, redacted: str
) -> set[str]:
    """Validate literal placeholder metadata before accepting namespaced text."""

    literal_counts = _validated_count_map(manifest.get("literal_placeholder_counts"))
    if any(ALL_LITERAL_PLACEHOLDER_PATTERN.fullmatch(marker) is None for marker in literal_counts):
        raise WorkflowError("INVALID_MANIFEST", "Private literal placeholders are invalid.")
    expected_sequence = ALL_LITERAL_PLACEHOLDER_PATTERN.findall(original)
    manifest_sequence = manifest.get("literal_placeholder_sequence")
    if not isinstance(manifest_sequence, list) or not all(
        isinstance(marker, str) for marker in manifest_sequence
    ):
        raise WorkflowError("INVALID_MANIFEST", "Private literal placeholder sequence is invalid.")
    if manifest_sequence != expected_sequence:
        raise WorkflowError("INVALID_MANIFEST", "Private literal placeholder sequence is invalid.")
    expected_counts = {marker: redacted.count(marker) for marker in expected_sequence}
    if literal_counts != expected_counts:
        raise WorkflowError("INVALID_MANIFEST", "Private literal placeholder counts are invalid.")
    return set(literal_counts)


def _validate_edited_redacted(state: JobState, edited_redacted: str) -> None:
    """Validate an edited redacted document before any private restoration."""

    if not isinstance(edited_redacted, str):
        raise WorkflowError("INPUT_NOT_UTF8", "Edited redacted input must be UTF-8 text.")
    if len(edited_redacted.encode("utf-8")) > MAX_INPUT_BYTES:
        raise WorkflowError("INPUT_TOO_LARGE", "Edited redacted input exceeds the safety limit.")

    expected_counts = _validated_count_map(state.manifest.get("placeholder_counts"))
    if set(expected_counts) != set(state.mapping):
        raise WorkflowError("INVALID_MANIFEST", "Private placeholder identity is invalid.")
    if any(NAMESPACED_PATTERN.fullmatch(marker) is None for marker in expected_counts):
        raise WorkflowError("INVALID_MANIFEST", "Private placeholder identity is invalid.")

    expected_sequence = state.manifest.get("placeholder_sequence")
    if not isinstance(expected_sequence, list) or not all(
        isinstance(marker, str) for marker in expected_sequence
    ):
        raise WorkflowError("INVALID_MANIFEST", "Private placeholder sequence is invalid.")

    literal_counts = _validated_count_map(state.manifest.get("literal_placeholder_counts"))
    if any(
        PLACEHOLDER_PATTERN.fullmatch(marker) is None
        and NAMESPACED_PATTERN.fullmatch(marker) is None
        for marker in literal_counts
    ):
        raise WorkflowError("INVALID_MANIFEST", "Private literal placeholders are invalid.")

    expected_literal_sequence_value = state.manifest.get("literal_placeholder_sequence")
    if expected_literal_sequence_value is None:
        # Older quick manifests did not persist literal order.  Derive it
        # from the immutable private source for a compatible, still strict
        # validation rather than accepting an unverified edited sequence.
        expected_literal_sequence = [
            marker
            for marker in ALL_LITERAL_PLACEHOLDER_PATTERN.findall(state.original)
            if marker in literal_counts
        ]
    elif isinstance(expected_literal_sequence_value, list) and all(
        isinstance(marker, str) for marker in expected_literal_sequence_value
    ):
        expected_literal_sequence = list(expected_literal_sequence_value)
    else:
        raise WorkflowError("INVALID_MANIFEST", "Private literal placeholder sequence is invalid.")
    if set(expected_literal_sequence) != set(literal_counts) or any(
        expected_literal_sequence.count(marker) != count for marker, count in literal_counts.items()
    ):
        raise WorkflowError("INVALID_MANIFEST", "Private literal placeholder sequence is invalid.")

    actual_counts = {marker: edited_redacted.count(marker) for marker in state.mapping}
    actual_sequence = [
        marker for marker in NAMESPACED_PATTERN.findall(edited_redacted) if marker in state.mapping
    ]
    actual_literal_counts = {marker: edited_redacted.count(marker) for marker in literal_counts}
    actual_literal_sequence = [
        marker
        for marker in ALL_LITERAL_PLACEHOLDER_PATTERN.findall(edited_redacted)
        if marker in literal_counts
    ]
    foreign_namespaced = (
        set(ALL_NAMESPACED_PATTERN.findall(edited_redacted))
        - set(state.mapping)
        - set(literal_counts)
    )
    expected_literal_placeholders = {
        marker for marker in literal_counts if PLACEHOLDER_PATTERN.fullmatch(marker)
    }
    foreign_plain = set(PLACEHOLDER_PATTERN.findall(edited_redacted)) - (
        expected_literal_placeholders
    )
    if (
        actual_counts != expected_counts
        or actual_sequence != expected_sequence
        or actual_literal_counts != literal_counts
        or actual_literal_sequence != expected_literal_sequence
        or foreign_namespaced
        or foreign_plain
    ):
        raise WorkflowError(
            "PLACEHOLDER_INTEGRITY_FAILED",
            "Edited redacted file changed private placeholder identity or counts.",
        )


def _validate_generated_placeholders(
    manifest: Mapping[str, object], mapping: Mapping[str, str], redacted: str
) -> None:
    """Validate generated marker identity, counts, and order from the manifest."""

    expected_counts = _validated_count_map(manifest.get("placeholder_counts"))
    if set(expected_counts) != set(mapping) or any(
        NAMESPACED_PATTERN.fullmatch(marker) is None for marker in expected_counts
    ):
        raise WorkflowError("INVALID_MANIFEST", "Private placeholder identity is invalid.")
    expected_sequence = manifest.get("placeholder_sequence")
    if not isinstance(expected_sequence, list) or not all(
        isinstance(marker, str) for marker in expected_sequence
    ):
        raise WorkflowError("INVALID_MANIFEST", "Private placeholder sequence is invalid.")
    actual_counts = {marker: redacted.count(marker) for marker in mapping}
    actual_sequence = [
        marker for marker in NAMESPACED_PATTERN.findall(redacted) if marker in mapping
    ]
    if actual_counts != expected_counts or actual_sequence != expected_sequence:
        raise WorkflowError("INVALID_MANIFEST", "Private placeholder metadata is invalid.")


def _reject_symlink_components(path: Path) -> Path:
    """Normalize a user output path while refusing existing symlink components."""

    normalized = Path(os.path.abspath(str(path.expanduser())))
    current = Path(normalized.anchor or os.curdir)
    for component in normalized.parts[1:]:
        current /= component
        try:
            info = current.lstat()
        except FileNotFoundError:
            break
        if stat.S_ISLNK(info.st_mode):
            raise WorkflowError("OUTPUT_SYMLINK_REFUSED", "Output path must not use a symlink.")
        if current != normalized and not stat.S_ISDIR(info.st_mode):
            raise WorkflowError("OUTPUT_PATH_INVALID", "Output parent is not a directory.")
    return normalized


def _validate_restore_output(path: Path, job_dir: Path, *, overwrite: bool) -> Path:
    output = _reject_symlink_components(path)
    if output.exists() or output.is_symlink():
        if output.is_symlink():
            raise WorkflowError("OUTPUT_SYMLINK_REFUSED", "Output path must not be a symlink.")
        if output.is_dir() or not overwrite:
            raise WorkflowError(
                "OUTPUT_EXISTS", "Restore output already exists; overwrite refused."
            )

    resolved_job = job_dir.resolve()
    try:
        relative = output.relative_to(resolved_job)
    except ValueError:
        relative = None
    if relative is not None and (
        len(relative.parts) != 1
        or (
            relative.name != RESTORED_NAME
            and _PRIVATE_RESTORE_OUTPUT_PATTERN.fullmatch(relative.name) is None
        )
    ):
        raise WorkflowError(
            "JOB_OUTPUT_REFUSED",
            "Restore output may not overwrite private job metadata.",
        )
    return output


class PrivateJobStore:
    """Create and mutate quick jobs in the shared private work directory."""

    def __init__(
        self,
        root: Path | None = None,
        *,
        engine: Anonymizer | None = None,
        engine_factory: EngineFactory | None = None,
        ckip_model: str = "ckiplab/bert-base-chinese-ner",
        score_threshold: float = 0.5,
    ) -> None:
        validated_threshold = _validate_score_threshold(score_threshold)
        self.root = _ensure_jobs_root(root or default_jobs_root())
        self._engine = engine
        self._engine_factory = engine_factory
        self.ckip_model = ckip_model
        self.score_threshold = validated_threshold

    def _get_engine(self) -> Anonymizer:
        if self._engine is None:
            # Third-party NER dependencies can print warnings containing the
            # source text.  The quick boundary must discard those streams,
            # even when the caller is the CLI rather than the isolated skill.
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                if self._engine_factory is not None:
                    self._engine = self._engine_factory(self.ckip_model, self.score_threshold)
                else:
                    from pii_guard.pipeline.engine import PiiGuardEngine

                    self._engine = PiiGuardEngine(
                        ckip_model=self.ckip_model,
                        score_threshold=self.score_threshold,
                    )
        return self._engine

    def _job_dir(self, job_id: str) -> Path:
        _validate_job_id(job_id)
        candidate = self.root / job_id
        if candidate.is_symlink():
            raise WorkflowError("JOB_NOT_FOUND", "Private job was not found.")
        if candidate.parent != self.root:
            raise WorkflowError("INVALID_JOB_ID", "Job ID resolves outside the private jobs root.")
        if not candidate.is_dir():
            raise WorkflowError("JOB_NOT_FOUND", "Private job was not found.")
        _assert_owner_mode(candidate, JOB_MODE, directory=True)
        return candidate

    def _materialize(
        self,
        *,
        job_id: str,
        job_dir: Path,
        original: str,
        source_path: Path,
        model: str,
        source_format: str = "text",
        page_count: int | None = None,
    ) -> None:
        if len(original.encode("utf-8")) > MAX_INPUT_BYTES:
            raise WorkflowError("INPUT_TOO_LARGE", "Input exceeds the safety size limit.")
        protected, literal_tokens = _protect_literal_placeholders(original)
        try:
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                redacted_raw, raw_mapping = self._get_engine().anonymize(protected)
        except Exception as exc:
            raise WorkflowError("PII_GUARD_FAILED", "Quick redaction failed safely.") from exc
        redacted, mapping = _namespace_anonymized(redacted_raw, raw_mapping, job_id, literal_tokens)
        if _replace_all(redacted, mapping) != original:
            raise WorkflowError(
                "ROUNDTRIP_INTEGRITY_FAILED",
                "Quick redaction failed round-trip verification.",
            )
        _write_private(job_dir / REDACTED_NAME, redacted)
        _write_private(
            job_dir / PRIVATE_MAP_NAME,
            _mapping_text(mapping),
        )
        manifest = _manifest_for(
            job_id=job_id,
            job_dir=job_dir,
            original=original,
            redacted=redacted,
            mapping=mapping,
            model=model,
            source_path=source_path,
            source_format=source_format,
            page_count=page_count,
        )
        _write_private(
            job_dir / MANIFEST_NAME,
            json.dumps(manifest, ensure_ascii=False, sort_keys=True),
        )

    def create_quick_from_text(
        self,
        text: str,
        *,
        source_name: str = "upload.txt",
        source_format: str = "text",
        page_count: int | None = None,
    ) -> dict[str, object]:
        """Create a quick job and return only its public redacted receipt."""

        if not isinstance(text, str):
            raise WorkflowError("INPUT_NOT_UTF8", "Input must be UTF-8 plain text.")
        if len(text.encode("utf-8")) > MAX_INPUT_BYTES:
            raise WorkflowError("INPUT_TOO_LARGE", "Input exceeds the safety size limit.")
        suffix = Path(source_name).suffix.lower()
        if source_format not in {"text", "pdf"}:
            raise WorkflowError("UNSUPPORTED_FORMAT", "Input format is not supported.")
        if source_format == "text" and suffix and suffix not in SUPPORTED_SUFFIXES:
            raise WorkflowError(
                "UNSUPPORTED_FORMAT", "Only verified UTF-8 plain-text files are supported."
            )
        if source_format == "pdf" and suffix != PDF_SUFFIX:
            raise WorkflowError("PDF_INVALID_UPLOAD", "PDF upload is invalid.")
        if source_format == "pdf" and (
            not isinstance(page_count, int)
            or isinstance(page_count, bool)
            or not 1 <= page_count <= MAX_PDF_PAGES
        ):
            raise WorkflowError("PDF_MALFORMED", "PDF page count is invalid.")
        if source_format == "text" and page_count is not None:
            raise WorkflowError("UNSUPPORTED_FORMAT", "Input format is not supported.")
        job_id = uuid.uuid4().hex
        job_dir = self.root / job_id
        job_dir.mkdir(mode=JOB_MODE)
        job_dir.chmod(JOB_MODE)
        source_path = job_dir / SOURCE_NAME
        try:
            _ensure_lock_file(job_dir)
            with _job_lock(job_dir, exclusive=True):
                _write_private(source_path, text)
                self._materialize(
                    job_id=job_id,
                    job_dir=job_dir,
                    original=text,
                    source_path=source_path,
                    model=self.ckip_model,
                    source_format=source_format,
                    page_count=page_count,
                )
            return self.public_state(job_id)
        except BaseException:
            shutil.rmtree(job_dir, ignore_errors=True)
            raise

    def create_quick_from_pdf_bytes(self, data: bytes) -> dict[str, object]:
        """Extract and process a PDF without persisting the uploaded bytes."""

        extraction = extract_pdf_text(data)
        return self.create_quick_from_text(
            extraction.text,
            source_name="upload.pdf",
            source_format="pdf",
            page_count=extraction.page_count,
        )

    def create_quick_from_path(self, path: Path) -> dict[str, object]:
        """Read one safe source path and create the corresponding private job."""

        source = path.expanduser()
        if source.suffix.lower() not in SUPPORTED_SUFFIXES:
            raise WorkflowError(
                "UNSUPPORTED_FORMAT", "Only verified UTF-8 plain-text files are supported."
            )
        text = _read_utf8(source)
        return self.create_quick_from_text(text, source_name=source.name)

    def materialize_existing_quick_job(
        self,
        job_dir: Path,
        job_id: str,
        *,
        model: str = "quick",
        source_path: Path | None = None,
    ) -> None:
        """Materialize a skill-created private snapshot without Ollama."""

        _validate_job_id(job_id)
        resolved_dir = job_dir
        if resolved_dir.is_symlink() or resolved_dir.name != job_id:
            raise WorkflowError("INVALID_JOB_ID", "Private job directory is invalid.")
        if resolved_dir.parent != self.root:
            raise WorkflowError("INVALID_JOB_ID", "Private job directory is invalid.")
        _assert_owner_mode(resolved_dir, JOB_MODE, directory=True)
        source = source_path or (resolved_dir / SOURCE_NAME)
        if source.is_symlink() or source != resolved_dir / SOURCE_NAME:
            raise WorkflowError("INVALID_WORKER_PATH", "Private snapshot path is invalid.")
        with _job_lock(resolved_dir, exclusive=True):
            original = _read_utf8(source)
            self._materialize(
                job_id=job_id,
                job_dir=resolved_dir,
                original=original,
                source_path=source,
                model=model,
                source_format="text",
            )

    def _load_state_unlocked(self, job_id: str, job_dir: Path) -> JobState:
        """Load and validate one job while its caller owns the job lock."""

        for name in (SOURCE_NAME, REDACTED_NAME, PRIVATE_MAP_NAME, MANIFEST_NAME):
            _assert_owner_mode(job_dir / name, PRIVATE_MODE, directory=False)
        raw_manifest = _safe_json(job_dir / MANIFEST_NAME)
        raw_mapping = _safe_json(job_dir / PRIVATE_MAP_NAME)
        if (
            not isinstance(raw_manifest, dict)
            or raw_manifest.get("kind") != WORKFLOW_KIND
            or raw_manifest.get("job_id") != job_id
            or raw_manifest.get("version") != WORKFLOW_VERSION
        ):
            raise WorkflowError("INVALID_JOB", "Private job metadata is invalid.")
        if not isinstance(raw_mapping, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in raw_mapping.items()
        ):
            raise WorkflowError("INVALID_MAPPING", "Private mapping is invalid.")
        mapping = dict(raw_mapping)
        if any(
            NAMESPACED_PATTERN.fullmatch(key) is None or not value for key, value in mapping.items()
        ):
            raise WorkflowError("INVALID_MAPPING", "Private mapping markers are invalid.")
        marker_prefix = f"[[PII-{job_id[:10]}-"
        if any(not key.startswith(marker_prefix) for key in mapping):
            raise WorkflowError("INVALID_MAPPING", "Private mapping belongs to another job.")
        source = job_dir / SOURCE_NAME
        original = _read_utf8(source)
        redacted = _read_utf8(job_dir / REDACTED_NAME)
        if raw_manifest.get("original_path") != str(source):
            raise WorkflowError("INVALID_JOB", "Private job source provenance is invalid.")
        if raw_manifest.get("original_sha256") != _sha256_text(original):
            raise WorkflowError("ORIGINAL_CHANGED", "Private source changed since redaction.")
        if raw_manifest.get("mapping_sha256") != _sha256_text(_mapping_text(mapping)):
            raise WorkflowError(
                "INTEGRITY_CHECK_FAILED", "Private job integrity verification failed."
            )
        if raw_manifest.get("redacted_sha256") != _sha256_text(redacted):
            raise WorkflowError(
                "INTEGRITY_CHECK_FAILED", "Private job integrity verification failed."
            )
        source_format = raw_manifest.get("source_format", "text")
        if source_format not in {"text", "pdf"}:
            raise WorkflowError("INVALID_JOB", "Private source format is invalid.")
        if source_format == "pdf":
            page_count = raw_manifest.get("page_count")
            if (
                not isinstance(page_count, int)
                or isinstance(page_count, bool)
                or not 1 <= page_count <= MAX_PDF_PAGES
            ):
                raise WorkflowError("INVALID_JOB", "Private PDF page count is invalid.")
        elif "page_count" in raw_manifest:
            raise WorkflowError("INVALID_JOB", "Private source format is invalid.")
        literal_markers = _validated_literal_markers(raw_manifest, original, redacted)
        if literal_markers & set(mapping):
            raise WorkflowError("INVALID_MANIFEST", "Private placeholder identity is invalid.")
        _validate_generated_placeholders(raw_manifest, mapping, redacted)
        if _replace_all(redacted, mapping) != original:
            raise WorkflowError("ROUNDTRIP_INTEGRITY_FAILED", "Private job no longer round-trips.")
        foreign_namespaced = (
            set(ALL_NAMESPACED_PATTERN.findall(redacted)) - set(mapping) - literal_markers
        )
        if foreign_namespaced:
            raise WorkflowError("INVALID_MAPPING", "Private mapping markers are inconsistent.")
        return JobState(job_id, job_dir, original, redacted, mapping, dict(raw_manifest))

    def load_state(self, job_id: str) -> JobState:
        job_dir = self._job_dir(job_id)
        with _job_lock(job_dir, exclusive=False):
            return self._load_state_unlocked(job_id, job_dir)

    @staticmethod
    def _public_state_from_state(state: JobState) -> dict[str, object]:
        """Build a public receipt from a state already protected by a lock."""

        placeholders: list[dict[str, str]] = []
        for placeholder in sorted(state.mapping):
            parsed = _split_marker(placeholder)
            if parsed is None:
                continue
            placeholders.append(
                {
                    "token": f"{parsed[0]}-{parsed[1]}",
                    "placeholder": placeholder,
                }
            )
        result: dict[str, object] = {
            "ok": True,
            "job_id": state.job_id,
            "mode": "quick",
            "source_format": state.manifest.get("source_format", "text"),
            "anonymized_text": state.redacted,
            "placeholders": placeholders,
            "replacement_count": len(state.mapping),
            "roundtrip_verified": True,
        }
        if result["source_format"] == "pdf":
            result["page_count"] = state.manifest["page_count"]
        return result

    def public_state(self, job_id: str) -> dict[str, object]:
        """Return a JSON-safe state with no mapping values."""

        state = self.load_state(job_id)
        return self._public_state_from_state(state)

    @staticmethod
    def _clean_terms(terms: Iterable[str]) -> list[str]:
        if isinstance(terms, (str, bytes)):
            raise WorkflowError("INVALID_TERM", "Terms must be provided as a list of strings.")
        cleaned: list[str] = []
        for term in terms:
            if not isinstance(term, str):
                raise WorkflowError("INVALID_TERM", "Terms must be strings.")
            value = term.strip()
            if not value or "[[" in value or "]]" in value or "\x00" in value:
                raise WorkflowError("INVALID_TERM", "Terms are invalid for a private annotation.")
            if len(value.encode("utf-8")) > MAX_TERM_BYTES:
                raise WorkflowError("INVALID_TERM", "A selected term is too long.")
            if value not in cleaned:
                cleaned.append(value)
        if not cleaned:
            raise WorkflowError("NO_TERMS", "No usable annotation terms were provided.")
        if len(cleaned) > MAX_ANNOTATION_TERMS:
            raise WorkflowError("TOO_MANY_TERMS", "Too many annotation terms were provided.")
        return cleaned

    @staticmethod
    def _apply_mask(
        redacted: str,
        mapping: dict[str, str],
        job_id: str,
        terms: Iterable[str],
    ) -> tuple[str, dict[str, str], int, int, int]:
        shielded = redacted
        sentinels: dict[str, str] = {}
        for index, placeholder in enumerate(sorted(mapping, key=len, reverse=True)):
            sentinel = f"\x00PII_SHIELD_{index}_{uuid.uuid4().hex[:12]}\x00"
            sentinels[sentinel] = placeholder
            shielded = shielded.replace(placeholder, sentinel)
        used = [
            parsed[1]
            for placeholder in mapping
            if (parsed := _split_marker(placeholder)) is not None and parsed[0] == "MANUAL"
        ]
        counter = max(used, default=0)
        applied = 0
        missing = 0
        occurrences = 0
        for term in sorted(terms, key=len, reverse=True):
            found = shielded.count(term)
            if not found:
                missing += 1
                continue
            counter += 1
            placeholder = f"[[PII-{job_id[:10]}-MANUAL-{counter}]]"
            shielded = shielded.replace(term, placeholder)
            mapping[placeholder] = term
            applied += 1
            occurrences += found
        for sentinel, placeholder in sentinels.items():
            shielded = shielded.replace(sentinel, placeholder)
        return shielded, mapping, applied, missing, occurrences

    def _commit_state(
        self,
        state: JobState,
        redacted: str,
        mapping: dict[str, str],
        *,
        annotation: Mapping[str, object],
    ) -> None:
        if _replace_all(redacted, mapping) != state.original:
            raise WorkflowError(
                "ROUNDTRIP_INTEGRITY_FAILED", "Review edit failed round-trip verification."
            )
        source_format = state.manifest.get("source_format", "text")
        source_page_count = state.manifest.get("page_count")
        page_count = (
            source_page_count
            if isinstance(source_page_count, int) and not isinstance(source_page_count, bool)
            else None
        )
        manifest = _manifest_for(
            job_id=state.job_id,
            job_dir=state.job_dir,
            original=state.original,
            redacted=redacted,
            mapping=mapping,
            model="quick",
            source_path=state.job_dir / SOURCE_NAME,
            source_format=str(source_format),
            page_count=page_count if source_format == "pdf" else None,
            previous=state.manifest,
        )
        history = manifest.get("manual_annotations", [])
        history_list = list(history) if isinstance(history, list) else []
        history_list.append(dict(annotation))
        manifest["manual_annotations"] = history_list
        _write_private(state.job_dir / REDACTED_NAME, redacted, replace=True)
        _write_private(
            state.job_dir / PRIVATE_MAP_NAME,
            json.dumps(mapping, ensure_ascii=False, sort_keys=True),
            replace=True,
        )
        _write_private(
            state.job_dir / MANIFEST_NAME,
            json.dumps(manifest, ensure_ascii=False, sort_keys=True),
            replace=True,
        )

    def mask_terms(self, job_id: str, terms: Iterable[str]) -> dict[str, object]:
        cleaned = self._clean_terms(terms)
        job_dir = self._job_dir(job_id)
        with _job_lock(job_dir, exclusive=True):
            state = self._load_state_unlocked(job_id, job_dir)
            redacted, mapping, applied, missing, occurrences = self._apply_mask(
                state.redacted, dict(state.mapping), job_id, cleaned
            )
            if applied:
                self._commit_state(
                    state,
                    redacted,
                    mapping,
                    annotation={"action": "mask", "applied": applied, "not_found": missing},
                )
            result = self._public_state_from_state(self._load_state_unlocked(job_id, job_dir))
            result.update(
                {
                    "terms_masked": applied,
                    "terms_not_found": missing,
                    "occurrences": occurrences,
                    "roundtrip_verified": True,
                }
            )
            return result

    def restore_edited_redacted(
        self,
        job_id: str,
        edited_redacted: str | None = None,
        *,
        output_path: Path | None = None,
        overwrite: bool = True,
    ) -> RestoreResult:
        """Restore an edited redacted quick job through the shared core.

        The input may change ordinary non-placeholder text, but all generated
        markers and literal placeholders must retain the manifest's identity,
        occurrence counts, and order.  The returned path and digest are for
        local callers that must verify a private artifact; public adapters
        deliberately select a smaller receipt.
        """

        job_dir = self._job_dir(job_id)
        with _job_lock(job_dir, exclusive=True):
            state = self._load_state_unlocked(job_id, job_dir)
            if state.manifest.get("mode") != "quick":
                raise WorkflowError(
                    "MODE_UNAVAILABLE",
                    "This restore core only accepts quick-mode private jobs.",
                )
            edited = state.redacted if edited_redacted is None else edited_redacted
            _validate_edited_redacted(state, edited)
            restored = _replace_all(edited, state.mapping)
            destination = _validate_restore_output(
                output_path or (state.job_dir / RESTORED_NAME),
                state.job_dir,
                overwrite=overwrite,
            )
            try:
                _write_private(destination, restored, replace=overwrite)
            except FileExistsError as exc:
                raise WorkflowError(
                    "OUTPUT_EXISTS", "Restore output already exists; overwrite refused."
                ) from exc
            return RestoreResult(
                job_id=job_id,
                output_path=destination,
                restored_sha256=_sha256_text(restored),
                roundtrip_equal=restored == state.original,
            )

    def restore_to_private(self, job_id: str) -> dict[str, object]:
        """Write the stored redacted text to a private job artifact."""

        result = self.restore_edited_redacted(job_id)
        return {
            "ok": True,
            "job_id": job_id,
            "roundtrip_equal": result.roundtrip_equal,
            "agent_may_read_restored": False,
        }

    def delete(self, job_id: str) -> None:
        """Delete one validated private job and nothing outside the jobs root."""

        job_dir = self._job_dir(job_id)
        with _job_lock(job_dir, exclusive=True):
            known_files = {
                SOURCE_NAME,
                REDACTED_NAME,
                PRIVATE_MAP_NAME,
                MANIFEST_NAME,
                RESTORED_NAME,
                LOCK_NAME,
            }
            temporary_pattern = re.compile(
                r"^\.[A-Za-z0-9._-]+\.(?:private\.txt|private\.json|safe\.json)$"
            )
            for entry in job_dir.iterdir():
                if entry.is_symlink() or not entry.is_file():
                    raise WorkflowError("INVALID_JOB", "Private job contains an unknown artifact.")
                if (
                    entry.name not in known_files
                    and temporary_pattern.fullmatch(entry.name) is None
                ):
                    raise WorkflowError("INVALID_JOB", "Private job contains an unknown artifact.")
            manifest = _safe_json(job_dir / MANIFEST_NAME)
            if not isinstance(manifest, dict) or manifest.get("kind") != WORKFLOW_KIND:
                raise WorkflowError("INVALID_JOB", "Private job metadata is invalid.")
            if manifest.get("job_id") != job_id:
                raise WorkflowError("INVALID_JOB", "Private job identity is invalid.")
            shutil.rmtree(job_dir)
