"""Single-child manager for the optional local enhanced audit.

The manager is intentionally independent from the quick workflow.  Importing
this module does not import an audit model client or contact Ollama; the
enhanced module is imported only inside the spawned worker after a job has
been explicitly started.
"""

from __future__ import annotations

import io
import json
import logging
import multiprocessing
import os
import stat
import threading
import time
from collections.abc import Callable, Mapping
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from dataclasses import dataclass
from multiprocessing.connection import Connection
from multiprocessing.process import BaseProcess
from pathlib import Path
from typing import Any, cast

from pii_guard._compat import (
    is_reparse_point,
    lock_descriptor,
    mode_matches,
    owner_matches,
    set_descriptor_mode,
    unlock_descriptor,
)
from pii_guard.local_workflow import (
    JOB_MODE,
    EnhancedAttempt,
    WorkflowError,
)

AUDIT_PROCESS_GRACE_SECONDS = 0.5
AUDIT_DEFAULT_TIMEOUT_SECONDS = 5_400.0
MAX_AUDIT_RESPONSE_BYTES = 512 * 1024
MANAGER_LEASE_NAME = ".enhanced-audit-manager.lock"
_LEASE_REGISTRY_LOCK = threading.Lock()
_LEASED_ROOTS: set[Path] = set()
SAFE_AUDIT_CODES = frozenset(
    {
        "AUDIT_UNAVAILABLE",
        "AUDIT_TIMEOUT",
        "AUDIT_FAILED",
        "AUDIT_CRASHED",
        "AUDIT_CANCELLED",
        "AUDIT_RESOURCE_LIMIT",
        "AUDIT_INVALID_RESULT",
        "AUDIT_INTERRUPTED",
        "LOCAL_MODEL_UNVERIFIED",
        "LOCAL_AUDIT_UNAVAILABLE",
        "LOCAL_AUDIT_INVALID",
        "LOCAL_AUDIT_UNRESOLVED",
        "LOCAL_AUDIT_RESIDUAL",
        "ADVERSARIAL_INPUT_REVIEW_REQUIRED",
        "LEAKAGE_CHECK_FAILED",
        "INVALID_MAPPING",
        "ROUNDTRIP_INTEGRITY_FAILED",
        "INVALID_OLLAMA_URL",
        "INVALID_AUDIT_CONFIG",
        "AUDIT_CALL_BUDGET_EXCEEDED",
    }
)


def _acquire_manager_lease(store: object) -> tuple[Path, int]:
    """Hold one process- and host-wide manager lease for a jobs root."""

    root_value = getattr(store, "root", None)
    if not isinstance(root_value, Path):
        raise WorkflowError("AUDIT_UNAVAILABLE", "Enhanced audit manager is unavailable.")
    root = root_value.resolve()
    lease_path = root / MANAGER_LEASE_NAME
    descriptor: int | None = None
    with _LEASE_REGISTRY_LOCK:
        if root in _LEASED_ROOTS:
            raise WorkflowError("ENHANCED_BUSY", "Another enhanced audit manager is active.")
        try:
            descriptor = os.open(
                lease_path,
                os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            info = os.fstat(descriptor)
            path_info = lease_path.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or not owner_matches(info)
                or info.st_nlink != 1
                or is_reparse_point(path_info)
                or path_info.st_dev != info.st_dev
                or path_info.st_ino != info.st_ino
            ):
                raise OSError("unsafe manager lease")
            set_descriptor_mode(descriptor, 0o600)
            lock_descriptor(descriptor, exclusive=True, blocking=False)
        except (BlockingIOError, OSError):
            if descriptor is not None:
                os.close(descriptor)
            raise WorkflowError(
                "ENHANCED_BUSY", "Another enhanced audit manager is active."
            ) from None
        _LEASED_ROOTS.add(root)
    return root, descriptor


def _release_manager_lease(root: Path, descriptor: int) -> None:
    with _LEASE_REGISTRY_LOCK:
        _LEASED_ROOTS.discard(root)
        try:
            unlock_descriptor(descriptor)
        finally:
            os.close(descriptor)


@dataclass(frozen=True)
class _WorkerResult:
    ok: bool
    redacted_text: str | None = None
    mapping: dict[str, str] | None = None
    error_code: str | None = None
    progress: dict[str, object] | None = None


def _safe_progress(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        return {
            "completed": 0,
            "total": 0,
            "pass_number": 0,
            "scope": "enhanced_audit",
        }
    output: dict[str, object] = {}
    for key in ("completed", "total", "pass_number"):
        count = value.get(key)
        if isinstance(count, int) and not isinstance(count, bool) and 0 <= count <= 1_000_000:
            output[key] = count
    scope = value.get("scope")
    if isinstance(scope, str) and scope in {"enhanced_audit", "pii_review"}:
        output["scope"] = scope
    output.setdefault("completed", 0)
    output.setdefault("total", 0)
    output.setdefault("pass_number", 0)
    output.setdefault("scope", "enhanced_audit")
    return output


def _safe_summary(result: object) -> dict[str, object]:
    """Extract bounded audit evidence without carrying model text forward."""

    summary: dict[str, object] = {}
    for output_key, names in (
        ("audit_passes", ("audit_passes", "passes")),
        ("selected_paragraphs", ("selected_paragraphs",)),
        ("total_paragraphs", ("total_paragraphs",)),
        ("model_calls", ("model_calls",)),
    ):
        value = _value(result, names)
        if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 1_000_000:
            summary[output_key] = value
    scope = _value(result, ("audit_scope", "scope"))
    if isinstance(scope, str) and scope in {
        "full",
        "suspicious_paragraphs",
        "enhanced_audit",
        "pii_review",
    }:
        summary["audit_scope"] = scope
    return summary


def _value(result: object, names: tuple[str, ...]) -> object:
    if isinstance(result, Mapping):
        for name in names:
            if name in result:
                return result[name]
        return None
    for name in names:
        try:
            return getattr(result, name)
        except AttributeError:
            continue
    return None


def _safe_error_code(error: BaseException) -> str:
    candidate = getattr(error, "code", None)
    if isinstance(candidate, str) and candidate in SAFE_AUDIT_CODES:
        return candidate
    name = type(error).__name__
    return {
        "TimeoutError": "AUDIT_TIMEOUT",
        "MemoryError": "AUDIT_RESOURCE_LIMIT",
        "AuditUnavailable": "AUDIT_UNAVAILABLE",
        "AuditError": "AUDIT_FAILED",
    }.get(name, "AUDIT_FAILED")


def _result_payload(result: object) -> dict[str, object]:
    """Extract only the private candidate fields required by the parent."""

    candidate_text = _value(result, ("redacted_text", "redacted", "anonymized_text", "text"))
    candidate_mapping = _value(result, ("mapping", "replacement_map", "private_mapping"))
    passed = _value(result, ("passed", "ok", "success"))
    if passed is False:
        code = _value(result, ("error_code", "code"))
        safe_code = code if isinstance(code, str) and code in SAFE_AUDIT_CODES else "AUDIT_FAILED"
        return {"ok": False, "code": safe_code}
    if passed is not True:
        return {"ok": False, "code": "AUDIT_INVALID_RESULT"}
    if not isinstance(candidate_text, str):
        return {"ok": False, "code": "AUDIT_INVALID_RESULT"}
    if not isinstance(candidate_mapping, Mapping) or not all(
        isinstance(key, str) and isinstance(value, str) and value
        for key, value in candidate_mapping.items()
    ):
        return {"ok": False, "code": "AUDIT_INVALID_RESULT"}
    mapping = dict(candidate_mapping)
    progress = _safe_progress(_value(result, ("progress", "audit_progress")))
    payload: dict[str, object] = {
        "ok": True,
        "redacted_text": candidate_text,
        "mapping": mapping,
        "progress": progress,
    }
    summary = _safe_summary(result)
    if summary:
        payload["summary"] = summary
    return payload


class _ProgressProxy:
    """Callable/object-compatible progress sink with no raw model output."""

    def __init__(self, connection: Connection) -> None:
        self.connection = connection
        self.last: dict[str, object] = _safe_progress(None)
        self._last_sent = 0.0

    def __call__(self, value: object = None, **kwargs: object) -> None:
        candidate: object = value if value is not None else kwargs
        if not isinstance(candidate, Mapping):
            candidate = {
                key: getattr(value, key)
                for key in ("completed", "total", "scope", "pass_number")
                if value is not None and hasattr(value, key)
            }
        self.update(candidate)

    def update(self, value: object = None, **kwargs: object) -> None:
        candidate: object = value if value is not None else kwargs
        progress = _safe_progress(candidate)
        self.last = progress
        now = time.monotonic()
        if now - self._last_sent < 0.05:
            return
        self._last_sent = now
        payload = json.dumps(
            {"kind": "progress", "progress": progress},
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(payload) > MAX_AUDIT_RESPONSE_BYTES:
            return
        try:
            self.connection.send_bytes(payload)
        except (BrokenPipeError, EOFError, OSError):
            return


@contextmanager
def _silence_worker_output():
    """Suppress child stdout/stderr at descriptor level before model import."""

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


def _make_config(
    module: Any,
    model: str | None,
    ollama_url: str | None,
    supplied: object,
) -> object:
    if supplied is not None:
        return supplied
    config_class = getattr(module, "AuditConfig", None)
    if config_class is None:
        return None
    selected_model = model if model is not None else getattr(module, "DEFAULT_AUDIT_MODEL", None)
    selected_url = (
        ollama_url if ollama_url is not None else getattr(module, "DEFAULT_OLLAMA_URL", None)
    )
    variants: tuple[dict[str, object], ...] = (
        {"model": selected_model, "ollama_url": selected_url},
        {"audit_model": selected_model, "ollama_url": selected_url},
        {"model_name": selected_model, "base_url": selected_url},
        {},
    )
    for kwargs in variants:
        try:
            filtered = {key: value for key, value in kwargs.items() if value is not None}
            return config_class(**filtered)
        except (TypeError, ValueError):
            continue
    return None


def _audit_worker(
    attempt: EnhancedAttempt,
    output_connection: Connection,
    model: str | None,
    ollama_url: str | None,
    config: object,
    runner: Callable[..., object] | None,
) -> None:
    """Run the model audit in the sole manager child and return safe fields."""

    with _silence_worker_output():
        try:
            if runner is None:
                from importlib import import_module

                module = import_module("pii_guard.enhanced_audit")
                runner = getattr(module, "run_enhanced_audit")
            else:
                module = None
            selected_config = _make_config(module, model, ollama_url, config) if module else config
            progress_proxy = _ProgressProxy(output_connection)
            result = runner(
                attempt.original,
                attempt.redacted,
                attempt.mapping,
                job_id=attempt.job_id,
                config=selected_config,
                progress=progress_proxy,
            )
            payload = _result_payload(result)
            if payload.get("ok") is True:
                result_progress = _value(result, ("progress", "audit_progress"))
                payload["progress"] = (
                    _safe_progress(result_progress)
                    if result_progress is not None
                    else progress_proxy.last
                )
        except BaseException as error:
            payload = {"ok": False, "code": _safe_error_code(error)}
        try:
            encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            if len(encoded) > MAX_AUDIT_RESPONSE_BYTES:
                encoded = b'{"ok":false,"code":"AUDIT_INVALID_RESULT"}'
            output_connection.send_bytes(encoded)
        except (BrokenPipeError, EOFError, OSError, TypeError, UnicodeError):
            pass
        finally:
            try:
                output_connection.close()
            except OSError:
                pass


class AuditManager:
    """Own one spawned enhanced worker for the lifetime of one app instance."""

    def __init__(
        self,
        store: object,
        *,
        audit_model: str | None = None,
        ollama_url: str | None = None,
        config: object = None,
        timeout_seconds: float = AUDIT_DEFAULT_TIMEOUT_SECONDS,
        runner: Callable[..., object] | None = None,
    ) -> None:
        if not isinstance(timeout_seconds, (int, float)) or timeout_seconds <= 0:
            raise WorkflowError("AUDIT_UNAVAILABLE", "Enhanced audit manager is unavailable.")
        self.store: Any = store
        self.audit_model = audit_model
        self.ollama_url = ollama_url
        self.config = config
        self.timeout_seconds = float(timeout_seconds)
        self.runner = runner
        self._lock = threading.RLock()
        self._process: BaseProcess | None = None
        self._connection: Connection | None = None
        self._attempt: EnhancedAttempt | None = None
        self._attempt_dir: Path | None = None
        self._monitor: threading.Thread | None = None
        self._terminal_publication_failed = False
        self._closed = False
        self._lease_root, self._lease_descriptor = _acquire_manager_lease(store)
        try:
            register = getattr(store, "_register_audit_manager", None)
            if callable(register):
                register(self)
            # The root lease proves there is no live manager for this jobs
            # root. Only now may abandoned active states be recovered.
            recover = getattr(store, "recover_stale_enhanced_jobs", None)
            if callable(recover):
                recover()
        except BaseException:
            _release_manager_lease(self._lease_root, self._lease_descriptor)
            raise

    def _clear_active(self) -> None:
        self._process = None
        self._connection = None
        self._attempt = None
        self._attempt_dir = None
        self._monitor = None
        self._terminal_publication_failed = False

    def _publish_terminal_state(
        self,
        attempt: EnhancedAttempt,
        *,
        status: str,
        result: object | None,
        error_code: str | None,
        progress: dict[str, object],
    ) -> bool:
        """Publish a terminal state, retrying one transient storage failure."""

        finish = getattr(self.store, "_finish_enhanced_attempt", None)
        if not callable(finish):
            return False
        for retry_number in range(2):
            try:
                published = finish(
                    attempt,
                    status=status,
                    result=result,
                    error_code=error_code,
                    progress=progress,
                )
                if published is not False:
                    return True
            except (OSError, WorkflowError):
                pass
            if retry_number == 0:
                time.sleep(0.05)
        return False

    def _cleanup_attempt_dir(self, path: Path | None) -> None:
        if path is None:
            return
        try:
            import shutil

            info = path.lstat()
            if stat.S_ISDIR(info.st_mode) and not is_reparse_point(info):
                shutil.rmtree(path)
        except (OSError, ValueError):
            return

    @staticmethod
    def _stop_process(process: BaseProcess | None) -> None:
        if process is None:
            return
        try:
            if process.is_alive():
                process.terminate()
                process.join(AUDIT_PROCESS_GRACE_SECONDS)
            if process.is_alive() and hasattr(process, "kill"):
                process.kill()
                process.join(AUDIT_PROCESS_GRACE_SECONDS)
            else:
                process.join()
        except (AssertionError, OSError, ValueError):
            return

    def _new_attempt_dir(self, attempt: EnhancedAttempt) -> Path:
        path = Path(self.store.root) / attempt.job_id / f".attempt-{attempt.attempt_token}"
        path.mkdir(mode=JOB_MODE)
        path.chmod(JOB_MODE)
        info = path.lstat()
        if (
            is_reparse_point(info)
            or not stat.S_ISDIR(info.st_mode)
            or not owner_matches(info)
            or not mode_matches(info, JOB_MODE)
        ):
            raise WorkflowError("PERMISSION_CHECK_FAILED", "Private audit path is unsafe.")
        return path

    def _ensure_idle(self) -> None:
        """Wait briefly for a completed monitor so restart is race-safe."""

        with self._lock:
            if self._terminal_publication_failed:
                raise WorkflowError(
                    "AUDIT_UNAVAILABLE",
                    "Enhanced audit terminal state could not be published.",
                )
            process = self._process
            monitor = self._monitor
        if monitor is not None and monitor.is_alive() and monitor is not threading.current_thread():
            monitor.join(AUDIT_PROCESS_GRACE_SECONDS * 4)
        if process is not None:
            try:
                if process.is_alive():
                    raise WorkflowError(
                        "ENHANCED_BUSY", "Another enhanced audit is already running."
                    )
            except AssertionError:
                pass
        with self._lock:
            if self._monitor is not None and self._monitor.is_alive():
                raise WorkflowError("ENHANCED_BUSY", "Another enhanced audit is already running.")
            if self._process is not None:
                self._clear_active()

    def start(self, job_id: str) -> dict[str, object]:
        """Claim and spawn one enhanced audit, returning a safe running receipt."""

        with self._lock:
            if self._closed:
                raise WorkflowError("AUDIT_UNAVAILABLE", "Enhanced audit manager is closed.")
        self._ensure_idle()
        with self._lock:
            if self._closed:
                raise WorkflowError("AUDIT_UNAVAILABLE", "Enhanced audit manager is closed.")
            if self._process is not None or self._monitor is not None:
                raise WorkflowError("ENHANCED_BUSY", "Another enhanced audit is already running.")
            begin = getattr(self.store, "_begin_enhanced_attempt", None)
            if not callable(begin):
                raise WorkflowError("AUDIT_UNAVAILABLE", "Enhanced audit manager is unavailable.")
            attempt = begin(job_id)
            if not isinstance(attempt, EnhancedAttempt):
                raise WorkflowError("AUDIT_UNAVAILABLE", "Enhanced audit manager is unavailable.")
            attempt_dir: Path | None = None
            output_read: Connection | None = None
            output_write: Connection | None = None
            process: BaseProcess | None = None
            try:
                attempt_dir = self._new_attempt_dir(attempt)
                context = multiprocessing.get_context("spawn")
                raw_output_read, raw_output_write = context.Pipe(duplex=False)
                output_read = cast(Connection, raw_output_read)
                output_write = cast(Connection, raw_output_write)
                process = context.Process(
                    target=_audit_worker,
                    args=(
                        attempt,
                        output_write,
                        self.audit_model,
                        self.ollama_url,
                        self.config,
                        self.runner,
                    ),
                    daemon=True,
                )
                process.start()
            except Exception:
                # Spawn pickles the attempt, config, and runner; a pickling
                # failure surfaces as PicklingError or AttributeError, which
                # the previous narrower clause let escape with the manifest
                # stuck in "running" and both pipe ends still open.
                if output_read is not None:
                    output_read.close()
                if output_write is not None:
                    output_write.close()
                self._cleanup_attempt_dir(attempt_dir)
                finish = getattr(self.store, "_finish_enhanced_attempt", None)
                if callable(finish):
                    finish(attempt, status="failed", error_code="AUDIT_UNAVAILABLE")
                self._stop_process(process)
                raise WorkflowError(
                    "AUDIT_UNAVAILABLE", "Enhanced audit could not be started safely."
                ) from None
            if (
                output_read is None
                or output_write is None
                or process is None
                or attempt_dir is None
            ):
                raise WorkflowError(
                    "AUDIT_UNAVAILABLE", "Enhanced audit could not be started safely."
                )
            output_write.close()
            self._attempt = attempt
            self._attempt_dir = attempt_dir
            self._process = process
            self._connection = output_read
            monitor = threading.Thread(
                target=self._monitor_worker,
                args=(process, output_read, attempt, attempt_dir),
                name="pii-guard-enhanced-audit",
                daemon=True,
            )
            self._monitor = monitor
            try:
                monitor.start()
            except RuntimeError as exc:
                self._stop_process(process)
                output_read.close()
                self._cleanup_attempt_dir(attempt_dir)
                finish = getattr(self.store, "_finish_enhanced_attempt", None)
                if callable(finish):
                    finish(attempt, status="failed", error_code="AUDIT_UNAVAILABLE")
                self._clear_active()
                raise WorkflowError(
                    "AUDIT_UNAVAILABLE", "Enhanced audit monitor could not be started safely."
                ) from exc
        public = getattr(self.store, "public_state")(job_id)
        return public

    def _monitor_worker(
        self,
        process: BaseProcess,
        connection: Connection,
        attempt: EnhancedAttempt,
        attempt_dir: Path,
    ) -> None:
        payload: dict[str, object] | None = None
        timed_out = False
        terminal_published = False
        deadline = time.monotonic() + self.timeout_seconds
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    self._stop_process(process)
                    break
                try:
                    if connection.poll(min(remaining, 0.05)):
                        encoded = connection.recv_bytes(MAX_AUDIT_RESPONSE_BYTES)
                        decoded = json.loads(encoded.decode("utf-8"))
                        if isinstance(decoded, dict) and decoded.get("kind") == "progress":
                            update = getattr(self.store, "_update_enhanced_progress", None)
                            if callable(update):
                                update(attempt, _safe_progress(decoded.get("progress")))
                            continue
                        if isinstance(decoded, dict):
                            payload = decoded
                        break
                except (EOFError, BufferError, OSError, UnicodeDecodeError, json.JSONDecodeError):
                    break
                try:
                    if not process.is_alive():
                        # Give a just-exited child one final chance to flush.
                        if connection.poll(0.05):
                            encoded = connection.recv_bytes(MAX_AUDIT_RESPONSE_BYTES)
                            decoded = json.loads(encoded.decode("utf-8"))
                            if isinstance(decoded, dict) and decoded.get("kind") != "progress":
                                payload = decoded
                        break
                except (
                    AssertionError,
                    EOFError,
                    BufferError,
                    OSError,
                    UnicodeDecodeError,
                    json.JSONDecodeError,
                ):
                    break
            result: object | None
            error_code: str | None
            if timed_out:
                status = "failed"
                error_code = "AUDIT_TIMEOUT"
                result = None
            elif payload is None:
                status = "failed"
                error_code = "AUDIT_CRASHED"
                result = None
            elif payload.get("ok") is True:
                status = "passed"
                error_code = None
                result = payload
            else:
                status = "failed"
                result = None
                candidate_code = payload.get("code")
                error_code = candidate_code if isinstance(candidate_code, str) else "AUDIT_FAILED"
            # Remove attempt staging before publishing a terminal state. A
            # caller that observes failed/cancelled/passed must never race a
            # still-visible private staging directory.
            self._cleanup_attempt_dir(attempt_dir)
            try:
                process.join(AUDIT_PROCESS_GRACE_SECONDS)
            except (AssertionError, OSError):
                pass
            try:
                child_alive = process.is_alive()
            except AssertionError:
                child_alive = False
            if child_alive:
                self._stop_process(process)
            terminal_published = self._publish_terminal_state(
                attempt,
                status=status,
                result=result,
                error_code=error_code,
                progress=_safe_progress(payload.get("progress") if payload else None),
            )
        finally:
            try:
                connection.close()
            except OSError:
                pass
            try:
                alive = process.is_alive()
            except AssertionError:
                alive = False
            if alive:
                self._stop_process(process)
            try:
                process.join()
            except (AssertionError, OSError, ValueError):
                pass
            try:
                process.close()
            except (AssertionError, OSError):
                pass
            self._cleanup_attempt_dir(attempt_dir)
            with self._lock:
                if self._attempt is attempt:
                    if terminal_published:
                        self._clear_active()
                    else:
                        self._terminal_publication_failed = True

    def status(self, job_id: str | None = None) -> dict[str, object]:
        """Return a public job receipt or manager-level idle/active status."""

        if job_id is not None:
            return getattr(self.store, "public_state")(job_id)
        with self._lock:
            attempt = self._attempt
            active = self._process is not None and self._monitor is not None
        if attempt is None or not active:
            return {"ok": True, "active": False, "audit_status": "idle"}
        return {
            "ok": True,
            "active": True,
            "job_id": attempt.job_id,
            "mode": "enhanced",
            "audit_status": "running",
        }

    get_status = status

    def cancel(self, job_id: str) -> dict[str, object]:
        """Cancel the active child, then publish a cancellation outcome."""

        with self._lock:
            attempt = self._attempt
            process = self._process
            monitor = self._monitor
        if attempt is not None and attempt.job_id != job_id:
            raise WorkflowError("ENHANCED_BUSY", "Another enhanced audit is already running.")
        request = getattr(self.store, "_request_enhanced_cancel", None)
        if not callable(request):
            raise WorkflowError("AUDIT_UNAVAILABLE", "Enhanced audit manager is unavailable.")
        requested = request(job_id)
        if attempt is None:
            return requested
        self._stop_process(process)
        finish = getattr(self.store, "_finish_enhanced_attempt", None)
        if callable(finish):
            finish(attempt, status="cancelled", error_code="AUDIT_CANCELLED")
        self._cleanup_attempt_dir(self._attempt_dir)
        # Join the monitor before releasing the active claim so a new start()
        # cannot overlap with the previous attempt's teardown.
        if monitor is not None and monitor is not threading.current_thread():
            monitor.join(AUDIT_PROCESS_GRACE_SECONDS * 2)
        with self._lock:
            if self._attempt is attempt:
                self._clear_active()
        try:
            return getattr(self.store, "public_state")(job_id)
        except WorkflowError:
            return requested

    def restart(self, job_id: str) -> dict[str, object]:
        """Explicitly queue a terminal attempt and start it again."""

        self._ensure_idle()
        queue = getattr(self.store, "_queue_enhanced_restart", None)
        if not callable(queue):
            raise WorkflowError("AUDIT_UNAVAILABLE", "Enhanced audit manager is unavailable.")
        queue(job_id)
        return self.start(job_id)

    def close(self) -> None:
        """Stop the child and mark an unfinished attempt interrupted."""

        with self._lock:
            if self._closed:
                return
            self._closed = True
            attempt = self._attempt
            process = self._process
            monitor = self._monitor
        try:
            if attempt is not None:
                request = getattr(self.store, "_request_enhanced_cancel", None)
                if callable(request):
                    try:
                        request(attempt.job_id)
                    except (OSError, WorkflowError):
                        pass
                self._stop_process(process)
                finish = getattr(self.store, "_finish_enhanced_attempt", None)
                if callable(finish):
                    try:
                        finish(
                            attempt,
                            status="interrupted",
                            error_code="AUDIT_INTERRUPTED",
                        )
                    except (OSError, WorkflowError):
                        pass
                self._cleanup_attempt_dir(self._attempt_dir)
            if monitor is not None and monitor is not threading.current_thread():
                monitor.join(AUDIT_PROCESS_GRACE_SECONDS * 2)
        finally:
            with self._lock:
                self._clear_active()
            unregister = getattr(self.store, "_unregister_audit_manager", None)
            try:
                if callable(unregister):
                    unregister(self)
            finally:
                _release_manager_lease(self._lease_root, self._lease_descriptor)

    shutdown = close

    def __enter__(self) -> AuditManager:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()
