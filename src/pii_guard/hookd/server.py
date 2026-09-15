"""Loopback-only HTTP service that owns the redaction engine.

Hardening follows ``pii_guard.web``: it binds to 127.0.0.1 only, checks the
Host header, never logs a request line or a body, and answers with fixed error
bodies.  Authentication is a bearer token from the owner-only state file, since
the only intended caller is this project's own hook client.
"""

from __future__ import annotations

import http.server
import json
import re
import secrets
import threading
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from pii_guard.hookd import hooks
from pii_guard.hookd.core import MAX_TEXT_BYTES, SessionStore, validate_session_id
from pii_guard.local_workflow import WorkflowError

LOOPBACK_HOST: Final[str] = "127.0.0.1"
MAX_REQUEST_BYTES: Final[int] = MAX_TEXT_BYTES + 256 * 1024
API_PREFIX: Final[str] = "/v1"
SERVICE_VERSION: Final[int] = 1
_EVENT_NAME_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z]{1,40}$")

_ERROR_STATUS: Final[dict[str, int]] = {
    "INVALID_SESSION_ID": 400,
    "INVALID_REQUEST": 400,
    "REQUEST_TOO_LARGE": 413,
    "NOT_FOUND": 404,
}


@dataclass(frozen=True)
class HookdServerConfig:
    """Configuration for one loopback-only hookd service."""

    host: str = LOOPBACK_HOST
    port: int = 0


class HookdApplication:
    """Request-level behaviour, independent of the HTTP plumbing."""

    def __init__(
        self,
        store: SessionStore,
        engine_name: str,
        *,
        engine_fallback: bool = False,
    ) -> None:
        self._store = store
        self._engine_name = engine_name
        self._engine_fallback = engine_fallback
        self._context = hooks.HookContext(names_covered=engine_name == "full")
        self._lock = threading.Lock()

    @property
    def store(self) -> SessionStore:
        return self._store

    def health(self) -> dict[str, object]:
        return {
            "ok": True,
            "engine": self._engine_name,
            "engine_fallback": self._engine_fallback,
            "names_covered": self._context.names_covered,
            "sessions": len(self._store.summary()),
            "version": SERVICE_VERSION,
        }

    def redact(self, payload: Mapping[str, Any]) -> dict[str, object]:
        session_id, text = _session_and_text(payload)
        redactor = self._store.get(session_id)
        result = redactor.redact(text)
        self._store.save(redactor)
        return {
            "text": result.text,
            "new_placeholders": result.new_placeholders,
            "counts": result.counts,
        }

    def restore(self, payload: Mapping[str, Any]) -> dict[str, object]:
        session_id, text = _session_and_text(payload)
        result = self._store.get(session_id).restore(text)
        return {"text": result.text, "replaced": result.replaced}

    def hook(self, event_name: str, payload: Mapping[str, Any]) -> dict[str, object]:
        if not _EVENT_NAME_PATTERN.fullmatch(event_name):
            raise WorkflowError("NOT_FOUND", "The requested local resource was not found.")
        if event_name not in hooks.SUPPORTED_EVENTS:
            # An unmatched event is not an error: the hook should simply do
            # nothing rather than fail the tool call it is attached to.
            return {}
        return hooks.dispatch(self._store, event_name, payload, self._context)

    def sessions(self) -> dict[str, object]:
        return {"sessions": self._store.summary()}

    def purge(self, session_id: str) -> dict[str, object]:
        return {"ok": True, "purged": self._store.purge(session_id)}


def _session_and_text(payload: Mapping[str, Any]) -> tuple[str, str]:
    if not isinstance(payload, Mapping):
        raise WorkflowError("INVALID_REQUEST", "Request body is invalid.")
    text = payload.get("text")
    if not isinstance(text, str):
        raise WorkflowError("INVALID_REQUEST", "Request body is invalid.")
    if len(text.encode("utf-8")) > MAX_TEXT_BYTES:
        raise WorkflowError("REQUEST_TOO_LARGE", "Request exceeds the safety size limit.")
    return validate_session_id(payload.get("session_id")), text


class _SilentHookdServer(http.server.ThreadingHTTPServer):
    """Threaded loopback server that never writes request data to stderr."""

    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        request_handler: type[http.server.BaseHTTPRequestHandler],
        application: HookdApplication,
    ) -> None:
        super().__init__(server_address, request_handler)
        self.application = application

    def handle_error(self, _request: object, _client_address: object) -> None:
        return


def _json_bytes(payload: Mapping[str, object]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")


def _handler_for(app: HookdApplication, token: str, port: int):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def setup(self) -> None:
            super().setup()
            self.connection.settimeout(30.0)

        def log_message(self, *_args: object) -> None:
            # Request bodies carry file contents and mapping values.  Keep the
            # service completely silent, including on parser failures.
            return

        def send_error(
            self,
            code: int,
            message: str | None = None,
            explain: str | None = None,
        ) -> None:
            del message, explain
            payload = b"bad request" if code < 500 else b"server failure"
            self._send(payload, "text/plain; charset=utf-8", code)

        def _host_ok(self) -> bool:
            host = self.headers.get("Host", "")
            return host in {f"{LOOPBACK_HOST}:{port}", f"localhost:{port}"}

        def _authorized(self) -> bool:
            header = self.headers.get("Authorization", "")
            scheme, _, value = header.partition(" ")
            if scheme.lower() != "bearer":
                return False
            return secrets.compare_digest(value.strip(), token)

        def _send(self, payload: bytes, content_type: str, status: int = 200) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.send_header("Content-Security-Policy", "default-src 'none'")
            self.end_headers()
            self.wfile.write(payload)

        def _json(self, payload: Mapping[str, object], status: int = 200) -> None:
            self._send(_json_bytes(payload), "application/json; charset=utf-8", status)

        def _fail(self, error: WorkflowError) -> None:
            status = _ERROR_STATUS.get(error.code, 400)
            self._json({"ok": False, "error_code": error.code, "message": error.message}, status)

        def _segments(self) -> list[str] | None:
            if not self._host_ok():
                return None
            path = urllib.parse.urlsplit(self.path).path
            if path != API_PREFIX and not path.startswith(API_PREFIX + "/"):
                return None
            return [segment for segment in path[len(API_PREFIX) :].split("/") if segment]

        def _body(self) -> dict[str, Any]:
            value = self.headers.get("Content-Length")
            try:
                length = int(value or "-1")
            except ValueError as exc:
                raise WorkflowError("INVALID_REQUEST", "Request body is invalid.") from exc
            if length < 0:
                raise WorkflowError("INVALID_REQUEST", "Request body is required.")
            if length > MAX_REQUEST_BYTES:
                raise WorkflowError("REQUEST_TOO_LARGE", "Request exceeds the safety size limit.")
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise WorkflowError("INVALID_REQUEST", "Request body is incomplete.")
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeError, ValueError) as exc:
                raise WorkflowError("INVALID_REQUEST", "Request body is invalid.") from exc
            if not isinstance(payload, dict):
                raise WorkflowError("INVALID_REQUEST", "Request body is invalid.")
            return payload

        def _guard(self) -> list[str] | None:
            segments = self._segments()
            if segments is None:
                self._send(b"not found", "text/plain; charset=utf-8", 404)
                return None
            if not self._authorized():
                self._send(b"unauthorized", "text/plain; charset=utf-8", 401)
                return None
            return segments

        def do_GET(self) -> None:  # noqa: N802 - stdlib naming
            segments = self._guard()
            if segments is None:
                return
            try:
                if segments == ["health"]:
                    self._json(app.health())
                elif segments == ["sessions"]:
                    self._json(app.sessions())
                else:
                    self._send(b"not found", "text/plain; charset=utf-8", 404)
            except WorkflowError as error:
                self._fail(error)

        def do_POST(self) -> None:  # noqa: N802 - stdlib naming
            segments = self._guard()
            if segments is None:
                return
            try:
                payload = self._body()
                if segments == ["redact"]:
                    self._json(app.redact(payload))
                elif segments == ["restore"]:
                    self._json(app.restore(payload))
                elif len(segments) == 2 and segments[0] == "hooks":
                    self._json(app.hook(segments[1], payload))
                elif len(segments) == 3 and segments[0] == "sessions" and segments[2] == "purge":
                    self._json(app.purge(segments[1]))
                else:
                    self._send(b"not found", "text/plain; charset=utf-8", 404)
            except WorkflowError as error:
                self._fail(error)

    return Handler


def create_server(
    app: HookdApplication,
    config: HookdServerConfig | None = None,
) -> tuple[_SilentHookdServer, str, int]:
    """Create a loopback-only server; returns the server, its token and port."""

    selected = config or HookdServerConfig()
    if selected.host != LOOPBACK_HOST:
        raise WorkflowError("LOOPBACK_ONLY", "The hookd service only binds to 127.0.0.1.")
    if not 0 <= selected.port <= 65535:
        raise WorkflowError("INVALID_PORT", "The hookd service port is invalid.")
    token = secrets.token_urlsafe(32)
    server = _SilentHookdServer(
        (LOOPBACK_HOST, selected.port),
        http.server.BaseHTTPRequestHandler,
        app,
    )
    port = server.server_address[1]
    server.RequestHandlerClass = _handler_for(app, token, port)
    return server, token, port
