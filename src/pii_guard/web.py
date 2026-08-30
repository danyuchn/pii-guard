"""One-page localhost UI for the staged quick-mode workflow.

The server is intentionally small and stdlib-only.  It is a local review
surface, not a network API: it binds to loopback, uses a random path token,
does not log request lines, and never sends private mapping values or restored
text over HTTP.
"""

from __future__ import annotations

import html
import http.server
import json
import secrets
import threading
import urllib.parse
import webbrowser
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Final

from pii_guard.local_workflow import (
    MAX_PDF_BYTES,
    PDF_SIGNATURE,
    PDF_SUFFIX,
    SUPPORTED_SUFFIXES,
    PrivateJobStore,
    WorkflowError,
)

MAX_REQUEST_BYTES: Final[int] = MAX_PDF_BYTES + 128 * 1024
MAX_UPLOAD_BYTES: Final[int] = MAX_PDF_BYTES
LOOPBACK_HOST: Final[str] = "127.0.0.1"
WEB_CSP: Final[str] = (
    "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
    "connect-src 'self'; base-uri 'none'; form-action 'none'"
)
DOWNLOAD_CSP: Final[str] = (
    "default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; "
    "connect-src 'none'; base-uri 'none'; form-action 'none'"
)


WEB_PAGE: Final[str] = r"""<!doctype html>
<html lang="zh-Hant"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>PII Guard 本機快審</title>
<style>
:root { color-scheme: light dark; --line: #8885; --accent: #c8371e; --blue: #2563eb; }
* { box-sizing: border-box; }
body { margin: 0; font: 15px/1.7 ui-sans-serif, system-ui, "PingFang TC", sans-serif; }
header { padding: 20px; border-bottom: 1px solid var(--line); }
main { max-width: 72rem; margin: 0 auto; padding: 20px; }
h1 { margin: 0 0 4px; font-size: 22px; }
h2 { font-size: 17px; margin: 24px 0 8px; }
.muted { opacity: .72; font-size: 13px; }
.notice { border-left: 3px solid var(--accent); padding: 8px 12px;
  background: color-mix(in srgb, var(--accent) 10%, transparent); }
.controls { display: flex; gap: 10px; align-items: center;
  flex-wrap: wrap; }
input, select, button { font: inherit; padding: 7px 10px;
  border: 1px solid var(--line); border-radius: 6px; }
button { cursor: pointer; background: Canvas; color: inherit; }
button.primary { background: var(--accent); color: white; border-color: transparent; }
button.danger { color: #b42318; }
button:disabled { cursor: default; opacity: .45; }
#review { white-space: pre-wrap; word-break: break-word; min-height: 30vh;
  border: 1px solid var(--line); border-radius: 7px; padding: 14px; }
#review mark { background: color-mix(in srgb, var(--accent) 18%, transparent);
  border: 1px solid color-mix(in srgb, var(--accent) 45%, transparent);
  border-radius: 4px; padding: 1px 4px; font-family: ui-monospace, monospace; }
#message { min-height: 1.8em; margin-top: 10px; }
#job { display: none; }
pre { white-space: pre-wrap; overflow-wrap: anywhere; }
a { color: var(--blue); }
</style></head><body>
<header><h1>PII Guard 本機快審</h1>
<div class="muted">所有處理只在本機完成。這一頁提供文字檔與文字型 PDF 的快速模式。</div></header>
<main>
<p class="notice">這頁只顯示去識別化文字與代號。私有對照表留在本機工作目錄，
不會放進回應、頁面或記錄。PDF 只抽取可選取的文字，不保留原 PDF 版面，
也不會輸出去識別化 PDF；掃描型、圖片型 PDF 與 OCR 留待後續階段。</p>
<section aria-labelledby="process-title"><h2 id="process-title">1. 選檔與處理</h2>
<div class="controls"><input id="file" type="file" accept=".txt,.md,.csv,.tsv,.log,.dat,.pdf">
<label for="mode">模式</label><select id="mode">
<option value="quick">快速模式（規則＋Presidio＋中文辨識）</option>
<option value="enhanced" disabled>加強模式（第三階段，尚未完成）</option></select>
<button id="process" class="primary">開始處理</button></div>
<div id="selected-format" class="muted">尚未選擇檔案。</div>
<div id="message" class="muted" role="status"></div></section>

<section id="job" aria-labelledby="review-title"><h2 id="review-title">2. 快審與人工補標</h2>
<p class="muted">選取仍然可見、希望遮蔽的文字，再按「補遮選取文字」。
頁面不提供放回原值的功能，避免把私有對照表送回瀏覽器。</p>
<div class="controls"><button id="mask">補遮選取文字</button>
<span id="count" class="muted"></span></div>
<div id="review" tabindex="0" aria-label="去識別化文字"></div>
<p class="muted">工作編號：<code id="job-id"></code><br>私有工作目錄：<code id="job-dir"></code></p>
<div class="controls"><a id="download-text" download="pii-guard-anonymized.txt">下載去識別化文字</a>
<a id="download-html" download="pii-guard-anonymized.html">下載安全 HTML</a>
<button id="restore">在私有工作目錄產生還原檔</button>
<button id="delete" class="danger">刪除這個工作</button></div>
<p id="format-note" class="muted">還原檔只寫到上面的私有工作目錄，不透過 HTTP 下載；
確認不再需要時請手動刪除此工作。</p></section>
</main>
<script>
const BASE = location.pathname.replace(/\/$/, ""), review = document.getElementById("review");
const message = document.getElementById("message"), jobBox = document.getElementById("job");
const PRIVATE_JOBS_HINT = "~/.local/share/pii-safe-documents/jobs/";
let jobId = null, busy = false;
function say(text) { message.textContent = text; }
async function call(path, options = {}) {
  if (busy) return null;
  busy = true;
  try {
    const response = await fetch(BASE + path, {cache: "no-store", ...options});
    const data = await response.json();
    if (!response.ok) {
      say("失敗：" + (data.message || "本機伺服器拒絕了這個請求。"));
      return null;
    }
    return data;
  } catch (_) { say("無法連線，請確認本機伺服器仍在執行。"); return null; }
  finally { busy = false; }
}
function render(data) {
  jobId = data.job_id;
  jobBox.style.display = "block";
  document.getElementById("job-id").textContent = data.job_id;
  document.getElementById("job-dir").textContent = PRIVATE_JOBS_HINT + data.job_id +
    "（若啟動時設定 jobs-root，則為該私有工作根目錄＋工作編號）";
  document.getElementById("count").textContent =
    `${data.replacement_count} 個代號；可重新選取文字補遮`;
  review.textContent = data.anonymized_text;
  const downloadBase = BASE + "/api/jobs/" + encodeURIComponent(jobId) + "/download";
  document.getElementById("download-text").href = downloadBase + "?format=text";
  document.getElementById("download-html").href = downloadBase + "?format=html";
  const format = data.source_format === "pdf" ? "PDF 文字抽取" : "UTF-8 純文字";
  const pages = data.source_format === "pdf" ? `，${data.page_count} 頁` : "";
  document.getElementById("format-note").textContent =
    `${format}${pages}。只保留抽出的文字；不保留原 PDF 版面，也不輸出去識別化 PDF。` +
    "還原檔只寫到私有工作目錄，不透過 HTTP 下載；確認不再需要時請手動刪除。";
}
document.getElementById("file").addEventListener("change", () => {
  const input = document.getElementById("file"), selected = input.files[0];
  if (!selected) {
    document.getElementById("selected-format").textContent = "尚未選擇檔案。";
    return;
  }
  const isPdf = selected.name.toLowerCase().endsWith(".pdf");
  document.getElementById("selected-format").textContent = isPdf ?
    "目前選擇：PDF 文字抽取（不保留原版面、不輸出 PDF；掃描型 PDF 不支援）。" :
    "目前選擇：UTF-8 純文字。";
});
document.getElementById("process").addEventListener("click", async () => {
  const input = document.getElementById("file"), mode = document.getElementById("mode").value;
  if (!input.files.length) { say("請先選一個 UTF-8 純文字或文字型 PDF 檔案。"); return; }
  const form = new FormData(); form.append("mode", mode); form.append("file", input.files[0]);
  say("處理中，首次載入中文辨識模型可能需要一些時間……");
  const data = await call("/api/process", {method: "POST", body: form});
  if (data) {
    render(data);
    say("完成。下面的文字是去識別化版本，可先快審再下載文字或安全 HTML。");
  }
});
document.getElementById("mask").addEventListener("click", async () => {
  if (!jobId) return;
  const selection = getSelection().toString().trim();
  if (!selection || selection.includes("[[")) {
    say("請在去識別化文字中選取要補遮的普通文字。");
    return;
  }
  const data = await call("/api/jobs/" + encodeURIComponent(jobId) + "/mask", {
    method: "POST", headers: {"content-type": "application/json"},
    body: JSON.stringify({terms: [selection]})
  });
  if (data) {
    render(data);
    say(data.terms_masked ? "已補遮選取文字。" : "找不到選取文字，沒有變更。");
  }
});
document.getElementById("restore").addEventListener("click", async () => {
  if (!jobId) return;
  const data = await call("/api/jobs/" + encodeURIComponent(jobId) + "/restore", {method: "POST"});
  if (data) {
    say(data.roundtrip_equal ? "還原檔已寫入私有工作目錄，逐字還原驗證通過。" :
      "還原檔已寫入私有工作目錄；這次內容含人工修改，未宣稱等於原文。");
  }
});
document.getElementById("delete").addEventListener("click", async () => {
  if (!jobId || !confirm("確定刪除這個工作及私有對照表？")) return;
  const data = await call("/api/jobs/" + encodeURIComponent(jobId), {method: "DELETE"});
  if (data) {
    jobBox.style.display = "none";
    jobId = null;
    say("私有工作與對照表已刪除；沒有自動到期機制。");
  }
});
</script></body></html>"""


HTML_DOWNLOAD_TEMPLATE: Final[str] = """<!doctype html>
<html lang="zh-Hant"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>PII Guard 去識別化文字</title>
<style>
body { margin: 2rem auto; max-width: 72rem; padding: 0 1rem;
  font: 16px/1.7 ui-sans-serif, system-ui, sans-serif; }
.notice { border-left: 3px solid #c8371e; padding: .5rem .8rem; }
pre { white-space: pre-wrap; overflow-wrap: anywhere; }
</style></head><body><main>
<h1>PII Guard 去識別化文字</h1>
<p class="notice">此檔案只含去識別化文字。若來源是 PDF，這是文字抽取結果，
不保留原 PDF 版面，也不代表輸出了一份去識別化 PDF。</p>
<pre>CONTENT</pre>
</main></body></html>"""


def _html_download(text: str) -> bytes:
    """Render escaped redacted text into the fixed standalone HTML template."""

    escaped = html.escape(text, quote=True)
    return HTML_DOWNLOAD_TEMPLATE.replace("CONTENT", escaped).encode("utf-8")


@dataclass(frozen=True)
class WebConfig:
    """Configuration for a loopback-only server."""

    host: str = LOOPBACK_HOST
    port: int = 0


class _SilentHTTPServer(http.server.HTTPServer):
    """Keep parser/socket failures from writing request data to stderr."""

    def handle_error(self, _request: object, _client_address: object) -> None:
        return


def _json_bytes(payload: dict[str, object]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")


def _multipart_fields(
    body: bytes, content_type: str
) -> tuple[dict[str, str], str, bytes, str | None]:
    """Extract one upload and small text fields without writing user filenames."""

    if len(body) > MAX_REQUEST_BYTES:
        raise WorkflowError("REQUEST_TOO_LARGE", "Upload exceeds the safety size limit.")
    try:
        encoded_content_type = content_type.encode("ascii", errors="strict")
    except UnicodeError as exc:
        raise WorkflowError("INVALID_UPLOAD", "Upload form is invalid.") from exc
    raw_headers = b"MIME-Version: 1.0\r\nContent-Type: " + encoded_content_type + b"\r\n\r\n" + body
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw_headers)
    except (ValueError, UnicodeError) as exc:
        raise WorkflowError("INVALID_UPLOAD", "Upload form is invalid.") from exc
    if not message.is_multipart():
        raise WorkflowError("INVALID_UPLOAD", "Upload form is invalid.")
    fields: dict[str, str] = {}
    filename = "upload.txt"
    data: bytes | None = None
    file_content_type: str | None = None
    for part in message.iter_parts():
        name = part.get_param("name", header="content-disposition")
        if not isinstance(name, str):
            continue
        payload = part.get_payload(decode=True)
        payload_bytes = payload if isinstance(payload, bytes) else b""
        if name in {"mode", "text"}:
            try:
                fields[name] = payload_bytes.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise WorkflowError("INPUT_NOT_UTF8", "Input must be UTF-8 plain text.") from exc
        elif name in {"file", "upload", "input"}:
            candidate = part.get_filename()
            if isinstance(candidate, str) and candidate:
                filename = Path(candidate.replace("\\", "/")).name or "upload.txt"
            data = payload_bytes
            candidate_content_type = part.get_content_type()
            if isinstance(candidate_content_type, str):
                file_content_type = candidate_content_type.lower()
    if data is None:
        raise WorkflowError("INVALID_UPLOAD", "A file upload is required.")
    if len(data) > MAX_UPLOAD_BYTES:
        raise WorkflowError("INPUT_TOO_LARGE", "Upload exceeds the safety size limit.")
    return fields, filename, data, file_content_type


def _segments(path: str) -> list[str]:
    return [urllib.parse.unquote(segment) for segment in path.split("/") if segment]


def _download_format(path: str, segments: list[str]) -> str:
    """Return one supported download representation, rejecting PDF output."""

    selected = "text"
    if len(segments) == 5 and segments[3] == "download":
        selected = segments[4]
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query, keep_blank_values=True).get(
        "format"
    )
    if query is not None:
        if len(query) != 1:
            raise WorkflowError("INVALID_DOWNLOAD_FORMAT", "Download format is invalid.")
        selected = query[0]
    if selected not in {"text", "html"}:
        raise WorkflowError(
            "INVALID_DOWNLOAD_FORMAT",
            "Only de-identified text or standalone HTML can be downloaded.",
        )
    return selected


class LocalWebApplication:
    """Application object shared by the HTTP handler and integration tests."""

    def __init__(self, store: PrivateJobStore | None = None) -> None:
        self.store = store or PrivateJobStore()
        self.lock = threading.RLock()

    def process(self, text: str, source_name: str, mode: str) -> dict[str, object]:
        with self.lock:
            if mode != "quick":
                raise WorkflowError(
                    "MODE_UNAVAILABLE",
                    "Only quick mode is available in phase one; enhanced mode is not implemented.",
                )
            return self.store.create_quick_from_text(text, source_name=source_name)

    def process_upload(
        self,
        data: bytes,
        source_name: str,
        mode: str,
        *,
        file_content_type: str | None = None,
    ) -> dict[str, object]:
        """Process a browser upload while keeping PDF bytes in memory only."""

        suffix = Path(source_name).suffix.lower()
        if suffix == PDF_SUFFIX:
            return self._process_pdf_upload(data, mode)
        if suffix not in SUPPORTED_SUFFIXES:
            raise WorkflowError(
                "UNSUPPORTED_FORMAT", "Only verified UTF-8 plain-text or PDF files are supported."
            )
        if file_content_type == "application/pdf" or data.startswith(PDF_SIGNATURE):
            raise WorkflowError(
                "PDF_FILENAME_MISMATCH",
                "PDF uploads must use a .pdf filename.",
            )
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise WorkflowError("INPUT_NOT_UTF8", "Input must be UTF-8 plain text.") from exc
        return self.process(text, source_name, mode)

    def _process_pdf_upload(self, data: bytes, mode: str) -> dict[str, object]:
        if mode != "quick":
            raise WorkflowError(
                "MODE_UNAVAILABLE",
                "Only quick mode is available; enhanced mode is not implemented.",
            )
        with self.lock:
            return self.store.create_quick_from_pdf_bytes(data)

    def state(self, job_id: str) -> dict[str, object]:
        with self.lock:
            return self.store.public_state(job_id)

    def mask(self, job_id: str, terms: list[str]) -> dict[str, object]:
        with self.lock:
            return self.store.mask_terms(job_id, terms)

    def restore(self, job_id: str) -> dict[str, object]:
        with self.lock:
            return self.store.restore_to_private(job_id)

    def delete(self, job_id: str) -> dict[str, object]:
        with self.lock:
            self.store.delete(job_id)
        return {"ok": True, "job_id": job_id, "deleted": True}


def _handler_for(app: LocalWebApplication, token: str, port: int):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def setup(self) -> None:
            super().setup()
            self.connection.settimeout(10.0)

        def log_message(self, *_args: object) -> None:
            # Request paths can contain the job token, and request bodies may
            # contain selected text.  Keep the local server completely silent.
            return

        def send_error(
            self,
            code: int,
            message: str | None = None,
            explain: str | None = None,
        ) -> None:
            """Return a fixed body instead of echoing malformed request data."""

            del message, explain
            payload = b"bad request" if code < 500 else b"server failure"
            self._send(payload, "text/plain; charset=utf-8", code)

        def _route(self) -> tuple[str, list[str]] | None:
            host = self.headers.get("Host", "")
            if host not in {f"{LOOPBACK_HOST}:{port}", f"localhost:{port}"}:
                return None
            parsed = urllib.parse.urlsplit(self.path)
            path = parsed.path
            prefix = f"/{token}"
            if path == prefix:
                return "/", []
            if not path.startswith(prefix + "/"):
                return None
            route = path[len(prefix) :] or "/"
            return route, _segments(route)

        def _send(
            self,
            payload: bytes,
            content_type: str,
            status: int = 200,
            *,
            disposition: str | None = None,
            content_security_policy: str | None = None,
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header(
                "Content-Security-Policy",
                content_security_policy or WEB_CSP,
            )
            if disposition is not None:
                self.send_header("Content-Disposition", disposition)
            self.end_headers()
            self.wfile.write(payload)

        def _json(self, payload: dict[str, object], status: int = 200) -> None:
            self._send(_json_bytes(payload), "application/json; charset=utf-8", status)

        def _error(self, error: WorkflowError, status: int = 400) -> None:
            self._json({"ok": False, "error_code": error.code, "message": error.message}, status)

        def _read_body(self, *, required: bool = True) -> bytes:
            value = self.headers.get("Content-Length")
            if value is None and not required:
                return b""
            try:
                length = int(value or "-1")
            except ValueError as exc:
                raise WorkflowError("INVALID_REQUEST", "Request body is invalid.") from exc
            if length < 0:
                raise WorkflowError("INVALID_REQUEST", "Request body is required.")
            if length > MAX_REQUEST_BYTES:
                raise WorkflowError("REQUEST_TOO_LARGE", "Request exceeds the safety size limit.")
            body = self.rfile.read(length)
            if len(body) != length:
                raise WorkflowError("INVALID_REQUEST", "Request body is incomplete.")
            return body

        def _job_id_from(self, segments: list[str]) -> str:
            if len(segments) < 3 or segments[0] != "api" or segments[1] != "jobs":
                raise WorkflowError("NOT_FOUND", "The requested local resource was not found.")
            return segments[2]

        def do_GET(self) -> None:  # noqa: N802 - stdlib naming
            route_data = self._route()
            if route_data is None:
                self._send(b"not found", "text/plain; charset=utf-8", 404)
                return
            route, segments = route_data
            try:
                if route == "/":
                    self._send(WEB_PAGE.encode("utf-8"), "text/html; charset=utf-8")
                    return
                if (
                    len(segments) == 4
                    and segments[:2] == ["api", "jobs"]
                    and segments[3] == "state"
                ):
                    self._json(app.state(segments[2]))
                    return
                if (
                    len(segments) in {4, 5}
                    and segments[:2] == ["api", "jobs"]
                    and segments[3] == "download"
                    and (len(segments) == 4 or segments[4] in {"text", "html"})
                ):
                    state = app.state(segments[2])
                    download_format = _download_format(self.path, segments)
                    if download_format == "html":
                        payload = _html_download(str(state["anonymized_text"]))
                        content_type = "text/html; charset=utf-8"
                        filename = "pii-guard-anonymized.html"
                    else:
                        payload = str(state["anonymized_text"]).encode("utf-8")
                        content_type = "text/plain; charset=utf-8"
                        filename = "pii-guard-anonymized.txt"
                    self._send(
                        payload,
                        content_type,
                        disposition=f'attachment; filename="{filename}"',
                        content_security_policy=(
                            DOWNLOAD_CSP if download_format == "html" else None
                        ),
                    )
                    return
                raise WorkflowError("NOT_FOUND", "The requested local resource was not found.")
            except WorkflowError as error:
                self._error(error, 404 if error.code in {"NOT_FOUND", "JOB_NOT_FOUND"} else 400)
            except Exception:
                self._error(
                    WorkflowError("INTERNAL_FAILURE", "Local privacy operation failed."),
                    500,
                )

        def do_POST(self) -> None:  # noqa: N802 - stdlib naming
            route_data = self._route()
            if route_data is None:
                self._send(b"not found", "text/plain; charset=utf-8", 404)
                return
            route, segments = route_data
            try:
                if (
                    len(segments) == 4
                    and segments[:2] == ["api", "jobs"]
                    and segments[3] == "restore"
                ):
                    self._read_body(required=False)
                    self._json(app.restore(segments[2]))
                    return
                body = self._read_body()
                if route == "/api/process":
                    content_type = self.headers.get("Content-Type", "")
                    if content_type.lower().startswith("multipart/form-data"):
                        fields, filename, data, file_content_type = _multipart_fields(
                            body, content_type
                        )
                        mode = fields.get("mode", "quick")
                        if not isinstance(mode, str):
                            raise WorkflowError("INVALID_REQUEST", "Mode is invalid.")
                        self._json(
                            app.process_upload(
                                data,
                                filename,
                                mode,
                                file_content_type=file_content_type,
                            )
                        )
                        return
                    else:
                        try:
                            payload = json.loads(body.decode("utf-8"))
                        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                            raise WorkflowError(
                                "INVALID_REQUEST", "Request body is invalid."
                            ) from exc
                        if not isinstance(payload, dict) or not isinstance(
                            payload.get("text"), str
                        ):
                            raise WorkflowError(
                                "INVALID_REQUEST", "A UTF-8 text input is required."
                            )
                        text = payload["text"]
                        filename = str(payload.get("filename", "upload.txt"))
                        mode = payload.get("mode", "quick")
                    if not isinstance(mode, str):
                        raise WorkflowError("INVALID_REQUEST", "Mode is invalid.")
                    self._json(app.process(text, filename, mode))
                    return
                if len(segments) == 4 and segments[:2] == ["api", "jobs"] and segments[3] == "mask":
                    try:
                        payload = json.loads(body.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                        raise WorkflowError("INVALID_REQUEST", "Request body is invalid.") from exc
                    if not isinstance(payload, dict) or not isinstance(payload.get("terms"), list):
                        raise WorkflowError("INVALID_TERM", "Terms are invalid.")
                    terms = payload["terms"]
                    if not all(isinstance(term, str) for term in terms):
                        raise WorkflowError("INVALID_TERM", "Terms are invalid.")
                    self._json(app.mask(segments[2], terms))
                    return
                raise WorkflowError("NOT_FOUND", "The requested local resource was not found.")
            except TimeoutError:
                self._error(
                    WorkflowError("REQUEST_TIMEOUT", "Local request timed out safely."),
                    408,
                )
            except UnicodeDecodeError:
                self._error(WorkflowError("INPUT_NOT_UTF8", "Input must be UTF-8 plain text."), 400)
            except WorkflowError as error:
                status = (
                    404
                    if error.code in {"NOT_FOUND", "JOB_NOT_FOUND"}
                    else 413
                    if error.code in {"INPUT_TOO_LARGE", "REQUEST_TOO_LARGE"}
                    else 400
                )
                self._error(error, status)
            except Exception:
                self._error(
                    WorkflowError("INTERNAL_FAILURE", "Local privacy operation failed."),
                    500,
                )

        def do_DELETE(self) -> None:  # noqa: N802 - stdlib naming
            route_data = self._route()
            if route_data is None:
                self._send(b"not found", "text/plain; charset=utf-8", 404)
                return
            _, segments = route_data
            try:
                if len(segments) != 3 or segments[:2] != ["api", "jobs"]:
                    raise WorkflowError("NOT_FOUND", "The requested local resource was not found.")
                self._json(app.delete(segments[2]))
            except WorkflowError as error:
                self._error(error, 404 if error.code in {"NOT_FOUND", "JOB_NOT_FOUND"} else 400)
            except Exception:
                self._error(
                    WorkflowError("INTERNAL_FAILURE", "Local privacy operation failed."),
                    500,
                )

    return Handler


def create_server(
    app: LocalWebApplication | None = None,
    config: WebConfig | None = None,
) -> tuple[_SilentHTTPServer, str]:
    """Create a loopback-only server and return it with its single-use URL."""

    selected = config or WebConfig()
    if selected.host != LOOPBACK_HOST:
        raise WorkflowError("LOOPBACK_ONLY", "The local web server only binds to 127.0.0.1.")
    if not 0 <= selected.port <= 65535:
        raise WorkflowError("INVALID_PORT", "The local web server port is invalid.")
    application = app or LocalWebApplication()
    token = secrets.token_urlsafe(32)
    server = _SilentHTTPServer((LOOPBACK_HOST, selected.port), http.server.BaseHTTPRequestHandler)
    server.RequestHandlerClass = _handler_for(application, token, server.server_address[1])
    port = server.server_address[1]
    return server, f"http://{LOOPBACK_HOST}:{port}/{token}/"


def run_web(
    *,
    port: int = 0,
    open_browser: bool = False,
    store: PrivateJobStore | None = None,
) -> None:
    """Run the local web UI until interrupted."""

    server, url = create_server(LocalWebApplication(store), WebConfig(port=port))
    print(url, flush=True)
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()
