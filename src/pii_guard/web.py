"""One-page localhost UI for the staged quick-mode workflow.

The server is intentionally small and stdlib-only.  It is a local review
surface, not a network API: it binds to loopback, uses a random path token,
does not log request lines, and never sends private mapping values or restored
text over HTTP.
"""

from __future__ import annotations

import html
import http.server
import io
import json
import secrets
import threading
import urllib.parse
import urllib.request
import webbrowser
from collections.abc import Mapping
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
    "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)
DOWNLOAD_CSP: Final[str] = (
    "default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; "
    "connect-src 'self'; base-uri 'none'; form-action 'none'"
)
ENHANCED_ACTIVE_STATES: Final[frozenset[str]] = frozenset({"queued", "running", "cancel_requested"})
ENHANCED_TERMINAL_STATES: Final[frozenset[str]] = frozenset(
    {"passed", "failed", "cancelled", "interrupted"}
)
_PRIVATE_RESULT_KEYS: Final[frozenset[str]] = frozenset(
    {
        "mapping",
        "private_mapping",
        "original",
        "original_text",
        "private_work_dir",
        "restored_path",
        "restored_sha256",
        "original_sha256",
        "redacted_sha256",
        "mapping_sha256",
    }
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
nav.tabs { display: flex; gap: 6px; padding: 0 20px; border-bottom: 1px solid var(--line); }
nav.tabs button { border: none; border-bottom: 3px solid transparent; border-radius: 0;
  padding: 10px 14px; opacity: .65; }
nav.tabs button[aria-selected="true"] { border-bottom-color: var(--accent); opacity: 1; }
table.grid { border-collapse: collapse; width: 100%; margin-top: 8px; }
table.grid th, table.grid td { border: 1px solid var(--line); padding: 6px 8px;
  text-align: left; vertical-align: top; font-size: 14px; }
table.grid td.samples { font-family: ui-monospace, monospace; opacity: .8;
  word-break: break-all; }
textarea { font: inherit; width: 100%; padding: 8px 10px; border: 1px solid var(--line);
  border-radius: 6px; }
.preview { white-space: pre-wrap; word-break: break-word; min-height: 6em;
  border: 1px solid var(--line); border-radius: 7px; padding: 12px; margin-top: 10px; }
.ok-card { border-left: 3px solid #2e7d32; padding: 8px 12px;
  background: color-mix(in srgb, #2e7d32 10%, transparent); }
.ok-card.warn-card { border-left-color: var(--accent);
  background: color-mix(in srgb, var(--accent) 12%, transparent); }
label.inline { display: inline-flex; gap: 6px; align-items: center; }
</style></head><body>
<header><h1>PII Guard 本機工具</h1>
<div class="muted">所有處理只在本機完成。「快審」處理單一文件；
「名單」把客戶名單設成固定要遮的字。</div></header>
<nav class="tabs" role="tablist">
<button id="tab-quick-button" type="button" role="tab" aria-selected="true"
aria-controls="tab-quick">快審</button>
<button id="tab-terms-button" type="button" role="tab" aria-selected="false"
aria-controls="tab-terms">名單</button>
</nav>
<main>
<div id="tab-quick" role="tabpanel">
<p class="notice">這頁只顯示去識別化文字與代號。私有對照表留在本機工作目錄，
不會放進回應、頁面或記錄。PDF 只抽取可選取的文字，不保留原 PDF 版面，
也不會輸出去識別化 PDF；掃描型、圖片型 PDF 與 OCR 留待後續階段。加強模式是可選的本機
Ollama 稽核，會以三次取樣檢查殘留個資；長文件可只挑疑似段落，這只代表送入稽核的範圍，
不代表速度或召回率保證。</p>
<section aria-labelledby="process-title"><h2 id="process-title">1. 選檔與處理</h2>
<div class="controls"><input id="file" type="file" accept=".txt,.md,.csv,.tsv,.log,.dat,.pdf">
<label for="mode">模式</label><select id="mode">
<option value="quick">快速模式（規則＋Presidio＋中文辨識）</option>
<option value="enhanced">加強模式（可選本機 Ollama 稽核，三次取樣）</option></select>
<button id="process" class="primary">開始處理</button></div>
<div id="selected-format" class="muted">尚未選擇檔案。</div>
<div id="message" class="muted" role="status"></div></section>

<section id="job" aria-labelledby="review-title"><h2 id="review-title">2. 狀態、快審與人工補標</h2>
<p class="muted">選取仍然可見、希望遮蔽的文字，再按「補遮選取文字」。
頁面不提供放回原值的功能，避免把私有對照表送回瀏覽器。加強稽核尚未通過前，文字與代號會暫時隱藏。</p>
<div class="controls"><button id="mask">補遮選取文字</button>
<button id="cancel" class="danger">取消加強稽核</button>
<button id="restart">重新執行加強稽核</button>
<span id="status" class="muted"></span><span id="count" class="muted"></span></div>
<div id="review" tabindex="0" aria-label="去識別化文字"></div>
<p class="muted">工作編號：<code id="job-id"></code><br>私有工作目錄：<code id="job-dir"></code></p>
<div class="controls"><a id="download-text" download="pii-guard-anonymized.txt"
aria-disabled="true">下載去識別化文字</a>
<a id="download-html" download="pii-guard-anonymized.html" aria-disabled="true">下載安全 HTML</a>
<button id="restore">在私有工作目錄產生還原檔</button>
<button id="delete" class="danger">刪除這個工作</button></div>
<p id="format-note" class="muted">還原檔只寫到上面的私有工作目錄，不透過 HTTP 下載；
確認不再需要時請手動刪除此工作。</p></section>
</div>

<div id="tab-terms" role="tabpanel" hidden>
<p class="notice">把你的客戶名單（Excel 或 CSV）交給這頁，之後 AI 看到的內容裡，
名單上的姓名、電話這些會自動換成代號。<strong>檔案只在你的電腦上處理，不會上傳到任何地方。</strong>
程式只會記住「這個檔案的哪一欄是什麼」，不會另外存一份名單內容。</p>

<section aria-labelledby="ref-step1"><h2 id="ref-step1">1. 選檔案</h2>
<div class="controls"><input id="ref-file" type="file" accept=".xlsx,.xlsm,.csv,.tsv">
<label for="ref-sheet">工作表</label>
<select id="ref-sheet"><option value="">（預設第一個）</option></select>
<button id="ref-inspect" class="primary">讀取欄位</button></div>
<div id="ref-message" class="muted" role="status"></div></section>

<section id="ref-columns-box" aria-labelledby="ref-step2" hidden>
<h2 id="ref-step2">2. 確認每一欄要怎麼遮</h2>
<p class="muted">金額與日期預設「不要遮」：短數字到處都會撞到，遮了會把正常內容也改掉。</p>
<table class="grid"><thead><tr><th>欄位</th><th>這欄是什麼</th><th>筆數</th>
<th>前 3 筆預覽</th></tr></thead><tbody id="ref-columns"></tbody></table>
<div id="ref-shapes" class="muted"></div></section>

<section id="ref-save-box" aria-labelledby="ref-step3" hidden>
<h2 id="ref-step3">3. 儲存並啟用</h2>
<div class="controls"><label for="ref-project">存到這個專案</label>
<input id="ref-project" size="42" placeholder="/Users/你/專案"></div>
<div class="controls"><label class="inline"><input id="ref-copy" type="checkbox">
複製一份名單到專案的 .pii-guard/ 夾（只有你讀得到）</label></div>
<div class="controls" id="ref-path-row"><label for="ref-source-path">這個檔案放在哪</label>
<input id="ref-source-path" size="42"></div>
<div class="muted">瀏覽器拿不到檔案的真實路徑，所以請確認上面這一行，
或改勾上面的「複製一份」。</div>
<div class="controls"><label class="inline"><input id="ref-materialize" type="checkbox">
另外寫一份純文字詞表（這份會含真實值）</label></div>
<div class="controls"><button id="ref-save" class="primary">儲存</button></div>
<div id="ref-result" class="ok-card" hidden></div></section>

<section aria-labelledby="ref-step4"><h2 id="ref-step4">試試看</h2>
<p class="muted">貼一段文字，看 AI 會看到的樣子。這裡只用規則引擎加上剛存的名單，不會顯示原值。</p>
<textarea id="ref-try-input" rows="5" placeholder="貼一段含名單內容的文字"></textarea>
<div class="controls"><button id="ref-try">看遮完的樣子</button></div>
<div id="ref-try-output" class="preview"></div></section>
</div>
</main>
<script>
const BASE = location.pathname.replace(/\/$/, ""), review = document.getElementById("review");
const message = document.getElementById("message"), jobBox = document.getElementById("job");
const PRIVATE_JOBS_HINT = "~/.local/share/pii-safe-documents/jobs/";
const statusBox = document.getElementById("status"), maskButton = document.getElementById("mask");
const cancelButton = document.getElementById("cancel"),
  restartButton = document.getElementById("restart");
const restoreButton = document.getElementById("restore");
const downloadText = document.getElementById("download-text"),
  downloadHtml = document.getElementById("download-html");
let jobId = null, busy = false, pollTimer = null;
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
  const enhanced = data.mode === "enhanced", status = data.audit_status || "passed";
  const ready = !enhanced || status === "passed";
  statusBox.textContent = enhanced ? `加強稽核狀態：${status}` : "快速模式已完成";
  document.getElementById("count").textContent = ready && data.replacement_count !== undefined ?
    `${data.replacement_count} 個代號；可重新選取文字補遮` : "";
  review.textContent = ready && typeof data.anonymized_text === "string" ? data.anonymized_text :
    "加強稽核尚未通過；去識別化文字與代號暫不顯示。";
  const downloadBase = BASE + "/api/jobs/" + encodeURIComponent(jobId) + "/download";
  for (const link of [downloadText, downloadHtml]) {
    link.toggleAttribute("aria-disabled", !ready);
    if (ready) link.removeAttribute("tabindex");
    else { link.removeAttribute("href"); link.setAttribute("tabindex", "-1"); }
  }
  if (ready) {
    downloadText.href = downloadBase + "?format=text";
    downloadHtml.href = downloadBase + "?format=html";
  }
  maskButton.disabled = !ready;
  restoreButton.disabled = !ready;
  cancelButton.hidden = !enhanced || !["queued", "running", "cancel_requested"].includes(status);
  restartButton.hidden = !enhanced || !["failed", "cancelled", "interrupted"].includes(status);
  const format = data.source_format === "pdf" ? "PDF 文字抽取" : "UTF-8 純文字";
  const pages = data.source_format === "pdf" ? `，${data.page_count} 頁` : "";
  document.getElementById("format-note").textContent = enhanced && !ready ?
    "加強稽核完成前不提供下載、人工補標或還原；可取消，失敗或中斷後可明確重新執行。" :
    `${format}${pages}。只保留抽出的文字；不保留原 PDF 版面，也不輸出去識別化 PDF。` +
    "還原檔只寫到私有工作目錄，不透過 HTTP 下載；確認不再需要時請手動刪除。";
  if (enhanced && !["passed", "failed", "cancelled", "interrupted"].includes(status)) {
    schedulePoll();
  }
}
function schedulePoll() {
  if (pollTimer || !jobId) return;
  pollTimer = setTimeout(async () => {
    pollTimer = null;
    const data = await call("/api/jobs/" + encodeURIComponent(jobId) + "/state");
    if (data) render(data);
  }, 500);
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
    say(data.mode === "enhanced" ? "已排入本機加強稽核；完成前不顯示文字。" :
      "完成。下面的文字是去識別化版本，可先快審再下載文字或安全 HTML。");
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
cancelButton.addEventListener("click", async () => {
  if (!jobId) return;
  const data = await call(
    "/api/jobs/" + encodeURIComponent(jobId) + "/audit/cancel", {method: "POST"});
  if (data) { render(data); say("已取消加強稽核；文字仍然隱藏。可選擇重新執行。"); }
});
restartButton.addEventListener("click", async () => {
  if (!jobId) return;
  const data = await call(
    "/api/jobs/" + encodeURIComponent(jobId) + "/audit/restart", {method: "POST"});
  if (data) { render(data); say("已重新排入加強稽核；完成前不顯示文字。"); }
});
document.getElementById("delete").addEventListener("click", async () => {
  if (!jobId || !confirm("確定刪除這個工作及私有對照表？")) return;
  const data = await call("/api/jobs/" + encodeURIComponent(jobId), {method: "DELETE"});
  if (data) {
    if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; }
    jobBox.style.display = "none";
    jobId = null;
    say("私有工作與對照表已刪除；沒有自動到期機制。");
  }
});

// 名單分頁
const refMessage = document.getElementById("ref-message");
const refFile = document.getElementById("ref-file"),
  refSheet = document.getElementById("ref-sheet");
const refColumnsBox = document.getElementById("ref-columns-box");
const refColumns = document.getElementById("ref-columns");
const refSaveBox = document.getElementById("ref-save-box");
const refResult = document.getElementById("ref-result");
const refShapes = document.getElementById("ref-shapes");
const refProject = document.getElementById("ref-project");
const refSourcePath = document.getElementById("ref-source-path");
const refCopy = document.getElementById("ref-copy");
const refPathRow = document.getElementById("ref-path-row");
let refReport = null, refTypes = [];
function refSay(text) { refMessage.textContent = text; }
async function refCall(path, options = {}) {
  try {
    const response = await fetch(BASE + path, {cache: "no-store", ...options});
    const data = await response.json();
    if (!response.ok) {
      refSay("失敗：" + (data.message || "本機伺服器拒絕了這個請求。"));
      return null;
    }
    return data;
  } catch (_) { refSay("無法連線，請確認本機伺服器仍在執行。"); return null; }
}
function showTab(name) {
  const terms = name === "terms";
  document.getElementById("tab-quick").hidden = terms;
  document.getElementById("tab-terms").hidden = !terms;
  document.getElementById("tab-quick-button").setAttribute("aria-selected", String(!terms));
  document.getElementById("tab-terms-button").setAttribute("aria-selected", String(terms));
}
document.getElementById("tab-quick-button").addEventListener("click", () => showTab("quick"));
document.getElementById("tab-terms-button").addEventListener("click", () => showTab("terms"));
refCopy.addEventListener("change", () => { refPathRow.hidden = refCopy.checked; });
refFile.addEventListener("change", () => {
  const selected = refFile.files[0];
  if (!selected) return;
  refSourcePath.value = "~/Downloads/" + selected.name;
  refSay("按「讀取欄位」看這份名單有哪些欄位。");
});
function refRow(column) {
  const row = document.createElement("tr");
  const name = document.createElement("td");
  name.textContent = column.name;
  const picker = document.createElement("td");
  const select = document.createElement("select");
  select.dataset.column = column.name;
  for (const type of refTypes) {
    const option = document.createElement("option");
    option.value = type.value;
    option.textContent = type.label;
    if (type.value === column.guessed_type) option.selected = true;
    select.append(option);
  }
  picker.append(select);
  if (column.guessed_type === "SKIP") {
    const hint = document.createElement("div");
    hint.className = "muted";
    hint.textContent = "短數字容易誤遮，建議不遮";
    picker.append(hint);
  }
  const count = document.createElement("td");
  count.textContent = String(column.non_empty);
  if (column.risky) {
    const risky = document.createElement("div");
    risky.className = "muted";
    risky.textContent = "有 " + column.risky + " 筆太短，預設略過";
    count.append(risky);
  }
  const samples = document.createElement("td");
  samples.className = "samples";
  samples.textContent = (column.samples || []).join("、");
  row.append(name, picker, count, samples);
  return row;
}
function refShapeList() {
  const shapes = [];
  if (!refReport) return shapes;
  for (const column of refReport.columns) {
    const select = refColumns.querySelector(
      'select[data-column="' + CSS.escape(column.name) + '"]');
    const chosen = select ? select.value : column.guessed_type;
    if (column.shape && (chosen === "ORDER_ID" || chosen === "CUSTOM")) {
      shapes.push({type: chosen, regex: column.shape, column: column.name});
    }
  }
  return shapes;
}
function refRenderShapes() {
  const shapes = refShapeList();
  refShapes.textContent = shapes.length ?
    "偵測到固定格式：" + shapes.map((s) => s.column).join("、") +
    "。名單外的新編號也會一起遮。" : "";
}
refColumns.addEventListener("change", refRenderShapes);
document.getElementById("ref-inspect").addEventListener("click", async () => {
  if (!refFile.files.length) { refSay("請先選一個 Excel 或 CSV 檔案。"); return; }
  const form = new FormData();
  form.append("file", refFile.files[0]);
  form.append("sheet", refSheet.value);
  refSay("讀取中……");
  const data = await refCall("/api/reference/inspect", {method: "POST", body: form});
  if (!data) return;
  refReport = data;
  refTypes = data.types || [];
  refSheet.innerHTML = "";
  const auto = document.createElement("option");
  auto.value = ""; auto.textContent = "（預設第一個）";
  refSheet.append(auto);
  for (const name of data.sheets || []) {
    const option = document.createElement("option");
    option.value = name; option.textContent = name;
    if (name === data.sheet) option.selected = true;
    refSheet.append(option);
  }
  refColumns.innerHTML = "";
  for (const column of data.columns) refColumns.append(refRow(column));
  refRenderShapes();
  refColumnsBox.hidden = false;
  refSaveBox.hidden = false;
  refResult.hidden = true;
  refSay(data.rows + " 筆資料，" + data.columns.length + " 個欄位。請逐欄確認。");
});
document.getElementById("ref-save").addEventListener("click", async () => {
  if (!refReport) return;
  const columns = {};
  for (const select of refColumns.querySelectorAll("select[data-column]")) {
    columns[select.dataset.column] = select.value;
  }
  const body = {
    project: refProject.value.trim(),
    source_path: refSourcePath.value.trim(),
    sheet: refSheet.value || refReport.sheet || null,
    columns: columns,
    patterns: refShapeList().map((s) => ({type: s.type, regex: s.regex})),
    materialize: document.getElementById("ref-materialize").checked,
    copy_into_project: refCopy.checked,
    upload_id: refReport.upload_id
  };
  refSay("儲存中……");
  const data = await refCall("/api/reference/save", {
    method: "POST", headers: {"content-type": "application/json"},
    body: JSON.stringify(body)
  });
  if (!data) return;
  const lines = [];
  for (const [type, count] of Object.entries(data.counts || {})) {
    const label = data.labels && data.labels[type] ? data.labels[type] : type;
    lines.push(label + " " + count + " 筆");
  }
  const service = data.service || {};
  let serviceLine;
  if (!service.running) {
    serviceLine = "保護服務：尚未啟動，下次開 Claude Code 會自動載入。";
  } else if (!service.reloaded) {
    serviceLine = "保護服務：執行中，但這次沒能重新載入。";
  } else if (!service.terms) {
    // A reload that loaded nothing must not look like success.
    serviceLine = "注意：保護服務重新載入後是 0 筆，等於現在沒有遮任何東西。" +
      "請確認欄位不是全設成「不要遮」，以及名單檔還在原處。";
  } else {
    serviceLine = "保護服務：執行中 ✓ 已重新載入 " + service.terms + " 筆。";
  }
  refResult.classList.toggle("warn-card",
    Boolean(service.running && service.reloaded && !service.terms));
  refResult.textContent = (lines.length ?
    "之後 AI 看到的內容裡，這些會自動被遮掉：" + lines.join("、") + "。" :
    "已儲存，但目前沒有任何欄位會被遮蔽。") +
    (data.risky_skipped ? "略過 " + data.risky_skipped + " 筆過短的值。" : "") +
    (data.materialized ? "另外寫了 " + data.materialized + " 筆詞表。" : "") +
    serviceLine;
  refResult.hidden = false;
  refSay("已存到 " + data.saved_path);
});
document.getElementById("ref-try").addEventListener("click", async () => {
  const text = document.getElementById("ref-try-input").value;
  if (!text.trim()) { refSay("先貼一段文字再試。"); return; }
  refSay("處理中……");
  const data = await refCall("/api/reference/try", {
    method: "POST", headers: {"content-type": "application/json"},
    body: JSON.stringify({text: text, project: refProject.value.trim()})
  });
  if (!data) return;
  document.getElementById("ref-try-output").textContent = data.text;
  refSay("這就是 AI 會看到的內容。");
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
    audit_model: str | None = None
    ollama_url: str | None = None


class _SilentHTTPServer(http.server.ThreadingHTTPServer):
    """Keep parser/socket failures from writing request data to stderr.

    The server is threaded on purpose.  A single-threaded ``HTTPServer`` with
    HTTP/1.1 keep-alive serves exactly one socket at a time, so one idle
    browser connection (a speculative preconnect, or the socket left open
    after the page load) blocks every other request for the whole 10-second
    idle timeout.  ``LocalWebApplication`` guards all private state with its
    own lock, so concurrent handler threads only overlap on request parsing.
    """

    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        request_handler: type[http.server.BaseHTTPRequestHandler],
        application: LocalWebApplication,
    ) -> None:
        super().__init__(server_address, request_handler)
        self.application = application
        self._application_closed = False

    def _close_application(self) -> None:
        if self._application_closed:
            return
        self._application_closed = True
        try:
            self.application.close()
        except Exception:
            # Closing the listening socket is still required when an optional
            # audit manager has already exited or a test double is imperfect.
            return

    def shutdown(self) -> None:
        super().shutdown()
        self._close_application()

    def server_close(self) -> None:
        try:
            self._close_application()
        finally:
            super().server_close()

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
        if name in {"mode", "text", "sheet", "project", "source_path"}:
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


def _error_status(error: WorkflowError) -> int:
    if error.code in {"NOT_FOUND", "JOB_NOT_FOUND", "TABLE_NOT_FOUND"}:
        return 404
    if error.code in {"INPUT_TOO_LARGE", "REQUEST_TOO_LARGE", "TABLE_TOO_LARGE"}:
        return 413
    if error.code in {"DELETE_CONFLICT", "ENHANCED_BUSY", "JOB_DELETING", "JOB_NOT_READY"}:
        return 409
    if error.code == "AUDIT_UNAVAILABLE":
        return 503
    return 400


class LocalWebApplication:
    """Application object shared by the HTTP handler and integration tests.

    Every public method takes ``self.lock``, so the threaded HTTP server can
    never run two store operations at once.  Quick redaction happens inside
    its request; enhanced model work is handed to the injected manager from a
    daemon thread so state polling, cancellation, and quick requests remain
    responsive while the local model runs.
    """

    def __init__(
        self,
        store: PrivateJobStore | None = None,
        audit_manager: object | None = None,
        *,
        audit_model: str | None = None,
        ollama_url: str | None = None,
    ) -> None:
        self.store = store or PrivateJobStore()
        self.audit_manager = audit_manager
        self.audit_model = audit_model
        self.ollama_url = ollama_url
        self.lock = threading.RLock()
        self._enhanced_job: str | None = None
        self._audit_threads: set[threading.Thread] = set()
        self._close_event = threading.Event()
        self._closed = False
        # One uploaded table at a time, held in memory so the browser never
        # writes a copy of someone's customer list to a temporary file.
        self._reference_upload: tuple[str, str, bytes] | None = None
        self._reference_engine: object | None = None

    @staticmethod
    def _safe_state(raw: object) -> dict[str, object]:
        """Return only public receipt fields, withholding pending text/markers."""

        if not isinstance(raw, Mapping):
            raise WorkflowError("INVALID_JOB", "Private job state is invalid.")
        result = {key: value for key, value in raw.items() if key not in _PRIVATE_RESULT_KEYS}
        mode = result.get("mode")
        if mode == "enhanced" and result.get("audit_status") != "passed":
            for key in (
                "anonymized_text",
                "placeholders",
                "replacement_count",
                "roundtrip_verified",
            ):
                result.pop(key, None)
        return result

    @staticmethod
    def _status(state: Mapping[str, object]) -> str | None:
        value = state.get("audit_status")
        return value if isinstance(value, str) else None

    @classmethod
    def _ready_for_review(cls, state: Mapping[str, object]) -> bool:
        return state.get("mode") != "enhanced" or cls._status(state) == "passed"

    def _get_audit_manager(self) -> object:
        with self.lock:
            if self.audit_manager is None:
                from pii_guard.audit_manager import AuditManager

                self.audit_manager = AuditManager(
                    self.store,
                    audit_model=self.audit_model,
                    ollama_url=self.ollama_url,
                )
            return self.audit_manager

    def _refresh_enhanced_claim_locked(self) -> None:
        job_id = self._enhanced_job
        if job_id is None:
            return
        try:
            state = self._safe_state(self.store.public_state(job_id))
        except (AttributeError, OSError, WorkflowError):
            self._enhanced_job = None
            return
        if state.get("mode") != "enhanced" or self._status(state) in ENHANCED_TERMINAL_STATES:
            self._enhanced_job = None

    def _claim_enhanced_locked(self) -> None:
        self._refresh_enhanced_claim_locked()
        if self._enhanced_job is not None:
            raise WorkflowError("ENHANCED_BUSY", "Another enhanced audit is already running.")

    def _start_manager(self, job_id: str, *, restart: bool = False) -> None:
        """Run manager start/restart away from the HTTP request thread."""

        try:
            manager = self._get_audit_manager()
            if restart:
                operation = getattr(manager, "restart", None)
                if callable(operation):
                    result = operation(job_id)
                else:
                    operation = getattr(self.store, "restart_enhanced", None)
                    if not callable(operation):
                        raise WorkflowError(
                            "AUDIT_UNAVAILABLE", "Enhanced audit manager is unavailable."
                        )
                    result = operation(job_id, manager=manager)
            else:
                operation = getattr(manager, "start", None)
                if callable(operation):
                    result = operation(job_id)
                else:
                    operation = getattr(self.store, "start_enhanced_audit", None)
                    if not callable(operation):
                        raise WorkflowError(
                            "AUDIT_UNAVAILABLE", "Enhanced audit manager is unavailable."
                        )
                    result = operation(job_id, manager=manager)
            result_state = self._safe_state(result) if isinstance(result, Mapping) else {}
            if self._status(result_state) in ENHANCED_TERMINAL_STATES:
                return
            # AuditManager owns the child and publishes terminal state.  The
            # small watcher only releases the app-wide claim after that state
            # is visible; it never reads model output.
            while not self._close_event.wait(0.05):
                try:
                    state = self._safe_state(self.store.public_state(job_id))
                except (AttributeError, OSError, WorkflowError):
                    break
                if self._status(state) in ENHANCED_TERMINAL_STATES:
                    break
        except (OSError, RuntimeError, TypeError, ValueError, WorkflowError):
            # The safe state is persisted by the real AuditManager on normal
            # failures.  Test doubles may only raise; either way the request
            # has already returned a safe receipt and must not leak details.
            return
        finally:
            with self.lock:
                if self._enhanced_job == job_id:
                    self._enhanced_job = None
                self._audit_threads.discard(threading.current_thread())

    def _launch_enhanced_locked(self, job_id: str, *, restart: bool = False) -> None:
        thread = threading.Thread(
            target=self._start_manager,
            kwargs={"job_id": job_id, "restart": restart},
            name="pii-guard-enhanced-web",
            daemon=True,
        )
        self._audit_threads.add(thread)
        try:
            thread.start()
        except RuntimeError as exc:
            self._audit_threads.discard(thread)
            self._enhanced_job = None
            raise WorkflowError(
                "AUDIT_UNAVAILABLE", "Enhanced audit could not be started safely."
            ) from exc

    def _prepare_enhanced_from_text_locked(
        self,
        text: str,
        source_name: str,
        *,
        source_format: str = "text",
        page_count: int | None = None,
    ) -> dict[str, object]:
        self._claim_enhanced_locked()
        # Acquire the jobs-root manager lease and recover truly abandoned jobs
        # before creating this request's fresh queued state.
        self._get_audit_manager()
        prepare = getattr(self.store, "prepare_enhanced_from_text", None)
        if not callable(prepare):
            raise WorkflowError("AUDIT_UNAVAILABLE", "Enhanced audit is unavailable.")
        receipt = prepare(
            text,
            source_name=source_name,
            source_format=source_format,
            page_count=page_count,
        )
        safe_receipt = self._safe_state(receipt)
        job_id = safe_receipt.get("job_id")
        if not isinstance(job_id, str) or not job_id:
            raise WorkflowError("AUDIT_UNAVAILABLE", "Enhanced audit returned an invalid receipt.")
        self._enhanced_job = job_id
        self._launch_enhanced_locked(job_id)
        return safe_receipt

    def process(self, text: str, source_name: str, mode: str) -> dict[str, object]:
        with self.lock:
            if self._closed:
                raise WorkflowError("AUDIT_UNAVAILABLE", "Local web application is closed.")
            if mode == "quick":
                return self._safe_state(
                    self.store.create_quick_from_text(text, source_name=source_name)
                )
            if mode == "enhanced":
                return self._prepare_enhanced_from_text_locked(text, source_name)
            raise WorkflowError("INVALID_MODE", "The requested processing mode is invalid.")

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
        with self.lock:
            if self._closed:
                raise WorkflowError("AUDIT_UNAVAILABLE", "Local web application is closed.")
            if mode == "quick":
                return self._safe_state(self.store.create_quick_from_pdf_bytes(data))
            if mode != "enhanced":
                raise WorkflowError("INVALID_MODE", "The requested processing mode is invalid.")
            self._claim_enhanced_locked()
            self._get_audit_manager()
            prepare = getattr(self.store, "prepare_enhanced_from_pdf_bytes", None)
            if not callable(prepare):
                raise WorkflowError("AUDIT_UNAVAILABLE", "Enhanced audit is unavailable.")
            receipt = self._safe_state(prepare(data))
            job_id = receipt.get("job_id")
            if not isinstance(job_id, str) or not job_id:
                raise WorkflowError(
                    "AUDIT_UNAVAILABLE", "Enhanced audit returned an invalid receipt."
                )
            self._enhanced_job = job_id
            self._launch_enhanced_locked(job_id)
            return receipt

    def state(self, job_id: str) -> dict[str, object]:
        with self.lock:
            return self._safe_state(self.store.public_state(job_id))

    def _ready_state_locked(self, job_id: str) -> dict[str, object]:
        state = self._safe_state(self.store.public_state(job_id))
        if not self._ready_for_review(state) or "anonymized_text" not in state:
            raise WorkflowError(
                "JOB_NOT_READY", "This enhanced job is not ready for manual review."
            )
        return state

    def review_state(self, job_id: str) -> dict[str, object]:
        """Return a state only when manual review/download is authorized."""

        with self.lock:
            return self._ready_state_locked(job_id)

    def mask(self, job_id: str, terms: list[str]) -> dict[str, object]:
        with self.lock:
            self._ready_state_locked(job_id)
            return self._safe_state(self.store.mask_terms(job_id, terms))

    def restore(self, job_id: str) -> dict[str, object]:
        with self.lock:
            self._ready_state_locked(job_id)
            return self._safe_state(self.store.restore_to_private(job_id))

    def cancel(self, job_id: str) -> dict[str, object]:
        with self.lock:
            state = self._safe_state(self.store.public_state(job_id))
            if state.get("mode") != "enhanced":
                raise WorkflowError("JOB_NOT_READY", "This job has no enhanced audit.")
            manager = self._get_audit_manager()
            operation = getattr(manager, "cancel", None)
            if callable(operation):
                result = operation(job_id)
            else:
                operation = getattr(self.store, "cancel_enhanced", None)
                if not callable(operation):
                    raise WorkflowError("AUDIT_UNAVAILABLE", "Enhanced audit is unavailable.")
                result = operation(job_id, manager=manager)
            safe = self._safe_state(result)
            if self._status(safe) in ENHANCED_TERMINAL_STATES and self._enhanced_job == job_id:
                self._enhanced_job = None
            return safe

    def restart(self, job_id: str) -> dict[str, object]:
        with self.lock:
            if self._closed:
                raise WorkflowError("AUDIT_UNAVAILABLE", "Local web application is closed.")
            self._claim_enhanced_locked()
            state = self._safe_state(self.store.public_state(job_id))
            if state.get("mode") != "enhanced":
                raise WorkflowError("JOB_NOT_READY", "This job has no enhanced audit.")
            queue = getattr(self.store, "_queue_enhanced_restart", None)
            if callable(queue):
                queued = self._safe_state(queue(job_id))
                operation_is_restart = False
            else:
                queue = getattr(self.store, "queue_enhanced_restart", None)
                if callable(queue):
                    queued = self._safe_state(queue(job_id))
                    operation_is_restart = False
                else:
                    # A store adapter can expose restart_enhanced as its only
                    # lifecycle operation; run it in the background and return
                    # the last safe terminal receipt until it publishes queued.
                    queued = state
                    operation_is_restart = True
            self._enhanced_job = job_id
            self._launch_enhanced_locked(job_id, restart=operation_is_restart)
            return queued

    def delete(self, job_id: str) -> dict[str, object]:
        with self.lock:
            try:
                state = self._safe_state(self.store.public_state(job_id))
            except (AttributeError, OSError, WorkflowError):
                state = {}
            if state.get("mode") == "enhanced" and self._status(state) in ENHANCED_ACTIVE_STATES:
                self.cancel(job_id)
            self.store.delete(job_id)
            if self._enhanced_job == job_id:
                self._enhanced_job = None
        return {"ok": True, "job_id": job_id, "deleted": True}

    # ------------------------------------------------------------------
    # Reference lists
    # ------------------------------------------------------------------

    @staticmethod
    def _reference_project(value: object) -> Path:
        """Resolve the project directory a reference list belongs to."""

        raw = str(value or "").strip()
        project = Path(raw).expanduser() if raw else Path.cwd()
        if not project.is_dir():
            raise WorkflowError("PROJECT_NOT_FOUND", "That project directory does not exist.")
        return project

    def reference_types(self) -> list[dict[str, str]]:
        """The type menu the page shows, in the order it should be listed."""

        from pii_guard.reference import COLUMN_TYPES

        return [{"value": name, "label": label} for name, label in COLUMN_TYPES.items()]

    def reference_inspect(
        self, data: bytes, filename: str, sheet: str | None = None
    ) -> dict[str, object]:
        """Describe an uploaded table's columns, with three samples each.

        The samples are the one place a value from the list crosses HTTP.  The
        page is on loopback behind a random path token and shows the user their
        own file, which is the only way a non-technical person can confirm they
        picked the right column.
        """

        from pii_guard.reference import build_report, parse_csv_bytes

        suffix = Path(filename).suffix.lower()
        upload_id = secrets.token_urlsafe(16)
        selected: str | None
        sheets: tuple[str, ...]
        if suffix in {".xlsx", ".xlsm"}:
            # openpyxl takes a file-like object, so BytesIO keeps the workbook
            # in memory and no copy of the list is written to a temporary file.
            rows, selected, sheets = self._excel_rows(io.BytesIO(data), sheet)
        elif suffix in {".csv", ".tsv", ".txt"}:
            rows = parse_csv_bytes(data, delimiter="\t" if suffix == ".tsv" else None)
            selected, sheets = None, ()
        else:
            raise WorkflowError(
                "TABLE_UNSUPPORTED", "Only .xlsx, .xlsm, .csv and .tsv tables are supported."
            )
        report = build_report(rows, path=filename, sheet=selected, sheets=sheets)
        with self.lock:
            self._reference_upload = (upload_id, Path(filename).name, data)
        payload = report.describe(include_samples=True)
        payload["upload_id"] = upload_id
        payload["filename"] = Path(filename).name
        payload["types"] = self.reference_types()
        return payload

    @staticmethod
    def _excel_rows(
        stream: io.BytesIO, sheet: str | None
    ) -> tuple[list[list[str]], str, tuple[str, ...]]:
        """Read an uploaded workbook straight out of memory."""

        from pii_guard.reference import MAX_COLUMNS, MAX_TABLE_ROWS, _cell_text

        try:
            import openpyxl
        except ImportError as error:  # pragma: no cover - optional dependency
            raise WorkflowError(
                "OPENPYXL_MISSING", "Reading .xlsx needs openpyxl: uv sync --extra formats"
            ) from error
        try:
            workbook = openpyxl.load_workbook(stream, read_only=True, data_only=True)
        except Exception as error:  # noqa: BLE001 - any parse failure reads the same
            raise WorkflowError("TABLE_MALFORMED", "The table could not be read.") from error
        try:
            names = tuple(str(name) for name in workbook.sheetnames)
            if sheet and sheet not in names:
                raise WorkflowError("SHEET_NOT_FOUND", "That sheet is not in this workbook.")
            selected = sheet or (names[0] if names else "")
            if not selected:
                raise WorkflowError("TABLE_EMPTY", "The table has no sheets.")
            rows: list[list[str]] = []
            for row in workbook[selected].iter_rows(values_only=True):
                rows.append([_cell_text(cell) for cell in row[:MAX_COLUMNS]])
                if len(rows) >= MAX_TABLE_ROWS:
                    break
            return rows, selected, names
        finally:
            workbook.close()

    def _copy_upload_into_project(self, project: Path, upload_id: str) -> Path:
        """Keep the uploaded table inside the project, owner-only."""

        from pii_guard.reference import _write_owner_only

        with self.lock:
            held = self._reference_upload
        if held is None or held[0] != upload_id:
            raise WorkflowError("UPLOAD_EXPIRED", "Upload the table again before saving.")
        _, name, data = held
        target = project / ".pii-guard" / "lists" / name
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        _write_owner_only(target, "")
        with open(target, "wb") as handle:
            handle.write(data)
        target.chmod(0o600)
        return target

    def reference_save(self, payload: Mapping[str, object]) -> dict[str, object]:
        """Record one table as a reference list and ask the service to reload."""

        from pii_guard.reference import (
            ReferenceSource,
            load_reference_terms,
            load_sources,
            materialize,
            normalize_type,
            register_project,
            terms_path,
            write_sources,
        )

        project = self._reference_project(payload.get("project"))
        columns_raw = payload.get("columns")
        if not isinstance(columns_raw, Mapping):
            raise WorkflowError("INVALID_COLUMNS", "The column mapping is invalid.")
        columns = {
            str(name): normalize_type(str(entity))
            for name, entity in columns_raw.items()
            if str(entity).strip()
        }
        columns = {name: entity for name, entity in columns.items() if entity != "SKIP"}

        upload_id = str(payload.get("upload_id") or "")
        if payload.get("copy_into_project"):
            source_path = str(self._copy_upload_into_project(project, upload_id))
        else:
            raw_path = str(payload.get("source_path") or "").strip()
            if not raw_path:
                raise WorkflowError("SOURCE_PATH_REQUIRED", "The table's own path is required.")
            resolved = Path(raw_path).expanduser()
            if not resolved.is_file():
                raise WorkflowError("TABLE_NOT_FOUND", "That table does not exist.")
            source_path = str(resolved)

        patterns: list[tuple[str, str]] = []
        raw_patterns = payload.get("patterns")
        if isinstance(raw_patterns, list):
            for entry in raw_patterns:
                if not isinstance(entry, Mapping):
                    continue
                name = entry.get("type")
                regex = entry.get("regex")
                if isinstance(name, str) and isinstance(regex, str) and regex:
                    patterns.append((normalize_type(name), regex))

        sheet = payload.get("sheet")
        source = ReferenceSource(
            path=source_path,
            sheet=str(sheet) if isinstance(sheet, str) and sheet else None,
            columns=columns,
            patterns=tuple(patterns),
        )
        kept = [
            item
            for item in load_sources(project)
            if not (item.path == source.path and item.sheet == source.sheet)
        ]
        kept.append(source)
        saved = write_sources(project, kept)
        # Writing the description is not enough on its own: the service only
        # reads the projects the installer config names.
        registered = register_project(project)
        loaded = load_reference_terms(kept)
        materialized = 0
        if payload.get("materialize"):
            materialized = materialize(kept, terms_path(project))
        summary = loaded.summary()
        summary.update(
            {
                "ok": True,
                "saved_path": str(saved),
                "project": str(project),
                "source_path": source_path,
                "materialized": materialized,
                "registered": registered,
                "service": self._reload_hookd(),
            }
        )
        return summary

    def reference_status(self, project_value: object) -> dict[str, object]:
        """What this project already has recorded; counts only."""

        from pii_guard.reference import load_reference_terms, load_sources, sources_path

        project = self._reference_project(project_value)
        sources = load_sources(project)
        loaded = load_reference_terms(sources)
        summary = loaded.summary()
        summary.update(
            {
                "ok": True,
                "project": str(project),
                "saved_path": str(sources_path(project)),
                "sources": [
                    {
                        "path": source.path,
                        "sheet": source.sheet,
                        "columns": len(source.columns),
                        "present": Path(source.path).expanduser().is_file(),
                    }
                    for source in sources
                ],
                "service": self._hookd_health(),
            }
        )
        return summary

    def _try_engine(self) -> object:
        """A regex-only engine kept for the preview box, built once."""

        with self.lock:
            if self._reference_engine is None:
                from pii_guard.hookd.core import create_engine

                self._reference_engine = create_engine("regex")
            return self._reference_engine

    def reference_try(self, text: str, project_value: object) -> dict[str, object]:
        """Show what the model would see, using the list that is saved now.

        Only the redacted text comes back.  The mapping that could undo it is
        built inside this call and dropped when it returns.
        """

        from pii_guard.hookd.core import SessionRedactor
        from pii_guard.reference import load_reference_terms, load_sources

        if not isinstance(text, str):
            raise WorkflowError("INVALID_REQUEST", "A UTF-8 text input is required.")
        if len(text.encode("utf-8")) > MAX_UPLOAD_BYTES:
            raise WorkflowError("INPUT_TOO_LARGE", "Input exceeds the safety size limit.")
        project = self._reference_project(project_value)
        loaded = load_reference_terms(load_sources(project))
        engine = self._try_engine()
        register = getattr(engine, "register_pattern_recognizers", None)
        if callable(register) and loaded.patterns:
            register(loaded.patterns)
        redactor = SessionRedactor(session_id="reference-preview", engine=engine)  # type: ignore[arg-type]
        redactor.seed(loaded.terms)
        result = redactor.redact(text)
        return {"ok": True, "text": result.text, "counts": result.counts}

    @staticmethod
    def _hookd_state() -> dict[str, object] | None:
        try:
            from pii_guard.hookd.state import HookdConfig, read_state

            return read_state(HookdConfig.from_env())
        except Exception:  # noqa: BLE001 - the service being absent is normal
            return None

    @classmethod
    def _hookd_health(cls) -> dict[str, object]:
        state = cls._hookd_state()
        if state is None:
            return {"running": False}
        return {"running": True, "port": state.get("port"), "engine": state.get("engine")}

    @classmethod
    def _reload_hookd(cls) -> dict[str, object]:
        """Ask a running guard service to re-read the lists, if there is one."""

        state = cls._hookd_state()
        if state is None:
            return {"running": False, "reloaded": False}
        try:
            request = urllib.request.Request(
                f"http://{LOOPBACK_HOST}:{state['port']}/v1/reload",
                data=b"{}",
                method="POST",
            )
            request.add_header("Authorization", f"Bearer {state['token']}")
            request.add_header("Host", f"{LOOPBACK_HOST}:{state['port']}")
            request.add_header("Content-Type", "application/json")
            with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
                body = json.loads(response.read().decode("utf-8"))
        except Exception:  # noqa: BLE001 - a guard that is down is not an error here
            return {"running": True, "reloaded": False}
        terms = body.get("terms") if isinstance(body, Mapping) else 0
        return {"running": True, "reloaded": True, "terms": terms}

    def close(self) -> None:
        """Stop the optional manager and release all background app threads."""

        with self.lock:
            if self._closed:
                return
            self._closed = True
            self._close_event.set()
            manager = self.audit_manager
            threads = list(self._audit_threads)
        if manager is not None:
            close = getattr(manager, "close", None)
            if not callable(close):
                close = getattr(manager, "shutdown", None)
            if callable(close):
                try:
                    close()
                except (OSError, RuntimeError, WorkflowError):
                    pass
        for thread in threads:
            if thread is not threading.current_thread():
                thread.join(timeout=2.0)
        with self.lock:
            self._audit_threads.clear()
            self._enhanced_job = None

    shutdown = close


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
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
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
                if segments == ["api", "reference", "status"]:
                    query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                    project = (query.get("project") or [""])[0]
                    self._json(app.reference_status(project))
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
                    state = app.review_state(segments[2])
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
                self._error(error, _error_status(error))
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
                if route == "/api/reference/inspect":
                    content_type = self.headers.get("Content-Type", "")
                    if not content_type.lower().startswith("multipart/form-data"):
                        raise WorkflowError("INVALID_UPLOAD", "A file upload is required.")
                    fields, filename, data, _ = _multipart_fields(body, content_type)
                    self._json(
                        app.reference_inspect(data, filename, fields.get("sheet") or None)
                    )
                    return
                if route in {"/api/reference/save", "/api/reference/try"}:
                    try:
                        payload = json.loads(body.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                        raise WorkflowError("INVALID_REQUEST", "Request body is invalid.") from exc
                    if not isinstance(payload, dict):
                        raise WorkflowError("INVALID_REQUEST", "Request body is invalid.")
                    if route == "/api/reference/save":
                        self._json(app.reference_save(payload))
                    else:
                        self._json(
                            app.reference_try(payload.get("text", ""), payload.get("project"))
                        )
                    return
                if route == "/api/process":
                    content_type = self.headers.get("Content-Type", "")
                    if content_type.lower().startswith("multipart/form-data"):
                        fields, filename, data, file_content_type = _multipart_fields(
                            body, content_type
                        )
                        mode = fields.get("mode", "quick")
                        if not isinstance(mode, str):
                            raise WorkflowError("INVALID_REQUEST", "Mode is invalid.")
                        result = app.process_upload(
                            data,
                            filename,
                            mode,
                            file_content_type=file_content_type,
                        )
                        self._json(result, 202 if result.get("mode") == "enhanced" else 200)
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
                    result = app.process(text, filename, mode)
                    self._json(result, 202 if result.get("mode") == "enhanced" else 200)
                    return
                if (
                    len(segments) == 5
                    and segments[:2] == ["api", "jobs"]
                    and segments[3] == "audit"
                    and segments[4] in {"cancel", "restart"}
                ):
                    operation = app.cancel if segments[4] == "cancel" else app.restart
                    self._json(operation(segments[2]), 202 if segments[4] == "restart" else 200)
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
                self._error(error, _error_status(error))
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
                self._error(error, _error_status(error))
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
    server = _SilentHTTPServer(
        (LOOPBACK_HOST, selected.port),
        http.server.BaseHTTPRequestHandler,
        application,
    )
    server.RequestHandlerClass = _handler_for(application, token, server.server_address[1])
    port = server.server_address[1]
    return server, f"http://{LOOPBACK_HOST}:{port}/{token}/"


def run_web(
    *,
    port: int = 0,
    open_browser: bool = False,
    store: PrivateJobStore | None = None,
    audit_model: str | None = None,
    ollama_url: str | None = None,
) -> None:
    """Run the local web UI until interrupted."""

    server, url = create_server(
        LocalWebApplication(
            store,
            audit_model=audit_model,
            ollama_url=ollama_url,
        ),
        WebConfig(port=port, audit_model=audit_model, ollama_url=ollama_url),
    )
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
