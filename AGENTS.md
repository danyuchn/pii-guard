# AGENTS.md

This file provides guidance to coding agents (Claude Code, Codex, and others) working in this repository. `CLAUDE.md` is a symlink to this file.

## Project Overview

**pii-guard-tw** — 繁體中文（台灣）個人資料去識別化工具。將文件中的 PII 替換為佔位符後送 AI 處理，完成後自動還原，確保真實資料全程不離開本機。

## Tech Stack

- **Language**: Python 3.11+
- **Package manager**: `uv`（必用 `uv run` / `uvx`，禁用 pip）
- **PII framework**: Microsoft Presidio（偵測 + 匿名化 + 還原）
- **Chinese NER**: `ckiplab/bert-base-chinese-ner`（中研院，繁體中文）
- **Taiwan PII Regex**: 自建 `PatternRecognizer`（身分證、手機、市話、統一編號）
- **Pipeline**: LangChain `PresidioReversibleAnonymizer`（mapping table 序列化/還原）

## Architecture

```
原始文件
  ↓ [偵測層] CKIP NER + 台灣 Regex PatternRecognizer
  ↓ [替換層] 建立 mapping table → 去識別化文本
  ↓ [LLM 處理] AI 只看到佔位符版本
  ↓ [還原層] reverse replace → 還原後 AI 回答
```

**關鍵原則**：LLM 只做輔助偵測，替換與還原全由程式碼完成，decode 可靠性 100%。

## Commands

```bash
# 安裝依賴
uv sync

# 執行主程式（CLI）
uv run python -m pii_guard <input_file>

# 執行測試
uv run pytest

# 執行單一測試
uv run pytest tests/test_recognizers.py::test_tw_id_number -v

# 型別檢查
uv run mypy src/

# Lint
uv run ruff check src/

# 常駐 hook 去識別化服務（install 會併好 settings 並自動啟動）
uv run pii-guard-hookd install [--engine full|regex] [--scope user|project] [--no-launchd] [--harden] [--mod]
uv run pii-guard-hookd doctor [--harden] [--mod] | uninstall
uv run pii-guard-hookd serve [--engine full|regex] [--foreground] [--session-ttl-days N]
uv run pii-guard-hookd status | stop | purge [session_id|--all]

# 參考名單：把客戶名單（xlsx/csv）的欄位對應存成描述檔，值留在原檔
uv run pii-guard-hookd terms inspect <表格> [--sheet 名稱] [--json]
uv run pii-guard-hookd terms import <表格> [--map 姓名=PERSON,金額=SKIP] [--yes] [--materialize]
uv run pii-guard-hookd terms status | remove <表格>|--all | ui
```

## PII Types Supported

| 類型 | 方式 | Pattern |
|------|------|---------|
| 人名、組織、地名 | CKIP NER | BERT 模型推論 |
| 身分證字號 | Regex | `[A-Z][12]\d{8}` |
| 外籍居留證 | Regex | `[A-Z][A-D89]\d{8}` |
| 手機號碼（本地） | Regex | `09\d{8}` |
| 手機號碼（+886） | Regex | `\+886[-\s]?9\d{2}...` |
| 市話 | Regex | `0[2-8]\d{7,8}` |
| 統一編號 | Regex + context | `\d{8}` |
| Email、信用卡 | Presidio 內建（zh 覆寫） | — |
| 車牌 | Regex + context | `[A-Z]{2,3}-\d{4}` / `\d{3,4}-[A-Z]{2}` |
| 出生日期 | Regex + context | 民國 `\d{2,3}年...` / 西元 `\d{4}[-/.]` |
| 銀行帳號 | Regex + context | `\d{12,16}` |

## Development Roadmap

- **Phase 1 MVP** ✅ 2026-03-30：Presidio + 台灣 Regex 8 種，MCP Server 介面，89 tests
- **Phase 2** ✅ 2026-03-30：CKIP BERT NER（人名/組織/地名）整合驗證，+4 種 PII 類型，MCP smoke test，152 tests total
- **Phase 3** ✅ 2026-03-30，**2026-08-21 移除**：Ollama Qwen2.5:1.5b LLM fallback 偵測層。改由 `pii-safe-documents` skill 的多次取樣稽核取代；舊層無語料證據且與新層並存會讓使用者選錯。要在 CLI 端補回稽核，做法是下沉 skill 那套，不是重新啟用這個。
- **Phase 4** ✅ 2026-03-30：eval corpus 53 筆標註語料 + precision/recall/F1 框架，修復 5 個偵測問題。2026-08-31 實跑 `uv run pytest tests/eval/ -v -m eval -s`：Regex 49 TP / 0 FP / 0 FN（F1=100%），Full CKIP 62 TP / 1 FP / 2 FN（F1=97.6%）。同日把 loc-001 的標註由 LOCATION 更正為 TW_ADDRESS，並在類別正規化前依 raw type 排除 NER-only 類型，使結構化地址確實貢獻 Regex TP；另修正 TW_PASSWORD 關鍵字邊界，避免把 "passport" 的 "port" 誤判為密碼。
- **Phase 5** ✅：`pii-safe-documents` skill（顯式觸發、可逆、主 agent 隔離）。早期的 PreToolUse hook 已退役，見 `examples/claude-code-hook/`。
- **Phase 6** ✅ 2026-03-31：多格式檔案支援（xlsx/docx/pdf）CLI + MCP，file_handlers 模組，MIT LICENSE
- **Phase 7** 已完成：`src/pii_guard/hookd/` 常駐 loopback 服務＋classic hooks，工具輸出進模型前遮蔽、寫回時還原，連不到服務就擋住（設計與涵蓋範圍見 `examples/claude-code-hookd/README.md`）
- **Phase 9** 已完成：參考名單（reference list seeding）。`src/pii_guard/reference.py` 把客戶名單（xlsx／csv）的「欄位 → 類型」對應存成 `<專案>/.pii-guard/sources.json`（**只存描述，不存值**），服務依來源檔 mtime 重讀，`POST /v1/reload` 免重啟。編號類欄位會推出格式 regex 動態註冊成 `PatternRecognizer`，名單外的新編號也抓得到。三個入口共用同一份設定：`pii-guard-hookd terms`、Claude Code 的 `/pii-terms`、本機網頁的「名單」分頁；匯入時會自動把專案登記進 installer config 的 `policy.reference_sources`，服務每次 reload 重讀該清單，所以「先裝 hook、後匯名單」不需重啟。Excel 存成數字而掉了開頭 0 的手機／市話／統編會依欄位類型補回。值不進 stdout／log／hook 回覆／HTTP JSON，例外只有網頁每欄 3 筆預覽與 `--materialize` 寫出的 `terms.txt`。
- **Phase 8** 已完成：`examples/claude-code-mod/` Claude Mods 前端（function hooks）。同一個服務、同一套規則，但 `tool.call` 跑在 Edit 驗證之前，補掉 classic hooks 的 Edit 缺口；prompt 由「整則擋掉」改成「改寫」。安裝用 `install --mod`，只有 MessageDisplay 仍是 classic hook（function hook API 沒有對應事件）。設計、限制與事前驗證見 `examples/claude-code-mod/README.md`

### Recall Benchmark（2026-03-31 真實文件測試）
- 格式化 PII（身分證/手機/Email/市話/車牌/生日/銀行帳號）：~95%
- 中文人名/組織：~75%
- 英文人名/組織（需 `en_core_web_sm`）：~80%
- 整體 recall（68 項 PII）：82.4%
- 已知弱點：暱稱（龍哥/寶哥）、非典型英文名（Ema/Proco）、統編 context 觸發

