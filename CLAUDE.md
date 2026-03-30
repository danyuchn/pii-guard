# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**pii-guard-tw** — 繁體中文（台灣）個人資料去識別化工具。將文件中的 PII 替換為佔位符後送 AI 處理，完成後自動還原，確保真實資料全程不離開本機。

## Tech Stack

- **Language**: Python 3.11+
- **Package manager**: `uv`（必用 `uv run` / `uvx`，禁用 pip）
- **PII framework**: Microsoft Presidio（偵測 + 匿名化 + 還原）
- **Chinese NER**: `ckiplab/bert-base-chinese-ner`（中研院，繁體中文）
- **Taiwan PII Regex**: 自建 `PatternRecognizer`（身分證、手機、市話、統一編號）
- **Pipeline**: LangChain `PresidioReversibleAnonymizer`（mapping table 序列化/還原）
- **LLM fallback（Phase 3）**: Qwen2.5 via Ollama

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
- **Phase 3** ✅ 2026-03-30：Ollama Qwen2.5:1.5b LLM fallback 偵測層（opt-in `--llm-fallback`），14 unit tests，167 tests total
- **Phase 4** ✅ 2026-03-30：eval corpus 53 筆標註語料 + precision/recall/F1 框架，修復 5 個偵測問題，Regex F1=100%、Full CKIP F1=97.6%
- **Phase 5** ✅ 2026-03-30：Claude Code PreToolUse hook（審核模式）+ anonymize_file MCP 工具，180 tests total

## Phase 5: PreToolUse Hook + anonymize_file

### How it works
```
Claude Read(file)
  → Bash filter（跳過 .py/.json/etc）
  → Python regex-only engine 偵測 PII
  → 有 PII → permissionDecision: "ask"（使用者審核）
    → 使用者允許 → Claude 讀原檔（知情同意）
    → 使用者拒絕 → Claude 改用 anonymize_file MCP 工具
  → 無 PII → 靜默放行
```

### MCP Tools（5 個）
- `anonymize_text(text)` — 文字去識別化
- `anonymize_file(file_path)` — 讀檔 + 去識別化（不需先 Read）
- `restore_text(anonymized_text, session_id)` — 還原
- `save_mapping(session_id, path)` — 匯出 mapping
- `restore_from_file(anonymized_text, mapping_path)` — 跨 session 還原

### Configuration
- Hook 設定：`.claude/settings.json`（project-level）
- 行為設定：`~/.config/pii-guard/hook-config.json`
  - `enabled`: 開關
  - `protected_paths`: 只處理這些目錄下的檔案（空 = 全部）
  - `protected_extensions`: 只處理這些副檔名（`.txt`, `.csv`, `.tsv`, `.log`, `.dat`）

## Key Reference Files

- 調研筆記：`~/knowledge-base/bookmarks/presidio-pii-deidentification.md`
- 課程研究：`~/claude-course/official/research-pii-anonymization.md`
