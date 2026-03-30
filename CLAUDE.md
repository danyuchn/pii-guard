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
- **Phase 4**：評估集，precision/recall 測試
- **Phase 5**：Claude Code `PreToolUse` hook 整合（自動攔截讀檔）

## Key Reference Files

- 調研筆記：`~/knowledge-base/bookmarks/presidio-pii-deidentification.md`
- 課程研究：`~/claude-course/official/research-pii-anonymization.md`
