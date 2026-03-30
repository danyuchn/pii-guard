# pii-guard-tw

繁體中文（台灣）個人資料去識別化工具，讓業務文件可以安全地送進 AI 處理，完成後自動還原原始資料。

## 目的

企業用戶在使用 Claude / ChatGPT 等 AI 工具時，最大的顧慮是機敏資料外洩。本工具解決這個問題：

1. **送進 AI 前**：自動偵測文件中的個資，替換為佔位符（如 `[人名1]`、`[電話1]`）
2. **AI 回答後**：用對照表將佔位符還原為原始資料
3. **全程本地執行**：AI 只看到去識別化版本，真實資料不離開你的電腦

目標場景：台灣企業的業務文件、客戶資料、合約、會議記錄等。

## 架構設計

```
原始文件
    ↓
[偵測層] CKIP NER + 台灣 Regex + (可選) Ollama LLM
    → 輸出 JSON 實體列表
    ↓
[替換層] 程式碼建立 mapping table
    { "人名1": "張大明", "電話1": "0912-345-678" }
    ↓
去識別化文本（送 LLM）
    ↓
AI 回答（含佔位符）
    ↓
[還原層] 程式碼 reverse replace
    ↓
還原後的 AI 回答
```

**關鍵設計原則**：LLM 只做偵測輔助，替換與還原全部由程式碼完成，decode 可靠性 100%。

## 技術棧

| 層次 | 工具 | 說明 |
|------|------|------|
| PII 框架 | [Microsoft Presidio](https://github.com/microsoft/presidio) | 偵測 + 匿名化 + 還原，MIT 授權 |
| 繁中 NER | [ckiplab/bert-base-chinese-ner](https://huggingface.co/ckiplab/bert-base-chinese-ner) | 中研院，繁體中文人名/組織，102M |
| 台灣 PII Regex | 自建 PatternRecognizer | 身分證、統一編號、手機、市話 |
| LLM fallback（可選） | Qwen2.5:1.5b via Ollama | `--llm-fallback` 啟用，補充 NER 漏掉的非結構化 PII |
| Pipeline 整合 | LangChain PresidioReversibleAnonymizer | mapping table 序列化/還原 |
| 語言 | Python 3.11+ | |
| 套件管理 | uv | |

## 支援的 PII 類型

**NER 模型偵測（CKIP）：**
- 人名（PERSON）
- 組織名稱（ORG）
- 地名（LOC）

**Regex 偵測（台灣特有）：**
- 身分證字號：`[A-Z][12]\d{8}`
- 外籍居留證：`[A-Z][A-D89]\d{8}`
- 手機號碼：`09\d{8}`
- 市話：`0[2-8]\d{7,8}`
- 統一編號：`\d{8}`（搭配 context 詞過濾）
- Email、信用卡號（Presidio 內建）

## LLM Fallback（可選）

啟用 Ollama Qwen2.5 作為輔助偵測層，補抓 regex/CKIP 遺漏的邊緣案例：

```bash
# 前置：安裝 Ollama 並拉取模型
ollama pull qwen2.5:1.5b

# CLI 使用
uv run python -m pii_guard --llm-fallback input.txt -o output.txt

# 指定其他模型
uv run python -m pii_guard --llm-fallback --ollama-model qwen2.5:3b input.txt

# MCP Server 啟用
uv run python -m pii_guard serve --llm-fallback
# 或透過環境變數
PII_GUARD_LLM_FALLBACK=1 uv run python -m pii_guard serve
```

LLM confidence 設為 0.75（低於 regex 0.85 和 CKIP 0.85），確保確定性偵測結果優先。Ollama 不可用時自動降級，不影響既有功能。

## 開發路線圖

- [x] Phase 1 MVP：Presidio + CKIP NER + 台灣 Regex，MCP Server 介面
- [x] Phase 2：CKIP BERT NER 整合，+4 種 PII 類型（車牌/出生日期/國際手機/銀行帳號）
- [x] Phase 3：Ollama Qwen2.5:1.5b LLM fallback 偵測層（`--llm-fallback` 啟用）
- [ ] Phase 4：評估集建立，precision/recall 測試
- [ ] Phase 5：Claude Code PreToolUse hook 整合（自動攔截讀檔）

## 參考資料

- [Microsoft Presidio 官方文件](https://microsoft.github.io/presidio/)
- [Presidio 多語言設定](https://microsoft.github.io/presidio/tutorial/05_languages/)
- [Presidio TransformersRecognizer](https://microsoft.github.io/presidio/samples/python/transformers_recognizer/)
- [CKIP Transformers（中研院）](https://github.com/ckiplab/ckip-transformers)
- [LangChain PresidioReversibleAnonymizer](https://python.langchain.com/docs/guides/privacy/presidio_data_anonymization/reversible)
- 調研筆記：`~/knowledge-base/bookmarks/presidio-pii-deidentification.md`
- 課程研究：`~/claude-course/official/research-pii-anonymization.md`
