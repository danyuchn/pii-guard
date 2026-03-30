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
[偵測層] CKIP NER + 台灣 Regex
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
| LLM（可選輔助） | Qwen2.5-3B/7B via Ollama | 補充 NER 漏掉的非結構化 PII |
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

## 開發路線圖

- [ ] Phase 1 MVP：Presidio + CKIP NER + 台灣 Regex，CLI 工具
- [ ] Phase 2：LangChain PresidioReversibleAnonymizer 整合，mapping JSON 可存檔
- [ ] Phase 3：Ollama Qwen2.5 作為 fallback 偵測層
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
