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

**關鍵設計原則**：偵測層可以是機率性的，但**替換與還原全部由程式碼完成**，所以還原一定精確。skill 在這條管線之後另外加一層本地模型稽核，見下方說明。

## 技術棧

| 層次 | 工具 | 說明 |
|------|------|------|
| PII 框架 | [Microsoft Presidio](https://github.com/microsoft/presidio) | 偵測 + 匿名化 + 還原，MIT 授權 |
| 繁中 NER | [ckiplab/bert-base-chinese-ner](https://huggingface.co/ckiplab/bert-base-chinese-ner) | 中研院，繁體中文人名/組織，102M |
| 台灣 PII Regex | 自建 PatternRecognizer | 身分證、統一編號、手機、市話 |
| Pipeline 整合 | LangChain PresidioReversibleAnonymizer | mapping table 序列化/還原 |
| 語言 | Python 3.13（`requires-python >=3.11`） | |
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

## 安裝

需要 Python 3.13（3.11 以上可跑）、[uv](https://docs.astral.sh/uv/)、以及 [Ollama](https://ollama.com/)。

```bash
git clone https://github.com/danyuchn/pii-guard.git
cd pii-guard
uv sync

# 需要 CLI 直接處理 .docx / .xlsx / .pdf 時再加裝（skill 目前不需要）
uv sync --extra formats
```

首次執行會下載 CKIP BERT NER 模型（約 500MB）。未加裝 `formats` 時，`tests/test_file_handlers.py` 的 10 個測試會因缺少 `openpyxl` / `python-docx` / `pdfplumber` 而跳不過，屬預期行為。

## Claude Code Skill（推薦用法）

本 repo 內含 `pii-safe-documents` skill，位於 `.agents/skills/pii-safe-documents/`。它在 CLI 之外多做一件事：**讓主 agent 全程看不到原始文件、對照表與還原結果**——主 agent 只拿到路徑與「成功／失敗」回執，讀檔、呼叫模型、還原都在一個獨立的本地行程裡完成。

安裝方式是把它連結進 skills 目錄，不要複製：

```bash
# Claude Code（user level）
ln -s "$(pwd)/.agents/skills/pii-safe-documents" ~/.claude/skills/pii-safe-documents

# 稽核模型
ollama pull ornith-1.5:9b
```

用連結而非複製，是因為 skill 需要找到它所屬的 repo 才能呼叫 pii-guard 本體。若你的環境只能複製，改設環境變數 `PII_GUARD_HOME` 指向 clone 出來的路徑。

裝好後在 Claude Code 裡直接說「幫我把這份檔案去識別化」即可。

### 使用前必讀的三個限制

1. **支援格式有限**：目前只吃 64 KiB 以內的 UTF-8 純文字（`.txt` `.md` `.csv` `.tsv` `.log` `.dat`）。`.docx` `.xlsx` `.pdf` 尚未提供保證隔離的解析器，改副檔名繞過會被擋。
2. **很慢**：稽核層開啟推理並對每個視窗取樣三次，單份文件實測 10–50 分鐘。這是為了偵測召回率付的代價（關閉推理時模型會漏掉判決書簽名欄的人名）。**批次處理上百份文件在此設定下不可行。**
3. **這是個資遮蔽，不是機密分級**。金額、病情、行程、合約條款只要不指向特定個人就會留著。不要單憑本工具宣稱「整份文件可以對外」。

隔離性的正確描述是：**防止意外把原文餵給雲端模型的強保護，不是作業系統層級的安全邊界**。同一個使用者身分下的惡意行程仍可讀到檔案；真正的敵意隔離需要獨立權限的本地 broker 或另開系統帳號。

## 開發路線圖

- [x] Phase 1 MVP：Presidio + CKIP NER + 台灣 Regex，MCP Server 介面
- [x] Phase 2：CKIP BERT NER 整合，+4 種 PII 類型（車牌/出生日期/國際手機/銀行帳號）
- [x] Phase 3：~~Ollama Qwen2.5:1.5b LLM fallback 偵測層~~（2026-08-21 移除，見下方說明）
- [x] Phase 4：評估集建立，precision/recall 測試
- [x] Phase 5：`pii-safe-documents` skill（主 agent 隔離的可逆去識別化工作流）
- [x] Phase 6：人工補標介面（localhost 網頁）
- [ ] Phase 7：效能
- [ ] Phase 8：更多文件類型
- [ ] Phase 9：可公開的準確率數字與 CI

以下依「解鎖關係」排序，不是依工作量。

### Phase 6：人工補標介面（已完成）

排第一不是因為最急，而是**它決定其他每一項的取捨空間**。稽核層目前開推理、每個視窗取樣三次，是因為它是最後一道防線，漏了就真的漏了。有了人工兜底，稽核就不必扛滿，效能優化的天花板才鬆得開。

```bash
python3 .agents/skills/pii-safe-documents/scripts/pii_safe_workflow.py annotate --job-id "<job_id>"
```

在使用者自己的瀏覽器開一頁，兩種操作都在上面完成，都不需要對照原文：

- **選取任何仍然裸露的文字 → 遮蔽**。全文所有出現位置一起遮，不是只遮選到的那一處。
- **點任何標記 → 看到背後的值 → 放回**。用在不該被遮的內容，通常是法院、醫院、公司名——遮掉會讓判決書失去文件用途。

**這一頁 agent 連不上，不是靠規則、是靠設計**：網址帶一次性 token，token 在私有子行程內產生、只交給它自己開啟的瀏覽器，從不印出；agent 收到的回執只有數量，沒有網址。

每次編輯都即時寫檔並重新驗證整份仍能逐字還原，所以中途關掉瀏覽器只會失去還沒做的編輯，不會失去已做的。

無瀏覽器的機器可改用 `mask --terms <檔>` / `unmask --marker TYPE-N`，並用 `review` 列出標記與值——`review` 會印出未遮蔽的值，因此在輸出不是終端機時拒絕執行。

### Phase 7：效能

單份文件目前 10–50 分鐘，批次處理上百份在此設定下不可行。

1. **先做免費的那項**：`OLLAMA_NUM_PARALLEL` 目前未設定，三次取樣改併發後只快了約一半而非三倍，很可能就卡在這裡。設定後重新計時，成本極低，且**尚未驗證**——應該在任何架構優化之前先排除它。
2. **決定性預篩**：整份文件多數視窗根本沒有人名形狀的字串，卻同樣花三次推理去確認「沒有」。先用規則篩出可疑視窗再送模型，是批次可行的唯一路徑。
3. **模型與取樣次數的取捨**：更小更快的模型配更多次取樣是否勝過現在的 9B 配三次，只能用真實語料量測，不能推論——合成測資在本專案已證實會系統性高估。
4. 少數文件（如通訊錄）會讓模型進入不終止的生成，切半重試能救正確性但救不了時間，可能需要單獨路徑。

### Phase 8：更多文件類型

library 端已能讀 `.docx` / `.xlsx` / `.pdf`（`formats` 相依套件）。卡住的是 skill 端：解析套件可能在警告訊息中回吐原文，會破壞隔離。所以工作不是寫解析器，而是**把既有解析器移進私有行程執行，並驗證它不回吐原文**。

難度排序：`.docx`（結構化、可寫回、保留格式可行）→ `.xlsx`（格子座標讓對齊比純文字更好處理）→ `.pdf`（寫回幾乎不可能，現行 handler 對 PDF 只輸出純文字；是否支援可逆去識別化屬產品決策）。

### Phase 9：可公開的準確率數字與 CI

- 目前沒有 CI，外部貢獻無從判斷有沒有弄壞既有行為。
- 現有的驗收語料含真實姓名、永不進 git，因此**無法公開任何準確率數字**。要讓別人有理由相信這個工具，需要另建一份可公開的語料來報數。
- 安裝流程尚未在作者以外的機器驗證過。

### 尚未解決的已知問題

- 簡繁折疊未實作：稽核模型若回傳簡體姓名，會以 `LOCAL_AUDIT_UNRESOLVED` 失敗，需要對照表。
- Presidio 會把法院名、醫院名、公司名判為組織而遮蔽，判決書因此失去部分文件用途。可用 `--allow` 逐案放行，長期解在 Phase 6 的「放回」。
- 曾出現一次 `ROUNDTRIP_INTEGRITY_FAILED`，其後未再重現，未能隔離。

### 關於已移除的 LLM fallback 偵測層

Phase 3 曾在 Presidio 內掛一個 Ollama recognizer（`--llm-fallback`，預設 `qwen2.5:1.5b`）。2026-08-21 移除，原因是 `pii-safe-documents` skill 用**取樣多次取聯集**的方式做本地模型稽核，在真實文件上量測有效，而舊的單次 1.5B 呼叫沒有任何語料證明它有效，卻讓使用者面對兩個看起來在做同一件事的開關。留著會讓人選錯。要在 CLI 端補回模型稽核，正確做法是把 skill 那套下沉，不是把舊的打開。

## 變更紀錄

見 [CHANGELOG.md](CHANGELOG.md)。

## 參考資料

- [Microsoft Presidio 官方文件](https://microsoft.github.io/presidio/)
- [Presidio 多語言設定](https://microsoft.github.io/presidio/tutorial/05_languages/)
- [Presidio TransformersRecognizer](https://microsoft.github.io/presidio/samples/python/transformers_recognizer/)
- [CKIP Transformers（中研院）](https://github.com/ckiplab/ckip-transformers)
- [LangChain PresidioReversibleAnonymizer](https://python.langchain.com/docs/guides/privacy/presidio_data_anonymization/reversible)
