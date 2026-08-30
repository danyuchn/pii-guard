# Changelog

本檔案記錄對使用者可見的變更。格式參考 [Keep a Changelog](https://keepachangelog.com/zh-TW/1.1.0/)，
版號依 [Semantic Versioning](https://semver.org/lang/zh-TW/)。

## [未發布]

### 新增

- **第二階段文字型 PDF 本機快審。** localhost 入口接受 `.pdf`，在記憶體中以既有
  `pdfplumber` 選用依賴抽取文字，沿用 quick 私有工作核心、人工補遮、還原與手動刪除。
  可分別下載去識別化 UTF-8 文字或固定模板的安全獨立 HTML；不保存上傳 PDF 或原始檔名。
- **第一階段快速模式與完整 localhost 入口。** 新增 `pii_guard quick`、`web`／`local-web`
  與 `benchmark` 指令；快速模式沿用 Presidio、台灣規則與 CKIP，完全不啟動 Ollama。
  本機網頁提供選檔、模式選擇、去識別化快審、人工補遮、下載與單一工作手動刪除。
- CLI、網頁與 `pii-safe-documents` skill 的快速路徑共用私有工作目錄、mapping、
  anonymize／restore 核心；新增固定中文 fixture 與 cold/warm 可重跑 benchmark。
- 新增 `quick-restore` job-based CLI 入口；編輯後的去識別化文字可透過工作編號走共用
  restore core，輸出檔以 `0600` 建立，回執不含還原內容、mapping、digest 或私有路徑。

- README 補上一段人工補標介面的實際操作動畫（`docs/annotate-demo.gif`），
  示範文件是虛構判決書。靜態截圖保留在它下面。
- README 新增「還在做的事」：商用 agent 的越權與隔離（考慮走 proxy 配置）、
  批量與多格式文檔處理，並公開徵求試用者、意見與 PR。

### 修正

- localhost 入口固定繫結 `127.0.0.1`，不把原文、mapping 或還原內容放進 HTTP 回應、
  HTML、錯誤訊息或 server log；私有工作目錄保留 `0700`／`0600` 權限並可逐一刪除。
- 第一階段的模式選單明確標示加強模式尚未完成，避免把第二階段／第三階段功能當成已交付。
- PDF 上傳會先檢查 `%PDF-` 簽名、4 MiB 大小與 50 頁上限，再在記憶體中抽取；
  加密／密碼保護、無文字、掃描／圖片型、格式錯誤或抽取文字超過 64 KiB 都只回傳固定安全錯誤。
  PDF 下載明確只有文字與安全 HTML，沒有版面保留或去識別化 PDF 輸出。
- PDF 解析移入每次請求新建的隔離子行程；輸入／輸出走有界的記憶體管道，父行程設定
  15 秒牆鐘，子行程在可用平台設定 10 秒 CPU 與 512 MiB 位址空間上限。子行程的
  stdout／stderr 與 parser 例外細節不會穿透到父行程或公開回應。

- **`purge` 現在清得掉中途死掉的 job。** 一次 redact 若在寫出 manifest 之前結束
  ——被砍、逾時、或稽核不過——會把 worker 的 `.source.private.txt`（**完整原文**）
  與 `.mapping.private.json` 留在 job 目錄裡；而 `purge` 開頭就讀 manifest，
  於是**官方的清理指令正好清不掉最該清的那一種殘骸**。
  2026-08-26 在一個 jobs 目錄裡實際找到 11 個這種目錄，最舊的放了六天。

  manifest 既然從未寫出，來源驗證就改看版面：目錄在 jobs 根目錄底下、名字是合法的
  job id、且**裡面只有本 skill 會寫的檔案**——任何一個不認得的檔案就拒絕刪除，
  不對不認識的目錄執行 `rmtree`。清掉這種 job 時回執會多一個 `incomplete_job: true`。
  兩種情況都有測試（該刪的刪掉、有異物的拒絕），並已反向驗證。

- **被中斷的 `redact` 不再留下佔住模型的孤兒行程。** wrapper 原本用
  `subprocess.run()` 起私有 worker：逾時會回收子行程，但**父行程自己被砍時不會**。
  一次 `redact` 會安靜跑上好幾分鐘，所以「按耐不住把它砍掉」是新使用者最可能做的事——
  而那會留下一個看不見的 worker，最長可以再跑 90 分鐘
  （`REDACT_WORKER_TIMEOUT_SECONDS`），期間握著三條到 Ollama 的連線，
  把伺服器卡在 `Stopping...`，之後每一次執行都變慢。
  2026-08-26 實測：一個孤兒活了 31 分鐘，同一份文件原本 3 分 37 秒跑完的變成 16 分鐘，
  砍掉孤兒後 Ollama 立刻恢復。

  修法兩層：父行程改用 `Popen` 並在 `SIGTERM`／`SIGINT`／`SIGHUP` 與任何例外路徑上
  終止子行程；worker 自己另有一條看門狗執行緒，發現被收養（`getppid()` 變了或變成 1）
  就直接退出，這一層擋的是父行程被 `SIGKILL` 的情況。
  兩條路徑都有測試，且已反向驗證——把修復拿掉，測試會失敗。

## [0.2.0] — 2026-08-21

第一個「別人可以拿去用」的版本。此前 skill 的實際開發副本住在作者的私人目錄，
本 repo 內的是七月的過期複本；本版把兩者合為一份，並補上安裝、限制說明與人工補標介面。

### 新增

- **`pii-safe-documents` skill 的人工補標介面**（`annotate` 子指令）。在使用者自己的
  瀏覽器開一頁，可以選取仍然裸露的文字補遮（全文所有出現位置一起遮），也可以點任何
  標記看到背後的值並放回原文——後者用於被誤判為組織而遮掉的法院、醫院、公司名，
  那正是判決書遮完會失去文件用途的原因。
  網址帶一次性 token，在私有子行程內產生、只交給它自己開啟的瀏覽器，從不印出；
  呼叫端拿到的回執只有數量，沒有網址。
- 同樣兩種操作的無瀏覽器版本：`mask --terms <檔>`、`unmask --marker TYPE-N`，
  以及列出標記與值的 `review`（輸出不是終端機時拒絕執行）。
- 每次人工編輯都即時落檔，並在寫入前重新驗證整份文件仍能逐字還原，不通過就拒絕該次編輯。
- `CHANGELOG.md`（本檔）。

### 變更

- **skill 現在由本 repo 提供**，位於 `.agents/skills/pii-safe-documents/`，
  安裝方式是連結進 skills 目錄（見 README）。
- skill 的 wrapper 不再寫死 `~/tools/pii-guard`，改為解析自己所在的 checkout，
  clone 到任何位置都能運作；只能複製不能連結的環境可用 `PII_GUARD_HOME` 指定。
- README 補上安裝步驟、skill 安裝、稽核模型，以及三個使用前必讀的限制
  （只吃純文字、單份 10–50 分鐘、這是個資遮蔽不是機密分級），並展開了開發路線圖。
- `uv.lock` 改為納入版控，讓 clone 的人裝到相同版本。
- 環境需求文字統一為 Python 3.13（`requires-python` 仍為 >=3.11）。

### 文件與定位

- README 重寫：改以「為什麼還要一個」開場，明確主張**繁中／台灣個資 + 產出可留存的檔案**，
  並附一組**真實跑出來、刻意保留兩處漏遮**的 before/after 示範。
- 新增「這不是什麼」段，把需要透明批量的使用者指向 LiteLLM + Presidio 與 PrivAiTe。
- 準確率改以可重現者為主：`tests/eval/eval_corpus.json`（53 條合成語料，`pytest tests/eval -m eval` 可跑）
  打頭陣，私有真實語料的 71 項人工檢查降為註腳並標明無法外部驗證。
- 補英文摘要區塊（維持繁中為主體）、作者段、GitHub description 與 topics。
- `CLAUDE.md` 改為 `AGENTS.md` 的 symlink，兩檔不再各自漂移。

### 移除

- **`--llm-fallback` 與 `OllamaRecognizer`**（原 Phase 3，預設 `qwen2.5:1.5b`）。
  它與 skill 的稽核層目的重疊但沒有任何語料證明有效，並存只會讓使用者選錯。
  要在 CLI 端補回模型稽核，正確做法是下沉 skill 那一套，不是重新啟用這個。
  一併移除的還有 `PII_GUARD_LLM_FALLBACK` 環境變數與 `--ollama-model` 參數。

  > **破壞性變更**：若你的腳本帶了 `--llm-fallback`、`--ollama-model`，
  > 或設了 `PII_GUARD_LLM_FALLBACK`，請直接刪除；其餘偵測行為不變。

- **Claude Code PreToolUse hook** 移至 `examples/claude-code-hook/`，附退役理由說明，不再維護。
  它原本以攔截讀檔的方式隱式遮蔽，四個問題使其被 skill 取代：靜默失敗時使用者以為有防護、
  熱路徑載不動 CKIP 故只能用 regex（而繁中人名正是 regex 抓不到的）、不可逆、且涵蓋不到 `Bash`。

  > 這不影響 clone 的人：該 hook 找不到 `~/.config/pii-guard/hook-config.json` 就直接結束，預設為惰性。


### 修正

- 稽核層對隨機性的處理：每個視窗取樣多次取聯集，單次格式錯誤的回覆丟棄而非讓整份文件失敗，
  模型不肯終止的視窗切半重試。實測前，同一份罰款表會一次抓到四個公司名、下一次一個都沒有。
- 稽核層開啟推理。實測關閉推理時，判決書簽名欄的書記官姓名會被漏掉。
- PII Guard 只替換偵測到的區段而非該值的每一次出現，導致同一個姓名有殘留副本；
  現在會把已知值的其餘出現一併遮蔽。
- 全形空格填充的「中　華　民　國」被 CKIP 切成單字實體，污染全文；
  現在在送進偵測器前就先保護，且單字實體一律還原。
- 中文姓名的對齊門檻：原本沿用拉丁文的四字元下限，等於每個中文姓名都對不齊而使整份文件失敗。
- 個人信箱帳號在網址路徑中殘留（`http://example.edu/~xiaoming/`）。

### 已知限制
- 工作目錄（`~/.local/share/pii-safe-documents/jobs/`）沒有自動保留期限，只能手動 `purge`；
  長期使用會累積含真實對照表的目錄。

- 只支援 64 KiB 以內的 UTF-8 純文字。
- 單份文件 10–50 分鐘，批次處理上百份在此設定下不可行。
- 尚無簡繁折疊；稽核模型若回傳簡體姓名會以 `LOCAL_AUDIT_UNRESOLVED` 失敗。
- 尚無 CI，也尚無可公開的準確率數字（驗收語料含真實姓名，永不進 git）。

## [0.1.0]

初始版本：Presidio + CKIP BERT NER + 台灣特有 Regex 的可逆去識別化管線，
MCP server 介面，以及評估語料與 precision/recall 框架。
