# Claude Code hookd 整合（常駐服務 + classic hooks）

讓 Claude Code **透過工具讀到的東西，在進入模型之前就被去識別化**；模型寫回檔案、
或畫面要顯示給你看的時候，再把佔位符換回真值。真實個資全程不進模型 context。

這是 `examples/claude-code-hook/`（已退役）那個想法的復活版。當年那版的四個致命傷，
這版用新的 hook 能力逐一補掉：**失敗時擋住而不是放行**、**引擎常駐所以跑得動 NER**、
**對照表留在服務裡所以可逆**、**涵蓋 Read／Bash／Grep 而不只是 Read**。

## 流程

```
Claude 呼叫 Read/Bash/Grep
        │
        ▼
  PostToolUse hook ──► hookd ──► 遮蔽 ──► 模型只看到 <PERSON_1>
        │                （對照表留在服務記憶體與本機檔案）
        ▼
  模型產出含 <PERSON_1> 的內容
        │
        ├─► PreToolUse(Write/Edit/MultiEdit/Bash) ──► 還原真值 ──► 寫進磁碟
        │
        └─► MessageDisplay ──► 還原真值 ──► 只顯示給你看（不回模型）
```

對照表以 `session_id` 為索引。subagent 的工具呼叫帶的是同一個 `session_id`
（多一個 `agent_id`），所以 subagent 與主 agent 共用同一組佔位符。

## 安裝

```bash
# 1. 安裝 hook client 並印出要合併的設定（這支腳本不會自己改你的 settings.json）
bash examples/claude-code-hookd/install.sh

# 2. 把印出來的 hooks 區塊自己併進 ~/.claude/settings.json 或專案 .claude/settings.json

# 3. 啟動常駐服務
uv run pii-guard-hookd serve
```

指令：

| 指令 | 作用 |
|------|------|
| `uv run pii-guard-hookd serve` | 背景啟動（regex 引擎） |
| `uv run pii-guard-hookd serve --engine full` | 啟動並載入 CKIP BERT（抓得到中文人名） |
| `uv run pii-guard-hookd serve --foreground` | 不背景化，留在終端機 |
| `uv run pii-guard-hookd status` | 看有沒有在跑、port、已載入的 session 數 |
| `uv run pii-guard-hookd stop` | 停止並清掉狀態檔 |
| `uv run pii-guard-hookd purge <session_id>` | 忘掉某個 session 的對照表 |
| `uv run pii-guard-hookd purge --all` | 忘掉全部 |

服務把 port 與 bearer token 寫在 `~/.local/share/pii-guard/hookd/` 底下的
`state.json` 與 `state.env`（兩個都是 0600），hook client 靠這兩個檔找到服務。
用 `PII_GUARD_HOOKD_HOME` 可以換位置。

## 引擎選擇

| 引擎 | 啟動 | 抓得到 | 抓不到 |
|------|------|--------|--------|
| `regex`（預設） | 不到一秒 | 身分證、居留證、手機、市話、統編、Email、信用卡、車牌、生日、銀行帳號 | **人名、組織名、地名** |
| `full` | 數秒（載入 CKIP BERT，約 500MB） | 上列全部 ＋ 中文人名／組織／地名 | 暱稱、非典型英文名 |

**這是整份文件最重要的一段**：regex 引擎擋得住身分證字號，擋不住「王小明」。
文件裡真正敏感的常常是人名，所以要靠這套防線就用 `--engine full`。
實測 recall 見專案根目錄 README 的 benchmark 段。

## 失敗時的行為：一律擋住（fail closed）

hook client 連不到服務、逾時、收到非 2xx、或收到看不懂的回覆時，**不會放行原始內容**：

- **Read**：檔案內容換成一行「hookd unreachable」說明，其餘欄位照原樣回填。
- **Bash**：stdout／stderr 同樣換掉。
- **Grep**：結構保留，每個字串葉節點換掉。
- **Write／Edit／MultiEdit／Bash（寫入側）**：直接 `deny`，理由是佔位符還原不了。
- **MessageDisplay**：每則訊息的第一個 delta 前面加上離線標記。
- **SessionStart**：送出明顯的警告，並告訴模型在使用者啟動服務前不要讀敏感檔案。

這是刻意的取捨。`type: "http"` 的 hook 連不上時會 fail **open**，所以這裡用
`type: "command"` 搭配一支自己會擋的 client。

## 涵蓋範圍：明說擋不到哪些

擋得到：`Read`、`Bash`、`Grep` 的輸出，含 subagent 發出的同名工具呼叫。

**擋不到**：

- **你自己打進去的字**（UserPromptSubmit）。你貼進對話框的個資不經過這條路。
- **Compaction 摘要**。壓縮時模型看的是已經在 context 裡的內容，那些已經是佔位符，
  但摘要本身不再經過 hook。
- **MCP server 的輸出**，除非你自己把工具名加進 PostToolUse 的 matcher。
- **會記錄原始工具輸出的 telemetry**。hook 換掉的是模型看到的東西，不是磁碟上的紀錄。
- **transcript 存的是佔位符**，所以 `--resume` 回來看到的是佔位符，不是真值。
- **惡意情境**。這套擋的是「不小心把個資餵給模型」，不是擋一個想繞過它的人。

另外，偵測本身有 recall 上限（見上表），所以**這是 best-effort，不是保證**。

## 和 `pii-safe-documents` skill 的關係

兩者解的是不同問題，可以並存：

| | `pii-safe-documents` skill | hookd |
|---|---|---|
| 觸發 | 顯式，使用者說「處理這份檔案」 | 隱式，每一次工具呼叫 |
| 範圍 | 一份文件 | 整個 session 讀到的全部 |
| 稽核 | 有，多次取樣稽核 | 無 |
| 主 agent 隔離 | 有 | 無（主 agent 看得到遮蔽後的內容） |
| 適合 | 真的機密、需要確認遮乾淨的文件 | 日常降低意外曝光 |

**要處理真正機密的文件，用 skill。hookd 是背景的安全網，不是替代品。**

## 檔案

- `pii_guard_hook_client.py` — hook 本體。只用標準函式庫，不 import 這個專案，
  不跑 uv。刻意寫得短而好讀，因為這是你要親自審的那一支。
- `settings.json` — hooks 區塊範本，路徑處寫 `__HOOKD_CLIENT__` 佔位。
- `install.sh` — 複製 client 到 `~/.claude/hooks/pii-guard/` 並印出填好路徑的設定。
  **它不會自己改你的 settings.json**，要你自己看過再併。
