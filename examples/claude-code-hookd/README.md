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
        │      註：Edit 的 old_string 例外，見「限制」一節
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

## 已驗證（2026-09-15，Claude Code 2.1.272）

以一個 Sonnet session 實跑，判讀依據是 transcript JSONL 而不是畫面。

| 情境 | 結果 |
|------|------|
| `Read` 之後模型只看到 `<TW_MOBILE_1>` 這類佔位符 | 通過 |
| 同一個真值跨 `Read` 與 `Bash` 拿到同一個佔位符 | 通過 |
| `MessageDisplay` 畫面顯示真值、transcript 仍是佔位符 | 通過 |
| `Write` 寫進磁碟的是真值、transcript 的 tool_use 仍是佔位符 | 通過 |
| `Bash` stdout 被遮蔽；命令列裡的佔位符執行前被還原 | 通過 |
| 服務停掉時 `Read` 回擋住的樣板、`Write` 被 deny | 通過 |
| `Edit` 的 `old_string` 帶佔位符 | **失敗**，見下節 |
| `Grep` 的葉節點遮蔽 | **未實測**（該 session 的環境停用了 `Grep`） |

## 限制：`Edit` 的 `old_string` 不會被還原

`Edit` 與 `MultiEdit` 用 `old_string` 去比對**磁碟上的真實檔案**，而那個比對發生在
**hook 觸發之前**。官方 hooks 文件寫得很清楚：輸入若沒通過 schema 或工具自身的驗證，
「會在 hooks 執行前就結束，因此 PreToolUse 與 PostToolUseFailure 都不會觸發」。

所以 `old_string` 裡帶佔位符的 `Edit` 會直接失敗，錯誤訊息是
`String to replace not found`，這條路徑我們補不了。

`new_string` 仍然會被還原，所以 `Edit`／`MultiEdit` 留在 matcher 裡。
遇到這個錯誤時的正解寫在 SessionStart 送給模型的 context 裡：改用 `Write`
重寫整個檔案（`content` 會被還原），或用 `Bash` 指令改。
**絕對不要為了讓 `Edit` 對得上而去猜佔位符背後的真值。**

## 失敗時的行為：一律擋住（fail closed）

hook client 連不到服務、逾時、收到非 2xx、或收到看不懂的回覆時，**不會放行原始內容**：

- **Read**：檔案內容換成一行「hookd unreachable」說明，其餘欄位照原樣回填。
- **Bash**：stdout／stderr 同樣換掉。
- **Grep**：結構保留，每個字串葉節點換掉（**未實測**，見上面的驗證表）。
- **Write／Edit／MultiEdit／Bash（寫入側）**：直接 `deny`，理由是佔位符還原不了。
- **MessageDisplay**：每則訊息的第一個 delta 前面加上離線標記。
- **SessionStart**：送出明顯的警告，並告訴模型在使用者啟動服務前不要讀敏感檔案。

這是刻意的取捨。`type: "http"` 的 hook 連不上時會 fail **open**，所以這裡用
`type: "command"` 搭配一支自己會擋的 client。

**服務停著的時候，每一個 `Write`／`Edit`／`MultiEdit`／`Bash` 都會被 deny，
包含那些根本沒有佔位符的。** 這是刻意的，不是 bug：hook client 連不到服務時，
沒有任何辦法知道某段內容裡有沒有佔位符——能判斷的那個東西正是連不上的服務。
要恢復寫入就把服務啟動起來，或把 hooks 從 settings 拿掉。

## 涵蓋範圍：明說擋不到哪些

擋得到：`Read`、`Bash`、`Grep` 的輸出，含 subagent 發出的同名工具呼叫。

**擋不到**：

- **prompt 裡用 `@` 引用的檔案**。官方文件說明這類檔案是直接插進 prompt 的，
  **不經過任何工具呼叫**，所以沒有任何 hook 會觸發。這是最容易踩到的一個洞：
  你以為 `@secrets.csv` 和 `Read secrets.csv` 一樣受保護，其實完全沒有。
- **你自己打進去的字**（UserPromptSubmit）。你貼進對話框的個資不經過這條路。
- **Compaction 摘要**。壓縮時模型看的是已經在 context 裡的內容，那些已經是佔位符，
  但摘要本身不再經過 hook。
- **MCP server 的輸出**，除非你自己把工具名加進 PostToolUse 的 matcher。
- **會記錄原始工具輸出的 telemetry**。hook 換掉的是模型看到的東西，不是磁碟上的紀錄。
- **transcript 存的是佔位符**。這對安全是好事（真值沒有落進 transcript），但代價是
  `--resume` 回來看到的是佔位符，要等 `MessageDisplay` 還原後才看得到真值。
- **`Edit` 的 `old_string`**，原因見上面的「限制」一節。
- **惡意情境**。這套擋的是「不小心把個資餵給模型」，不是擋一個想繞過它的人。

另外，偵測本身有 recall 上限（見上表），所以**這是 best-effort，不是保證**。

### `Bash` 還原是唯一擴大曝險的路徑

`PreToolUse` 會把 `Bash` 指令裡的佔位符換成真值才執行，所以真值會出現在
**process list 與 shell history** 裡。這一條是刻意保留的：不還原的話，
對受保護檔案下 `grep`／`sed`／`awk` 全部會失效，等於逼模型改用別的方式繞開防線。

如果你的威脅模型包含「同一台機器上的其他使用者看得到 process list」，
就把 `Bash` 從 `PreToolUse` 的 matcher 拿掉，代價是模型無法用 shell 指令
處理含佔位符的內容。

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
