# Claude Code hookd 整合（常駐服務 + classic hooks）

讓 Claude Code **透過工具讀到的東西，在進入模型之前就被去識別化**；模型寫回檔案、
或畫面要顯示給你看的時候，再把佔位符換回真值。真實個資全程不進模型 context。

這是 `examples/claude-code-hook/`（已退役）那個想法的復活版。當年那版的四個致命傷，
這版用新的 hook 能力逐一補掉：**失敗時擋住而不是放行**、**引擎常駐所以跑得動 NER**、
**對照表留在服務裡所以可逆**、**涵蓋 Read／Bash／Grep 而不只是 Read**。

## 快速開始

```bash
# 1. 取得這個 repo 並裝好依賴（只做一次）
git clone https://github.com/danyuchn/pii-guard && cd pii-guard && uv sync

# 2. 一行安裝：複製 hook client、併進 settings.json、寫設定、註冊開機自動啟動
uv run pii-guard-hookd install

# 3. 打開 Claude Code。沒了。
```

處理真正敏感的專案時改用 `uv run pii-guard-hookd install --harden`，
它會多堵住幾條「拿到佔位符之後還能把內容送出去」的路，代價見下面的加固模式一節。

`install` 最後會自動跑一次 `doctor` 並逐項印出結果，所以你不必猜自己有沒有被保護。
之後任何時候都可以再跑 `uv run pii-guard-hookd doctor` 確認。

要移除：`uv run pii-guard-hookd uninstall`（只拿掉自己裝的東西，備份與對照表留著）。

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

## 指令

| 指令 | 作用 |
|------|------|
| `install` | 裝 hook client、併設定、寫設定檔、註冊自動啟動，最後跑 doctor |
| `install --engine regex` | 同上，但只用 regex 引擎（快，但抓不到人名） |
| `install --scope project` | 併進當前目錄的 `.claude/settings.json` 而不是使用者層 |
| `install --no-launchd` | 不註冊 LaunchAgent，改由 hook client 隨用隨啟 |
| `install --harden` | 同上加出口封鎖、sandbox、prompt 檢查（見加固模式一節） |
| `doctor --harden` | 連加固設定一起檢查 |
| `uninstall` | 反向移除（備份、設定檔與對照表留著） |
| `doctor` | 逐項檢查並回報；任何一項 FAIL 就 exit 1 |
| `serve` | 手動啟動（背景）；`--foreground` 留在終端機 |
| `status` / `stop` | 看狀態／停止 |
| `purge <session_id>` / `purge --all` | 忘掉對照表 |

全部都以 `uv run pii-guard-hookd <指令>` 執行。

### 服務怎麼被啟動

四條路，優先序由上而下：

1. **`install` 當下**：裝完如果服務沒在跑，`install` 會直接把它啟動並等到它回應，
   所以安裝結束時服務就是活的（`--no-launchd` 與非 macOS 也一樣）。
2. **LaunchAgent**（macOS，`install` 預設）：登入時自動起，掛掉會被 `KeepAlive` 拉回來。
3. **隨用隨啟**：`SessionStart` 時 hook client 發現服務沒起來，就照
   `~/.config/pii-guard/hookd.json` 裡的 `serve_command` 把它拉起來，等它回應再放行。
   **只有 `SessionStart` 會這樣做**——其他事件必須即時回應，不能卡著等模型載入。
4. **手動** `serve`。

第一次跑 `--engine full` 而模型還沒下載完時，等待會逾時（預設 20 秒，
可用 `PII_GUARD_HOOKD_START_TIMEOUT` 調整）。那個 session 會拿到離線警告，
但服務會繼續在背景載入，下一個 session 就正常了。

### 檔案位置

| 檔案 | 用途 |
|------|------|
| `~/.local/share/pii-guard/hookd/state.json`、`state.env`（0600） | port 與 bearer token，hook client 靠它找到服務 |
| `~/.local/share/pii-guard/hookd/sessions/*.json`（0600） | 每個 session 的對照表 |
| `~/.config/pii-guard/hookd.json`（0600） | repo 路徑、引擎、`serve_command` |
| `~/.claude/hooks/pii-guard/pii_guard_hook_client.py` | hook client 本體 |
| `~/Library/LaunchAgents/com.pii-guard.hookd.plist` | macOS 自動啟動 |

環境變數：

| 變數 | 作用 |
|------|------|
| `PII_GUARD_HOOKD_HOME` | 換掉 state 與對照表的位置 |
| `PII_GUARD_HOOKD_CONFIG` | 換掉 `hookd.json` 的位置 |
| `CLAUDE_CONFIG_DIR` | 換掉 Claude Code 設定目錄（`install` 據此決定裝哪裡） |
| `PII_GUARD_HOOKD_START_TIMEOUT` | `SessionStart` 等待服務啟動的秒數，預設 20 |

這些目錄一建立就是 `0700`，對照表與 state 檔是 `0600`。

對照表預設保存 14 天，服務啟動時掃掉過期的（`serve --session-ttl-days`，`0` 關閉）。

## 引擎選擇

| 引擎 | 啟動 | 抓得到 | 抓不到 |
|------|------|--------|--------|
| `full`（**預設**） | 數秒（載入 CKIP BERT，約 500MB） | 下列全部 ＋ 中文人名／組織／地名 | 暱稱、非典型英文名 |
| `regex` | 不到一秒 | 身分證、居留證、手機、市話、統編、Email、信用卡、車牌、生日、銀行帳號 | **人名、組織名、地名** |

**這是整份文件最重要的一段**：regex 引擎擋得住身分證字號，擋不住「王小明」。
文件裡真正敏感的常常是人名，所以預設是 `full`。實測 recall 見專案根目錄 README
的 benchmark 段。

`full` 載入失敗時（模型沒下載、import 出錯），服務**不會整個不動**，而是退回
`regex` 並大聲說出來：stderr 印一行、`/v1/health` 的 `engine_fallback` 為真、
`doctor` report 該項 FAIL、SessionStart 的 systemMessage 變成
`pii-guard: on (regex only, names NOT covered)`。

換句話說，狀態列那一行就是你有沒有被完整保護的答案：

- `pii-guard: on (full engine, names covered)` — 完整保護
- `pii-guard: on (regex only, names NOT covered)` — 人名沒擋

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
| `install` 併設定、`doctor` 全綠、隨用隨啟真的把服務拉起來 | 通過（2026-09-15，tmp 設定目錄） |
| macOS LaunchAgent 真的被 launchctl 載入 | **未實測**（測試一律 mock 掉 launchctl） |
| `--engine full` 實際載入 CKIP，`SessionStart` 自動拉起（冷 28 秒／熱 5 秒） | 通過（2026-09-15，隔離 e2e） |
| 中文人名被遮成 `<PERSON_1>`，磁碟與畫面是真名 | 通過（2026-09-15，隔離 e2e） |
| 服務停掉時工具事件維持 fail-closed 且**不會**自行啟動服務 | 通過（2026-09-15，隔離 e2e） |
| `/clear` 之後服務被重新拉起 | 通過（2026-09-15，隔離 e2e） |
| `--harden` 併設定（保留既有 deny）、`doctor --harden` 全綠 | 通過（2026-09-15，tmp 設定目錄） |
| 帶佔位符的 `curl` 被 deny、`grep` 照常還原執行 | 通過（2026-09-15，真實 client） |
| 種子詞 `龍哥` 在 regex 引擎下仍被遮成 `<PERSON_1>` | 通過（2026-09-15，真實 client） |
| 含手機號碼的 prompt 被擋且理由只講類型與數量 | 通過（2026-09-15，真實 client） |
| sandbox 真的擋住裸 `curl`（Seatbelt 回 sandbox_violations） | 通過（2026-09-15，加固 e2e） |
| `cat｜base64` 與 python base64 一行腳本被編碼器規則 deny | 通過（2026-09-15，加固 e2e） |
| 帶佔位符的 `curl` deny；`grep '<TW_MOBILE_1>'` 還原後執行 | 通過（2026-09-15，加固 e2e） |
| `@customers.txt` 的 prompt 被擋；含手機號碼的 prompt 在進模型前被擋 | 通過（2026-09-15，加固 e2e） |
| MCP 工具呼叫 deny 並附 allowlist 提示；`isolation: remote` 的 Agent deny | 通過（2026-09-15，加固 e2e） |
| 種子詞 `龍哥` 在 full 引擎下被遮成 `<PERSON_1>` | 通過（2026-09-15，加固 e2e） |

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

這條限制是 classic hooks 才有的。同一個服務的 Claude Mods 前端
（[`examples/claude-code-mod/`](../claude-code-mod/)，`install --mod`）攔截點跑在
Edit 比對 `old_string` 之前，帶佔位符的 `Edit` 在那邊會正常成功。

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
  **不經過任何工具呼叫**，所以沒有任何 hook 會觸發。你以為 `@secrets.csv` 和
  `Read secrets.csv` 一樣受保護，其實完全沒有。
  **`--harden` 會直接擋掉這種 prompt** 並要你改口說「讀這個檔」。
- **你自己打進去的字**。預設模式不看 prompt；`--harden` 會檢查並擋下含個資的 prompt。
- **Compaction 摘要**。壓縮時模型看的是已經在 context 裡的內容，那些已經是佔位符，
  但摘要本身不再經過 hook。
- **MCP server 的輸出**：預設 matcher 已含 `mcp__.*`，所以輸出**有**走葉節點遮蔽
  （未在真實 MCP 工具上實測）。`--harden` 更進一步，直接 deny 所有 `mcp__*` 呼叫。
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

## 加固模式 `install --harden`

預設安裝擋的是「不小心把個資餵給模型」。`--harden` 再往前一步，堵住幾條
**已經拿到佔位符之後還能把內容送出去**的路。

```bash
uv run pii-guard-hookd install --harden
uv run pii-guard-hookd doctor --harden
```

### 每條規則擋什麼，以及代價

| 規則 | 擋什麼 | 誤擋的代價 |
|------|--------|------------|
| **網路命令不還原** | 帶佔位符的 `curl`／`wget`／`nc`／`ssh`／`scp`／`rsync`／含 URL 的指令，以及 `python -c` 之類含 `urllib`／`socket`／`fetch` 的一行腳本，一律 deny | 要把去識別化後的內容送出去得自己改寫。**沒帶佔位符的 `curl` 完全不受影響**——沒東西要還原就不關這層的事 |
| **編碼器 deny** | `base64`／`base32`／`xxd`／`od`／`hexdump`／`openssl enc`、寫到 stdout 的 `tar czf -`／`gzip -c`，以及含 `b64`／`zlib`／`hexlify` 的一行腳本。**不論有沒有佔位符** | 這是最容易誤擋的一條：正當地讀一個本來就是 base64 的檔案也會被擋。改用 `cat` 看原檔，或把工具加進 `policy.encoders_extra` 的反面——目前只能改用別的指令 |
| **輸出閘門** | 指令輸出含 64 字元以上的 base64 連續串、96 字元以上的 hex 串，或非文字字元超過三成 → 整份輸出扣住 | 憑證、minified bundle 的輸出會被扣住。**SHA-256 不會**（剛好 64 個 hex 字元，已特別放行）；SHA-512 會。用 `policy.output_gate: false` 關掉 |
| **出口工具 deny** | `WebFetch`、`WebSearch`、所有 `mcp__*` | 這期間不能上網查資料。要放行特定 MCP 工具見下 |
| **遠端 agent deny** | `isolation: "remote"` 的 Agent／Workflow | 不能用雲端 sandbox。理由是那台機器上沒有 hook，等於整個防線失效 |
| **prompt 檢查** | `@檔案` 引用（因為它不經過工具呼叫，任何 hook 都看不到）、以及 prompt 本身含個資 | 想引用檔案要改口說「讀這個檔」。`@目錄` 不受影響 |
| **sandbox** | `sandbox.enabled`＋`failIfUnavailable`＋空的 `network.allowedDomains` | 指令連不了外網。這條才是唯一真正兜底的 |

### 放行

編輯 `~/.config/pii-guard/hookd.json` 的 `policy` 區塊（重跑 `install` 不會覆蓋你手改的內容）：

```json
{
  "policy": {
    "allowed_tools": ["mcp__local-db__query"],
    "output_gate": false,
    "encoders_extra": ["mycompany-encode"],
    "network_extra": ["mycompany-upload"],
    "seed_terms_files": ["/path/to/.pii-guard/terms.txt"]
  }
}
```

放行網域改 settings 的 `sandbox.network.allowedDomains`。改完重啟服務
（`stop` 之後下一個 session 會自己拉起來）。

### 種子詞：補偵測抓不到的那一類

`<專案>/.pii-guard/terms.txt` 每行一個值，可選 `TYPE<TAB>值`：

```
# 偵測抓不到的暱稱與內部代號
龍哥
ORG	寶島顧問
TW_MOBILE	0912345678
```

`install` 會自動把它寫進設定。服務啟動時載入，之後這些值**在任何一次工具輸出裡
都會被遮掉**，不需要偵測層認得它們。值本身不會出現在任何回覆裡，SessionStart
只會說「載入 N 個種子詞」。

這一條補的是 recall 的已知弱點：暱稱、非典型英文名、內部代號，NER 模型本來就抓不到。

### 誠實的殘餘風險

**這些規則擋的是機械式的搬運，擋不了改寫。** 模型可以把
`<PERSON_1> 的電話是 <TW_MOBILE_1>` 用自然語言重述成別的樣子，再放進一個
沒被擋的欄位——那不是 base64，沒有連續字元特徵，任何 regex 都看不出來。

**真正兜住這一層的只有 sandbox 的網域白名單。** 規則層負責讓「不小心」和
「順手」變得做不到，sandbox 負責讓「刻意」也出不去。只開 `--harden` 的規則
而把 sandbox 關掉，等於只裝了前者。

**被擋下的 prompt 仍然會寫進本機 transcript。** Claude Code 會在
`~/.claude/projects/` 的 transcript JSONL 裡寫一行
`type: "system", subtype: "informational"`，內容引用了被擋的原始 prompt
（`Original prompt: ...`）。依官方說明那段文字**不會進入模型 context**，
但它確實留在磁碟上。也就是說：擋下來防的是「模型看到」，不是「本機留存」。
要一併處理本機留存，得自己清 transcript。

另外三點：

- 偵測本身有 recall 上限（見上面的引擎表），遮不到的東西這些規則也保護不了。
- 編碼器 deny 是黑名單，列舉不完。`policy.encoders_extra` 存在就是因為這點。
- `Bash` 還原仍然會把真值放進 process list 與 shell history，見上面那一節。

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
  只在你想完全手動設定時才需要；`install` 會自己產生正確的內容。
- `install.sh` — 舊的半手動安裝腳本，`uv run pii-guard-hookd install` 取代了它。
