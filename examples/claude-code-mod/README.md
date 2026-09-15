# pii-guard Mod（Claude Mods 前端）

這個目錄是一個完整的 Claude Code plugin。它做的事情跟 `examples/claude-code-hookd/`
的 classic hooks 一樣——把個資換成佔位符再送進模型、寫回去時還原、擋掉會把內容帶離這台機器的
指令——差別只在它是用 **Claude Mods**（function hooks）實作，因此拿得到 classic hooks 拿不到的
攔截點。

判斷準則跟資料都還在常駐服務 `pii-guard-hookd` 裡。這個 plugin 只是把引擎事件的值搬給服務、
再把服務的回答搬回來，自己不做任何偵測。

## 為什麼要有第二個前端：Edit 缺口

classic hooks 的 `PreToolUse` 在 Edit 自己比對 `old_string` **之後**才跑，所以模型看到
`<TW_MOBILE_1>` 之後拿它去 Edit，一定會撞到 `String to replace not found`。
classic 前端只能在 SessionStart 告訴模型「遇到這種情況改用 Write」。

Mod 的 `tool.call` 跑在 Edit 驗證**之前**，所以佔位符可以在比對前就被換回真值，Edit 直接成功。
這是換前端唯一真正換到的能力，其餘行為兩邊一致。

## 安裝

```bash
uv run pii-guard-hookd install --mod [--harden] [--engine full|regex]
```

install 會把 plugin 連到 Claude Code 設定目錄下一個固定路徑、清掉被 Mod 取代的 classic hook
條目、並印出啟動指令。**Mod 只有帶旗標才會載入**，沒帶就等於沒裝：

```bash
CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1 claude --plugin-dir ~/.claude/plugins/pii-guard
```

檢查安裝：`uv run pii-guard-hookd doctor --mod`（會實際跑 `claude plugin validate`）。
移除：`uv run pii-guard-hookd uninstall`。

### 為什麼 MessageDisplay 還是 classic hook

「使用者看到真值、模型看到佔位符」這件事在 function hook API 裡沒有對應事件，
所以 `--mod` 安裝後 settings 只留 MessageDisplay 一條，其餘全部移掉。
兩邊都留會遮蔽兩次、開場訊息也會出現兩次。

## 涵蓋範圍

| 事件 | 往下（進工具前） | 往上（回模型前） |
|------|------------------|------------------|
| `tool.call` | Write／Edit／MultiEdit／Bash 還原佔位符；WebFetch／WebSearch／`mcp__*`／remote agent 直接拒絕；帶佔位符又能連網的指令拒絕 | Read／Bash／Grep／`mcp__*` 的結果去識別化 |
| `prompt.submit` | `@檔案` 改寫成「請 Read 這個檔」；使用者打字打進去的個資換成佔位符 | — |
| `session.compact` | 壓縮前後都掃一次已知值 | 同左 |
| `session.start` | 向服務要開場說明並載入 seed terms | — |

`prompt.submit` 這條跟 classic 前端不同：classic 只能整則 **擋掉**，Mod 是 **改寫**，
所以正常工作不會被打斷，而且打進去的值會被記住，之後寫回檔案時會還原。

## 兩個實作上最容易踩的地方

**回傳結果時不能把 `ref` 一起帶回去。** `ref` 指的是 core 用**真值**建好的訊息；
把拿到的物件原封不動回傳，core 就會照用那份，你改過的 `result` 會被忽略。
要改結果就只回 `{ result, context }`。

**hook 失敗或超時會被「跳過」，底下的東西照跑，也就是 fail open。** 預算是十秒。
所以每個註冊都掛了 `.catch`，由 handler 自己回安全值；沒掛的話，服務出問題的當下防線就沒了。

## 傳輸方式

plugin 用 `$.fs.read` 讀服務的 state 檔拿 port 與 token，再用 `$.http.fetch` 直接打
`127.0.0.1`。兩者實測都通（見下方 spike）。這樣每次工具呼叫不用另外開一個 Python 行程。
服務位置的解析順序是 `options.hookdHome` → 環境變數 `PII_GUARD_HOOKD_HOME` → 預設值，
沒有寫死路徑。

注意：`$` 上的每個呼叫都是往 host 的 dispatch，**全部都是非同步的**，`$.env.get` 也是。
沒 await 會拿到 Promise，字串化之後變成 `[object Promise]` 塞進路徑裡，
結果是服務明明在跑卻每個事件都 fail closed。`claude plugin validate` 跟 `tsc` 都抓不到這個。

## 已知限制

- **打字打進去的原始 prompt 還是會落到本機 transcript。** `prompt.submit` 的改寫保護的是
  送進模型的內容；Claude Code 會在改寫之前先把使用者輸入原樣記進 `~/.claude/projects/` 的
  `queue-operation` 紀錄。模型看不到，但那個值確實寫進了本機檔案。classic 前端（整則擋掉）
  也有同樣情形。
- **被改寫出來的檔案路徑本身不會去識別化。** 路徑要能讀得到才有意義，所以如果路徑裡就含人名，
  模型會看到。classic 前端的拒絕訊息也會顯示路徑，行為一致。
- **`session.compact` 只掃已知值，不跑偵測。** 整份 transcript 跑一次偵測太慢，而且值在第一次
  經過工具時就該被抓到了。
- **`--plugin-dir` 是目前唯一的載入方式。** 少帶旗標就完全沒有防護，doctor 不會知道你啟動時
  有沒有帶。

## 事前驗證（spike）

改版前先用一個拋棄式 plugin 實測了兩個排序問題，證據在 `~/.claude/projects/` 的 transcript。

**（a）`tool.call` 有沒有跑在 Edit 驗證之前？有。**
檔案內容是 `hello world`，hook 把 Read 結果改成 `hello PLACEHOLDER` 給模型看，
模型據此下 Edit（`old_string: "hello PLACEHOLDER"`），hook 在往下時換回 `hello world`。
Edit 成功，檔案變成 `goodbye everyone`。Edit 缺口確定可以補。

**（b）`prompt.submit` 有沒有跑在 `@檔案` 展開之前？未定論，但設計上已經與順序無關。**
hook 看到的是還沒展開的 `@secret.txt`，改寫也確實生效（模型只看到改寫後的字）。
但對照組顯示 `-p` 模式**根本不會展開 `@` 引用**，所以這個實驗證明不了互動模式下的先後。
因此實作沒有押在任何一邊：先把 `@檔案` 換成 sentinel、再對整段文字做去識別化、最後才把
sentinel 換成路徑。萬一哪天展開跑在前面，被內嵌進來的檔案內容會被當成一般文字去識別化，
而不是整段漏出去。

另外 `claude plugin validate` 會擋下把 `$` 傳給非頂層函式的寫法，所有拿 `$` 的 helper
都必須宣告在檔案最上層。

## 開發

型別宣告是跟著 Claude Code 版本產生的，沒有進版控。要改這個 plugin 先產一份：

```bash
CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1 claude -p "/plugin-types" --model haiku
# 把產生的 .claude/types/claude-code.d.ts 放到 examples/claude-code-mod/types/
```

然後 `claude plugin validate examples/claude-code-mod` 與 `tsc -p examples/claude-code-mod/tsconfig.json`。
