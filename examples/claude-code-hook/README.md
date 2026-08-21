# Claude Code PreToolUse hook（已退役，保留作為參考）

> **這個做法已被 `.agents/skills/pii-safe-documents/` 取代，不再維護。**
> 留在這裡是因為它示範了一種和 skill 完全不同的整合思路，可能對正在設計自己的
> harness 的人有用。要實際使用去識別化功能，請看 repo 根目錄的 README。

## 它想做什麼

在 Claude Code 讀檔的當下攔截，把個資遮掉之後才交給模型——**隱式、自動、不需要使用者知道自己正在被保護**。

```
Claude 要 Read(某檔)
    ↓
PreToolUse[Read] hook 攔截
    ↓
比對副檔名與保護路徑清單
    ↓
用 pii-guard 的 regex-only 引擎遮蔽
    ↓
把遮蔽後的內容交給 Claude
```

## 為什麼退役

**1. 隱式保護會讓人不知道自己有沒有被保護。** hook 靜默失敗（設定檔不存在、路徑寫錯、副檔名不在清單裡）時，模型就直接讀到原文，而使用者以為有防護。這比沒有防護更危險。事實上本專案作者自己機器上的設定就已經指向一個不存在的路徑，等於長期處於「以為有、其實沒有」的狀態——這正是這個設計的失敗模式在真實世界發生了一次。

**2. 只能用 regex，不能用 NER。** hook 卡在每一次讀檔的路徑上，載入 CKIP BERT 模型（500MB、數秒）不可接受，所以它只跑得動 regex。而繁體中文人名與組織名**恰恰是 regex 抓不到的那一類**——也就是說，它擋得住身分證字號，擋不住人名。

**3. 不可逆。** 攔截式遮蔽沒有地方存對照表給後續還原用，模型的回答裡帶著代號也換不回來。

**4. 涵蓋不了其他讀取路徑。** `Read` 只是其中一個工具。`Bash` 裡的 `cat`、subagent、MCP server 都不經過這個 hook。

skill 的做法把這四點反過來：**顯式觸發**（使用者說「幫我去識別化這份檔案」）、**可以用重模型**（一次性成本，不在熱路徑上）、**可逆**（對照表存在私有工作目錄）、**不假裝涵蓋所有路徑**（明文寫出它擋意外不擋惡意）。

## 檔案

- `settings.json` — 專案層級的 hook 註冊。原本放在 repo 的 `.claude/settings.json`。
- `pii-guard-read.sh` — hook 本體。讀 `~/.config/pii-guard/hook-config.json`，**找不到就直接 exit 0**（所以它預設是惰性的，clone 這個 repo 不會讓它動起來）。

設定檔格式：

```json
{
  "enabled": true,
  "project_path": "/絕對路徑/到/pii-guard",
  "protected_paths": [],
  "protected_extensions": [".txt", ".csv", ".tsv", ".log", ".dat"],
  "mapping_dir": "/tmp/pii-guard-hook"
}
```

## 如果你還是想用

把 `settings.json` 的內容併進你的 `.claude/settings.json`，把腳本放到 hook 指令指得到的位置，然後建立上面那個設定檔。

**兩個已知缺陷要先知道**：`settings.json` 裡的指令是相對路徑，只在工作目錄等於 repo 根目錄時找得到腳本；而且它保護不了 `Bash` 讀檔。

真的要在 Claude Code 裡安全處理機密文件，用 skill，不要用這個。
