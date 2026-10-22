# Office xlsx/xlsm 去識別化（移除券商／作者品牌，給 demo 用）

原則：**內容就地中和，不刪 OPC part**。刪 part 要連動改 `[Content_Types].xml` 與多個 `.rels`，極易壞檔；保留 part、清空／中和內容零結構風險，openpyxl 仍能開。

## 逐處掃描的痕跡點

- `xl/media/image*.png`（logo，換同尺寸透明 PNG）、`xl/drawings/drawing1.xml`（圖片 alt text `descr=`）
- `xl/sharedStrings.xml`：品牌名、分析師聯絡行、「X Research estimates」。券商／銀行縮寫（GS、JPM、Nomura…）若是 consensus 覆蓋名單的業務內容，不是識別資訊，不用清
- `docProps/core.xml`（creator／lastModifiedBy）、`docProps/app.xml` 的 `<Company>`（兩個 part 各查）
- `xl/comments*.xml`：`<author>` + 內文第一段嵌入的作者名；`xl/persons/person.xml`（displayName、userId、公司 email）
- `xl/theme/theme1.xml` 主題名；`xl/workbook.xml` definedNames 前綴（孤立未被公式引用可安全改名）
- 治理 metadata 三套：`docMetadata/LabelInfo.xml`（MIP 標籤含 tenant siteId）、`docProps/custom.xml`（分類標籤）、`customXml/item2.xml`（base64 解開含品牌 ns，重編成無品牌）
- `xl/workbook.xml` 的 `<x15ac:absPath url="...">`（最後儲存位置，常是內部 SharePoint URL，洩公司名與團隊名）
- `xl/workbook.xml` 的 `<definedName>` 字面值本身是絕對路徑字串（舊版 MS Query／Access 連結殘留，如 `AccessDatabase`、`HTML_PathFile`），常帶 UNC 主機名與使用者名
- `xl/externalLinks/_rels/externalLink*.xml.rels` 的 `Target`：外部連結真正藏路徑處（`externalLink*.xml` 本體乾淨）。老範本可有 20+ 個帶內部主機名、員工編號風使用者名或真人全名。用正規表達式讀出現有 Target（勿手 key，CJK 易轉譯錯），整批換成 `file:///C:\archive\external-model-NN.<原副檔名>` 佔位；死連結換路徑零風險（Excel 靠 `[N]SheetName!A1` 索引運作）
- `vbaProject.bin`／`customProperty*.bin`：先 `strings | grep` 掃明文，無品牌則保留
- `printerSettings/*.bin`、`calcChain.xml`、`metadata.xml`、`volatileDependencies.xml`、`customXml/item1-3.xml` 以往掃過乾淨，但每個新檔仍要掃一次，不因「上次乾淨」省略

## 驗收

- 對整檔每個 part（text 直掃、binary 走 `strings`）grep 所有品牌／人名／email token，應零殘留
- openpyxl `data_only=False` 比對兩版所有 cell `.value`（ArrayFormula 要拆 `.text`/`.ref` 比，否則物件位址不同產生假陽性）＋ `data_only=True` 比對快取值＋defined_names 數量一致，三者全過才算「0 格商業內容被改動」

## 機密紀律

第三方模型（券商財報模型、同事範本、券商 PDF）一律本機 demo 用，不打包給客戶、不進 git、對外錄影前清痕跡。
