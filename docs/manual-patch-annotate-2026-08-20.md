# pii-safe-documents：新增 `patch` 子指令（人工補標）patch 說明

> ⚠️ **這是一份已被取代的設計提案，保留作為設計理由的紀錄，不是現行實作的說明。**
> 2026-08-20 產出時是「只產 patch、不落檔」交付：目標檔 `pii_safe_workflow.py` 受 sensitive-file 閘門保護，未由該批次寫入。
>
> **後來出貨的不是這個形狀。** 0.2.0 實際提供的是瀏覽器內的人工補標介面（`annotate`），無瀏覽器環境則走 `mask --terms <檔>` 與 `unmask --marker TYPE-N`，另有列出標記與值的 `review`。**現行程式裡沒有 `patch` 子指令。**
>
> **本文所有行號均已失效**：文中行號指的是當時 1673 行的版本，現行檔已逾 2600 行。要對照現行實作請直接讀原始碼，不要用這裡的行號。
>
> 仍有保留價值的是「為什麼這樣設計」那一層——隔離約束怎麼滿足、為什麼走私有 worker 子行程、為什麼用 manifest 的 `original_sha256` 而不是原檔比對、placeholder 型別為什麼不能含連字號、為什麼不重跑 local audit。這些判準在 `annotate` 的實作裡同樣成立。

## 設計摘要（隔離約束怎麼滿足）

詞清單由使用者自己寫成本機檔，主 agent 只傳「路徑」給程式，從頭到尾看不到詞。程式在私有子行程裡跑（stdout/stderr 一律丟棄），結果經 receipt 回到公開層，公開層只搬白名單的整數欄位與 digest，詞、上下文、not-found 名單一律不出現。可還原性靠三件事保住：新詞寫進同一份 mapping、placeholder 沿用既有命名規則、寫回前用 manifest 的 `original_sha256` 重跑 roundtrip，不符就整批拒絕。

---

## 一、設計決策與依據（引用實際行號）

以下行號皆指**未修改前**的 `pii_safe_workflow.py`（全檔 1673 行）。

| 決策 | 依據 |
|------|------|
| 子指令名用 `patch` | 既有三個公開子指令 `redact` / `restore` / `purge`（1595、1601、1606 行）皆為單一動詞小寫，`patch` 同構。不用 `sweep`（易與內部 `_sweep_remaining_occurrences` 混淆）、不用 `add-terms`（既有無連字號子指令） |
| 走私有 worker 子行程，不在主行程直接做 | `_run_private_worker`（340-376 行）刻意丟棄兩條輸出流（363 行註解：dependencies can echo source text）。補標詞就是漏網個資，同樣不該有任何流到主 agent 的管道。這是結構性保證，不靠「記得別 print」 |
| 完整性檢查用 manifest 的 `original_sha256` | redact worker 在 1248-1252 行保證 `_replace_all(redacted, mapping) == original`，並在 1276 行把 `original_sha256` 寫進 manifest。原檔快照在 1292-1293 行已被刪除，所以 patch 時**無法**比對原檔，但可比對 digest——等價強度，且不需要原檔存在 |
| patch 前先驗 job 自洽 | 若 job 已被外部改動，patch 後的失敗將無法歸因。先驗一次（`JOB_STATE_MISMATCH`），失敗即停 |
| placeholder 型別用 `MANUAL_TERM` | 既有型別皆為大寫底線（`AUDIT_{TYPE}`、`SHIELD_{TYPE}`、`ADDRESS_SUFFIX`、`LABELED_ID`、`URL_HANDLE`、`PERSON_ALIAS`）。注意 `_parse_entity_type_from_namespaced`（507-509 行）的 regex 是 `\[\[PII-[^-]+-(.+)-\d+\]\]`，型別名**不可含連字號**，故用底線 |
| 續號掃既有 mapping | 仿 `_redact_casefold_person_aliases`（638-648 行）的 `existing_counters` 寫法，讓多次 patch 不會撞號 |
| 套用前先 shield 既有 placeholder | 使用者若寫了 `PERSON`、`PII` 之類的詞，直接 `str.replace` 會切壞既有 placeholder。用既有 `_protect_literals`（379-392 行），與 redact worker 1094-1101 行護 literal placeholder 的手法完全一致 |
| 長詞優先 | 同 `_sweep_remaining_occurrences`（444 行）的理由：短詞是長詞子字串時，不得先吃掉長詞的出現位置 |
| 寫回用 `os.replace` 不用 unlink + write | `_private_write`（110-134 行）以 `os.link` 建檔，遇既有檔會 `FileExistsError`。先寫 staging 檔（0600）再 `os.replace` 是原子的，且保留權限與 `st_nlink == 1`（`_assert_private_file` 在 173 行檢查這點） |
| 不重跑 local audit | 補標只增加遮蔽、不減少，redact 當初已通過 audit（manifest `local_audit: passed`）。重跑一次完整 audit 在 64 KiB 文件上是數十分鐘量級（1451-1456 行註解），代價與收益不成比例。故 `integrity` 只涵蓋 roundtrip / leakage / marker 一致性三項，**不宣稱重新通過模型稽核** |

**本 patch 不修改任何既有函式**。新增內容為：1 個常數、2 個純函式、1 個 worker、1 個公開函式、parser 3 處插入、dispatch 2 處插入。

---

## 二、新增常數

插在**第 39 行**（`REDACTED_NAME: Final[str] = "redacted.txt"`）之後、第 40 行（`MAX_INPUT_BYTES`）之前。

原文上下文：

```python
REDACTED_NAME: Final[str] = "redacted.txt"          # ← 第 39 行
MAX_INPUT_BYTES: Final[int] = 64 * 1024             # ← 第 40 行
```

插入：

```python
# Entity type for terms the user marked by hand. Underscore, not hyphen:
# _parse_entity_type_from_namespaced splits on hyphens, so a hyphenated type
# name would be parsed back wrongly.
MANUAL_TERM_TYPE: Final[str] = "MANUAL_TERM"
```

---

## 三、新增純函式（兩個）

插在**第 448 行**（`_sweep_remaining_occurrences` 的 `return output`）之後、第 451 行（`def _parse_entity_type`）之前。原文上下文：

```python
        if value and value in output:
            output = output.replace(value, placeholder)
    return output                                    # ← 第 448 行
                                                     # ← 第 449 行（空行）
                                                     # ← 第 450 行（空行）
def _parse_entity_type(placeholder: str) -> str:     # ← 第 451 行
```

插入：

```python
def _parse_patch_terms(raw: str) -> list[str]:
    """Read a user-authored term list without ever echoing its contents.

    Blank lines and '#' comments are dropped so the user can annotate the file
    while working through a redacted copy by eye. Duplicates collapse silently:
    marking the same name twice is a natural way to write such a list, not an
    error worth reporting back.

    A term that looks like a placeholder is refused outright. Patching one in
    would make the mapping self-referential -- the placeholder would restore to
    a string containing a placeholder -- and restoration would stop being
    single-pass exact.
    """

    terms: list[str] = []
    seen: set[str] = set()
    for line in raw.splitlines():
        term = line.strip()
        if not term or term.startswith("#"):
            continue
        if "[[PII-" in term or PLACEHOLDER_PATTERN.search(term):
            raise SafeFailure(
                "INVALID_PATCH_TERMS",
                "A term list entry looks like a redaction placeholder.",
            )
        if term in seen:
            continue
        seen.add(term)
        terms.append(term)
    if not terms:
        raise SafeFailure(
            "EMPTY_PATCH_TERMS", "The term list contained no usable terms."
        )
    return terms


def _apply_patch_terms(
    redacted: str, terms: list[str], job_id: str, start_index: int
) -> tuple[str, dict[str, str], dict[str, int]]:
    """Redact every occurrence of each user-supplied term under a new placeholder.

    Longest term first, for the same reason _sweep_remaining_occurrences sorts
    that way: a shorter term that is a substring of a longer one must not
    consume the longer one's occurrences.

    One placeholder per term regardless of occurrence count, which is what keeps
    restoration exact -- restoration maps one placeholder to one value.

    Counts come back, terms do not. Every caller above this point emits numbers
    only, so a term that was not found is a number here and stays a number all
    the way out.
    """

    output = redacted
    additions: dict[str, str] = {}
    counter = start_index
    applied = 0
    occurrences = 0
    for term in sorted(terms, key=len, reverse=True):
        found = output.count(term)
        if not found:
            continue
        counter += 1
        placeholder = f"[[PII-{job_id[:10]}-{MANUAL_TERM_TYPE}-{counter}]]"
        output = output.replace(term, placeholder)
        additions[placeholder] = term
        applied += 1
        occurrences += found
    return (
        output,
        additions,
        {
            "terms_read": len(terms),
            "terms_applied": applied,
            "terms_not_found": len(terms) - applied,
            "occurrences_redacted": occurrences,
        },
    )
```

---

## 四、新增 `_patch_worker`

插在**第 1410 行**（`_restore_worker` 的最後一行 `raise`）之後、第 1413 行（`def _public_redact`）之前。原文上下文：

```python
    except Exception:
        if output_created:
            output.unlink(missing_ok=True)
        raise                                        # ← 第 1410 行
                                                     # ← 第 1411 行（空行）
                                                     # ← 第 1412 行（空行）
def _public_redact(args: argparse.Namespace) -> None:  # ← 第 1413 行
```

插入：

```python
def _patch_worker(args: argparse.Namespace) -> None:
    job_dir = Path(args.job_dir)
    terms_path = Path(args.terms)
    if (
        job_dir.name != args.job_id
        or terms_path.parent.resolve() != job_dir.resolve()
        or not terms_path.name.startswith(".patch-terms-")
    ):
        raise SafeFailure(
            "INVALID_WORKER_PATH",
            "Private patch worker received an invalid snapshot path.",
        )
    receipt_path = Path(args.receipt_path).resolve()
    if receipt_path.parent != job_dir.resolve() or receipt_path.exists():
        raise SafeFailure("PATCH_CHECK_FAILED", "Patch receipt path is invalid.")

    redacted_path = job_dir / REDACTED_NAME
    mapping_path = job_dir / PRIVATE_MAP_NAME
    manifest_path = job_dir / MANIFEST_NAME
    for artifact in (redacted_path, mapping_path, manifest_path):
        _assert_private_file(artifact)

    redacted = _read_utf8(redacted_path)
    mapping_data = json.loads(_read_utf8(mapping_path))
    if not isinstance(mapping_data, dict) or not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in mapping_data.items()
    ):
        raise SafeFailure("INVALID_MAPPING", "Private mapping is invalid.")
    mapping: dict[str, str] = dict(mapping_data)
    manifest = json.loads(_read_utf8(manifest_path))
    if (
        not isinstance(manifest, dict)
        or manifest.get("kind") != "pii-safe-documents-private-job"
        or manifest.get("job_id") != args.job_id
        or any(
            not placeholder.startswith(f"[[PII-{args.job_id[:10]}-")
            for placeholder in mapping
        )
    ):
        raise SafeFailure("INVALID_MANIFEST", "Private job identity is invalid.")
    original_sha256 = manifest.get("original_sha256")
    if not isinstance(original_sha256, str) or not re.fullmatch(
        r"[0-9a-f]{64}", original_sha256
    ):
        raise SafeFailure("INVALID_MANIFEST", "Private job digest is invalid.")
    literal_counts = manifest.get("literal_placeholder_counts")
    if not isinstance(literal_counts, dict) or not all(
        isinstance(key, str) and isinstance(value, int)
        for key, value in literal_counts.items()
    ):
        raise SafeFailure(
            "INVALID_MANIFEST", "Private literal-placeholder state is invalid."
        )

    # The job has to be self-consistent before it is touched. Without this, a
    # roundtrip failure after patching could equally well mean the job was
    # already broken, and there would be no way to tell the two apart.
    if (
        hashlib.sha256(_replace_all(redacted, mapping).encode("utf-8")).hexdigest()
        != original_sha256
    ):
        raise SafeFailure(
            "JOB_STATE_MISMATCH",
            "The stored redacted copy no longer reproduces its original digest.",
        )

    terms = _parse_patch_terms(_read_utf8(terms_path))
    # Shield every existing marker before touching the text. A user-supplied
    # term like "PERSON" or "PII" would otherwise cut an existing placeholder in
    # half, which breaks both the document and its restoration.
    protected, placeholder_tokens = _protect_literals(
        redacted,
        [*mapping, *literal_counts],
        f"PATCH{args.job_id[:8]}",
    )
    existing_counters = [
        int(match.group(1))
        for placeholder in mapping
        if (
            match := re.fullmatch(
                rf"\[\[PII-{re.escape(args.job_id[:10])}-"
                rf"{MANUAL_TERM_TYPE}-(\d+)\]\]",
                placeholder,
            )
        )
    ]
    patched, additions, counts = _apply_patch_terms(
        protected, terms, args.job_id, max(existing_counters, default=0)
    )
    patched = _replace_all(patched, placeholder_tokens)
    mapping.update(additions)

    leaked_known_values = [
        value for value in mapping.values() if value and value in patched
    ]
    if leaked_known_values:
        raise SafeFailure("LEAKAGE_CHECK_FAILED", "A local leakage check failed.")
    if any(patched.count(placeholder) == 0 for placeholder in mapping):
        raise SafeFailure(
            "INVALID_MAPPING",
            "A private mapping entry has no corresponding redaction marker.",
        )
    generated_markers = set(NAMESPACED_PATTERN.findall(patched)) - set(literal_counts)
    if generated_markers != set(mapping):
        raise SafeFailure(
            "INVALID_MAPPING",
            "Final redaction markers and private mapping do not match.",
        )
    patched_digest = hashlib.sha256(patched.encode("utf-8")).hexdigest()
    if (
        hashlib.sha256(_replace_all(patched, mapping).encode("utf-8")).hexdigest()
        != original_sha256
    ):
        raise SafeFailure(
            "PATCH_ROUNDTRIP_FAILED",
            "The patched copy no longer restores to the original document.",
        )

    entity_counts: dict[str, int] = {}
    for placeholder in mapping:
        match = re.fullmatch(r"\[\[PII-[^-]+-(.+)-\d+\]\]", placeholder)
        entity_type = match.group(1) if match else "OTHER"
        entity_counts[entity_type] = entity_counts.get(entity_type, 0) + 1
    updated_manifest = {
        **manifest,
        "replacement_count": len(mapping),
        "entity_counts": entity_counts,
        "redacted_sha256": patched_digest,
        "placeholder_counts": {
            placeholder: patched.count(placeholder) for placeholder in mapping
        },
        "placeholder_sequence": [
            placeholder
            for placeholder in NAMESPACED_PATTERN.findall(patched)
            if placeholder in mapping
        ],
        "manual_patch_rounds": int(manifest.get("manual_patch_rounds", 0)) + 1,
    }

    # Stage all three artifacts first, then swap them in. os.replace is atomic
    # per file and preserves the 0600 staging mode, so a crash mid-swap leaves a
    # job that fails the self-consistency check above on the next run rather
    # than one that silently restores to the wrong text.
    suffix = uuid.uuid4().hex
    staged_redacted = job_dir / f".patched-{suffix}.private.txt"
    staged_mapping = job_dir / f".patched-map-{suffix}.private.json"
    staged_manifest = job_dir / f".patched-manifest-{suffix}.safe.json"
    try:
        _private_write(staged_redacted, patched)
        _private_write(
            staged_mapping, json.dumps(mapping, ensure_ascii=False, sort_keys=True)
        )
        _private_write(staged_manifest, json.dumps(updated_manifest, sort_keys=True))
        os.replace(staged_redacted, redacted_path)
        os.replace(staged_mapping, mapping_path)
        os.replace(staged_manifest, manifest_path)
    except Exception:
        for staged in (staged_redacted, staged_mapping, staged_manifest):
            staged.unlink(missing_ok=True)
        raise

    for artifact in (redacted_path, mapping_path, manifest_path):
        _assert_private_file(artifact)
    if _sha256(redacted_path) != patched_digest:
        raise SafeFailure(
            "PATCH_CHECK_FAILED", "The patched copy failed its readback check."
        )

    _private_write(
        receipt_path,
        json.dumps(
            {
                **counts,
                "replacement_count": len(mapping),
                "redacted_sha256": patched_digest,
                "integrity": "passed",
            },
            sort_keys=True,
        ),
    )
```

---

## 五、新增 `_public_patch`

插在**第 1588 行**（`_public_purge` 的 `_emit(...)`）之後、第 1591 行（`def _build_parser`）之前。原文上下文：

```python
    shutil.rmtree(job_dir)
    _emit({"ok": True, "job_id": args.job_id, "purged": True})   # ← 第 1588 行
                                                                 # ← 第 1589 行（空行）
                                                                 # ← 第 1590 行（空行）
def _build_parser() -> argparse.ArgumentParser:                  # ← 第 1591 行
```

插入：

```python
def _public_patch(args: argparse.Namespace) -> None:
    root = _prepare_jobs_root(_default_jobs_root())
    job_dir = _resolve_job_dir(root, args.job_id)
    validated_terms = _validate_input(Path(args.terms_file))
    suffix = uuid.uuid4().hex
    terms_snapshot = job_dir / f".patch-terms-{suffix}.private.txt"
    receipt_path = job_dir / f".patch-receipt-{suffix}.safe.json"
    _snapshot_input(
        validated_terms.path,
        terms_snapshot,
        expected_device=validated_terms.device,
        expected_inode=validated_terms.inode,
    )
    try:
        _run_private_worker(
            [
                "patch",
                "--terms",
                str(terms_snapshot),
                "--job-dir",
                str(job_dir),
                "--job-id",
                args.job_id,
                "--receipt-path",
                str(receipt_path),
            ],
            status_path=job_dir / ".worker.safe.json",
            # Pure string work on a file already bounded to MAX_INPUT_BYTES.
            timeout=120,
        )
        receipt = json.loads(_read_utf8(receipt_path))
        # The public layer re-derives what it will print rather than forwarding
        # the receipt. A field the worker adds later cannot become main-agent
        # output by accident; only these five integers and one digest can.
        numeric_fields = (
            "terms_read",
            "terms_applied",
            "terms_not_found",
            "occurrences_redacted",
            "replacement_count",
        )
        if not isinstance(receipt, dict) or any(
            not isinstance(receipt.get(field), int)
            or isinstance(receipt.get(field), bool)
            for field in numeric_fields
        ):
            raise SafeFailure("PATCH_CHECK_FAILED", "Patch receipt is invalid.")
        if receipt.get("integrity") != "passed":
            raise SafeFailure(
                "PATCH_CHECK_FAILED", "Patch integrity was not confirmed."
            )
        digest = receipt.get("redacted_sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise SafeFailure(
                "PATCH_CHECK_FAILED", "Patch receipt digest is invalid."
            )
        counts = {field: receipt[field] for field in numeric_fields}
    finally:
        terms_snapshot.unlink(missing_ok=True)
        receipt_path.unlink(missing_ok=True)
    _emit(
        {
            "ok": True,
            "agent_may_read_redacted": True,
            "job_id": args.job_id,
            "redacted_path": str(job_dir / REDACTED_NAME),
            **counts,
            "integrity": "passed",
            "redacted_sha256": digest,
            "message": (
                "Manual terms were applied by count only; no term text is reported."
            ),
        }
    )
```

---

## 六、`_build_parser()` 插入（兩處）

### 6a. 公開子指令

插在**第 1607 行**之後、第 1609 行之前。原文上下文：

```python
    purge = subparsers.add_parser("purge")           # ← 第 1606 行
    purge.add_argument("--job-id", required=True)    # ← 第 1607 行
                                                     # ← 第 1608 行（空行）
    worker = subparsers.add_parser("_worker", help=argparse.SUPPRESS)  # ← 第 1609 行
```

插入（含前置空行）：

```python

    patch = subparsers.add_parser("patch")
    patch.add_argument("--job-id", required=True)
    patch.add_argument("--terms-file", required=True)
```

`--terms-file` 對應 `args.terms_file`（argparse 自動把連字號轉底線）。

### 6b. worker 子指令

插在**第 1626 行**之後、第 1627 行（`return parser`）之前。原文上下文：

```python
    worker_restore.add_argument("--receipt-path", required=True)  # ← 第 1625 行
    worker_restore.add_argument("--status-path", required=True)   # ← 第 1626 行
    return parser                                                 # ← 第 1627 行
```

插入：

```python
    worker_patch = worker_subparsers.add_parser("patch")
    worker_patch.add_argument("--terms", required=True)
    worker_patch.add_argument("--job-dir", required=True)
    worker_patch.add_argument("--job-id", required=True)
    worker_patch.add_argument("--receipt-path", required=True)
    worker_patch.add_argument("--status-path", required=True)
```

---

## 七、`main()` dispatch 插入（兩處）

### 7a. 公開分派

插在**第 1639 行**之後、第 1640 行之前。原文上下文：

```python
        if args.command == "purge":                  # ← 第 1638 行
            _public_purge(args)                      # ← 第 1639 行
        if args.command == "_worker" and args.worker_command == "redact":  # ← 第 1640 行
```

插入：

```python
        if args.command == "patch":
            _public_patch(args)
```

沿用既有風格：公開分派後不 `return`，因為 `_public_patch` 必定以 `_emit`（`SystemExit`）收尾。

### 7b. worker 分派

插在**第 1645 行**之後、第 1646 行之前。原文上下文：

```python
        if args.command == "_worker" and args.worker_command == "restore":  # ← 第 1643 行
            _restore_worker(args)                    # ← 第 1644 行
            return                                   # ← 第 1645 行
        raise SafeFailure("INVALID_COMMAND", "Unsupported command.")  # ← 第 1646 行
```

插入：

```python
        if args.command == "_worker" and args.worker_command == "patch":
            _patch_worker(args)
            return
```

`main()` 第 1647-1653 行的 `except SafeFailure` 分支會把 worker 失敗寫進 `--status-path`，patch worker 已宣告該旗標，無須改動。

---

## 八、既有函式改動

**無**。本 patch 不修改任何既有函式或既有測試。

理由：mapping 寫回沿用 `_private_write` + `os.replace`，roundtrip 沿用 `_replace_all`，還原路徑（`_restore_worker`，1296-1410 行）讀的是同一份 mapping 與 manifest，補標後的 placeholder 在格式、命名空間、manifest 三處欄位（`placeholder_counts` / `placeholder_sequence` / `literal_placeholder_counts`）上與原有 placeholder 完全同構，restore 的四項一致性檢查（1351-1360 行）自然涵蓋新詞。

---

## 九、新增測試

追加在測試檔 `tests/test_pii_safe_workflow.py` 的 `ChineseCorpusRegressionTests` 之後、第 700 行 `if __name__ == "__main__":` 之前。

```python
class ManualPatchTests(unittest.TestCase):
    """Manual patch pass: the user marks leftovers, the wrapper counts them.

    The point of these tests is not only that patching works, but that nothing
    on the way out carries the terms themselves.
    """

    JOB_ID = "deadbeef00deadbeef00deadbeef00"

    def _make_job(
        self,
        root: Path,
        redacted_text: str,
        mapping: dict[str, str],
        literal_counts: dict[str, int] | None = None,
    ) -> Path:
        job_dir = root / self.JOB_ID
        job_dir.mkdir()
        original = WORKFLOW._replace_all(redacted_text, mapping)
        WORKFLOW._private_write(
            job_dir / WORKFLOW.REDACTED_NAME, redacted_text
        )
        WORKFLOW._private_write(
            job_dir / WORKFLOW.PRIVATE_MAP_NAME,
            json.dumps(mapping, ensure_ascii=False, sort_keys=True),
        )
        WORKFLOW._private_write(
            job_dir / WORKFLOW.MANIFEST_NAME,
            json.dumps(
                {
                    "kind": "pii-safe-documents-private-job",
                    "job_id": self.JOB_ID,
                    "original_path": str(job_dir / "original.txt"),
                    "original_sha256": hashlib.sha256(
                        original.encode("utf-8")
                    ).hexdigest(),
                    "redacted_sha256": hashlib.sha256(
                        redacted_text.encode("utf-8")
                    ).hexdigest(),
                    "replacement_count": len(mapping),
                    "entity_counts": {},
                    "placeholder_counts": {
                        placeholder: redacted_text.count(placeholder)
                        for placeholder in mapping
                    },
                    "placeholder_sequence": [
                        placeholder
                        for placeholder in WORKFLOW.NAMESPACED_PATTERN.findall(
                            redacted_text
                        )
                        if placeholder in mapping
                    ],
                    "literal_placeholder_counts": literal_counts or {},
                },
                sort_keys=True,
            ),
        )
        return job_dir

    def _run_patch(self, job_dir: Path, term_lines: str) -> dict[str, object]:
        terms_path = job_dir / ".patch-terms-test.private.txt"
        WORKFLOW._private_write(terms_path, term_lines)
        receipt_path = job_dir / ".patch-receipt-test.safe.json"
        WORKFLOW._patch_worker(
            Namespace(
                job_dir=str(job_dir),
                job_id=self.JOB_ID,
                terms=str(terms_path),
                receipt_path=str(receipt_path),
            )
        )
        return json.loads(receipt_path.read_text(encoding="utf-8"))

    def test_every_occurrence_is_redacted_and_still_restores(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            person = f"[[PII-{self.JOB_ID[:10]}-PERSON-1]]"
            job_dir = self._make_job(
                Path(directory),
                f"被告{person}到庭。證人林淑芬在場，林淑芬否認。",
                {person: "王大明"},
            )
            original = "被告王大明到庭。證人林淑芬在場，林淑芬否認。"
            receipt = self._run_patch(job_dir, "林淑芬\n")

            patched = (job_dir / WORKFLOW.REDACTED_NAME).read_text(encoding="utf-8")
            mapping = json.loads(
                (job_dir / WORKFLOW.PRIVATE_MAP_NAME).read_text(encoding="utf-8")
            )
            self.assertNotIn("林淑芬", patched)
            self.assertEqual(receipt["terms_applied"], 1)
            self.assertEqual(receipt["occurrences_redacted"], 2)
            self.assertEqual(receipt["terms_not_found"], 0)
            self.assertEqual(receipt["integrity"], "passed")
            self.assertEqual(WORKFLOW._replace_all(patched, mapping), original)

    def test_a_term_that_is_absent_is_only_a_number(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            person = f"[[PII-{self.JOB_ID[:10]}-PERSON-1]]"
            job_dir = self._make_job(
                Path(directory), f"被告{person}到庭。", {person: "王大明"}
            )
            receipt = self._run_patch(job_dir, "查無此人\n")
            self.assertEqual(receipt["terms_read"], 1)
            self.assertEqual(receipt["terms_applied"], 0)
            self.assertEqual(receipt["terms_not_found"], 1)
            self.assertEqual(receipt["occurrences_redacted"], 0)

    def test_receipt_never_carries_the_terms(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            person = f"[[PII-{self.JOB_ID[:10]}-PERSON-1]]"
            job_dir = self._make_job(
                Path(directory),
                f"被告{person}到庭。證人林淑芬在場。",
                {person: "王大明"},
            )
            receipt_path = job_dir / ".patch-receipt-test.safe.json"
            self._run_patch(job_dir, "林淑芬\n查無此人\n")
            raw_receipt = receipt_path.read_text(encoding="utf-8")
            self.assertNotIn("林淑芬", raw_receipt)
            self.assertNotIn("查無此人", raw_receipt)
            receipt = json.loads(raw_receipt)
            for field in (
                "terms_read",
                "terms_applied",
                "terms_not_found",
                "occurrences_redacted",
                "replacement_count",
            ):
                self.assertIsInstance(receipt[field], int)
            self.assertEqual(
                set(receipt) - {"integrity", "redacted_sha256"},
                {
                    "terms_read",
                    "terms_applied",
                    "terms_not_found",
                    "occurrences_redacted",
                    "replacement_count",
                },
            )

    def test_comments_and_blank_lines_are_ignored(self) -> None:
        terms = WORKFLOW._parse_patch_terms(
            "# 這行是註解\n\n  林淑芬  \n\n# 另一則註解\n李真\n林淑芬\n"
        )
        self.assertEqual(terms, ["林淑芬", "李真"])

    def test_placeholder_like_term_is_refused(self) -> None:
        for value in ("[[PII-deadbeef00-PERSON-1]]", "<PERSON_1>"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    WORKFLOW.SafeFailure, "INVALID_PATCH_TERMS"
                ):
                    WORKFLOW._parse_patch_terms(f"林淑芬\n{value}\n")

    def test_an_empty_list_is_refused(self) -> None:
        with self.assertRaisesRegex(WORKFLOW.SafeFailure, "EMPTY_PATCH_TERMS"):
            WORKFLOW._parse_patch_terms("# 全部都是註解\n\n")

    def test_a_term_matching_placeholder_text_cannot_corrupt_markers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            person = f"[[PII-{self.JOB_ID[:10]}-PERSON-1]]"
            job_dir = self._make_job(
                Path(directory), f"被告{person}到庭，PERSON 一詞另有他解。",
                {person: "王大明"},
            )
            receipt = self._run_patch(job_dir, "PERSON\n")
            patched = (job_dir / WORKFLOW.REDACTED_NAME).read_text(encoding="utf-8")
            mapping = json.loads(
                (job_dir / WORKFLOW.PRIVATE_MAP_NAME).read_text(encoding="utf-8")
            )
            self.assertIn(person, patched)
            self.assertEqual(receipt["occurrences_redacted"], 1)
            self.assertEqual(
                WORKFLOW._replace_all(patched, mapping),
                "被告王大明到庭，PERSON 一詞另有他解。",
            )

    def test_longer_term_wins_over_its_own_substring(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            person = f"[[PII-{self.JOB_ID[:10]}-PERSON-1]]"
            job_dir = self._make_job(
                Path(directory), f"{person} 地址為新竹市中正路一段", {person: "王大明"}
            )
            self._run_patch(job_dir, "中正路\n新竹市中正路\n")
            patched = (job_dir / WORKFLOW.REDACTED_NAME).read_text(encoding="utf-8")
            mapping = json.loads(
                (job_dir / WORKFLOW.PRIVATE_MAP_NAME).read_text(encoding="utf-8")
            )
            self.assertNotIn("中正路", patched)
            self.assertEqual(
                WORKFLOW._replace_all(patched, mapping),
                "王大明 地址為新竹市中正路一段",
            )

    def test_patched_job_still_restores_through_the_restore_worker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            outer = Path(directory)
            person = f"[[PII-{self.JOB_ID[:10]}-PERSON-1]]"
            job_dir = self._make_job(
                outer, f"被告{person}到庭。證人林淑芬在場。", {person: "王大明"}
            )
            original = "被告王大明到庭。證人林淑芬在場。"
            self._run_patch(job_dir, "林淑芬\n")

            edited = job_dir / "edited.txt"
            edited.write_text(
                (job_dir / WORKFLOW.REDACTED_NAME).read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            output = job_dir / ".restore-output-patched.private.txt"
            WORKFLOW._restore_worker(
                Namespace(
                    job_dir=str(job_dir),
                    job_id=self.JOB_ID,
                    input=str(edited),
                    output=str(output),
                    receipt_path=str(job_dir / ".restore-receipt-patched.safe.json"),
                )
            )
            self.assertEqual(output.read_text(encoding="utf-8"), original)

    def test_two_patch_rounds_do_not_reuse_a_placeholder_number(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            person = f"[[PII-{self.JOB_ID[:10]}-PERSON-1]]"
            job_dir = self._make_job(
                Path(directory),
                f"被告{person}到庭。證人林淑芬與李真在場。",
                {person: "王大明"},
            )
            original = "被告王大明到庭。證人林淑芬與李真在場。"
            self._run_patch(job_dir, "林淑芬\n")
            (job_dir / ".patch-terms-test.private.txt").unlink()
            (job_dir / ".patch-receipt-test.safe.json").unlink()
            self._run_patch(job_dir, "李真\n")

            patched = (job_dir / WORKFLOW.REDACTED_NAME).read_text(encoding="utf-8")
            mapping = json.loads(
                (job_dir / WORKFLOW.PRIVATE_MAP_NAME).read_text(encoding="utf-8")
            )
            manual = [
                key
                for key in mapping
                if WORKFLOW.MANUAL_TERM_TYPE in key
            ]
            self.assertEqual(len(manual), 2)
            self.assertEqual(len(set(manual)), 2)
            self.assertEqual(WORKFLOW._replace_all(patched, mapping), original)

    def test_a_tampered_job_is_refused_before_patching(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            person = f"[[PII-{self.JOB_ID[:10]}-PERSON-1]]"
            job_dir = self._make_job(
                Path(directory), f"被告{person}到庭。林淑芬在場。", {person: "王大明"}
            )
            manifest_path = job_dir / WORKFLOW.MANIFEST_NAME
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["original_sha256"] = "0" * 64
            manifest_path.unlink()
            WORKFLOW._private_write(
                manifest_path, json.dumps(manifest, sort_keys=True)
            )
            with self.assertRaisesRegex(
                WORKFLOW.SafeFailure, "JOB_STATE_MISMATCH"
            ):
                self._run_patch(job_dir, "林淑芬\n")

    def test_worker_refuses_a_terms_path_outside_the_job(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            outer = Path(directory)
            person = f"[[PII-{self.JOB_ID[:10]}-PERSON-1]]"
            job_dir = self._make_job(outer, f"被告{person}到庭。", {person: "王大明"})
            stray = outer / ".patch-terms-stray.private.txt"
            WORKFLOW._private_write(stray, "林淑芬\n")
            with self.assertRaisesRegex(
                WORKFLOW.SafeFailure, "INVALID_WORKER_PATH"
            ):
                WORKFLOW._patch_worker(
                    Namespace(
                        job_dir=str(job_dir),
                        job_id=self.JOB_ID,
                        terms=str(stray),
                        receipt_path=str(job_dir / ".patch-receipt-x.safe.json"),
                    )
                )
```

測試涵蓋任務要求的五項（正常補標、詞不存在、註解與空行、補標後 restore 完整還原、輸出不含詞本身），另加五項邊界（placeholder 文字誤傷、長短詞覆蓋、續號、job 竄改、路徑逃逸）。

---

## 十、人工套用步驟

1. **插入程式碼（由檔尾往檔頭做，避免行號位移）**，順序：
   - 第 1645 行後 → 七-7b（worker dispatch）
   - 第 1639 行後 → 七-7a（公開 dispatch）
   - 第 1626 行後 → 六-6b（worker subparser）
   - 第 1607 行後 → 六-6a（公開 subparser）
   - 第 1588 行後 → 五（`_public_patch`）
   - 第 1410 行後 → 四（`_patch_worker`）
   - 第 448 行後 → 三（兩個純函式）
   - 第 39 行後 → 二（`MANUAL_TERM_TYPE`）

2. **追加測試**：把第九節整個 class 貼進 `tests/test_pii_safe_workflow.py` 的第 699 行之後、第 700 行 `if __name__ == "__main__":` 之前。

3. **驗證**：

```bash
cd ~/.claude/skills/pii-safe-documents
python3 -m unittest tests.test_pii_safe_workflow -v
```

全綠即可。要單跑新增這批：

```bash
python3 -m unittest tests.test_pii_safe_workflow.ManualPatchTests -v
```

---

## 十一、使用方式（給 SKILL.md 的補充草稿，本次未寫入）

建議在 SKILL.md 的「### 3. Work only on the redacted copy」之後、「### 4. Restore」之前插入一節：

> ### 3b. 人工補標漏遮的詞（選用）
>
> 自動偵測不會抓乾淨。使用者肉眼掃過 `redacted_path` 之後，若發現還有裸露的個資，請**自行**建立一份純文字詞清單（`.txt`，UTF-8，每行一個詞，空行與 `#` 開頭的註解會被忽略），然後執行：
>
> ```bash
> python3 <skill-dir>/scripts/pii_safe_workflow.py patch \
>   --job-id "<job_id from receipt>" \
>   --terms-file "/absolute/path/to/terms.txt"
> ```
>
> 主 agent **不得**讀取、開啟、預覽或協助撰寫這份詞清單，也不得詢問清單內容。它只負責代跑指令並轉述回傳的數字。
>
> 回傳只有數字與狀態：`terms_read`、`terms_applied`、`terms_not_found`、`occurrences_redacted`、`replacement_count`、`integrity`、`redacted_sha256`。`terms_not_found` 是數字，不會列出是哪些詞——若不為 0，請自行檢查是否有錯字、全半形差異，或該詞已被先前的長詞吸收。
>
> 補標會就地更新 job 的 redacted 檔與 mapping，restore 仍可完整還原。補標可重複執行多次。完成後請自行刪除詞清單檔——它就是漏網的個資本身。
>
> 補標只重跑完整性檢查（roundtrip、洩漏、標記一致性），**不重跑本地模型稽核**。補標只增加遮蔽、不減少，所以既有的 `agent_may_read_redacted` 結論仍然成立。
>
> 反方向的「把遮過頭的組織名放回來」不在此指令範圍。純文字檔操作那一半較痛苦，之後若要做介面，先做那邊。

---

## 十二、已知取捨（要讓 Dustin 知道的）

1. **單字元詞不擋**。`_drop_degenerate_detections`（401-424 行）會把單字元的自動偵測結果撤回，理由是單字元無法識別自然人。人工補標**不套用**這條限制——使用者明確指定的就照做。代價是補一個「大」字會把全文的「大」都遮掉，`occurrences_redacted` 的數字會明顯異常，使用者看得出來。
2. **三個檔的 `os.replace` 不是整體原子**。中途崩潰會留下半新半舊的 job，但下次 patch 的 `JOB_STATE_MISMATCH` 前置檢查會抓到，restore 的 placeholder 一致性檢查（1351-1360 行）也會抓到，不會靜默還原成錯的文本。
3. **詞清單檔本身是敏感資料**。程式只讀不刪（快照進 job dir 的副本用完即刪），原檔留在使用者手上，需自行清理。
4. **`--terms-file` 受 `_validate_input` 限制**：非 symlink、UTF-8、64 KiB 以內、副檔名須在 `SUPPORTED_SUFFIXES`（`.txt` / `.md` / `.csv` / `.tsv` / `.log` / `.dat`）。用 `.txt` 最單純。

> 產出：2026-08-20 夜間批次 worker（patch-only，未落檔）；待 Dustin 人工套用。對應待辦：my-claude-code-harness.md:52
