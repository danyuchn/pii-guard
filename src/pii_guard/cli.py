"""CLI interface: anonymize / restore / serve subcommands."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pii-guard",
        description="繁體中文（台灣）個人資料去識別化工具",
    )
    subparsers = parser.add_subparsers(dest="command")

    # ── anonymize ────────────────────────────────────────────────────────
    anon = subparsers.add_parser(
        "anonymize",
        aliases=["anon"],
        help="去識別化文本，輸出去識別化版本與 mapping JSON",
    )
    anon.add_argument(
        "input",
        type=str,
        help="輸入檔案路徑或 - (stdin，僅純文字)",
    )
    anon.add_argument(
        "-o", "--output",
        type=Path,
        default=None,
        help="去識別化輸出路徑（預設：stdout for text, <input>.anon.<ext> for files）",
    )
    anon.add_argument(
        "-m", "--mapping",
        type=Path,
        default=Path("mapping.json"),
        help="mapping JSON 輸出路徑（預設：mapping.json）",
    )
    anon.add_argument(
        "--model",
        type=str,
        default="ckiplab/bert-base-chinese-ner",
        help="CKIP NER 模型 ID 或本地路徑",
    )
    anon.add_argument(
        "--threshold",
        type=float,
        default=0.5,
        help="Presidio 信心分數閾值（預設：0.5）",
    )
    anon.add_argument(
        "--llm-fallback",
        action="store_true",
        default=False,
        help="啟用 Ollama LLM 輔助偵測（需先安裝 Ollama 並拉取模型）",
    )
    anon.add_argument(
        "--ollama-model",
        type=str,
        default="qwen2.5:1.5b",
        help="Ollama 模型名稱（預設：qwen2.5:1.5b）",
    )

    # ── restore ──────────────────────────────────────────────────────────
    restore = subparsers.add_parser(
        "restore",
        help="還原去識別化文本",
    )
    restore.add_argument(
        "input",
        type=str,
        help="去識別化文本檔案路徑或 - (stdin，僅純文字)",
    )
    restore.add_argument(
        "-m", "--mapping",
        type=Path,
        required=True,
        help="mapping JSON 路徑",
    )
    restore.add_argument(
        "-o", "--output",
        type=Path,
        default=None,
        help="還原後文本輸出路徑（預設：stdout）",
    )

    # ── serve (MCP server) ───────────────────────────────────────────────
    serve = subparsers.add_parser(
        "serve",
        help="以 stdio 模式啟動 MCP Server（供 claude mcp add 使用）",
    )
    serve.add_argument(
        "--model",
        type=str,
        default="ckiplab/bert-base-chinese-ner",
        help="CKIP NER 模型 ID 或本地路徑",
    )
    serve.add_argument(
        "--llm-fallback",
        action="store_true",
        default=False,
        help="啟用 Ollama LLM 輔助偵測",
    )

    return parser


def _read_input(input_path: str) -> str:
    if input_path == "-":
        return sys.stdin.read()
    return Path(input_path).read_text(encoding="utf-8")


def _write_output(text: str, output: Path | None) -> None:
    if output is None:
        sys.stdout.write(text)
        sys.stdout.flush()
    else:
        output.write_text(text, encoding="utf-8")


def _default_output_path(input_path: str) -> Path:
    """Generate default output path: <stem>.anon.<ext>."""
    p = Path(input_path)
    from pii_guard.file_handlers import get_output_extension, PDF_EXTENSIONS
    out_ext = get_output_extension(p)
    return p.with_stem(p.stem + ".anon").with_suffix(out_ext)


def cmd_anonymize(args: argparse.Namespace) -> int:
    from pii_guard.pipeline.engine import PiiGuardEngine
    from pii_guard.file_handlers import read_file, write_file, is_supported, PLAIN_TEXT_EXTENSIONS

    is_stdin = args.input == "-"

    print("[pii-guard] 載入模型中，首次執行需要下載 CKIP 模型…", file=sys.stderr)
    engine = PiiGuardEngine(
        ckip_model=args.model,
        score_threshold=args.threshold,
        llm_fallback=args.llm_fallback,
        ollama_model=args.ollama_model,
    )

    if is_stdin:
        # stdin: plain text only
        text = sys.stdin.read()
        anonymized, mapping = engine.anonymize(text)
        _write_output(anonymized, args.output)
        engine.save_mapping(mapping, args.mapping)
        print(f"\n[pii-guard] 偵測到 {len(mapping)} 個 PII 實體", file=sys.stderr)
        print(f"[pii-guard] mapping 已儲存至：{args.mapping}", file=sys.stderr)
        return 0

    # File input: use file_handlers for multi-format support
    input_path = Path(args.input)
    if not is_supported(input_path):
        print(f"[pii-guard] 不支援的檔案格式：{input_path.suffix}", file=sys.stderr)
        print(f"[pii-guard] 支援的格式：.txt .csv .tsv .xlsx .docx .pdf 等", file=sys.stderr)
        return 1

    content = read_file(input_path)
    anonymized_text, mapping = engine.anonymize(content.text)

    output_path = args.output or _default_output_path(args.input)

    if content.file_type == "plain" or content.file_type == "pdf":
        _write_output(anonymized_text, output_path)
    else:
        # Structured format: write back with per-cell anonymization
        write_file(content, anonymized_text, mapping, output_path)

    engine.save_mapping(mapping, args.mapping)

    entity_count = len(mapping)
    print(f"\n[pii-guard] 偵測到 {entity_count} 個 PII 實體", file=sys.stderr)
    print(f"[pii-guard] 去識別化檔案：{output_path}", file=sys.stderr)
    print(f"[pii-guard] mapping 已儲存至：{args.mapping}", file=sys.stderr)
    return 0


def cmd_restore(args: argparse.Namespace) -> int:
    from pii_guard.pipeline.engine import PiiGuardEngine
    from pii_guard.file_handlers import read_file, write_file, is_supported

    mapping = PiiGuardEngine.load_mapping(args.mapping)
    is_stdin = args.input == "-"

    if is_stdin:
        text = sys.stdin.read()
        restored = PiiGuardEngine.deanonymize(text, mapping)
        _write_output(restored, args.output)
        return 0

    input_path = Path(args.input)

    if is_supported(input_path) and input_path.suffix.lower() not in {".pdf"}:
        content = read_file(input_path)

        if content.file_type == "plain":
            restored = PiiGuardEngine.deanonymize(content.text, mapping)
            output_path = args.output or Path(args.input)
            _write_output(restored, output_path)
        else:
            # Structured format: reverse mapping to restore per-cell
            reverse_mapping = {v: k for k, v in mapping.items()}
            output_path = args.output or Path(args.input)
            write_file(content, "", reverse_mapping, output_path)
    else:
        # Fallback: treat as plain text
        text = _read_input(args.input)
        restored = PiiGuardEngine.deanonymize(text, mapping)
        _write_output(restored, args.output)

    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import os

    os.environ.setdefault("PII_GUARD_MODEL", args.model)
    if args.llm_fallback:
        os.environ["PII_GUARD_LLM_FALLBACK"] = "1"
    from pii_guard.server import app

    app.run(transport="stdio")
    return 0
