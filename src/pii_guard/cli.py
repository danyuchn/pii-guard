"""CLI interface: anonymize / restore / serve subcommands."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional


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
        help="輸入檔案路徑或 - (stdin)",
    )
    anon.add_argument(
        "-o", "--output",
        type=Path,
        default=None,
        help="去識別化文本輸出路徑（預設：stdout）",
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

    # ── restore ──────────────────────────────────────────────────────────
    restore = subparsers.add_parser(
        "restore",
        help="還原去識別化文本",
    )
    restore.add_argument(
        "input",
        type=str,
        help="去識別化文本檔案路徑或 - (stdin)",
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

    return parser


def _read_input(input_path: str) -> str:
    if input_path == "-":
        return sys.stdin.read()
    return Path(input_path).read_text(encoding="utf-8")


def _write_output(text: str, output: Optional[Path]) -> None:
    if output is None:
        sys.stdout.write(text)
        sys.stdout.flush()
    else:
        output.write_text(text, encoding="utf-8")


def cmd_anonymize(args: argparse.Namespace) -> int:
    from pii_guard.pipeline.engine import PiiGuardEngine

    text = _read_input(args.input)
    print("[pii-guard] 載入模型中，首次執行需要下載 CKIP 模型…", file=sys.stderr)
    engine = PiiGuardEngine(ckip_model=args.model, score_threshold=args.threshold)
    anonymized, mapping = engine.anonymize(text)

    _write_output(anonymized, args.output)
    engine.save_mapping(mapping, args.mapping)

    print(f"\n[pii-guard] 偵測到 {len(mapping)} 個 PII 實體", file=sys.stderr)
    print(f"[pii-guard] mapping 已儲存至：{args.mapping}", file=sys.stderr)
    return 0


def cmd_restore(args: argparse.Namespace) -> int:
    from pii_guard.pipeline.engine import PiiGuardEngine

    text = _read_input(args.input)
    mapping = PiiGuardEngine.load_mapping(args.mapping)
    restored = PiiGuardEngine.deanonymize(text, mapping)
    _write_output(restored, args.output)
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import os

    os.environ.setdefault("PII_GUARD_MODEL", args.model)
    from pii_guard.server import app

    app.run(transport="stdio")
    return 0
