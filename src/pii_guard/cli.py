"""CLI interface: anonymize / quick / restore / benchmark / web / serve."""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
from pathlib import Path


def _safe_error(error_code: str, message: str) -> int:
    """Print a structured error without echoing source text or mappings."""

    print(
        json.dumps(
            {"ok": False, "error_code": error_code, "message": message},
            ensure_ascii=False,
            sort_keys=True,
        ),
        file=sys.stderr,
    )
    return 2


def _threshold_arg(raw: str) -> float:
    """Parse a finite Presidio threshold constrained to the documented range."""

    try:
        value = float(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("threshold must be a number from 0 to 1") from exc
    if not math.isfinite(value) or not 0 <= value <= 1:
        raise argparse.ArgumentTypeError("threshold must be a finite number from 0 to 1")
    return value


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
        "-o",
        "--output",
        type=Path,
        default=None,
        help="去識別化輸出路徑（預設：stdout for text, <input>.anon.<ext> for files）",
    )
    anon.add_argument(
        "-m",
        "--mapping",
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
        type=_threshold_arg,
        default=0.5,
        help="Presidio 信心分數閾值（預設：0.5）",
    )

    # ── quick (shared private job workflow) ─────────────────────────────
    quick = subparsers.add_parser(
        "quick",
        help="快速模式：不啟動 Ollama，使用規則、Presidio 與中文辨識做可逆處理",
    )
    quick.add_argument("input", type=Path, help="UTF-8 純文字檔案路徑")
    quick.add_argument(
        "-o", "--output", type=Path, default=None, help="去識別化文字輸出路徑（預設輸出安全 JSON）"
    )
    quick.add_argument("--model", type=str, default="ckiplab/bert-base-chinese-ner")
    quick.add_argument("--threshold", type=_threshold_arg, default=0.5)
    quick.add_argument(
        "--jobs-root",
        type=Path,
        default=None,
        help="私有工作目錄（預設 ~/.local/share/pii-safe-documents/jobs）",
    )

    quick_restore = subparsers.add_parser(
        "quick-restore",
        help="以 quick 工作編號還原編輯後的去識別化文字",
    )
    quick_restore.add_argument("job_id", type=str, help="quick receipt 中的工作編號")
    quick_restore.add_argument("input", type=Path, help="編輯後的去識別化 UTF-8 純文字檔")
    quick_restore.add_argument(
        "-o", "--output", type=Path, required=True, help="還原檔輸出路徑（拒絕覆寫）"
    )
    quick_restore.add_argument(
        "--jobs-root",
        type=Path,
        default=None,
        help="私有工作目錄（預設 ~/.local/share/pii-safe-documents/jobs）",
    )

    # ── benchmark ────────────────────────────────────────────────────────
    benchmark = subparsers.add_parser("benchmark", help="量測 quick 冷啟動與後續處理速度")
    benchmark.add_argument(
        "--fixture",
        type=Path,
        default=Path("tests/fixtures/phase1_chinese.txt"),
        help="固定 UTF-8 中文 fixture",
    )
    benchmark.add_argument("--runs", type=int, default=3)
    benchmark.add_argument("--model", type=str, default="ckiplab/bert-base-chinese-ner")
    benchmark.add_argument("--threshold", type=_threshold_arg, default=0.5)
    benchmark.add_argument(
        "--regex-only",
        action="store_true",
        help="只供本機快速測試；正式 benchmark 預設包含 CKIP",
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
        "-m",
        "--mapping",
        type=Path,
        required=True,
        help="mapping JSON 路徑",
    )
    restore.add_argument(
        "-o",
        "--output",
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

    # ── web (loopback-only one-page UI) ──────────────────────────────────
    web = subparsers.add_parser(
        "web",
        aliases=["local-web"],
        help="啟動 127.0.0.1 本機快速／加強去識別化介面",
    )
    web.add_argument("--port", type=int, default=0, help="本機埠號（預設隨機）")
    web.add_argument("--open", action="store_true", help="啟動後開啟預設瀏覽器")
    web.add_argument("--model", type=str, default="ckiplab/bert-base-chinese-ner")
    web.add_argument("--threshold", type=_threshold_arg, default=0.5)
    web.add_argument("--jobs-root", type=Path, default=None)
    web.add_argument(
        "--audit-model",
        type=str,
        default=None,
        help="加強模式使用的本機 Ollama 模型（預設由共用稽核核心決定）",
    )
    web.add_argument(
        "--ollama-url",
        type=str,
        default=None,
        help="加強模式的本機 Ollama loopback URL",
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


def _write_quick_output(text: str, output: Path) -> None:
    """Create a user-requested quick output without following an output link."""

    target = output.expanduser()
    if target.exists() or target.is_symlink():
        raise OSError("quick output already exists")
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.parent.is_symlink():
        raise OSError("quick output parent is a symlink")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(target, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        target.unlink(missing_ok=True)
        raise


def _default_output_path(input_path: str) -> Path:
    """Generate default output path: <stem>.anon.<ext>."""
    p = Path(input_path)
    from pii_guard.file_handlers import get_output_extension

    out_ext = get_output_extension(p)
    return p.with_stem(p.stem + ".anon").with_suffix(out_ext)


def _default_restore_output_path(input_path: str) -> Path:
    """Generate default restore output path for structured formats: <stem>.restored.<ext>."""
    p = Path(input_path)
    from pii_guard.file_handlers import get_output_extension

    out_ext = get_output_extension(p)
    return p.with_stem(p.stem + ".restored").with_suffix(out_ext)


def cmd_anonymize(args: argparse.Namespace) -> int:
    from pii_guard.file_handlers import FileHandlerError, is_supported, read_file, write_file
    from pii_guard.pipeline.engine import PiiGuardEngine

    try:
        is_stdin = args.input == "-"

        print("[pii-guard] 載入模型中，首次執行需要下載 CKIP 模型…", file=sys.stderr)
        engine = PiiGuardEngine(
            ckip_model=args.model,
            score_threshold=args.threshold,
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

        # File input: use the isolated file-handler boundary.
        input_path = Path(args.input)
        if not is_supported(input_path):
            return _safe_error("FILE_UNSUPPORTED", "Input file format is not supported.")

        content = read_file(input_path)
        anonymized_text, mapping = engine.anonymize(content.text)
        output_path = args.output or _default_output_path(args.input)

        if content.file_type == "plain":
            _write_output(anonymized_text, output_path)
        else:
            # Structured formats and PDF output are written in an isolated
            # worker. PDF failures are fail-closed and produce no artifact.
            write_file(content, anonymized_text, mapping, output_path)

        engine.save_mapping(mapping, args.mapping)

        entity_count = len(mapping)
        print(f"\n[pii-guard] 偵測到 {entity_count} 個 PII 實體", file=sys.stderr)
        print(f"[pii-guard] 去識別化檔案：{output_path}", file=sys.stderr)
        print(f"[pii-guard] mapping 已儲存至：{args.mapping}", file=sys.stderr)
        return 0
    except FileHandlerError as error:
        return _safe_error(error.code, error.message)
    except (OSError, ValueError):
        return _safe_error("FILE_WRITE_FAILED", "The requested output could not be written safely.")


def cmd_quick(args: argparse.Namespace) -> int:
    """Run the shared deterministic quick path and keep the reverse map private."""

    from pii_guard.local_workflow import PrivateJobStore, WorkflowError

    try:
        store = PrivateJobStore(
            args.jobs_root,
            ckip_model=args.model,
            score_threshold=args.threshold,
        )
        receipt = store.create_quick_from_path(args.input)
    except WorkflowError as error:
        return _safe_error(error.code, error.message)
    except (OSError, ValueError):
        return _safe_error("QUICK_FAILED", "Quick redaction failed safely.")
    anonymized = str(receipt["anonymized_text"])
    try:
        if args.output is not None:
            _write_quick_output(anonymized, args.output)
    except (OSError, ValueError):
        try:
            store.delete(str(receipt["job_id"]))
        except (OSError, ValueError, WorkflowError):
            pass
        return _safe_error("OUTPUT_FAILED", "The requested output could not be written safely.")
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True))
    return 0


def cmd_quick_restore(args: argparse.Namespace) -> int:
    """Restore an edited quick job without exposing its private mapping."""

    from pii_guard.local_workflow import PrivateJobStore, WorkflowError, read_source_path

    try:
        store = PrivateJobStore(args.jobs_root)
        edited_redacted = read_source_path(args.input)
        result = store.restore_edited_redacted(
            args.job_id,
            edited_redacted,
            output_path=args.output,
            overwrite=False,
        )
    except WorkflowError as error:
        return _safe_error(error.code, error.message)
    except (OSError, ValueError):
        return _safe_error(
            "QUICK_RESTORE_FAILED", "Quick restore failed without exposing private details."
        )
    print(
        json.dumps(
            {
                "ok": True,
                "mode": "quick",
                "job_id": result.job_id,
                "roundtrip_equal": result.roundtrip_equal,
                "restored": True,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


def cmd_benchmark(args: argparse.Namespace) -> int:
    from pii_guard.benchmark import run_quick_benchmark
    from pii_guard.local_workflow import WorkflowError

    try:
        result = run_quick_benchmark(
            args.fixture,
            runs=args.runs,
            model=args.model,
            threshold=args.threshold,
            regex_only=args.regex_only,
        )
    except WorkflowError as error:
        return _safe_error(error.code, error.message)
    except (OSError, ValueError):
        return _safe_error("BENCHMARK_FAILED", "The benchmark could not run safely.")
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


def cmd_web(args: argparse.Namespace) -> int:
    from pii_guard.local_workflow import PrivateJobStore, WorkflowError
    from pii_guard.web import run_web

    try:
        store = PrivateJobStore(
            args.jobs_root,
            ckip_model=args.model,
            score_threshold=args.threshold,
        )
        run_web(
            port=args.port,
            open_browser=args.open,
            store=store,
            audit_model=args.audit_model,
            ollama_url=args.ollama_url,
        )
    except WorkflowError as error:
        return _safe_error(error.code, error.message)
    except OSError:
        return _safe_error("WEB_START_FAILED", "The localhost server could not be started safely.")
    return 0


def cmd_restore(args: argparse.Namespace) -> int:
    from pii_guard.file_handlers import FileHandlerError, is_supported, read_file, write_file
    from pii_guard.pipeline.engine import PiiGuardEngine

    try:
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
                _write_output(restored, args.output)
            else:
                # Structured format: reverse mapping to restore per-cell.
                # Binary formats can't go to stdout, so fall back to a derived
                # filename rather than silently overwriting the input.
                reverse_mapping = {v: k for k, v in mapping.items()}
                output_path = args.output or _default_restore_output_path(args.input)
                write_file(content, "", reverse_mapping, output_path)
        else:
            # Fallback: treat as plain text
            text = _read_input(args.input)
            restored = PiiGuardEngine.deanonymize(text, mapping)
            _write_output(restored, args.output)

        return 0
    except FileHandlerError as error:
        return _safe_error(error.code, error.message)
    except (OSError, ValueError, json.JSONDecodeError):
        return _safe_error("FILE_WRITE_FAILED", "The requested output could not be written safely.")


def cmd_serve(args: argparse.Namespace) -> int:
    import os

    os.environ.setdefault("PII_GUARD_MODEL", args.model)
    from pii_guard.server import app

    app.run(transport="stdio")
    return 0
