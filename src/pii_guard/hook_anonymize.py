"""Claude Code PreToolUse hook worker for PII anonymization.

Reads hook JSON from stdin, anonymizes the target file using the regex-only
engine, writes a temp file + mapping, and outputs hook response JSON.

Usage (called by pii-guard-read.sh):
    echo '{"tool_input":{"file_path":"/path/to/file.txt"}}' | \
        uv run python -m pii_guard.hook_anonymize
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


MAPPING_DIR = Path("/tmp/pii-guard-hook")


def main() -> None:
    raw = sys.stdin.read().strip()
    if not raw:
        sys.exit(0)

    try:
        hook_input = json.loads(raw)
    except json.JSONDecodeError:
        sys.exit(0)

    tool_input = hook_input.get("tool_input", {})
    file_path = tool_input.get("file_path", "")

    if not file_path:
        sys.exit(0)

    path = Path(file_path)
    if not path.is_file():
        sys.exit(0)

    # Read file content (skip non-UTF-8)
    try:
        content = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        sys.exit(0)

    if not content.strip():
        sys.exit(0)

    # Lazy import to keep startup fast when exiting early
    from pii_guard.hook_engine import create_regex_only_engine
    from pii_guard.pipeline.engine import PiiGuardEngine

    engine = create_regex_only_engine()
    anonymized, mapping = engine.anonymize(content)

    if not mapping:
        # No PII found — let Read proceed with original file
        sys.exit(0)

    # Write temp file + mapping
    MAPPING_DIR.mkdir(parents=True, exist_ok=True)
    hash_key = hashlib.sha256(file_path.encode()).hexdigest()[:16]
    temp_path = MAPPING_DIR / f"{hash_key}.txt"
    mapping_path = MAPPING_DIR / f"{hash_key}.mapping.json"

    temp_path.write_text(anonymized, encoding="utf-8")
    PiiGuardEngine.save_mapping(mapping, mapping_path)

    # Build hook response preserving original offset/limit
    updated_input: dict = {"file_path": str(temp_path)}
    if "offset" in tool_input:
        updated_input["offset"] = tool_input["offset"]
    if "limit" in tool_input:
        updated_input["limit"] = tool_input["limit"]

    response = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "updatedInput": updated_input,
            "additionalContext": (
                f"=== PII GUARD: CONTENT ANONYMIZED ===\n"
                f"File content has been anonymized. "
                f"{len(mapping)} PII entities replaced with placeholders.\n"
                f"Original file: {file_path}\n"
                f"Mapping saved: {mapping_path}\n"
                f"To restore: pii-guard restore <file> -m {mapping_path}"
            ),
        },
    }

    json.dump(response, sys.stdout, ensure_ascii=False)
    sys.stdout.flush()


if __name__ == "__main__":
    main()
