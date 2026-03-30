"""Claude Code PreToolUse hook: PII detection + user review prompt.

Scans the target file for PII using the regex-only engine. If PII is found,
returns permissionDecision: "ask" so the user sees a review prompt and can
approve or deny the read. Does NOT create temp files or modify the read target.

Usage (called by pii-guard-read.sh):
    echo '{"tool_input":{"file_path":"/path/to/file.txt"}}' | \
        uv run python -m pii_guard.hook_detect
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path


# Entity type display names for the review prompt
_DISPLAY_NAMES: dict[str, str] = {
    "TW_NATIONAL_ID": "身分證字號",
    "TW_ARC": "居留證",
    "TW_MOBILE": "手機號碼",
    "TW_LANDLINE": "市話",
    "TW_BUSINESS_ID": "統一編號",
    "EMAIL_ADDRESS": "Email",
    "CREDIT_CARD": "信用卡",
    "TW_PASSPORT": "護照",
    "TW_LICENSE_PLATE": "車牌",
    "TW_BIRTH_DATE": "出生日期",
    "TW_BANK_ACCOUNT": "銀行帳號",
    "TW_INTL_MOBILE": "國際手機",
}


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

    engine = create_regex_only_engine()
    results = engine.detect(content)

    if not results:
        # No PII found — let Read proceed without prompting
        sys.exit(0)

    # Count entities by type
    counts = Counter(r.entity_type for r in results)
    total = sum(counts.values())

    # Build human-readable summary
    lines = []
    for entity_type, count in counts.most_common():
        display = _DISPLAY_NAMES.get(entity_type, entity_type)
        lines.append(f"  - {display} ({entity_type}): {count}")
    entity_summary = "\n".join(lines)

    response = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": (
                f"=== PII GUARD: {total} PII entities detected ===\n"
                f"{entity_summary}\n\n"
                f"Allow: Claude reads the original file (you decided it's OK).\n"
                f"Deny: Claude uses anonymize_file MCP tool instead."
            ),
        },
    }

    json.dump(response, sys.stdout, ensure_ascii=False)
    sys.stdout.flush()


if __name__ == "__main__":
    main()
