#!/usr/bin/env python3
"""Claude Code hook client for the pii-guard hookd service.

Standard library only, on purpose: this script runs on every matched tool
call, so it must not import this project or pay a package manager's start-up
cost. All of the redaction logic lives in the service.

It FAILS CLOSED. If the service cannot be reached, or answers with anything
this script does not understand, the tool result is withheld rather than
handed to the model unredacted, and writes are denied rather than written with
placeholders still in them.

    python3 pii_guard_hook_client.py PostToolUse < hook.json
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

DEFAULT_HOME = "~/.local/share/pii-guard/hookd"
HOME_ENV_VAR = "PII_GUARD_HOOKD_HOME"
DEFAULT_TIMEOUT = 20.0
DISPLAY_TIMEOUT = 5.0

OFFLINE = (
    "[pii-guard] hookd unreachable; {what} withheld. "
    "Start it with: uv run pii-guard-hookd serve"
)
OFFLINE_CONTEXT = (
    "pii-guard hookd is not running, so this tool result could not be "
    "de-identified and was withheld. Do not retry the same read through "
    "another tool. Tell the user to start the guard with "
    "'uv run pii-guard-hookd serve', then try again."
)
DENY_REASON = (
    "[pii-guard] hookd unreachable; write withheld because placeholders could not be restored"
)
DISPLAY_PREFIX = "[pii-guard offline: placeholders not restored] "
SESSION_WARNING = (
    "WARNING: pii-guard hookd is NOT running. Tool results are not being "
    "de-identified and placeholders are not being restored."
)
SESSION_CONTEXT = (
    "The pii-guard guard service is offline. Until the user starts it with "
    "'uv run pii-guard-hookd serve', do not read files that may contain "
    "personal data, and tell the user the guard is off."
)


def _home() -> str:
    return os.path.expanduser(os.environ.get(HOME_ENV_VAR, "").strip() or DEFAULT_HOME)


def _connection() -> tuple[int, str]:
    """Return the advertised port and token, or raise ``RuntimeError``."""

    home = _home()
    env_path = os.path.join(home, "state.env")
    try:
        with open(env_path, encoding="utf-8") as handle:
            values = dict(
                line.strip().split("=", 1) for line in handle if "=" in line and line.strip()
            )
        return int(values["PII_HOOKD_PORT"]), values["PII_HOOKD_TOKEN"]
    except (OSError, ValueError, KeyError):
        pass
    try:
        with open(os.path.join(home, "state.json"), encoding="utf-8") as handle:
            state = json.load(handle)
        return int(state["port"]), str(state["token"])
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise RuntimeError("no hookd state") from error


def _ask_service(event: str, payload: dict, timeout: float) -> dict:
    port, token = _connection()
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/v1/hooks/{event}",
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
    )
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("Content-Type", "application/json")
    request.add_header("Host", f"127.0.0.1:{port}")
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - loopback
        body = response.read()
    reply = json.loads(body.decode("utf-8"))
    if not isinstance(reply, dict):
        raise RuntimeError("unexpected reply")
    return reply


def _hook_output(event: str, **fields: object) -> dict:
    return {"hookSpecificOutput": {"hookEventName": event, **fields}}


def _withhold_leaves(value: object, depth: int = 0) -> object:
    """Replace every string in an unknown structure, keeping the shape."""

    if depth > 12:
        return value
    if isinstance(value, str):
        return OFFLINE.format(what="content")
    if isinstance(value, dict):
        return {key: _withhold_leaves(item, depth + 1) for key, item in value.items()}
    if isinstance(value, list):
        return [_withhold_leaves(item, depth + 1) for item in value]
    return value


def _withhold_read(response: dict) -> dict:
    file_block = response.get("file")
    original = file_block if isinstance(file_block, dict) else {}
    withheld = {
        "filePath": original.get("filePath", ""),
        "content": OFFLINE.format(what="file content"),
        "numLines": 1,
        "startLine": original.get("startLine", 1),
        "totalLines": 1,
    }
    return {"type": "text", "file": withheld}


def _withhold_bash(response: dict) -> dict:
    return {
        "stdout": OFFLINE.format(what="command output"),
        "stderr": "",
        "interrupted": bool(response.get("interrupted", False)),
        "isImage": bool(response.get("isImage", False)),
    }


def _closed_post_tool_use(payload: dict) -> dict:
    response = payload.get("tool_response")
    response = response if isinstance(response, dict) else {}
    tool_name = payload.get("tool_name")
    if tool_name == "Read":
        # An image read carries no text for the model, so let it through.
        if response.get("type") not in (None, "text"):
            return {}
        updated = _withhold_read(response)
    elif tool_name == "Bash":
        updated = _withhold_bash(response)
    else:
        updated = _withhold_leaves(response)  # type: ignore[assignment]
    return _hook_output(
        "PostToolUse",
        updatedToolOutput=updated,
        additionalContext=OFFLINE_CONTEXT,
    )


def _closed_message_display(payload: dict) -> dict:
    delta = payload.get("delta")
    delta = delta if isinstance(delta, str) else ""
    prefix = DISPLAY_PREFIX if payload.get("index") in (0, None) else ""
    return _hook_output("MessageDisplay", displayContent=prefix + delta)


def fail_closed(event: str, payload: dict) -> dict:
    """Return the safe reply for one event when the service is unavailable."""

    if event == "PostToolUse":
        return _closed_post_tool_use(payload)
    if event == "PreToolUse":
        return _hook_output(
            "PreToolUse",
            permissionDecision="deny",
            permissionDecisionReason=DENY_REASON,
        )
    if event == "MessageDisplay":
        return _closed_message_display(payload)
    if event == "SessionStart":
        return {
            "systemMessage": SESSION_WARNING,
            "hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "additionalContext": SESSION_CONTEXT,
            },
        }
    return {}


def main(argv: list[str]) -> int:
    event = argv[1] if len(argv) > 1 else ""
    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except ValueError:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}

    timeout = DISPLAY_TIMEOUT if event == "MessageDisplay" else DEFAULT_TIMEOUT
    try:
        reply = _ask_service(event, payload, timeout)
    except (OSError, ValueError, RuntimeError, urllib.error.URLError):
        reply = fail_closed(event, payload)
    json.dump(reply, sys.stdout, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
