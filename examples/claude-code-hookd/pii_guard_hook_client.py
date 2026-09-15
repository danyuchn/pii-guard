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
import subprocess
import sys
import time
import urllib.error
import urllib.request

DEFAULT_HOME = "~/.local/share/pii-guard/hookd"
HOME_ENV_VAR = "PII_GUARD_HOOKD_HOME"
DEFAULT_CONFIG_PATH = "~/.config/pii-guard/hookd.json"
CONFIG_ENV_VAR = "PII_GUARD_HOOKD_CONFIG"
DEFAULT_TIMEOUT = 20.0
DISPLAY_TIMEOUT = 5.0
# How long SessionStart waits for a service it just started.  A first run
# that still has to download a model can exceed this; the session then gets
# the offline warning while the service keeps loading for the next one.
try:
    START_TIMEOUT = float(os.environ.get("PII_GUARD_HOOKD_START_TIMEOUT", "") or 20.0)
except ValueError:
    START_TIMEOUT = 20.0

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


def _make_private_dir(path: str) -> None:
    """Create a directory chain that is owner-only from the first moment.

    os.makedirs applies its mode to the last directory only, which would leave
    the enclosing one world-readable.
    """

    missing = []
    current = path
    while current and not os.path.isdir(current):
        missing.append(current)
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    for directory in reversed(missing):
        os.mkdir(directory, 0o700)


def _start_service() -> bool:
    """Start the service on demand and wait for it to answer.

    Only SessionStart does this. Every other event stays fail-closed and fast,
    because a tool call must not block for the seconds a model load can take.
    """

    config_path = os.path.expanduser(
        os.environ.get(CONFIG_ENV_VAR, "").strip() or DEFAULT_CONFIG_PATH
    )
    try:
        with open(config_path, encoding="utf-8") as handle:
            command = json.load(handle)["serve_command"]
    except (OSError, ValueError, KeyError, TypeError):
        return False
    if not isinstance(command, list) or not all(isinstance(part, str) for part in command):
        return False
    # The stored command runs in the foreground for launchd; dropping that flag
    # makes it detach on its own.
    command = [part for part in command if part != "--foreground"]

    lock_path = os.path.join(_home(), "starting.lock")
    try:
        _make_private_dir(_home())
        # O_EXCL makes this the one process that gets to spawn the service.
        lock = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        if time.time() - os.path.getmtime(lock_path) < START_TIMEOUT:
            return _wait_for_service()
        os.unlink(lock_path)
        return _start_service()
    except OSError:
        return False
    try:
        os.close(lock)
        subprocess.Popen(  # noqa: S603 - argv from an owner-only config file
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except (OSError, ValueError):
        return False
    finally:
        try:
            os.unlink(lock_path)
        except OSError:
            pass
    return _wait_for_service()


def _wait_for_service() -> bool:
    deadline = time.time() + START_TIMEOUT
    while time.time() < deadline:
        try:
            _ask_service("Ping", {}, 2.0)
        except Exception:  # noqa: BLE001 - any failure means not ready yet
            time.sleep(0.4)
            continue
        return True
    return False


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
        # A session opening with no service running is the normal case, not an
        # error: start it now so the user never has to.  Other events must stay
        # fast, so they fail closed instead of waiting for a model to load.
        reply = None
        if event == "SessionStart" and _start_service():
            try:
                reply = _ask_service(event, payload, timeout)
            except (OSError, ValueError, RuntimeError, urllib.error.URLError):
                reply = None
        if reply is None:
            reply = fail_closed(event, payload)
    json.dump(reply, sys.stdout, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
