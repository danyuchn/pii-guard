"""Tests for the dependency-free Claude Code hook client.

The client is run as a real subprocess with its own ``PII_GUARD_HOOKD_HOME``,
because the whole point of it is what a separate ``python3`` process does when
the service is or is not there.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from pii_guard.hookd.core import SessionStore
from pii_guard.hookd.server import HookdApplication, HookdServerConfig, create_server
from pii_guard.hookd.state import HookdConfig, write_state
from tests.test_hookd_core import FakeEngine

CLIENT = (
    Path(__file__).resolve().parents[1]
    / "examples"
    / "claude-code-hookd"
    / "pii_guard_hook_client.py"
)
SPANS = {"王小明": "PERSON", "0912345678": "TW_MOBILE"}


def run_client(event: str, payload: dict[str, object], home: Path) -> dict[str, object]:
    """Run the hook client exactly as Claude Code would."""

    completed = subprocess.run(
        [sys.executable, str(CLIENT), event],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env={"PII_GUARD_HOOKD_HOME": str(home), "PATH": "/usr/bin:/bin"},
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


@pytest.fixture
def offline_home(tmp_path) -> Path:
    home = tmp_path / "hookd"
    home.mkdir()
    return home


@pytest.fixture
def online_home(tmp_path) -> Iterator[Path]:
    config = HookdConfig(home=tmp_path / "hookd")
    store = SessionStore(config, FakeEngine(dict(SPANS)))
    server, token, port = create_server(
        HookdApplication(store, "regex"), HookdServerConfig(port=0)
    )
    write_state(config, port=port, token=token, pid=1, engine="regex", started_at=0.0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield config.home
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


READ_PAYLOAD: dict[str, object] = {
    "session_id": "s1",
    "hook_event_name": "PostToolUse",
    "tool_name": "Read",
    "tool_input": {"file_path": "/tmp/notes.txt"},
    "tool_response": {
        "type": "text",
        "file": {
            "filePath": "/tmp/notes.txt",
            "content": "聯絡人 王小明 0912345678",
            "numLines": 1,
            "startLine": 1,
            "totalLines": 1,
        },
    },
}


def test_offline_read_withholds_the_file_content(offline_home: Path) -> None:
    reply = run_client("PostToolUse", READ_PAYLOAD, offline_home)

    updated = reply["hookSpecificOutput"]["updatedToolOutput"]
    assert updated["type"] == "text"
    assert "王小明" not in json.dumps(reply, ensure_ascii=False)
    assert "hookd unreachable" in updated["file"]["content"]
    assert updated["file"]["filePath"] == "/tmp/notes.txt"
    assert "pii-guard-hookd serve" in reply["hookSpecificOutput"]["additionalContext"]


def test_offline_read_of_an_image_is_passed_through(offline_home: Path) -> None:
    payload = {
        "session_id": "s1",
        "tool_name": "Read",
        "tool_response": {"type": "image", "file": {"base64": "abc"}},
    }

    assert run_client("PostToolUse", payload, offline_home) == {}


def test_offline_bash_withholds_both_streams(offline_home: Path) -> None:
    payload = {
        "session_id": "s1",
        "tool_name": "Bash",
        "tool_response": {
            "stdout": "王小明",
            "stderr": "0912345678",
            "interrupted": False,
            "isImage": False,
        },
    }

    reply = run_client("PostToolUse", payload, offline_home)

    updated = reply["hookSpecificOutput"]["updatedToolOutput"]
    assert "hookd unreachable" in updated["stdout"]
    assert updated["stderr"] == ""
    assert updated["interrupted"] is False
    assert "王小明" not in json.dumps(reply, ensure_ascii=False)


def test_offline_grep_withholds_every_string_leaf(offline_home: Path) -> None:
    payload = {
        "session_id": "s1",
        "tool_name": "Grep",
        "tool_response": {"mode": "content", "numFiles": 2, "content": "a.txt:1:王小明"},
    }

    reply = run_client("PostToolUse", payload, offline_home)

    updated = reply["hookSpecificOutput"]["updatedToolOutput"]
    assert "hookd unreachable" in updated["content"]
    assert updated["numFiles"] == 2
    assert updated["mode"] != "content"


def test_offline_write_is_denied(offline_home: Path) -> None:
    payload = {
        "session_id": "s1",
        "tool_name": "Write",
        "tool_input": {"file_path": "/tmp/out.txt", "content": "<PERSON_1>"},
    }

    reply = run_client("PreToolUse", payload, offline_home)

    assert reply["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "placeholders could not be restored" in (
        reply["hookSpecificOutput"]["permissionDecisionReason"]
    )


def test_offline_message_display_is_marked_once(offline_home: Path) -> None:
    first = run_client(
        "MessageDisplay", {"session_id": "s1", "delta": "hello", "index": 0}, offline_home
    )
    later = run_client(
        "MessageDisplay", {"session_id": "s1", "delta": "hello", "index": 3}, offline_home
    )

    assert first["hookSpecificOutput"]["displayContent"].startswith("[pii-guard offline")
    assert later["hookSpecificOutput"]["displayContent"] == "hello"


def test_offline_session_start_warns_loudly(offline_home: Path) -> None:
    reply = run_client("SessionStart", {"session_id": "s1", "source": "startup"}, offline_home)

    assert "NOT running" in reply["systemMessage"]
    assert "offline" in reply["hookSpecificOutput"]["additionalContext"]


def test_missing_state_directory_still_fails_closed(tmp_path: Path) -> None:
    reply = run_client("PostToolUse", READ_PAYLOAD, tmp_path / "nowhere")

    assert "hookd unreachable" in (
        reply["hookSpecificOutput"]["updatedToolOutput"]["file"]["content"]
    )


def test_online_read_is_redacted_not_withheld(online_home: Path) -> None:
    reply = run_client("PostToolUse", READ_PAYLOAD, online_home)

    updated = reply["hookSpecificOutput"]["updatedToolOutput"]
    assert updated["file"]["content"] == "聯絡人 <PERSON_1> <TW_MOBILE_1>"
    assert updated["file"]["totalLines"] == 1


def test_online_write_restores_the_real_value(online_home: Path) -> None:
    run_client("PostToolUse", READ_PAYLOAD, online_home)

    reply = run_client(
        "PreToolUse",
        {
            "session_id": "s1",
            "tool_name": "Write",
            "tool_input": {"file_path": "/tmp/out.txt", "content": "寄給 <PERSON_1>"},
        },
        online_home,
    )

    assert reply["hookSpecificOutput"]["updatedInput"]["content"] == "寄給 王小明"


def test_online_message_display_restores_without_a_prefix(online_home: Path) -> None:
    run_client("PostToolUse", READ_PAYLOAD, online_home)

    reply = run_client(
        "MessageDisplay",
        {"session_id": "s1", "delta": "客戶是 <PERSON_1>", "index": 0},
        online_home,
    )

    assert reply["hookSpecificOutput"]["displayContent"] == "客戶是 王小明"


def test_online_session_start_does_not_warn(online_home: Path) -> None:
    reply = run_client("SessionStart", {"session_id": "s1", "source": "startup"}, online_home)

    assert "NOT running" not in reply["systemMessage"]


def test_a_subagent_shares_the_parent_session_mapping(online_home: Path) -> None:
    """Subagent tool calls carry an agent_id but the same session_id."""

    run_client("PostToolUse", READ_PAYLOAD, online_home)
    subagent_payload = dict(READ_PAYLOAD)
    subagent_payload["agent_id"] = "agent-7"

    reply = run_client("PostToolUse", subagent_payload, online_home)

    updated = reply["hookSpecificOutput"]["updatedToolOutput"]
    assert updated["file"]["content"] == "聯絡人 <PERSON_1> <TW_MOBILE_1>"
