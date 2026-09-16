"""Tests for the dependency-free Claude Code hook client.

The client is run as a real subprocess with its own ``PII_GUARD_HOOKD_HOME``,
because the whole point of it is what a separate ``python3`` process does when
the service is or is not there.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
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

# The child environment is hand-built on purpose: the client must find the
# service through its own variables, never through the developer's shell.
# Windows still needs a handful of its own variables before a process can
# open a socket at all, so those are carried over rather than invented.
# USERPROFILE is deliberately NOT among them, so the tests that check the
# default home still resolve to nothing rather than to a real installation.
_WINDOWS_ESSENTIALS = (
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "TEMP",
    "TMP",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
)


def child_environment(values: dict[str, str]) -> dict[str, str]:
    """Build the environment Claude Code would hand the hook client."""

    environment = dict(values)
    if os.name != "nt":
        environment["PATH"] = "/usr/bin:/bin"
        return environment
    for name in _WINDOWS_ESSENTIALS:
        if name in os.environ and name not in environment:
            environment[name] = os.environ[name]
    # System32 has to stay reachable or the child cannot load its own DLLs.
    environment["PATH"] = os.environ.get("PATH", "")
    return environment


def run_client(
    event: str,
    payload: dict[str, object],
    home: Path,
    *arguments: str,
    config: Path | None = None,
    env: dict[str, str] | None = None,
) -> dict[str, object]:
    """Run the hook client exactly as Claude Code would."""

    environment = child_environment(
        dict(env) if env is not None else {"PII_GUARD_HOOKD_HOME": str(home)}
    )
    if config is not None:
        environment["PII_GUARD_HOOKD_CONFIG"] = str(config)
    completed = subprocess.run(
        [sys.executable, str(CLIENT), event, *arguments],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env=environment,
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


FAKE_SERVE = """
import json, os, stat, sys
argv_log, home, port, token = sys.argv[1:5]
with open(argv_log, "w") as handle:
    json.dump(sys.argv, handle)
os.makedirs(home, mode=0o700, exist_ok=True)
state = os.path.join(home, "state.json")
with open(state, "w") as handle:
    json.dump({"version": 1, "port": int(port), "token": token, "pid": os.getpid(),
               "engine": "regex", "started_at": 0.0}, handle)
os.chmod(state, 0o600)
env = os.path.join(home, "state.env")
with open(env, "w") as handle:
    handle.write("PII_HOOKD_PORT=%s\\nPII_HOOKD_TOKEN=%s\\n" % (port, token))
os.chmod(env, 0o600)
"""


@pytest.fixture
def lazy_start(tmp_path) -> Iterator[dict[str, Path]]:
    """A server that is running but not yet advertised in the state file.

    The fake serve command publishes the state file, which is exactly what the
    client is waiting for, without needing a real engine load.
    """

    config = HookdConfig(home=tmp_path / "hookd")
    store = SessionStore(config, FakeEngine(dict(SPANS)))
    server, token, port = create_server(
        HookdApplication(store, "regex"), HookdServerConfig(port=0)
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    argv_log = tmp_path / "argv.json"
    installer_config = tmp_path / "hookd-config.json"
    installer_config.write_text(
        json.dumps(
            {
                "repo": str(tmp_path),
                "engine": "regex",
                "serve_command": [
                    sys.executable,
                    "-c",
                    FAKE_SERVE,
                    str(argv_log),
                    str(config.home),
                    str(port),
                    token,
                    "--foreground",
                ],
            }
        ),
        encoding="utf-8",
    )
    try:
        yield {"home": config.home, "config": installer_config, "argv_log": argv_log}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def run_with_config(
    event: str,
    payload: dict[str, object],
    home: Path,
    config: Path,
    start_timeout: str = "20",
) -> dict[str, object]:
    completed = subprocess.run(
        [sys.executable, str(CLIENT), event],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env=child_environment(
            {
                "PII_GUARD_HOOKD_HOME": str(home),
                "PII_GUARD_HOOKD_CONFIG": str(config),
                "PII_GUARD_HOOKD_START_TIMEOUT": start_timeout,
            }
        ),
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def test_session_start_starts_the_service_on_demand(lazy_start) -> None:
    reply = run_with_config(
        "SessionStart",
        {"session_id": "s1", "source": "startup"},
        lazy_start["home"],
        lazy_start["config"],
    )

    # The offline warning would say "NOT running"; this is the live reply.
    assert reply["systemMessage"] == "pii-guard: on (regex only, names NOT covered)"
    assert (lazy_start["home"] / "state.env").is_file()


def test_lazy_start_drops_the_foreground_flag(lazy_start) -> None:
    """The stored command is launchd's; on demand it must daemonize itself."""

    run_with_config(
        "SessionStart",
        {"session_id": "s1", "source": "startup"},
        lazy_start["home"],
        lazy_start["config"],
    )

    argv = json.loads(lazy_start["argv_log"].read_text(encoding="utf-8"))
    assert "--foreground" not in argv


def test_other_events_never_start_the_service(lazy_start) -> None:
    reply = run_with_config(
        "PostToolUse", READ_PAYLOAD, lazy_start["home"], lazy_start["config"]
    )

    assert "hookd unreachable" in (
        reply["hookSpecificOutput"]["updatedToolOutput"]["file"]["content"]
    )
    assert not (lazy_start["home"] / "state.env").exists()
    assert not lazy_start["argv_log"].exists()


def test_session_start_warns_when_there_is_no_installer_config(tmp_path: Path) -> None:
    reply = run_with_config(
        "SessionStart",
        {"session_id": "s1", "source": "startup"},
        tmp_path / "hookd",
        tmp_path / "missing.json",
        start_timeout="2",
    )

    assert "NOT running" in reply["systemMessage"]


def test_session_start_warns_when_the_spawned_command_never_serves(tmp_path: Path) -> None:
    config = tmp_path / "hookd-config.json"
    config.write_text(
        json.dumps({"serve_command": [sys.executable, "-c", "pass"]}), encoding="utf-8"
    )

    reply = run_with_config(
        "SessionStart",
        {"session_id": "s1", "source": "startup"},
        tmp_path / "hookd",
        config,
        start_timeout="2",
    )

    assert "NOT running" in reply["systemMessage"]


def test_offline_prompt_submit_is_blocked(offline_home: Path) -> None:
    reply = run_client(
        "UserPromptSubmit", {"session_id": "s1", "prompt": "hello"}, offline_home
    )

    assert reply["decision"] == "block"
    assert "offline" in reply["reason"]


def test_online_prompt_submit_passes_a_clean_prompt(online_home: Path) -> None:
    reply = run_client(
        "UserPromptSubmit",
        {"session_id": "s1", "prompt": "請看一下測試", "cwd": "/tmp"},
        online_home,
    )

    assert reply == {}


# --- SessionStart --start-only, the Mod's one classic hook -------------------
#
# The Mod handles SessionStart itself but cannot spawn a service that outlives
# the session, so this entry survives a --mod install purely to start it.


def _start_only_config(tmp_path: Path, marker: Path) -> Path:
    """An installer config whose serve command only touches a marker file."""

    config = tmp_path / "hookd.json"
    config.write_text(
        json.dumps(
            {
                "serve_command": [
                    sys.executable,
                    "-c",
                    f"open({str(marker)!r}, 'w').write('started')",
                ]
            }
        ),
        encoding="utf-8",
    )
    return config


def test_start_only_says_nothing_and_starts_the_service(tmp_path, offline_home) -> None:
    marker = tmp_path / "started.txt"
    config = _start_only_config(tmp_path, marker)

    reply = run_client("SessionStart", {}, offline_home, "--start-only", config=config)

    assert reply == {}
    deadline = time.time() + 10
    while time.time() < deadline and not marker.exists():
        time.sleep(0.1)
    assert marker.exists(), "the start-only hook did not run the serve command"


def test_start_only_still_says_nothing_when_the_start_fails(tmp_path, offline_home) -> None:
    """A guard that cannot start is not a reason to disturb the session here.

    The Mod fails closed on the very next event, which is where the user is
    told; printing anything at this hook would only duplicate that.
    """

    config = tmp_path / "hookd.json"
    config.write_text(json.dumps({"serve_command": "not-a-list"}), encoding="utf-8")

    reply = run_client("SessionStart", {}, offline_home, "--start-only", config=config)

    assert reply == {}


def test_start_only_without_any_config_says_nothing(offline_home) -> None:
    assert run_client("SessionStart", {}, offline_home, "--start-only") == {}


def test_start_only_does_not_greet_when_the_service_is_up(online_home: Path) -> None:
    """The Mod sends its own briefing, so this hook must stay silent."""

    reply = run_client("SessionStart", {}, online_home, "--start-only")

    assert reply == {}


def test_plain_session_start_still_greets(online_home: Path) -> None:
    """Without the flag the classic behaviour is unchanged."""

    reply = run_client("SessionStart", {}, online_home)

    assert "systemMessage" in reply


# --- Finding the service under `claude plugin eval` --------------------------
#
# An eval run gets a throwaway home directory and inherits only EVAL_ prefixed
# variables from the surrounding shell, so the usual path finds nothing.


def test_the_eval_variable_locates_the_service(online_home: Path) -> None:
    reply = run_client(
        "PostToolUse",
        READ_PAYLOAD,
        online_home,
        env={"EVAL_PII_GUARD_HOOKD_HOME": str(online_home)},
    )

    content = reply["hookSpecificOutput"]["updatedToolOutput"]["file"]["content"]
    assert "0912345678" not in content
    assert "<TW_MOBILE_1>" in content


def test_the_ordinary_variable_still_wins(online_home: Path, tmp_path: Path) -> None:
    """A real installation must not be overridden by a stray EVAL_ variable."""

    reply = run_client(
        "PostToolUse",
        READ_PAYLOAD,
        online_home,
        env={
            "PII_GUARD_HOOKD_HOME": str(online_home),
            "EVAL_PII_GUARD_HOOKD_HOME": str(tmp_path / "nowhere"),
        },
    )

    content = reply["hookSpecificOutput"]["updatedToolOutput"]["file"]["content"]
    assert "<TW_MOBILE_1>" in content


def test_without_either_variable_it_still_fails_closed(tmp_path: Path) -> None:
    reply = run_client("PostToolUse", READ_PAYLOAD, tmp_path, env={"HOME": str(tmp_path)})

    content = reply["hookSpecificOutput"]["updatedToolOutput"]["file"]["content"]
    assert "0912345678" not in content
    assert "withheld" in content
