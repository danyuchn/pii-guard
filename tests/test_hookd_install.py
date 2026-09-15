"""Tests for the installer, the doctor report and the uninstall path.

Nothing here touches the real Claude Code configuration or real launchd: the
config directory is a tmp path and every launchctl call is monkeypatched.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from pii_guard.hookd import install as installer
from pii_guard.hookd.__main__ import main
from pii_guard.hookd.state import HookdConfig
from pii_guard.local_workflow import WorkflowError

FOREIGN_HOOK = {
    "matcher": "Bash",
    "hooks": [{"type": "command", "command": "/usr/local/bin/my-own-guard.sh"}],
}


@pytest.fixture
def env(tmp_path, monkeypatch) -> dict[str, Path]:
    """A complete, isolated installation environment."""

    config_dir = tmp_path / "claude"
    config_dir.mkdir()
    hookd_home = tmp_path / "hookd"
    installer_config = tmp_path / "config" / "hookd.json"
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(config_dir))
    monkeypatch.setenv("PII_GUARD_HOOKD_HOME", str(hookd_home))
    monkeypatch.setenv("PII_GUARD_HOOKD_CONFIG", str(installer_config))
    # Never touch real launchd, and never spawn a real service: these tests
    # are about the installer, and a real engine load would take a minute.
    monkeypatch.setattr(installer, "run_launchctl", lambda arguments: (0, "fake"))
    monkeypatch.setattr(installer, "start_service_detached", lambda repo, engine: False)
    monkeypatch.setattr(installer, "wait_for_health", lambda config, timeout=90.0: None)
    monkeypatch.setattr(installer, "service_health", lambda config, timeout=5.0: None)
    return {
        "config_dir": config_dir,
        "hookd_home": hookd_home,
        "installer_config": installer_config,
        "settings": config_dir / "settings.json",
    }


def _install(*extra: str) -> int:
    return main(["install", "--no-launchd", *extra])


def _settings(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_install_into_a_fresh_config(env, capsys) -> None:
    assert _install() == 0

    settings = _settings(env["settings"])
    assert sorted(settings["hooks"]) == [
        "MessageDisplay",
        "PostToolUse",
        "PreToolUse",
        "SessionStart",
    ]
    client = installer.client_target(env["config_dir"])
    assert client.is_file()
    assert stat.S_IMODE(client.stat().st_mode) == 0o700
    assert str(client) in settings["hooks"]["PostToolUse"][0]["hooks"][0]["command"]
    # MCP output is not schema validated, so leaf redaction is safe there.
    assert settings["hooks"]["PostToolUse"][0]["matcher"] == "Read|Bash|Grep|mcp__.*"
    assert "service" in capsys.readouterr().out


def test_install_preserves_existing_keys_and_foreign_hooks(env) -> None:
    env["settings"].write_text(
        json.dumps(
            {
                "model": "opus",
                "permissions": {"allow": ["Bash(ls:*)"]},
                "hooks": {"PreToolUse": [FOREIGN_HOOK], "Stop": [FOREIGN_HOOK]},
            }
        ),
        encoding="utf-8",
    )

    _install()

    settings = _settings(env["settings"])
    assert settings["model"] == "opus"
    assert settings["permissions"] == {"allow": ["Bash(ls:*)"]}
    assert settings["hooks"]["Stop"] == [FOREIGN_HOOK]
    assert FOREIGN_HOOK in settings["hooks"]["PreToolUse"]
    assert len(settings["hooks"]["PreToolUse"]) == 2


def test_install_is_idempotent(env) -> None:
    _install()
    first = _settings(env["settings"])
    _install()
    second = _settings(env["settings"])

    assert first == second
    for entries in second["hooks"].values():
        assert len(entries) == 1


def test_install_backs_up_an_existing_settings_file(env) -> None:
    env["settings"].write_text(json.dumps({"model": "opus"}), encoding="utf-8")

    _install()

    backups = list(env["config_dir"].glob("settings.json.bak-*"))
    assert len(backups) == 1
    assert json.loads(backups[0].read_text(encoding="utf-8")) == {"model": "opus"}


def test_install_refuses_malformed_settings_and_leaves_them_alone(env) -> None:
    original = "{ this is not json"
    env["settings"].write_text(original, encoding="utf-8")

    assert main(["install", "--no-launchd"]) == 1
    assert env["settings"].read_text(encoding="utf-8") == original
    assert not list(env["config_dir"].glob("settings.json.bak-*"))


def test_install_writes_an_owner_only_config(env) -> None:
    _install("--engine", "full")

    config_file = env["installer_config"]
    assert stat.S_IMODE(config_file.stat().st_mode) == 0o600
    payload = json.loads(config_file.read_text(encoding="utf-8"))
    assert payload["engine"] == "full"
    assert Path(payload["repo"]).is_dir()
    assert payload["serve_command"][:2] == ["uv", "run"]
    assert "--foreground" in payload["serve_command"]


def test_uninstall_removes_only_our_entries(env) -> None:
    env["settings"].write_text(
        json.dumps({"model": "opus", "hooks": {"PreToolUse": [FOREIGN_HOOK]}}),
        encoding="utf-8",
    )
    _install()

    assert main(["uninstall"]) == 0

    settings = _settings(env["settings"])
    assert settings["model"] == "opus"
    assert settings["hooks"] == {"PreToolUse": [FOREIGN_HOOK]}
    assert not installer.client_target(env["config_dir"]).exists()


def test_uninstall_drops_the_hooks_key_when_nothing_is_left(env) -> None:
    _install()

    main(["uninstall"])

    assert "hooks" not in _settings(env["settings"])


def test_uninstall_without_an_install_is_harmless(env) -> None:
    assert main(["uninstall"]) == 0


def test_project_scope_writes_into_the_working_directory(env, tmp_path, monkeypatch) -> None:
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.chdir(project)

    _install("--scope", "project")

    assert (project / ".claude" / "settings.json").is_file()
    assert not env["settings"].exists()


def test_doctor_reports_each_missing_piece(env, capsys) -> None:
    assert main(["doctor"]) == 1

    output = capsys.readouterr().out
    assert "[FAIL] hook client" in output
    assert "[FAIL] hooks in settings" in output
    assert "[FAIL] installer config" in output
    assert "[FAIL] service" in output


def test_doctor_passes_after_install(env, capsys) -> None:
    _install()
    capsys.readouterr()

    assert main(["doctor"]) == 0

    output = capsys.readouterr().out
    assert "[OK  ] hook client" in output
    assert "[OK  ] hooks in settings" in output
    assert "[OK  ] installer config" in output


def test_doctor_reports_a_running_service_and_its_engine(env, capsys, monkeypatch) -> None:
    _install()
    capsys.readouterr()
    monkeypatch.setattr(
        installer,
        "service_health",
        lambda config, timeout=5.0: {
            "sessions": 2,
            "names_covered": True,
            "engine_fallback": False,
            "policy": {"output_gate": True, "allowed_tools": []},
        },
    )

    assert main(["doctor"]) == 0

    output = capsys.readouterr().out
    assert "[OK  ] service: healthy, 2 session(s)" in output
    assert "[OK  ] engine: full, names covered" in output


def test_doctor_fails_when_the_engine_fell_back(env, capsys, monkeypatch) -> None:
    _install()
    capsys.readouterr()
    monkeypatch.setattr(
        installer,
        "service_health",
        lambda config, timeout=5.0: {
            "sessions": 0,
            "names_covered": False,
            "engine_fallback": True,
            "policy": {"output_gate": True, "allowed_tools": []},
        },
    )

    assert main(["doctor"]) == 1
    assert "names NOT covered" in capsys.readouterr().out


def test_launch_agent_plist_runs_the_foreground_command(tmp_path) -> None:
    import plistlib

    plist = tmp_path / "agent.plist"
    command = installer.serve_command(Path("/repo"), "full")

    installer.write_launch_agent(plist, command, tmp_path)

    payload = plistlib.loads(plist.read_bytes())
    assert payload["Label"] == "com.pii-guard.hookd"
    assert payload["ProgramArguments"] == command
    assert payload["RunAtLoad"] is True
    assert payload["KeepAlive"] is True


def test_load_launch_agent_falls_back_to_the_old_verb(tmp_path, monkeypatch) -> None:
    calls: list[list[str]] = []

    def fake(arguments: list[str]) -> tuple[int, str]:
        calls.append(arguments)
        return (1, "bootstrap unsupported") if arguments[0] == "bootstrap" else (0, "")

    monkeypatch.setattr(installer, "run_launchctl", fake)

    loaded, detail = installer.load_launch_agent(tmp_path / "agent.plist")

    assert loaded is True
    assert detail == "loaded"
    assert [call[0] for call in calls] == ["bootstrap", "load"]


def test_install_registers_the_launch_agent(env, monkeypatch, capsys) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(installer, "run_launchctl", lambda a: (calls.append(a), (0, ""))[1])
    monkeypatch.setattr(installer, "launch_agent_path", lambda: env["config_dir"] / "agent.plist")
    monkeypatch.setattr(installer, "wait_for_health", lambda config, timeout=90.0: None)
    monkeypatch.setattr("sys.platform", "darwin")

    main(["install"])

    assert (env["config_dir"] / "agent.plist").is_file()
    assert calls and calls[0][0] == "bootstrap"
    assert "loaded" in capsys.readouterr().out


def test_settings_path_rejects_an_unknown_scope() -> None:
    with pytest.raises(WorkflowError):
        installer.settings_path(Path("/tmp"), "global")


def test_session_store_permissions_are_checked(env, monkeypatch, capsys) -> None:
    _install()
    capsys.readouterr()
    config = HookdConfig(home=env["hookd_home"])
    config.ensure_home()
    config.sessions_dir.chmod(0o755)

    main(["doctor"])

    assert "[FAIL] session store" in capsys.readouterr().out
    config.sessions_dir.chmod(0o700)


def test_install_creates_owner_only_directories_from_the_start(env, tmp_path) -> None:
    """The enclosing directory must not be world-readable even for a moment."""

    nested = tmp_path / "share" / "pii-guard" / "hookd"
    HookdConfig(home=nested).ensure_home()

    assert stat.S_IMODE(nested.stat().st_mode) == 0o700
    assert stat.S_IMODE(nested.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE((nested / "sessions").stat().st_mode) == 0o700


def test_ensure_home_leaves_pre_existing_directories_alone(tmp_path) -> None:
    shared = tmp_path / "share"
    shared.mkdir(mode=0o755)

    HookdConfig(home=shared / "pii-guard" / "hookd").ensure_home()

    # A directory that was already there is not ours to tighten.
    assert stat.S_IMODE(shared.stat().st_mode) == 0o755
    assert stat.S_IMODE((shared / "pii-guard").stat().st_mode) == 0o700


def test_install_leaves_the_hookd_home_owner_only(env) -> None:
    _install()

    home = env["hookd_home"]
    assert stat.S_IMODE(home.stat().st_mode) == 0o700
    assert stat.S_IMODE((home / "sessions").stat().st_mode) == 0o700


def test_install_starts_the_service_without_launchd(env, monkeypatch, capsys) -> None:
    started: list[list[str]] = []

    def fake_start(repo, engine):
        started.append(installer.detached_serve_command(repo, engine))
        return True

    monkeypatch.setattr(installer, "start_service_detached", fake_start)
    monkeypatch.setattr(
        installer,
        "wait_for_health",
        lambda config, timeout=90.0: {"sessions": 0, "names_covered": True},
    )
    monkeypatch.setattr(
        installer,
        "service_health",
        lambda config, timeout=5.0: (
            {
                "sessions": 0,
                "names_covered": True,
                "engine_fallback": False,
                "policy": {"output_gate": True, "allowed_tools": []},
            }
            if started
            else None
        ),
    )

    assert main(["install", "--no-launchd"]) == 0

    assert len(started) == 1
    # The detached command must not carry launchd's foreground flag.
    assert "--foreground" not in started[0]
    assert "Starting the service" in capsys.readouterr().out


def test_install_does_not_restart_a_running_service(env, monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        installer,
        "service_health",
        lambda config, timeout=5.0: {
            "sessions": 1,
            "names_covered": True,
            "engine_fallback": False,
            "policy": {"output_gate": True, "allowed_tools": []},
        },
    )
    monkeypatch.setattr(
        installer,
        "start_service_detached",
        lambda repo, engine: pytest.fail("should not spawn a second service"),
    )

    assert main(["install", "--no-launchd"]) == 0
    assert "already running" in capsys.readouterr().out


def test_doctor_warns_rather_than_fails_when_the_service_is_idle(env, capsys) -> None:
    _install()
    capsys.readouterr()

    # The installer config exists, so something will start it at the next
    # session; that is a warning, not a broken installation.
    assert main(["doctor"]) == 0

    output = capsys.readouterr().out
    assert "[WARN] service: not running (starts on demand at next session)" in output
    assert "Everything checks out" in output


def test_doctor_still_fails_when_nothing_would_start_the_service(env, capsys) -> None:
    assert main(["doctor"]) == 1
    assert "[FAIL] service: not reachable" in capsys.readouterr().out


def test_harden_adds_the_sandbox_and_egress_denials(env) -> None:
    assert main(["install", "--no-launchd", "--harden"]) == 0

    settings = _settings(env["settings"])
    assert settings["sandbox"] == installer.SANDBOX_BLOCK
    assert settings["permissions"]["deny"] == ["WebFetch", "WebSearch"]
    assert "UserPromptSubmit" in settings["hooks"]
    assert "WebFetch" in settings["hooks"]["PreToolUse"][0]["matcher"]
    assert "mcp__.*" in settings["hooks"]["PreToolUse"][0]["matcher"]


def test_plain_install_does_not_harden(env) -> None:
    _install()

    settings = _settings(env["settings"])
    assert "sandbox" not in settings
    assert "UserPromptSubmit" not in settings["hooks"]


def test_harden_preserves_an_existing_sandbox_block(env, capsys) -> None:
    mine = {"enabled": True, "network": {"allowedDomains": ["api.internal"]}}
    env["settings"].write_text(json.dumps({"sandbox": mine}), encoding="utf-8")

    main(["install", "--no-launchd", "--harden"])

    settings = _settings(env["settings"])
    assert settings["sandbox"] == mine
    assert "already exists and was left alone" in capsys.readouterr().out


def test_harden_keeps_existing_permission_denials(env) -> None:
    env["settings"].write_text(
        json.dumps({"permissions": {"deny": ["Bash(rm:*)"], "allow": ["Bash(ls:*)"]}}),
        encoding="utf-8",
    )

    main(["install", "--no-launchd", "--harden"])

    permissions = _settings(env["settings"])["permissions"]
    assert permissions["allow"] == ["Bash(ls:*)"]
    assert permissions["deny"] == ["Bash(rm:*)", "WebFetch", "WebSearch"]


def test_uninstall_removes_only_the_hardening_we_added(env) -> None:
    env["settings"].write_text(
        json.dumps({"permissions": {"deny": ["Bash(rm:*)"]}}), encoding="utf-8"
    )
    main(["install", "--no-launchd", "--harden"])

    main(["uninstall"])

    settings = _settings(env["settings"])
    assert "sandbox" not in settings
    assert settings["permissions"]["deny"] == ["Bash(rm:*)"]


def test_uninstall_leaves_a_sandbox_block_it_did_not_write(env) -> None:
    mine = {"enabled": False}
    env["settings"].write_text(json.dumps({"sandbox": mine}), encoding="utf-8")
    main(["install", "--no-launchd", "--harden"])

    main(["uninstall"])

    assert _settings(env["settings"])["sandbox"] == mine


def test_harden_is_idempotent(env) -> None:
    main(["install", "--no-launchd", "--harden"])
    first = _settings(env["settings"])
    main(["install", "--no-launchd", "--harden"])

    assert _settings(env["settings"]) == first


def test_doctor_harden_checks_the_sandbox(env, capsys) -> None:
    main(["install", "--no-launchd", "--harden"])
    capsys.readouterr()

    assert main(["doctor", "--harden"]) == 0

    output = capsys.readouterr().out
    assert "[OK  ] sandbox: enabled" in output
    assert "[OK  ] egress denied: WebFetch, WebSearch" in output


def test_doctor_harden_fails_without_hardening(env, capsys) -> None:
    _install()
    capsys.readouterr()

    assert main(["doctor", "--harden"]) == 1

    output = capsys.readouterr().out
    assert "[FAIL] sandbox" in output
    assert "[FAIL] egress denied" in output


def test_doctor_reports_the_running_policy(env, capsys, monkeypatch) -> None:
    _install()
    capsys.readouterr()
    monkeypatch.setattr(
        installer,
        "service_health",
        lambda config, timeout=5.0: {
            "sessions": 0,
            "names_covered": True,
            "engine_fallback": False,
            "policy": {"output_gate": True, "allowed_tools": ["mcp__local__x"]},
        },
    )

    main(["doctor"])

    assert "[OK  ] policy: active, output gate on, 1 allowlisted tool(s)" in capsys.readouterr().out


def test_doctor_flags_a_service_without_the_policy(env, capsys, monkeypatch) -> None:
    _install()
    capsys.readouterr()
    monkeypatch.setattr(
        installer,
        "service_health",
        lambda config, timeout=5.0: {"sessions": 0, "names_covered": True},
    )

    assert main(["doctor"]) == 1
    assert "predates the policy rules" in capsys.readouterr().out


def test_install_picks_up_a_project_term_list(env, tmp_path, monkeypatch) -> None:
    project = tmp_path / "proj"
    (project / ".pii-guard").mkdir(parents=True)
    (project / ".pii-guard" / "terms.txt").write_text("龍哥\n", encoding="utf-8")
    monkeypatch.chdir(project)

    _install()

    policy_block = json.loads(env["installer_config"].read_text(encoding="utf-8"))["policy"]
    assert policy_block["seed_terms_files"] == [str(project / ".pii-guard" / "terms.txt")]


def test_reinstall_keeps_a_hand_edited_allowlist(env) -> None:
    _install()
    config_file = env["installer_config"]
    payload = json.loads(config_file.read_text(encoding="utf-8"))
    payload["policy"]["allowed_tools"] = ["mcp__local__read"]
    config_file.write_text(json.dumps(payload), encoding="utf-8")

    _install()

    kept = json.loads(config_file.read_text(encoding="utf-8"))["policy"]
    assert kept["allowed_tools"] == ["mcp__local__read"]
