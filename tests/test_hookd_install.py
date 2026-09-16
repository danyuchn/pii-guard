"""Tests for the installer, the doctor report and the uninstall path.

Nothing here touches the real Claude Code configuration or real launchd: the
config directory is a tmp path and every launchctl call is monkeypatched.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from pii_guard._compat import private_directory_acl_matches
from pii_guard.hookd import install as installer
from pii_guard.hookd import state
from pii_guard.hookd.__main__ import main
from pii_guard.hookd.state import HookdConfig
from pii_guard.local_workflow import WorkflowError
from tests.conftest import assert_mode

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
    assert_mode(client, 0o700)
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
    assert_mode(config_file, 0o600)
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


# launchd is macOS-only, and so is the os.getuid() its bootstrap target needs;
# monkeypatching sys.platform cannot conjure either onto Windows.
_LAUNCHD = pytest.mark.skipif(os.name == "nt", reason="launchd exists only on POSIX")


@_LAUNCHD
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


@_LAUNCHD
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


# Loosening the store to 0o755 is how this check is provoked, and NTFS cannot
# record that, so doctor correctly reports the verified ACL instead.
@pytest.mark.skipif(os.name == "nt", reason="POSIX modes cannot be loosened on NTFS")
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

    assert_mode(nested, 0o700)
    assert_mode(nested.parent, 0o700)
    assert_mode((nested / "sessions"), 0o700)


def test_ensure_home_leaves_pre_existing_directories_alone(tmp_path) -> None:
    shared = tmp_path / "share"
    shared.mkdir(mode=0o755)

    HookdConfig(home=shared / "pii-guard" / "hookd").ensure_home()

    # A directory that was already there is not ours to tighten.
    assert_mode(shared, 0o755)
    assert_mode((shared / "pii-guard"), 0o700)


def test_the_home_is_secured_before_the_sessions_directory_exists(monkeypatch, tmp_path) -> None:
    """The mappings must never sit below a boundary that is not up yet."""

    order: list[str] = []
    home = tmp_path / "hookd"
    real_secure = state.secure_private_directory

    def spy(path, *, created):
        order.append(f"secure:{(home / 'sessions').is_dir()}")
        return real_secure(path, created=created)

    monkeypatch.setattr(state, "secure_private_directory", spy)
    monkeypatch.setattr(state, "_SECURED_HOMES", set())

    HookdConfig(home=home).ensure_home()

    assert order == ["secure:False"]
    assert (home / "sessions").is_dir()


def test_the_home_boundary_is_established_once_per_process(monkeypatch, tmp_path) -> None:
    """SessionStore.save calls ensure_home on every write; securing is not free."""

    calls: list[Path] = []
    monkeypatch.setattr(state, "secure_private_directory", lambda p, *, created: calls.append(p))
    monkeypatch.setattr(state, "_SECURED_HOMES", set())
    config = HookdConfig(home=tmp_path / "hookd")

    config.ensure_home()
    config.ensure_home()
    HookdConfig(home=tmp_path / "hookd").ensure_home()

    assert calls == [(tmp_path / "hookd").resolve()]


def test_an_unverifiable_home_fails_closed(monkeypatch, tmp_path) -> None:
    def refuse(path, *, created):
        raise OSError("parent ACL is unsafe")

    monkeypatch.setattr(state, "secure_private_directory", refuse)
    monkeypatch.setattr(state, "_SECURED_HOMES", set())

    with pytest.raises(WorkflowError, match="PERMISSION_CHECK_FAILED"):
        HookdConfig(home=tmp_path / "hookd").ensure_home()


@pytest.mark.skipif(os.name != "nt", reason="Windows ACLs are platform-specific")
def test_windows_home_acl_is_applied_verified_and_tamper_evident(tmp_path) -> None:
    config = HookdConfig(home=tmp_path / "hookd")
    config.ensure_home()

    assert private_directory_acl_matches(config.home)

    icacls = Path(os.environ["SystemRoot"]) / "System32" / "icacls.exe"
    completed = subprocess.run(
        [str(icacls), str(config.home), "/grant", "*S-1-1-0:(OI)(CI)R", "/Q"],
        check=False,
        capture_output=True,
    )
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    assert not private_directory_acl_matches(config.home)

    # A home this process already secured is trusted for the rest of the run;
    # a fresh process, which is what a restart is, must refuse to reuse it.
    state._SECURED_HOMES.discard(config.home.resolve())
    with pytest.raises(WorkflowError, match="PERMISSION_CHECK_FAILED"):
        config.ensure_home()


@pytest.mark.skipif(os.name != "nt", reason="Windows ACLs are platform-specific")
def test_windows_home_under_a_shared_parent_is_refused(tmp_path) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    icacls = Path(os.environ["SystemRoot"]) / "System32" / "icacls.exe"
    completed = subprocess.run(
        [str(icacls), str(shared), "/grant", "*S-1-1-0:(OI)(CI)F", "/Q"],
        check=False,
        capture_output=True,
    )
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")

    with pytest.raises(WorkflowError, match="PERMISSION_CHECK_FAILED"):
        HookdConfig(home=shared / "hookd").ensure_home()


def test_install_leaves_the_hookd_home_owner_only(env) -> None:
    _install()

    home = env["hookd_home"]
    assert_mode(home, 0o700)
    assert_mode((home / "sessions"), 0o700)


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


# --- The Mod front end -------------------------------------------------------


@pytest.fixture
def mod_env(env, monkeypatch) -> dict[str, Path]:
    """The installation environment with plugin validation stubbed out.

    Running the real `claude plugin validate` would make these tests depend on
    a Claude Code build being present, which the installer's own logic does not.
    """

    monkeypatch.setattr(installer, "validate_plugin", lambda path: (True, "Validation passed"))
    return env


def test_mod_install_keeps_the_display_and_start_only_hooks(mod_env) -> None:
    assert _install("--mod") == 0

    settings = _settings(mod_env["settings"])
    assert sorted(settings["hooks"]) == ["MessageDisplay", "SessionStart"]


def test_mod_install_puts_the_plugin_where_the_launch_line_points(mod_env) -> None:
    _install("--mod")

    plugin = installer.mod_target(mod_env["config_dir"])
    assert (plugin / ".claude-plugin" / "plugin.json").is_file()
    assert (plugin / "hooks" / "hooks.json").is_file()
    assert (plugin / "hooks" / "register.ts").is_file()


def test_mod_install_prints_the_launch_line(mod_env, capsys) -> None:
    _install("--mod")

    out = capsys.readouterr().out
    plugin = installer.mod_target(mod_env["config_dir"])
    assert f"CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1 claude --plugin-dir {plugin}" in out


def test_mod_install_supersedes_the_classic_hooks(mod_env) -> None:
    """A classic install followed by a mod install must not leave both running."""

    _install()
    assert "PostToolUse" in _settings(mod_env["settings"])["hooks"]

    _install("--mod")

    settings = _settings(mod_env["settings"])
    assert sorted(settings["hooks"]) == ["MessageDisplay", "SessionStart"]
    assert "PostToolUse" not in settings["hooks"]
    assert "PreToolUse" not in settings["hooks"]


def test_mod_install_keeps_a_foreign_hook(mod_env) -> None:
    mod_env["settings"].write_text(
        json.dumps({"hooks": {"PreToolUse": [FOREIGN_HOOK]}}), encoding="utf-8"
    )

    _install("--mod")

    settings = _settings(mod_env["settings"])
    assert settings["hooks"]["PreToolUse"] == [FOREIGN_HOOK]
    assert sorted(settings["hooks"]) == ["MessageDisplay", "PreToolUse", "SessionStart"]


def test_mod_install_can_be_hardened(mod_env) -> None:
    assert main(["install", "--no-launchd", "--mod", "--harden"]) == 0

    settings = _settings(mod_env["settings"])
    assert settings["sandbox"] == installer.SANDBOX_BLOCK
    assert settings["permissions"]["deny"] == ["WebFetch", "WebSearch"]
    # The mod checks prompts itself, so no classic UserPromptSubmit entry.
    assert sorted(settings["hooks"]) == ["MessageDisplay", "SessionStart"]


def test_doctor_mod_reports_a_valid_plugin(mod_env, capsys) -> None:
    _install("--mod")
    capsys.readouterr()

    main(["doctor", "--mod"])

    out = capsys.readouterr().out
    assert "[OK  ] mod plugin" in out
    assert "[OK  ] mod validates" in out
    assert "[OK  ] mod launch" in out


def test_doctor_mod_fails_when_the_plugin_does_not_validate(env, monkeypatch, capsys) -> None:
    monkeypatch.setattr(installer, "validate_plugin", lambda path: (True, "ok"))
    _install("--mod")
    monkeypatch.setattr(installer, "validate_plugin", lambda path: (False, "Validation failed"))
    capsys.readouterr()

    assert main(["doctor", "--mod"]) == 1

    assert "[FAIL] mod validates: Validation failed" in capsys.readouterr().out


def test_doctor_mod_fails_without_the_plugin(env, capsys) -> None:
    _install()
    capsys.readouterr()

    assert main(["doctor", "--mod"]) == 1

    assert "[FAIL] mod plugin" in capsys.readouterr().out


def test_uninstall_removes_the_mod_plugin(mod_env) -> None:
    _install("--mod")
    plugin = installer.mod_target(mod_env["config_dir"])
    assert plugin.exists()

    assert main(["uninstall"]) == 0

    assert not plugin.exists()
    assert not plugin.is_symlink()


def test_mod_install_is_idempotent(mod_env) -> None:
    _install("--mod")
    _install("--mod")

    settings = _settings(mod_env["settings"])
    assert sorted(settings["hooks"]) == ["MessageDisplay", "SessionStart"]
    assert len(settings["hooks"]["MessageDisplay"]) == 1
    assert len(settings["hooks"]["SessionStart"]) == 1


def test_mod_install_writes_the_start_only_session_hook(mod_env) -> None:
    """Without this the guard never comes back after a stop."""

    _install("--mod")

    settings = _settings(mod_env["settings"])
    command = settings["hooks"]["SessionStart"][0]["hooks"][0]["command"]
    assert command.endswith("SessionStart --start-only")
    assert str(installer.client_target(mod_env["config_dir"])) in command
    assert settings["hooks"]["SessionStart"][0]["matcher"] == installer.SESSION_START_MATCHER


def test_classic_install_session_hook_is_not_start_only(env) -> None:
    """The classic front end still needs the greeting and the seed loading."""

    _install()

    settings = _settings(env["settings"])
    command = settings["hooks"]["SessionStart"][0]["hooks"][0]["command"]
    assert command.endswith("SessionStart")
    assert not installer.has_start_only_hook(settings)


def test_doctor_mod_reports_the_on_demand_start(mod_env, capsys) -> None:
    _install("--mod")
    capsys.readouterr()

    main(["doctor", "--mod"])

    out = capsys.readouterr().out
    assert "[OK  ] auto-start: on demand (classic SessionStart)" in out
    # The launchd branch must not add a second auto-start line.
    assert out.count("auto-start") == 1


def test_doctor_mod_fails_without_the_start_only_hook(mod_env, capsys) -> None:
    _install("--mod")
    settings = _settings(mod_env["settings"])
    del settings["hooks"]["SessionStart"]
    mod_env["settings"].write_text(json.dumps(settings), encoding="utf-8")
    capsys.readouterr()

    assert main(["doctor", "--mod"]) == 1

    assert "[FAIL] auto-start" in capsys.readouterr().out


def test_uninstall_removes_the_start_only_hook(mod_env) -> None:
    _install("--mod")

    assert main(["uninstall"]) == 0

    assert _settings(mod_env["settings"]).get("hooks") is None
