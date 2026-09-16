"""One-command setup for the hookd service and its Claude Code hooks.

Everything here is reversible and non-destructive: the settings file is backed
up before it is touched, only entries this installer recognises as its own are
ever removed, and a settings file that does not parse is refused rather than
overwritten.
"""

from __future__ import annotations

import json
import os
import plistlib
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from pii_guard.hookd.state import HookdConfig, read_state
from pii_guard.local_workflow import JOB_MODE, PRIVATE_MODE, WorkflowError

CLIENT_NAME: Final[str] = "pii_guard_hook_client.py"
# Every hook entry this installer owns carries the marker, so a re-run can
# recognise its own work even if the client has been moved.
HOOK_MARKER: Final[str] = "pii-guard"
LAUNCH_LABEL: Final[str] = "com.pii-guard.hookd"
CONFIG_ENV_VAR: Final[str] = "PII_GUARD_HOOKD_CONFIG"
CLAUDE_CONFIG_ENV_VAR: Final[str] = "CLAUDE_CONFIG_DIR"
DEFAULT_CLAUDE_CONFIG_DIR: Final[str] = "~/.claude"
DEFAULT_CONFIG_PATH: Final[str] = "~/.config/pii-guard/hookd.json"
POST_TOOL_MATCHER: Final[str] = "Read|Bash|Grep|mcp__.*"
PRE_TOOL_MATCHER: Final[str] = "Write|Edit|MultiEdit|Bash"
# Hardened mode also intercepts the tools that can carry content off the box.
HARDENED_PRE_TOOL_MATCHER: Final[str] = (
    "Write|Edit|MultiEdit|Bash|WebFetch|WebSearch|Agent|Task|Workflow|mcp__.*"
)
DENIED_PERMISSIONS: Final[tuple[str, ...]] = ("WebFetch", "WebSearch")
SANDBOX_BLOCK: Final[dict[str, Any]] = {
    "enabled": True,
    "failIfUnavailable": True,
    "allowUnsandboxedCommands": False,
    "network": {"allowedDomains": []},
}
SEED_TERMS_RELATIVE: Final[str] = ".pii-guard/terms.txt"
# The reference-list description: which columns of which table mean what.  It
# holds no values, so it is the file the installer points the service at.
REFERENCE_SOURCES_RELATIVE: Final[str] = ".pii-guard/sources.json"
# The Mod front end: a plugin directory whose hooks module replaces every
# classic hook except MessageDisplay, which has no function-hook equivalent
# because display-only restore does not exist in that API.
MOD_DIRECTORY: Final[str] = "claude-code-mod"
MOD_NAME: Final[str] = "pii-guard"
FUNCTION_HOOKS_ENV_VAR: Final[str] = "CLAUDE_CODE_ENABLE_FUNCTION_HOOKS"
# Tells the hook client to start the service and print nothing else.
START_ONLY_FLAG: Final[str] = "--start-only"
SESSION_START_MATCHER: Final[str] = "startup|resume|clear"
HEALTH_TIMEOUT_SECONDS: Final[float] = 90.0
POLL_SECONDS: Final[float] = 0.4


@dataclass(frozen=True)
class CheckResult:
    """One line of the doctor report.

    A warning is not a failure: it reports something the user should know
    without making the whole report, and the exit code, say the install is
    broken.
    """

    name: str
    ok: bool
    detail: str
    warn: bool = False

    def render(self) -> str:
        if self.warn:
            label = "WARN"
        else:
            label = "OK  " if self.ok else "FAIL"
        return f"[{label}] {self.name}: {self.detail}"


def claude_config_dir(env: dict[str, str] | None = None) -> Path:
    """Resolve Claude Code's configuration directory."""

    source = os.environ if env is None else env
    raw = source.get(CLAUDE_CONFIG_ENV_VAR, "").strip()
    return Path(raw or DEFAULT_CLAUDE_CONFIG_DIR).expanduser()


def hookd_config_path(env: dict[str, str] | None = None) -> Path:
    """Resolve the installer's own configuration file."""

    source = os.environ if env is None else env
    raw = source.get(CONFIG_ENV_VAR, "").strip()
    return Path(raw or DEFAULT_CONFIG_PATH).expanduser()


def repo_root() -> Path:
    """Find the checkout this package was imported from."""

    for candidate in Path(__file__).resolve().parents:
        if (candidate / "pyproject.toml").is_file():
            return candidate
    raise WorkflowError("REPO_NOT_FOUND", "Could not locate the pii-guard checkout.")


def client_source() -> Path:
    """Locate the hook client shipped with this checkout."""

    path = repo_root() / "examples" / "claude-code-hookd" / CLIENT_NAME
    if not path.is_file():
        raise WorkflowError("CLIENT_NOT_FOUND", "The hook client source is missing.")
    return path


def client_target(config_dir: Path) -> Path:
    return config_dir / "hooks" / HOOK_MARKER / CLIENT_NAME


def mod_source() -> Path:
    """Locate the Mod plugin directory shipped with this checkout."""

    path = repo_root() / "examples" / MOD_DIRECTORY
    if not (path / ".claude-plugin" / "plugin.json").is_file():
        raise WorkflowError("MOD_NOT_FOUND", "The Mod plugin directory is missing.")
    return path


def mod_target(config_dir: Path) -> Path:
    return config_dir / "plugins" / MOD_NAME


def install_mod(config_dir: Path) -> Path:
    """Point a stable path at the Mod, so the launch line never moves.

    A symlink keeps the plugin current when the checkout is updated; where one
    cannot be made the directory is copied instead.
    """

    target = mod_target(config_dir)
    target.parent.mkdir(parents=True, exist_ok=True, mode=JOB_MODE)
    source = mod_source()
    if target.is_symlink() or target.is_file():
        target.unlink()
    elif target.is_dir():
        shutil.rmtree(target)
    try:
        target.symlink_to(source, target_is_directory=True)
    except OSError:
        shutil.copytree(source, target)
    return target


def launch_line(plugin_dir: Path) -> str:
    """The exact command that starts Claude Code with the Mod loaded."""

    return f"{FUNCTION_HOOKS_ENV_VAR}=1 claude --plugin-dir {plugin_dir}"


def validate_plugin(plugin_dir: Path) -> tuple[bool, str]:
    """Ask Claude Code whether the plugin loads. Tests monkeypatch this."""

    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["claude", "plugin", "validate", str(plugin_dir)],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
            env={**os.environ, FUNCTION_HOOKS_ENV_VAR: "1"},
        )
    except (OSError, subprocess.SubprocessError) as error:
        return False, str(error)
    output = (completed.stdout or completed.stderr).strip().splitlines()
    detail = output[-1].strip() if output else "no output"
    return completed.returncode == 0, detail


def settings_path(config_dir: Path, scope: str) -> Path:
    if scope == "user":
        return config_dir / "settings.json"
    if scope == "project":
        return Path.cwd() / ".claude" / "settings.json"
    raise WorkflowError("INVALID_SCOPE", "The installation scope is invalid.")


def serve_command(repo: Path, engine: str) -> list[str]:
    """The command that runs the service in the foreground."""

    return [
        "uv",
        "run",
        "--project",
        str(repo),
        "pii-guard-hookd",
        "serve",
        "--foreground",
        "--engine",
        engine,
    ]


def hooks_block(
    client_path: Path, *, hardened: bool = False, mod: bool = False
) -> dict[str, list[dict[str, Any]]]:
    """Build the hooks this installer owns, all tagged with the marker.

    With the Mod loaded the hooks module supersedes almost all of these, and
    running both would redact twice and greet twice.  Two entries survive.
    MessageDisplay, because showing the user real values while the model keeps
    placeholders has no equivalent in the function-hook API.  And a SessionStart
    that only starts the service: a hooks module cannot spawn one that outlives
    the session, so without this entry nothing brings the guard back after a
    stop, and every later session is dead until the user runs serve by hand.
    """

    def entry(
        event: str,
        message: str,
        matcher: str | None = None,
        arguments: str = "",
    ) -> dict[str, Any]:
        command = f'python3 "{client_path}" {event}'
        block: dict[str, Any] = {
            "hooks": [
                {
                    "type": "command",
                    "command": f"{command} {arguments}".rstrip(),
                    "statusMessage": message,
                }
            ]
        }
        if matcher is not None:
            block["matcher"] = matcher
        return block

    if mod:
        return {
            "SessionStart": [
                entry(
                    "SessionStart",
                    "pii-guard: starting guard",
                    SESSION_START_MATCHER,
                    START_ONLY_FLAG,
                )
            ],
            "MessageDisplay": [entry("MessageDisplay", "pii-guard: restoring display")],
        }

    block: dict[str, list[dict[str, Any]]] = {
        "SessionStart": [
            entry("SessionStart", "pii-guard: checking guard", SESSION_START_MATCHER)
        ],
        "PostToolUse": [
            entry("PostToolUse", "pii-guard: de-identifying output", POST_TOOL_MATCHER)
        ],
        "PreToolUse": [
            entry(
                "PreToolUse",
                "pii-guard: restoring values",
                HARDENED_PRE_TOOL_MATCHER if hardened else PRE_TOOL_MATCHER,
            )
        ],
        "MessageDisplay": [entry("MessageDisplay", "pii-guard: restoring display")],
    }
    if hardened:
        block["UserPromptSubmit"] = [entry("UserPromptSubmit", "pii-guard: checking prompt")]
    return block


def harden_settings(settings: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Add the sandbox and egress denials, never overwriting what is there.

    An existing sandbox block is the user's own decision about how their
    machine runs, so it is reported rather than replaced.
    """

    merged = dict(settings)
    warnings: list[str] = []

    if "sandbox" in merged:
        warnings.append(
            "A sandbox block already exists and was left alone. For full hardening it "
            "should set enabled true, failIfUnavailable true, allowUnsandboxedCommands "
            "false and an empty network.allowedDomains."
        )
    else:
        merged["sandbox"] = json.loads(json.dumps(SANDBOX_BLOCK))

    permissions = dict(merged.get("permissions") or {})
    if not isinstance(merged.get("permissions", {}), dict):
        warnings.append("The permissions key is not an object and was left alone.")
        return merged, warnings
    deny = list(permissions.get("deny") or []) if isinstance(permissions.get("deny"), list) else []
    for tool in DENIED_PERMISSIONS:
        if tool not in deny:
            deny.append(tool)
    permissions["deny"] = deny
    merged["permissions"] = permissions
    return merged, warnings


def unharden_settings(settings: dict[str, Any]) -> dict[str, Any]:
    """Remove only the exact values this installer added."""

    merged = dict(settings)
    if merged.get("sandbox") == SANDBOX_BLOCK:
        merged.pop("sandbox")
    permissions = merged.get("permissions")
    if isinstance(permissions, dict) and isinstance(permissions.get("deny"), list):
        permissions = dict(permissions)
        deny = [item for item in permissions["deny"] if item not in DENIED_PERMISSIONS]
        if deny:
            permissions["deny"] = deny
        else:
            permissions.pop("deny")
        if permissions:
            merged["permissions"] = permissions
        else:
            merged.pop("permissions")
    return merged


def default_seed_terms_files(project: Path) -> list[str]:
    """The project's own term list, when it has one."""

    candidate = project / SEED_TERMS_RELATIVE
    return [str(candidate)] if candidate.is_file() else []


def default_reference_sources(project: Path) -> list[str]:
    """The project's reference-list description, when it has one."""

    candidate = project / REFERENCE_SOURCES_RELATIVE
    return [str(candidate)] if candidate.is_file() else []


def _is_ours(entry: object) -> bool:
    """Recognise an entry this installer wrote, wherever the client now lives."""

    if not isinstance(entry, dict):
        return False
    for hook in entry.get("hooks", []) or []:
        if not isinstance(hook, dict):
            continue
        if CLIENT_NAME in str(hook.get("command", "")):
            return True
        if HOOK_MARKER in str(hook.get("statusMessage", "")):
            return True
    return False


def _load_settings(path: Path) -> dict[str, Any]:
    """Read a settings file, refusing rather than clobbering a broken one."""

    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise WorkflowError(
            "SETTINGS_UNREADABLE",
            f"{path} could not be parsed; it was left untouched.",
        ) from error
    if not isinstance(payload, dict):
        raise WorkflowError(
            "SETTINGS_UNREADABLE",
            f"{path} is not a JSON object; it was left untouched.",
        )
    return payload


def merge_hooks(settings: dict[str, Any], block: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    """Add our hooks, keeping every other key and every foreign hook.

    Re-running replaces our own entries instead of stacking another copy.
    """

    merged = dict(settings)
    hooks = dict(merged.get("hooks") or {}) if isinstance(merged.get("hooks"), dict) else {}
    for event, entries in block.items():
        existing = hooks.get(event)
        kept: list[Any] = []
        if isinstance(existing, list):
            kept = [item for item in existing if not _is_ours(item)]
        hooks[event] = kept + entries
    merged["hooks"] = hooks
    return merged


def remove_hooks(settings: dict[str, Any]) -> tuple[dict[str, Any], int]:
    """Strip only our entries; returns the settings and how many went."""

    merged = dict(settings)
    raw = merged.get("hooks")
    if not isinstance(raw, dict):
        return merged, 0
    hooks: dict[str, Any] = {}
    removed = 0
    for event, entries in raw.items():
        if not isinstance(entries, list):
            hooks[event] = entries
            continue
        kept = [item for item in entries if not _is_ours(item)]
        removed += len(entries) - len(kept)
        if kept:
            hooks[event] = kept
    if hooks:
        merged["hooks"] = hooks
    else:
        merged.pop("hooks", None)
    return merged, removed


def _atomic_write(path: Path, data: str, *, mode: int | None = None) -> None:
    """Replace a file in one step, keeping its current permissions."""

    path.parent.mkdir(parents=True, exist_ok=True)
    if mode is None:
        mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else PRIVATE_MODE
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def backup_settings(path: Path) -> Path | None:
    """Copy the settings file aside before changing it."""

    if not path.exists():
        return None
    backup = path.with_name(f"{path.name}.bak-{time.strftime('%Y%m%d-%H%M%S')}")
    shutil.copy2(path, backup)
    return backup


def write_installer_config(
    path: Path,
    repo: Path,
    engine: str,
    *,
    seed_terms_files: list[str] | None = None,
    reference_sources: list[str] | None = None,
    existing_policy: Mapping[str, Any] | None = None,
) -> None:
    """Record what the hook client needs in order to start the service."""

    path.parent.mkdir(parents=True, exist_ok=True, mode=JOB_MODE)
    # A re-run must not silently drop an allowlist the user added by hand.
    policy_block: dict[str, Any] = dict(existing_policy or {})
    policy_block.setdefault("allowed_tools", [])
    policy_block.setdefault("encoders_extra", [])
    policy_block.setdefault("network_extra", [])
    policy_block.setdefault("output_gate", True)
    if seed_terms_files or "seed_terms_files" not in policy_block:
        policy_block["seed_terms_files"] = seed_terms_files or []
    # Projects register themselves as they are imported, so a re-run of install
    # must add to that list rather than replace it with whatever is in cwd.
    known = [
        item
        for item in policy_block.get("reference_sources") or []
        if isinstance(item, str) and item.strip()
    ]
    for descriptor in reference_sources or []:
        if descriptor not in known:
            known.append(descriptor)
    policy_block["reference_sources"] = known
    payload = {
        "repo": str(repo),
        "engine": engine,
        "serve_command": serve_command(repo, engine),
        "policy": policy_block,
    }
    _atomic_write(path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n", mode=PRIVATE_MODE)


def install_client(config_dir: Path) -> Path:
    """Copy the hook client into the Claude Code configuration directory."""

    target = client_target(config_dir)
    target.parent.mkdir(parents=True, exist_ok=True, mode=JOB_MODE)
    shutil.copyfile(client_source(), target)
    target.chmod(0o700)
    return target


def detached_serve_command(repo: Path, engine: str) -> list[str]:
    """The serve command without the flag that keeps it in the foreground."""

    return [part for part in serve_command(repo, engine) if part != "--foreground"]


def start_service_detached(repo: Path, engine: str) -> bool:
    """Spawn the service so it outlives this process."""

    try:
        subprocess.Popen(  # noqa: S603 - fixed argv, no shell
            detached_serve_command(repo, engine),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except (OSError, ValueError):
        return False
    return True


def launch_agent_path() -> Path:
    return Path("~/Library/LaunchAgents").expanduser() / f"{LAUNCH_LABEL}.plist"


def run_launchctl(arguments: list[str]) -> tuple[int, str]:
    """Call launchctl. Tests monkeypatch this; nothing else shells out."""

    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["launchctl", *arguments],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return 1, str(error)
    return completed.returncode, (completed.stderr or completed.stdout).strip()


def write_launch_agent(path: Path, command: list[str], hookd_home: Path) -> None:
    """Write the LaunchAgent that keeps the service running."""

    path.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "Label": LAUNCH_LABEL,
        "ProgramArguments": command,
        "RunAtLoad": True,
        "KeepAlive": True,
        "ProcessType": "Background",
        "StandardOutPath": os.devnull,
        # The service never logs request bodies, so this only ever holds
        # start-up diagnostics such as the engine fallback line.
        "StandardErrorPath": str(hookd_home / "hookd.err"),
    }
    path.write_bytes(plistlib.dumps(payload))


def load_launch_agent(path: Path) -> tuple[bool, str]:
    """Bootstrap the agent, falling back to the older load verb."""

    code, message = run_launchctl(["bootstrap", f"gui/{os.getuid()}", str(path)])
    if code == 0:
        return True, "bootstrapped"
    code, fallback = run_launchctl(["load", "-w", str(path)])
    if code == 0:
        return True, "loaded"
    return False, message or fallback


def unload_launch_agent(path: Path) -> None:
    code, _ = run_launchctl(["bootout", f"gui/{os.getuid()}/{LAUNCH_LABEL}"])
    if code != 0:
        run_launchctl(["unload", "-w", str(path)])


def launch_agent_loaded() -> bool:
    code, _ = run_launchctl(["print", f"gui/{os.getuid()}/{LAUNCH_LABEL}"])
    return code == 0


def service_health(config: HookdConfig, timeout: float = 5.0) -> dict[str, Any] | None:
    """Ask the running service how it is; ``None`` when unreachable."""

    state = read_state(config)
    if state is None:
        return None
    request = urllib.request.Request(
        f"http://127.0.0.1:{state['port']}/v1/health",
        method="GET",
    )
    request.add_header("Authorization", f"Bearer {state['token']}")
    request.add_header("Host", f"127.0.0.1:{state['port']}")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            payload = json.loads(response.read().decode("utf-8"))
    except (OSError, ValueError, urllib.error.URLError):
        return None
    return payload if isinstance(payload, dict) else None


def wait_for_health(config: HookdConfig, timeout: float = HEALTH_TIMEOUT_SECONDS) -> dict | None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        health = service_health(config)
        if health is not None:
            return health
        time.sleep(POLL_SECONDS)
    return None


def doctor(
    config: HookdConfig,
    config_dir: Path,
    installer_config: Path,
    scope: str = "user",
    *,
    check_launchd: bool | None = None,
    hardened: bool = False,
    mod: bool = False,
) -> list[CheckResult]:
    """Check every moving part and report one line each."""

    if check_launchd is None:
        check_launchd = sys.platform == "darwin"
    results: list[CheckResult] = []

    client = client_target(config_dir)
    if client.is_file() and os.access(client, os.X_OK):
        results.append(CheckResult("hook client", True, str(client)))
    elif client.is_file():
        results.append(CheckResult("hook client", False, f"{client} is not executable"))
    else:
        results.append(CheckResult("hook client", False, f"missing at {client}"))

    settings_file = settings_path(config_dir, scope)
    try:
        settings = _load_settings(settings_file)
    except WorkflowError as error:
        settings = {}
        results.append(CheckResult("settings", False, error.message))
    else:
        raw_hooks = settings.get("hooks")
        events = sorted(
            event
            for event, entries in (raw_hooks or {}).items()
            if isinstance(entries, list) and any(_is_ours(item) for item in entries)
        )
        expected = sorted(hooks_block(client, hardened=hardened, mod=mod))
        if events == expected:
            detail = f"{settings_file} ({len(events)})"
            results.append(CheckResult("hooks in settings", True, detail))
        else:
            missing = sorted(set(expected) - set(events))
            results.append(
                CheckResult("hooks in settings", False, f"missing {', '.join(missing) or 'all'}")
            )

    if installer_config.is_file():
        results.append(CheckResult("installer config", True, str(installer_config)))
    else:
        results.append(CheckResult("installer config", False, f"missing at {installer_config}"))

    if mod:
        results.extend(_mod_checks(config_dir, settings))

    if hardened:
        results.extend(_hardening_checks(settings))

    # Only report on the agent when one was actually installed.  A user who
    # chose --no-launchd relies on the hook client's on-demand start instead,
    # and a missing agent is not a fault in that setup.
    if check_launchd and launch_agent_path().exists():
        loaded = launch_agent_loaded()
        results.append(
            CheckResult("launchd agent", loaded, LAUNCH_LABEL if loaded else "not loaded")
        )
    elif check_launchd and not mod:
        results.append(
            CheckResult("auto-start", True, "on demand from the hook client (no launchd agent)")
        )

    health = service_health(config)
    if health is None and installer_config.is_file():
        results.append(
            CheckResult(
                "service",
                True,
                "not running (starts on demand at next session)",
                warn=True,
            )
        )
    elif health is None:
        results.append(CheckResult("service", False, "not reachable on 127.0.0.1"))
    else:
        sessions = health.get("sessions", 0)
        results.append(CheckResult("service", True, f"healthy, {sessions} session(s)"))
        described = health.get("policy")
        if isinstance(described, Mapping):
            gate = "output gate on" if described.get("output_gate") else "output gate OFF"
            allowed = described.get("allowed_tools") or []
            results.append(
                CheckResult("policy", True, f"active, {gate}, {len(allowed)} allowlisted tool(s)")
            )
        else:
            results.append(
                CheckResult("policy", False, "the running service predates the policy rules")
            )
        if health.get("engine_fallback"):
            results.append(
                CheckResult("engine", False, "full engine failed to load; names NOT covered")
            )
        elif health.get("names_covered"):
            results.append(CheckResult("engine", True, "full, names covered"))
        else:
            results.append(CheckResult("engine", True, "regex by choice, names NOT covered"))

    results.extend(_reference_checks(installer_config))

    sessions_dir = config.sessions_dir
    if not sessions_dir.is_dir():
        results.append(CheckResult("session store", True, "no mappings stored yet"))
    elif stat.S_IMODE(sessions_dir.stat().st_mode) == JOB_MODE:
        results.append(CheckResult("session store", True, f"{sessions_dir} is owner only"))
    else:
        results.append(CheckResult("session store", False, f"{sessions_dir} is not mode 0700"))

    return results


def _reference_checks(installer_config: Path) -> list[CheckResult]:
    """Report each reference source: is it there, and how much does it add?

    Counts only.  Nothing in a doctor report is ever a value from the list.
    """

    from pii_guard import reference as reference_module

    try:
        payload = json.loads(installer_config.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    policy_block = payload.get("policy") if isinstance(payload, dict) else None
    raw = policy_block.get("reference_sources") if isinstance(policy_block, Mapping) else None
    files = [item for item in raw or [] if isinstance(item, str) and item.strip()]
    if not files:
        return []
    results: list[CheckResult] = []
    for descriptor in files:
        sources = reference_module.load_sources_file(descriptor)
        if not sources:
            results.append(CheckResult("reference list", False, f"unreadable: {descriptor}"))
            continue
        loaded = reference_module.load_reference_terms(sources)
        for source in sources:
            present = Path(source.path).expanduser().is_file()
            detail = (
                f"{source.path}: {len(source.columns)} column(s), "
                f"{len(source.patterns)} shape rule(s)"
            )
            results.append(
                CheckResult(
                    "reference source",
                    present,
                    detail if present else f"missing file {source.path}",
                )
            )
        results.append(
            CheckResult("reference terms", True, f"{len(loaded.terms)} term(s) loaded")
        )
    return results


def has_start_only_hook(settings: Mapping[str, Any]) -> bool:
    """Is the classic SessionStart entry that starts the service present?"""

    entries = (settings.get("hooks") or {}).get("SessionStart")
    if not isinstance(entries, list):
        return False
    for entry in entries:
        if not _is_ours(entry):
            continue
        for hook in entry.get("hooks", []) or []:
            if isinstance(hook, dict) and START_ONLY_FLAG in str(hook.get("command", "")):
                return True
    return False


def _mod_checks(config_dir: Path, settings: Mapping[str, Any]) -> list[CheckResult]:
    """Report that the plugin is in place and that Claude Code accepts it."""

    results: list[CheckResult] = []
    plugin = mod_target(config_dir)
    if not (plugin / ".claude-plugin" / "plugin.json").is_file():
        results.append(CheckResult("mod plugin", False, f"missing at {plugin}"))
        return results
    results.append(CheckResult("mod plugin", True, str(plugin)))
    ok, detail = validate_plugin(plugin)
    results.append(CheckResult("mod validates", ok, detail))
    results.append(CheckResult("mod launch", True, launch_line(plugin)))
    if has_start_only_hook(settings):
        results.append(
            CheckResult("auto-start", True, "on demand (classic SessionStart)")
        )
    else:
        results.append(
            CheckResult(
                "auto-start",
                False,
                "no classic SessionStart entry, so a stopped service never comes back",
            )
        )
    return results


def _hardening_checks(settings: Mapping[str, Any]) -> list[CheckResult]:
    """Report the settings that hardening is supposed to have put in place."""

    results: list[CheckResult] = []
    sandbox = settings.get("sandbox")
    if not isinstance(sandbox, Mapping):
        results.append(CheckResult("sandbox", False, "no sandbox block in settings"))
    elif sandbox.get("enabled") and not sandbox.get("allowUnsandboxedCommands", False):
        domains = (sandbox.get("network") or {}).get("allowedDomains")
        detail = "enabled"
        if isinstance(domains, list) and domains:
            detail = f"enabled, {len(domains)} allowed domain(s)"
        results.append(CheckResult("sandbox", True, detail))
    else:
        results.append(
            CheckResult("sandbox", True, "present but permissive; review it by hand", warn=True)
        )

    permissions = settings.get("permissions")
    deny = permissions.get("deny") if isinstance(permissions, Mapping) else None
    missing = [tool for tool in DENIED_PERMISSIONS if tool not in (deny or [])]
    if missing:
        results.append(CheckResult("egress denied", False, f"missing {', '.join(missing)}"))
    else:
        results.append(CheckResult("egress denied", True, ", ".join(DENIED_PERMISSIONS)))
    return results
