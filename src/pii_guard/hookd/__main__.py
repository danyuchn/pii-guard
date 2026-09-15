"""Command line front end for the resident hookd service.

    uv run pii-guard-hookd serve [--engine regex|full] [--port N] [--foreground]
    uv run pii-guard-hookd status
    uv run pii-guard-hookd stop
    uv run pii-guard-hookd purge [session_id | --all]
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Final, cast

from pii_guard.hookd import install as installer
from pii_guard.hookd.core import SessionStore, create_engine_with_fallback
from pii_guard.hookd.server import HookdApplication, HookdServerConfig, create_server
from pii_guard.hookd.state import HookdConfig, clear_state, read_state, write_state
from pii_guard.local_workflow import WorkflowError

START_TIMEOUT_SECONDS: Final[float] = 180.0
STOP_TIMEOUT_SECONDS: Final[float] = 15.0
POLL_SECONDS: Final[float] = 0.2
DEFAULT_SESSION_TTL_DAYS: Final[float] = 14.0


def _request(
    state: dict[str, Any],
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
    *,
    timeout: float = 20.0,
) -> dict[str, Any]:
    """Call the running service; raises ``OSError`` when it is unreachable."""

    url = f"http://127.0.0.1:{state['port']}{path}"
    data = json.dumps(payload or {}).encode("utf-8") if method == "POST" else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Authorization", f"Bearer {state['token']}")
    request.add_header("Host", f"127.0.0.1:{state['port']}")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - loopback
        body = response.read()
    parsed = json.loads(body.decode("utf-8"))
    return parsed if isinstance(parsed, dict) else {}


def _pid_alive(pid: object) -> bool:
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _live_state(config: HookdConfig) -> dict[str, Any] | None:
    state = read_state(config)
    if state is None or not _pid_alive(state.get("pid")):
        return None
    return state


def _serve_foreground(
    config: HookdConfig,
    engine_name: str,
    port: int,
    session_ttl_days: float,
) -> int:
    engine, loaded_engine, fallback = create_engine_with_fallback(engine_name)
    store = SessionStore(config, engine)
    # Old mappings are the only thing that can undo a placeholder, so they are
    # swept before the service starts answering.
    expired = store.sweep_expired(session_ttl_days)
    app = HookdApplication(store, loaded_engine, engine_fallback=fallback)
    server, token, bound_port = create_server(app, HookdServerConfig(port=port))
    write_state(
        config,
        port=bound_port,
        token=token,
        pid=os.getpid(),
        engine=loaded_engine,
        started_at=time.time(),
        engine_fallback=fallback,
    )
    stopping = threading.Event()

    def _stop(_signum: int, _frame: object) -> None:
        if stopping.is_set():
            return
        stopping.set()
        # serve_forever() cannot be shut down from its own thread.
        threading.Thread(target=server.shutdown, daemon=True).start()

    for received in (signal.SIGTERM, signal.SIGINT):
        signal.signal(received, _stop)

    names = "names covered" if loaded_engine == "full" else "names NOT covered"
    swept = f", swept {expired} expired session(s)" if expired else ""
    print(
        f"pii-guard hookd listening on 127.0.0.1:{bound_port} "
        f"(engine: {loaded_engine}, {names}{swept})"
    )
    sys.stdout.flush()
    try:
        server.serve_forever()
    finally:
        server.server_close()
        clear_state(config)
    return 0


def _serve_background(
    config: HookdConfig,
    engine_name: str,
    port: int,
    session_ttl_days: float,
) -> int:
    command = [
        sys.executable,
        "-m",
        "pii_guard.hookd",
        "serve",
        "--foreground",
        "--engine",
        engine_name,
        "--port",
        str(port),
        "--session-ttl-days",
        str(session_ttl_days),
    ]
    with open(os.devnull, "wb") as sink:
        subprocess.Popen(  # noqa: S603 - fixed argv, no shell
            command,
            stdin=subprocess.DEVNULL,
            stdout=sink,
            stderr=sink,
            start_new_session=True,
            env=dict(os.environ),
        )
    deadline = time.monotonic() + START_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        state = _live_state(config)
        if state is not None:
            print(
                f"pii-guard hookd listening on 127.0.0.1:{state['port']} "
                f"(engine: {state.get('engine')}, pid: {state.get('pid')})"
            )
            return 0
        time.sleep(POLL_SECONDS)
    print("pii-guard hookd did not start in time.", file=sys.stderr)
    return 1


def cmd_serve(args: argparse.Namespace, config: HookdConfig) -> int:
    if _live_state(config) is not None:
        print("pii-guard hookd is already running.", file=sys.stderr)
        return 1
    # A stale registration from a crashed run would otherwise block startup.
    clear_state(config)
    if args.foreground:
        return _serve_foreground(config, args.engine, args.port, args.session_ttl_days)
    return _serve_background(config, args.engine, args.port, args.session_ttl_days)


def cmd_status(_args: argparse.Namespace, config: HookdConfig) -> int:
    state = read_state(config)
    if state is None:
        print("pii-guard hookd is not running (no state file).")
        return 1
    if not _pid_alive(state.get("pid")):
        print(f"pii-guard hookd is not running (stale state for pid {state.get('pid')}).")
        return 1
    try:
        health = _request(state, "GET", "/v1/health", timeout=5.0)
    except (OSError, ValueError):
        print(f"pii-guard hookd pid {state.get('pid')} is alive but did not answer /v1/health.")
        return 1
    print(
        f"pii-guard hookd running: pid {state.get('pid')}, port {state.get('port')}, "
        f"engine {health.get('engine')}, sessions {health.get('sessions')}"
    )
    return 0


def cmd_stop(_args: argparse.Namespace, config: HookdConfig) -> int:
    state = read_state(config)
    if state is None or not _pid_alive(state.get("pid")):
        clear_state(config)
        print("pii-guard hookd is not running.")
        return 0
    # _pid_alive above already established that this is a positive int.
    pid = cast(int, state["pid"])
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError as error:
        print(f"Could not signal pid {pid}: {error}", file=sys.stderr)
        return 1
    deadline = time.monotonic() + STOP_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if not _pid_alive(pid):
            clear_state(config)
            print(f"pii-guard hookd stopped (pid {pid}).")
            return 0
        time.sleep(POLL_SECONDS)
    print(
        f"pii-guard hookd pid {pid} did not exit within {STOP_TIMEOUT_SECONDS:.0f}s.",
        file=sys.stderr,
    )
    return 1


def _purge_offline(config: HookdConfig, session_id: str | None) -> int:
    # Purging only touches files, so the store is built without an engine.
    store = SessionStore(config)
    if session_id is None:
        removed = store.purge_all()
        print(f"Purged {removed} stored session mapping(s).")
        return 0
    purged = store.purge(session_id)
    print(f"Purged session {session_id}." if purged else f"No stored mapping for {session_id}.")
    return 0


def cmd_purge(args: argparse.Namespace, config: HookdConfig) -> int:
    if args.session_id is None and not args.all:
        print("Give a session id or --all.", file=sys.stderr)
        return 1
    state = _live_state(config)
    if state is None:
        return _purge_offline(config, None if args.all else args.session_id)
    targets: list[str] = []
    if args.all:
        listing = _request(state, "GET", "/v1/sessions", timeout=10.0)
        entries = listing.get("sessions")
        if isinstance(entries, list):
            targets = [
                str(entry["session_id"])
                for entry in entries
                if isinstance(entry, dict) and "session_id" in entry
            ]
    else:
        targets = [args.session_id]
    for target in targets:
        _request(state, "POST", f"/v1/sessions/{target}/purge", {}, timeout=10.0)
    # Files belonging to sessions the running service never loaded stay behind.
    _purge_offline(config, None if args.all else args.session_id)
    return 0


def _start_now(config: HookdConfig, repo: Path, engine: str) -> None:
    """Leave the service running, so install never ends on a dead guard."""

    if installer.service_health(config) is not None:
        print("Service: already running.")
        return
    if not installer.start_service_detached(repo, engine):
        print("Service: could not be started; it will start at the next session.")
        return
    wait = " (the full engine loads a model, so this can take a while)" if engine == "full" else ""
    print(f"Starting the service{wait}...")
    if installer.wait_for_health(config) is None:
        print("Service: still loading; it will be ready shortly.")


def _report(results: list[installer.CheckResult]) -> int:
    for result in results:
        print(result.render())
    failed = [result for result in results if not result.ok and not result.warn]
    if failed:
        print(f"\n{len(failed)} check(s) failed.")
        return 1
    print("\nEverything checks out.")
    return 0


def cmd_install(args: argparse.Namespace, config: HookdConfig) -> int:
    config_dir = installer.claude_config_dir()
    # Create the private directories before anything writes into them, so they
    # are owner-only from the first moment rather than tightened later.
    config.ensure_home()
    settings_file = installer.settings_path(config_dir, args.scope)
    # Parse before touching anything: a settings file we cannot read must be
    # left exactly as it is rather than replaced with our block alone.
    settings = installer._load_settings(settings_file)

    client = installer.install_client(config_dir)
    print(f"Installed hook client: {client}")

    backup = installer.backup_settings(settings_file)
    if backup is not None:
        print(f"Backed up settings: {backup}")
    merged = installer.merge_hooks(settings, installer.hooks_block(client))
    installer._atomic_write(settings_file, json.dumps(merged, ensure_ascii=False, indent=2) + "\n")
    print(f"Merged hooks into: {settings_file}")

    repo = installer.repo_root()
    installer_config = installer.hookd_config_path()
    installer.write_installer_config(installer_config, repo, args.engine)
    print(f"Wrote config: {installer_config}")

    if args.no_launchd or sys.platform != "darwin":
        reason = "skipped" if args.no_launchd else "not macOS"
        print(f"Auto-start agent: {reason}; the hook client starts the service on demand.")
        _start_now(config, repo, args.engine)
    else:
        plist = installer.launch_agent_path()
        installer.write_launch_agent(plist, installer.serve_command(repo, args.engine), config.home)
        loaded, detail = installer.load_launch_agent(plist)
        print(f"Auto-start agent: {'loaded' if loaded else 'FAILED'} ({detail})")
        if loaded:
            print("Waiting for the service to answer...")
            installer.wait_for_health(config)
        else:
            _start_now(config, repo, args.engine)

    print()
    return _report(installer.doctor(config, config_dir, installer_config, args.scope))


def cmd_uninstall(args: argparse.Namespace, config: HookdConfig) -> int:
    config_dir = installer.claude_config_dir()
    settings_file = installer.settings_path(config_dir, args.scope)

    if sys.platform == "darwin":
        plist = installer.launch_agent_path()
        if plist.exists():
            installer.unload_launch_agent(plist)
            plist.unlink(missing_ok=True)
            print(f"Removed auto-start agent: {plist}")

    try:
        settings = installer._load_settings(settings_file)
    except WorkflowError as error:
        print(f"{error.message} Remove the pii-guard hooks by hand.", file=sys.stderr)
        return 1
    stripped, removed = installer.remove_hooks(settings)
    if removed:
        backup = installer.backup_settings(settings_file)
        if backup is not None:
            print(f"Backed up settings: {backup}")
        installer._atomic_write(
            settings_file, json.dumps(stripped, ensure_ascii=False, indent=2) + "\n"
        )
    print(f"Removed {removed} hook entr(ies) from {settings_file}")

    client = installer.client_target(config_dir)
    client.unlink(missing_ok=True)
    print(f"Removed hook client: {client}")
    print("Left in place: settings backups, the installer config and stored mappings.")
    print("Run 'pii-guard-hookd purge --all' to forget stored mappings.")
    del config
    return 0


def cmd_doctor(args: argparse.Namespace, config: HookdConfig) -> int:
    return _report(
        installer.doctor(
            config,
            installer.claude_config_dir(),
            installer.hookd_config_path(),
            args.scope,
        )
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pii-guard-hookd",
        description="Resident localhost redaction service for Claude Code hooks.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve = subparsers.add_parser("serve", help="start the service")
    serve.add_argument("--engine", choices=("regex", "full"), default="full")
    serve.add_argument("--port", type=int, default=0)
    serve.add_argument(
        "--session-ttl-days",
        type=float,
        default=DEFAULT_SESSION_TTL_DAYS,
        help="delete stored mappings older than this at start (0 disables)",
    )
    serve.add_argument(
        "--foreground",
        action="store_true",
        help="stay attached instead of detaching into the background",
    )

    setup = subparsers.add_parser("install", help="install the hooks and auto-start")
    setup.add_argument("--engine", choices=("regex", "full"), default="full")
    setup.add_argument("--scope", choices=("user", "project"), default="user")
    setup.add_argument("--no-launchd", action="store_true", help="do not register auto-start")

    remove = subparsers.add_parser("uninstall", help="remove the hooks and auto-start")
    remove.add_argument("--scope", choices=("user", "project"), default="user")

    check = subparsers.add_parser("doctor", help="check every part of the installation")
    check.add_argument("--scope", choices=("user", "project"), default="user")

    subparsers.add_parser("status", help="report whether the service is running")
    subparsers.add_parser("stop", help="stop the running service")

    purge = subparsers.add_parser("purge", help="forget stored session mappings")
    purge.add_argument("session_id", nargs="?", default=None)
    purge.add_argument("--all", action="store_true", help="forget every session")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config = HookdConfig.from_env()
    commands = {
        "serve": cmd_serve,
        "install": cmd_install,
        "uninstall": cmd_uninstall,
        "doctor": cmd_doctor,
        "status": cmd_status,
        "stop": cmd_stop,
        "purge": cmd_purge,
    }
    try:
        return commands[args.command](args, config)
    except WorkflowError as error:
        print(f"{error.code}: {error.message}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
