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
import shutil
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
from pii_guard.hookd import policy
from pii_guard.hookd.core import SessionStore, create_engine_with_fallback
from pii_guard.hookd.server import HookdApplication, HookdServerConfig, create_server
from pii_guard.hookd.state import HookdConfig, clear_state, read_state, write_state
from pii_guard.local_workflow import WorkflowError
from pii_guard.reference import (
    COLUMN_TYPES,
    ReferenceCache,
    ReferenceSource,
    TableReport,
    inspect_table,
    load_reference_terms,
    load_sources,
    materialize,
    normalize_type,
    register_project,
    registered_source_files,
    sources_path,
    terms_path,
    type_label,
    unregister_project,
    write_sources,
)

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
    policy_config = _load_policy()
    seed_terms = policy.load_seed_terms(policy_config.seed_terms_files)
    # A callable, not the list read at startup: a project imported later must
    # become visible on the next /v1/reload without restarting the service.
    reference = ReferenceCache(registered_source_files)
    engine, loaded_engine, fallback = create_engine_with_fallback(engine_name)
    store = SessionStore(config, engine)
    # Old mappings are the only thing that can undo a placeholder, so they are
    # swept before the service starts answering.
    expired = store.sweep_expired(session_ttl_days)
    app = HookdApplication(
        store,
        loaded_engine,
        engine_fallback=fallback,
        policy_config=policy_config,
        seed_terms=seed_terms,
        reference=reference,
    )
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
    reference_terms = len(reference.load().terms)
    seeded_total = len(seed_terms) + reference_terms
    seeds = f", {seeded_total} seed term(s)" if seeded_total else ""
    swept = f", swept {expired} expired session(s)" if expired else ""
    print(
        f"pii-guard hookd listening on 127.0.0.1:{bound_port} "
        f"(engine: {loaded_engine}, {names}{seeds}{swept})"
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


def _load_policy() -> policy.PolicyConfig:
    """Read the policy the installer wrote, if there is one."""

    path = installer.hookd_config_path()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return policy.PolicyConfig()
    if not isinstance(payload, dict):
        return policy.PolicyConfig()
    return policy.PolicyConfig.from_mapping(payload.get("policy"))


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

    plugin: Path | None = None
    if args.mod:
        plugin = installer.install_mod(config_dir)
        print(f"Installed mod plugin: {plugin}")

    backup = installer.backup_settings(settings_file)
    if backup is not None:
        print(f"Backed up settings: {backup}")
    if args.mod:
        # The Mod supersedes every classic hook but MessageDisplay, so the
        # others are cleared rather than left to run a second time.
        settings, superseded = installer.remove_hooks(settings)
        if superseded:
            print(f"Removed {superseded} classic hook entr(ies) the mod supersedes")
    merged = installer.merge_hooks(
        settings, installer.hooks_block(client, hardened=args.harden, mod=args.mod)
    )
    if args.harden:
        merged, warnings = installer.harden_settings(merged)
        for warning in warnings:
            print(f"Note: {warning}")
    installer._atomic_write(settings_file, json.dumps(merged, ensure_ascii=False, indent=2) + "\n")
    print(f"Merged hooks into: {settings_file}")
    if args.harden:
        print("Hardened: sandbox on, WebFetch and WebSearch denied, prompts checked.")

    repo = installer.repo_root()
    installer_config = installer.hookd_config_path()
    installer.write_installer_config(
        installer_config,
        repo,
        args.engine,
        seed_terms_files=installer.default_seed_terms_files(Path.cwd()),
        reference_sources=installer.default_reference_sources(Path.cwd()),
        existing_policy=_existing_policy(installer_config),
    )
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
    if plugin is not None:
        print("Start Claude Code with the mod loaded:")
        print(f"  {installer.launch_line(plugin)}")
        print("The mod only loads with that flag; without it the guard is off.")
        print()
    return _report(
        installer.doctor(
            config,
            config_dir,
            installer_config,
            args.scope,
            hardened=args.harden,
            mod=args.mod,
        )
    )


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
    stripped = installer.unharden_settings(stripped)
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

    plugin = installer.mod_target(config_dir)
    if plugin.is_symlink() or plugin.is_file():
        plugin.unlink()
        print(f"Removed mod plugin: {plugin}")
    elif plugin.is_dir():
        shutil.rmtree(plugin)
        print(f"Removed mod plugin: {plugin}")
    print("Left in place: settings backups, the installer config and stored mappings.")
    print("Run 'pii-guard-hookd purge --all' to forget stored mappings.")
    del config
    return 0


def _existing_policy(path: Path) -> dict[str, Any] | None:
    """Keep an allowlist the user edited by hand across a re-install."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    policy_block = payload.get("policy") if isinstance(payload, dict) else None
    return policy_block if isinstance(policy_block, dict) else None


def cmd_doctor(args: argparse.Namespace, config: HookdConfig) -> int:
    return _report(
        installer.doctor(
            config,
            installer.claude_config_dir(),
            installer.hookd_config_path(),
            args.scope,
            hardened=args.harden,
            mod=args.mod,
        )
    )


# ---------------------------------------------------------------------------
# Reference lists
# ---------------------------------------------------------------------------

# Every one of these prints column names, types and counts.  None of them ever
# prints a value out of the table, because this output lands in a terminal, a
# scrollback buffer and often a transcript.
TERMS_HEADER: Final[str] = "欄位 | 猜到的類型 | 筆數 | 風險筆數 | 形狀"


def _project_path(args: argparse.Namespace) -> Path:
    return Path(getattr(args, "project", None) or Path.cwd()).expanduser()


def _print_type_menu() -> list[str]:
    """Show the type table once and return the numbered order used by it."""

    order = list(COLUMN_TYPES)
    print("可選的類型：")
    for number, entity_type in enumerate(order, start=1):
        print(f"  {number:>2}. {type_label(entity_type)}（{entity_type}）")
    return order


def _render_report(report: TableReport) -> None:
    print(f"檔案：{report.path}")
    if report.sheet:
        print(f"工作表：{report.sheet}（可用：{', '.join(report.sheets)}）")
    print(f"資料列數：{report.rows}")
    print()
    print(TERMS_HEADER)
    for column in report.columns:
        shape = column.shape or "－"
        print(
            f"{column.name} | {type_label(column.guessed_type)}"
            f"（{column.guessed_type}） | {column.non_empty} | {column.risky} | {shape}"
        )


def cmd_terms_inspect(args: argparse.Namespace, _config: HookdConfig) -> int:
    report = inspect_table(args.file, sheet=args.sheet)
    if args.json:
        # Deliberately without samples: this output is meant to be safe to hand
        # to a model or paste anywhere.
        print(json.dumps(report.describe(), ensure_ascii=False, indent=2))
        return 0
    _render_report(report)
    return 0


def _parse_map(values: list[str] | None) -> dict[str, str]:
    """Read ``--map 姓名=PERSON,電話=TW_MOBILE`` into a column mapping."""

    mapping: dict[str, str] = {}
    for raw in values or []:
        for item in raw.split(","):
            entry = item.strip()
            if not entry:
                continue
            name, separator, entity_type = entry.partition("=")
            if not separator or not name.strip():
                raise WorkflowError("INVALID_MAP", "Use --map 欄位=類型 pairs.")
            mapping[name.strip()] = normalize_type(entity_type)
    return mapping


def _ask_columns(report: TableReport) -> dict[str, str]:
    """Walk the columns with the user, one confirmation each."""

    order = _print_type_menu()
    print()
    chosen: dict[str, str] = {}
    for column in report.columns:
        label = type_label(column.guessed_type)
        risky = f"，其中 {column.risky} 筆太短會略過" if column.risky else ""
        prompt = (
            f"「{column.name}」看起來是{label}（{column.non_empty} 筆{risky}）。"
            "Enter 接受／輸入編號改／s 不要遮：> "
        )
        while True:
            try:
                answer = input(prompt).strip()
            except EOFError:
                answer = ""
            if not answer:
                chosen[column.name] = column.guessed_type
                break
            if answer.lower() == "s":
                chosen[column.name] = "SKIP"
                break
            if answer.isdigit() and 1 <= int(answer) <= len(order):
                chosen[column.name] = order[int(answer) - 1]
                break
            print("請按 Enter、輸入清單裡的編號，或輸入 s。")
    return chosen


def _shape_patterns(report: TableReport, columns: dict[str, str]) -> list[tuple[str, str]]:
    """Shape rules worth registering, which is the types nothing else covers.

    A phone number or a national id already has a recognizer, so inferring a
    second pattern for it would only add work.  An order number does not.
    """

    patterns: list[tuple[str, str]] = []
    for column in report.columns:
        entity_type = columns.get(column.name, "SKIP")
        if entity_type not in {"ORDER_ID", "CUSTOM"} or not column.shape:
            continue
        patterns.append((entity_type, column.shape))
    return patterns


def _reload_service(config: HookdConfig) -> dict[str, Any] | None:
    """Ask a running service to re-read the lists; ``None`` when it is down."""

    state = _live_state(config)
    if state is None:
        return None
    try:
        return _request(state, "POST", "/v1/reload", {}, timeout=60.0)
    except (OSError, ValueError):
        return None


def _merge_source(
    existing: list[ReferenceSource], source: ReferenceSource
) -> list[ReferenceSource]:
    kept = [
        item
        for item in existing
        if not (item.path == source.path and item.sheet == source.sheet)
    ]
    kept.append(source)
    return kept


def cmd_terms_import(args: argparse.Namespace, config: HookdConfig) -> int:
    report = inspect_table(args.file, sheet=args.sheet)
    explicit = _parse_map(args.map)
    if explicit:
        columns = {
            column.name: explicit.get(column.name, "SKIP") for column in report.columns
        }
        unknown = sorted(set(explicit) - {column.name for column in report.columns})
        if unknown:
            print(f"注意：這幾欄不在檔案裡，已忽略：{', '.join(unknown)}")
    elif args.yes:
        columns = {column.name: column.guessed_type for column in report.columns}
    else:
        columns = _ask_columns(report)

    source = ReferenceSource(
        path=report.path,
        sheet=report.sheet,
        columns={name: entity for name, entity in columns.items() if entity != "SKIP"},
        patterns=tuple(_shape_patterns(report, columns)),
    )
    project = _project_path(args)
    stored = _merge_source(load_sources(project), source)
    target = write_sources(project, stored)
    print(f"已存下名單設定：{target}")
    if register_project(project):
        print("已把這個專案登記給保護服務。")

    loaded = load_reference_terms(stored)
    if args.materialize:
        written = materialize(stored, terms_path(project))
        print(f"已寫出詞表（含真實值，僅本機可讀）：{terms_path(project)}，{written} 筆")

    if not loaded.counts:
        print("這次沒有任何欄位會被遮蔽。")
    else:
        print("將自動遮蔽：")
        for entity_type, count in sorted(loaded.counts.items()):
            print(f"  {type_label(entity_type)} {count} 筆")
    if loaded.risky_skipped:
        print(f"略過 {loaded.risky_skipped} 筆過短的值（太容易誤遮）。")
    for name, regex in loaded.patterns:
        print(f"固定格式：{type_label(name)} {regex}，名單外的新值也會一起遮。")
    if loaded.truncated:
        print("注意：已達詞數上限，後面的值沒有載入。")

    reloaded = _reload_service(config)
    if reloaded is None:
        print("保護服務目前沒在跑；下次開 Claude Code 時會自動載入這份名單。")
        return 0
    loaded_count = int(reloaded.get("terms", 0) or 0)
    if loaded_count:
        print(f"保護服務已重新載入，共 {loaded_count} 筆。")
        return 0
    # Reporting a reload that loaded nothing as a success is how someone ends
    # up believing they are protected when they are not.
    print(
        "注意：保護服務載入了 0 筆。請跑 'pii-guard-hookd terms status' 查原因，"
        "常見的是欄位全設成「不要遮」，或名單檔已經被移走。",
        file=sys.stderr,
    )
    return 0


def cmd_terms_status(args: argparse.Namespace, config: HookdConfig) -> int:
    project = _project_path(args)
    sources = load_sources(project)
    print(f"名單設定：{sources_path(project)}")
    if not sources:
        print("尚未匯入任何名單。")
        return 0
    for source in sources:
        path = Path(source.path).expanduser()
        if path.is_file():
            stamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(path.stat().st_mtime))
            freshness = f"最後修改 {stamp}"
        else:
            freshness = "檔案不存在"
        sheet = f"（工作表 {source.sheet}）" if source.sheet else ""
        print(f"- {source.path}{sheet}：{len(source.columns)} 欄，{freshness}")
    loaded = load_reference_terms(sources)
    for entity_type, count in sorted(loaded.counts.items()):
        print(f"  {type_label(entity_type)} {count} 筆")
    if loaded.missing:
        print(f"  讀不到的來源：{len(loaded.missing)} 個")
    state = _live_state(config)
    if state is None:
        print("保護服務：沒在跑（下次開 Claude Code 會自動載入）")
        return 0
    try:
        health = _request(state, "GET", "/v1/health", timeout=5.0)
    except (OSError, ValueError):
        print("保護服務：有回應但拿不到狀態")
        return 0
    running = health.get("reference")
    count = running.get("terms", 0) if isinstance(running, dict) else 0
    print(f"保護服務：執行中，已載入 {count} 筆")
    return 0


def cmd_terms_remove(args: argparse.Namespace, config: HookdConfig) -> int:
    project = _project_path(args)
    if not args.all and not args.file:
        print("給一個檔案路徑，或用 --all。", file=sys.stderr)
        return 1
    sources = load_sources(project)
    if args.all:
        remaining: list[ReferenceSource] = []
    else:
        wanted = str(Path(args.file).expanduser())
        remaining = [source for source in sources if source.path != wanted]
        if len(remaining) == len(sources):
            print("這個檔案不在名單設定裡。")
            return 1
    write_sources(project, remaining)
    print(f"已移除 {len(sources) - len(remaining)} 個來源。")
    if not remaining and unregister_project(project):
        print("已把這個專案從保護服務的名單裡撤掉。")
    _reload_service(config)
    return 0


def cmd_terms_ui(args: argparse.Namespace, _config: HookdConfig) -> int:
    """Open the same local page as ``pii-guard web``, for hookd users."""

    from pii_guard.web import run_web

    run_web(port=args.port, open_browser=not args.no_open)
    return 0


TERMS_COMMANDS: Final[dict[str, Any]] = {
    "inspect": cmd_terms_inspect,
    "import": cmd_terms_import,
    "status": cmd_terms_status,
    "remove": cmd_terms_remove,
    "ui": cmd_terms_ui,
}


def cmd_terms(args: argparse.Namespace, config: HookdConfig) -> int:
    handler = TERMS_COMMANDS.get(args.terms_command)
    if handler is None:
        print("Unknown terms command.", file=sys.stderr)
        return 1
    return int(handler(args, config))


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
    setup.add_argument(
        "--mod",
        action="store_true",
        help="install the Claude Mods front end instead of the classic hooks",
    )
    setup.add_argument(
        "--harden",
        action="store_true",
        help="also sandbox the session, deny egress tools and check prompts",
    )

    remove = subparsers.add_parser("uninstall", help="remove the hooks and auto-start")
    remove.add_argument("--scope", choices=("user", "project"), default="user")

    check = subparsers.add_parser("doctor", help="check every part of the installation")
    check.add_argument("--scope", choices=("user", "project"), default="user")
    check.add_argument("--harden", action="store_true", help="also check the hardened settings")
    check.add_argument("--mod", action="store_true", help="also check the mod front end")

    terms = subparsers.add_parser("terms", help="manage the project's reference lists")
    terms_sub = terms.add_subparsers(dest="terms_command", required=True)

    inspect = terms_sub.add_parser("inspect", help="show what a table's columns look like")
    inspect.add_argument("file")
    inspect.add_argument("--sheet", default=None, help="worksheet name for .xlsx files")
    inspect.add_argument("--json", action="store_true", help="machine-readable, still no values")

    bring = terms_sub.add_parser("import", help="record a table as a reference list")
    bring.add_argument("file")
    bring.add_argument("--sheet", default=None)
    bring.add_argument(
        "--map",
        action="append",
        default=None,
        help="column to type pairs, as 姓名=PERSON,電話=TW_MOBILE",
    )
    bring.add_argument("--yes", action="store_true", help="accept every guess without asking")
    bring.add_argument(
        "--materialize",
        action="store_true",
        help="also write .pii-guard/terms.txt, which does hold the real values",
    )
    bring.add_argument("--project", default=None, help="project directory (default: cwd)")

    terms_status = terms_sub.add_parser("status", help="list the recorded lists and their counts")
    terms_status.add_argument("--project", default=None)

    terms_remove = terms_sub.add_parser("remove", help="forget one recorded list, or all of them")
    terms_remove.add_argument("file", nargs="?", default=None)
    terms_remove.add_argument("--all", action="store_true")
    terms_remove.add_argument("--project", default=None)

    terms_ui = terms_sub.add_parser("ui", help="open the local page for importing a list")
    terms_ui.add_argument("--port", type=int, default=0)
    terms_ui.add_argument("--no-open", action="store_true", help="do not open a browser")

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
        "terms": cmd_terms,
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
