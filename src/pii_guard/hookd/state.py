"""On-disk location and connection state for the resident hookd service.

The service advertises its port and bearer token through two owner-only files
so the dependency-free hook client can find it without importing anything from
this project.  ``state.json`` is for programs, ``state.env`` for shells.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from pii_guard.local_workflow import (
    JOB_MODE,
    PRIVATE_MODE,
    WorkflowError,
    _assert_owner_mode,
    _write_private,
)

HOME_ENV_VAR: Final[str] = "PII_GUARD_HOOKD_HOME"
DEFAULT_HOME: Final[Path] = Path("~/.local/share/pii-guard/hookd")
STATE_FILE_NAME: Final[str] = "state.json"
STATE_ENV_NAME: Final[str] = "state.env"
SESSIONS_DIR_NAME: Final[str] = "sessions"
STATE_VERSION: Final[int] = 1

# Shell-safe values only: the env file is meant to be sourced or parsed with a
# trivial split, so anything that could inject a newline or quote is rejected.
_TOKEN_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_-]{16,256}$")


@dataclass(frozen=True)
class HookdConfig:
    """Resolved on-disk layout for one hookd installation."""

    home: Path

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> HookdConfig:
        """Resolve the hookd home, honouring ``PII_GUARD_HOOKD_HOME``."""

        source = os.environ if env is None else env
        raw = source.get(HOME_ENV_VAR, "").strip()
        home = Path(raw).expanduser() if raw else DEFAULT_HOME.expanduser()
        return cls(home=home)

    @property
    def state_path(self) -> Path:
        return self.home / STATE_FILE_NAME

    @property
    def state_env_path(self) -> Path:
        return self.home / STATE_ENV_NAME

    @property
    def sessions_dir(self) -> Path:
        return self.home / SESSIONS_DIR_NAME

    def ensure_home(self) -> None:
        """Create the owner-only home and sessions directories."""

        self.home.mkdir(parents=True, exist_ok=True, mode=JOB_MODE)
        self.sessions_dir.mkdir(parents=True, exist_ok=True, mode=JOB_MODE)
        # mkdir honours the mode only when it actually creates the directory,
        # so an inherited-permission directory from an older run is tightened.
        self.home.chmod(JOB_MODE)
        self.sessions_dir.chmod(JOB_MODE)
        _assert_owner_mode(self.home, JOB_MODE, directory=True)
        _assert_owner_mode(self.sessions_dir, JOB_MODE, directory=True)


def write_state(
    config: HookdConfig,
    *,
    port: int,
    token: str,
    pid: int,
    engine: str,
    started_at: float,
) -> None:
    """Write both state files atomically with mode 0600."""

    if not _TOKEN_PATTERN.fullmatch(token):
        raise WorkflowError("INVALID_TOKEN", "The service token is invalid.")
    if not 1 <= port <= 65535:
        raise WorkflowError("INVALID_PORT", "The service port is invalid.")
    config.ensure_home()
    payload = {
        "version": STATE_VERSION,
        "port": port,
        "token": token,
        "pid": pid,
        "engine": engine,
        "started_at": started_at,
    }
    _write_private(
        config.state_path,
        json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n",
        replace=True,
    )
    _write_private(
        config.state_env_path,
        f"PII_HOOKD_PORT={port}\nPII_HOOKD_TOKEN={token}\n",
        replace=True,
    )


def read_state(config: HookdConfig) -> dict[str, object] | None:
    """Return the advertised state, or ``None`` when no service is registered."""

    path = config.state_path
    try:
        _assert_owner_mode(path, PRIVATE_MODE, directory=False)
    except WorkflowError:
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    port = payload.get("port")
    token = payload.get("token")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        return None
    if not isinstance(token, str) or not _TOKEN_PATTERN.fullmatch(token):
        return None
    return payload


def clear_state(config: HookdConfig) -> None:
    """Remove both state files; missing files are not an error."""

    for path in (config.state_path, config.state_env_path):
        try:
            path.unlink(missing_ok=True)
        except OSError:
            continue
