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

from pii_guard._compat import secure_private_directory
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

# Homes this process has already secured and verified.  See _secure_home.
_SECURED_HOMES: set[Path] = set()


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
        """Create the owner-only home and sessions directories.

        Every directory this creates is owner-only from the moment it exists.
        ``mkdir(parents=True)`` would give the intermediate directories the
        default permissions instead, leaving the enclosing directory
        world-readable, so the missing ancestors are created one at a time.
        Directories that already existed are left exactly as they are.

        The home is secured before the sessions directory is created, so the
        mappings never live for a moment below a boundary that has not been
        established yet.
        """

        self._make_owner_only(self.home)
        self._secure_home()
        self._make_owner_only(self.sessions_dir)

    @staticmethod
    def _make_owner_only(path: Path) -> None:
        missing = [ancestor for ancestor in (path, *path.parents) if not ancestor.exists()]
        for ancestor in reversed(missing):
            ancestor.mkdir(mode=JOB_MODE)
        # mkdir honours the mode only when it actually creates the directory,
        # so an inherited-permission directory from an older run is tightened.
        path.chmod(JOB_MODE)
        _assert_owner_mode(path, JOB_MODE, directory=True)

    def _secure_home(self) -> None:
        """Establish and verify the Windows ACL boundary on the home.

        The 0700 above is the whole boundary on POSIX and cosmetic on NTFS,
        where chmod only toggles a read-only flag.  Windows therefore gets the
        same protected, non-inheriting ACL the private jobs root gets --
        current user, SYSTEM and Administrators, inheritance removed -- and the
        sessions directory below it inherits that boundary.  Without this the
        session mappings, which hold every real value behind a placeholder,
        would be protected on Windows by nothing but whatever the parent chain
        happened to hand down.

        An existing home is tightened rather than refused, unlike a jobs root:
        this directory is always the project's own, at the path the installer
        chose, so tightening it is exactly what the chmod above does on POSIX.
        A parent chain that lets another account replace it is still refused,
        and taking ownership of a home somebody else created will fail.

        Securing costs an icacls call plus a probe per parent directory, which
        SessionStore.save cannot pay on every tool call, so a home this process
        has already verified is not checked again.  The boundary cannot move
        under a resident service without the account already being lost.
        """

        resolved = self.home.resolve()
        if resolved in _SECURED_HOMES:
            return
        try:
            secure_private_directory(resolved, created=True)
        except OSError as exc:
            raise WorkflowError(
                "PERMISSION_CHECK_FAILED",
                "The hookd home permissions could not be verified.",
            ) from exc
        _SECURED_HOMES.add(resolved)


def write_state(
    config: HookdConfig,
    *,
    port: int,
    token: str,
    pid: int,
    engine: str,
    started_at: float,
    engine_fallback: bool = False,
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
        "engine_fallback": engine_fallback,
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
