"""Resident localhost redaction service for Claude Code classic hooks.

The package holds a per-session redactor, a loopback-only HTTP service and the
hook event handlers.  The engine lives here because loading it costs seconds;
the hook client that talks to this service is deliberately dependency-free.
"""

from __future__ import annotations

from pii_guard.hookd.core import (
    RedactResult,
    RestoreResult,
    SessionRedactor,
    SessionStore,
    create_engine,
)
from pii_guard.hookd.state import HookdConfig, clear_state, read_state, write_state

__all__ = [
    "HookdConfig",
    "RedactResult",
    "RestoreResult",
    "SessionRedactor",
    "SessionStore",
    "clear_state",
    "create_engine",
    "read_state",
    "write_state",
]
