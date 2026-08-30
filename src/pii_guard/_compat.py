"""POSIX/Windows compatibility layer for private-file primitives.

POSIX is the reference platform: ``fcntl.flock`` advisory locks,
``os.fchmod`` and exact owner/mode checks against 0o600/0o700. Windows
has none of these primitives, so this module substitutes what it can and
is explicit about what it cannot:

- Locks use ``msvcrt.locking`` on one byte at offset 0 of the dedicated
  lock file. ``msvcrt`` has no shared mode, so a shared request degrades
  to exclusive — more serialisation, never less protection.
- POSIX permission bits do not exist on NTFS; ``chmod``/``fchmod`` can
  only toggle a read-only flag and a mode can never read back as 0o600.
  The mode/uid checks therefore pass unconditionally on Windows, and the
  privacy boundary of the private jobs root rests on the NTFS ACL of the
  user profile directory (``%USERPROFILE%``) instead.
"""

from __future__ import annotations

import os
import stat
import time
from typing import Final

WINDOWS: Final[bool] = os.name == "nt"

if WINDOWS:
    import msvcrt
else:
    import fcntl

_LOCK_LENGTH: Final[int] = 1
_LOCK_RETRY_SECONDS: Final[float] = 0.1


def lock_descriptor(descriptor: int, *, exclusive: bool, blocking: bool) -> None:
    """Lock ``descriptor``; a losing non-blocking request raises ``OSError``."""
    if not WINDOWS:
        operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        if not blocking:
            operation |= fcntl.LOCK_NB
        fcntl.flock(descriptor, operation)
        return
    os.lseek(descriptor, 0, os.SEEK_SET)
    if not blocking:
        msvcrt.locking(descriptor, msvcrt.LK_NBLCK, _LOCK_LENGTH)
        return
    # LK_LOCK gives up after ~10 seconds; flock blocks indefinitely, so
    # emulate that with an explicit retry loop.
    while True:
        try:
            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, _LOCK_LENGTH)
            return
        except OSError:
            time.sleep(_LOCK_RETRY_SECONDS)


def unlock_descriptor(descriptor: int) -> None:
    """Release a lock taken with :func:`lock_descriptor`."""
    if not WINDOWS:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        return
    os.lseek(descriptor, 0, os.SEEK_SET)
    msvcrt.locking(descriptor, msvcrt.LK_UNLCK, _LOCK_LENGTH)


def set_descriptor_mode(descriptor: int, mode: int) -> None:
    """``os.fchmod`` on POSIX; a no-op on Windows, which has no POSIX modes."""
    if not WINDOWS:
        os.fchmod(descriptor, mode)


def owner_matches(info: os.stat_result) -> bool:
    """True when the stat owner is the current user (ACL-delegated on Windows)."""
    if WINDOWS:
        return True
    return info.st_uid == os.getuid()


def mode_matches(info: os.stat_result, expected_mode: int) -> bool:
    """True when the permission bits equal ``expected_mode`` (POSIX only)."""
    if WINDOWS:
        return True
    return stat.S_IMODE(info.st_mode) == expected_mode
