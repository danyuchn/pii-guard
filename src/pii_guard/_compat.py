"""POSIX/Windows compatibility for private-file primitives.

POSIX keeps the original ``flock`` and exact owner/mode checks. Windows
uses an exclusive byte-range lock and protects the jobs root with a verified,
non-inheriting ACL for the current user, SYSTEM, and Administrators. Files
and directories below that root inherit the verified boundary.
"""

from __future__ import annotations

import os
import stat
import sys
import time
from pathlib import Path
from typing import Final

_LOCK_LENGTH: Final[int] = 1
_LOCK_RETRY_SECONDS: Final[float] = 0.1


if sys.platform == "win32":
    import json
    import msvcrt
    import re
    import subprocess

    _ACL_PATH_ENV: Final[str] = "_PII_GUARD_PRIVATE_ACL_PATH"
    _FULL_CONTROL: Final[int] = 0x1F01FF
    _INHERIT_FILES_AND_DIRECTORIES: Final[int] = 3
    _REPARSE_POINT_ATTRIBUTE: Final[int] = 0x400
    _OWNER_RIGHTS_SID: Final[str] = "S-1-3-4"
    _SYSTEM_SID: Final[str] = "S-1-5-18"
    _ADMINISTRATORS_SID: Final[str] = "S-1-5-32-544"
    _DANGEROUS_PARENT_RIGHTS: Final[int] = (
        0x00000002  # FILE_ADD_FILE
        | 0x00000004  # FILE_ADD_SUBDIRECTORY
        | 0x00000040  # FILE_DELETE_CHILD
        | 0x00010000  # DELETE
        | 0x00040000  # WRITE_DAC
        | 0x00080000  # WRITE_OWNER
        | 0x10000000  # GENERIC_ALL
        | 0x40000000  # GENERIC_WRITE
    )
    _SID_PATTERN: Final[re.Pattern[bytes]] = re.compile(rb"S-\d-\d+(?:-\d+)+")
    _ACL_PROBE_SCRIPT: Final[str] = r"""
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$path = [Environment]::GetEnvironmentVariable("_PII_GUARD_PRIVATE_ACL_PATH")
$acl = [System.IO.Directory]::GetAccessControl($path)
$owner = ([System.Security.Principal.NTAccount]$acl.Owner).Translate(
    [System.Security.Principal.SecurityIdentifier]
).Value
$rules = @($acl.GetAccessRules(
    $true,
    $true,
    [System.Security.Principal.SecurityIdentifier]
) | ForEach-Object {
    [pscustomobject]@{
        sid = $_.IdentityReference.Value
        type = [int]$_.AccessControlType
        rights = [int]$_.FileSystemRights
        inherited = $_.IsInherited
        inheritance = [int]$_.InheritanceFlags
        propagation = [int]$_.PropagationFlags
    }
})
[pscustomobject]@{
    owner_sid = $owner
    protected = $acl.AreAccessRulesProtected
    canonical = $acl.AreAccessRulesCanonical
    rules = $rules
} | ConvertTo-Json -Compress -Depth 4
"""

    def _system_tool(*parts: str) -> str:
        system_root = os.environ.get("SystemRoot")
        if not system_root:
            raise OSError("Windows system directory is unavailable")
        tool = Path(system_root, "System32", *parts)
        if not tool.is_file():
            raise OSError("Required Windows security tool is unavailable")
        return str(tool)

    def _current_user_sid() -> str:
        completed = subprocess.run(
            [_system_tool("whoami.exe"), "/user", "/fo", "csv", "/nh"],
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=10,
        )
        match = _SID_PATTERN.search(completed.stdout) if completed.returncode == 0 else None
        if match is None:
            raise OSError("Current Windows user SID could not be verified")
        return match.group().decode("ascii")

    def _private_acl_payload(path: Path) -> dict[str, object]:
        environment = os.environ.copy()
        environment[_ACL_PATH_ENV] = str(path)
        completed = subprocess.run(
            [
                _system_tool("WindowsPowerShell", "v1.0", "powershell.exe"),
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                _ACL_PROBE_SCRIPT,
            ],
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=10,
            env=environment,
        )
        if completed.returncode != 0 or len(completed.stdout) > 64 * 1024:
            raise OSError("Windows private-directory ACL could not be read")
        payload = json.loads(completed.stdout.decode("utf-8"))
        if not isinstance(payload, dict):
            raise OSError("Windows private-directory ACL is invalid")
        return payload

    def private_directory_acl_matches(path: Path) -> bool:
        """Return whether ``path`` has the exact supported private root ACL."""

        try:
            current_sid = _current_user_sid()
            payload = _private_acl_payload(path)
        except (OSError, subprocess.TimeoutExpired, UnicodeError, json.JSONDecodeError):
            return False
        if (
            payload.get("owner_sid") != current_sid
            or payload.get("protected") is not True
            or payload.get("canonical") is not True
        ):
            return False
        rules = payload.get("rules")
        if not isinstance(rules, list) or len(rules) not in {3, 4}:
            return False
        required_sids = {current_sid, _SYSTEM_SID, _ADMINISTRATORS_SID}
        allowed_sids = required_sids | {_OWNER_RIGHTS_SID}
        observed_sids: set[str] = set()
        for rule in rules:
            if not isinstance(rule, dict):
                return False
            sid = rule.get("sid")
            if (
                not isinstance(sid, str)
                or sid not in allowed_sids
                or rule.get("type") != 0
                or rule.get("rights") != _FULL_CONTROL
                or rule.get("inherited") is not False
                or rule.get("inheritance") != _INHERIT_FILES_AND_DIRECTORIES
                or rule.get("propagation") != 0
            ):
                return False
            observed_sids.add(sid)
        return required_sids <= observed_sids <= allowed_sids

    def private_parent_chain_is_safe(path: Path) -> bool:
        """Reject replaceable roots by checking every parent up to the profile."""

        try:
            current_sid = _current_user_sid()
            profile = Path.home().resolve(strict=True)
            resolved = path.resolve(strict=True)
            resolved.relative_to(profile)
        except (OSError, RuntimeError, ValueError):
            return False
        trusted_sids = {
            current_sid,
            _SYSTEM_SID,
            _ADMINISTRATORS_SID,
            _OWNER_RIGHTS_SID,
        }
        trusted_owner_sids = {current_sid, _SYSTEM_SID, _ADMINISTRATORS_SID}
        current = resolved.parent
        while True:
            try:
                info = current.lstat()
                if is_reparse_point(info):
                    return False
                payload = _private_acl_payload(current)
            except (OSError, subprocess.TimeoutExpired, UnicodeError, json.JSONDecodeError):
                return False
            rules = payload.get("rules")
            if payload.get("owner_sid") not in trusted_owner_sids or not isinstance(rules, list):
                return False
            for rule in rules:
                if not isinstance(rule, dict):
                    return False
                sid = rule.get("sid")
                rule_type = rule.get("type")
                rights = rule.get("rights")
                if (
                    rule_type == 0
                    and isinstance(sid, str)
                    and sid not in trusted_sids
                    and isinstance(rights, int)
                    and rights & _DANGEROUS_PARENT_RIGHTS
                ):
                    return False
                if (
                    not isinstance(sid, str)
                    or not isinstance(rule_type, int)
                    or not isinstance(rights, int)
                ):
                    return False
            if current == profile:
                return True
            current = current.parent

    def secure_private_directory(path: Path, *, created: bool) -> None:
        """Secure a new jobs root and verify every jobs root fail-closed."""

        if not private_parent_chain_is_safe(path):
            raise OSError("Windows private-directory parent ACL is unsafe")
        if created:
            current_sid = _current_user_sid()
            try:
                completed = subprocess.run(
                    [
                        _system_tool("icacls.exe"),
                        str(path),
                        "/inheritance:r",
                        "/grant:r",
                        f"*{current_sid}:(OI)(CI)F",
                        f"*{_SYSTEM_SID}:(OI)(CI)F",
                        f"*{_ADMINISTRATORS_SID}:(OI)(CI)F",
                        "/Q",
                    ],
                    check=False,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    timeout=10,
                )
            except subprocess.TimeoutExpired as exc:
                raise OSError("Windows private-directory ACL application timed out") from exc
            if completed.returncode != 0:
                raise OSError("Windows private-directory ACL could not be applied")
        if not private_directory_acl_matches(path):
            raise OSError("Windows private-directory ACL could not be verified")

    def is_reparse_point(info: os.stat_result) -> bool:
        """Return whether a Windows stat result is any reparse point."""

        return bool(getattr(info, "st_file_attributes", 0) & _REPARSE_POINT_ATTRIBUTE)

    def lock_descriptor(descriptor: int, *, exclusive: bool, blocking: bool) -> None:
        """Lock one byte; Windows shared requests conservatively become exclusive."""

        os.lseek(descriptor, 0, os.SEEK_SET)
        if not blocking:
            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, _LOCK_LENGTH)
            return
        while True:
            try:
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, _LOCK_LENGTH)
                return
            except OSError:
                time.sleep(_LOCK_RETRY_SECONDS)

    def unlock_descriptor(descriptor: int) -> None:
        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, _LOCK_LENGTH)

    def set_descriptor_mode(descriptor: int, mode: int) -> None:
        """Files inherit the verified Windows jobs-root ACL."""

    def owner_matches(info: os.stat_result) -> bool:
        """Ownership is enforced by the verified Windows jobs-root ACL."""

        return True

    def mode_matches(info: os.stat_result, expected_mode: int) -> bool:
        """POSIX modes do not exist; the verified Windows ACL is authoritative."""

        return True

else:
    import fcntl

    def private_directory_acl_matches(path: Path) -> bool:
        """POSIX privacy is verified through owner and mode checks."""

        return True

    def private_parent_chain_is_safe(path: Path) -> bool:
        """POSIX parent replacement is covered by owner and mode checks."""

        return True

    def secure_private_directory(path: Path, *, created: bool) -> None:
        """POSIX privacy is applied and verified by the caller's mode checks."""

    def is_reparse_point(info: os.stat_result) -> bool:
        """Treat POSIX symbolic links as the corresponding unsafe indirection."""

        return stat.S_ISLNK(info.st_mode)

    def lock_descriptor(descriptor: int, *, exclusive: bool, blocking: bool) -> None:
        operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        if not blocking:
            operation |= fcntl.LOCK_NB
        fcntl.flock(descriptor, operation)

    def unlock_descriptor(descriptor: int) -> None:
        fcntl.flock(descriptor, fcntl.LOCK_UN)

    def set_descriptor_mode(descriptor: int, mode: int) -> None:
        os.fchmod(descriptor, mode)

    def owner_matches(info: os.stat_result) -> bool:
        return info.st_uid == os.getuid()

    def mode_matches(info: os.stat_result, expected_mode: int) -> bool:
        return stat.S_IMODE(info.st_mode) == expected_mode
