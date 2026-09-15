"""Per-session redaction state for the resident hookd service.

One :class:`SessionRedactor` owns the placeholder namespace of a single Claude
Code session.  Placeholders are stable for the life of the session, so a value
first seen in a ``Read`` result carries the same marker when it later shows up
in ``Bash`` output, and the model's own use of the marker can be restored on
the way back to disk.
"""

from __future__ import annotations

import json
import re
import sys
import threading
import time
import uuid
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Protocol

from pii_guard.hookd.policy import structured_entity_type
from pii_guard.hookd.state import HookdConfig
from pii_guard.local_workflow import (
    PLACEHOLDER_PATTERN,
    PRIVATE_MODE,
    WorkflowError,
    _assert_owner_mode,
    _protect_literal_placeholders,
    _replace_all,
    _restore_literals,
    _write_private,
)

# Presidio and CKIP are not documented as thread safe, and the anonymizer holds
# per-call closures.  One shared lock keeps every engine call serialized.
_ENGINE_LOCK: Final[threading.Lock] = threading.Lock()

SESSION_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
PLACEHOLDER_TYPE_PATTERN: Final[re.Pattern[str]] = re.compile(r"^<([A-Z][A-Z0-9_]*)_(\d+)>$")
# Splitting on a capturing group keeps the separators, so a sweep can skip the
# placeholders that are already in the text.
_PLACEHOLDER_SPLIT_PATTERN: Final[re.Pattern[str]] = re.compile(
    "(" + PLACEHOLDER_PATTERN.pattern + ")"
)
STATE_VERSION: Final[int] = 1
MAX_TEXT_BYTES: Final[int] = 4 * 1024 * 1024
ENGINE_NAMES: Final[frozenset[str]] = frozenset({"regex", "full"})


class Engine(Protocol):
    """The slice of ``PiiGuardEngine`` the service depends on."""

    def anonymize(self, text: str) -> tuple[str, dict[str, str]]: ...


@dataclass(frozen=True)
class RedactResult:
    """Outcome of one redaction call."""

    text: str
    new_placeholders: int
    counts: dict[str, int]


@dataclass(frozen=True)
class RestoreResult:
    """Outcome of one restore call."""

    text: str
    replaced: int


def create_engine(name: str) -> Engine:
    """Build the requested detection engine.

    ``regex`` starts in well under a second and never detects names; ``full``
    loads CKIP BERT and blocks for several seconds on first construction.
    """

    if name == "regex":
        from pii_guard.hook_engine import create_regex_only_engine

        return create_regex_only_engine()
    if name == "full":
        from pii_guard.pipeline.engine import PiiGuardEngine

        return PiiGuardEngine()
    raise WorkflowError("INVALID_ENGINE", "The requested engine is not supported.")


def create_engine_with_fallback(name: str) -> tuple[Engine, str, bool]:
    """Build *name*, dropping to ``regex`` when the full engine cannot load.

    Returns the engine, the name that actually loaded, and whether a fallback
    happened.  A missing CKIP model must not leave the user with no guard at
    all, but it does leave names uncovered, so the caller has to be able to
    say so out loud.
    """

    try:
        return create_engine(name), name, False
    except WorkflowError:
        raise
    except Exception as error:  # noqa: BLE001 - any model loading failure
        if name != "full":
            raise
        print(
            f"pii-guard: the full engine failed to load ({type(error).__name__}); "
            "falling back to regex. Names are NOT covered.",
            file=sys.stderr,
        )
    return create_engine("regex"), "regex", True


def validate_session_id(session_id: object) -> str:
    """Return a session id that is safe to use as a file name."""

    if not isinstance(session_id, str) or not SESSION_ID_PATTERN.fullmatch(session_id):
        raise WorkflowError("INVALID_SESSION_ID", "The session identifier is invalid.")
    if session_id in {".", ".."}:
        raise WorkflowError("INVALID_SESSION_ID", "The session identifier is invalid.")
    return session_id


def _placeholder_type(placeholder: str) -> str:
    match = PLACEHOLDER_TYPE_PATTERN.fullmatch(placeholder)
    return match.group(1) if match else "OTHER"


def _outside_placeholders(text: str) -> Iterator[tuple[int, str]]:
    """Yield ``(index, part)`` for the segments that are not placeholders."""

    parts = _PLACEHOLDER_SPLIT_PATTERN.split(text)
    for index in range(0, len(parts), 2):
        yield index, parts[index]


@dataclass
class SessionRedactor:
    """Stable placeholder namespace for one Claude Code session."""

    session_id: str
    engine: Engine
    mapping: dict[str, str] = field(default_factory=dict)
    reverse: dict[str, str] = field(default_factory=dict)
    counters: dict[str, int] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def _allocate_locked(
        self,
        entity_type: str,
        value: str,
        reserved: frozenset[str] = frozenset(),
    ) -> str:
        """Return the existing placeholder for *value*, or allocate a new one.

        ``reserved`` holds markers that appear literally in the text being
        redacted.  Handing one of them to a real value would make the literal
        indistinguishable from the marker, and restore would rewrite both.
        """

        existing = self.reverse.get(value)
        if existing is not None:
            return existing
        while True:
            self.counters[entity_type] = self.counters.get(entity_type, 0) + 1
            placeholder = f"<{entity_type}_{self.counters[entity_type]}>"
            if placeholder not in self.mapping and placeholder not in reserved:
                break
        self.mapping[placeholder] = value
        self.reverse[value] = placeholder
        return placeholder

    def redact(self, text: str) -> RedactResult:
        """Replace detected PII and every value known to this session."""

        if not text:
            return RedactResult(text="", new_placeholders=0, counts={})

        protected, literal_tokens = _protect_literal_placeholders(text)
        with _ENGINE_LOCK:
            redacted, raw_mapping = self.engine.anonymize(protected)

        reserved = frozenset(
            literal for literal in literal_tokens.values() if PLACEHOLDER_PATTERN.fullmatch(literal)
        )
        with self._lock:
            before = len(self.mapping)
            output = self._apply_engine_mapping_locked(redacted, raw_mapping, reserved)
            output = _restore_literals(output, literal_tokens)
            output = self._sweep_known_values_locked(output)
            new_placeholders = len(self.mapping) - before
            counts = self._counts_for(output)
        return RedactResult(text=output, new_placeholders=new_placeholders, counts=counts)

    def _apply_engine_mapping_locked(
        self,
        redacted: str,
        raw_mapping: Mapping[str, str],
        reserved: frozenset[str] = frozenset(),
    ) -> str:
        """Rewrite the engine's per-call markers into session placeholders.

        The engine numbers from one on every call, so its ``<PERSON_1>`` may
        already mean a different person in this session.  Substituting through
        unique sentinels avoids a second pass rewriting the result of the first.
        """

        if not isinstance(raw_mapping, Mapping):
            raise WorkflowError("INVALID_MAPPING", "The engine returned an invalid mapping.")
        sentinels: dict[str, str] = {}
        output = redacted
        for engine_placeholder, value in sorted(
            raw_mapping.items(), key=lambda item: len(item[0]), reverse=True
        ):
            if not isinstance(engine_placeholder, str) or not isinstance(value, str) or not value:
                raise WorkflowError("INVALID_MAPPING", "The engine returned an invalid mapping.")
            if engine_placeholder not in output:
                continue
            sentinel = f"\x00PII_HOOKD_{uuid.uuid4().hex}\x00"
            sentinels[sentinel] = self._allocate_locked(
                _placeholder_type(engine_placeholder), value, reserved
            )
            output = output.replace(engine_placeholder, sentinel)
        for sentinel, placeholder in sentinels.items():
            output = output.replace(sentinel, placeholder)
        return output

    def _sweep_known_values_locked(self, text: str) -> str:
        """Mask any known value the engine missed in this particular call.

        Detection is context sensitive, so a value recognised once can go
        unrecognised later.  Once the session knows a value it is masked every
        time, outside the placeholders that are already in the text.
        """

        if not self.reverse:
            return text
        values = sorted(self.reverse, key=len, reverse=True)
        parts = _PLACEHOLDER_SPLIT_PATTERN.split(text)
        for index, part in _outside_placeholders(text):
            swept = part
            for value in values:
                if value and value in swept:
                    swept = swept.replace(value, self.reverse[value])
            parts[index] = swept
        return "".join(parts)

    def _counts_for(self, text: str) -> dict[str, int]:
        """Count placeholder occurrences in *text* that belong to this session."""

        counts: dict[str, int] = {}
        for placeholder in PLACEHOLDER_PATTERN.findall(text):
            if placeholder not in self.mapping:
                continue
            entity_type = _placeholder_type(placeholder)
            counts[entity_type] = counts.get(entity_type, 0) + 1
        return counts

    def restore(self, text: str) -> RestoreResult:
        """Put real values back, longest placeholder first.

        Placeholders that this session never issued are left untouched, so a
        literal ``<PERSON_1>`` written by the user survives unchanged when the
        session has no such mapping.
        """

        if not text:
            return RestoreResult(text="", replaced=0)
        with self._lock:
            snapshot = dict(self.mapping)
        replaced = sum(text.count(placeholder) for placeholder in snapshot)
        if not replaced:
            return RestoreResult(text=text, replaced=0)
        return RestoreResult(text=_replace_all(text, snapshot), replaced=replaced)

    def snapshot(self) -> dict[str, object]:
        """Return the serialisable state of this session."""

        with self._lock:
            return {
                "version": STATE_VERSION,
                "session_id": self.session_id,
                "counters": dict(self.counters),
                "mapping": dict(self.mapping),
                "updated_at": time.time(),
            }

    def placeholders(self) -> tuple[str, ...]:
        """Every marker this session has issued."""

        with self._lock:
            return tuple(self.mapping)

    def seed(self, terms: Iterable[tuple[str, str]]) -> int:
        """Pre-load known values so the sweep masks them from the first read.

        Detection is context sensitive and misses nicknames and unusual
        spellings entirely.  A project can name those up front.
        """

        added = 0
        with self._lock:
            for entity_type, value in terms:
                if not value or value in self.reverse:
                    continue
                self._allocate_locked(entity_type or "PERSON", value)
                added += 1
        return added

    def detect(self, text: str) -> dict[str, int]:
        """Report what PII is in *text* without learning anything from it.

        Used for the prompt the user is about to send: the session must not
        gain placeholders from text that is going to be refused anyway.
        """

        if not text:
            return {}
        probe = SessionRedactor(
            session_id=self.session_id,
            engine=self.engine,
            mapping=dict(self.mapping),
            reverse=dict(self.reverse),
            counters=dict(self.counters),
        )
        known = set(self.mapping)
        probe.redact(text)
        found: dict[str, int] = {}
        for placeholder, value in probe.mapping.items():
            if placeholder in known:
                continue
            # The engine labels by context, so a phone number sitting inside a
            # sentence can come back as PERSON.  Report what the value is.
            entity_type = structured_entity_type(value) or _placeholder_type(placeholder)
            found[entity_type] = found.get(entity_type, 0) + 1
        return found

    def placeholder_count(self) -> int:
        with self._lock:
            return len(self.mapping)


class SessionStore:
    """Load, cache and persist one :class:`SessionRedactor` per session id."""

    def __init__(self, config: HookdConfig, engine: Engine | None = None) -> None:
        # The engine is optional so that offline maintenance (purging stored
        # mappings from the CLI) never pays the model loading cost.
        self._config = config
        self._engine = engine
        self._sessions: dict[str, SessionRedactor] = {}
        self._lock = threading.Lock()

    @property
    def config(self) -> HookdConfig:
        return self._config

    def _path_for(self, session_id: str) -> Path:
        return self._config.sessions_dir / f"{session_id}.json"

    def get(self, session_id: str) -> SessionRedactor:
        """Return the redactor for *session_id*, loading it from disk once."""

        validated = validate_session_id(session_id)
        with self._lock:
            cached = self._sessions.get(validated)
            if cached is not None:
                return cached
            redactor = self._load(validated)
            self._sessions[validated] = redactor
            return redactor

    def _load(self, session_id: str) -> SessionRedactor:
        if self._engine is None:
            raise WorkflowError("ENGINE_UNAVAILABLE", "No detection engine is loaded.")
        redactor = SessionRedactor(session_id=session_id, engine=self._engine)
        path = self._path_for(session_id)
        try:
            _assert_owner_mode(path, PRIVATE_MODE, directory=False)
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (WorkflowError, OSError, ValueError):
            return redactor
        if not isinstance(payload, dict):
            return redactor
        mapping = payload.get("mapping")
        counters = payload.get("counters")
        if isinstance(mapping, dict):
            for placeholder, value in mapping.items():
                if not isinstance(placeholder, str) or not isinstance(value, str):
                    continue
                if PLACEHOLDER_TYPE_PATTERN.fullmatch(placeholder) is None or not value:
                    continue
                redactor.mapping[placeholder] = value
                redactor.reverse.setdefault(value, placeholder)
        if isinstance(counters, dict):
            for entity_type, count in counters.items():
                if isinstance(entity_type, str) and isinstance(count, int):
                    if not isinstance(count, bool) and count >= 0:
                        redactor.counters[entity_type] = count
        return redactor

    def save(self, redactor: SessionRedactor) -> None:
        """Persist one session's mapping to its owner-only JSON file."""

        self._config.ensure_home()
        payload = redactor.snapshot()
        _write_private(
            self._path_for(redactor.session_id),
            json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n",
            replace=True,
        )

    def purge(self, session_id: str) -> bool:
        """Forget one session in memory and on disk."""

        validated = validate_session_id(session_id)
        with self._lock:
            existed = self._sessions.pop(validated, None) is not None
        path = self._path_for(validated)
        try:
            path.unlink()
        except FileNotFoundError:
            return existed
        except OSError:
            return existed
        return True

    def purge_all(self) -> int:
        """Forget every session; returns how many files were removed."""

        with self._lock:
            self._sessions.clear()
        removed = 0
        try:
            entries = list(self._config.sessions_dir.glob("*.json"))
        except OSError:
            return removed
        for entry in entries:
            try:
                entry.unlink()
            except OSError:
                continue
            removed += 1
        return removed

    def sweep_expired(self, max_age_days: float) -> int:
        """Delete stored mappings older than *max_age_days*.

        A mapping is the only thing that can turn a placeholder back into a
        real value, so it should not outlive the session that needed it.
        """

        if max_age_days <= 0:
            return 0
        cutoff = time.time() - max_age_days * 86400
        removed = 0
        try:
            entries = list(self._config.sessions_dir.glob("*.json"))
        except OSError:
            return 0
        for entry in entries:
            try:
                if entry.stat().st_mtime >= cutoff:
                    continue
                entry.unlink()
            except OSError:
                continue
            with self._lock:
                self._sessions.pop(entry.stem, None)
            removed += 1
        return removed

    def summary(self) -> list[dict[str, object]]:
        """Return per-session placeholder counts only, never values."""

        with self._lock:
            sessions = dict(self._sessions)
        return [
            {"session_id": session_id, "placeholders": redactor.placeholder_count()}
            for session_id, redactor in sorted(sessions.items())
        ]
