"""Deterministic rules that close the ways around the guard.

Restoring a placeholder into a shell command is the one path where the guard
hands a real value back to something that can act on it.  These rules decide
when that is safe, and refuse the commands and tool results that would move
de-identified content somewhere the guard cannot see it.

Everything here is string and regex work on text the service already holds, so
it adds no measurable time to a redact or restore call.  Nothing here asks a
model anything.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Final

# Command words that can put bytes on a network.
NETWORK_COMMANDS: Final[frozenset[str]] = frozenset(
    {
        "curl",
        "wget",
        "nc",
        "ncat",
        "netcat",
        "ssh",
        "scp",
        "sftp",
        "rsync",
        "ftp",
        "telnet",
        "socat",
        "openssl",
    }
)
# Command words that can re-encode content past a plain-text inspection.
ENCODER_COMMANDS: Final[frozenset[str]] = frozenset(
    {
        "base64",
        "base32",
        "basenc",
        "xxd",
        "od",
        "hexdump",
        "uuencode",
    }
)
# Archivers are only a problem when they write the archive to stdout.
ARCHIVE_COMMANDS: Final[frozenset[str]] = frozenset({"gzip", "bzip2", "xz", "zstd", "tar"})
INTERPRETERS: Final[frozenset[str]] = frozenset({"perl", "node", "ruby", "php", "deno", "bun"})
INLINE_FLAGS: Final[frozenset[str]] = frozenset({"-c", "-e", "-E", "--eval", "--exec"})
STDOUT_FLAGS: Final[frozenset[str]] = frozenset({"-c", "--stdout", "--to-stdout", "-O"})
WRAPPERS: Final[frozenset[str]] = frozenset(
    {"sudo", "doas", "env", "command", "nohup", "time", "xargs", "nice", "builtin", "exec", "then"}
)

URL_PATTERN: Final[re.Pattern[str]] = re.compile(r"\b(?:https?|ftp)://", re.IGNORECASE)
PYTHON_PATTERN: Final[re.Pattern[str]] = re.compile(r"^python[0-9.]*$")
INLINE_NETWORK_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"urllib|requests|httpx|http\.client|socket|fetch\(|net\.|Net::|open-uri", re.IGNORECASE
)
INLINE_ENCODER_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"b64|base64|encode|hexlify|\bhex\b|rot13|zlib|codecs|btoa|\bunpack\b|\bpack\b",
    re.IGNORECASE,
)
OPENSSL_ENCODER_PATTERN: Final[re.Pattern[str]] = re.compile(r"\b(?:enc|base64)\b")
OPENSSL_NETWORK_PATTERN: Final[re.Pattern[str]] = re.compile(r"\bs_client\b")

BASE64_RUN_PATTERN: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9+/=]{64,}")
# A SHA-256 digest is exactly 64 hex characters, so checksumming a file used to
# have its output withheld.  SHA-512 still trips this, which is the right way
# round: printing a hash is common, printing 96 hex characters is not.
HEX_RUN_PATTERN: Final[re.Pattern[str]] = re.compile(r"[0-9a-fA-F]{96,}")
_HEX_ONLY_PATTERN: Final[re.Pattern[str]] = re.compile(r"[0-9a-fA-F]+")
HEX_EXEMPT_LENGTH: Final[int] = 96
# Letters, CJK, digits and the punctuation ordinary output is made of.
ORDINARY_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"[0-9A-Za-z　-〿㐀-䶿一-鿿＀-￯"
    r"\-_.,:;!?'\"`()\[\]{}<>@#$%^&*+=/\\|~]"
)
OBFUSCATION_RATIO: Final[float] = 0.30
MIN_GATED_LENGTH: Final[int] = 64

NETWORK_DENY_REASON: Final[str] = (
    "pii-guard: placeholders are never restored into a command that can reach the network"
)
ENCODER_DENY_REASON: Final[str] = (
    "pii-guard: this command would let de-identified content bypass the guard"
)
OUTPUT_WITHHELD: Final[str] = (
    "[pii-guard] output withheld: it looks encoded or obfuscated, "
    "which the guard cannot inspect"
)
OUTPUT_WITHHELD_CONTEXT: Final[str] = (
    "pii-guard withheld this command's output because it looks encoded or "
    "obfuscated and cannot be de-identified. Re-run the command so it prints "
    "the content as plain text, for example without base64, xxd or a compressed "
    "stream, and it will come through normally."
)
REMOTE_DENY_REASON: Final[str] = (
    "pii-guard: a remote agent runs outside this machine where no hook can "
    "de-identify anything, so it is refused while the guard is on"
)


def egress_deny_reason(tool_name: str) -> str:
    return (
        f"pii-guard: {tool_name} can send content off this machine, where the guard "
        "cannot follow it. Allowlist it in policy.allowed_tools if you need it."
    )


@dataclass(frozen=True)
class PolicyConfig:
    """Rules the installer config can widen or relax."""

    encoders_extra: tuple[str, ...] = ()
    network_extra: tuple[str, ...] = ()
    allowed_tools: tuple[str, ...] = ()
    output_gate: bool = True
    seed_terms_files: tuple[str, ...] = field(default=())
    reference_sources: tuple[str, ...] = field(default=())

    @classmethod
    def from_mapping(cls, payload: object) -> PolicyConfig:
        """Build a config from the installer file, ignoring malformed values."""

        if not isinstance(payload, Mapping):
            return cls()

        def words(key: str) -> tuple[str, ...]:
            value = payload.get(key)
            if not isinstance(value, list):
                return ()
            return tuple(str(item) for item in value if isinstance(item, str) and item.strip())

        gate = payload.get("output_gate", True)
        return cls(
            encoders_extra=words("encoders_extra"),
            network_extra=words("network_extra"),
            allowed_tools=words("allowed_tools"),
            output_gate=bool(gate) if isinstance(gate, bool) else True,
            seed_terms_files=words("seed_terms_files"),
            reference_sources=words("reference_sources"),
        )

    @property
    def network_commands(self) -> frozenset[str]:
        return NETWORK_COMMANDS | frozenset(self.network_extra)

    @property
    def encoder_commands(self) -> frozenset[str]:
        return ENCODER_COMMANDS | frozenset(self.encoders_extra)

    def describe(self) -> dict[str, Any]:
        """A summary for health; never includes anything session specific."""

        return {
            "output_gate": self.output_gate,
            "allowed_tools": list(self.allowed_tools),
            "network_commands": len(self.network_commands),
            "encoder_commands": len(self.encoder_commands),
            "reference_sources": len(self.reference_sources),
        }


_SEGMENT_SPLIT: Final[re.Pattern[str]] = re.compile(r"\|\||&&|\$\(|[|;&\n()`{}]")
_ASSIGNMENT: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def command_segments(command: str) -> list[list[str]]:
    """Split a command line into pipeline segments of whitespace tokens.

    This is a reader, not a shell: it only has to be good enough to find the
    word in command position, and it errs towards seeing more segments rather
    than fewer.
    """

    return [segment.split() for segment in _SEGMENT_SPLIT.split(command) if segment.strip()]


def _command_word(tokens: Sequence[str]) -> tuple[str, int]:
    """Return the command word of one segment and where it sat."""

    for index, token in enumerate(tokens):
        if _ASSIGNMENT.match(token) or token.startswith("-"):
            continue
        name = PurePosixPath(token).name
        if name in WRAPPERS:
            continue
        return name, index
    return "", -1


def command_words(command: str) -> set[str]:
    """Every word that appears in command position anywhere in the line."""

    words = set()
    for tokens in command_segments(command):
        word, _ = _command_word(tokens)
        if word:
            words.add(word)
    return words


def _inline_script(word: str, tokens: Sequence[str]) -> bool:
    """Is this segment an interpreter running a script from the command line?"""

    if not (word in INTERPRETERS or PYTHON_PATTERN.match(word)):
        return False
    return any(token in INLINE_FLAGS or token.startswith("-m") for token in tokens)


def _archive_to_stdout(word: str, tokens: Sequence[str], position: int) -> bool:
    if word not in ARCHIVE_COMMANDS:
        return False
    for index, token in enumerate(tokens):
        if token in STDOUT_FLAGS:
            return True
        # tar's classic bundled form, as in "tar czf - dir".
        is_bundle = token.startswith("-") or (word == "tar" and index == position + 1)
        if is_bundle and "c" in token and "z" in token:
            return True
    return False


def network_reach(command: str, config: PolicyConfig | None = None) -> bool:
    """Could this command line put bytes on a network?"""

    policy = config or PolicyConfig()
    if URL_PATTERN.search(command):
        return True
    for tokens in command_segments(command):
        word, _ = _command_word(tokens)
        if not word:
            continue
        segment = " ".join(tokens)
        if word == "openssl":
            if OPENSSL_NETWORK_PATTERN.search(segment):
                return True
            continue
        if word in policy.network_commands:
            return True
        # The segment has lost its parentheses to the split, so the script
        # body is matched against the original line instead.
        if _inline_script(word, tokens) and INLINE_NETWORK_PATTERN.search(command):
            return True
    return False


def encoder_reach(command: str, config: PolicyConfig | None = None) -> bool:
    """Could this command line re-encode content past a plain-text read?"""

    policy = config or PolicyConfig()
    for tokens in command_segments(command):
        word, position = _command_word(tokens)
        if not word:
            continue
        segment = " ".join(tokens)
        if word == "openssl":
            if OPENSSL_ENCODER_PATTERN.search(segment):
                return True
            continue
        if word in policy.encoder_commands:
            return True
        if _archive_to_stdout(word, tokens, position):
            return True
        if _inline_script(word, tokens) and INLINE_ENCODER_PATTERN.search(command):
            return True
    return False


def mentions_placeholder(text: str, placeholders: Iterable[str]) -> bool:
    """Does this text carry a marker this session issued?"""

    return any(placeholder in text for placeholder in placeholders)


def bash_command_decision(
    command: str,
    placeholders: Iterable[str],
    config: PolicyConfig | None = None,
) -> str | None:
    """Return the reason to refuse a Bash command, or ``None`` to allow it.

    A command carrying no placeholder is not this guard's business: there is
    nothing to restore, so refusing it would only get in the way of ordinary
    work that the sandbox already governs.  Encoders are the exception,
    because the content they would hide came out of a guarded read.
    """

    policy = config or PolicyConfig()
    if encoder_reach(command, policy):
        return ENCODER_DENY_REASON
    if mentions_placeholder(command, placeholders) and network_reach(command, policy):
        return NETWORK_DENY_REASON
    return None


def looks_encoded(text: str) -> bool:
    """Does this output look like something the guard cannot read?"""

    if len(text) < MIN_GATED_LENGTH:
        return False
    if HEX_RUN_PATTERN.search(text):
        return True
    for match in BASE64_RUN_PATTERN.finditer(text):
        run = match.group()
        # Hex is a subset of the base64 alphabet, so a checksum would trip this
        # rule too.  Runs that are pure hex are left to the longer hex limit.
        if len(run) < HEX_EXEMPT_LENGTH and _HEX_ONLY_PATTERN.fullmatch(run):
            continue
        return True
    dense = "".join(text.split())
    if len(dense) < MIN_GATED_LENGTH:
        return False
    ordinary = len(ORDINARY_PATTERN.findall(dense))
    return (len(dense) - ordinary) / len(dense) > OBFUSCATION_RATIO


def egress_tool_decision(
    tool_name: str,
    tool_input: Mapping[str, Any],
    config: PolicyConfig | None = None,
) -> str | None:
    """Refuse the tools that can carry content off this machine."""

    policy = config or PolicyConfig()
    if tool_name in policy.allowed_tools:
        return None
    if tool_name in {"WebFetch", "WebSearch"} or tool_name.startswith("mcp__"):
        return egress_deny_reason(tool_name)
    if tool_name in {"Agent", "Task", "Workflow"} and _is_remote(tool_input):
        return REMOTE_DENY_REASON
    return None


def _is_remote(tool_input: Mapping[str, Any]) -> bool:
    if str(tool_input.get("isolation", "")).lower() == "remote":
        return True
    options = tool_input.get("opts")
    if isinstance(options, Mapping):
        return str(options.get("isolation", "")).lower() == "remote"
    return False


# A reference list built from a customer table is routinely thousands of
# values, so the ceiling is high enough to hold one and low enough to keep the
# compiled sweep pattern to a sane size.
MAX_SEED_TERMS: Final[int] = 50_000
MAX_SEED_BYTES: Final[int] = 10 * 1024 * 1024


def load_seed_terms(paths: Iterable[str]) -> tuple[tuple[str, str], ...]:
    """Read ``TYPE<TAB>value`` lines, or bare values meaning PERSON.

    Detection misses nicknames and unusual spellings, so a project can name
    the values it knows about up front.  The values are read here and never
    echoed anywhere.
    """

    terms: list[tuple[str, str]] = []
    seen: set[str] = set()
    for raw in paths:
        path = Path(raw).expanduser()
        try:
            if path.stat().st_size > MAX_SEED_BYTES:
                continue
            content = path.read_text(encoding="utf-8")
        except (OSError, ValueError):
            continue
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or len(terms) >= MAX_SEED_TERMS:
                continue
            entity_type, tab, value = line.partition("\t")
            if not tab:
                entity_type, value = "PERSON", entity_type
            value = value.strip()
            entity_type = entity_type.strip().upper() or "PERSON"
            if not value or value in seen:
                continue
            if not re.fullmatch(r"[A-Z][A-Z0-9_]*", entity_type):
                entity_type = "PERSON"
            seen.add(value)
            terms.append((entity_type, value))
    return tuple(terms)


_STRUCTURED_PATTERNS: list[tuple[str, re.Pattern[str]]] = []


def _structured_patterns() -> list[tuple[str, re.Pattern[str]]]:
    """Compile the Taiwan recognizers' patterns once, for relabelling only."""

    if _STRUCTURED_PATTERNS:
        return _STRUCTURED_PATTERNS
    try:
        from pii_guard.recognizers.tw_recognizers import get_all_tw_recognizers

        for recognizer in get_all_tw_recognizers():
            entity = (recognizer.supported_entities or [""])[0]
            for pattern in getattr(recognizer, "patterns", []):
                try:
                    _STRUCTURED_PATTERNS.append((entity, re.compile(pattern.regex)))
                except re.error:
                    continue
    except Exception:  # noqa: BLE001 - relabelling is cosmetic, never fatal
        return []
    return _STRUCTURED_PATTERNS


def structured_entity_type(value: str) -> str | None:
    """Name what *value* is by shape, ignoring the context it was found in.

    The full engine can label a phone number PERSON when a name recogniser
    overlaps it, which makes a refusal reason say the wrong thing.  A value
    that is exactly a known structured identifier is reported as one.
    """

    if not value:
        return None
    for entity, pattern in _structured_patterns():
        if pattern.fullmatch(value):
            return entity
    return None
