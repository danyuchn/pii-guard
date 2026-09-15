"""Claude Code hook event handling, kept server side.

The hook client is deliberately trivial, so every decision about which fields
to redact or restore lives here.  Every handler returns the exact JSON the
client should print, or an empty object when there is nothing to change.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from pii_guard.hookd import policy
from pii_guard.hookd.core import SessionRedactor, SessionStore

POST_TOOL_USE: Final[str] = "PostToolUse"
PRE_TOOL_USE: Final[str] = "PreToolUse"
MESSAGE_DISPLAY: Final[str] = "MessageDisplay"
SESSION_START: Final[str] = "SessionStart"
USER_PROMPT_SUBMIT: Final[str] = "UserPromptSubmit"

SUPPORTED_EVENTS: Final[frozenset[str]] = frozenset(
    {POST_TOOL_USE, PRE_TOOL_USE, MESSAGE_DISPLAY, SESSION_START, USER_PROMPT_SUBMIT}
)

# Read results carry the file text under "file"; image reads use a different
# shape and are passed through untouched.
_READ_TEXT_TYPE: Final[str] = "text"
# Recursion guard for the Grep fallback, which walks an unspecified structure.
_MAX_DEPTH: Final[int] = 12

@dataclass(frozen=True)
class HookContext:
    """What the handlers need to know about the running service."""

    names_covered: bool = False
    policy: policy.PolicyConfig = field(default_factory=policy.PolicyConfig)
    seed_terms: tuple[tuple[str, str], ...] = ()


NAMES_COVERED_MESSAGE: Final[str] = "pii-guard: on (full engine, names covered)"
NAMES_UNCOVERED_MESSAGE: Final[str] = "pii-guard: on (regex only, names NOT covered)"
NAMES_UNCOVERED_CONTEXT: Final[str] = (
    " The regex engine is loaded, so personal NAMES and organization names are "
    "NOT detected and may still reach you in full. Treat any name you see as "
    "real personal data."
)

SESSION_START_CONTEXT: Final[str] = (
    "pii-guard hookd is running. Tool results you receive are de-identified: "
    "personal data has been replaced with placeholders such as <PERSON_1> or "
    "<TW_ID_NUMBER_1>. Keep those placeholders exactly as they are. When you "
    "write them back to a file or a shell command they are restored to the "
    "real values automatically, so do not try to guess what they stand for. "
    "One important exception: Edit and MultiEdit match old_string against the "
    "real file, which still holds the real value, and that match happens "
    "before this guard can restore anything. An Edit whose old_string "
    "contains a placeholder therefore fails with 'String to replace not "
    "found'. When that happens, rewrite the whole file with Write, whose "
    "content is restored, or make the change with a Bash command. Never guess "
    "what a placeholder stands for in order to make an Edit match."
)


def _hook_output(event_name: str, **fields: object) -> dict[str, object]:
    return {"hookSpecificOutput": {"hookEventName": event_name, **fields}}


def _deny(reason: str) -> dict[str, object]:
    return _hook_output(
        PRE_TOOL_USE,
        permissionDecision="deny",
        permissionDecisionReason=reason,
    )


def _redact(redactor: SessionRedactor, text: str) -> tuple[str, bool]:
    result = redactor.redact(text)
    return result.text, result.text != text


def _restore(redactor: SessionRedactor, text: str) -> tuple[str, bool]:
    result = redactor.restore(text)
    return result.text, result.replaced > 0


def _redact_string_leaves(
    redactor: SessionRedactor,
    value: Any,
    depth: int = 0,
) -> tuple[Any, bool]:
    """Redact every string inside an arbitrary JSON structure.

    Used for tool results whose shape is not pinned down.  The structure and
    the keys are preserved exactly, because a reply that does not match the
    tool's own output shape is silently ignored by Claude Code.
    """

    if depth > _MAX_DEPTH:
        return value, False
    if isinstance(value, str):
        return _redact(redactor, value)
    if isinstance(value, Mapping):
        output: dict[str, Any] = {}
        changed = False
        for key, item in value.items():
            output[key], item_changed = _redact_string_leaves(redactor, item, depth + 1)
            changed = changed or item_changed
        return output, changed
    if isinstance(value, list):
        items: list[Any] = []
        changed = False
        for item in value:
            redacted, item_changed = _redact_string_leaves(redactor, item, depth + 1)
            items.append(redacted)
            changed = changed or item_changed
        return items, changed
    return value, False


def _handle_read(redactor: SessionRedactor, response: Mapping[str, Any]) -> dict[str, object]:
    if response.get("type") != _READ_TEXT_TYPE:
        return {}
    file_block = response.get("file")
    if not isinstance(file_block, Mapping):
        return {}
    content = file_block.get("content")
    if not isinstance(content, str):
        return {}
    redacted, changed = _redact(redactor, content)
    if not changed:
        return {}
    updated_file = dict(file_block)
    updated_file["content"] = redacted
    updated = dict(response)
    updated["file"] = updated_file
    return _hook_output(POST_TOOL_USE, updatedToolOutput=updated)


def _handle_bash_output(
    redactor: SessionRedactor,
    response: Mapping[str, Any],
    context: HookContext,
) -> dict[str, object]:
    updated = dict(response)
    changed = False
    for key in ("stdout", "stderr"):
        value = updated.get(key)
        if isinstance(value, str):
            updated[key], field_changed = _redact(redactor, value)
            changed = changed or field_changed

    # Content the guard cannot read is content it cannot de-identify, so an
    # encoded blob is withheld whole rather than passed through unexamined.
    if context.policy.output_gate and any(
        isinstance(updated.get(key), str) and policy.looks_encoded(str(updated[key]))
        for key in ("stdout", "stderr")
    ):
        withheld = dict(response)
        withheld["stdout"] = policy.OUTPUT_WITHHELD
        withheld["stderr"] = ""
        return _hook_output(
            POST_TOOL_USE,
            updatedToolOutput=withheld,
            additionalContext=policy.OUTPUT_WITHHELD_CONTEXT,
        )
    if not changed:
        return {}
    return _hook_output(POST_TOOL_USE, updatedToolOutput=updated)


def handle_post_tool_use(
    store: SessionStore, payload: Mapping[str, Any], context: HookContext
) -> dict[str, object]:
    """De-identify what a tool result would otherwise put into the context."""

    tool_name = payload.get("tool_name")
    response = payload.get("tool_response")
    if not isinstance(tool_name, str) or not isinstance(response, Mapping):
        return {}
    redactor = store.get(str(payload.get("session_id", "")))
    if tool_name == "Read":
        reply = _handle_read(redactor, response)
    elif tool_name == "Bash":
        reply = _handle_bash_output(redactor, response, context)
    else:
        updated, changed = _redact_string_leaves(redactor, dict(response))
        reply = _hook_output(POST_TOOL_USE, updatedToolOutput=updated) if changed else {}
    if reply:
        store.save(redactor)
    return reply


def _restore_tool_input(
    redactor: SessionRedactor,
    tool_name: str,
    tool_input: Mapping[str, Any],
) -> tuple[dict[str, Any], bool]:
    updated = dict(tool_input)
    changed = False

    def restore_key(container: dict[str, Any], key: str) -> None:
        nonlocal changed
        value = container.get(key)
        if isinstance(value, str):
            container[key], field_changed = _restore(redactor, value)
            changed = changed or field_changed

    if tool_name == "Write":
        restore_key(updated, "content")
    elif tool_name == "Edit":
        restore_key(updated, "old_string")
        restore_key(updated, "new_string")
    elif tool_name == "MultiEdit":
        edits = updated.get("edits")
        if isinstance(edits, list):
            rebuilt: list[Any] = []
            for edit in edits:
                if isinstance(edit, Mapping):
                    entry = dict(edit)
                    restore_key(entry, "old_string")
                    restore_key(entry, "new_string")
                    rebuilt.append(entry)
                else:
                    rebuilt.append(edit)
            updated["edits"] = rebuilt
    elif tool_name == "Bash":
        restore_key(updated, "command")
    return updated, changed


def handle_pre_tool_use(
    store: SessionStore, payload: Mapping[str, Any], context: HookContext
) -> dict[str, object]:
    """Put real values back before Claude writes them to disk or to a shell."""

    tool_name = payload.get("tool_name")
    tool_input = payload.get("tool_input")
    if not isinstance(tool_name, str) or not isinstance(tool_input, Mapping):
        return {}

    egress = policy.egress_tool_decision(tool_name, tool_input, context.policy)
    if egress is not None:
        return _deny(egress)

    redactor = store.get(str(payload.get("session_id", "")))
    if tool_name == "Bash":
        command = tool_input.get("command")
        if isinstance(command, str):
            refusal = policy.bash_command_decision(
                command, redactor.placeholders(), context.policy
            )
            if refusal is not None:
                return _deny(refusal)
    updated, changed = _restore_tool_input(redactor, tool_name, tool_input)
    if not changed:
        return {}
    # updatedInput replaces the whole input object, so every field is echoed.
    return _hook_output(PRE_TOOL_USE, updatedInput=updated)


def handle_message_display(
    store: SessionStore, payload: Mapping[str, Any], context: HookContext
) -> dict[str, object]:
    """Show the user real values while the model keeps seeing placeholders."""

    del context
    delta = payload.get("delta")
    if not isinstance(delta, str) or not delta:
        return {}
    redactor = store.get(str(payload.get("session_id", "")))
    restored, changed = _restore(redactor, delta)
    if not changed:
        return {}
    return _hook_output(MESSAGE_DISPLAY, displayContent=restored)


# An @ reference pulls a file straight into the prompt with no tool call, so
# no hook ever sees it.  The only defence is to refuse the prompt.
_AT_REFERENCE_PATTERN: Final[re.Pattern[str]] = re.compile(r"@([^\s]+)")
_TRAILING_PUNCTUATION: Final[str] = ".,;:!?)]}'\"，。、！？）】」"


def _referenced_file(reference: str, cwd: str) -> Path | None:
    """Resolve an @ reference to an existing file, or ``None``."""

    cleaned = reference.rstrip(_TRAILING_PUNCTUATION)
    if not cleaned:
        return None
    candidate = Path(cleaned).expanduser()
    if not candidate.is_absolute():
        candidate = Path(cwd or ".") / candidate
    try:
        # Directories are fine: Claude Code lists them, it does not inline them.
        return candidate if candidate.is_file() else None
    except OSError:
        return None


def _block(reason: str) -> dict[str, object]:
    return {"decision": "block", "reason": reason}


def handle_user_prompt_submit(
    store: SessionStore, payload: Mapping[str, Any], context: HookContext
) -> dict[str, object]:
    """Refuse a prompt that would carry real data past every other hook."""

    del context
    prompt = payload.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip():
        return {}
    cwd = str(payload.get("cwd", ""))

    for reference in _AT_REFERENCE_PATTERN.findall(prompt):
        path = _referenced_file(reference, cwd)
        if path is not None:
            return _block(
                "pii-guard: @file references bypass the guard. "
                f"Ask me to Read the file instead: {path}"
            )

    redactor = store.get(str(payload.get("session_id", "")))
    found = redactor.detect(prompt)
    if not found:
        return {}
    # Report what kind of data and how much, never the data itself.
    summary = ", ".join(f"{count} {name}" for name, count in sorted(found.items()))
    return _block(
        f"pii-guard: this prompt contains personal data ({summary}). "
        "Put it in a file and ask me to read that file, so it can be "
        "de-identified before it reaches the model."
    )


def handle_session_start(
    store: SessionStore, payload: Mapping[str, Any], context: HookContext
) -> dict[str, object]:
    """Tell the model that placeholders are expected and must be preserved."""

    seeded = 0
    if context.seed_terms:
        redactor = store.get(str(payload.get("session_id", "")))
        seeded = redactor.seed(context.seed_terms)
        if seeded:
            store.save(redactor)
    extra = "" if context.names_covered else NAMES_UNCOVERED_CONTEXT
    # The count is safe to show; the terms themselves never leave the service.
    seeds = f", {seeded} seed terms loaded" if seeded else ""
    return {
        "systemMessage": (
            (NAMES_COVERED_MESSAGE if context.names_covered else NAMES_UNCOVERED_MESSAGE) + seeds
        ),
        "hookSpecificOutput": {
            "hookEventName": SESSION_START,
            "additionalContext": SESSION_START_CONTEXT + extra,
        },
    }


_HANDLERS: Final[dict[str, Any]] = {
    POST_TOOL_USE: handle_post_tool_use,
    USER_PROMPT_SUBMIT: handle_user_prompt_submit,
    PRE_TOOL_USE: handle_pre_tool_use,
    MESSAGE_DISPLAY: handle_message_display,
    SESSION_START: handle_session_start,
}


def dispatch(
    store: SessionStore,
    event_name: str,
    payload: Mapping[str, Any],
    context: HookContext | None = None,
) -> dict[str, object]:
    """Route one hook event to its handler; unknown events do nothing."""

    handler = _HANDLERS.get(event_name)
    if handler is None:
        return {}
    return handler(store, payload, context or HookContext())
