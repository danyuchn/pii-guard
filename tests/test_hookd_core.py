"""Tests for the per-session redactor and its persistent store."""

from __future__ import annotations

import json
import stat

import pytest

from pii_guard.hookd.core import SessionRedactor, SessionStore, create_engine
from pii_guard.hookd.state import HookdConfig
from pii_guard.local_workflow import WorkflowError


class FakeEngine:
    """Engine double that replaces exactly the spans it is told about.

    The real engine is context sensitive, which makes ordering and collision
    cases hard to provoke on purpose.  This double makes them deterministic.
    """

    def __init__(self, spans: dict[str, str]) -> None:
        # value -> entity type
        self.spans = spans

    def anonymize(self, text: str) -> tuple[str, dict[str, str]]:
        counters: dict[str, int] = {}
        mapping: dict[str, str] = {}
        output = text
        for value, entity_type in sorted(self.spans.items(), key=lambda i: len(i[0]), reverse=True):
            if value not in output:
                continue
            counters[entity_type] = counters.get(entity_type, 0) + 1
            placeholder = f"<{entity_type}_{counters[entity_type]}>"
            output = output.replace(value, placeholder)
            mapping[placeholder] = value
        return output, mapping


@pytest.fixture
def config(tmp_path) -> HookdConfig:
    return HookdConfig(home=tmp_path / "hookd")


def _redactor(spans: dict[str, str]) -> SessionRedactor:
    return SessionRedactor(session_id="s1", engine=FakeEngine(spans))


def test_same_value_keeps_one_placeholder_across_calls() -> None:
    redactor = _redactor({"王小明": "PERSON"})

    first = redactor.redact("負責人是王小明。")
    second = redactor.redact("再確認一次：王小明。")

    assert first.text == "負責人是<PERSON_1>。"
    assert second.text == "再確認一次：<PERSON_1>。"
    assert first.new_placeholders == 1
    assert second.new_placeholders == 0


def test_different_values_get_distinct_placeholders() -> None:
    redactor = _redactor({"王小明": "PERSON", "李大華": "PERSON"})

    result = redactor.redact("王小明與李大華")

    assert result.text == "<PERSON_1>與<PERSON_2>"
    assert result.new_placeholders == 2
    assert result.counts == {"PERSON": 2}


def test_engine_numbering_collision_does_not_corrupt_earlier_placeholders() -> None:
    """The engine renumbers from one on every call; the session must not."""

    redactor = _redactor({"王小明": "PERSON"})
    redactor.redact("王小明")
    redactor.engine = FakeEngine({"李大華": "PERSON"})  # type: ignore[assignment]

    result = redactor.redact("李大華找王小明")

    assert result.text == "<PERSON_2>找<PERSON_1>"


def test_sweep_masks_a_known_value_the_engine_missed() -> None:
    redactor = _redactor({"A123456789": "TW_NATIONAL_ID"})
    redactor.redact("身分證 A123456789")
    # The engine now detects nothing at all, as happens when the surrounding
    # context no longer triggers the recognizer.
    redactor.engine = FakeEngine({})  # type: ignore[assignment]

    result = redactor.redact("ref=A123456789&status=ok")

    assert result.text == "ref=<TW_NATIONAL_ID_1>&status=ok"
    assert result.new_placeholders == 0


def test_literal_placeholder_in_input_is_not_treated_as_a_mapping() -> None:
    redactor = _redactor({"王小明": "PERSON"})

    result = redactor.redact("文件寫著 <PERSON_1> 這個字樣，實際負責人是王小明。")

    # The literal survives untouched, and the real name gets a marker that
    # cannot be confused with it, so restore rewrites only the real one.
    assert result.text == "文件寫著 <PERSON_1> 這個字樣，實際負責人是<PERSON_2>。"
    assert "<PERSON_1>" not in redactor.mapping
    assert redactor.mapping["<PERSON_2>"] == "王小明"
    assert redactor.restore(result.text).text.count("<PERSON_1>") == 1


def test_restore_round_trip() -> None:
    redactor = _redactor({"王小明": "PERSON", "0912345678": "TW_MOBILE"})
    original = "王小明 0912345678"

    redacted = redactor.redact(original)
    restored = redactor.restore(redacted.text)

    assert restored.text == original
    assert restored.replaced == 2


def test_restore_ignores_unknown_placeholders() -> None:
    redactor = _redactor({})

    restored = redactor.restore("keep <PERSON_1> and <TW_MOBILE_3>")

    assert restored.text == "keep <PERSON_1> and <TW_MOBILE_3>"
    assert restored.replaced == 0


def test_restore_prefers_the_longest_placeholder() -> None:
    redactor = _redactor({f"name{index}": "PERSON" for index in range(1, 11)})
    redactor.redact(" ".join(f"name{index}" for index in range(1, 11)))

    assert redactor.mapping["<PERSON_10>"] not in {redactor.mapping["<PERSON_1>"]}
    restored = redactor.restore("<PERSON_10>/<PERSON_1>")

    # A naive replace would rewrite the <PERSON_1> prefix inside <PERSON_10>.
    assert restored.text == f"{redactor.mapping['<PERSON_10>']}/{redactor.mapping['<PERSON_1>']}"


def test_counters_survive_a_persistence_reload(config: HookdConfig) -> None:
    engine = FakeEngine({"王小明": "PERSON", "李大華": "PERSON"})
    store = SessionStore(config, engine)
    first = store.get("session-a")
    first.redact("王小明")
    store.save(first)

    reloaded = SessionStore(config, engine).get("session-a")
    result = reloaded.redact("李大華")

    assert reloaded.mapping["<PERSON_1>"] == "王小明"
    assert result.text == "<PERSON_2>"


def test_stored_session_file_is_owner_only(config: HookdConfig) -> None:
    store = SessionStore(config, FakeEngine({"王小明": "PERSON"}))
    redactor = store.get("session-a")
    redactor.redact("王小明")
    store.save(redactor)

    path = config.sessions_dir / "session-a.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(config.sessions_dir.stat().st_mode) == 0o700
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["mapping"] == {"<PERSON_1>": "王小明"}


def test_purge_forgets_memory_and_disk(config: HookdConfig) -> None:
    store = SessionStore(config, FakeEngine({"王小明": "PERSON"}))
    redactor = store.get("session-a")
    redactor.redact("王小明")
    store.save(redactor)

    assert store.purge("session-a") is True
    assert not (config.sessions_dir / "session-a.json").exists()
    assert store.get("session-a").mapping == {}


def test_purge_all_removes_every_stored_session(config: HookdConfig) -> None:
    store = SessionStore(config, FakeEngine({"王小明": "PERSON"}))
    for name in ("session-a", "session-b"):
        redactor = store.get(name)
        redactor.redact("王小明")
        store.save(redactor)

    assert store.purge_all() == 2
    assert store.summary() == []


@pytest.mark.parametrize(
    "session_id",
    ["", "..", "../escape", "a/b", "with space", "x" * 200, None, 5],
)
def test_invalid_session_ids_are_rejected(config: HookdConfig, session_id: object) -> None:
    store = SessionStore(config, FakeEngine({}))

    with pytest.raises(WorkflowError):
        store.get(session_id)  # type: ignore[arg-type]


def test_unknown_engine_name_is_rejected() -> None:
    with pytest.raises(WorkflowError):
        create_engine("bert-of-theseus")


def test_regex_engine_masks_taiwan_identifiers(config: HookdConfig) -> None:
    store = SessionStore(config, create_engine("regex"))
    redactor = store.get("session-real")

    result = redactor.redact("身分證 A123456789，手機 0912345678。")

    assert "A123456789" not in result.text
    assert "0912345678" not in result.text
    assert redactor.restore(result.text).text == "身分證 A123456789，手機 0912345678。"


def test_full_engine_failure_falls_back_to_regex(monkeypatch, capsys) -> None:
    """A missing model must degrade to regex, never to no guard at all."""

    import pii_guard.hookd.core as core

    real = core.create_engine

    def fake(name: str):
        if name == "full":
            raise RuntimeError("model not downloaded")
        return real(name)

    monkeypatch.setattr(core, "create_engine", fake)

    engine, loaded, fallback = core.create_engine_with_fallback("full")

    assert loaded == "regex"
    assert fallback is True
    assert engine is not None
    assert "NOT covered" in capsys.readouterr().err


def test_regex_engine_failure_is_not_swallowed(monkeypatch) -> None:
    import pii_guard.hookd.core as core

    monkeypatch.setattr(
        core, "create_engine", lambda name: (_ for _ in ()).throw(RuntimeError("broken"))
    )

    with pytest.raises(RuntimeError):
        core.create_engine_with_fallback("regex")


def test_successful_load_reports_no_fallback() -> None:
    from pii_guard.hookd.core import create_engine_with_fallback

    engine, loaded, fallback = create_engine_with_fallback("regex")

    assert (loaded, fallback) == ("regex", False)
    assert engine is not None


def test_sweep_removes_only_expired_sessions(config: HookdConfig) -> None:
    import os
    import time

    store = SessionStore(config, FakeEngine({"王小明": "PERSON"}))
    for name in ("old-session", "fresh-session"):
        redactor = store.get(name)
        redactor.redact("王小明")
        store.save(redactor)
    stale = config.sessions_dir / "old-session.json"
    long_ago = time.time() - 30 * 86400
    os.utime(stale, (long_ago, long_ago))

    removed = store.sweep_expired(14)

    assert removed == 1
    assert not stale.exists()
    assert (config.sessions_dir / "fresh-session.json").exists()
    # The swept session must also be dropped from the in-memory cache.
    assert store.get("old-session").mapping == {}


def test_sweep_is_disabled_by_a_zero_ttl(config: HookdConfig) -> None:
    import os
    import time

    store = SessionStore(config, FakeEngine({"王小明": "PERSON"}))
    redactor = store.get("old-session")
    redactor.redact("王小明")
    store.save(redactor)
    stale = config.sessions_dir / "old-session.json"
    long_ago = time.time() - 365 * 86400
    os.utime(stale, (long_ago, long_ago))

    assert store.sweep_expired(0) == 0
    assert stale.exists()


def test_detect_prefers_the_structured_type_over_the_model_label() -> None:
    """The full engine can call a phone number PERSON; the reason must not."""

    redactor = _redactor({"0955123456": "PERSON"})

    assert redactor.detect("請打 0955123456 給我") == {"TW_MOBILE": 1}
    # Detection must not teach the session anything about a refused prompt.
    assert redactor.mapping == {}


def test_detect_keeps_the_model_label_for_a_name() -> None:
    redactor = _redactor({"王小明": "PERSON"})

    assert redactor.detect("負責人是王小明") == {"PERSON": 1}


def test_detect_ignores_a_placeholder_the_session_already_issued() -> None:
    redactor = _redactor({"王小明": "PERSON"})
    redactor.redact("王小明")

    assert redactor.detect("把 <PERSON_1> 寫進檔案") == {}
