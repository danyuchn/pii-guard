"""MCP Server smoke tests.

Tests the four tool functions (anonymize_text, restore_text, save_mapping,
restore_from_file) by calling them directly as Python functions — no MCP
protocol layer required.

The _engine global in server.py is replaced via monkeypatch to inject
spacy_only_engine, avoiding CKIP model download in the normal test run.
"""

from __future__ import annotations

import json

import pytest

import pii_guard.server as srv


@pytest.fixture(autouse=True)
def mock_server(spacy_only_engine, monkeypatch):
    """Inject spacy_only_engine into the server module and clear session store."""
    monkeypatch.setattr(srv, "_engine", spacy_only_engine)
    srv._sessions.clear()
    yield


# ── anonymize_text ────────────────────────────────────────────────────────────

class TestAnonymizeText:

    def test_returns_expected_fields(self):
        result = srv.anonymize_text("身分證A123456789")
        assert "anonymized_text" in result
        assert "session_id" in result
        assert "entity_count" in result

    def test_pii_replaced_in_output(self):
        result = srv.anonymize_text("身分證A123456789")
        assert "A123456789" not in result["anonymized_text"]
        assert "<TW_NATIONAL_ID_1>" in result["anonymized_text"]

    def test_entity_count_correct(self):
        result = srv.anonymize_text("身分證A123456789，手機0912345678")
        assert result["entity_count"] == 2

    def test_no_pii_entity_count_zero(self):
        result = srv.anonymize_text("今天天氣很好，無任何個資。")
        assert result["entity_count"] == 0
        assert result["anonymized_text"] == "今天天氣很好，無任何個資。"

    def test_session_stored(self):
        result = srv.anonymize_text("身分證A123456789")
        session_id = result["session_id"]
        assert session_id in srv._sessions
        assert "<TW_NATIONAL_ID_1>" in srv._sessions[session_id]


# ── restore_text ──────────────────────────────────────────────────────────────

class TestRestoreText:

    def test_roundtrip(self):
        original = "身分證A123456789，手機0912345678"
        result = srv.anonymize_text(original)
        restored = srv.restore_text(result["anonymized_text"], result["session_id"])
        assert restored == original

    def test_no_pii_roundtrip(self):
        original = "今天天氣很好，無任何個資。"
        result = srv.anonymize_text(original)
        restored = srv.restore_text(result["anonymized_text"], result["session_id"])
        assert restored == original

    def test_unknown_session_raises(self):
        with pytest.raises(ValueError, match="not found"):
            srv.restore_text("some text", "nonexistent-session-id")

    def test_multiple_same_pii_roundtrip(self):
        original = "身分證A123456789，再次：A123456789"
        result = srv.anonymize_text(original)
        restored = srv.restore_text(result["anonymized_text"], result["session_id"])
        assert restored == original


# ── save_mapping / restore_from_file ─────────────────────────────────────────

class TestSaveAndRestoreMapping:

    def test_save_creates_valid_json(self, tmp_path):
        result = srv.anonymize_text("身分證A123456789")
        path = str(tmp_path / "mapping.json")
        msg = srv.save_mapping(result["session_id"], path)

        # Confirm file is valid JSON
        data = json.loads((tmp_path / "mapping.json").read_text(encoding="utf-8"))
        assert isinstance(data, dict)
        assert len(data) == result["entity_count"]
        assert "saved to" in msg

    def test_save_unknown_session_raises(self, tmp_path):
        with pytest.raises(ValueError, match="not found"):
            srv.save_mapping("nonexistent-id", str(tmp_path / "x.json"))

    def test_restore_from_file_roundtrip(self, tmp_path):
        original = "身分證A123456789，統一編號04595257"
        result = srv.anonymize_text(original)
        path = str(tmp_path / "mapping.json")
        srv.save_mapping(result["session_id"], path)

        restored = srv.restore_from_file(result["anonymized_text"], path)
        assert restored == original

    def test_restore_from_file_missing_path_raises(self):
        with pytest.raises(Exception):
            srv.restore_from_file("some text", "/tmp/definitely_does_not_exist_pii.json")
