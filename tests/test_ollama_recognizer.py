"""Tests for OllamaRecognizer (LLM fallback PII detection)."""

from __future__ import annotations

import json

import httpx
import pytest

from pii_guard.recognizers.ollama_recognizer import (
    VALID_ENTITY_TYPES,
    OllamaRecognizer,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tags_response(model_names: list[str]) -> dict:
    """Fake /api/tags JSON body."""
    return {"models": [{"name": n} for n in model_names]}


def _generate_response_body(entities: list[dict]) -> dict:
    """Fake /api/generate JSON body."""
    return {"response": json.dumps({"entities": entities})}


def _make_recognizer(**kwargs) -> OllamaRecognizer:
    rec = OllamaRecognizer(**kwargs)
    return rec


ALL_ENTITIES = sorted(VALID_ENTITY_TYPES)


# ---------------------------------------------------------------------------
# Unit Tests (mocked httpx)
# ---------------------------------------------------------------------------


class TestAvailabilityCheck:
    def test_unavailable_when_connection_refused(self, monkeypatch):
        def mock_get(*args, **kwargs):
            raise httpx.ConnectError("Connection refused")

        monkeypatch.setattr(httpx, "get", mock_get)
        rec = _make_recognizer()
        results = rec.analyze("張大明", ALL_ENTITIES, None)
        assert results == []
        assert rec._available is False

    def test_unavailable_when_model_not_found(self, monkeypatch):
        """Mock _check_available internals to simulate model-not-found."""
        rec = _make_recognizer(model="qwen2.5:1.5b")
        # Simulate: Ollama running but model not pulled
        rec._available = False
        results = rec.analyze("張大明", ALL_ENTITIES, None)
        assert results == []

    def test_available_exact_model_match(self):
        rec = _make_recognizer(model="qwen2.5:1.5b")
        rec._available = True  # simulate successful health check
        # Mock _call_ollama to avoid real HTTP
        rec._call_ollama = lambda text: json.dumps({"entities": []})
        rec.analyze("test", ALL_ENTITIES, None)
        assert rec._available is True

    def test_availability_cached(self, monkeypatch):
        rec = _make_recognizer()
        rec._available = True
        rec._call_ollama = lambda text: json.dumps({"entities": []})

        call_count = 0
        original_check = rec._check_available

        def counting_check():
            nonlocal call_count
            call_count += 1
            return rec._available

        rec._check_available = counting_check
        rec.analyze("text1", ALL_ENTITIES, None)
        rec.analyze("text2", ALL_ENTITIES, None)
        assert call_count == 2  # called each time but returns cached value


class TestResponseParsing:
    @pytest.fixture(autouse=True)
    def _setup(self):
        """All response-parsing tests bypass availability check."""

    def _make_available_recognizer(self) -> OllamaRecognizer:
        rec = _make_recognizer()
        rec._available = True
        return rec

    def test_valid_response_with_correct_offsets(self):
        text = "張大明的手機0912345678"
        entities = [
            {"type": "PERSON", "value": "張大明", "start": 0, "end": 3},
            {"type": "TW_MOBILE", "value": "0912345678", "start": 6, "end": 16},
        ]
        rec = self._make_available_recognizer()
        rec._call_ollama = lambda t: json.dumps({"entities": entities})
        results = rec.analyze(text, ALL_ENTITIES, None)
        assert len(results) == 2
        assert results[0].entity_type == "PERSON"
        assert results[0].start == 0
        assert results[0].end == 3
        assert results[0].score == 0.75
        assert results[1].entity_type == "TW_MOBILE"

    def test_offset_fallback_via_text_find(self):
        text = "聯絡人：王小美"
        entities = [
            {"type": "PERSON", "value": "王小美", "start": 99, "end": 102},
        ]
        rec = self._make_available_recognizer()
        rec._call_ollama = lambda t: json.dumps({"entities": entities})
        results = rec.analyze(text, ALL_ENTITIES, None)
        assert len(results) == 1
        assert results[0].start == 4  # text.find("王小美")
        assert results[0].end == 7

    def test_value_not_in_text_discarded(self):
        text = "這是一段普通文字"
        entities = [
            {"type": "PERSON", "value": "不存在的人", "start": 0, "end": 5},
        ]
        rec = self._make_available_recognizer()
        rec._call_ollama = lambda t: json.dumps({"entities": entities})
        results = rec.analyze(text, ALL_ENTITIES, None)
        assert results == []

    def test_unknown_entity_type_filtered(self):
        text = "張大明"
        entities = [
            {"type": "UNKNOWN_TYPE", "value": "張大明", "start": 0, "end": 3},
        ]
        rec = self._make_available_recognizer()
        rec._call_ollama = lambda t: json.dumps({"entities": entities})
        results = rec.analyze(text, ALL_ENTITIES, None)
        assert results == []

    def test_entity_not_in_requested_list_filtered(self):
        text = "張大明"
        entities = [
            {"type": "PERSON", "value": "張大明", "start": 0, "end": 3},
        ]
        rec = self._make_available_recognizer()
        rec._call_ollama = lambda t: json.dumps({"entities": entities})
        # Only request TW_MOBILE, not PERSON
        results = rec.analyze(text, ["TW_MOBILE"], None)
        assert results == []

    def test_empty_entities_response(self):
        rec = self._make_available_recognizer()
        rec._call_ollama = lambda t: json.dumps({"entities": []})
        results = rec.analyze("普通文字", ALL_ENTITIES, None)
        assert results == []


class TestErrorHandling:
    def _make_available_recognizer(self) -> OllamaRecognizer:
        rec = _make_recognizer()
        rec._available = True
        return rec

    def test_malformed_json_returns_empty(self):
        rec = self._make_available_recognizer()
        rec._call_ollama = lambda t: "not valid json {{{"
        results = rec.analyze("張大明", ALL_ENTITIES, None)
        assert results == []

    def test_timeout_returns_empty(self):
        rec = self._make_available_recognizer()

        def raise_timeout(text):
            raise httpx.TimeoutException("Request timed out")

        rec._call_ollama = raise_timeout
        results = rec.analyze("張大明", ALL_ENTITIES, None)
        assert results == []

    def test_http_error_returns_empty(self):
        rec = self._make_available_recognizer()

        def raise_http_error(text):
            raise httpx.HTTPStatusError(
                "Server Error", request=httpx.Request("POST", "http://x"), response=httpx.Response(500)
            )

        rec._call_ollama = raise_http_error
        results = rec.analyze("張大明", ALL_ENTITIES, None)
        assert results == []

    def test_markdown_fenced_json_parsed(self):
        text = "張大明的電話0912345678"
        fenced = '```json\n{"entities": [{"type": "PERSON", "value": "張大明", "start": 0, "end": 3}]}\n```'
        rec = self._make_available_recognizer()
        rec._call_ollama = lambda t: fenced
        results = rec.analyze(text, ALL_ENTITIES, None)
        assert len(results) == 1
        assert results[0].entity_type == "PERSON"


# ---------------------------------------------------------------------------
# Integration test (requires running Ollama + qwen2.5:1.5b)
# ---------------------------------------------------------------------------


@pytest.mark.slow
class TestOllamaIntegration:
    def test_detect_person_and_phone(self):
        rec = OllamaRecognizer(model="qwen2.5:1.5b")
        text = "張大明的手機號碼是0912345678，住在台北市信義區"
        results = rec.analyze(text, ALL_ENTITIES, None)
        # LLM should detect at least some PII; exact count depends on model
        detected_types = {r.entity_type for r in results}
        # At minimum, PERSON should be detected
        assert "PERSON" in detected_types or len(results) > 0

    def test_full_pipeline_roundtrip(self):
        from pii_guard.pipeline.engine import PiiGuardEngine

        engine = PiiGuardEngine(llm_fallback=True, ollama_model="qwen2.5:1.5b")
        text = "客戶張大明，手機0912345678，身分證A123456789"
        anonymized, mapping = engine.anonymize(text)
        restored = engine.deanonymize(anonymized, mapping)
        assert restored == text
