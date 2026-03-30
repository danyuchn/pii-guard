"""Integration tests for PiiGuardEngine (Taiwan regex only, no CKIP download)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest


class TestPiiGuardEngineAnonymize:
    """Tests using spacy_only_engine (no CKIP model download)."""

    def test_tw_national_id_replaced(self, spacy_only_engine):
        text = "身分證A123456789"
        anonymized, mapping = spacy_only_engine.anonymize(text)
        assert "A123456789" not in anonymized
        assert any("TW_NATIONAL_ID" in k for k in mapping)

    def test_placeholder_format(self, spacy_only_engine):
        text = "身分證A123456789"
        anonymized, mapping = spacy_only_engine.anonymize(text)
        assert "<TW_NATIONAL_ID_1>" in anonymized
        assert "<TW_NATIONAL_ID_1>" in mapping

    def test_tw_mobile_replaced(self, spacy_only_engine):
        text = "手機0912345678"
        anonymized, mapping = spacy_only_engine.anonymize(text)
        assert "0912345678" not in anonymized
        assert any("TW_MOBILE" in k for k in mapping)

    def test_tw_business_id_with_context(self, spacy_only_engine):
        text = "統一編號04595257"
        anonymized, mapping = spacy_only_engine.anonymize(text)
        assert "04595257" not in anonymized
        assert any("TW_BUSINESS_ID" in k for k in mapping)

    def test_multiple_pii_types(self, spacy_only_engine):
        text = "身分證A123456789，手機0912345678，統一編號04595257"
        anonymized, mapping = spacy_only_engine.anonymize(text)
        assert "A123456789" not in anonymized
        assert "0912345678" not in anonymized
        assert "04595257" not in anonymized
        assert len(mapping) >= 3

    def test_mapping_value_is_original(self, spacy_only_engine):
        text = "身分證A123456789"
        anonymized, mapping = spacy_only_engine.anonymize(text)
        # mapping is {placeholder: original}
        assert "A123456789" in mapping.values()

    def test_no_pii_text_unchanged(self, spacy_only_engine):
        text = "今天天氣很好，無任何個資。"
        anonymized, mapping = spacy_only_engine.anonymize(text)
        assert anonymized == text
        assert len(mapping) == 0


class TestPiiGuardEngineRoundtrip:
    """Roundtrip: deanonymize(anonymize(text)) == text."""

    def test_single_entity_roundtrip(self, spacy_only_engine):
        original = "身分證A123456789"
        anonymized, mapping = spacy_only_engine.anonymize(original)
        restored = spacy_only_engine.deanonymize(anonymized, mapping)
        assert restored == original

    def test_multi_entity_roundtrip(self, spacy_only_engine):
        original = "身分證A123456789，手機0912345678，統一編號04595257"
        anonymized, mapping = spacy_only_engine.anonymize(original)
        restored = spacy_only_engine.deanonymize(anonymized, mapping)
        assert restored == original

    def test_full_sample_roundtrip(self, spacy_only_engine):
        """Uses the fixture sample file."""
        sample = Path(__file__).parent / "fixtures" / "sample.txt"
        original = sample.read_text(encoding="utf-8")
        anonymized, mapping = spacy_only_engine.anonymize(original)
        restored = spacy_only_engine.deanonymize(anonymized, mapping)
        assert restored == original


class TestRepeatedEntities:
    """Same PII value appearing multiple times must use the same placeholder."""

    def test_same_id_same_placeholder(self, spacy_only_engine):
        text = "身分證A123456789，再次：A123456789"
        anonymized, mapping = spacy_only_engine.anonymize(text)
        tw_id_entries = {k: v for k, v in mapping.items() if "TW_NATIONAL_ID" in k}
        assert len(tw_id_entries) == 1
        assert list(tw_id_entries.values())[0] == "A123456789"
        assert anonymized.count("<TW_NATIONAL_ID_1>") == 2

    def test_different_ids_different_placeholders(self, spacy_only_engine):
        text = "甲身分證A123456789，乙身分證B234567890"
        anonymized, mapping = spacy_only_engine.anonymize(text)
        tw_id_entries = {k for k in mapping if "TW_NATIONAL_ID" in k}
        assert len(tw_id_entries) == 2
        assert "<TW_NATIONAL_ID_1>" in mapping
        assert "<TW_NATIONAL_ID_2>" in mapping


class TestDeanonymizeSafety:
    """Edge cases in deanonymize to prevent partial replacements."""

    def test_longer_placeholder_not_shadowed_by_shorter(self, spacy_only_engine):
        # <TW_NATIONAL_ID_10> must not be partially replaced by <TW_NATIONAL_ID_1>
        mapping = {
            "<TW_NATIONAL_ID_1>": "A123456789",
            "<TW_NATIONAL_ID_10>": "Z199999999",
        }
        text = "<TW_NATIONAL_ID_10> 和 <TW_NATIONAL_ID_1>"
        restored = spacy_only_engine.deanonymize(text, mapping)
        assert restored == "Z199999999 和 A123456789"

    def test_empty_mapping_returns_unchanged(self, spacy_only_engine):
        text = "沒有佔位符的文本"
        restored = spacy_only_engine.deanonymize(text, {})
        assert restored == text


class TestMappingPersistence:
    """save_mapping / load_mapping roundtrip."""

    def test_save_and_load(self, spacy_only_engine, tmp_path):
        from pii_guard.pipeline.engine import PiiGuardEngine

        original = "身分證A123456789"
        anonymized, mapping = spacy_only_engine.anonymize(original)

        save_path = tmp_path / "mapping.json"
        PiiGuardEngine.save_mapping(mapping, save_path)

        # File must be valid JSON
        loaded = json.loads(save_path.read_text(encoding="utf-8"))
        assert loaded == mapping

        # Load via API
        loaded_via_api = PiiGuardEngine.load_mapping(save_path)
        assert loaded_via_api == mapping

    def test_restore_via_saved_mapping(self, spacy_only_engine, tmp_path):
        from pii_guard.pipeline.engine import PiiGuardEngine

        original = "手機0912345678，統一編號04595257"
        anonymized, mapping = spacy_only_engine.anonymize(original)

        save_path = tmp_path / "mapping.json"
        PiiGuardEngine.save_mapping(mapping, save_path)

        # Load and restore
        loaded_mapping = PiiGuardEngine.load_mapping(save_path)
        restored = PiiGuardEngine.deanonymize(anonymized, loaded_mapping)
        assert restored == original
