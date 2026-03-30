"""Integration tests for PiiGuardEngine (Taiwan regex only, no CKIP download)."""

from __future__ import annotations

import json
from pathlib import Path


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


class TestMixedEntityTypes:
    """Pipeline-level tests for texts containing multiple Taiwan PII types simultaneously."""

    def test_nid_and_arc_same_text(self, spacy_only_engine):
        """NID and ARC in the same text must be detected independently."""
        text = "甲的身分證A123456789，乙的居留證AB12345678"
        anonymized, mapping = spacy_only_engine.anonymize(text)

        nid_keys = [k for k in mapping if "TW_NATIONAL_ID" in k]
        arc_keys = [k for k in mapping if "TW_ARC" in k]
        assert len(nid_keys) == 1, "should detect exactly one NID"
        assert len(arc_keys) == 1, "should detect exactly one ARC"
        # Placeholders must differ
        assert nid_keys[0] != arc_keys[0]
        # Roundtrip
        assert spacy_only_engine.deanonymize(anonymized, mapping) == text

    def test_nid_and_passport_same_text(self, spacy_only_engine):
        """NID (10 chars) and passport (9 chars) in the same text."""
        text = "護照A12345678，身分證A123456789"
        anonymized, mapping = spacy_only_engine.anonymize(text)

        passport_keys = [k for k in mapping if "TW_PASSPORT" in k]
        nid_keys = [k for k in mapping if "TW_NATIONAL_ID" in k]
        assert len(passport_keys) == 1
        assert len(nid_keys) == 1
        assert spacy_only_engine.deanonymize(anonymized, mapping) == text

    def test_all_tw_types_roundtrip(self, spacy_only_engine):
        """Text containing NID, mobile, landline, business ID, email, and passport."""
        text = (
            "身分證A123456789，"
            "護照B12345678，"
            "手機0912345678，"
            "電話0212345678，"
            "統一編號04595257，"
            "信箱test@example.com"
        )
        anonymized, mapping = spacy_only_engine.anonymize(text)

        assert "<TW_NATIONAL_ID_1>" in anonymized
        assert "<TW_PASSPORT_1>" in anonymized
        assert "<TW_MOBILE_1>" in anonymized
        assert "<TW_LANDLINE_1>" in anonymized
        assert "<TW_BUSINESS_ID_1>" in anonymized
        assert "<EMAIL_ADDRESS_1>" in anonymized
        # Roundtrip must be lossless
        assert spacy_only_engine.deanonymize(anonymized, mapping) == text

    def test_email_and_credit_card_roundtrip(self, spacy_only_engine):
        text = "信箱john@example.com，信用卡4111111111111111"
        anonymized, mapping = spacy_only_engine.anonymize(text)

        assert "<EMAIL_ADDRESS_1>" in anonymized
        assert "<CREDIT_CARD_1>" in anonymized
        assert spacy_only_engine.deanonymize(anonymized, mapping) == text
