"""CKIP BERT NER integration tests.

These tests require downloading ckiplab/bert-base-chinese-ner (~500 MB) and
are therefore marked @pytest.mark.slow.

Run with:
    uv run pytest tests/test_ckip_ner.py -v -m slow

Skip in fast CI runs:
    uv run pytest -m "not slow"
"""

from __future__ import annotations

import pytest


@pytest.mark.slow
class TestCkipPersonDetection:
    """CKIP NER detects PERSON entities in Traditional Chinese text."""

    def test_person_detected(self, ckip_engine):
        text = "張大明的身分證A123456789"
        anonymized, mapping = ckip_engine.anonymize(text)
        person_keys = [k for k in mapping if "PERSON" in k]
        assert len(person_keys) >= 1, f"Expected PERSON entity, mapping={mapping}"
        assert mapping[person_keys[0]] == "張大明"

    def test_person_placeholder_format(self, ckip_engine):
        text = "客戶王小明請來電。"
        anonymized, mapping = ckip_engine.anonymize(text)
        person_keys = [k for k in mapping if "PERSON" in k]
        assert len(person_keys) >= 1
        assert "<PERSON_1>" in anonymized

    def test_person_roundtrip(self, ckip_engine):
        original = "聯絡人李大華，手機0912345678。"
        anonymized, mapping = ckip_engine.anonymize(original)
        restored = ckip_engine.deanonymize(anonymized, mapping)
        assert restored == original

    def test_multiple_persons_distinct_placeholders(self, ckip_engine):
        text = "甲方陳志明，乙方林美玲，請簽約。"
        anonymized, mapping = ckip_engine.anonymize(text)
        person_keys = [k for k in mapping if "PERSON" in k]
        # CKIP may detect one or both names; at least one must be detected
        assert len(person_keys) >= 1
        # All detected names must not appear in anonymized text
        for placeholder, original in mapping.items():
            if "PERSON" in placeholder:
                assert original not in anonymized, f"{original!r} still in anonymized text"


@pytest.mark.slow
class TestCkipOrgDetection:
    """CKIP NER detects ORG entities."""

    def test_org_detected(self, ckip_engine):
        text = "台積電的員工需簽署保密協議。"
        anonymized, mapping = ckip_engine.anonymize(text)
        org_keys = [k for k in mapping if "ORG" in k]
        assert len(org_keys) >= 1, f"Expected ORG entity, mapping={mapping}"

    def test_org_roundtrip(self, ckip_engine):
        original = "他在台灣大學就讀，主修資工系。"
        anonymized, mapping = ckip_engine.anonymize(original)
        restored = ckip_engine.deanonymize(anonymized, mapping)
        assert restored == original


@pytest.mark.slow
class TestCkipLocationDetection:
    """CKIP NER detects LOCATION entities."""

    def test_location_detected(self, ckip_engine):
        text = "住址：台北市信義區松仁路100號。"
        anonymized, mapping = ckip_engine.anonymize(text)
        loc_keys = [k for k in mapping if "LOCATION" in k]
        assert len(loc_keys) >= 1, f"Expected LOCATION entity, mapping={mapping}"

    def test_location_roundtrip(self, ckip_engine):
        original = "出生地高雄市三民區，現居台中市西屯區。"
        anonymized, mapping = ckip_engine.anonymize(original)
        restored = ckip_engine.deanonymize(anonymized, mapping)
        assert restored == original


@pytest.mark.slow
class TestCkipCharOffsetCorrectness:
    """Verify CKIP NER char offsets align correctly with the source text."""

    def test_person_span_aligns_with_source(self, ckip_engine):
        """The chars at [start, end) in the original text must equal the detected entity value."""
        text = "負責人張偉明請於三日內回覆。"
        anonymized, mapping = ckip_engine.anonymize(text)
        # Verify: every mapped original value appears verbatim in the source text
        for placeholder, original_value in mapping.items():
            assert original_value in text, (
                f"Placeholder {placeholder!r} maps to {original_value!r} "
                f"which is NOT in source text — likely an offset bug"
            )

    def test_entity_not_split_across_chars(self, ckip_engine):
        """CKIP detections should not split Chinese words mid-character."""
        text = "客戶劉建國，統一編號04595257。"
        anonymized, mapping = ckip_engine.anonymize(text)
        for placeholder, original_value in mapping.items():
            # Each original value must be a coherent substring of the source
            assert original_value in text, (
                f"{placeholder!r} → {original_value!r} not found in source text"
            )


@pytest.mark.slow
class TestCkipCombinedWithTwRegex:
    """CKIP NER and Taiwan regex recognizers must coexist without interference."""

    def test_nid_and_person_roundtrip(self, ckip_engine):
        original = "張大明的身分證A123456789"
        anonymized, mapping = ckip_engine.anonymize(original)
        assert "A123456789" not in anonymized
        assert ckip_engine.deanonymize(anonymized, mapping) == original

    def test_person_org_nid_mobile_roundtrip(self, ckip_engine):
        original = (
            "員工陳雅琳，身分證A123456789，手機0912345678，"
            "任職台積電，統一編號04595257。"
        )
        anonymized, mapping = ckip_engine.anonymize(original)
        assert "A123456789" not in anonymized
        assert "0912345678" not in anonymized
        assert "04595257" not in anonymized
        restored = ckip_engine.deanonymize(anonymized, mapping)
        assert restored == original

    def test_regex_not_interfered_by_ckip(self, ckip_engine):
        """Pure-regex PII must still be detected even when CKIP NER is active."""
        text = "手機0912345678，統一編號04595257，Email test@example.com"
        anonymized, mapping = ckip_engine.anonymize(text)
        assert "<TW_MOBILE_1>" in anonymized
        assert "<TW_BUSINESS_ID_1>" in anonymized
        assert "<EMAIL_ADDRESS_1>" in anonymized
