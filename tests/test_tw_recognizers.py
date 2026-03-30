"""Unit tests for Taiwan-specific PII recognizers (no model download needed)."""

from __future__ import annotations

import pytest

from pii_guard.recognizers.tw_business_recognizer import TwBusinessIdRecognizer
from pii_guard.recognizers.tw_id_recognizer import (
    TwArcRecognizer,
    TwNationalIdRecognizer,
    TwPassportRecognizer,
)
from pii_guard.recognizers.tw_misc_recognizers import TwCreditCardRecognizer, TwEmailRecognizer
from pii_guard.recognizers.tw_phone_recognizer import TwLandlineRecognizer, TwMobileRecognizer

# ── TwNationalIdRecognizer ────────────────────────────────────────────────────

class TestTwNationalIdRecognizer:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.r = TwNationalIdRecognizer()

    @pytest.mark.parametrize("text,expected_match", [
        ("A123456789", True),    # valid male ID
        ("B234567890", True),    # valid female ID
        ("Z199999999", True),    # uppercase Z
        ("A323456789", False),   # 2nd char must be 1 or 2
        ("a123456789", False),   # lowercase (ASCII mode: no IGNORECASE)
        ("A12345678",  False),   # only 9 digits total
        ("A1234567890", False),  # 11 digits
        ("1123456789",  False),  # starts with digit
        ("AB23456789",  False),  # 2nd char B is not 1 or 2
    ])
    def test_pattern(self, text, expected_match):
        results = self.r.analyze(text, entities=["TW_NATIONAL_ID"])
        matched = any(r.entity_type == "TW_NATIONAL_ID" for r in results)
        assert matched == expected_match, f"text={text!r}, results={results}"

    def test_entity_type_correct(self):
        results = self.r.analyze("A123456789", entities=["TW_NATIONAL_ID"])
        assert results[0].entity_type == "TW_NATIONAL_ID"

    def test_span_correct_standalone(self):
        """Verify span positions for a standalone ID."""
        text = "A123456789"
        results = self.r.analyze(text, entities=["TW_NATIONAL_ID"])
        assert len(results) == 1
        assert text[results[0].start:results[0].end] == "A123456789"

    def test_span_in_chinese_context(self):
        """Verify span positions when surrounded by Chinese text."""
        text = "身分證A123456789在這"
        results = self.r.analyze(text, entities=["TW_NATIONAL_ID"])
        assert len(results) == 1
        assert text[results[0].start:results[0].end] == "A123456789"


# ── TwPassportRecognizer ──────────────────────────────────────────────────────

class TestTwPassportRecognizer:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.r = TwPassportRecognizer()

    @pytest.mark.parametrize("text,expected_match", [
        ("A12345678",   True),   # valid: 1 letter + 8 digits
        ("B87654321",   True),   # valid
        ("Z00000000",   True),   # valid edge: all zeros
        ("a12345678",   False),  # lowercase
        ("1B2345678",   False),  # starts with digit
        ("A1234567",    False),  # only 8 chars total
        ("A123456789",  False),  # 10 chars → NID, not passport (lookahead blocks)
        ("AB12345678",  False),  # 2nd char is letter → ARC, not passport
    ])
    def test_pattern(self, text, expected_match):
        results = self.r.analyze(text, entities=["TW_PASSPORT"])
        matched = any(r.entity_type == "TW_PASSPORT" for r in results)
        assert matched == expected_match, f"text={text!r}"

    def test_no_conflict_with_nid(self):
        """NID (10 chars) must NOT be matched as passport."""
        r_nid = TwNationalIdRecognizer()
        nid_text = "A123456789"
        assert bool(r_nid.analyze(nid_text, entities=["TW_NATIONAL_ID"]))
        assert not bool(self.r.analyze(nid_text, entities=["TW_PASSPORT"]))

    def test_no_conflict_with_arc(self):
        """ARC (10 chars, 2nd char letter) must NOT be matched as passport."""
        r_arc = TwArcRecognizer()
        arc_text = "AB12345678"
        assert bool(r_arc.analyze(arc_text, entities=["TW_ARC"]))
        assert not bool(self.r.analyze(arc_text, entities=["TW_PASSPORT"]))

    def test_span_in_chinese_context(self):
        text = "護照號碼A12345678入境"
        results = self.r.analyze(text, entities=["TW_PASSPORT"])
        assert len(results) == 1
        assert text[results[0].start:results[0].end] == "A12345678"


# ── TwArcRecognizer ───────────────────────────────────────────────────────────

class TestTwArcRecognizer:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.r = TwArcRecognizer()

    @pytest.mark.parametrize("text,expected_match", [
        ("AB12345678", True),   # valid ARC (2nd char A-D)
        ("AC87654321", True),
        ("A812345678", True),   # 2nd char 8 is allowed
        ("A912345678", True),   # 2nd char 9 is allowed
        ("AA12345678", True),   # A is in A-D
        ("A123456789", False),  # 2nd char 1 is NOT in A-D89
    ])
    def test_pattern(self, text, expected_match):
        results = self.r.analyze(text, entities=["TW_ARC"])
        matched = any(r.entity_type == "TW_ARC" for r in results)
        assert matched == expected_match, f"text={text!r}"


# ── TwMobileRecognizer ────────────────────────────────────────────────────────

class TestTwMobileRecognizer:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.r = TwMobileRecognizer()

    @pytest.mark.parametrize("text,expected_match", [
        ("0912345678",   True),   # compact
        ("0812345678",   False),  # 08 is not mobile prefix
        ("091234567",    False),  # 9 digits only
        ("09123456789",  False),  # 11 digits
    ])
    def test_pattern(self, text, expected_match):
        results = self.r.analyze(text, entities=["TW_MOBILE"])
        matched = len(results) > 0
        assert matched == expected_match, f"text={text!r}"

    def test_dashed_format(self):
        results = self.r.analyze("0912-345-678", entities=["TW_MOBILE"])
        assert len(results) == 1


# ── TwLandlineRecognizer ──────────────────────────────────────────────────────

class TestTwLandlineRecognizer:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.r = TwLandlineRecognizer()

    @pytest.mark.parametrize("text,expected_match", [
        ("0212345678",    True),   # Taipei (02) – 10 digits
        ("0312345678",    True),   # Taoyuan (03) – valid area code
        ("0712345678",    True),   # Tainan (07)
        ("0912345678",    False),  # 09 is mobile, not landline
        ("(02)1234-5678", True),
        ("02-12345678",   True),
    ])
    def test_pattern(self, text, expected_match):
        results = self.r.analyze(text, entities=["TW_LANDLINE"])
        matched = len(results) > 0
        assert matched == expected_match, f"text={text!r}"


# ── TwBusinessIdRecognizer ────────────────────────────────────────────────────

class TestTwBusinessIdRecognizer:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.r = TwBusinessIdRecognizer()

    # --- checksum unit tests ---
    @pytest.mark.parametrize("number,expected_valid", [
        ("04595257", True),   # sum=40, 40%10==0
        ("12345678", False),  # sum=42, 42%10==2
        ("00000000", True),   # sum=0, 0%10==0 (edge case)
        # 7th digit = 7 special rule: total%10 != 0 but (total-1)%10 == 0
        ("10000070", True),   # d7=7, total=11, (11-1)%10==0 → special rule only
        ("10000178", True),   # d7=7, total=21, (21-1)%10==0 → special rule only
        ("10000276", True),   # d7=7, total=21, (21-1)%10==0 → special rule only
    ])
    def test_checksum(self, number, expected_valid):
        assert TwBusinessIdRecognizer._validate_checksum(number) == expected_valid, number

    # --- context filtering ---
    def test_no_context_no_match(self):
        # Plain 8-digit number without context keyword
        results = self.r.analyze("帳號是04595257", entities=["TW_BUSINESS_ID"])
        assert len(results) == 0, "Should not match without context keyword"

    def test_with_context_keyword(self):
        results = self.r.analyze("統一編號04595257", entities=["TW_BUSINESS_ID"])
        assert len(results) == 1
        assert results[0].entity_type == "TW_BUSINESS_ID"

    @pytest.mark.parametrize("keyword", [
        "統一編號", "統編", "公司", "廠商", "發票",
    ])
    def test_various_context_keywords(self, keyword):
        text = f"{keyword}04595257"
        results = self.r.analyze(text, entities=["TW_BUSINESS_ID"])
        assert len(results) == 1, f"keyword={keyword!r} should trigger detection"

    def test_context_window_distance(self):
        # Keyword more than 50 chars away → no match
        far_text = "統一編號" + "X" * 60 + "04595257"
        results = self.r.analyze(far_text, entities=["TW_BUSINESS_ID"])
        assert len(results) == 0

        # Keyword within 50 chars → match
        near_text = "統一編號" + "X" * 10 + "04595257"
        results = self.r.analyze(near_text, entities=["TW_BUSINESS_ID"])
        assert len(results) == 1

    def test_span_correct(self):
        text = "統一編號04595257"
        results = self.r.analyze(text, entities=["TW_BUSINESS_ID"])
        assert len(results) == 1
        assert text[results[0].start:results[0].end] == "04595257"


# ── TwEmailRecognizer ─────────────────────────────────────────────────────────

class TestTwEmailRecognizer:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.r = TwEmailRecognizer()

    @pytest.mark.parametrize("text,expected_match", [
        ("john@example.com",                True),   # standalone
        ("test.user+tag@sub.domain.com",    True),   # complex address
        ("電子郵件john@example.com以便聯絡",  True),   # no-space Chinese context
        ("請寄信到 john@example.com 謝謝",    True),   # space-separated Chinese
        ("notanemail@",                     False),  # missing domain
        ("@noemail.com",                    False),  # missing local part
        ("not@valid",                       False),  # missing TLD
    ])
    def test_pattern(self, text, expected_match):
        results = self.r.analyze(text, entities=["EMAIL_ADDRESS"])
        matched = any(r.entity_type == "EMAIL_ADDRESS" for r in results)
        assert matched == expected_match, f"text={text!r}"

    def test_span_no_space_chinese(self):
        """Span must capture only the email, not surrounding Chinese characters."""
        text = "電子郵件john@example.com以便聯絡"
        results = self.r.analyze(text, entities=["EMAIL_ADDRESS"])
        assert len(results) == 1
        assert text[results[0].start:results[0].end] == "john@example.com"


# ── TwCreditCardRecognizer ────────────────────────────────────────────────────

class TestTwCreditCardRecognizer:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.r = TwCreditCardRecognizer()

    @pytest.mark.parametrize("text,expected_match", [
        ("4111111111111111",          True),   # Visa test number (Luhn valid)
        ("5500005555555559",          True),   # Mastercard test number
        ("信用卡號 4111111111111111",   True),   # Chinese context
        ("4111111111111112",          False),  # Luhn checksum fails
        ("1234567890123456",          False),  # invalid prefix
    ])
    def test_pattern(self, text, expected_match):
        results = self.r.analyze(text, entities=["CREDIT_CARD"])
        matched = any(r.entity_type == "CREDIT_CARD" for r in results)
        assert matched == expected_match, f"text={text!r}"

    def test_span_in_chinese_context(self):
        text = "信用卡號 4111111111111111 請保密"
        results = self.r.analyze(text, entities=["CREDIT_CARD"])
        assert len(results) == 1
        assert text[results[0].start:results[0].end] == "4111111111111111"
