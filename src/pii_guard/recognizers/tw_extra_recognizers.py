"""Taiwan license plate, birth date, international mobile, and bank account recognizers.

Additional Taiwan PII types beyond the Phase 1 set.  All use lookarounds rather
than \\b boundaries (re.ASCII maps to regex.V1 in Presidio's internal regex module,
breaking boundary detection adjacent to Chinese characters).

Ambiguous numeric patterns (license plates, bank accounts, Western dates) require
a context keyword within ±50 characters to fire; self-contextualizing patterns
(Minguo dates with 民國 embedded, +886 prefix) do not.
"""

from __future__ import annotations

import re
from typing import ClassVar

from presidio_analyzer import LocalRecognizer, Pattern, PatternRecognizer, RecognizerResult
from presidio_analyzer.nlp_engine import NlpArtifacts

_FLAGS = re.DOTALL | re.MULTILINE
_CONTEXT_WINDOW = 50


def _has_context(text: str, start: int, end: int, keywords: list[str]) -> bool:
    """Return True if any keyword appears within ±CONTEXT_WINDOW chars of [start, end)."""
    ws = max(0, start - _CONTEXT_WINDOW)
    we = min(len(text), end + _CONTEXT_WINDOW)
    window = text[ws:we]
    return any(kw in window for kw in keywords)


# ── License Plate ──────────────────────────────────────────────────────────────

class TwLicensePlateRecognizer(LocalRecognizer):
    """Taiwan vehicle license plates (new and old formats) with context filter.

    New format: 2–3 uppercase letters + dash + 4 digits  (e.g. ABC-1234)
    Old format: 3–4 digits + dash + 2 uppercase letters  (e.g. 1234-AB)

    A context keyword is required within ±50 chars to suppress false positives
    from product codes, model numbers, etc.
    """

    SUPPORTED_ENTITY: ClassVar[str] = "TW_LICENSE_PLATE"
    # Compile with re.ASCII so [A-Z] / \d only match ASCII characters
    _PATTERNS: ClassVar[list[re.Pattern[str]]] = [
        re.compile(r"(?<![A-Za-z0-9])[A-Z]{2,3}-\d{4}(?![A-Za-z0-9])", re.ASCII),  # new
        re.compile(r"(?<!\d)\d{3,4}-[A-Z]{2}(?![A-Za-z0-9])", re.ASCII),            # old
    ]
    CONTEXT_KEYWORDS: ClassVar[list[str]] = [
        "車牌", "牌照", "車號", "車輛", "汽車", "機車", "行照", "號牌", "車籍", "車",
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entities=[self.SUPPORTED_ENTITY],
            supported_language="zh",
            name="TwLicensePlateRecognizer",
        )

    def load(self) -> None:
        pass

    def analyze(
        self,
        text: str,
        entities: list[str],
        nlp_artifacts: NlpArtifacts | None = None,
    ) -> list[RecognizerResult]:
        if self.SUPPORTED_ENTITY not in entities:
            return []
        results: list[RecognizerResult] = []
        for pattern in self._PATTERNS:
            for match in pattern.finditer(text):
                if not _has_context(text, match.start(), match.end(), self.CONTEXT_KEYWORDS):
                    continue
                results.append(
                    RecognizerResult(
                        entity_type=self.SUPPORTED_ENTITY,
                        start=match.start(),
                        end=match.end(),
                        score=0.85,
                    )
                )
        return results


# ── Birth Date ─────────────────────────────────────────────────────────────────

class TwBirthDateRecognizer(LocalRecognizer):
    """Taiwan birth dates: Minguo calendar or Western ISO-style.

    Minguo pattern (e.g. 民國90年1月1日) embeds 民國 as a literal anchor so it
    is self-contextualizing — no external keyword needed (score = 0.9).

    Western pattern (e.g. 1990-01-01 / 1990/01/01 / 1990.01.01) is extremely
    common and would cause too many false positives without a hard context gate.
    A keyword within ±30 chars is required (score = 0.85 when matched).
    """

    SUPPORTED_ENTITY: ClassVar[str] = "TW_BIRTH_DATE"
    _MINGUO: ClassVar[re.Pattern[str]] = re.compile(
        r"民國\s?\d{2,3}\s?年\s?\d{1,2}\s?月\s?\d{1,2}\s?日",
        _FLAGS,
    )
    _WESTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"(?<!\d)\d{4}[-/.]\d{1,2}[-/.]\d{1,2}(?!\d)",
        _FLAGS,
    )
    CONTEXT_KEYWORDS: ClassVar[list[str]] = [
        "生日", "出生", "出生日期", "出生年月日", "出生日", "DOB", "birthday",
        "生日期", "出生年", "年齡",
    ]
    _WESTERN_WINDOW: ClassVar[int] = 30  # tighter window for Western dates

    def __init__(self) -> None:
        super().__init__(
            supported_entities=[self.SUPPORTED_ENTITY],
            supported_language="zh",
            name="TwBirthDateRecognizer",
        )

    def load(self) -> None:
        pass

    def analyze(
        self,
        text: str,
        entities: list[str],
        nlp_artifacts: NlpArtifacts | None = None,
    ) -> list[RecognizerResult]:
        if self.SUPPORTED_ENTITY not in entities:
            return []
        results: list[RecognizerResult] = []
        # Minguo: 民國 prefix is self-contextualizing
        for match in self._MINGUO.finditer(text):
            results.append(
                RecognizerResult(
                    entity_type=self.SUPPORTED_ENTITY,
                    start=match.start(),
                    end=match.end(),
                    score=0.9,
                )
            )
        # Western: requires context keyword within ±30 chars
        for match in self._WESTERN.finditer(text):
            if _has_context(text, match.start(), match.end(), self.CONTEXT_KEYWORDS):
                results.append(
                    RecognizerResult(
                        entity_type=self.SUPPORTED_ENTITY,
                        start=match.start(),
                        end=match.end(),
                        score=0.85,
                    )
                )
        return results


# ── International Mobile (+886) ────────────────────────────────────────────────

class TwIntlMobileRecognizer(PatternRecognizer):
    """Taiwan mobile in international dialling format: +886-9XX-XXX-XXX.

    Covers compact (+886912345678), dash-separated (+886-912-345-678), and
    space-separated (+886 912 345 678) variants.  The +886 prefix is a strong
    signal on its own (score = 0.9); context keywords further boost confidence.

    Uses the same entity type (TW_MOBILE) as TwMobileRecognizer so all mobile
    numbers collapse into a single placeholder series regardless of format.
    """

    SUPPORTED_ENTITY: ClassVar[str] = "TW_MOBILE"
    PATTERNS: ClassVar[list[Pattern]] = [
        Pattern(
            "TW_MOBILE_INTL",
            r"\+886[-\s]?9\d{2}[-\s]?\d{3}[-\s]?\d{3}",
            0.9,
        ),
    ]
    CONTEXT: ClassVar[list[str]] = [
        "手機", "電話", "mobile", "phone", "聯絡", "聯繫", "行動電話",
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity=self.SUPPORTED_ENTITY,
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="zh",
            global_regex_flags=_FLAGS,
        )


# ── Bank Account ───────────────────────────────────────────────────────────────

class TwBankAccountRecognizer(LocalRecognizer):
    """Taiwan bank account numbers (12–16 digits) with mandatory context filter.

    Raw 12–16 digit strings are extremely ambiguous (timestamps, order numbers,
    credit card PANs, etc.).  A context keyword is required within ±50 chars to
    avoid false positives.  Luhn-valid numbers are skipped because they are
    handled by TwCreditCardRecognizer.
    """

    SUPPORTED_ENTITY: ClassVar[str] = "TW_BANK_ACCOUNT"
    PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"(?<!\d)\d{12,16}(?!\d)", re.ASCII)
    CONTEXT_KEYWORDS: ClassVar[list[str]] = [
        "帳號", "帳戶", "存摺", "銀行", "轉帳", "匯款", "戶號", "銀行帳戶",
        "銀行帳號", "帳", "存款", "金融帳號",
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entities=[self.SUPPORTED_ENTITY],
            supported_language="zh",
            name="TwBankAccountRecognizer",
        )

    def load(self) -> None:
        pass

    def analyze(
        self,
        text: str,
        entities: list[str],
        nlp_artifacts: NlpArtifacts | None = None,
    ) -> list[RecognizerResult]:
        if self.SUPPORTED_ENTITY not in entities:
            return []
        results: list[RecognizerResult] = []
        for match in self.PATTERN.finditer(text):
            number = match.group()
            # Only exclude Luhn-valid numbers at credit card lengths (13-16 digits)
            if len(number) >= 13 and self._is_luhn_valid(number):
                continue
            if not _has_context(text, match.start(), match.end(), self.CONTEXT_KEYWORDS):
                continue
            results.append(
                RecognizerResult(
                    entity_type=self.SUPPORTED_ENTITY,
                    start=match.start(),
                    end=match.end(),
                    score=0.85,
                )
            )
        return results

    @staticmethod
    def _is_luhn_valid(number: str) -> bool:
        """Return True if *number* passes the Luhn checksum (likely a credit card)."""
        digits = [int(d) for d in number]
        checksum = 0
        for i, d in enumerate(reversed(digits)):
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            checksum += d
        return checksum % 10 == 0
