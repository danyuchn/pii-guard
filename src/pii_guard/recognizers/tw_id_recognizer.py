"""Taiwan national ID and foreign resident certificate recognizers."""

from __future__ import annotations

import re
from typing import ClassVar

from presidio_analyzer import Pattern, PatternRecognizer

# Override Presidio's default (which includes IGNORECASE) so [A-Z] stays case-sensitive.
# Use lookarounds instead of \b: re.ASCII maps to regex.V1 in the regex module that
# Presidio uses internally, so \b with re.ASCII does NOT work correctly in Chinese text.
_FLAGS = re.DOTALL | re.MULTILINE


class TwNationalIdRecognizer(PatternRecognizer):
    """Taiwan national ID: [A-Z][12]\\d{8}, e.g. A123456789."""

    SUPPORTED_ENTITY: ClassVar[str] = "TW_NATIONAL_ID"
    PATTERNS: ClassVar[list[Pattern]] = [
        Pattern("TW_NATIONAL_ID", r"(?<![A-Za-z0-9])[A-Z][12]\d{8}(?![A-Za-z0-9])", 0.9),
    ]
    CONTEXT: ClassVar[list[str]] = [
        "身分證", "身份證", "證號", "國民身分證", "身分證字號", "ID",
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity=self.SUPPORTED_ENTITY,
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="zh",
            global_regex_flags=_FLAGS,
        )


class TwArcRecognizer(PatternRecognizer):
    """Taiwan Alien Resident Certificate: [A-Z][A-D89]\\d{8}, e.g. AB12345678."""

    SUPPORTED_ENTITY: ClassVar[str] = "TW_ARC"
    PATTERNS: ClassVar[list[Pattern]] = [
        Pattern("TW_ARC", r"(?<![A-Za-z0-9])[A-Z][A-D89]\d{8}(?![A-Za-z0-9])", 0.85),
    ]
    CONTEXT: ClassVar[list[str]] = [
        "居留證", "外僑居留證", "外籍居留證", "ARC", "外籍", "居留",
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity=self.SUPPORTED_ENTITY,
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="zh",
            global_regex_flags=_FLAGS,
        )


class TwPassportRecognizer(PatternRecognizer):
    """Taiwan passport number: [A-Z]\\d{8} (9 chars), e.g. A12345678.

    Distinct from NationalID ([A-Z][12]\\d{8}, 10 chars) and ARC ([A-Z][A-D89]\\d{8},
    10 chars): passport has exactly 9 characters and the second character is always
    a digit (0-9), not a letter.  The trailing lookahead (?![A-Za-z0-9]) prevents
    matching the first 9 chars of a 10-char NID/ARC.
    """

    SUPPORTED_ENTITY: ClassVar[str] = "TW_PASSPORT"
    PATTERNS: ClassVar[list[Pattern]] = [
        Pattern("TW_PASSPORT", r"(?<![A-Za-z0-9])[A-Z]\d{8}(?![A-Za-z0-9])", 0.6),
    ]
    CONTEXT: ClassVar[list[str]] = [
        "護照", "passport", "護照號碼", "護照號", "出入境",
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity=self.SUPPORTED_ENTITY,
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="zh",
            global_regex_flags=_FLAGS,
        )
