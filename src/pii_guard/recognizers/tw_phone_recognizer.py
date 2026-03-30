"""Taiwan mobile and landline phone recognizers."""

from __future__ import annotations

import re
from typing import ClassVar

from presidio_analyzer import Pattern, PatternRecognizer

# Override Presidio's default (which includes IGNORECASE).
# Use lookarounds instead of \b: re.ASCII maps to regex.V1 in the regex module
# used by Presidio internally, breaking boundary detection in Chinese text.
_FLAGS = re.DOTALL | re.MULTILINE


class TwMobileRecognizer(PatternRecognizer):
    """Taiwan mobile: 09xxxxxxxx, with optional dash/space separators."""

    SUPPORTED_ENTITY: ClassVar[str] = "TW_MOBILE"
    PATTERNS: ClassVar[list[Pattern]] = [
        Pattern("TW_MOBILE_COMPACT", r"(?<!\d)09\d{8}(?!\d)", 0.9),
        Pattern("TW_MOBILE_DASHED", r"(?<!\d)09\d{2}[-\s]\d{3}[-\s]\d{3}(?!\d)", 0.9),
    ]
    CONTEXT: ClassVar[list[str]] = [
        "手機", "行動電話", "手機號碼", "行動", "mobile", "cell",
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity=self.SUPPORTED_ENTITY,
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="zh",
            global_regex_flags=_FLAGS,
        )


class TwLandlineRecognizer(PatternRecognizer):
    """Taiwan landline: 0[2-8]xxxxxxx(x), with optional parentheses/dashes."""

    SUPPORTED_ENTITY: ClassVar[str] = "TW_LANDLINE"
    PATTERNS: ClassVar[list[Pattern]] = [
        # Compact: 0212345678
        Pattern("TW_LANDLINE_COMPACT", r"(?<!\d)0[2-8]\d{7,8}(?!\d)", 0.7),
        # With parentheses: (02)1234-5678
        Pattern("TW_LANDLINE_PAREN", r"\(0[2-8]\)\s*\d{4}[-\s]?\d{4}", 0.85),
        # With hyphen after area code: 02-12345678
        Pattern("TW_LANDLINE_HYPHEN", r"(?<!\d)0[2-8]-\d{7,8}(?!\d)", 0.85),
    ]
    CONTEXT: ClassVar[list[str]] = [
        "電話", "市話", "辦公室", "公司電話", "聯絡電話", "分機", "phone", "tel",
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity=self.SUPPORTED_ENTITY,
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="zh",
            global_regex_flags=_FLAGS,
        )
