"""Taiwan national ID and foreign resident certificate recognizers."""

from __future__ import annotations

from typing import ClassVar, List

from presidio_analyzer import Pattern, PatternRecognizer


class TwNationalIdRecognizer(PatternRecognizer):
    """Taiwan national ID: [A-Z][12]\\d{8}, e.g. A123456789."""

    SUPPORTED_ENTITY: ClassVar[str] = "TW_NATIONAL_ID"
    PATTERNS: ClassVar[List[Pattern]] = [
        Pattern("TW_NATIONAL_ID", r"\b[A-Z][12]\d{8}\b", 0.9),
    ]
    CONTEXT: ClassVar[List[str]] = [
        "身分證", "身份證", "證號", "國民身分證", "身分證字號", "ID",
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity=self.SUPPORTED_ENTITY,
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="zh",
        )


class TwArcRecognizer(PatternRecognizer):
    """Taiwan Alien Resident Certificate: [A-Z][A-D89]\\d{8}, e.g. AB12345678."""

    SUPPORTED_ENTITY: ClassVar[str] = "TW_ARC"
    PATTERNS: ClassVar[List[Pattern]] = [
        Pattern("TW_ARC", r"\b[A-Z][A-D89]\d{8}\b", 0.85),
    ]
    CONTEXT: ClassVar[List[str]] = [
        "居留證", "外僑居留證", "外籍居留證", "ARC", "外籍", "居留",
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity=self.SUPPORTED_ENTITY,
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="zh",
        )
