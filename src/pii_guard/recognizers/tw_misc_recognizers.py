"""Email and credit card recognizers with Traditional Chinese (zh) language support.

Presidio's built-in EmailRecognizer uses \\b boundaries that fail adjacent to Chinese
characters (\\w in Unicode mode).  TwEmailRecognizer replaces \\b with lookarounds and
uses explicit ASCII character classes so Chinese text is never part of the match.

CreditCardRecognizer only registers for 'en'; TwCreditCardRecognizer re-uses the
same Luhn-validated logic but registers for 'zh'.
"""

from __future__ import annotations

import re
from typing import ClassVar

from presidio_analyzer import Pattern, PatternRecognizer
from presidio_analyzer.predefined_recognizers import CreditCardRecognizer

# ── Email ─────────────────────────────────────────────────────────────────────

class TwEmailRecognizer(PatternRecognizer):
    """Email recognizer for zh context with lookaround-based boundaries.

    Presidio's built-in EmailRecognizer relies on word boundaries, which fail when
    the email sits directly adjacent to Chinese characters.  This recognizer uses
    explicit ASCII character classes so Chinese text cannot be included in the match,
    and negative lookarounds so no word-boundary assumption is needed.
    """

    SUPPORTED_ENTITY: ClassVar[str] = "EMAIL_ADDRESS"
    PATTERNS: ClassVar[list[Pattern]] = [
        Pattern(
            "Email (zh)",
            r"(?<![A-Za-z0-9.@])[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}(?![A-Za-z0-9.@])",
            0.85,
        ),
    ]
    CONTEXT: ClassVar[list[str]] = [
        "信箱", "電郵", "email", "e-mail", "郵件", "寄信",
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity=self.SUPPORTED_ENTITY,
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="zh",
            global_regex_flags=re.ASCII,
        )


# ── Credit Card ───────────────────────────────────────────────────────────────

class TwCreditCardRecognizer(CreditCardRecognizer):
    """Credit card recognizer for zh context.

    Inherits Presidio's full Luhn-checksum validation.  Replaces \\b boundaries
    in the original pattern with (?<!\\d) / (?!\\d) lookarounds so the recognizer
    works when a credit card number is adjacent to Chinese characters.
    """

    def __init__(self) -> None:
        super().__init__(supported_language="zh")
        # Replace \b with digit-only lookarounds to handle Chinese adjacency
        for p in self.patterns:  # type: ignore[has-type]
            p.regex = p.regex.replace(r"\b", "").strip()
            p.regex = r"(?<!\d)" + p.regex + r"(?!\d)"
