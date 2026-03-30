"""Taiwan Unified Business Number (統一編號) recognizer with context + checksum validation."""

from __future__ import annotations

import re
from typing import ClassVar

from presidio_analyzer import LocalRecognizer, RecognizerResult
from presidio_analyzer.nlp_engine import NlpArtifacts


class TwBusinessIdRecognizer(LocalRecognizer):
    """
    Recognizes Taiwan Unified Business Numbers (統一編號, 8 digits).

    Uses two-layer filtering to minimize false positives:
    1. Context keyword within ±50 characters
    2. Official MOF checksum validation (weighted digits + special rule for 7th digit = 7)
    """

    SUPPORTED_ENTITY: ClassVar[str] = "TW_BUSINESS_ID"
    # Lookaround instead of \b: re.ASCII maps to regex.V1 in Presidio's regex module,
    # breaking boundary detection in Chinese text.
    PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"(?<!\d)\d{8}(?!\d)")
    CONTEXT_KEYWORDS: ClassVar[list[str]] = [
        "統一編號", "統編", "公司", "廠商", "發票", "稅籍", "法人", "營業",
        "企業", "行號", "商號",
    ]
    CONTEXT_WINDOW: ClassVar[int] = 50
    _WEIGHTS: ClassVar[list[int]] = [1, 2, 1, 2, 1, 2, 4, 1]

    def __init__(self) -> None:
        super().__init__(
            supported_entities=[self.SUPPORTED_ENTITY],
            supported_language="zh",
            name="TwBusinessIdRecognizer",
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
            if not self._validate_checksum(number):
                continue
            if not self._has_context(text, match.start(), match.end()):
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

    @classmethod
    def _validate_checksum(cls, number: str) -> bool:
        """
        Taiwan MOF checksum: sum weighted cross-products mod 10 == 0.
        Special rule: when 7th digit (index 6) is '7', also accept (total - 1) % 10 == 0.
        """
        if len(number) != 8 or not number.isdigit():
            return False
        total = sum(
            (int(d) * w) // 10 + (int(d) * w) % 10
            for d, w in zip(number, cls._WEIGHTS)
        )
        if total % 10 == 0:
            return True
        # Special case: 7 × 4 = 28 can also be counted as 9 (alternative path)
        if number[6] == "7" and (total - 1) % 10 == 0:
            return True
        return False

    def _has_context(self, text: str, start: int, end: int) -> bool:
        window_start = max(0, start - self.CONTEXT_WINDOW)
        window_end = min(len(text), end + self.CONTEXT_WINDOW)
        window = text[window_start:window_end]
        return any(kw in window for kw in self.CONTEXT_KEYWORDS)
