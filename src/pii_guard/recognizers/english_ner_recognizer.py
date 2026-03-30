"""English NER recognizer using spaCy en_core_web_sm.

Runs alongside CKIP (Chinese NER) on the same text to detect English
person names, organizations, and locations in mixed zh/en documents.
Registered for ``zh`` language so Presidio invokes it on every call
without requiring language detection or text splitting.

Strategy: extract contiguous ASCII "islands" from the text, run English
NER on each island independently, then map detected spans back to the
original character offsets.  This avoids feeding CJK characters into
``en_core_web_sm`` which produces garbage when it encounters them.
"""

from __future__ import annotations

import logging
import re
from typing import ClassVar

from presidio_analyzer import LocalRecognizer, RecognizerResult
from presidio_analyzer.nlp_engine import NlpArtifacts

logger = logging.getLogger(__name__)

# spaCy NER label → Presidio entity type
_EN_LABEL_MAP: dict[str, str] = {
    "PERSON": "PERSON",
    "ORG": "ORG",
    "GPE": "LOCATION",
    "LOC": "LOCATION",
    "FAC": "LOCATION",
}

# Match contiguous runs of ASCII characters (at least 2 letters required
# to avoid single-letter false positives like "A" in ID numbers).
_ASCII_ISLAND = re.compile(r"[A-Za-z][A-Za-z0-9 .'\-]{1,}[A-Za-z0-9.]")

# Skip ASCII islands that look like email addresses or URLs
_EMAIL_LIKE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


class EnglishNerRecognizer(LocalRecognizer):
    """Detect English PERSON / ORG / LOCATION via spaCy ``en_core_web_sm``.

    The model is loaded lazily on first ``analyze()`` call (~12 MB download).
    Detection score is set to 0.80, slightly below CKIP's 0.85, so that when
    both recognizers fire on the same span Presidio's dedup keeps the more
    specific CKIP result.
    """

    SUPPORTED_ENTITIES: ClassVar[list[str]] = ["PERSON", "ORG", "LOCATION"]
    DEFAULT_SCORE: ClassVar[float] = 0.80
    MODEL_NAME: ClassVar[str] = "en_core_web_sm"

    def __init__(self, model_name: str = MODEL_NAME) -> None:
        self._model_name = model_name
        self._nlp = None  # lazy-loaded
        super().__init__(
            supported_entities=self.SUPPORTED_ENTITIES,
            supported_language="zh",  # register for zh so it runs with CKIP
            name="EnglishNerRecognizer",
        )

    def load(self) -> None:
        """Lazy-load the spaCy English model."""
        if self._nlp is None:
            import spacy

            self._nlp = spacy.load(self._model_name, disable=["parser", "lemmatizer"])
            logger.info("EnglishNerRecognizer loaded model: %s", self._model_name)

    def analyze(
        self,
        text: str,
        entities: list[str],
        nlp_artifacts: NlpArtifacts | None = None,
    ) -> list[RecognizerResult]:
        requested = set(entities) & set(self.SUPPORTED_ENTITIES)
        if not requested:
            return []

        self.load()
        assert self._nlp is not None

        results: list[RecognizerResult] = []
        # Extract ASCII islands and run NER on each independently
        for match in _ASCII_ISLAND.finditer(text):
            island = match.group()
            if _EMAIL_LIKE.match(island):
                continue
            island_start = match.start()
            doc = self._nlp(island)
            for ent in doc.ents:
                presidio_type = _EN_LABEL_MAP.get(ent.label_)
                if presidio_type is None or presidio_type not in requested:
                    continue
                abs_start = island_start + ent.start_char
                abs_end = island_start + ent.end_char
                # Skip entities that are the local part of an email (followed by @)
                if abs_end < len(text) and text[abs_end] == "@":
                    continue
                results.append(
                    RecognizerResult(
                        entity_type=presidio_type,
                        start=abs_start,
                        end=abs_end,
                        score=self.DEFAULT_SCORE,
                    )
                )
        return results
