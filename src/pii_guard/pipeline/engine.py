"""Core PII anonymization engine using Presidio + CKIP BERT."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

from pii_guard.recognizers.tw_recognizers import TW_ENTITY_TYPES, get_all_tw_recognizers

logger = logging.getLogger(__name__)

# All entity types the engine handles
SUPPORTED_ENTITIES: list[str] = [
    "PERSON",
    "ORG",
    "LOCATION",
    "EMAIL_ADDRESS",
    "CREDIT_CARD",
    *TW_ENTITY_TYPES,
]

# CKIP NER label → Presidio entity type mapping
_CKIP_LABEL_MAP: dict[str, str] = {
    "PERSON": "PERSON",
    "PER": "PERSON",
    "ORG": "ORG",
    "LOC": "LOCATION",
    "GPE": "LOCATION",
    "FAC": "LOCATION",
}


def _build_analyzer(ckip_model: str) -> AnalyzerEngine:
    """
    Build Presidio AnalyzerEngine backed by CKIP BERT (for PERSON/ORG/LOCATION)
    plus Taiwan-specific PatternRecognizers.

    Falls back gracefully if transformers/spaCy models are unavailable.
    """
    nlp_engine = _create_nlp_engine(ckip_model)
    analyzer = AnalyzerEngine(
        nlp_engine=nlp_engine,
        supported_languages=["zh"],
    )
    for recognizer in get_all_tw_recognizers():
        analyzer.registry.add_recognizer(recognizer)
    return analyzer


def _create_nlp_engine(ckip_model: str):
    """Create NLP engine: TransformersNlpEngine (CKIP) → SpacyNlpEngine fallback."""
    try:
        from presidio_analyzer.nlp_engine import TransformersNlpEngine

        models = [
            {
                "lang_code": "zh",
                "model_name": {
                    "spacy": "zh_core_web_sm",
                    "transformers": ckip_model,
                },
            }
        ]

        # Presidio ≥ 2.2.34 exposes NerModelConfiguration for label mapping
        try:
            from presidio_analyzer.nlp_engine.transformers_nlp_engine import (
                NerModelConfiguration,
            )

            ner_config = NerModelConfiguration(
                model_to_presidio_entity_mapping=_CKIP_LABEL_MAP,
                aggregation_strategy="simple",
                default_score=0.85,
                low_score_entity_names=["MISC", "NORP", "WORK_OF_ART", "EVENT"],
            )
            engine = TransformersNlpEngine(models=models, ner_model_configuration=ner_config)
            logger.info("Using CKIP TransformersNlpEngine with NerModelConfiguration")
        except (ImportError, TypeError):
            engine = TransformersNlpEngine(models=models)
            logger.info("Using CKIP TransformersNlpEngine (no NerModelConfiguration)")

        return engine

    except (ImportError, OSError) as exc:
        logger.warning(
            "TransformersNlpEngine unavailable (%s). "
            "PERSON/ORG/LOCATION detection via CKIP will be disabled. "
            "Taiwan regex recognizers still active.",
            exc,
        )
        from presidio_analyzer.nlp_engine import SpacyNlpEngine

        return SpacyNlpEngine(
            models=[{"lang_code": "zh", "model_name": "zh_core_web_sm"}]
        )


class PiiGuardEngine:
    """
    Orchestrates PII detection and reversible anonymization for Traditional Chinese text.

    Usage::

        engine = PiiGuardEngine()
        anonymized, mapping = engine.anonymize("張大明的身分證A123456789")
        # anonymized → "<PERSON_1>的身分證<TW_NATIONAL_ID_1>"
        # mapping    → {"<PERSON_1>": "張大明", "<TW_NATIONAL_ID_1>": "A123456789"}

        original = engine.deanonymize(anonymized, mapping)
        assert original == "張大明的身分證A123456789"
    """

    def __init__(
        self,
        ckip_model: str = "ckiplab/bert-base-chinese-ner",
        score_threshold: float = 0.5,
    ) -> None:
        self.score_threshold = score_threshold
        self._analyzer = _build_analyzer(ckip_model)
        self._anonymizer = AnonymizerEngine()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def anonymize(self, text: str) -> tuple[str, dict[str, str]]:
        """
        Anonymize PII in *text*.

        Returns
        -------
        anonymized_text : str
            Text with PII replaced by numbered placeholders, e.g. ``<PERSON_1>``.
        mapping : dict[str, str]
            ``{placeholder: original_value}`` — needed for :meth:`deanonymize`.
        """
        # Shared mutable state for the operator lambdas (closure)
        entity_mapping: dict[str, str] = {}   # original_value → placeholder
        counters: dict[str, int] = {}          # entity_type → running count

        def make_lambda(entity_type: str):
            def replace_fn(original: str) -> str:
                # Presidio's Custom.validate() always calls lambda("PII") to type-check
                # the return value. Skip this sentinel to avoid polluting entity_mapping.
                if original == "PII":
                    return "<VALIDATION>"
                if original not in entity_mapping:
                    counters[entity_type] = counters.get(entity_type, 0) + 1
                    placeholder = f"<{entity_type}_{counters[entity_type]}>"
                    entity_mapping[original] = placeholder
                return entity_mapping[original]
            return replace_fn

        operators = {
            et: OperatorConfig("custom", {"lambda": make_lambda(et)})
            for et in SUPPORTED_ENTITIES
        }

        results = self._analyzer.analyze(
            text=text,
            language="zh",
            entities=SUPPORTED_ENTITIES,
            score_threshold=self.score_threshold,
        )

        anonymized_result = self._anonymizer.anonymize(
            text=text,
            analyzer_results=results,  # type: ignore[arg-type]
            operators=operators,
        )

        # Reverse: placeholder → original (for deanonymize)
        reverse_mapping: dict[str, str] = {v: k for k, v in entity_mapping.items()}
        return anonymized_result.text, reverse_mapping

    @staticmethod
    def deanonymize(text: str, mapping: dict[str, str]) -> str:
        """
        Restore anonymized *text* using *mapping*.

        Parameters
        ----------
        text : str
            Text containing placeholders like ``<PERSON_1>``.
        mapping : dict[str, str]
            ``{placeholder: original_value}`` as returned by :meth:`anonymize`.
        """
        # Sort longest first to avoid <PERSON_1> matching inside <PERSON_10>
        for placeholder in sorted(mapping, key=len, reverse=True):
            text = text.replace(placeholder, mapping[placeholder])
        return text

    # ------------------------------------------------------------------
    # Mapping persistence
    # ------------------------------------------------------------------

    @staticmethod
    def save_mapping(mapping: dict[str, str], path: Path) -> None:
        """Serialise *mapping* to a JSON file at *path*."""
        path.write_text(json.dumps(mapping, ensure_ascii=False, indent=2), encoding="utf-8")

    @staticmethod
    def load_mapping(path: Path) -> dict[str, str]:
        """Load a mapping JSON file previously saved by :meth:`save_mapping`."""
        return json.loads(path.read_text(encoding="utf-8"))
