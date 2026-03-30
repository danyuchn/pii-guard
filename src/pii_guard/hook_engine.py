"""Lightweight regex-only PiiGuardEngine factory for hook and testing use.

Constructs a PiiGuardEngine backed only by Taiwan regex recognizers
(no CKIP BERT model download required). Startup is fast (~200ms).
"""

from __future__ import annotations

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import SpacyNlpEngine
from presidio_anonymizer import AnonymizerEngine

from pii_guard.pipeline.engine import PiiGuardEngine
from pii_guard.recognizers.tw_recognizers import get_all_tw_recognizers


def create_regex_only_engine(score_threshold: float = 0.5) -> PiiGuardEngine:
    """Create a fast PiiGuardEngine using only regex recognizers (no CKIP).

    This engine detects: National ID, ARC, mobile, landline, business ID,
    email, credit card, passport, license plate, birth date, bank account.
    It does NOT detect PERSON/ORG/LOCATION (those require CKIP BERT).
    """
    nlp_engine = SpacyNlpEngine(
        models=[{"lang_code": "zh", "model_name": "zh_core_web_sm"}]
    )
    registry = RecognizerRegistry(recognizers=[], supported_languages=["zh"])
    for r in get_all_tw_recognizers():
        registry.add_recognizer(r)

    analyzer = AnalyzerEngine(
        registry=registry,
        nlp_engine=nlp_engine,
        supported_languages=["zh"],
    )

    engine = object.__new__(PiiGuardEngine)
    engine.score_threshold = score_threshold
    engine._analyzer = analyzer
    engine._anonymizer = AnonymizerEngine()
    return engine
