"""Pytest fixtures shared across test modules."""

from __future__ import annotations

import pytest


@pytest.fixture(scope="session")
def spacy_only_engine():
    """
    PiiGuardEngine with Taiwan regex recognizers only (no CKIP download required).
    PERSON/ORG/LOCATION detection disabled: registry starts empty so spaCy NER
    entities (which interfere with regex span tests) are never added.
    """
    from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
    from presidio_analyzer.nlp_engine import SpacyNlpEngine
    from presidio_anonymizer import AnonymizerEngine

    from pii_guard.pipeline.engine import PiiGuardEngine
    from pii_guard.recognizers.tw_recognizers import get_all_tw_recognizers

    nlp_engine = SpacyNlpEngine(
        models=[{"lang_code": "zh", "model_name": "zh_core_web_sm"}]
    )
    # Empty registry — no built-in Presidio/spaCy recognizers, only Taiwan ones
    registry = RecognizerRegistry(recognizers=[], supported_languages=["zh"])
    for r in get_all_tw_recognizers():
        registry.add_recognizer(r)

    analyzer = AnalyzerEngine(
        registry=registry,
        nlp_engine=nlp_engine,
        supported_languages=["zh"],
    )

    # Construct engine directly without triggering CKIP model download
    engine = object.__new__(PiiGuardEngine)
    engine.score_threshold = 0.5
    engine._analyzer = analyzer
    engine._anonymizer = AnonymizerEngine()
    return engine
