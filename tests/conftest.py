"""Pytest fixtures shared across test modules."""

from __future__ import annotations

import pytest


@pytest.fixture(scope="session")
def spacy_only_engine():
    """
    PiiGuardEngine backed by spaCy only (no CKIP download required).
    Covers all Taiwan regex recognizers; PERSON/ORG/LOCATION detection disabled.
    """
    from unittest.mock import patch

    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import SpacyNlpEngine

    def _mock_build_analyzer(ckip_model: str) -> AnalyzerEngine:
        nlp_engine = SpacyNlpEngine(
            models=[{"lang_code": "zh", "model_name": "zh_core_web_sm"}]
        )
        analyzer = AnalyzerEngine(
            nlp_engine=nlp_engine,
            supported_languages=["zh"],
        )
        from pii_guard.recognizers.tw_recognizers import get_all_tw_recognizers

        for r in get_all_tw_recognizers():
            analyzer.registry.add_recognizer(r)
        return analyzer

    with patch("pii_guard.pipeline.engine._build_analyzer", side_effect=_mock_build_analyzer):
        from pii_guard.pipeline.engine import PiiGuardEngine

        yield PiiGuardEngine()
