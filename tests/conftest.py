"""Pytest fixtures shared across test modules."""

from __future__ import annotations

import pytest


@pytest.fixture(scope="session")
def ckip_engine():
    """
    Full PiiGuardEngine with CKIP BERT NER enabled.

    Downloads ckiplab/bert-base-chinese-ner on first run (~500 MB).
    Mark tests that use this fixture with @pytest.mark.slow so they can be
    skipped in fast CI runs with: pytest -m "not slow"
    """
    from pii_guard.pipeline.engine import PiiGuardEngine

    return PiiGuardEngine()  # uses ckiplab/bert-base-chinese-ner by default


@pytest.fixture(scope="session")
def spacy_only_engine():
    """
    PiiGuardEngine with Taiwan regex recognizers only (no CKIP download required).
    PERSON/ORG/LOCATION detection disabled: registry starts empty so spaCy NER
    entities (which interfere with regex span tests) are never added.
    """
    from pii_guard.hook_engine import create_regex_only_engine

    return create_regex_only_engine()
