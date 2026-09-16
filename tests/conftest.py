"""Pytest fixtures shared across test modules."""

from __future__ import annotations

import os
import stat
from pathlib import Path

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


# ---------------------------------------------------------------------------
# Privacy assertions that mean the same thing on both platforms
# ---------------------------------------------------------------------------

# POSIX permission bits don't exist on NTFS: chmod can only toggle a read-only
# flag, so 0o600/0o700 can never be read back on Windows. The guard's own
# privacy invariant is pii_guard._compat.mode_matches, which defers to the
# verified Windows ACL instead, so the tests assert the same thing the product
# enforces rather than a mode the filesystem cannot store.
POSIX_MODES = os.name != "nt"


def assert_mode(path: Path, expected: int) -> None:
    """Assert a POSIX mode wherever the filesystem actually has one."""

    if not POSIX_MODES:
        return
    assert stat.S_IMODE(path.stat().st_mode) == expected, path
