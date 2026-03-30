"""Eval-specific fixtures: corpus loading and annotation validation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

CORPUS_PATH = Path(__file__).parent / "eval_corpus.json"


@pytest.fixture(scope="session")
def corpus() -> list[dict]:
    """Load and return the evaluation corpus."""
    return json.loads(CORPUS_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="session", autouse=True)
def validate_corpus() -> None:
    """Verify all corpus annotations have correct text <-> start:end alignment."""
    data = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    for sample in data:
        text = sample["text"]
        for ann in sample["annotations"]:
            actual = text[ann["start"] : ann["end"]]
            assert actual == ann["text"], (
                f"Sample {sample['id']}: annotation text mismatch: "
                f"expected {ann['text']!r} at [{ann['start']}:{ann['end']}], "
                f"got {actual!r}"
            )
