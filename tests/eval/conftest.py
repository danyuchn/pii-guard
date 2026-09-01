"""Eval-specific fixtures: corpus loading and annotation validation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

CORPUS_PATH = Path(__file__).parent / "eval_corpus.json"
MANIFEST_PATH = Path(__file__).parent / "corpus_manifest.json"


@pytest.fixture(scope="session")
def corpus() -> list[dict]:
    """Load and return the evaluation corpus."""
    return json.loads(CORPUS_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="session", autouse=True)
def validate_corpus() -> None:
    """Verify the public marker and every text <-> start:end alignment."""
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    assert manifest == {
        "name": "pii-guard-public-synthetic-v1",
        "status": "public-synthetic",
        "contains_private_data": False,
        "source": (
            "Hand-authored synthetic examples for regression testing; "
            "no customer or production documents."
        ),
        "annotation_schema": "exact UTF-8 character offsets with entity_type and text",
        "corpus_file": "eval_corpus.json",
        "sample_count": 53,
    }
    data = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    assert len(data) == manifest["sample_count"]
    assert len({sample["id"] for sample in data}) == len(data)
    for sample in data:
        assert set(sample) == {"id", "text", "annotations"}
        assert isinstance(sample["text"], str)
        text = sample["text"]
        for ann in sample["annotations"]:
            assert set(ann) == {"entity_type", "start", "end", "text"}
            actual = text[ann["start"] : ann["end"]]
            assert actual == ann["text"], (
                f"Sample {sample['id']}: annotation text mismatch: "
                f"expected {ann['text']!r} at [{ann['start']}:{ann['end']}], "
                f"got {actual!r}"
            )
