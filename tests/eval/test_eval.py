"""Evaluation tests: precision / recall / F1 per entity type.

Usage::

    # Fast eval (regex only, no model download):
    uv run pytest tests/eval/ -v -m "eval and not slow" -s

    # Full eval (CKIP + regex, needs BERT model):
    uv run pytest tests/eval/ -v -m eval -s
"""

from __future__ import annotations

import pytest

from tests.eval.eval_utils import (
    Span,
    annotations_to_spans,
    compute_metrics,
    format_report,
    results_to_spans,
)

_NER_TYPES = {"PERSON", "ORG", "LOCATION"}


def _aggregate(engine, corpus, *, exclude_ner: bool = False):
    """Run detection on all corpus samples and aggregate spans."""
    all_predicted: set[Span] = set()
    all_expected: set[Span] = set()
    offset = 0

    for sample in corpus:
        annotations = sample["annotations"]
        if exclude_ner:
            annotations = [a for a in annotations if a["entity_type"] not in _NER_TYPES]

        results = engine.detect(sample["text"])
        if exclude_ner:
            results = [r for r in results if r.entity_type not in _NER_TYPES]

        all_predicted |= results_to_spans(results, offset)
        all_expected |= annotations_to_spans(annotations, offset)
        # Large gap ensures spans from different samples never collide
        offset += len(sample["text"]) + 10_000

    return all_predicted, all_expected


# ── Regex-only evaluation (fast, no model download) ──────────────────────


@pytest.mark.eval
class TestEvalRegexOnly:
    """Evaluate regex recognizers against corpus (excludes PERSON/ORG/LOCATION)."""

    def test_precision_recall_regex(self, spacy_only_engine, corpus):
        predicted, expected = _aggregate(
            spacy_only_engine, corpus, exclude_ner=True,
        )
        metrics = compute_metrics(predicted, expected)
        print("\n" + format_report(metrics))

        total = metrics["__total__"]
        assert total.precision >= 0.90, f"Precision {total.precision:.1%} below 90%"
        assert total.recall >= 0.90, f"Recall {total.recall:.1%} below 90%"


# ── Full evaluation (CKIP + regex, slow) ─────────────────────────────────


@pytest.mark.eval
@pytest.mark.slow
class TestEvalFull:
    """Evaluate full engine (CKIP NER + regex) against entire corpus."""

    def test_precision_recall_full(self, ckip_engine, corpus):
        predicted, expected = _aggregate(ckip_engine, corpus)
        metrics = compute_metrics(predicted, expected)
        print("\n" + format_report(metrics))

        total = metrics["__total__"]
        assert total.precision >= 0.70, f"Precision {total.precision:.1%} below 70%"
        assert total.recall >= 0.70, f"Recall {total.recall:.1%} below 70%"
