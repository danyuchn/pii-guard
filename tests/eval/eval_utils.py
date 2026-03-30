"""Span-level precision / recall / F1 computation for PII evaluation."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Span:
    """An entity span identified by type and character offsets."""

    entity_type: str
    start: int
    end: int


def results_to_spans(results, offset: int = 0) -> set[Span]:
    """Convert ``list[RecognizerResult]`` to a set of :class:`Span`."""
    return {Span(r.entity_type, r.start + offset, r.end + offset) for r in results}


def annotations_to_spans(annotations: list[dict], offset: int = 0) -> set[Span]:
    """Convert corpus annotation dicts to a set of :class:`Span`."""
    return {
        Span(a["entity_type"], a["start"] + offset, a["end"] + offset)
        for a in annotations
    }


@dataclass
class Metrics:
    """Precision / recall / F1 accumulator."""

    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 1.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


def compute_metrics(
    predicted: set[Span],
    expected: set[Span],
) -> dict[str, Metrics]:
    """Compute per-entity-type and micro-averaged metrics (exact span match).

    Returns a dict keyed by entity type plus a ``"__total__"`` entry.
    """
    all_types = {s.entity_type for s in predicted | expected}
    per_type: dict[str, Metrics] = {}

    for et in sorted(all_types):
        pred_et = {s for s in predicted if s.entity_type == et}
        exp_et = {s for s in expected if s.entity_type == et}
        m = Metrics()
        m.tp = len(pred_et & exp_et)
        m.fp = len(pred_et - exp_et)
        m.fn = len(exp_et - pred_et)
        per_type[et] = m

    total = Metrics()
    total.tp = sum(m.tp for m in per_type.values())
    total.fp = sum(m.fp for m in per_type.values())
    total.fn = sum(m.fn for m in per_type.values())
    per_type["__total__"] = total

    return per_type


def format_report(per_type: dict[str, Metrics]) -> str:
    """Return a formatted console table of metrics."""
    lines: list[str] = []
    header = f"{'Entity Type':<20} {'TP':>4} {'FP':>4} {'FN':>4} {'Prec':>6} {'Rec':>6} {'F1':>6}"
    lines.append(header)
    lines.append("-" * len(header))
    for et, m in per_type.items():
        label = "TOTAL" if et == "__total__" else et
        if et == "__total__":
            lines.append("-" * len(header))
        lines.append(
            f"{label:<20} {m.tp:>4} {m.fp:>4} {m.fn:>4}"
            f" {m.precision:>6.1%} {m.recall:>6.1%} {m.f1:>6.1%}"
        )
    return "\n".join(lines)
