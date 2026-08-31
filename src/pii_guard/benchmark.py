"""Re-runnable quick-mode cold-start and warm-processing benchmark."""

from __future__ import annotations

import tempfile
import time
from pathlib import Path

from pii_guard.local_workflow import (
    Anonymizer,
    EngineFactory,
    PrivateJobStore,
    WorkflowError,
    read_source_path,
)


def _default_engine(model: str, threshold: float) -> Anonymizer:
    from pii_guard.pipeline.engine import PiiGuardEngine

    return PiiGuardEngine(ckip_model=model, score_threshold=threshold)


def _regex_engine(_model: str, threshold: float) -> Anonymizer:
    from pii_guard.hook_engine import create_regex_only_engine

    return create_regex_only_engine(score_threshold=threshold)


def run_quick_benchmark(
    fixture: Path,
    *,
    runs: int = 3,
    model: str = "ckiplab/bert-base-chinese-ner",
    threshold: float = 0.5,
    regex_only: bool = False,
) -> dict[str, object]:
    """Measure engine construction separately from subsequent quick jobs."""

    if runs < 1 or runs > 20:
        raise WorkflowError("INVALID_RUNS", "Benchmark runs must be between 1 and 20.")
    text = read_source_path(fixture)
    # Do not reflect an arbitrary user-provided filename in the public JSON;
    # benchmark output is safe to hand to an external tool.
    fixture_label = (
        "phase1_chinese.txt" if fixture.name == "phase1_chinese.txt" else "custom-utf8-text"
    )
    factory: EngineFactory = _regex_engine if regex_only else _default_engine
    with tempfile.TemporaryDirectory(prefix="pii-guard-benchmark-") as directory:
        store = PrivateJobStore(
            Path(directory) / "jobs",
            engine_factory=factory,
            ckip_model=model,
            score_threshold=threshold,
        )
        cold_started = time.perf_counter()
        cold_receipt = store.create_quick_from_text(text, source_name=fixture.name)
        cold_restore = store.restore_to_private(str(cold_receipt["job_id"]))
        cold_seconds = time.perf_counter() - cold_started
        store.delete(str(cold_receipt["job_id"]))

        warm_seconds: list[float] = []
        warm_roundtrips: list[bool] = []
        for _ in range(runs):
            started = time.perf_counter()
            receipt = store.create_quick_from_text(text, source_name=fixture.name)
            restore = store.restore_to_private(str(receipt["job_id"]))
            warm_seconds.append(time.perf_counter() - started)
            warm_roundtrips.append(bool(restore["roundtrip_equal"]))
            store.delete(str(receipt["job_id"]))

    return {
        "ok": True,
        "benchmark": "quick",
        "fixture": fixture_label,
        "mode": "quick",
        "engine": "regex-only" if regex_only else "ckip+presidio+regex",
        "runs": runs,
        "cold_start_seconds": round(cold_seconds, 6),
        "warm_processing_seconds": [round(value, 6) for value in warm_seconds],
        "warm_mean_seconds": round(sum(warm_seconds) / len(warm_seconds), 6),
        "cold_roundtrip_equal": bool(cold_restore["roundtrip_equal"]),
        "warm_roundtrip_equal": all(warm_roundtrips),
    }
