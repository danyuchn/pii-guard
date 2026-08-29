"""Quick benchmark output contract tests."""

from __future__ import annotations

from pathlib import Path

from pii_guard.benchmark import run_quick_benchmark


def test_quick_benchmark_reports_cold_warm_and_roundtrip(tmp_path: Path) -> None:
    fixture = tmp_path / "fixture.txt"
    fixture.write_text(
        "聯絡人王小明，身分證A123456789，手機0912345678。",
        encoding="utf-8",
    )
    result = run_quick_benchmark(fixture, runs=2, regex_only=True)

    assert result["ok"] is True
    assert result["mode"] == "quick"
    assert isinstance(result["cold_start_seconds"], float)
    assert len(result["warm_processing_seconds"]) == 2
    assert result["cold_roundtrip_equal"] is True
    assert result["warm_roundtrip_equal"] is True
