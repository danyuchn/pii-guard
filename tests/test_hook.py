"""Tests for the PreToolUse hook system (hook_engine + hook_detect)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from pii_guard.hook_engine import create_regex_only_engine
from pii_guard.pipeline.engine import PiiGuardEngine


# ---------------------------------------------------------------------------
# hook_engine tests
# ---------------------------------------------------------------------------


class TestRegexOnlyEngine:
    """Verify create_regex_only_engine() produces a working PiiGuardEngine."""

    def test_returns_pii_guard_engine(self):
        engine = create_regex_only_engine()
        assert isinstance(engine, PiiGuardEngine)

    def test_detects_national_id(self):
        engine = create_regex_only_engine()
        _, mapping = engine.anonymize("身分證字號A123456789")
        assert any("TW_NATIONAL_ID" in k for k in mapping)

    def test_detects_mobile(self):
        engine = create_regex_only_engine()
        _, mapping = engine.anonymize("手機0912345678")
        assert any("TW_MOBILE" in k for k in mapping)

    def test_detects_email(self):
        engine = create_regex_only_engine()
        _, mapping = engine.anonymize("信箱test@example.com")
        assert any("EMAIL" in k for k in mapping)

    def test_detects_credit_card(self):
        engine = create_regex_only_engine()
        _, mapping = engine.anonymize("信用卡4111111111111111")
        assert any("CREDIT_CARD" in k for k in mapping)

    def test_detects_business_id(self):
        engine = create_regex_only_engine()
        _, mapping = engine.anonymize("統一編號04595257")
        assert any("TW_BUSINESS_ID" in k for k in mapping)

    def test_detects_arc(self):
        engine = create_regex_only_engine()
        _, mapping = engine.anonymize("居留證AB12345678")
        assert any("TW_ARC" in k for k in mapping)

    def test_detects_landline(self):
        engine = create_regex_only_engine()
        _, mapping = engine.anonymize("電話02-12345678")
        assert any("TW_LANDLINE" in k for k in mapping)

    def test_detects_license_plate(self):
        engine = create_regex_only_engine()
        _, mapping = engine.anonymize("車牌ABC-1234")
        assert any("TW_LICENSE_PLATE" in k for k in mapping)

    def test_detects_birth_date(self):
        engine = create_regex_only_engine()
        _, mapping = engine.anonymize("生日民國85年12月3日")
        assert any("TW_BIRTH_DATE" in k for k in mapping)

    def test_detects_passport(self):
        engine = create_regex_only_engine()
        _, mapping = engine.anonymize("護照號碼A12345678入境")
        assert any("TW_PASSPORT" in k for k in mapping)


# ---------------------------------------------------------------------------
# hook_detect tests (subprocess invocation)
# ---------------------------------------------------------------------------


class TestHookDetect:
    """Test hook_detect.py as a subprocess (simulating hook invocation)."""

    @pytest.fixture()
    def pii_file(self, tmp_path: Path) -> Path:
        f = tmp_path / "data.txt"
        f.write_text(
            "客戶張大明，身分證A123456789，手機0912345678，"
            "email: test@example.com",
            encoding="utf-8",
        )
        return f

    @pytest.fixture()
    def no_pii_file(self, tmp_path: Path) -> Path:
        f = tmp_path / "clean.txt"
        f.write_text("這是一段沒有個人資料的文字。", encoding="utf-8")
        return f

    @pytest.fixture()
    def empty_file(self, tmp_path: Path) -> Path:
        f = tmp_path / "empty.txt"
        f.write_text("", encoding="utf-8")
        return f

    @pytest.fixture()
    def binary_file(self, tmp_path: Path) -> Path:
        f = tmp_path / "binary.dat"
        f.write_bytes(b"\x00\x01\x02\xff\xfe\xfd")
        return f

    def _run_hook(self, file_path: str) -> subprocess.CompletedProcess:
        hook_input = json.dumps({
            "tool_name": "Read",
            "tool_input": {"file_path": file_path},
        })
        return subprocess.run(
            [sys.executable, "-m", "pii_guard.hook_detect"],
            input=hook_input,
            capture_output=True,
            text=True,
            timeout=30,
        )

    def test_pii_detected_returns_ask(self, pii_file: Path):
        """When PII is found, hook returns permissionDecision: ask."""
        result = self._run_hook(str(pii_file))
        assert result.returncode == 0
        assert result.stdout.strip()

        response = json.loads(result.stdout)
        hook_output = response["hookSpecificOutput"]
        assert hook_output["permissionDecision"] == "ask"
        assert "PII GUARD" in hook_output["permissionDecisionReason"]

    def test_pii_detected_shows_entity_counts(self, pii_file: Path):
        """Review prompt includes entity type breakdown."""
        result = self._run_hook(str(pii_file))
        response = json.loads(result.stdout)
        reason = response["hookSpecificOutput"]["permissionDecisionReason"]
        assert "TW_NATIONAL_ID" in reason
        assert "TW_MOBILE" in reason
        assert "EMAIL_ADDRESS" in reason

    def test_pii_detected_no_updated_input(self, pii_file: Path):
        """Hook must NOT redirect Read — no updatedInput."""
        result = self._run_hook(str(pii_file))
        response = json.loads(result.stdout)
        assert "updatedInput" not in response["hookSpecificOutput"]

    def test_pii_detected_no_temp_files(self, pii_file: Path):
        """Hook must NOT create temp files in /tmp/pii-guard-hook/."""
        import glob
        before = set(glob.glob("/tmp/pii-guard-hook/*"))
        self._run_hook(str(pii_file))
        after = set(glob.glob("/tmp/pii-guard-hook/*"))
        assert before == after

    def test_no_pii_produces_no_output(self, no_pii_file: Path):
        result = self._run_hook(str(no_pii_file))
        assert result.returncode == 0
        assert result.stdout.strip() == ""

    def test_empty_file_produces_no_output(self, empty_file: Path):
        result = self._run_hook(str(empty_file))
        assert result.returncode == 0
        assert result.stdout.strip() == ""

    def test_nonexistent_file_produces_no_output(self):
        result = self._run_hook("/tmp/nonexistent-pii-guard-test-file.txt")
        assert result.returncode == 0
        assert result.stdout.strip() == ""

    def test_binary_file_skipped(self, binary_file: Path):
        result = self._run_hook(str(binary_file))
        assert result.returncode == 0
        assert result.stdout.strip() == ""

    def test_empty_stdin_exits_cleanly(self):
        result = subprocess.run(
            [sys.executable, "-m", "pii_guard.hook_detect"],
            input="",
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0
        assert result.stdout.strip() == ""

    def test_invalid_json_exits_cleanly(self):
        result = subprocess.run(
            [sys.executable, "-m", "pii_guard.hook_detect"],
            input="not json",
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0
        assert result.stdout.strip() == ""
