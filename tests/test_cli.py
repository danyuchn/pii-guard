"""CLI helpers that must stay byte-faithful to the document's line endings."""

from __future__ import annotations

from pathlib import Path

from pii_guard import cli

CRLF_TEXT = "第一行\r\n第二行\r\n"


def test_write_output_does_not_translate_line_endings(tmp_path: Path) -> None:
    """``write_file`` was fixed for plain text, but the CLI wrote plain files
    through this helper instead, so a CRLF document still became CRCRLF on
    Windows."""
    target = tmp_path / "out.txt"

    cli._write_output(CRLF_TEXT, target)

    assert target.read_bytes() == CRLF_TEXT.encode("utf-8")


def test_write_quick_output_does_not_translate_line_endings(tmp_path: Path) -> None:
    target = tmp_path / "quick.txt"

    cli._write_quick_output(CRLF_TEXT, target)

    assert target.read_bytes() == CRLF_TEXT.encode("utf-8")


def test_read_input_preserves_line_endings(tmp_path: Path) -> None:
    source = tmp_path / "in.txt"
    source.write_bytes(CRLF_TEXT.encode("utf-8"))

    assert cli._read_input(str(source)) == CRLF_TEXT
