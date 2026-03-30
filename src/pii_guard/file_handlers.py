"""Multi-format file reading and writing for PII anonymization.

Supported formats:
- Plain text (.txt, .csv, .tsv, .log, .md, .json, .xml, .html)
- Excel (.xlsx) — requires ``openpyxl``
- Word (.docx) — requires ``python-docx``
- PDF (.pdf) — read-only, requires ``pdfplumber``
"""

from __future__ import annotations

import csv
import io
import logging
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# Extensions that are treated as plain UTF-8 text (read_text / write_text).
PLAIN_TEXT_EXTENSIONS: set[str] = {
    ".txt", ".csv", ".tsv", ".log", ".md", ".dat",
    ".json", ".xml", ".html", ".htm", ".yaml", ".yml",
}

# Extensions that need special handlers.
EXCEL_EXTENSIONS: set[str] = {".xlsx"}
WORD_EXTENSIONS: set[str] = {".docx"}
PDF_EXTENSIONS: set[str] = {".pdf"}

SUPPORTED_EXTENSIONS: set[str] = (
    PLAIN_TEXT_EXTENSIONS | EXCEL_EXTENSIONS | WORD_EXTENSIONS | PDF_EXTENSIONS
)


@dataclass
class FileContent:
    """Represents extracted text from a file, with enough info to write back.

    For plain text files, ``text`` is the full content and ``cells`` is empty.
    For structured formats (Excel/Word), ``cells`` holds per-cell text and
    ``text`` is the concatenation used for display / single-pass anonymization.
    """

    text: str
    file_type: str  # "plain", "excel", "docx", "pdf"
    source_path: str = ""

    # Structured content: list of (location_key, cell_text) pairs.
    # location_key is opaque — used by the write-back function.
    cells: list[tuple[str, str]] = field(default_factory=list)


def _check_import(package: str, pip_name: str) -> None:
    """Raise ImportError with a helpful message if *package* is missing."""
    try:
        __import__(package)
    except ImportError:
        raise ImportError(
            f"{package} is required for this file type. "
            f'Install it with: uv pip install "{pip_name}" '
            f'or: uv sync --extra formats'
        ) from None


# ---------------------------------------------------------------------------
# Readers
# ---------------------------------------------------------------------------


def read_file(path: str | Path) -> FileContent:
    """Read a file and return its textual content.

    Auto-detects format by extension. Raises ``ValueError`` for unsupported
    extensions and ``FileNotFoundError`` if the file doesn't exist.
    """
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    ext = p.suffix.lower()

    if ext in PLAIN_TEXT_EXTENSIONS:
        return _read_plain(p)
    if ext in EXCEL_EXTENSIONS:
        return _read_excel(p)
    if ext in WORD_EXTENSIONS:
        return _read_docx(p)
    if ext in PDF_EXTENSIONS:
        return _read_pdf(p)

    raise ValueError(
        f"Unsupported file extension: {ext}. "
        f"Supported: {sorted(SUPPORTED_EXTENSIONS)}"
    )


def _read_plain(p: Path) -> FileContent:
    text = p.read_text(encoding="utf-8")
    return FileContent(text=text, file_type="plain", source_path=str(p))


def _read_excel(p: Path) -> FileContent:
    _check_import("openpyxl", "openpyxl>=3.1.0")
    import openpyxl

    wb = openpyxl.load_workbook(str(p), read_only=True, data_only=True)
    cells: list[tuple[str, str]] = []
    text_parts: list[str] = []

    for sheet_name in wb.sheetnames:
        ws = wb[sheet_name]
        for row in ws.iter_rows():
            for cell in row:
                if cell.value is not None:
                    cell_text = str(cell.value)
                    key = f"{sheet_name}!{cell.coordinate}"
                    cells.append((key, cell_text))
                    text_parts.append(cell_text)

    wb.close()
    return FileContent(
        text="\n".join(text_parts),
        file_type="excel",
        source_path=str(p),
        cells=cells,
    )


def _read_docx(p: Path) -> FileContent:
    _check_import("docx", "python-docx>=1.1.0")
    from docx import Document

    doc = Document(str(p))
    cells: list[tuple[str, str]] = []
    text_parts: list[str] = []

    # Paragraphs
    for i, para in enumerate(doc.paragraphs):
        if para.text.strip():
            key = f"para:{i}"
            cells.append((key, para.text))
            text_parts.append(para.text)

    # Tables
    for ti, table in enumerate(doc.tables):
        for ri, row in enumerate(table.rows):
            for ci, cell in enumerate(row.cells):
                if cell.text.strip():
                    key = f"table:{ti}:r{ri}:c{ci}"
                    cells.append((key, cell.text))
                    text_parts.append(cell.text)

    return FileContent(
        text="\n".join(text_parts),
        file_type="docx",
        source_path=str(p),
        cells=cells,
    )


def _read_pdf(p: Path) -> FileContent:
    _check_import("pdfplumber", "pdfplumber>=0.11.0")
    import pdfplumber

    text_parts: list[str] = []
    with pdfplumber.open(str(p)) as pdf:
        for page in pdf.pages:
            page_text = page.extract_text()
            if page_text:
                text_parts.append(page_text)

    return FileContent(
        text="\n".join(text_parts),
        file_type="pdf",
        source_path=str(p),
    )


# ---------------------------------------------------------------------------
# Writers
# ---------------------------------------------------------------------------


def write_file(
    content: FileContent,
    anonymized_text: str,
    mapping: dict[str, str],
    output_path: str | Path,
) -> None:
    """Write anonymized content back to a file, preserving original format.

    For structured formats (Excel/Word), each cell is individually anonymized
    using the *mapping*. For plain text and PDF, writes the full
    *anonymized_text* directly.

    Parameters
    ----------
    content : FileContent
        The original file content returned by :func:`read_file`.
    anonymized_text : str
        The full anonymized text (used for plain text / PDF output).
    mapping : dict[str, str]
        ``{placeholder: original_value}`` from the engine.
    output_path : str | Path
        Where to write the result.
    """
    out = Path(output_path)

    if content.file_type == "plain":
        out.write_text(anonymized_text, encoding="utf-8")

    elif content.file_type == "excel":
        _write_excel(content, mapping, out)

    elif content.file_type == "docx":
        _write_docx(content, mapping, out)

    elif content.file_type == "pdf":
        # PDF can't be written back — output as .txt
        actual_out = out.with_suffix(".txt") if out.suffix.lower() == ".pdf" else out
        actual_out.write_text(anonymized_text, encoding="utf-8")
        if actual_out != out:
            logger.info("PDF cannot be written back; saved as %s", actual_out)


def _anonymize_cell(cell_text: str, mapping: dict[str, str]) -> str:
    """Apply reverse mapping to anonymize a single cell's text.

    *mapping* is ``{placeholder: original}``. We need original→placeholder.
    """
    reverse = {v: k for k, v in mapping.items()}
    result = cell_text
    for original in sorted(reverse, key=len, reverse=True):
        result = result.replace(original, reverse[original])
    return result


def _write_excel(content: FileContent, mapping: dict[str, str], out: Path) -> None:
    _check_import("openpyxl", "openpyxl>=3.1.0")
    import openpyxl

    # Copy original workbook, then overwrite cells with anonymized text.
    wb = openpyxl.load_workbook(content.source_path)

    for key, original_text in content.cells:
        sheet_name, coord = key.split("!", 1)
        ws = wb[sheet_name]
        anonymized = _anonymize_cell(original_text, mapping)
        ws[coord] = anonymized

    wb.save(str(out))
    wb.close()


def _write_docx(content: FileContent, mapping: dict[str, str], out: Path) -> None:
    _check_import("docx", "python-docx>=1.1.0")
    from docx import Document

    doc = Document(content.source_path)

    for key, original_text in content.cells:
        anonymized = _anonymize_cell(original_text, mapping)
        if key.startswith("para:"):
            idx = int(key.split(":")[1])
            para = doc.paragraphs[idx]
            # Clear existing runs, write anonymized text preserving first run's style
            if para.runs:
                first_run = para.runs[0]
                for run in para.runs[1:]:
                    run.text = ""
                first_run.text = anonymized
            else:
                para.text = anonymized

        elif key.startswith("table:"):
            parts = key.split(":")
            ti, ri, ci = int(parts[1]), int(parts[2][1:]), int(parts[3][1:])
            cell = doc.tables[ti].rows[ri].cells[ci]
            if cell.paragraphs and cell.paragraphs[0].runs:
                first_run = cell.paragraphs[0].runs[0]
                for run in cell.paragraphs[0].runs[1:]:
                    run.text = ""
                first_run.text = anonymized
            elif cell.paragraphs:
                cell.paragraphs[0].text = anonymized

    doc.save(str(out))


# ---------------------------------------------------------------------------
# Convenience: detect if a file extension is supported
# ---------------------------------------------------------------------------


def is_supported(path: str | Path) -> bool:
    """Return True if the file extension is supported."""
    return Path(path).suffix.lower() in SUPPORTED_EXTENSIONS


def get_output_extension(input_path: str | Path) -> str:
    """Return the appropriate output extension for the given input file.

    PDF inputs produce ``.txt`` output; everything else keeps its extension.
    """
    ext = Path(input_path).suffix.lower()
    return ".txt" if ext in PDF_EXTENSIONS else ext
