"""Tests for multi-format file reading and writing (file_handlers.py)."""

from __future__ import annotations

from pathlib import Path

import pytest

from pii_guard.file_handlers import (
    FileContent,
    read_file,
    write_file,
    is_supported,
    get_output_extension,
    SUPPORTED_EXTENSIONS,
)


# ---------------------------------------------------------------------------
# is_supported / get_output_extension
# ---------------------------------------------------------------------------


class TestHelpers:

    def test_supported_txt(self):
        assert is_supported("data.txt")

    def test_supported_csv(self):
        assert is_supported("data.csv")

    def test_supported_xlsx(self):
        assert is_supported("report.xlsx")

    def test_supported_docx(self):
        assert is_supported("memo.docx")

    def test_supported_pdf(self):
        assert is_supported("invoice.pdf")

    def test_unsupported_pptx(self):
        assert not is_supported("slides.pptx")

    def test_output_ext_txt(self):
        assert get_output_extension("data.txt") == ".txt"

    def test_output_ext_xlsx(self):
        assert get_output_extension("report.xlsx") == ".xlsx"

    def test_output_ext_pdf_becomes_txt(self):
        assert get_output_extension("invoice.pdf") == ".txt"


# ---------------------------------------------------------------------------
# Plain text reading and writing
# ---------------------------------------------------------------------------


class TestPlainText:

    def test_read_txt(self, tmp_path: Path):
        f = tmp_path / "data.txt"
        f.write_text("身分證A123456789", encoding="utf-8")
        content = read_file(f)
        assert content.file_type == "plain"
        assert "A123456789" in content.text

    def test_read_csv(self, tmp_path: Path):
        f = tmp_path / "data.csv"
        f.write_text("name,id\n張三,A123456789", encoding="utf-8")
        content = read_file(f)
        assert content.file_type == "plain"
        assert "A123456789" in content.text

    def test_write_plain(self, tmp_path: Path):
        f = tmp_path / "data.txt"
        f.write_text("身分證A123456789", encoding="utf-8")
        content = read_file(f)
        out = tmp_path / "out.txt"
        write_file(content, "身分證<TW_NATIONAL_ID_1>", {}, out)
        assert "<TW_NATIONAL_ID_1>" in out.read_text(encoding="utf-8")

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            read_file("/tmp/definitely_not_exist_pii_guard.txt")

    def test_unsupported_extension(self, tmp_path: Path):
        f = tmp_path / "data.pptx"
        f.write_bytes(b"fake")
        with pytest.raises(ValueError, match="Unsupported"):
            read_file(f)


# ---------------------------------------------------------------------------
# Excel (.xlsx) reading and writing
# ---------------------------------------------------------------------------


class TestExcel:

    @pytest.fixture()
    def sample_xlsx(self, tmp_path: Path) -> Path:
        import openpyxl
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Sheet1"
        ws["A1"] = "姓名"
        ws["B1"] = "身分證"
        ws["A2"] = "張三"
        ws["B2"] = "A123456789"
        ws["A3"] = "李四"
        ws["B3"] = "B234567890"
        path = tmp_path / "data.xlsx"
        wb.save(str(path))
        wb.close()
        return path

    def test_read_xlsx(self, sample_xlsx: Path):
        content = read_file(sample_xlsx)
        assert content.file_type == "excel"
        assert "A123456789" in content.text
        assert "B234567890" in content.text
        assert len(content.cells) == 6  # 3 rows * 2 cols

    def test_read_xlsx_cells_have_keys(self, sample_xlsx: Path):
        content = read_file(sample_xlsx)
        keys = [k for k, _ in content.cells]
        assert any("Sheet1!" in k for k in keys)

    def test_write_xlsx_roundtrip(self, sample_xlsx: Path, tmp_path: Path, spacy_only_engine):
        content = read_file(sample_xlsx)
        anonymized_text, mapping = spacy_only_engine.anonymize(content.text)

        out = tmp_path / "anon.xlsx"
        write_file(content, anonymized_text, mapping, out)

        # Read back and verify PII is replaced
        import openpyxl
        wb = openpyxl.load_workbook(str(out), read_only=True)
        ws = wb.active
        values = [str(c.value) for row in ws.iter_rows() for c in row if c.value]
        wb.close()
        assert "A123456789" not in " ".join(values)
        assert "B234567890" not in " ".join(values)


# ---------------------------------------------------------------------------
# Word (.docx) reading and writing
# ---------------------------------------------------------------------------


class TestDocx:

    @pytest.fixture()
    def sample_docx(self, tmp_path: Path) -> Path:
        from docx import Document
        doc = Document()
        doc.add_paragraph("客戶：張三")
        doc.add_paragraph("身分證字號：A123456789")
        doc.add_paragraph("手機：0912345678")

        # Add a table
        table = doc.add_table(rows=2, cols=2)
        table.rows[0].cells[0].text = "姓名"
        table.rows[0].cells[1].text = "Email"
        table.rows[1].cells[0].text = "李四"
        table.rows[1].cells[1].text = "test@example.com"

        path = tmp_path / "data.docx"
        doc.save(str(path))
        return path

    def test_read_docx(self, sample_docx: Path):
        content = read_file(sample_docx)
        assert content.file_type == "docx"
        assert "A123456789" in content.text
        assert "0912345678" in content.text
        assert "test@example.com" in content.text

    def test_read_docx_has_table_cells(self, sample_docx: Path):
        content = read_file(sample_docx)
        keys = [k for k, _ in content.cells]
        assert any(k.startswith("table:") for k in keys)

    def test_write_docx_roundtrip(self, sample_docx: Path, tmp_path: Path, spacy_only_engine):
        content = read_file(sample_docx)
        anonymized_text, mapping = spacy_only_engine.anonymize(content.text)

        out = tmp_path / "anon.docx"
        write_file(content, anonymized_text, mapping, out)

        # Read back and verify PII is replaced
        from docx import Document
        doc = Document(str(out))
        all_text = " ".join(p.text for p in doc.paragraphs)
        assert "A123456789" not in all_text
        assert "0912345678" not in all_text


# ---------------------------------------------------------------------------
# PDF (.pdf) reading
# ---------------------------------------------------------------------------


class TestPdf:

    @pytest.fixture()
    def sample_pdf(self, tmp_path: Path) -> Path:
        """Create a minimal PDF with PII text using pdfplumber-compatible format."""
        # Use reportlab if available, otherwise create a minimal PDF manually
        try:
            from reportlab.pdfgen import canvas
            path = tmp_path / "data.pdf"
            c = canvas.Canvas(str(path))
            c.drawString(100, 750, "ID: A123456789")
            c.drawString(100, 730, "Phone: 0912345678")
            c.save()
            return path
        except ImportError:
            # Create a minimal valid PDF with text
            path = tmp_path / "data.pdf"
            pdf_content = (
                b"%PDF-1.4\n"
                b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
                b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
                b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]"
                b"/Parent 2 0 R/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>endobj\n"
                b"4 0 obj<</Length 44>>stream\n"
                b"BT /F1 12 Tf 100 750 Td (A123456789) Tj ET\n"
                b"endstream\nendobj\n"
                b"5 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj\n"
                b"xref\n0 6\n"
                b"0000000000 65535 f \n"
                b"0000000009 00000 n \n"
                b"0000000058 00000 n \n"
                b"0000000115 00000 n \n"
                b"0000000266 00000 n \n"
                b"0000000360 00000 n \n"
                b"trailer<</Size 6/Root 1 0 R>>\n"
                b"startxref\n431\n%%EOF"
            )
            path.write_bytes(pdf_content)
            return path

    def test_read_pdf(self, sample_pdf: Path):
        content = read_file(sample_pdf)
        assert content.file_type == "pdf"
        assert "A123456789" in content.text

    def test_pdf_no_cells(self, sample_pdf: Path):
        content = read_file(sample_pdf)
        assert content.cells == []

    def test_write_pdf_outputs_txt(self, sample_pdf: Path, tmp_path: Path):
        content = read_file(sample_pdf)
        out = tmp_path / "output.pdf"
        write_file(content, "anonymized content", {}, out)
        # PDF write produces .txt
        txt_out = tmp_path / "output.txt"
        assert txt_out.exists()
        assert "anonymized" in txt_out.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Integration: full anonymize + write-back + restore roundtrip
# ---------------------------------------------------------------------------


class TestFullRoundtrip:

    def test_txt_roundtrip(self, tmp_path: Path, spacy_only_engine):
        original = "客戶身分證A123456789，手機0912345678"
        f = tmp_path / "data.txt"
        f.write_text(original, encoding="utf-8")

        content = read_file(f)
        anonymized_text, mapping = spacy_only_engine.anonymize(content.text)
        assert "A123456789" not in anonymized_text

        from pii_guard.pipeline.engine import PiiGuardEngine
        restored = PiiGuardEngine.deanonymize(anonymized_text, mapping)
        assert restored == original

    def test_csv_roundtrip(self, tmp_path: Path, spacy_only_engine):
        original = "name,phone\n張三,0912345678\n李四,0923456789"
        f = tmp_path / "data.csv"
        f.write_text(original, encoding="utf-8")

        content = read_file(f)
        anonymized_text, mapping = spacy_only_engine.anonymize(content.text)
        assert "0912345678" not in anonymized_text

        from pii_guard.pipeline.engine import PiiGuardEngine
        restored = PiiGuardEngine.deanonymize(anonymized_text, mapping)
        assert restored == original

    def test_xlsx_roundtrip(self, tmp_path: Path, spacy_only_engine):
        import openpyxl

        # Create
        wb = openpyxl.Workbook()
        ws = wb.active
        ws["A1"] = "身分證"
        ws["B1"] = "A123456789"
        src = tmp_path / "data.xlsx"
        wb.save(str(src))
        wb.close()

        # Anonymize
        content = read_file(src)
        anonymized_text, mapping = spacy_only_engine.anonymize(content.text)
        anon_out = tmp_path / "anon.xlsx"
        write_file(content, anonymized_text, mapping, anon_out)

        # Verify anonymized xlsx
        wb2 = openpyxl.load_workbook(str(anon_out), read_only=True)
        ws2 = wb2.active
        assert "A123456789" not in str(ws2["B1"].value)
        wb2.close()
