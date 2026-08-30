"""Deterministic PDF byte fixtures used by Phase 2 tests.

The builder intentionally emits only ASCII PDF objects so the fixture stays
small, reviewable, and independent of reportlab or another PDF package.
"""

from __future__ import annotations

import zlib


def _build_pdf(objects: list[bytes]) -> bytes:
    prefix = b"%PDF-1.4\n"
    output = bytearray(prefix)
    offsets = [0]
    for number, obj in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{number} 0 obj\n".encode("ascii"))
        output.extend(obj)
        output.extend(b"\nendobj\n")
    xref_offset = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    output.extend(b"".join(f"{offset:010d} 00000 n \n".encode("ascii") for offset in offsets[1:]))
    output.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_offset}\n%%EOF\n".encode("ascii")
    )
    return bytes(output)


def build_text_pdf(*pages: str) -> bytes:
    """Return a valid PDF whose pages contain the supplied ASCII text."""

    if not pages:
        pages = ("EMPTY",)
    page_numbers = [3 + 3 * index for index in range(len(pages))]
    content_numbers = [number + 1 for number in page_numbers]
    font_numbers = [number + 2 for number in page_numbers]
    objects: list[bytes] = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        (
            b"<< /Type /Pages /Kids ["
            + b" ".join(f"{number} 0 R".encode("ascii") for number in page_numbers)
            + f"] /Count {len(pages)} >>".encode("ascii")
        ),
    ]
    for page_number, content_number, font_number, text in zip(
        page_numbers, content_numbers, font_numbers, pages
    ):
        escaped = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        content = f"BT /F1 12 Tf 72 720 Td ({escaped}) Tj ET".encode("ascii")
        objects.extend(
            [
                (
                    f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                    f"/Resources << /Font << /F1 {font_number} 0 R >> >> "
                    f"/Contents {content_number} 0 R >>"
                ).encode("ascii"),
                b"<< /Length "
                + str(len(content)).encode("ascii")
                + b" >>\nstream\n"
                + content
                + b"\nendstream",
                b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            ]
        )
    return _build_pdf(objects)


def build_image_only_pdf() -> bytes:
    """Return a valid one-page PDF with an image and no text operators."""

    content = b"q 1 0 0 1 0 0 cm /Im1 Do Q"
    return _build_pdf(
        [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            (
                b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 10 10] "
                b"/Resources << /XObject << /Im1 5 0 R >> >> /Contents 4 0 R >>"
            ),
            b"<< /Length "
            + str(len(content)).encode("ascii")
            + b" >>\nstream\n"
            + content
            + b"\nendstream",
            (
                b"<< /Type /XObject /Subtype /Image /Width 1 /Height 1 "
                b"/ColorSpace /DeviceGray /BitsPerComponent 8 /Length 1 >>\n"
                b"stream\n\x00\nendstream"
            ),
        ]
    )


def build_compressed_text_pdf(size: int) -> bytes:
    """Return a PDF whose compressed content expands to ``size`` text bytes."""

    content = ("BT /F1 12 Tf 72 720 Td (" + ("x" * size) + ") Tj ET").encode("ascii")
    compressed = zlib.compress(content)
    return _build_pdf(
        [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            (
                b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>"
            ),
            b"<< /Length "
            + str(len(compressed)).encode("ascii")
            + b" /Filter /FlateDecode >>\nstream\n"
            + compressed
            + b"\nendstream",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        ]
    )
