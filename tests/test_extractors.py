"""File format extractor tests.

The ZIP and DOCX tests matter most: v3.0 had no ZIP support at all,
and `.docx` was read as plain text, so nothing inside one was ever
found.
"""

from __future__ import annotations

import io
import zipfile

import pytest

from sentinel.extractors import extract, plain, supports
from tests.conftest import VALID_TCKN, VALID_VISA


def text_of(path, config) -> str:
    return "\n".join(chunk.text for chunk in extract(str(path), config))


class TestDispatch:
    @pytest.mark.parametrize(
        "name", ["a.txt", "a.pdf", "a.docx", "a.xlsx", "a.zip", "a.png", "a.py"]
    )
    def test_known_formats(self, name):
        assert supports(name)

    def test_unknown_extension_falls_back_to_plain(self, tmp_path, config):
        """Extensionless config files must be scanned too (.env.prod, Dockerfile)."""
        path = tmp_path / "Dockerfile"
        path.write_text(f"ENV TC={VALID_TCKN}\n", encoding="utf-8")
        assert VALID_TCKN in text_of(path, config)


class TestPlainText:
    def test_utf8(self, tmp_path, config):
        path = tmp_path / "a.txt"
        path.write_text("non-ASCII content: şğüöçİ", encoding="utf-8")
        assert "şğüöçİ" in text_of(path, config)

    def test_windows_turkish_encoding(self, tmp_path, config):
        """Turkish files are often encoded in cp1254.

    The letters below are the ones that distinguish cp1254 from
    cp1252; without them the test could not tell the two apart.
    """
        path = tmp_path / "a.txt"
        path.write_bytes("cp1254 letters: şğıİ".encode("cp1254"))
        assert "şğıİ" in text_of(path, config)

    def test_utf16(self, tmp_path, config):
        path = tmp_path / "a.txt"
        path.write_bytes("secret data".encode("utf-16"))
        assert "secret" in text_of(path, config)

    def test_empty_file_yields_nothing(self, tmp_path, config):
        path = tmp_path / "a.txt"
        path.write_text("", encoding="utf-8")
        assert list(extract(str(path), config)) == []

    def test_binary_is_skipped(self, tmp_path, config):
        path = tmp_path / "a.txt"
        path.write_bytes(b"\x00\x01\x02binary\x00data")
        assert list(extract(str(path), config)) == []

    def test_chunking_preserves_line_numbers(self, tmp_path, config):
        """Streaming reads must not shift line numbers."""
        lines = [f"line {i}" for i in range(1, 26)]
        lines[19] = f"ID: {VALID_TCKN}"  # line 20
        path = tmp_path / "a.txt"
        path.write_text("\n".join(lines), encoding="utf-8")

        chunks = list(extract(str(path), config.replace(chunk_lines=7)))
        assert len(chunks) == 4  # 7+7+7+4

        from sentinel.matcher import Matcher

        matcher = Matcher(config)
        findings = []
        for chunk in chunks:
            findings.extend(
                matcher.scan_text(chunk.text, "a.txt", line_offset=chunk.line_offset)
            )
        assert [f.line for f in findings if f.type == "TR_NATIONAL_ID"] == [20]

    def test_binary_sniffing_allows_utf16_bom(self, tmp_path):
        path = tmp_path / "a.txt"
        path.write_bytes("data".encode("utf-16"))
        assert not plain.looks_binary(str(path))


class TestArchive:
    def _make_zip(self, path, members: dict):
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, content in members.items():
                archive.writestr(name, content)
        return path

    def test_reads_zip_members(self, tmp_path, config):
        path = self._make_zip(
            tmp_path / "a.zip", {"secret_notes.txt": f"TC: {VALID_TCKN}"}
        )
        chunks = list(extract(str(path), config))
        assert chunks
        assert VALID_TCKN in chunks[0].text

    def test_member_path_is_shown_in_source(self, tmp_path, config):
        path = self._make_zip(tmp_path / "a.zip", {"folder/file.txt": "data"})
        chunk = next(iter(extract(str(path), config)))
        assert chunk.source.endswith("a.zip::folder/file.txt")

    def test_nested_zip_within_depth(self, tmp_path, config):
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as archive:
            archive.writestr("ic.txt", f"TC: {VALID_TCKN}")
        path = self._make_zip(tmp_path / "a.zip", {"ic.zip": inner.getvalue()})
        assert VALID_TCKN in text_of(path, config)

    def test_depth_limit_stops_recursion(self, tmp_path, config):
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as archive:
            archive.writestr("ic.txt", f"TC: {VALID_TCKN}")
        path = self._make_zip(tmp_path / "a.zip", {"ic.zip": inner.getvalue()})
        shallow = config.replace(archive_max_depth=1)
        assert VALID_TCKN not in text_of(path, shallow)

    def test_member_limit(self, tmp_path, config):
        members = {f"f{i}.txt": "data" for i in range(50)}
        path = self._make_zip(tmp_path / "a.zip", members)
        limited = config.replace(archive_max_members=5)
        assert len(list(extract(str(path), limited))) <= 5

    def test_zip_bomb_ratio_guard(self, tmp_path, config):
        """A large member with a high compression ratio (42.zip style) must be skipped."""
        path = tmp_path / "bomb.zip"
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("bomb.txt", "A" * (8 * 1024 * 1024))
        chunks = list(extract(str(path), config.replace(archive_max_ratio=10)))
        assert chunks == []

    def test_zip_slip_member_is_rejected(self, tmp_path, config):
        path = tmp_path / "evil.zip"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("../../etc/passwd", "evil")
            archive.writestr("good.txt", "data")
        sources = [chunk.source for chunk in extract(str(path), config)]
        assert all("etc/passwd" not in source for source in sources)
        assert any("good.txt" in source for source in sources)

    def test_archives_can_be_disabled(self, tmp_path, config):
        path = self._make_zip(tmp_path / "a.zip", {"x.txt": f"TC: {VALID_TCKN}"})
        assert list(extract(str(path), config.replace(archive_enabled=False))) == []

    def test_corrupt_zip_does_not_raise(self, tmp_path, config):
        path = tmp_path / "corrupt.zip"
        path.write_bytes(b"this is not a zip")
        assert list(extract(str(path), config)) == []


class TestOffice:
    def test_docx_paragraphs_and_tables(self, tmp_path, config):
        docx = pytest.importorskip("docx")
        document = docx.Document()
        document.add_paragraph(f"Customer ID: {VALID_TCKN}")
        table = document.add_table(rows=1, cols=2)
        table.cell(0, 0).text = "Card"
        table.cell(0, 1).text = VALID_VISA
        path = tmp_path / "a.docx"
        document.save(str(path))

        text = text_of(path, config)
        assert VALID_TCKN in text
        assert VALID_VISA in text

    def test_xlsx_all_sheets(self, tmp_path, config):
        openpyxl = pytest.importorskip("openpyxl")
        workbook = openpyxl.Workbook()
        workbook.active.title = "Musteriler"
        workbook.active["A1"] = "TC"
        workbook.active["B1"] = VALID_TCKN
        second = workbook.create_sheet("Odemeler")
        second["A1"] = VALID_VISA
        path = tmp_path / "a.xlsx"
        workbook.save(str(path))

        chunks = list(extract(str(path), config))
        combined = "\n".join(chunk.text for chunk in chunks)
        assert VALID_TCKN in combined
        assert VALID_VISA in combined
        # The page name must appear in the source path.
        assert any("Musteriler" in chunk.source for chunk in chunks)

    def test_pptx_slides_and_notes(self, tmp_path, config):
        pptx = pytest.importorskip("pptx")
        presentation = pptx.Presentation()
        slide = presentation.slides.add_slide(presentation.slide_layouts[5])
        slide.shapes.title.text = f"TC: {VALID_TCKN}"
        path = tmp_path / "a.pptx"
        presentation.save(str(path))
        assert VALID_TCKN in text_of(path, config)

    def test_corrupt_office_file_does_not_raise(self, tmp_path, config):
        path = tmp_path / "a.docx"
        path.write_bytes(b"this is not a docx")
        assert list(extract(str(path), config)) == []


class TestPdf:
    def test_reads_text(self, tmp_path, config):
        pytest.importorskip("reportlab")
        from reportlab.pdfgen import canvas

        path = tmp_path / "a.pdf"
        pdf = canvas.Canvas(str(path))
        pdf.drawString(72, 720, f"Customer ID: {VALID_TCKN}")
        pdf.save()

        assert VALID_TCKN in text_of(path, config)

    def test_corrupt_pdf_does_not_raise(self, tmp_path, config):
        path = tmp_path / "a.pdf"
        path.write_bytes(b"%PDF-1.4 corrupt")
        assert list(extract(str(path), config)) == []


class TestImageOcr:
    def test_disabled_by_default(self, tmp_path, config):
        pytest.importorskip("PIL")
        from PIL import Image

        path = tmp_path / "a.png"
        Image.new("RGB", (40, 20), "white").save(str(path))
        assert list(extract(str(path), config)) == []

    def test_cross_platform_lookup_does_not_crash(self):
        """Without Tesseract it must return None; no Windows path may be assumed."""
        from sentinel.extractors import image

        assert image.find_tesseract() is None or isinstance(
            image.find_tesseract(), str
        )
        assert image.get_ocr(None) is None or callable(image.get_ocr(None))
