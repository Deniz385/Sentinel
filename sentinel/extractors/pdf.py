"""PDF text extractor.

Yields page by page, so a 2000-page PDF never sits in memory as a
whole. Optionally the images embedded in a page are put through OCR,
which is how scanned copies of identity documents get caught.
"""

from __future__ import annotations

from sentinel.extractors import TextChunk

EXTENSIONS = frozenset({".pdf"})


def _reader(path: str):
    try:
        from pypdf import PdfReader
    except ImportError:  # pragma: no cover
        try:
            from PyPDF2 import PdfReader  # type: ignore
        except ImportError:
            return None

    try:
        return PdfReader(path)
    except Exception:
        # Corrupt or truncated PDF: one file must not fail the scan.
        return None


def extract(path: str, config):
    reader = _reader(path)
    if reader is None:
        return

    if getattr(reader, "is_encrypted", False):
        # Try an empty password (very common); otherwise skip quietly.
        try:
            reader.decrypt("")
        except Exception:
            return

    ocr = None
    if getattr(config, "ocr", False) and getattr(config, "ocr_pdf_images", False):
        from sentinel.extractors import image

        ocr = image.get_ocr(config)

    for index, page in enumerate(reader.pages, 1):
        parts: list[str] = []
        try:
            text = page.extract_text() or ""
        except Exception:
            text = ""
        if text.strip():
            parts.append(text)

        if ocr is not None:
            parts.extend(_ocr_page_images(page, ocr, config))

        if parts:
            yield TextChunk(
                "\n".join(parts), f"{path}::page-{index}", 0, path
            )


def _ocr_page_images(page, ocr, config):
    """Run OCR over the images embedded in a page."""
    import io

    try:
        images = list(getattr(page, "images", []) or [])
    except Exception:
        return

    from PIL import Image

    for embedded in images[:20]:  # per-page cap: OCR is expensive
        try:
            with Image.open(io.BytesIO(embedded.data)) as img:
                text = ocr(img)
        except Exception:
            continue
        if text and text.strip():
            yield text
