"""PDF metin çıkarıcısı.

Sayfa sayfa üretir; 2000 sayfalık bir PDF'in tamamı belleğe alınmaz.
İsteğe bağlı olarak sayfaya gömülü görseller OCR'dan geçirilir (taranmış
kimlik fotokopileri bu yolla yakalanır).
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
        # Bozuk/kesilmiş PDF: tek dosya yüzünden tarama düşmemeli.
        return None


def extract(path: str, config):
    reader = _reader(path)
    if reader is None:
        return

    if getattr(reader, "is_encrypted", False):
        # Boş parola ile açılmayı dene (çok yaygın); olmazsa sessizce geç.
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
                "\n".join(parts), f"{path}::sayfa-{index}", 0, path
            )


def _ocr_page_images(page, ocr, config):
    """Sayfadaki gömülü görselleri OCR'dan geçirir."""
    import io

    try:
        images = list(getattr(page, "images", []) or [])
    except Exception:
        return

    from PIL import Image

    for embedded in images[:20]:  # sayfa başına üst sınır: OCR pahalı
        try:
            with Image.open(io.BytesIO(embedded.data)) as img:
                text = ocr(img)
        except Exception:
            continue
        if text and text.strip():
            yield text
