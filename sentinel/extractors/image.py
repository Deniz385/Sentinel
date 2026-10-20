"""Görsel OCR çıkarıcısı (çapraz platform).

v3.0'da Tesseract yolu kaynak kodda ``C:\\Program Files\\Tesseract-OCR``
olarak sabitti; Linux ve macOS'ta OCR hiç çalışmıyordu. Burada motor
sırayla aranır: yapılandırma → ortam değişkeni → ``PATH`` → bilinen
kurulum dizinleri. Bulunamazsa OCR sessizce devre dışı kalır, tarama
durmaz.
"""

from __future__ import annotations

import os
import shutil

EXTENSIONS = frozenset({".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff", ".webp"})

#: Platforma göre bilinen Tesseract konumları.
_KNOWN_PATHS = (
    r"C:\Program Files\Tesseract-OCR\tesseract.exe",
    r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
    "/usr/bin/tesseract",
    "/usr/local/bin/tesseract",
    "/opt/homebrew/bin/tesseract",
)

#: Çok büyük görseller OCR'ı dakikalarca meşgul eder; önce küçültülür.
_MAX_PIXELS = 4000 * 4000


def find_tesseract(config=None) -> str | None:
    """Tesseract çalıştırılabilirinin yolunu bulur."""
    candidates = []
    if config is not None and getattr(config, "tesseract_cmd", ""):
        candidates.append(config.tesseract_cmd)
    if os.environ.get("TESSERACT_CMD"):
        candidates.append(os.environ["TESSERACT_CMD"])

    found = shutil.which("tesseract")
    if found:
        candidates.append(found)
    candidates.extend(_KNOWN_PATHS)

    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return candidate
    return None


def ocr_available(config=None) -> bool:
    try:
        import pytesseract  # noqa: F401
        from PIL import Image  # noqa: F401
    except ImportError:
        return False
    return find_tesseract(config) is not None


def get_ocr(config=None):
    """OCR çağrılabiliri döndürür: ``callable(PIL.Image) -> str``.

    OCR kullanılamıyorsa ``None`` döner — çağıran taraf buna göre karar
    verir, istisna fırlatılmaz.
    """
    try:
        import pytesseract
    except ImportError:
        return None

    command = find_tesseract(config)
    if command is None:
        return None

    pytesseract.pytesseract.tesseract_cmd = command

    tessdata = (getattr(config, "tessdata_prefix", "") if config else "") or os.environ.get(
        "TESSDATA_PREFIX", ""
    )
    if not tessdata:
        # Çalıştırılabilirin yanındaki tessdata dizinini dene.
        sibling = os.path.join(os.path.dirname(command), "tessdata")
        if os.path.isdir(sibling):
            tessdata = sibling
    if tessdata and os.path.isdir(tessdata):
        os.environ["TESSDATA_PREFIX"] = tessdata

    langs = (getattr(config, "ocr_langs", "") if config else "") or "eng"

    def run(img) -> str:
        try:
            return pytesseract.image_to_string(img, lang=langs)
        except Exception:
            # İstenen dil paketi kurulu değilse İngilizceye düş.
            try:
                return pytesseract.image_to_string(img, lang="eng")
            except Exception:
                return ""

    return run


def extract(path: str, config):
    from sentinel.extractors import TextChunk

    if not getattr(config, "ocr", False):
        return

    ocr = get_ocr(config)
    if ocr is None:
        return

    try:
        from PIL import Image
    except ImportError:
        return

    try:
        with Image.open(path) as img:
            if img.width * img.height > _MAX_PIXELS:
                img.thumbnail((4000, 4000))
            text = ocr(img)
    except Exception:
        return

    if text and text.strip():
        yield TextChunk(text, path, 0, path)
