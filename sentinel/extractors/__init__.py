"""Dosya biçimi → metin çıkarıcıları.

Eski `scanner.py` tüm biçimleri tek fonksiyonda `elif` zinciriyle
işliyordu; `.docx` düz metin olarak okunuyor (ZIP binary çöpü) ve ZIP
desteği hiç yoktu. Burada her biçim kendi modülünde, ortak bir arayüzle:

    extract(path, config) -> Iterator[TextChunk]

Akış (streaming) tasarımı büyük dosyaların belleğe sığmasını gerektirmez.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

__all__ = ["TextChunk", "ExtractionError", "extract", "supports", "EXTRACTORS"]


@dataclass(frozen=True)
class TextChunk:
    """Taranacak metin parçası.

    `source` kullanıcıya gösterilen konumdur; arşiv üyeleri için
    ``arsiv.zip::klasor/dosya.txt`` biçimini alır. `line_offset`, parça
    halinde okunan büyük dosyalarda satır numaralarını doğru tutar.
    """

    text: str
    source: str
    line_offset: int = 0
    real_path: str = ""


class ExtractionError(Exception):
    """Dosya okunamadı / biçim bozuk."""


def _registry():
    # Döngüsel import olmaması için tembel yükleme.
    from sentinel.extractors import archive, image, office, pdf, plain

    return (
        (archive.EXTENSIONS, archive.extract),
        (pdf.EXTENSIONS, pdf.extract),
        (office.DOCX_EXTENSIONS, office.extract_docx),
        (office.XLSX_EXTENSIONS, office.extract_xlsx),
        (office.PPTX_EXTENSIONS, office.extract_pptx),
        (image.EXTENSIONS, image.extract),
        (plain.EXTENSIONS, plain.extract),
    )


EXTRACTORS = None


def _resolve(path: str):
    global EXTRACTORS
    if EXTRACTORS is None:
        EXTRACTORS = _registry()
    extension = os.path.splitext(path)[1].lower()
    for extensions, handler in EXTRACTORS:
        if extension in extensions:
            return handler
    return None


def supports(path: str) -> bool:
    """Bu dosya için özel bir çıkarıcı var mı?"""
    return _resolve(path) is not None


def extract(path: str, config, depth: int = 0):
    """Dosyadan metin parçaları üretir.

    Bilinen bir çıkarıcı yoksa dosya düz metin olarak denenir; böylece
    uzantısız yapılandırma dosyaları (`Dockerfile`, `.env.prod`) da taranır.
    """
    from sentinel.extractors import archive, plain

    handler = _resolve(path)
    if handler is None:
        handler = plain.extract

    if handler is archive.extract:
        return handler(path, config, depth=depth)
    return handler(path, config)
