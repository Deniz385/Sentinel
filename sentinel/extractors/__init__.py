"""File format to text extractors.

The old `scanner.py` handled every format in one function through a
chain of `elif`s; `.docx` was read as plain text (ZIP binary noise) and
there was no ZIP support at all. Here each format lives in its own
module behind a shared interface:

    extract(path, config) -> Iterator[TextChunk]

The streaming design means large files never have to fit in memory.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

__all__ = ["TextChunk", "ExtractionError", "extract", "supports", "EXTRACTORS"]


@dataclass(frozen=True)
class TextChunk:
    """A chunk of text to scan.

    `source` is the location shown to the user; for archive members it
    takes the form ``archive.zip::folder/file.txt``. `line_offset` keeps
    line numbers correct in large files read chunk by chunk.
    """

    text: str
    source: str
    line_offset: int = 0
    real_path: str = ""


class ExtractionError(Exception):
    """The file could not be read, or the format is corrupt."""


def _registry():
    # Lazy import to avoid a circular import.
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
    """Is there a dedicated extractor for this file?"""
    return _resolve(path) is not None


def extract(path: str, config, depth: int = 0):
    """Yield chunks of text from a file.

    With no known extractor the file is tried as plain text, so
    extensionless configuration files (`Dockerfile`, `.env.prod`) are
    scanned too.
    """
    from sentinel.extractors import archive, plain

    handler = _resolve(path)
    if handler is None:
        handler = plain.extract

    if handler is archive.extract:
        return handler(path, config, depth=depth)
    return handler(path, config)
