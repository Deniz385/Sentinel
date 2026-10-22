"""Plain text and source code extractor.

Reads in chunks rather than pulling the whole file into memory: a 2 GB
log file can be scanned in 8 MB of RAM. Encoding detection is layered
(UTF-8 -> UTF-16 BOM -> cp1254 -> latin-1), because Turkish files are
frequently encoded in Windows-1254.
"""

from __future__ import annotations

import os

from sentinel.extractors import TextChunk

EXTENSIONS = frozenset(
    {
        ".txt", ".csv", ".tsv", ".log", ".md", ".rst", ".ini", ".cfg", ".conf",
        ".env", ".json", ".yml", ".yaml", ".xml", ".toml", ".sql", ".properties",
        ".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".rb", ".go", ".java",
        ".cs", ".kt", ".swift", ".sh", ".bash", ".ps1", ".bat", ".cmd",
        ".html", ".htm", ".css", ".scss", ".vue", ".svelte", ".tf", ".tfvars",
        ".c", ".h", ".cpp", ".hpp", ".rs", ".pl", ".lua", ".r", ".ipynb", "",
    }
)

_ENCODINGS = ("utf-8", "utf-8-sig", "cp1254", "latin-1")

#: This many bytes are enough to spot a NUL in a supposedly text file.
_BINARY_SNIFF_BYTES = 8192


def looks_binary(path: str) -> bool:
    """Is the file binary? A NUL byte is the fastest reliable signal."""
    try:
        with open(path, "rb") as handle:
            sample = handle.read(_BINARY_SNIFF_BYTES)
    except OSError:
        return True
    if not sample:
        return False
    if sample.startswith((b"\xff\xfe", b"\xfe\xff")):
        return False  # UTF-16 BOM: it is text
    return b"\x00" in sample


def _open_text(path: str):
    """Open the file with the right encoding."""
    with open(path, "rb") as handle:
        prefix = handle.read(4)

    if prefix.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        encodings = ("utf-32",) + _ENCODINGS
    elif prefix.startswith((b"\xff\xfe", b"\xfe\xff")):
        encodings = ("utf-16",) + _ENCODINGS
    else:
        encodings = _ENCODINGS

    for encoding in encodings:
        handle = open(path, encoding=encoding, errors="strict", newline="")
        try:
            handle.read(4096)
            handle.seek(0)
            return handle
        except (UnicodeDecodeError, UnicodeError):
            handle.close()
            continue
        except Exception:
            handle.close()
            raise

    # If none worked, read with replacement characters: silently
    # skipping the file would mean missing the secret inside it.
    return open(path, encoding="utf-8", errors="replace", newline="")


def extract(path: str, config):
    """Yield the file in chunks of `config.chunk_lines` lines."""
    if looks_binary(path):
        return

    try:
        size = os.path.getsize(path)
    except OSError:
        return
    if size == 0:
        return

    chunk_lines = max(1, int(getattr(config, "chunk_lines", 5000)))
    handle = _open_text(path)
    try:
        buffer: list[str] = []
        offset = 0
        for line in handle:
            buffer.append(line.rstrip("\r\n"))
            if len(buffer) >= chunk_lines:
                yield TextChunk("\n".join(buffer), path, offset, path)
                offset += len(buffer)
                buffer = []
        if buffer:
            yield TextChunk("\n".join(buffer), path, offset, path)
    finally:
        handle.close()


def extract_bytes(data: bytes, source: str, config, real_path: str = ""):
    """Decode in-memory bytes to text and yield them as one chunk.

    Used for archive members: small members are scanned without being
    written to disk.
    """
    if b"\x00" in data[:_BINARY_SNIFF_BYTES]:
        return
    for encoding in _ENCODINGS:
        try:
            text = data.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    else:
        text = data.decode("utf-8", errors="replace")
    if text.strip():
        yield TextChunk(text, source, 0, real_path or source)
