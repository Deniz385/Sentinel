"""Düz metin / kaynak kod çıkarıcısı.

Dosyanın tamamını belleğe almak yerine parça parça okur: 2 GB'lık bir log
dosyası 8 MB bellekle taranabilir. Kodlama tespiti kademelidir
(UTF-8 → UTF-16 BOM → cp1254 → latin-1), çünkü Türkçe dosyalar sıkça
Windows-1254 ile kodlanmıştır.
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

#: Metin sanıp açtığımız dosya aslında binary ise bu kadar NUL yeter.
_BINARY_SNIFF_BYTES = 8192


def looks_binary(path: str) -> bool:
    """Dosya binary mi? NUL baytı en güvenilir ve en hızlı göstergedir."""
    try:
        with open(path, "rb") as handle:
            sample = handle.read(_BINARY_SNIFF_BYTES)
    except OSError:
        return True
    if not sample:
        return False
    if sample.startswith((b"\xff\xfe", b"\xfe\xff")):
        return False  # UTF-16 BOM: metin
    return b"\x00" in sample


def _open_text(path: str):
    """Dosyayı doğru kodlamayla açar."""
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

    # Hiçbiri tutmadıysa bozuk karakterleri değiştirerek oku; dosyayı
    # sessizce atlamak, içindeki sırrı kaçırmak anlamına gelir.
    return open(path, encoding="utf-8", errors="replace", newline="")


def extract(path: str, config):
    """Dosyayı `config.chunk_lines` satırlık parçalar hâlinde üretir."""
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
    """Bellekteki baytları metne çevirip tek parça olarak üretir.

    Arşiv üyeleri için kullanılır: küçük üyeleri diske yazmadan tararız.
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
