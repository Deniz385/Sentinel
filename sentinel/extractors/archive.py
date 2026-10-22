"""ZIP archive extractor (recursive, zip-bomb protected).

The v3.0 `main.py` advertised a "ZIP" module, but `scanner.py` had no
ZIP support - while the old `scan_results.csv` in the repository
contains a finding inside ``secret_archive.zip``. So this was
a regression; it is restored here, and made safe.

Archive scanning is attack surface, so four separate limits apply:

* **depth** - endless recursion through nested archives,
* **member count** - millions of tiny files,
* **total expanded bytes** - 42.zip style bombs,
* **compression ratio** - a single member expanding absurdly,

and member paths that try to write outside the directory (`../`, an
absolute path, a symlink) are rejected.
"""

from __future__ import annotations

import os
import posixpath
import tempfile
import zipfile

from sentinel.extractors import TextChunk

EXTENSIONS = frozenset({".zip", ".jar", ".war", ".apk", ".whl", ".egg", ".xpi"})

#: Size limit for members scanned in memory, without touching disk.
_INLINE_LIMIT = 4 * 1024 * 1024

#: Member extensions extracted and handed to a dedicated extractor.
_NEEDS_FILE = frozenset(
    {
        ".pdf", ".docx", ".docm", ".dotx", ".xlsx", ".xlsm", ".xltx",
        ".pptx", ".pptm", ".potx", ".png", ".jpg", ".jpeg", ".bmp",
        ".tif", ".tiff", ".webp", ".zip", ".jar", ".war", ".apk",
    }
)


def _is_unsafe(name: str) -> bool:
    """Reject member names that try to escape the directory (zip slip)."""
    if not name or name.endswith("/"):
        return True
    if os.path.isabs(name) or name.startswith(("/", "\\")):
        return True
    normalized = posixpath.normpath(name.replace("\\", "/"))
    return normalized.startswith("..") or "/../" in f"/{normalized}"


def extract(path: str, config, depth: int = 0):
    if not getattr(config, "archive_enabled", True):
        return
    if depth >= getattr(config, "archive_max_depth", 3):
        return

    max_members = getattr(config, "archive_max_members", 2000)
    max_total = getattr(config, "archive_max_total_bytes", 512 * 1024 * 1024)
    max_ratio = getattr(config, "archive_max_ratio", 200)

    try:
        archive = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError):
        return

    with archive:
        try:
            infos = archive.infolist()
        except Exception:
            return

        total_bytes = 0
        processed = 0

        for info in infos:
            if processed >= max_members:
                break
            if info.is_dir() or _is_unsafe(info.filename):
                continue

            # Compression-ratio bomb: 1 KB compressed, 1 GB expanded.
            if info.compress_size > 0:
                ratio = info.file_size / info.compress_size
                if ratio > max_ratio and info.file_size > 1024 * 1024:
                    continue

            if total_bytes + info.file_size > max_total:
                break

            member_display = f"{path}::{info.filename}"
            extension = os.path.splitext(info.filename)[1].lower()

            try:
                if extension in _NEEDS_FILE or info.file_size > _INLINE_LIMIT:
                    yield from _via_tempfile(
                        archive, info, member_display, path, config, depth
                    )
                else:
                    data = archive.read(info)
                    total_bytes += len(data)
                    from sentinel.extractors import plain

                    yield from plain.extract_bytes(data, member_display, config, path)
                    processed += 1
                    continue
            except (RuntimeError, zipfile.BadZipFile, OSError, NotImplementedError):
                # Password protected or an unsupported compression method: skip.
                continue

            total_bytes += info.file_size
            processed += 1


def _via_tempfile(archive, info, member_display, container, config, depth: int):
    """Expand the member to a temp file and hand it to the right extractor."""
    from sentinel.extractors import extract as dispatch

    extension = os.path.splitext(info.filename)[1].lower() or ".bin"
    with tempfile.TemporaryDirectory(prefix="sentinel-zip-") as tmpdir:
        temp_path = os.path.join(tmpdir, f"member{extension}")
        try:
            with archive.open(info) as source, open(temp_path, "wb") as target:
                remaining = info.file_size
                while remaining > 0:
                    block = source.read(min(1024 * 1024, remaining))
                    if not block:
                        break
                    target.write(block)
                    remaining -= len(block)
        except Exception:
            return

        for chunk in dispatch(temp_path, config, depth=depth + 1):
            # The temp path must not reach the user: show the in-archive location.
            display = chunk.source.replace(temp_path, member_display, 1)
            yield TextChunk(chunk.text, display, chunk.line_offset, container)
