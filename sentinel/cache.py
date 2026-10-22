"""Incremental scan cache.

Re-reading a 500 GB file share from scratch every night, when 99% of it
has not changed, means nearly all of that time is wasted. The record
kept here - ``(path -> mtime_ns, size, findings)`` - skips unchanged
files without reading them again.

In a security tool a cache is, if built carelessly, the mechanism that
makes a leak **invisible**. Hence three rules:

1. **If the configuration or the rule catalogue changes, the whole cache
   is dropped.** Once a new rule exists the old verdicts no longer hold;
   a single stale entry hides the secret that rule would have found.
2. **Error results are never cached.** A transient read failure (a
   locked file, a network blip) must not make a file invisible forever.
3. **The cache is never used while quarantine is on** (enforced by the
   engine): a decision that deletes data cannot rest on stale evidence.

The freshness test is ``(st_mtime_ns, st_size)``. That is a heuristic,
not proof: an attacker who restores mtime by hand can slip past it. When
forensic certainty is required the cache stays off (the default).
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field

from sentinel import __version__

__all__ = [
    "ScanCache",
    "DEFAULT_CACHE_NAME",
    "CACHE_SCHEMA",
    "config_fingerprint",
    "clear_cache",
]

DEFAULT_CACHE_NAME = ".sentinel-cache.json"

#: Format version. Bumping it makes older caches be ignored silently.
CACHE_SCHEMA = 1

#: Maximum number of entries kept. Beyond this the least recently seen
#: are dropped, so the cache file cannot grow without bound.
MAX_ENTRIES = 200_000

#: Settings that do **not** affect results: when these change the cache
#: stays valid. Every other field goes into the fingerprint - when in
#: doubt, dropping the cache beats missing a finding.
_IRRELEVANT_FIELDS = frozenset(
    {
        "target",
        "workers",
        "executor",
        "audit_log",
        "webhook_url",
        "webhook_min_severity",
        "webhook_batch",
        "quarantine",
        "quarantine_dir",
        "quarantine_min_severity",
        "shred_original",
        "incremental",
        "cache_path",
        "baseline_path",
    }
)


def _yara_signature(config) -> list:
    """A signature of the ``rules/*.yar`` files.

    YARA rules determine verdicts just as the pattern catalogue does.
    The configuration holds only the *directory path*, so editing a rule
    file would not change the fingerprint and whatever the new rule would
    find would stay hidden behind the cache. There is no need to read the
    files: name plus mtime plus size is signature enough.
    """
    if not config.yara_enabled:
        return []
    directory = config.yara_rules_dir or ""
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        return []

    signature = []
    for name in names:
        if not name.lower().endswith((".yar", ".yara")):
            continue
        try:
            info = os.stat(os.path.join(directory, name))
        except OSError:
            continue
        signature.append([name, info.st_mtime_ns, info.st_size])
    return signature


def config_fingerprint(config) -> str:
    """A stable digest of configuration, rule catalogue and version.

    The version is included too: an upgrade may have changed the
    validators or the entropy heuristics, so a new version does not
    inherit the old verdicts.
    """
    from sentinel.patterns import PATTERN_DEFS

    payload = {
        key: value
        for key, value in sorted(config.to_dict().items())
        if key not in _IRRELEVANT_FIELDS
    }
    catalog = [
        (definition.name, definition.regex.pattern, definition.severity.value)
        for definition in PATTERN_DEFS
    ]
    blob = json.dumps(
        {
            "version": __version__,
            "config": payload,
            "catalog": catalog,
            "yara": _yara_signature(config),
        },
        sort_keys=True,
        ensure_ascii=False,
        default=str,
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:32]


@dataclass
class CacheStats:
    hits: int = 0
    misses: int = 0
    stale: int = 0

    def as_dict(self) -> dict:
        return {"hits": self.hits, "misses": self.misses, "stale": self.stale}


@dataclass
class ScanCache:
    """The incremental scan record on disk."""

    path: str
    config_hash: str
    entries: dict = field(default_factory=dict)
    stats: CacheStats = field(default_factory=CacheStats)
    #: Did the loaded cache fail to match this run's configuration?
    invalidated: bool = False

    # ------------------------------------------------------------------
    @classmethod
    def open(cls, path: str, config) -> ScanCache:
        """Read the cache; start empty when it is incompatible or corrupt."""
        fingerprint = config_fingerprint(config)
        cache = cls(path=path, config_hash=fingerprint)

        try:
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            # Missing, unreadable or corrupt: an empty cache means a full scan.
            return cache

        if not isinstance(data, dict):
            return cache
        if data.get("schema") != CACHE_SCHEMA:
            return cache
        if data.get("config_hash") != fingerprint:
            # Rules or settings changed: every entry is invalid.
            cache.invalidated = True
            return cache

        entries = data.get("entries")
        if isinstance(entries, dict):
            cache.entries = {
                key: value
                for key, value in entries.items()
                if isinstance(value, dict)
            }
        return cache

    # ------------------------------------------------------------------
    @staticmethod
    def _key(path: str) -> str:
        return os.path.abspath(path).replace(os.sep, "/")

    def lookup(self, path: str):
        """Build a `FileReport` from the cache when the file is unchanged."""
        from sentinel.engine import FileReport
        from sentinel.findings import Finding

        entry = self.entries.get(self._key(path))
        if entry is None:
            self.stats.misses += 1
            return None

        try:
            info = os.stat(path)
        except OSError:
            self.stats.misses += 1
            return None

        if entry.get("mtime_ns") != info.st_mtime_ns or entry.get("size") != info.st_size:
            self.stats.stale += 1
            return None

        try:
            findings = [Finding.from_dict(item) for item in entry.get("findings", [])]
        except (TypeError, ValueError):
            # If the entry is damaged, rescan the file rather than the cache.
            self.stats.misses += 1
            return None

        self.stats.hits += 1
        return FileReport(
            path=path,
            findings=findings,
            skipped=entry.get("skipped", ""),
            size=int(entry.get("size") or 0),
            sha256=entry.get("sha256", "N/A"),
            cached=True,
        )

    def remember(self, report) -> None:
        """Record the result of a fresh scan."""
        if report.error:
            # A transient failure must not make a file invisible for good.
            return
        if report.cached:
            return
        try:
            info = os.stat(report.path)
        except OSError:
            return

        self.entries[self._key(report.path)] = {
            "mtime_ns": info.st_mtime_ns,
            "size": info.st_size,
            "sha256": report.sha256,
            "skipped": report.skipped,
            "last_seen": int(time.time()),
            "findings": [finding.to_dict() for finding in report.findings],
        }

    # ------------------------------------------------------------------
    def save(self) -> bool:
        """Write the cache atomically. A failure never fails the scan."""
        entries = self.entries
        if len(entries) > MAX_ENTRIES:
            newest = sorted(
                entries.items(),
                key=lambda item: item[1].get("last_seen", 0),
                reverse=True,
            )[:MAX_ENTRIES]
            entries = dict(newest)

        payload = {
            "schema": CACHE_SCHEMA,
            "config_hash": self.config_hash,
            "written_at": int(time.time()),
            "entries": entries,
        }

        directory = os.path.dirname(os.path.abspath(self.path))
        temporary = f"{self.path}.tmp"
        try:
            if directory:
                os.makedirs(directory, exist_ok=True)
            with open(temporary, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False)
            os.replace(temporary, self.path)
            return True
        except OSError:
            # A half-written cache is worse than no cache: clean up the
            # temporary file and give up quietly.
            try:
                os.unlink(temporary)
            except OSError:
                pass
            return False


def clear_cache(path: str) -> bool:
    """Delete the cache file. Returns `False` when there was none."""
    try:
        os.unlink(path)
        return True
    except OSError:
        return False
