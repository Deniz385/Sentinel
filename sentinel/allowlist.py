"""False-positive management.

This is what decides whether a DLP tool gets used at all: if a team
keeps seeing the same 40 findings from test data on every scan, they
turn the tool off. Three ways to suppress are offered:

1. **Configuration**: path globs, exact values, fingerprints, regexes.
2. **Inline**: a ``sentinel:ignore`` comment on the line itself.
3. **Baseline**: freeze the current findings and report only new ones
   (`sentinel scan --baseline`).
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
from dataclasses import dataclass, field

__all__ = [
    "Allowlist",
    "DEFAULT_ALLOWED_VALUES",
    "INLINE_IGNORE_RE",
    "path_matches",
]

#: When this marker is on a line, findings on that line are suppressed.
#: ``sentinel:ignore`` (all) or ``sentinel:ignore=TR_NATIONAL_ID,EMAIL``
INLINE_IGNORE_RE = re.compile(
    r"sentinel\s*:\s*ignore(?:\s*[=:]\s*([A-Za-z0-9_, \-]+))?", re.IGNORECASE
)

#: Values from documentation and examples that are definitely not real.
DEFAULT_ALLOWED_VALUES = frozenset(
    {
        # Examples from the official AWS documentation
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        # Common placeholder and filler values
        "changeme",
        "CHANGEME",
        "your_api_key_here",
        "YOUR_API_KEY",
        "xxxxxxxxxxxxxxxx",
        "placeholder",
        "example",
        "password",
        "secret",
        "YOUR_WEBHOOK_URL_HERE",
    }
)

#: Domains reserved by RFC 2606 / 6761 that carry no real traffic.
_RESERVED_DOMAINS = (
    "@example.com",
    "@example.org",
    "@example.net",
    "@test",
    "@localhost",
    "@invalid",
)


@dataclass
class Allowlist:
    """Suppression rules. Picklable, so it can be sent to worker processes."""

    paths: tuple[str, ...] = ()
    values: tuple[str, ...] = ()
    fingerprints: tuple[str, ...] = ()
    patterns: tuple[str, ...] = ()
    rules: tuple[str, ...] = ()
    use_defaults: bool = True
    inline: bool = True
    _compiled: list = field(default_factory=list, repr=False, compare=False)

    def __post_init__(self):
        self.paths = tuple(self.paths)
        self.values = tuple(self.values)
        self.fingerprints = tuple(str(f).lower() for f in self.fingerprints)
        self.patterns = tuple(self.patterns)
        # Resolve aliases so an allowlist written against the former
        # Turkish rule names (``TC_KIMLIK``) still suppresses the renamed
        # rule (``TR_NATIONAL_ID``).
        from sentinel.patterns import resolve_name

        self.rules = tuple(resolve_name(r) for r in self.rules)

    # -- construction -----------------------------------------------------
    @classmethod
    def from_dict(cls, data: dict | None) -> Allowlist:
        data = data or {}
        return cls(
            paths=tuple(data.get("paths", ()) or ()),
            values=tuple(data.get("values", ()) or ()),
            fingerprints=tuple(data.get("fingerprints", ()) or ()),
            patterns=tuple(data.get("patterns", ()) or ()),
            rules=tuple(data.get("rules", ()) or ()),
            use_defaults=bool(data.get("use_defaults", True)),
            inline=bool(data.get("inline", True)),
        )

    def _regexes(self):
        if not self._compiled and self.patterns:
            # Compile lazily: a compiled regex is not carried through pickle.
            self._compiled = [re.compile(p) for p in self.patterns]
        return self._compiled

    def __getstate__(self):
        state = self.__dict__.copy()
        state["_compiled"] = []
        return state

    # -- queries ----------------------------------------------------------
    def allows_path(self, path: str) -> bool:
        """Is this file path exempt from scanning entirely?"""
        return path_matches(path, self.paths)

    def allows_rule(self, rule: str) -> bool:
        from sentinel.patterns import resolve_name

        return resolve_name(rule) in self.rules

    def allows_value(self, value: str, fingerprint: str = "") -> bool:
        if fingerprint and fingerprint.lower() in self.fingerprints:
            return True
        if value in self.values:
            return True
        if self.use_defaults:
            if value in DEFAULT_ALLOWED_VALUES:
                return True
            lowered = value.lower()
            if any(lowered.endswith(domain) for domain in _RESERVED_DOMAINS):
                return True
        return any(regex.search(value) for regex in self._regexes())

    def inline_suppressed(self, line: str, rule: str) -> bool:
        """Does the line carry a ``sentinel:ignore`` marker?"""
        if not self.inline or not line:
            return False
        match = INLINE_IGNORE_RE.search(line)
        if not match:
            return False
        scoped = match.group(1)
        if not scoped:
            return True
        from sentinel.patterns import resolve_name

        wanted = {resolve_name(r) for r in scoped.split(",") if r.strip()}
        return resolve_name(rule) in wanted


def path_matches(path: str, patterns) -> bool:
    """Does the path match any of the patterns?

    Users write patterns relative to the repository root (``tests/*``),
    but the scanned path may be absolute or prefixed with ``./``. Plain
    `fnmatch` then **silently does nothing** - the user believes files
    are excluded while they keep being scanned. So each pattern is also
    tried anchored anywhere within the path.

    Collected in one place so `exclude_globs` and allowlist paths share
    the same semantics.
    """
    if not patterns:
        return False

    normalized = str(path).replace(os.sep, "/")
    if normalized.startswith("./"):
        normalized = normalized[2:]
    name = normalized.rsplit("/", 1)[-1]

    for raw in patterns:
        pattern = str(raw).replace(os.sep, "/").rstrip("/")
        if pattern.startswith("./"):
            pattern = pattern[2:]
        if not pattern:
            continue

        candidates = [pattern, f"*/{pattern}"]
        # A "tests/**" pattern must cover the directory itself, so that
        # `os.walk` never descends into that branch.
        bare = pattern.removesuffix("/**").removesuffix("/*")
        if bare != pattern:
            candidates += [bare, f"*/{bare}"]

        if any(fnmatch.fnmatch(normalized, candidate) for candidate in candidates):
            return True
        if fnmatch.fnmatch(name, pattern):
            return True
        # A bare directory name ("test_data") occurring anywhere in the path.
        if "*" not in pattern and "?" not in pattern:
            if f"/{pattern}/" in f"/{normalized}/":
                return True
    return False


def load_baseline(path: str) -> set[str]:
    """Read the fingerprints to suppress from a baseline file."""
    if not path or not os.path.exists(path):
        return set()
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    entries = (
        data.get("findings", data.get("fingerprints", []))
        if isinstance(data, dict)
        else data
    )
    result = set()
    for entry in entries:
        if isinstance(entry, str):
            result.add(entry.lower())
        elif isinstance(entry, dict):
            key = entry.get("fingerprint") or entry.get("id")
            if key:
                result.add(str(key).lower())
    return result


def save_baseline(path: str, findings) -> int:
    """Freeze the current findings as a baseline."""
    payload = {
        "version": 1,
        "note": "Fingerprints in this file are suppressed in reports.",
        "findings": sorted(
            {f.fingerprint for f in findings if getattr(f, "fingerprint", "")}
        ),
    }
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
    return len(payload["findings"])
