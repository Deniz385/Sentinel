"""The YARA rule engine.

`rules/sample.yar` sat in the repository but no code ever read it - a
dead file. Here the rules are genuinely compiled and run. Without
`yara-python` installed the engine stays disabled and scanning is
unaffected (``pip install sentinel-dlp[yara]``).
"""

from __future__ import annotations

import glob
import os

from sentinel.findings import Finding
from sentinel.severity import Severity

__all__ = ["YaraEngine", "yara_available"]

#: Used when a rule's meta section carries no `severity`.
_DEFAULT_SEVERITY = Severity.MEDIUM


def yara_available() -> bool:
    try:
        import yara  # noqa: F401
    except ImportError:
        return False
    return True


class YaraEngine:
    """Apply compiled YARA rules to files."""

    def __init__(self, rules_dir: str = "rules"):
        self.rules_dir = rules_dir
        self.rules = None
        self.error: str | None = None
        self._compile()

    def _compile(self):
        try:
            import yara
        except ImportError:
            self.error = "yara-python is not installed"
            return

        if not os.path.isdir(self.rules_dir):
            self.error = f"Rules directory not found: {self.rules_dir}"
            return

        sources = {}
        for pattern in ("*.yar", "*.yara"):
            for path in sorted(glob.glob(os.path.join(self.rules_dir, pattern))):
                sources[os.path.splitext(os.path.basename(path))[0]] = path

        if not sources:
            self.error = f"No .yar rules found in {self.rules_dir}"
            return

        try:
            self.rules = yara.compile(filepaths=sources)
        except Exception as exc:  # a compile error must reach the user
            self.error = f"YARA compile error: {exc}"
            self.rules = None

    @property
    def enabled(self) -> bool:
        return self.rules is not None

    def match_file(self, path: str, display_path: str = "", file_sha: str = "N/A"):
        """Match the file against the rules and return a list of findings."""
        if self.rules is None:
            return []

        try:
            matches = self.rules.match(path, timeout=30)
        except Exception:
            return []

        display_path = display_path or path
        findings = []
        for match in matches:
            meta = getattr(match, "meta", {}) or {}
            try:
                severity = Severity.parse(meta.get("severity", _DEFAULT_SEVERITY.value))
            except ValueError:
                severity = _DEFAULT_SEVERITY

            description = meta.get("description") or match.rule
            findings.append(
                Finding(
                    file=display_path,
                    line=0,
                    type=f"YARA_{match.rule}",
                    title=f"YARA: {description}",
                    severity=severity.value,
                    content_masked=f"<{len(match.strings)} signature matches>",
                    fingerprint="",
                    validated=True,
                    sha256=file_sha,
                    real_path=path,
                    extra={"yara_rule": match.rule, "yara_tags": list(match.tags)},
                )
            )
        return findings
