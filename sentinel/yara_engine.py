"""YARA kural motoru.

`rules/sample.yar` depoda duruyordu ama hiçbir kod onu okumuyordu — ölü
bir dosyaydı. Burada gerçekten derlenip çalıştırılır. `yara-python`
kurulu değilse motor devre dışı kalır ve tarama etkilenmez
(``pip install sentinel-dlp[yara]``).
"""

from __future__ import annotations

import glob
import os

from sentinel.findings import Finding
from sentinel.severity import Severity

__all__ = ["YaraEngine", "yara_available"]

#: Kural meta alanında `severity` yoksa bu kullanılır.
_DEFAULT_SEVERITY = Severity.MEDIUM


def yara_available() -> bool:
    try:
        import yara  # noqa: F401
    except ImportError:
        return False
    return True


class YaraEngine:
    """Derlenmiş YARA kurallarını dosyalara uygular."""

    def __init__(self, rules_dir: str = "rules"):
        self.rules_dir = rules_dir
        self.rules = None
        self.error: str | None = None
        self._compile()

    def _compile(self):
        try:
            import yara
        except ImportError:
            self.error = "yara-python kurulu değil"
            return

        if not os.path.isdir(self.rules_dir):
            self.error = f"Kural dizini yok: {self.rules_dir}"
            return

        sources = {}
        for pattern in ("*.yar", "*.yara"):
            for path in sorted(glob.glob(os.path.join(self.rules_dir, pattern))):
                sources[os.path.splitext(os.path.basename(path))[0]] = path

        if not sources:
            self.error = f"{self.rules_dir} içinde .yar kuralı bulunamadı"
            return

        try:
            self.rules = yara.compile(filepaths=sources)
        except Exception as exc:  # derleme hatası kullanıcıya bildirilmeli
            self.error = f"YARA derleme hatası: {exc}"
            self.rules = None

    @property
    def enabled(self) -> bool:
        return self.rules is not None

    def match_file(self, path: str, display_path: str = "", file_sha: str = "N/A"):
        """Dosyayı kurallara karşı eşleştirir ve bulgu listesi döndürür."""
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
                    content_masked=f"<{len(match.strings)} imza eşleşmesi>",
                    fingerprint="",
                    validated=True,
                    sha256=file_sha,
                    real_path=path,
                    extra={"yara_rule": match.rule, "yara_tags": list(match.tags)},
                )
            )
        return findings
