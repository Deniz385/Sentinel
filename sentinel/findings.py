"""Bulgu (finding) veri modeli."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from sentinel.severity import Severity

__all__ = ["Finding", "LEGACY_COLUMNS", "CSV_COLUMNS"]

#: Eski ``scan_results.csv`` sütunları — dış araçlar kırılmasın diye korunur.
LEGACY_COLUMNS = ["file", "line", "type", "content_masked", "sha256"]

#: Yeni sütunlar eskilerin sonuna eklenir.
CSV_COLUMNS = LEGACY_COLUMNS + [
    "severity",
    "validated",
    "fingerprint",
    "source",
    "column",
    "snippet",
    "title",
]


@dataclass(frozen=True)
class Finding:
    """Tek bir hassas veri tespiti.

    `file` kullanıcıya gösterilen konumdur ve arşiv içindeki üyeler için
    ``arsiv.zip::klasor/dosya.txt`` biçimini alır. `real_path` ise diskteki
    gerçek dosyadır (karantina ve hash için kullanılır).
    """

    file: str
    line: int
    type: str
    content_masked: str
    severity: str = Severity.MEDIUM.value
    sha256: str = "N/A"
    fingerprint: str = ""
    column: int = 0
    snippet: str = ""
    validated: bool = False
    title: str = ""
    real_path: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def source(self) -> str:
        """Bulgunun geldiği kapsayıcı (arşiv) ya da dosyanın kendisi."""
        return self.file.split("::", 1)[0]

    @property
    def severity_enum(self) -> Severity:
        return Severity.parse(self.severity)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["source"] = self.source
        return data

    def to_row(self) -> dict:
        """CSV satırı (eski sütunlar önce)."""
        return {
            "file": self.file,
            "line": self.line,
            "type": self.type,
            "content_masked": self.content_masked,
            "sha256": self.sha256,
            "severity": self.severity,
            "validated": self.validated,
            "fingerprint": self.fingerprint,
            "source": self.source,
            "column": self.column,
            "snippet": self.snippet,
            "title": self.title,
        }

    @classmethod
    def from_dict(cls, data: dict) -> Finding:
        known = set(cls.__dataclass_fields__)  # type: ignore[attr-defined]
        extra = {k: v for k, v in data.items() if k not in known and k != "source"}
        payload = {k: v for k, v in data.items() if k in known}
        if extra:
            payload.setdefault("extra", {}).update(extra)
        return cls(**payload)

    def sort_key(self):
        """Önce en kritik, sonra dosya/satır sırası."""
        return (-self.severity_enum.rank, self.file, self.line, self.type)
