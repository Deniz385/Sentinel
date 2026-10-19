"""Önem derecesi (severity) ve risk skoru.

Eski sürümde her bulgu eşit ağırlıktaydı; 500 e-posta adresi ile 1 AWS
anahtarı aynı listede yan yana duruyordu. Burada her desene bir kademe
atanır ve rapora sıralanabilir bir risk skoru çıkar.
"""

from __future__ import annotations

from enum import Enum

__all__ = ["Severity", "risk_score", "SEVERITY_ORDER"]


class Severity(str, Enum):
    """Bulgu önem derecesi. Sıralama için :attr:`rank` kullanılır."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        # Sıralama anahtarı olarak satır başına birkaç kez çağrılır;
        # `list.index` (O(n)) yerine sabit zamanlı sözlük araması.
        return _RANKS[self.value]

    @property
    def label_tr(self) -> str:
        return {
            "info": "Bilgi",
            "low": "Düşük",
            "medium": "Orta",
            "high": "Yüksek",
            "critical": "Kritik",
        }[self.value]

    @property
    def icon(self) -> str:
        """Renk tek başına anlam taşımasın diye ikon + etiket birlikte gider."""
        return {
            "info": "·",
            "low": "○",
            "medium": "△",
            "high": "◆",
            "critical": "■",
        }[self.value]

    @classmethod
    def parse(cls, value: str | Severity) -> Severity:
        if isinstance(value, cls):
            return value
        try:
            return cls(str(value).strip().lower())
        except ValueError as exc:
            valid = ", ".join(s.value for s in cls)
            raise ValueError(
                f"Geçersiz önem derecesi: {value!r}. Geçerli değerler: {valid}"
            ) from exc

    def __ge__(self, other):  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank >= other.rank
        return NotImplemented

    def __gt__(self, other):  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank > other.rank
        return NotImplemented

    def __le__(self, other):  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank <= other.rank
        return NotImplemented

    def __lt__(self, other):  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank < other.rank
        return NotImplemented


SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
_RANKS = {value: index for index, value in enumerate(SEVERITY_ORDER)}

# Risk skoru ağırlıkları. Doğrulanmış (algoritmik olarak geçerli) bir bulgu
# ham regex eşleşmesinden daha ağır sayılır.
_WEIGHTS = {
    Severity.INFO: 1,
    Severity.LOW: 3,
    Severity.MEDIUM: 10,
    Severity.HIGH: 30,
    Severity.CRITICAL: 100,
}


def risk_score(findings) -> int:
    """Bulgu listesinden 0-100 arası toplu risk skoru üretir.

    Doğrusal toplam yerine logaritmik doyum kullanılır: tek bir kritik sır,
    yüzlerce düşük önemli e-postadan daha yüksek skor vermelidir.
    """
    import math

    total = 0.0
    for f in findings:
        sev = Severity.parse(getattr(f, "severity", None) or f["severity"])
        weight = _WEIGHTS[sev]
        if getattr(f, "validated", False):
            weight *= 1.5
        total += weight

    if total <= 0:
        return 0
    # 100 puanlık ağırlık ~ 70 skor; doygunluk 100'de.
    score = 100 * (1 - math.exp(-total / 120))
    return int(min(100, round(score)))
