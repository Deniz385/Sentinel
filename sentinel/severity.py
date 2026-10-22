"""Severity levels and the aggregate risk score.

In the previous version every finding carried equal weight: 500 email
addresses and one AWS key sat side by side in the same flat list. Here
each pattern is assigned a level, and the report gains a sortable risk
score.
"""

from __future__ import annotations

from enum import Enum

__all__ = ["Severity", "risk_score", "SEVERITY_ORDER"]


class Severity(str, Enum):
    """Finding severity. Use :attr:`rank` for ordering."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        # Called several times per line as a sort key, so this is a
        # constant-time dict lookup rather than `list.index` (O(n)).
        return _RANKS[self.value]

    @property
    def label(self) -> str:
        return {
            "info": "Info",
            "low": "Low",
            "medium": "Medium",
            "high": "High",
            "critical": "Critical",
        }[self.value]

    @property
    def icon(self) -> str:
        """Icon plus label, so colour never carries meaning on its own."""
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
                f"Invalid severity: {value!r}. Valid values: {valid}"
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

# Risk score weights. A validated finding (one that passed an algorithmic
# check) counts for more than a raw regex match.
_WEIGHTS = {
    Severity.INFO: 1,
    Severity.LOW: 3,
    Severity.MEDIUM: 10,
    Severity.HIGH: 30,
    Severity.CRITICAL: 100,
}


def risk_score(findings) -> int:
    """Produce an aggregate 0-100 risk score from a list of findings.

    Logarithmic saturation rather than a linear sum: a single critical
    secret must outrank hundreds of low-severity email addresses.
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
    # ~100 points of weight maps to a score of ~70; saturates at 100.
    score = 100 * (1 - math.exp(-total / 120))
    return int(min(100, round(score)))
