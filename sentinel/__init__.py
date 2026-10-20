"""Sentinel — Hassas Veri Keşif ve Sızıntı Önleme (DLP) motoru."""

__version__ = "4.0.0"
__all__ = [
    "__version__",
    "Finding",
    "ScanConfig",
    "ScanResult",
    "Scanner",
    "Severity",
    "get_patterns",
]


def __getattr__(name):
    # Ağır alt modülleri (pypdf, openpyxl...) sadece gerçekten istenince yükle.
    if name in ("Scanner", "ScanResult"):
        from sentinel.engine import Scanner, ScanResult

        return {"Scanner": Scanner, "ScanResult": ScanResult}[name]
    if name == "ScanConfig":
        from sentinel.config import ScanConfig

        return ScanConfig
    if name == "Finding":
        from sentinel.findings import Finding

        return Finding
    if name == "Severity":
        from sentinel.severity import Severity

        return Severity
    if name == "get_patterns":
        from sentinel.patterns import get_patterns

        return get_patterns
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
