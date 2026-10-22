"""Sentinel - sensitive data discovery and loss prevention (DLP) engine."""

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
    # Load heavy submodules (pypdf, openpyxl, ...) only when actually asked for.
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
