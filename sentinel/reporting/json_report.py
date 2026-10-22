"""JSON report, for machine consumption.

Summary and findings in one document; used to feed a SIEM, to produce a
baseline, or to diff two scans as a regression check.
"""

from __future__ import annotations

import json
import os

from sentinel import __version__

__all__ = ["write", "to_dict"]


def to_dict(result) -> dict:
    return {
        "schema": "sentinel-scan/1",
        "tool": {"name": "Sentinel DLP", "version": __version__},
        "summary": result.summary(),
        "quarantined": list(result.quarantined),
        "errors": result.errors,
        "findings": [finding.to_dict() for finding in result.findings],
        # Unique secrets: every copy of one value in a single record. In
        # a SIEM this reads as "1 key, 40 locations" rather than "40 alerts".
        "secrets": [group.to_dict() for group in result.groups()],
    }


def write(result, output_path: str) -> str:
    directory = os.path.dirname(os.path.abspath(output_path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(to_dict(result), handle, indent=2, ensure_ascii=False)
    return output_path
