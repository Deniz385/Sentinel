"""JSON raporu — makine tüketimi için.

Özet + bulgular tek belgede; SIEM'e aktarmak, baz çizgisi üretmek ya da
iki taramayı karşılaştırmak (regresyon kontrolü) için kullanılır.
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
    }


def write(result, output_path: str) -> str:
    directory = os.path.dirname(os.path.abspath(output_path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(to_dict(result), handle, indent=2, ensure_ascii=False)
    return output_path
