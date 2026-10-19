"""SARIF 2.1.0 çıktısı.

Neden bu biçim: GitHub Code Scanning, Azure DevOps ve çoğu SAST panosu
SARIF okur. Sentinel'in bulguları böylece bir pull request'in "Files
changed" görünümünde satır satır yorum olarak çıkar; araç masaüstü
taramasından CI kapısına dönüşür.

GitHub'a yükleme::

    sentinel scan . --format sarif
    # .github/workflows içinde:
    #   uses: github/codeql-action/upload-sarif@v3
    #   with: { sarif_file: sentinel.sarif }
"""

from __future__ import annotations

import json
import os

from sentinel import __version__
from sentinel.patterns import PATTERN_DEFS
from sentinel.severity import Severity

__all__ = ["write", "to_dict"]

SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

#: SARIF yalnızca error/warning/note/none bilir; beş kademeyi eşleriz.
_LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

#: GitHub bulguları bu puana göre sıralar (0-10).
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


def _rules() -> list:
    rules = []
    for definition in PATTERN_DEFS:
        rules.append(
            {
                "id": definition.name,
                "name": definition.name,
                "shortDescription": {"text": definition.title},
                "fullDescription": {"text": definition.description},
                "defaultConfiguration": {"level": _LEVELS[definition.severity]},
                "properties": {
                    "tags": list(definition.tags) or ["sensitive-data"],
                    "security-severity": _SECURITY_SEVERITY[definition.severity],
                },
            }
        )
    # Katalog dışı kurallar (entropi ve YARA) çalışma anında eklenir.
    rules.append(
        {
            "id": "HIGH_ENTROPY_STRING",
            "name": "HIGH_ENTROPY_STRING",
            "shortDescription": {"text": "Yüksek entropili dizge"},
            "fullDescription": {
                "text": "Rastgele üretilmiş görünen, bilinen bir sağlayıcıya "
                "ait olmayan sır adayı."
            },
            "defaultConfiguration": {"level": "warning"},
            "properties": {"tags": ["secret", "entropy"], "security-severity": "5.0"},
        }
    )
    return rules


def _relative(path: str, base: str) -> str:
    """SARIF göreli URI ister; mutlak Windows yolları paneli bozar."""
    container = path.split("::", 1)[0]
    try:
        relative = os.path.relpath(container, base)
    except ValueError:  # farklı sürücü (Windows)
        relative = container
    return relative.replace(os.sep, "/")


def _base_dir(target: str) -> str:
    """Göreli URI'lerin köküne alınacak dizin.

    Hedefi yalnızca *mevcut bir dosya* olduğunda üst dizinine indiririz;
    `isdir` kontrolüne güvenmek, hedef henüz yokken (ya da başka bir
    makinede üretilen rapor için) kökü bir seviye yukarı kaydırıp tüm
    yolları bozuyordu.
    """
    if os.path.isfile(target):
        return os.path.dirname(target) or "."
    return target or "."


def to_dict(result) -> dict:
    base = _base_dir(result.target)

    known = {rule["id"] for rule in _rules()}
    results = []
    extra_rules = {}

    for finding in result.findings:
        severity = finding.severity_enum
        if finding.type not in known and finding.type not in extra_rules:
            extra_rules[finding.type] = {
                "id": finding.type,
                "name": finding.type,
                "shortDescription": {"text": finding.title or finding.type},
                "defaultConfiguration": {"level": _LEVELS[severity]},
                "properties": {"tags": ["sensitive-data"]},
            }

        message = (
            f"{finding.title or finding.type} tespit edildi "
            f"(maskeli: {finding.content_masked})"
        )
        results.append(
            {
                "ruleId": finding.type,
                "level": _LEVELS[severity],
                "message": {"text": message},
                "partialFingerprints": {"sentinelFingerprint/v1": finding.fingerprint},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": _relative(finding.file, base),
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": max(1, finding.line),
                                "startColumn": max(1, finding.column),
                            },
                        }
                    }
                ],
                "properties": {
                    "severity": finding.severity,
                    "validated": finding.validated,
                    "sha256": finding.sha256,
                },
            }
        )

    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Sentinel DLP",
                        "version": __version__,
                        "informationUri": "https://github.com/deniz385/Sentinel",
                        "rules": _rules() + list(extra_rules.values()),
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": not result.cancelled,
                        "startTimeUtc": result.started_at or None,
                    }
                ],
                "results": results,
            }
        ],
    }


def write(result, output_path: str) -> str:
    directory = os.path.dirname(os.path.abspath(output_path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(to_dict(result), handle, indent=2, ensure_ascii=False)
    return output_path
