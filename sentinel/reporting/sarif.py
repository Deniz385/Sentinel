"""SARIF 2.1.0 output.

Why this format: GitHub Code Scanning, Azure DevOps and most SAST
dashboards read SARIF. Sentinel's findings therefore show up as
line-level comments in a pull request's "Files changed" view; the tool
turns from a desktop scan into a CI gate.

Uploading to GitHub::

    sentinel scan . --format sarif
    # inside .github/workflows:
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

#: SARIF knows only error/warning/note/none; map the five levels onto it.
_LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

#: GitHub orders findings by this score (0-10).
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
    # Rules outside the catalogue (entropy and YARA) are added at runtime.
    rules.append(
        {
            "id": "HIGH_ENTROPY_STRING",
            "name": "HIGH_ENTROPY_STRING",
            "shortDescription": {"text": "High-entropy string"},
            "fullDescription": {
                "text": "A secret candidate that looks randomly generated "
                "and belongs to no known provider."
            },
            "defaultConfiguration": {"level": "warning"},
            "properties": {"tags": ["secret", "entropy"], "security-severity": "5.0"},
        }
    )
    return rules


def _relative(path: str, base: str) -> str:
    """SARIF wants relative URIs; absolute Windows paths break the panel."""
    container = path.split("::", 1)[0]
    try:
        relative = os.path.relpath(container, base)
    except ValueError:  # different drive (Windows)
        relative = container
    return relative.replace(os.sep, "/")


def _base_dir(target: str) -> str:
    """The directory relative URIs are rooted at.

    We step up to the parent only when the target is an *existing
    file*; relying on an `isdir` check moved the root up one level when
    the target did not exist yet (or for a report produced on another
    machine), which broke every path.
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
            f"{finding.title or finding.type} detected "
            f"(masked: {finding.content_masked})"
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
