"""Report writers.

Formats: ``html``, ``json``, ``csv``, ``sarif``, ``md``, ``pdf``.

Why SARIF matters: GitHub Code Scanning and most SAST dashboards read
it. Sentinel's output can therefore appear line by line in the CI
"Security" tab - the tool turns from a desktop toy into a CI gate.
"""

from __future__ import annotations

import os

__all__ = ["write_reports", "FORMATS", "report_path"]

FORMATS = ("html", "json", "csv", "sarif", "md", "pdf")

_FILENAMES = {
    "html": "dashboard.html",
    "json": "scan_results.json",
    "csv": "scan_results.csv",
    "sarif": "sentinel.sarif",
    "md": "scan_report.md",
    "pdf": "scan_report.pdf",
}


def report_path(output_dir: str, fmt: str) -> str:
    return os.path.join(output_dir, _FILENAMES[fmt])


def write_reports(result, output_dir: str, formats=("html", "csv")) -> dict:
    """Write the requested formats and return ``{format: path | error}``."""
    from sentinel.reporting import csv_report, html, json_report, markdown, sarif

    os.makedirs(output_dir, exist_ok=True)
    written: dict[str, str] = {}

    writers = {
        "html": html.write,
        "json": json_report.write,
        "csv": csv_report.write,
        "sarif": sarif.write,
        "md": markdown.write,
    }

    for fmt in formats:
        fmt = fmt.strip().lower()
        if fmt not in FORMATS:
            written[fmt] = f"ERROR: unknown format ({fmt})"
            continue
        path = report_path(output_dir, fmt)
        try:
            if fmt == "pdf":
                from sentinel.reporting import pdf_report

                ok, message = pdf_report.write(result, path)
                written[fmt] = path if ok else f"ERROR: {message}"
            else:
                writers[fmt](result, path)
                written[fmt] = path
        except Exception as exc:
            written[fmt] = f"ERROR: {type(exc).__name__}: {exc}"

    return written
