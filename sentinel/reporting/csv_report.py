"""CSV report.

The legacy column order (``file, line, type, content_masked, sha256``)
is preserved and new fields are appended, so existing Excel templates
and scripts keep working. No `pandas` needed - the stdlib `csv` module
is enough and starts far faster.
"""

from __future__ import annotations

import csv
import os

from sentinel.findings import CSV_COLUMNS

__all__ = ["write"]


def write(result, output_path: str) -> str:
    directory = os.path.dirname(os.path.abspath(output_path))
    if directory:
        os.makedirs(directory, exist_ok=True)

    # Without newline="" Windows inserts a blank line between rows.
    # utf-8-sig adds the BOM Excel needs to show non-ASCII correctly.
    with open(output_path, "w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for finding in result.findings:
            writer.writerow(finding.to_row())
    return output_path
