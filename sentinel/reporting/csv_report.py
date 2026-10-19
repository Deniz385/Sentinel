"""CSV raporu.

Eski sütun düzeni (``file, line, type, content_masked, sha256``) korunur ve
yeni alanlar sonuna eklenir; mevcut Excel şablonları ve betikler kırılmaz.
`pandas` gerektirmez — stdlib `csv` yeterli ve çok daha hızlı başlar.
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

    # newline="" olmadan Windows'ta her satır arasına boş satır girer.
    # utf-8-sig: Excel'in Türkçe karakterleri doğru göstermesi için BOM.
    with open(output_path, "w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for finding in result.findings:
            writer.writerow(finding.to_row())
    return output_path
