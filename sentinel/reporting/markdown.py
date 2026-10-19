"""Markdown özeti — pull request yorumu ve CI iş özeti için.

``GITHUB_STEP_SUMMARY``'ye yazıldığında tarama sonucu doğrudan Actions
çalıştırma sayfasında görünür.
"""

from __future__ import annotations

import os

from sentinel.severity import Severity

__all__ = ["write", "render"]

MAX_ROWS = 100


def _escape(value: str) -> str:
    """Tablo hücresini bozabilecek karakterleri etkisizleştirir."""
    return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", "")


def render(result) -> str:
    counts = result.counts_by_severity()
    lines = [
        "# Sentinel DLP Tarama Raporu",
        "",
        f"- **Hedef:** `{_escape(result.target)}`",
        f"- **Risk skoru:** {result.risk_score}/100",
        f"- **Bulgu:** {len(result.findings)}",
        f"- **Taranan dosya:** {result.files_scanned} "
        f"(atlanan: {result.files_skipped})",
        f"- **Süre:** {result.duration:.2f} sn",
        "",
    ]

    if not result.findings:
        lines.append("✅ **Eşik üstü hassas veri bulunamadı.**")
        return "\n".join(lines) + "\n"

    lines.append("## Önem derecesi dağılımı")
    lines.append("")
    lines.append("| Önem | Adet |")
    lines.append("| --- | ---: |")
    for severity in sorted(Severity, key=lambda s: -s.rank):
        count = counts.get(severity.value, 0)
        if count:
            lines.append(f"| {severity.icon} {severity.label_tr} | {count} |")
    lines.append("")

    lines.append("## Bulgular")
    lines.append("")
    lines.append("| Önem | Tür | Konum | Satır | İçerik (maskeli) |")
    lines.append("| --- | --- | --- | ---: | --- |")
    for finding in result.findings[:MAX_ROWS]:
        lines.append(
            f"| {finding.severity_enum.label_tr} | `{_escape(finding.type)}` "
            f"| `{_escape(finding.file)}` | {finding.line} "
            f"| `{_escape(finding.content_masked)}` |"
        )

    remaining = len(result.findings) - MAX_ROWS
    if remaining > 0:
        lines.append("")
        lines.append(f"_… ve {remaining} bulgu daha (tam liste: JSON/CSV raporu)._")

    lines.append("")
    lines.append("> Tüm hassas değerler maskelenmiştir.")
    return "\n".join(lines) + "\n"


def write(result, output_path: str) -> str:
    directory = os.path.dirname(os.path.abspath(output_path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(render(result))
    return output_path
