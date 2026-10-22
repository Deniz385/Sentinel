"""Markdown summary, for pull-request comments and CI job summaries.

Written to ``GITHUB_STEP_SUMMARY``, the scan result appears directly on
the Actions run page.
"""

from __future__ import annotations

import os

from sentinel.severity import Severity

__all__ = ["write", "render"]

MAX_ROWS = 100
MAX_GROUPS = 20


def _escape(value: str) -> str:
    """Neutralise characters that would break a table cell."""
    return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", "")


def render(result) -> str:
    counts = result.counts_by_severity()
    lines = [
        "# Sentinel DLP Scan Report",
        "",
        f"- **Target:** `{_escape(result.target)}`",
        f"- **Risk score:** {result.risk_score}/100",
        f"- **Findings:** {len(result.findings)} "
        f"(**{result.unique_count}** unique secrets)",
        f"- **Files scanned:** {result.files_scanned} "
        f"(skipped: {result.files_skipped})",
        f"- **Duration:** {result.duration:.2f} s",
        "",
    ]
    if result.files_cached:
        lines.insert(
            -1,
            f"- **Files served from cache:** {result.files_cached} "
            "(content unchanged)",
        )

    if not result.findings:
        lines.append("✅ **No sensitive data at or above the threshold.**")
        return "\n".join(lines) + "\n"

    lines.append("## Severity distribution")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("| --- | ---: |")
    for severity in sorted(Severity, key=lambda s: -s.rank):
        count = counts.get(severity.value, 0)
        if count:
            lines.append(f"| {severity.icon} {severity.label} | {count} |")
    lines.append("")

    shared = result.shared_secrets()
    if shared:
        # These come first: N copies of one value close with a single
        # action (revoke the key, remove the data).
        lines.append("## Secrets copied into more than one file")
        lines.append("")
        lines.append("| Severity | Type | Files | Findings | Content (masked) |")
        lines.append("| --- | --- | ---: | ---: | --- |")
        for group in shared[:MAX_GROUPS]:
            lines.append(
                f"| {group.severity_enum.label} | `{_escape(group.type)}` "
                f"| {group.file_count} | {group.count} "
                f"| `{_escape(group.content_masked)}` |"
            )
        if len(shared) > MAX_GROUPS:
            lines.append("")
            lines.append(f"_… and {len(shared) - MAX_GROUPS} more secrets._")
        lines.append("")

    lines.append("## Findings")
    lines.append("")
    lines.append("| Severity | Type | Location | Line | Content (masked) |")
    lines.append("| --- | --- | --- | ---: | --- |")
    for finding in result.findings[:MAX_ROWS]:
        lines.append(
            f"| {finding.severity_enum.label} | `{_escape(finding.type)}` "
            f"| `{_escape(finding.file)}` | {finding.line} "
            f"| `{_escape(finding.content_masked)}` |"
        )

    remaining = len(result.findings) - MAX_ROWS
    if remaining > 0:
        lines.append("")
        lines.append(f"_… and {remaining} more findings (full list: JSON/CSV report)._")

    lines.append("")
    lines.append("> All sensitive values are masked.")
    return "\n".join(lines) + "\n"


def write(result, output_path: str) -> str:
    directory = os.path.dirname(os.path.abspath(output_path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(render(result))
    return output_path
