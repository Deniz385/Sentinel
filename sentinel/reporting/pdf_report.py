"""PDF report (reportlab).

Two defects from v3.0 are fixed:

1. Content was handed to ``Paragraph`` unescaped; a filename containing
   ``<`` or ``&`` blew up PDF generation. Every string now goes through
   XML escaping.
2. The font was ``Helvetica`` and non-ASCII characters came out broken.
   A Unicode TTF is now registered when one is found on the system.
"""

from __future__ import annotations

import os
from datetime import datetime
from xml.sax.saxutils import escape

from sentinel.severity import Severity

__all__ = ["write"]

#: Widely available fonts that render non-ASCII characters correctly.
_FONT_CANDIDATES = (
    ("DejaVuSans", "DejaVuSans.ttf", "DejaVuSans-Bold.ttf"),
    ("LiberationSans", "LiberationSans-Regular.ttf", "LiberationSans-Bold.ttf"),
    ("Arial", "arial.ttf", "arialbd.ttf"),
)

_FONT_DIRS = (
    "/usr/share/fonts/truetype/dejavu",
    "/usr/share/fonts/truetype/liberation",
    "/usr/share/fonts/TTF",
    "/usr/share/fonts",
    "/Library/Fonts",
    "/System/Library/Fonts/Supplemental",
    r"C:\Windows\Fonts",
)

MAX_ROWS = 400


def _find_font(filename: str) -> str | None:
    for directory in _FONT_DIRS:
        candidate = os.path.join(directory, filename)
        if os.path.isfile(candidate):
            return candidate
    return None


def _register_font() -> tuple[str, str]:
    """Register a Unicode-capable font, falling back to Helvetica."""
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    for name, regular_file, bold_file in _FONT_CANDIDATES:
        regular = _find_font(regular_file)
        if not regular:
            continue
        bold = _find_font(bold_file) or regular
        try:
            pdfmetrics.registerFont(TTFont(name, regular))
            pdfmetrics.registerFont(TTFont(f"{name}-Bold", bold))
            return name, f"{name}-Bold"
        except Exception:
            continue
    return "Helvetica", "Helvetica-Bold"


def write(result, output_path: str) -> tuple[bool, str]:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError:
        return False, "The PDF report requires reportlab: pip install reportlab"

    directory = os.path.dirname(os.path.abspath(output_path))
    if directory:
        os.makedirs(directory, exist_ok=True)

    font, font_bold = _register_font()
    styles = getSampleStyleSheet()
    body = ParagraphStyle(
        "SentinelBody",
        parent=styles["BodyText"],
        fontName=font,
        fontSize=7.5,
        leading=9.5,
    )
    title_style = ParagraphStyle(
        "SentinelTitle", parent=styles["Title"], fontName=font_bold, fontSize=18
    )
    normal = ParagraphStyle(
        "SentinelNormal", parent=styles["Normal"], fontName=font, fontSize=9.5
    )

    def cell(value) -> Paragraph:
        # escape(): keep `<` and `&` from breaking reportlab's mini markup.
        return Paragraph(escape(str(value)), body)

    document = SimpleDocTemplate(
        output_path,
        pagesize=landscape(A4),
        leftMargin=12 * mm,
        rightMargin=12 * mm,
        topMargin=12 * mm,
        bottomMargin=12 * mm,
        title="Sentinel DLP Report",
    )

    counts = result.counts_by_severity()
    elements = [
        Paragraph("SENTINEL - Sensitive Data Scan Report", title_style),
        Spacer(1, 8),
        Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>"
            f"Target: {escape(result.target)}<br/>"
            f"Risk score: <b>{result.risk_score}/100</b> &nbsp;·&nbsp; "
            f"Findings: <b>{len(result.findings)}</b> "
            f"({result.unique_count} unique secrets) &nbsp;·&nbsp; "
            f"Files scanned: {result.files_scanned} &nbsp;·&nbsp; "
            f"Duration: {result.duration:.2f} s",
            normal,
        ),
        Spacer(1, 10),
    ]

    severity_data = [["Severity", "Count"]]
    for severity in sorted(Severity, key=lambda s: -s.rank):
        count = counts.get(severity.value, 0)
        if count:
            severity_data.append([severity.label, str(count)])

    if len(severity_data) > 1:
        summary_table = Table(severity_data, colWidths=[60 * mm, 25 * mm])
        summary_table.setStyle(
            TableStyle(
                [
                    ("FONTNAME", (0, 0), (-1, 0), font_bold),
                    ("FONTNAME", (0, 1), (-1, -1), font),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2d3d")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("ALIGN", (1, 0), (1, -1), "RIGHT"),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9c9c4")),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        elements.extend([summary_table, Spacer(1, 14)])

    if not result.findings:
        elements.append(
            Paragraph("No sensitive data at or above the threshold.", normal)
        )
        document.build(elements)
        return True, output_path

    elements.append(Paragraph("Findings (masked)", normal))
    elements.append(Spacer(1, 6))

    data = [["Severity", "Type", "Location", "Line", "Content (masked)"]]
    for finding in result.findings[:MAX_ROWS]:
        data.append(
            [
                cell(finding.severity_enum.label),
                cell(finding.type),
                cell(finding.file),
                cell(finding.line or "-"),
                cell(finding.content_masked),
            ]
        )

    table = Table(
        data,
        colWidths=[20 * mm, 42 * mm, 95 * mm, 14 * mm, 60 * mm],
        repeatRows=1,
    )
    table.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (-1, 0), font_bold),
                ("FONTSIZE", (0, 0), (-1, 0), 8.5),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2d3d")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#c9c9c4")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f2")]),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    elements.append(table)

    remaining = len(result.findings) - MAX_ROWS
    if remaining > 0:
        elements.append(PageBreak())
        elements.append(
            Paragraph(
                f"The first {MAX_ROWS} findings are in this report; {remaining} more exist. "
                "Use the CSV or JSON report for the full list.",
                normal,
            )
        )

    try:
        document.build(elements)
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"
    return True, output_path


def create_pdf_report(results, filename: str):
    """Legacy API compatibility: accepts a list of dicts."""
    from sentinel.engine import ScanResult
    from sentinel.findings import Finding

    if hasattr(results, "findings"):
        return write(results, filename)

    findings = [
        item if isinstance(item, Finding) else Finding.from_dict(item)
        for item in (results or [])
    ]
    return write(ScanResult(findings=findings), filename)
