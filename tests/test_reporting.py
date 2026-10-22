"""Report writer tests.

The most important class here is :class:`TestHtmlEscaping`. The v3.0
`reporter.py` wrote file paths and finding content into HTML unescaped;
a filename containing ``<script>`` turned into an XSS aimed at the
security analyst opening the report.
"""

from __future__ import annotations

import csv
import json

import pytest

from sentinel.engine import ScanResult
from sentinel.findings import CSV_COLUMNS, LEGACY_COLUMNS, Finding
from sentinel.reporting import FORMATS, write_reports
from sentinel.severity import Severity


def make_result(findings=None, **kwargs) -> ScanResult:
    defaults = {
        "files_scanned": 3,
        "bytes_scanned": 1024,
        "duration": 0.42,
        "target": "/proje",
        "started_at": "2026-01-01T00:00:00+00:00",
    }
    defaults.update(kwargs)
    return ScanResult(findings=findings or [], **defaults)


def finding(**kwargs) -> Finding:
    data = {
        "file": "src/app.py",
        "line": 12,
        "type": "TR_NATIONAL_ID",
        "title": "Turkish National Identity Number",
        "content_masked": "10*******46",
        "severity": Severity.HIGH.value,
        "sha256": "a" * 64,
        "fingerprint": "deadbeef12345678",
        "snippet": "Customer ID: 10*******46 confirmed",
        "validated": True,
        "column": 13,
    }
    data.update(kwargs)
    return Finding(**data)


# ---------------------------------------------------------------------------
class TestHtmlEscaping:
    """The injection class must be closed structurally."""

    def test_script_in_filename_is_escaped(self):
        from sentinel.reporting.html import render

        html = render(make_result([finding(file="<script>alert(1)</script>.txt")]))
        assert "<script>alert(1)</script>.txt" not in html
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html

    def test_script_in_content_is_escaped(self):
        from sentinel.reporting.html import render

        html = render(
            make_result([finding(content_masked="<img src=x onerror=alert(1)>")])
        )
        assert "<img src=x onerror=alert(1)>" not in html
        assert "onerror=alert(1)" in html  # present, but escaped

    def test_attribute_breakout_is_escaped(self):
        """A value written into a data-* attribute must not escape the quotes."""
        from sentinel.reporting.html import render

        html = render(make_result([finding(type='X" onmouseover="alert(1)')]))
        assert 'onmouseover="alert(1)"' not in html

    def test_snippet_is_escaped(self):
        from sentinel.reporting.html import render

        html = render(make_result([finding(snippet="</td></tr><script>x</script>")]))
        assert "<script>x</script>" not in html

    def test_error_paths_are_escaped(self):
        from sentinel.reporting.html import render

        result = make_result(
            errors=[{"file": "<b>evil</b>.txt", "error": "<i>boom</i>"}]
        )
        html = render(result)
        assert "<b>evil</b>.txt" not in html
        assert "&lt;b&gt;evil&lt;/b&gt;" in html


class TestHtmlContent:
    def test_is_self_contained(self):
        """Must look the same during offline incident response: no external resources."""
        from sentinel.reporting.html import render

        html = render(make_result([finding()]))
        assert "http://" not in html
        assert "https://" not in html
        assert "<style>" in html

    def test_has_both_theme_scopes(self):
        from sentinel.reporting.html import render

        html = render(make_result([finding()]))
        assert "prefers-color-scheme: dark" in html
        assert '[data-theme="dark"]' in html

    def test_shows_summary_numbers(self):
        from sentinel.reporting.html import render

        result = make_result(
            [finding(severity="critical"), finding(line=20, severity="low")]
        )
        html = render(result)
        assert str(result.risk_score) in html
        assert "Risk Score" in html

    def test_empty_result_says_clean(self):
        from sentinel.reporting.html import render

        html = render(make_result([]))
        assert "No leaks detected" in html

    def test_cancelled_scan_is_flagged(self):
        from sentinel.reporting.html import render

        html = render(make_result([finding()], cancelled=True))
        assert "stopped before it finished" in html

    def test_table_is_truncated_with_notice(self):
        from sentinel.reporting import html as html_module

        many = [finding(line=index) for index in range(html_module.MAX_TABLE_ROWS + 50)]
        rendered = html_module.render(make_result(many))
        assert "more exist" in rendered

    def test_type_chart_folds_tail_into_other(self):
        """No new colour is invented for a ninth category; it folds into 'Other'."""
        from sentinel.reporting import html as html_module

        findings = [
            finding(type=f"TYPE_{index}", line=index) for index in range(12)
        ]
        rows = html_module._type_rows(make_result(findings))
        assert len(rows) == html_module.MAX_TYPE_BARS + 1
        assert rows[-1]["label"] == "Other"

    def test_severity_rows_skip_empty_levels(self):
        from sentinel.reporting import html as html_module

        rows = html_module._severity_rows(make_result([finding(severity="high")]))
        assert [row["key"] for row in rows] == ["high"]

    def test_writes_file(self, tmp_path):
        from sentinel.reporting.html import write

        path = tmp_path / "report" / "dashboard.html"
        write(make_result([finding()]), str(path))
        assert path.is_file()
        assert path.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")

    def test_legacy_api_accepts_dicts(self, tmp_path):
        """v3.0: generate_html_report(results_list, path)."""
        from sentinel.reporting.html import generate_html_report

        path = tmp_path / "dashboard.html"
        generate_html_report(
            [
                {
                    "file": "a.txt",
                    "line": 1,
                    "type": "EMAIL",
                    "content_masked": "a**@b.com",
                    "sha256": "x",
                }
            ],
            str(path),
        )
        assert "EMAIL" in path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
class TestCsv:
    def test_legacy_columns_come_first(self, tmp_path):
        from sentinel.reporting.csv_report import write

        path = tmp_path / "out.csv"
        write(make_result([finding()]), str(path))

        with open(path, encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.reader(handle))
        assert rows[0][: len(LEGACY_COLUMNS)] == LEGACY_COLUMNS
        assert rows[0] == CSV_COLUMNS

    def test_values_are_masked(self, tmp_path):
        from sentinel.reporting.csv_report import write

        path = tmp_path / "out.csv"
        write(make_result([finding()]), str(path))
        text = path.read_text(encoding="utf-8-sig")
        assert "10*******46" in text
        assert "10000000146" not in text

    def test_handles_commas_and_quotes(self, tmp_path):
        from sentinel.reporting.csv_report import write

        path = tmp_path / "out.csv"
        write(make_result([finding(file='a,b"c.txt')]), str(path))

        with open(path, encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.DictReader(handle))
        assert rows[0]["file"] == 'a,b"c.txt'

    def test_empty_result_writes_header_only(self, tmp_path):
        from sentinel.reporting.csv_report import write

        path = tmp_path / "out.csv"
        write(make_result([]), str(path))
        with open(path, encoding="utf-8-sig", newline="") as handle:
            assert len(list(csv.reader(handle))) == 1


class TestJson:
    def test_structure(self, tmp_path):
        from sentinel.reporting.json_report import write

        path = tmp_path / "out.json"
        write(make_result([finding()]), str(path))
        data = json.loads(path.read_text(encoding="utf-8"))

        assert data["schema"] == "sentinel-scan/1"
        assert data["tool"]["name"] == "Sentinel DLP"
        assert data["summary"]["findings"] == 1
        assert data["findings"][0]["type"] == "TR_NATIONAL_ID"
        assert data["findings"][0]["source"] == "src/app.py"

    def test_turkish_characters_survive(self, tmp_path):
        from sentinel.reporting.json_report import write

        path = tmp_path / "out.json"
        write(make_result([finding(file="données/mots-de-passe.txt")]), str(path))
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["findings"][0]["file"] == "données/mots-de-passe.txt"


class TestSarif:
    def test_schema_basics(self, tmp_path):
        from sentinel.reporting.sarif import write

        path = tmp_path / "out.sarif"
        write(make_result([finding()]), str(path))
        data = json.loads(path.read_text(encoding="utf-8"))

        assert data["version"] == "2.1.0"
        assert "$schema" in data
        run = data["runs"][0]
        assert run["tool"]["driver"]["name"] == "Sentinel DLP"
        assert run["tool"]["driver"]["rules"]

    def test_result_location(self, tmp_path):
        from sentinel.reporting.sarif import write

        path = tmp_path / "out.sarif"
        write(make_result([finding()], target="/proje"), str(path))
        entry = json.loads(path.read_text(encoding="utf-8"))["runs"][0]["results"][0]

        assert entry["ruleId"] == "TR_NATIONAL_ID"
        assert entry["level"] == "error"
        region = entry["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] == 12
        assert region["startColumn"] == 13

    def test_uri_is_relative(self, tmp_path):
        """Absolute Windows paths break the GitHub panel."""
        from sentinel.reporting.sarif import write

        path = tmp_path / "out.sarif"
        write(
            make_result([finding(file="/proje/src/app.py")], target="/proje"),
            str(path),
        )
        entry = json.loads(path.read_text(encoding="utf-8"))["runs"][0]["results"][0]
        uri = entry["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "src/app.py"

    def test_archive_member_uri_points_to_the_container(self, tmp_path):
        from sentinel.reporting.sarif import write

        path = tmp_path / "out.sarif"
        write(
            make_result(
                [finding(file="/project/a.zip::inner/secret.txt")], target="/project"
            ),
            str(path),
        )
        entry = json.loads(path.read_text(encoding="utf-8"))["runs"][0]["results"][0]
        uri = entry["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "a.zip"

    def test_severity_mapping(self, tmp_path):
        from sentinel.reporting.sarif import write

        path = tmp_path / "out.sarif"
        write(
            make_result(
                [
                    finding(severity="critical"),
                    finding(line=2, severity="medium"),
                    finding(line=3, severity="info"),
                ]
            ),
            str(path),
        )
        levels = [
            entry["level"]
            for entry in json.loads(path.read_text(encoding="utf-8"))["runs"][0][
                "results"
            ]
        ]
        assert levels == ["error", "warning", "note"]

    def test_unknown_rule_gets_a_definition(self, tmp_path):
        """YARA rules are added at runtime; the SARIF must stay valid."""
        from sentinel.reporting.sarif import write

        path = tmp_path / "out.sarif"
        write(make_result([finding(type="YARA_Suspicious_Keywords")]), str(path))
        driver = json.loads(path.read_text(encoding="utf-8"))["runs"][0]["tool"]["driver"]
        assert any(
            rule["id"] == "YARA_Suspicious_Keywords" for rule in driver["rules"]
        )


class TestMarkdown:
    def test_summary_and_table(self):
        from sentinel.reporting.markdown import render

        text = render(make_result([finding()]))
        assert text.startswith("# Sentinel DLP Scan Report")
        assert "| Severity | Type | Location | Line | Content (masked) |" in text
        assert "TR_NATIONAL_ID" in text

    def test_pipes_are_escaped(self):
        from sentinel.reporting.markdown import render

        text = render(make_result([finding(file="a|b.txt")]))
        assert "a\\|b.txt" in text

    def test_clean_result(self):
        from sentinel.reporting.markdown import render

        assert "No sensitive data" in render(make_result([]))


class TestPdf:
    def test_writes_a_pdf(self, tmp_path):
        pytest.importorskip("reportlab")
        from sentinel.reporting.pdf_report import write

        path = tmp_path / "out.pdf"
        ok, message = write(make_result([finding()]), str(path))
        assert ok, message
        assert path.read_bytes().startswith(b"%PDF")

    def test_markup_characters_do_not_break_it(self, tmp_path):
        """v3.0: data containing `<` broke reportlab's markup and blew up the PDF."""
        pytest.importorskip("reportlab")
        from sentinel.reporting.pdf_report import write

        path = tmp_path / "out.pdf"
        ok, message = write(
            make_result(
                [finding(file="<b>a</b>&c.txt", content_masked="<i>x</i> & <br/>")]
            ),
            str(path),
        )
        assert ok, message

    def test_empty_result(self, tmp_path):
        pytest.importorskip("reportlab")
        from sentinel.reporting.pdf_report import write

        path = tmp_path / "out.pdf"
        ok, _ = write(make_result([]), str(path))
        assert ok


class TestWriteReports:
    def test_writes_every_format(self, tmp_path):
        written = write_reports(make_result([finding()]), str(tmp_path), FORMATS)
        for fmt, path in written.items():
            assert not str(path).startswith("HATA"), f"{fmt}: {path}"
            assert tmp_path.joinpath(str(path)).exists() or str(path).startswith(
                str(tmp_path)
            )

    def test_unknown_format_is_reported_not_raised(self, tmp_path):
        written = write_reports(make_result([]), str(tmp_path), ["html", "bogusfmt"])
        assert written["bogusfmt"].startswith("ERROR")
        assert not written["html"].startswith("ERROR")

    def test_creates_output_directory(self, tmp_path):
        target = tmp_path / "new" / "directory"
        write_reports(make_result([]), str(target), ["csv"])
        assert target.is_dir()
