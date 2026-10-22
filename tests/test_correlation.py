"""Cross-file correlation tests.

The claim under test: the finding count does not measure workload.
Forty copies of one key close with a single revocation. These tests
check both that grouping is correct and that it **reveals no
"""

from __future__ import annotations

import json
import os

from sentinel.config import ScanConfig
from sentinel.correlation import group_findings
from sentinel.engine import Scanner
from sentinel.findings import Finding
from sentinel.severity import Severity
from tests.conftest import VALID_TCKN, VALID_VISA


def make(
    file="a.txt",
    line=1,
    type="AWS_ACCESS_KEY",
    fingerprint="abc123",
    severity=Severity.CRITICAL.value,
    masked="AK**********KE",
):
    return Finding(
        file=file,
        line=line,
        type=type,
        content_masked=masked,
        severity=severity,
        fingerprint=fingerprint,
        title="AWS Access Key",
    )


def run(target, **overrides):
    settings = {
        "min_severity": Severity.INFO.value,
        "entropy_scan": False,
        "yara_enabled": False,
        "workers": 1,
        "executor": "serial",
    }
    settings.update(overrides)
    return Scanner(str(target), config=ScanConfig(**settings)).scan()


class TestGrouping:
    def test_same_secret_in_many_files_is_one_group(self):
        findings = [make(file=f"file{i}.txt", line=i + 1) for i in range(5)]
        groups = group_findings(findings)
        assert len(groups) == 1
        assert groups[0].count == 5
        assert groups[0].file_count == 5
        assert groups[0].shared is True

    def test_different_values_stay_separate(self):
        findings = [
            make(fingerprint="aaa", file="a.txt"),
            make(fingerprint="bbb", file="a.txt"),
        ]
        assert len(group_findings(findings)) == 2

    def test_same_value_different_rule_stays_separate(self):
        # Fingerprints are derived from `rule:value`, so in practice they
        # do not collide; the grouping key must still include the rule.
        findings = [
            make(type="AWS_ACCESS_KEY", fingerprint="same"),
            make(type="GITHUB_TOKEN", fingerprint="same"),
        ]
        assert len(group_findings(findings)) == 2

    def test_single_file_group_is_not_shared(self):
        findings = [make(line=1), make(line=2)]
        groups = group_findings(findings)
        assert len(groups) == 1
        assert groups[0].count == 2
        assert groups[0].file_count == 1
        assert groups[0].shared is False

    def test_findings_without_fingerprint_never_merge(self):
        # YARA findings match a whole file, not a single value; merging
        # them would make the claim "the same secret" a lie.
        findings = [
            make(file="a.txt", fingerprint="", type="YARA_WEBSHELL", masked="(rule)"),
            make(file="b.txt", fingerprint="", type="YARA_WEBSHELL", masked="(rule)"),
        ]
        groups = group_findings(findings)
        assert len(groups) == 2
        assert all(group.shared is False for group in groups)

    def test_group_takes_the_worst_severity(self):
        # The same value may be validated (critical) in one file and
        # unvalidated (a level lower) in another; the group shows the worst.
        findings = [
            make(file="a.txt", severity=Severity.MEDIUM.value),
            make(file="b.txt", severity=Severity.CRITICAL.value),
            make(file="c.txt", severity=Severity.LOW.value),
        ]
        groups = group_findings(findings)
        assert groups[0].severity == Severity.CRITICAL.value

    def test_locations_are_capped_and_counted(self):
        findings = [make(file=f"d{i}.txt") for i in range(30)]
        groups = group_findings(findings, max_locations=10)
        assert len(groups[0].locations) == 10
        assert groups[0].truncated == 20
        # The file count must stay exact, untruncated.
        assert groups[0].file_count == 30
        assert groups[0].count == 30

    def test_sorted_by_severity_then_spread(self):
        findings = [
            make(fingerprint="low-wide", severity=Severity.LOW.value, file="a.txt"),
            make(fingerprint="low-wide", severity=Severity.LOW.value, file="b.txt"),
            make(fingerprint="low-wide", severity=Severity.LOW.value, file="c.txt"),
            make(fingerprint="crit-narrow", severity=Severity.CRITICAL.value),
            make(fingerprint="high-two", severity=Severity.HIGH.value, file="a.txt"),
            make(fingerprint="high-two", severity=Severity.HIGH.value, file="b.txt"),
        ]
        order = [group.fingerprint for group in group_findings(findings)]
        assert order == ["crit-narrow", "high-two", "low-wide"]

    def test_empty_input(self):
        assert group_findings([]) == []


class TestResultIntegration:
    def test_copied_secrets_collapse_to_unique_count(self, tree):
        # The same two values copied into five files: 10 findings, 2 secrets.
        files = {
            f"copy{i}.txt": f"ID: {VALID_TCKN}\nCard: {VALID_VISA}\n" for i in range(5)
        }
        result = run(tree(files))

        assert len(result.findings) == 10
        assert result.unique_count == 2
        shared = result.shared_secrets()
        assert len(shared) == 2
        assert all(group.file_count == 5 for group in shared)

    def test_summary_reports_both_numbers(self, tree):
        files = {f"k{i}.txt": f"ID: {VALID_TCKN}\n" for i in range(3)}
        summary = run(tree(files)).summary()
        assert summary["findings"] == 3
        assert summary["unique_secrets"] == 1
        assert summary["shared_secrets"] == 1

    def test_unique_secrets_never_exceeds_findings(self, tree):
        result = run(
            tree({"a.txt": f"ID: {VALID_TCKN}\nCard: {VALID_VISA}\n"}),
        )
        assert result.unique_count <= len(result.findings)

    def test_groups_are_memoised_but_follow_new_findings(self, tree):
        result = run(tree({"a.txt": f"ID: {VALID_TCKN}\n"}))
        first = result.groups()
        assert result.groups() is first  # same object: no regrouping

        result.findings.append(make(file="b.txt"))
        assert len(result.groups()) == len(first) + 1


class TestNoDisclosure:
    """Correlation must not break masking."""

    def test_group_output_carries_no_clear_value(self, tree):
        files = {f"k{i}.txt": f"ID: {VALID_TCKN}\nCard: {VALID_VISA}\n" for i in range(3)}
        result = run(tree(files))

        blob = json.dumps(
            [group.to_dict() for group in result.groups()], ensure_ascii=False
        )
        assert VALID_TCKN not in blob
        assert VALID_VISA not in blob

    def test_json_report_secrets_block_is_masked(self, tree, tmp_path):
        from sentinel.reporting import json_report

        files = {f"k{i}.txt": f"Card: {VALID_VISA}\n" for i in range(4)}
        result = run(tree(files))
        path = tmp_path / "out" / "scan.json"
        json_report.write(result, str(path))

        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["summary"]["unique_secrets"] == 1
        assert len(data["secrets"]) == 1
        assert data["secrets"][0]["file_count"] == 4
        assert VALID_VISA not in path.read_text(encoding="utf-8")


class TestReportWiring:
    def test_markdown_lists_shared_secrets(self, tree, tmp_path):
        from sentinel.reporting import markdown

        files = {f"k{i}.txt": f"ID: {VALID_TCKN}\n" for i in range(4)}
        text = markdown.render(run(tree(files)))

        assert "unique secrets" in text
        assert "Secrets copied into more than one file" in text
        assert VALID_TCKN not in text

    def test_markdown_omits_section_when_nothing_is_shared(self, tree):
        from sentinel.reporting import markdown

        text = markdown.render(run(tree({"a.txt": f"ID: {VALID_TCKN}\n"})))
        assert "Secrets copied into more than one file" not in text

    def test_html_shows_unique_tile_and_spread_table(self, tree):
        from sentinel.reporting import html

        files = {f"k{i}.txt": f"Card: {VALID_VISA}\n" for i in range(3)}
        page = html.render(run(tree(files)))

        assert "Unique Secrets" in page
        assert "Secrets copied into more than one file" in page
        assert VALID_VISA not in page

    def test_html_shortens_paths_against_the_target(self, tree):
        from sentinel.reporting import html

        files = {f"team/k{i}.txt": f"Card: {VALID_VISA}\n" for i in range(3)}
        target = tree(files)
        page = html.render(run(target)).replace("\\", "/")
        # The summary block only: the detail table still shows full paths.
        block = page.split('class="panel spread"', 1)[1].split("</section>", 1)[0]

        # Seven absolute paths side by side in the summary made a wall of
        # noise; a target-relative path stays readable.
        assert "team/k0.txt" in block
        assert str(target).replace("\\", "/") not in block

    def test_relative_keeps_paths_outside_the_target(self):
        from sentinel.reporting.html import _relative

        assert _relative("/data/sub/a.txt", "/data") == "sub/a.txt".replace("/", os.sep)
        # A path outside the target must not be misreported to shorten it.
        assert _relative("/other/a.txt", "/data") == "/other/a.txt"
        assert _relative("/data/a.txt", "") == "/data/a.txt"
