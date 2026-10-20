"""Çapraz dosya korelasyonu testleri.

Buradaki asıl iddia şu: bulgu sayısı iş yükünü ölçmez. Aynı anahtarın 40
kopyası tek bir iptalle kapanır. Testler hem gruplamanın doğruluğunu hem
de gruplamanın **hassas veriyi açığa çıkarmadığını** sınar.
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
        title="AWS Erişim Anahtarı",
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
        findings = [make(file=f"dosya{i}.txt", line=i + 1) for i in range(5)]
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
        # Parmak izi `kural:değer` üzerinden üretildiği için pratikte
        # çakışmaz; yine de gruplama anahtarı kuralı içermeli.
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
        # YARA bulguları tek bir değere değil dosyanın tamamına uyar;
        # birleştirilirlerse "aynı sır" iddiası yalan olur.
        findings = [
            make(file="a.txt", fingerprint="", type="YARA_WEBSHELL", masked="(kural)"),
            make(file="b.txt", fingerprint="", type="YARA_WEBSHELL", masked="(kural)"),
        ]
        groups = group_findings(findings)
        assert len(groups) == 2
        assert all(group.shared is False for group in groups)

    def test_group_takes_the_worst_severity(self):
        # Aynı değer bir dosyada doğrulanmış (kritik), ötekinde
        # doğrulanamamış (bir kademe düşük) olabilir; grup en kötüyü anlatmalı.
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
        # Dosya sayısı kırpılmadan doğru kalmalı.
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
        # Aynı iki değer beş dosyaya kopyalanmış: 10 bulgu, 2 tekil sır.
        files = {
            f"kopya{i}.txt": f"TC: {VALID_TCKN}\nKart: {VALID_VISA}\n" for i in range(5)
        }
        result = run(tree(files))

        assert len(result.findings) == 10
        assert result.unique_count == 2
        shared = result.shared_secrets()
        assert len(shared) == 2
        assert all(group.file_count == 5 for group in shared)

    def test_summary_reports_both_numbers(self, tree):
        files = {f"k{i}.txt": f"TC: {VALID_TCKN}\n" for i in range(3)}
        summary = run(tree(files)).summary()
        assert summary["findings"] == 3
        assert summary["unique_secrets"] == 1
        assert summary["shared_secrets"] == 1

    def test_unique_secrets_never_exceeds_findings(self, tree):
        result = run(
            tree({"a.txt": f"TC: {VALID_TCKN}\nKart: {VALID_VISA}\n"}),
        )
        assert result.unique_count <= len(result.findings)

    def test_groups_are_memoised_but_follow_new_findings(self, tree):
        result = run(tree({"a.txt": f"TC: {VALID_TCKN}\n"}))
        first = result.groups()
        assert result.groups() is first  # aynı nesne: yeniden gruplanmadı

        result.findings.append(make(file="b.txt"))
        assert len(result.groups()) == len(first) + 1


class TestNoDisclosure:
    """Korelasyon, maskelemeyi bozmamalı."""

    def test_group_output_carries_no_clear_value(self, tree):
        files = {f"k{i}.txt": f"TC: {VALID_TCKN}\nKart: {VALID_VISA}\n" for i in range(3)}
        result = run(tree(files))

        blob = json.dumps(
            [group.to_dict() for group in result.groups()], ensure_ascii=False
        )
        assert VALID_TCKN not in blob
        assert VALID_VISA not in blob

    def test_json_report_secrets_block_is_masked(self, tree, tmp_path):
        from sentinel.reporting import json_report

        files = {f"k{i}.txt": f"Kart: {VALID_VISA}\n" for i in range(4)}
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

        files = {f"k{i}.txt": f"TC: {VALID_TCKN}\n" for i in range(4)}
        text = markdown.render(run(tree(files)))

        assert "tekil sır" in text
        assert "Birden fazla dosyaya kopyalanmış sırlar" in text
        assert VALID_TCKN not in text

    def test_markdown_omits_section_when_nothing_is_shared(self, tree):
        from sentinel.reporting import markdown

        text = markdown.render(run(tree({"a.txt": f"TC: {VALID_TCKN}\n"})))
        assert "Birden fazla dosyaya kopyalanmış" not in text

    def test_html_shows_unique_tile_and_spread_table(self, tree):
        from sentinel.reporting import html

        files = {f"k{i}.txt": f"Kart: {VALID_VISA}\n" for i in range(3)}
        page = html.render(run(tree(files)))

        assert "Tekil Sır" in page
        assert "Birden fazla dosyaya kopyalanmış sırlar" in page
        assert VALID_VISA not in page

    def test_html_shortens_paths_against_the_target(self, tree):
        from sentinel.reporting import html

        files = {f"ekip/k{i}.txt": f"Kart: {VALID_VISA}\n" for i in range(3)}
        target = tree(files)
        page = html.render(run(target)).replace("\\", "/")
        # Yalnızca özet bloğu: ayrıntı tablosu tam yolu göstermeye devam eder.
        block = page.split('class="panel spread"', 1)[1].split("</section>", 1)[0]

        # Özet bloğunda yedi mutlak yolu yan yana basmak gürültü duvarı
        # üretiyordu; hedefe göreli yol okunur kalır.
        assert "ekip/k0.txt" in block
        assert str(target).replace("\\", "/") not in block

    def test_relative_keeps_paths_outside_the_target(self):
        from sentinel.reporting.html import _relative

        assert _relative("/veri/alt/a.txt", "/veri") == "alt/a.txt".replace("/", os.sep)
        # Hedefin dışındaki yol kısaltma uğruna yanlış gösterilmemeli.
        assert _relative("/baska/a.txt", "/veri") == "/baska/a.txt"
        assert _relative("/veri/a.txt", "") == "/veri/a.txt"
