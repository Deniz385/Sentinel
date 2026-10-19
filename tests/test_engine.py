"""Tarama motoru testleri (uçtan uca).

Özellikle v3.0'ın üç yanlış vaadi burada sınanır: paralellik, hash'in
dosya başına **bir kez** hesaplanması ve iptal edilebilirlik.
"""

from __future__ import annotations

import os
import zipfile

import pytest

from sentinel.config import ScanConfig
from sentinel.engine import Scanner, calculate_file_hash, scan_single_file
from sentinel.severity import Severity
from tests.conftest import INVALID_TCKN, VALID_TCKN, VALID_VISA


@pytest.fixture
def sample_tree(tree):
    return tree(
        {
            "musteriler.txt": f"TC: {VALID_TCKN}\nHatali: {INVALID_TCKN}\n",
            "odeme.csv": f"kart,tutar\n{VALID_VISA},100\n",
            "temiz.txt": "Burada hassas veri yok.\n",
            "alt/klasor/notlar.txt": "mail: deniz@adu.edu.tr\n",
            "resim.bin": b"\x00\x01binary",
            "bos.txt": "",
        }
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


class TestScanResults:
    def test_finds_expected_types(self, sample_tree):
        result = run(sample_tree)
        types = {finding.type for finding in result.findings}
        assert "TC_KIMLIK" in types
        assert "KREDI_KARTI" in types
        assert "EMAIL" in types

    def test_invalid_values_are_not_reported(self, sample_tree):
        result = run(sample_tree)
        assert all(INVALID_TCKN not in f.content_masked for f in result.findings)
        tckn_findings = [f for f in result.findings if f.type == "TC_KIMLIK"]
        assert len(tckn_findings) == 1  # geçersiz olan elendi

    def test_counts_and_summary(self, sample_tree):
        result = run(sample_tree)
        assert result.files_scanned >= 4
        assert result.bytes_scanned > 0
        assert result.duration >= 0
        summary = result.summary()
        assert summary["findings"] == len(result.findings)
        assert 0 < summary["risk_score"] <= 100

    def test_results_sorted_by_severity(self, sample_tree):
        result = run(sample_tree)
        ranks = [f.severity_enum.rank for f in result.findings]
        assert ranks == sorted(ranks, reverse=True)

    def test_empty_and_binary_files_are_skipped(self, sample_tree):
        result = run(sample_tree)
        assert result.files_skipped >= 1  # bos.txt

    def test_clean_tree_reports_nothing(self, tree):
        result = run(tree({"a.txt": "tamamen temiz icerik\n"}))
        assert result.findings == []
        assert result.risk_score == 0

    def test_single_file_target(self, tree):
        path = tree({"a.txt": f"TC: {VALID_TCKN}\n"}) / "a.txt"
        result = run(path)
        assert len(result.findings) == 1

    def test_missing_target_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            run(tmp_path / "yok")


class TestHashing:
    def test_hash_matches_hashlib(self, tree):
        import hashlib

        path = tree({"a.txt": "icerik"}) / "a.txt"
        expected = hashlib.sha256(b"icerik").hexdigest()
        assert calculate_file_hash(str(path)) == expected

    def test_hash_is_computed_once_per_file(self, tree, monkeypatch):
        """v3.0 her bulgu için yeniden hash alıyordu (50 MB × 1000 bulgu)."""
        import sentinel.engine as engine

        path = tree({"a.txt": "\n".join([f"TC: {VALID_TCKN}"] * 1)}) / "a.txt"
        # Aynı dosyada beş farklı bulgu üretelim.
        path.write_text(
            f"TC: {VALID_TCKN}\nKart: {VALID_VISA}\nmail: a@adu.edu.tr\n"
            "AKIAIOSFODNN7EXAMPLX\n-----BEGIN RSA PRIVATE KEY-----\n",
            encoding="utf-8",
        )

        calls = []
        original = engine.calculate_file_hash

        def counted(file_path, *args, **kwargs):
            calls.append(file_path)
            return original(file_path, *args, **kwargs)

        monkeypatch.setattr(engine, "calculate_file_hash", counted)

        report = scan_single_file(
            str(path),
            ScanConfig(
                min_severity=Severity.INFO.value, entropy_scan=False, yara_enabled=False
            ),
        )
        assert len(report.findings) >= 4
        assert len(calls) == 1, f"hash {len(calls)} kez hesaplandı, 1 olmalı"

    def test_all_findings_share_the_file_hash(self, tree):
        path = (
            tree({"a.txt": f"TC: {VALID_TCKN}\nKart: {VALID_VISA}\n"}) / "a.txt"
        )
        result = run(path)
        hashes = {f.sha256 for f in result.findings}
        assert len(hashes) == 1
        assert len(hashes.pop()) == 64


class TestTargetSelection:
    def test_excluded_dirs_are_not_walked(self, tree):
        root = tree(
            {
                "a.txt": f"TC: {VALID_TCKN}",
                "node_modules/paket/b.txt": f"TC: {VALID_TCKN}",
                ".git/config": f"TC: {VALID_TCKN}",
            }
        )
        result = run(root)
        assert all("node_modules" not in f.file for f in result.findings)
        assert all(".git" not in f.file for f in result.findings)

    def test_exclude_glob(self, tree):
        root = tree({"a.txt": f"TC: {VALID_TCKN}", "b.min.js": f"TC: {VALID_TCKN}"})
        result = run(root, exclude_globs=("*.min.js",))
        assert all("min.js" not in f.file for f in result.findings)

    @pytest.mark.parametrize("pattern", ["tests/*", "tests/**", "tests", "./tests/*"])
    def test_relative_exclude_works_on_absolute_targets(self, tree, pattern):
        """`--exclude tests/*` sessizce etkisiz kalmamalı.

        Kullanıcı kalıbı depo köküne göre yazar ama taranan yol mutlaktır;
        düz `fnmatch` hiçbir şey eşleştirmez ve dosyalar dışlandı
        sanılırken taranmaya devam eder.
        """
        root = tree(
            {"src/a.txt": f"TC: {VALID_TCKN}", "tests/b.txt": f"TC: {VALID_TCKN}"}
        )
        result = run(root, exclude_globs=(pattern,))
        assert result.findings, "src/ taranmaya devam etmeli"
        assert all("tests" not in f.file for f in result.findings), pattern

    def test_exclude_prunes_directories(self, tree):
        root = tree({"derin/cok/derin/a.txt": f"TC: {VALID_TCKN}"})
        result = run(root, exclude_globs=("derin/**",))
        assert result.findings == []

    def test_extension_filter(self, tree):
        root = tree({"a.txt": f"TC: {VALID_TCKN}", "b.dat": f"TC: {VALID_TCKN}"})
        result = run(root, extensions=(".txt",))
        assert all(f.file.endswith(".txt") for f in result.findings)

    def test_max_file_size(self, tree):
        root = tree({"buyuk.txt": f"TC: {VALID_TCKN}" + "x" * 5000})
        result = run(root, max_file_size=100)
        assert result.findings == []
        assert result.files_skipped == 1

    def test_allowlisted_paths_are_not_scanned(self, tree):
        from sentinel.allowlist import Allowlist

        root = tree(
            {"src/a.txt": f"TC: {VALID_TCKN}", "test_data/b.txt": f"TC: {VALID_TCKN}"}
        )
        result = run(root, allowlist=Allowlist(paths=("test_data/**",)))
        assert all("test_data" not in f.file for f in result.findings)
        assert result.findings


class TestFilters:
    def test_min_severity(self, sample_tree):
        result = run(sample_tree, min_severity=Severity.CRITICAL.value)
        assert result.findings
        assert all(f.severity_enum >= Severity.CRITICAL for f in result.findings)

    def test_rule_selection(self, sample_tree):
        result = run(sample_tree, include_rules=("TC_KIMLIK",))
        assert {f.type for f in result.findings} == {"TC_KIMLIK"}

    def test_rule_exclusion(self, sample_tree):
        result = run(sample_tree, exclude_rules=("EMAIL",))
        assert "EMAIL" not in {f.type for f in result.findings}

    def test_baseline_suppresses_known_findings(self, sample_tree, tmp_path):
        from sentinel.allowlist import save_baseline

        first = run(sample_tree)
        assert first.findings

        baseline = tmp_path / "baseline.json"
        save_baseline(str(baseline), first.findings)

        second = run(sample_tree, baseline_path=str(baseline))
        assert second.findings == []

    def test_baseline_still_reports_new_findings(self, sample_tree, tmp_path):
        from sentinel.allowlist import save_baseline

        first = run(sample_tree)
        baseline = tmp_path / "baseline.json"
        save_baseline(str(baseline), first.findings)

        (sample_tree / "yeni.txt").write_text(
            "AKIAIOSFODNN7EXAMPLX\n", encoding="utf-8"
        )
        second = run(sample_tree, baseline_path=str(baseline))
        assert {f.type for f in second.findings} == {"AWS_ACCESS_KEY"}


class TestArchiveIntegration:
    def test_zip_findings_carry_member_path(self, tmp_path):
        """v3.0 regresyonu: ZIP taraması tamamen kaybolmuştu."""
        archive_path = tmp_path / "arsiv.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("gizli_notlar.txt", f"TC: {VALID_TCKN}")

        result = run(tmp_path)
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.file.endswith("arsiv.zip::gizli_notlar.txt")
        assert finding.source.endswith("arsiv.zip")


class TestExecutionModes:
    @pytest.mark.parametrize("mode", ["serial", "thread", "process"])
    def test_all_modes_agree(self, tree, mode):
        """Paralel ve seri sonuçlar aynı olmalı; aksi hâlde yarış durumu var."""
        files = {
            f"f{i}.txt": f"TC: {VALID_TCKN}\nKart: {VALID_VISA}\n" for i in range(12)
        }
        root = tree(files)

        config = ScanConfig(
            min_severity=Severity.INFO.value,
            entropy_scan=False,
            yara_enabled=False,
            workers=3,
            executor=mode,
        )
        result = Scanner(str(root), config=config).scan()

        assert result.files_scanned == 12
        assert len(result.findings) == 24  # dosya başına 2 bulgu
        assert {f.type for f in result.findings} == {"TC_KIMLIK", "KREDI_KARTI"}

    def test_progress_callback_is_called(self, tree):
        root = tree({f"f{i}.txt": "temiz" for i in range(5)})
        seen = []
        config = ScanConfig(workers=1, executor="serial", yara_enabled=False)
        Scanner(str(root), config=config).scan(
            progress=lambda done, total, path: seen.append((done, total))
        )
        assert seen
        assert seen[-1][0] == seen[-1][1] == 5

    def test_config_is_picklable(self):
        """Süreç havuzu yapılandırmayı pickle eder; çağrılabilir alan olamaz."""
        import pickle

        from sentinel.allowlist import Allowlist

        config = ScanConfig(allowlist=Allowlist(patterns=(r"^X",)))
        restored = pickle.loads(pickle.dumps(config))
        assert restored.allowlist.allows_value("XYZ")


class TestCancellation:
    def test_stop_before_scan_yields_nothing(self, tree):
        root = tree({f"f{i}.txt": f"TC: {VALID_TCKN}" for i in range(20)})
        config = ScanConfig(workers=1, executor="serial", yara_enabled=False)
        scanner = Scanner(str(root), config=config)
        scanner.stop_scan()
        result = scanner.scan()
        assert result.cancelled
        assert result.findings == []

    def test_stop_midway(self, tree):
        root = tree({f"f{i:03d}.txt": f"TC: {VALID_TCKN}" for i in range(40)})
        config = ScanConfig(workers=1, executor="serial", yara_enabled=False)
        scanner = Scanner(str(root), config=config)

        def progress(done, total, path):
            if done >= 3:
                scanner.stop_scan()

        result = scanner.scan(progress=progress)
        assert result.cancelled
        assert result.files_scanned < 40


class TestLegacyApi:
    def test_start_scan_parallel_returns_dicts(self, sample_tree):
        """Eski betikler sözlük listesi bekliyor."""
        scanner = Scanner(
            str(sample_tree),
            config=ScanConfig(
                min_severity=Severity.INFO.value,
                entropy_scan=False,
                yara_enabled=False,
                workers=1,
                executor="serial",
            ),
        )
        rows = scanner.start_scan_parallel()
        assert rows and isinstance(rows[0], dict)
        for key in ("file", "line", "type", "content_masked", "sha256"):
            assert key in rows[0]

    def test_legacy_constructor_flags(self, tree):
        scanner = Scanner(str(tree({"a.txt": "x"})), use_ocr=True, quarantine_mode=False)
        assert scanner.use_ocr is True
        assert scanner.quarantine_mode is False

    def test_scan_file_wrapper_exists(self, tree):
        """v3.0'da bu metot yoktu; monitor.py her olayda patlıyordu."""
        path = tree({"a.txt": f"TC: {VALID_TCKN}"}) / "a.txt"
        scanner = Scanner(
            str(path),
            config=ScanConfig(entropy_scan=False, yara_enabled=False),
        )
        assert scanner.scan_file_wrapper(str(path))

    def test_stop_requested_property(self, tree):
        scanner = Scanner(str(tree({"a.txt": "x"})))
        assert scanner.stop_requested is False
        scanner.stop_scan()
        assert scanner.stop_requested is True


class TestSideEffects:
    def test_audit_log_is_appended(self, sample_tree, tmp_path):
        import json

        audit = tmp_path / "logs" / "audit.jsonl"
        run(sample_tree, audit_log=str(audit))
        run(sample_tree, audit_log=str(audit))

        lines = audit.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 2
        entry = json.loads(lines[0])
        assert entry["findings"] > 0
        assert "risk_score" in entry

    def test_errors_do_not_abort_the_scan(self, tree, monkeypatch):
        root = tree({"a.txt": f"TC: {VALID_TCKN}", "b.txt": f"TC: {VALID_TCKN}"})

        import sentinel.extractors as extractors

        original = extractors.extract

        def flaky(path, config, depth=0):
            if os.path.basename(path) == "a.txt":
                raise OSError("disk hatası taklidi")
            return original(path, config, depth=depth)

        monkeypatch.setattr(extractors, "extract", flaky)
        result = run(root)
        assert result.errors
        assert result.findings  # b.txt yine tarandı
