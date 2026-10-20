"""CLI ve yapılandırma testleri.

Çıkış kodları ayrıca sınanır: CI entegrasyonunun tamamı bunlara dayanır,
v3.0 ise her durumda 0 döndürüyordu.
"""

from __future__ import annotations

import json
import os

import pytest

from sentinel.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, build_parser, main
from sentinel.config import CONFIG_TEMPLATE, ScanConfig
from sentinel.severity import Severity
from tests.conftest import VALID_TCKN, VALID_VISA


@pytest.fixture
def project(tmp_path, monkeypatch):
    """İçinde bir sızıntı olan geçici proje; cwd oraya taşınır."""
    (tmp_path / "musteriler.txt").write_text(
        f"TC: {VALID_TCKN}\nKart: {VALID_VISA}\n", encoding="utf-8"
    )
    (tmp_path / "temiz.txt").write_text("hassas veri yok\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    # Kasa anahtarı ev dizinine yazılmasın.
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / ".sentinel"))
    return tmp_path


# ---------------------------------------------------------------------------
class TestParser:
    def test_subcommands_exist(self):
        parser = build_parser()
        for command in ("scan", "watch", "vault", "rules", "precommit", "init", "doctor"):
            assert parser.parse_args([command, *_required_args(command)])

    def test_no_command_prints_help(self, capsys):
        assert main([]) == EXIT_OK
        assert "usage" in capsys.readouterr().out.lower()

    def test_version(self, capsys):
        with pytest.raises(SystemExit) as exc:
            main(["--version"])
        assert exc.value.code == 0
        assert "Sentinel" in capsys.readouterr().out


def _required_args(command):
    return ["list"] if command == "vault" else []


# ---------------------------------------------------------------------------
class TestScanCommand:
    def test_clean_target_exits_zero(self, project, capsys):
        code = main(["scan", "temiz.txt", "--no-report"])
        assert code == EXIT_OK
        assert "TEMİZ" in capsys.readouterr().out

    def test_findings_alone_do_not_fail(self, project):
        """--fail-on verilmedikçe bulgu varlığı hata değildir."""
        assert main(["scan", ".", "--no-report", "--quiet"]) == EXIT_OK

    def test_fail_on_blocks(self, project, capsys):
        code = main(["scan", ".", "--no-report", "--fail-on", "high"])
        assert code == EXIT_FINDINGS
        assert "KAPI KAPALI" in capsys.readouterr().out

    def test_fail_on_below_threshold_passes(self, project):
        code = main(["scan", "temiz.txt", "--no-report", "--fail-on", "low"])
        assert code == EXIT_OK

    def test_missing_target_exits_error(self, project, capsys):
        code = main(["scan", "yok-boyle-bir-sey", "--no-report"])
        assert code == EXIT_ERROR
        assert "HATA" in capsys.readouterr().err

    def test_invalid_severity_exits_error(self, project, capsys):
        code = main(["scan", ".", "--no-report", "--min-severity", "cok-yuksek"])
        assert code == EXIT_ERROR

    def test_writes_requested_formats(self, project):
        out = project / "raporlar"
        code = main(
            [
                "scan", ".", "--output", str(out),
                "--format", "html,csv,json,sarif,md", "--quiet",
            ]
        )
        assert code == EXIT_OK
        for name in (
            "dashboard.html", "scan_results.csv", "scan_results.json",
            "sentinel.sarif", "scan_report.md",
        ):
            assert (out / name).is_file(), name

    def test_no_report_writes_nothing(self, project):
        main(["scan", ".", "--no-report", "--quiet"])
        assert not (project / "dashboard.html").exists()

    def test_legacy_no_html_flag(self, project):
        main(["scan", ".", "--format", "html,csv", "--no-html", "--quiet"])
        assert not (project / "dashboard.html").exists()
        assert (project / "scan_results.csv").is_file()

    def test_only_filters_rules(self, project):
        out = project / "r"
        main(["scan", ".", "--only", "TC_KIMLIK", "--output", str(out),
              "--format", "json", "--quiet"])
        data = json.loads((out / "scan_results.json").read_text(encoding="utf-8"))
        assert {item["type"] for item in data["findings"]} == {"TC_KIMLIK"}

    def test_skip_rules(self, project):
        out = project / "r"
        main(["scan", ".", "--skip-rules", "KREDI_KARTI", "--output", str(out),
              "--format", "json", "--quiet"])
        data = json.loads((out / "scan_results.json").read_text(encoding="utf-8"))
        assert "KREDI_KARTI" not in {item["type"] for item in data["findings"]}

    def test_exclude_glob(self, project):
        out = project / "r"
        main(["scan", ".", "--exclude", "musteriler.txt", "--output", str(out),
              "--format", "json", "--quiet"])
        data = json.loads((out / "scan_results.json").read_text(encoding="utf-8"))
        assert data["findings"] == []

    def test_baseline_roundtrip(self, project):
        baseline = project / "baseline.json"
        main(["scan", ".", "--no-report", "--quiet",
              "--write-baseline", str(baseline)])
        assert baseline.is_file()

        code = main(["scan", ".", "--no-report", "--baseline", str(baseline),
                     "--fail-on", "critical"])
        assert code == EXIT_OK  # bilinen bulgular bastırıldı

    def test_audit_log(self, project):
        audit = project / "logs" / "audit.jsonl"
        main(["scan", ".", "--no-report", "--quiet", "--audit-log", str(audit)])
        entry = json.loads(audit.read_text(encoding="utf-8").strip())
        assert entry["findings"] >= 1

    def test_verbose_lists_findings(self, project, capsys):
        main(["scan", ".", "--no-report", "--verbose"])
        assert "TC_KIMLIK" in capsys.readouterr().out

    def test_quiet_suppresses_banner(self, project, capsys):
        main(["scan", ".", "--no-report", "--quiet"])
        assert "SENTINEL" not in capsys.readouterr().out

    def test_masked_values_only_in_output(self, project, capsys):
        main(["scan", ".", "--no-report", "--verbose"])
        output = capsys.readouterr().out
        assert VALID_TCKN not in output
        assert VALID_VISA not in output

    def test_legacy_target_option(self, project):
        assert main(["scan", "--target", "temiz.txt", "--no-report"]) == EXIT_OK


# ---------------------------------------------------------------------------
class TestRulesCommand:
    def test_lists_rules(self, capsys):
        assert main(["rules"]) == EXIT_OK
        out = capsys.readouterr().out
        assert "TC_KIMLIK" in out
        assert "tespit kuralı" in out

    def test_tag_filter(self, capsys):
        main(["rules", "--tag", "secret"])
        out = capsys.readouterr().out
        assert "AWS_ACCESS_KEY" in out
        assert "TC_KIMLIK" not in out

    def test_json_output(self, capsys):
        main(["rules", "--json"])
        data = json.loads(capsys.readouterr().out)
        assert isinstance(data, list)
        assert all({"name", "severity", "title"} <= set(item) for item in data)


class TestInitCommand:
    def test_creates_config(self, project, capsys):
        assert main(["init"]) == EXIT_OK
        assert (project / "sentinel.yml").read_text(encoding="utf-8") == CONFIG_TEMPLATE

    def test_refuses_to_overwrite(self, project):
        main(["init"])
        assert main(["init"]) == EXIT_ERROR

    def test_force_overwrites(self, project):
        main(["init"])
        (project / "sentinel.yml").write_text("target: .\n", encoding="utf-8")
        assert main(["init", "--force"]) == EXIT_OK

    def test_generated_config_is_valid(self, project):
        main(["init"])
        config = ScanConfig.from_file(str(project / "sentinel.yml"))
        assert config.min_severity == "low"
        assert "tests/**" in config.allowlist.paths


class TestDoctorCommand:
    def test_runs(self, capsys):
        assert main(["doctor"]) == EXIT_OK
        out = capsys.readouterr().out
        assert "Python" in out
        assert "karantina" in out.lower()


class TestVaultCommand:
    def test_empty_vault(self, project, capsys):
        code = main(["vault", "list", "--dir", str(project / "kasa")])
        assert code == EXIT_OK
        assert "boş" in capsys.readouterr().out

    def test_purge_requires_a_target(self, project, capsys):
        code = main(["vault", "purge", "--dir", str(project / "kasa")])
        assert code == EXIT_ERROR
        assert "--all" in capsys.readouterr().err

    def test_restore_requires_a_name(self, project):
        code = main(["vault", "restore", "--dir", str(project / "kasa")])
        assert code == EXIT_ERROR

    def test_list_after_quarantine(self, project, capsys, monkeypatch):
        pytest.importorskip("cryptography")
        import base64

        monkeypatch.setenv(
            "SENTINEL_VAULT_KEY", base64.b64encode(os.urandom(32)).decode("ascii")
        )
        vault_dir = project / "kasa"
        main(["scan", "musteriler.txt", "--no-report", "--quiet", "--quarantine"])
        # Varsayılan kasa dizini KARANTINA_BOLGESI.
        code = main(["vault", "list"])
        assert code == EXIT_OK
        assert not (project / "musteriler.txt").exists()
        assert ".enc" in capsys.readouterr().out
        del vault_dir


class TestPrecommitCommand:
    def test_installs_hook(self, project, capsys):
        (project / ".git" / "hooks").mkdir(parents=True)
        assert main(["precommit", "--install"]) == EXIT_OK
        hook = project / ".git" / "hooks" / "pre-commit"
        assert hook.is_file()
        assert "sentinel precommit" in hook.read_text(encoding="utf-8")

    def test_refuses_to_clobber_existing_hook(self, project):
        hooks = project / ".git" / "hooks"
        hooks.mkdir(parents=True)
        (hooks / "pre-commit").write_text("#!/bin/sh\n", encoding="utf-8")
        assert main(["precommit", "--install"]) == EXIT_ERROR

    def test_install_without_git_errors(self, project, capsys):
        assert main(["precommit", "--install"]) == EXIT_ERROR
        assert "git" in capsys.readouterr().err.lower()

    def test_blocks_staged_secret(self, project, capsys):
        import subprocess

        def git(*args):
            subprocess.run(["git", *args], cwd=project, check=True,
                           capture_output=True)

        try:
            git("init", "-q")
            git("config", "user.email", "t@t.local")
            git("config", "user.name", "T")
        except (OSError, subprocess.CalledProcessError):
            pytest.skip("git yok")

        git("add", "musteriler.txt")
        code = main(["precommit", "--fail-on", "high"])
        assert code == EXIT_FINDINGS
        out = capsys.readouterr().out
        assert "COMMIT ENGELLENDİ" in out
        assert VALID_TCKN not in out

    def test_allows_clean_staged_files(self, project, capsys):
        import subprocess

        def git(*args):
            subprocess.run(["git", *args], cwd=project, check=True,
                           capture_output=True)

        try:
            git("init", "-q")
            git("config", "user.email", "t@t.local")
            git("config", "user.name", "T")
        except (OSError, subprocess.CalledProcessError):
            pytest.skip("git yok")

        git("add", "temiz.txt")
        assert main(["precommit", "--fail-on", "high"]) == EXIT_OK


# ---------------------------------------------------------------------------
class TestConfig:
    def test_defaults(self):
        config = ScanConfig()
        assert config.target == "."
        assert config.min_severity == Severity.INFO.value
        assert config.worker_count() >= 1

    def test_normalizes_extensions(self):
        config = ScanConfig(extensions=("TXT", ".PDF"))
        assert config.extensions == (".txt", ".pdf")

    def test_rejects_unknown_keys(self):
        with pytest.raises(ValueError, match="Bilinmeyen yapılandırma"):
            ScanConfig.from_dict({"hedef": "."})

    def test_rejects_bad_severity(self):
        with pytest.raises(ValueError):
            ScanConfig(min_severity="felaket")

    def test_yaml_roundtrip(self, tmp_path):
        pytest.importorskip("yaml")
        import yaml

        path = tmp_path / "sentinel.yml"
        path.write_text(
            yaml.safe_dump(
                {
                    "target": "veri",
                    "min_severity": "high",
                    "workers": 3,
                    "allowlist": {"paths": ["tests/**"], "rules": ["PRIVATE_IP"]},
                }
            ),
            encoding="utf-8",
        )
        config = ScanConfig.from_file(str(path))
        assert config.target == "veri"
        assert config.min_severity == "high"
        assert config.workers == 3
        assert config.allowlist.allows_path("tests/x.txt")
        assert config.allowlist.allows_rule("PRIVATE_IP")

    def test_json_config(self, tmp_path):
        path = tmp_path / "sentinel.json"
        path.write_text(json.dumps({"min_severity": "medium"}), encoding="utf-8")
        assert ScanConfig.from_file(str(path)).min_severity == "medium"

    def test_discovers_config_in_parent_directory(self, tmp_path, monkeypatch):
        (tmp_path / "sentinel.yml").write_text("min_severity: high\n", encoding="utf-8")
        deep = tmp_path / "a" / "b"
        deep.mkdir(parents=True)
        monkeypatch.chdir(deep)
        config = ScanConfig.discover()
        assert config is not None
        assert config.min_severity == "high"

    def test_env_overrides(self):
        """Sırlar koda ya da yapılandırma dosyasına değil, ortama yazılır."""
        config = ScanConfig().with_env(
            {
                "SENTINEL_WEBHOOK_URL": "https://example.invalid/hook",
                "SENTINEL_FINGERPRINT_SALT": "kurum-tuzu",
                "SENTINEL_WORKERS": "6",
                "SENTINEL_OCR": "true",
                "SENTINEL_MIN_SEVERITY": "high",
            }
        )
        assert config.webhook_url == "https://example.invalid/hook"
        assert config.fingerprint_salt == "kurum-tuzu"
        assert config.workers == 6
        assert config.ocr is True
        assert config.min_severity == "high"

    def test_env_ignores_garbage_numbers(self):
        config = ScanConfig().with_env({"SENTINEL_WORKERS": "cok"})
        assert config.workers == 0

    def test_cli_overrides_file(self, tmp_path, monkeypatch):
        (tmp_path / "sentinel.yml").write_text("min_severity: info\n", encoding="utf-8")
        (tmp_path / "a.txt").write_text("mail: a@adu.edu.tr\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)

        out = tmp_path / "r"
        main(["scan", ".", "--min-severity", "critical", "--output", str(out),
              "--format", "json", "--quiet"])
        data = json.loads((out / "scan_results.json").read_text(encoding="utf-8"))
        assert data["findings"] == []

    def test_to_dict_is_serializable(self):
        payload = ScanConfig().to_dict()
        assert json.dumps(payload)
        assert isinstance(payload["allowlist"], dict)

    def test_replace_returns_a_new_config(self):
        base = ScanConfig()
        changed = base.replace(ocr=True)
        assert changed.ocr is True
        assert base.ocr is False


class TestOutputEncoding:
    """Çıktı kodlaması, Windows'ta aracı tamamen kullanılamaz kılmıştı.

    Çıktı bir dosyaya ya da boruya yönlendirildiğinde Python, Windows'ta
    sistemin eski kod sayfasını (cp1252) kullanır; o sayfada ``ş`` yoktur
    ve ilk Türkçe karakterde ``UnicodeEncodeError`` fırlar. Yani
    `sentinel doctor > rapor.txt` ya da herhangi bir CI adımı çöküyordu.

    Bu testler alt süreçte gerçek bir yönlendirme kurar ve ortam
    kodlamasını cp1252'ye zorlar, böylece hata her platformda üretilebilir.
    """

    ENV = {"PYTHONIOENCODING": "cp1252"}

    def _run(self, project, *args):
        import subprocess
        import sys

        env = {**os.environ, **self.ENV}
        return subprocess.run(
            [sys.executable, "-m", "sentinel.cli", *args],
            cwd=project,
            env=env,
            capture_output=True,  # gerçek boru: konsol yazıcısı devrede değil
            text=True,
            encoding="utf-8",
            errors="replace",
        )

    @pytest.mark.parametrize(
        "args",
        [
            ("--version",),
            ("doctor",),
            ("rules",),
            ("rules", "--json"),
            ("scan", "musteriler.txt", "--no-report"),
            ("vault", "list"),
        ],
    )
    def test_commands_survive_a_legacy_codepage(self, project, args):
        result = self._run(project, *args)
        assert result.returncode == EXIT_OK, (
            f"{' '.join(args)} cp1252 boru hattında düştü:\n"
            f"{result.stdout}\n{result.stderr}"
        )
        assert "charmap" not in result.stdout + result.stderr
        assert "UnicodeEncodeError" not in result.stdout + result.stderr

    def test_turkish_characters_are_not_mangled(self, project):
        """Çökmemek yetmez: metin de okunabilir kalmalı."""
        result = self._run(project, "doctor")
        assert "Şifreli karantina" in result.stdout
        assert "Gerçek zamanlı izleme" in result.stdout

    def test_report_paths_with_turkish_names(self, project, tmp_path):
        """Türkçe adlı bir dizine rapor yazmak da çökmemeli."""
        out = tmp_path / "çıktı raporları"
        result = self._run(
            project, "scan", ".", "--output", str(out), "--format", "csv,json", "--quiet"
        )
        assert result.returncode == EXIT_OK, result.stdout + result.stderr
        assert (out / "scan_results.csv").is_file()
