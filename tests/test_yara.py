"""YARA engine tests.

In v3.0 `rules/sample.yar` sat in the repository but no code ever
read it. These tests verify that the rules are genuinely compiled
and do fire.
"""

from __future__ import annotations

import os

import pytest

from sentinel.yara_engine import YaraEngine, yara_available

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")

PRIVATE_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEAqwerty1234567890\n"
    "-----END RSA PRIVATE KEY-----\n"
)


class TestGracefulDegradation:
    """Everything must keep working without yara-python."""

    def test_engine_reports_its_state(self):
        engine = YaraEngine(RULES_DIR)
        if yara_available():
            assert engine.enabled, engine.error
        else:
            assert not engine.enabled
            assert engine.error

    def test_disabled_engine_returns_no_findings(self, tmp_path):
        engine = YaraEngine(str(tmp_path / "missing-dir"))
        assert not engine.enabled
        assert engine.match_file(__file__) == []

    def test_missing_directory_is_reported_not_raised(self, tmp_path):
        engine = YaraEngine(str(tmp_path / "missing"))
        assert engine.error

    def test_empty_directory_is_reported(self, tmp_path):
        """A disabled engine must *say* why, not swallow it silently.

        The exact message depends on the environment: with yara-python
        installed it is "no rules found", otherwise "yara-python is not
        installed". Both are valid explanations; what this test cares
        about is that the user is not left without a reason. The message
        itself is checked in :class:`TestRules`, with yara installed.
        """
        directory = tmp_path / "bos"
        directory.mkdir()
        engine = YaraEngine(str(directory))
        assert not engine.enabled
        assert engine.error

    def test_engine_does_not_break_the_scan_without_yara(self, tmp_path):
        """A scan with `yara_enabled=True` must work even with the engine off."""
        from sentinel.config import ScanConfig
        from sentinel.engine import Scanner

        (tmp_path / "a.txt").write_text("mail: jane@university.edu\n", encoding="utf-8")
        config = ScanConfig(
            yara_enabled=True,
            yara_rules_dir=str(tmp_path / "missing"),
            entropy_scan=False,
            workers=1,
            executor="serial",
        )
        result = Scanner(str(tmp_path), config=config).scan()
        assert result.findings


@pytest.mark.skipif(not yara_available(), reason="yara-python is not installed")
class TestRules:
    @pytest.fixture
    def engine(self):
        engine = YaraEngine(RULES_DIR)
        assert engine.enabled, engine.error
        return engine

    def test_repository_rules_compile(self, engine):
        assert engine.rules is not None
        assert engine.error is None

    def test_empty_rules_directory_names_the_reason(self, tmp_path):
        """With yara installed, an empty directory must state its reason."""
        directory = tmp_path / "bos"
        directory.mkdir()
        engine = YaraEngine(str(directory))
        assert not engine.enabled
        assert "No .yar rules found" in engine.error

    def test_private_key_rule_fires(self, engine, tmp_path):
        path = tmp_path / "id_rsa"
        path.write_text(PRIVATE_KEY, encoding="utf-8")

        findings = engine.match_file(str(path))
        assert findings
        finding = next(f for f in findings if "Private_Key" in f.type)
        assert finding.type.startswith("YARA_")
        assert finding.severity == "critical"
        assert finding.validated

    def test_webshell_rule_fires(self, engine, tmp_path):
        path = tmp_path / "shell.php"
        path.write_text('<?php system($_GET["cmd"]); ?>', encoding="utf-8")
        assert any("Webshell" in f.type for f in engine.match_file(str(path)))

    def test_clean_file_does_not_fire(self, engine, tmp_path):
        path = tmp_path / "clean.txt"
        path.write_text("This file contains entirely harmless text.\n", encoding="utf-8")
        assert engine.match_file(str(path)) == []

    def test_severity_comes_from_rule_meta(self, engine, tmp_path):
        path = tmp_path / "shell.php"
        path.write_text('<?php eval($_POST["x"]); ?>', encoding="utf-8")
        finding = next(
            f for f in engine.match_file(str(path)) if "Webshell" in f.type
        )
        assert finding.severity == "high"

    def test_invalid_severity_meta_falls_back(self, tmp_path):
        """A rule file with an invalid severity must not fail the scan."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "x.yar").write_text(
            'rule Broken { meta: severity = "catastrophe" strings: $a = "TRIGGER" condition: $a }',
            encoding="utf-8",
        )
        target = tmp_path / "a.txt"
        target.write_text("TRIGGER", encoding="utf-8")

        engine = YaraEngine(str(rules_dir))
        finding = engine.match_file(str(target))[0]
        assert finding.severity == "medium"  # fell back to the default

    def test_broken_rule_file_is_reported(self, tmp_path):
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "broken.yar").write_text("rule { this is not yara", encoding="utf-8")

        engine = YaraEngine(str(rules_dir))
        assert not engine.enabled
        assert "compile error" in engine.error

    def test_engine_integrates_with_the_scanner(self, tmp_path):
        from sentinel.config import ScanConfig
        from sentinel.engine import Scanner

        (tmp_path / "id_rsa").write_text(PRIVATE_KEY, encoding="utf-8")
        config = ScanConfig(
            yara_enabled=True,
            yara_rules_dir=RULES_DIR,
            entropy_scan=False,
            extensions=(".txt", ""),
            workers=1,
            executor="serial",
        )
        result = Scanner(str(tmp_path), config=config).scan()
        types = {f.type for f in result.findings}
        # Both a regex pattern and a YARA rule match the same file.
        assert "PRIVATE_KEY" in types
        assert any(name.startswith("YARA_") for name in types)
