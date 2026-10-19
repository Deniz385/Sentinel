"""YARA motoru testleri.

`rules/sample.yar` v3.0'da depoda duruyordu ama hiçbir kod onu
okumuyordu. Bu testler kuralların gerçekten derlendiğini ve
tetiklendiğini doğrular.
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
    """yara-python olmadan da her şey çalışmaya devam etmeli."""

    def test_engine_reports_its_state(self):
        engine = YaraEngine(RULES_DIR)
        if yara_available():
            assert engine.enabled, engine.error
        else:
            assert not engine.enabled
            assert engine.error

    def test_disabled_engine_returns_no_findings(self, tmp_path):
        engine = YaraEngine(str(tmp_path / "olmayan-dizin"))
        assert not engine.enabled
        assert engine.match_file(__file__) == []

    def test_missing_directory_is_reported_not_raised(self, tmp_path):
        engine = YaraEngine(str(tmp_path / "yok"))
        assert engine.error

    def test_empty_directory_is_reported(self, tmp_path):
        """Motor kapalıysa nedenini *söylemeli*, sessizce yutmamalı.

        Kesin mesaj ortama bağlıdır: yara-python kuruluysa "kural
        bulunamadı", değilse "yara-python kurulu değil". İkisi de geçerli
        bir açıklamadır; testin ilgilendiği şey kullanıcının sebepsiz
        bırakılmaması. Mesajın kendisi :class:`TestRules` içinde,
        yara kuruluyken doğrulanır.
        """
        directory = tmp_path / "bos"
        directory.mkdir()
        engine = YaraEngine(str(directory))
        assert not engine.enabled
        assert engine.error

    def test_engine_does_not_break_the_scan_without_yara(self, tmp_path):
        """Motor kapalıyken bile `yara_enabled=True` tarama yapmalı."""
        from sentinel.config import ScanConfig
        from sentinel.engine import Scanner

        (tmp_path / "a.txt").write_text("mail: deniz@adu.edu.tr\n", encoding="utf-8")
        config = ScanConfig(
            yara_enabled=True,
            yara_rules_dir=str(tmp_path / "olmayan"),
            entropy_scan=False,
            workers=1,
            executor="serial",
        )
        result = Scanner(str(tmp_path), config=config).scan()
        assert result.findings


@pytest.mark.skipif(not yara_available(), reason="yara-python kurulu değil")
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
        """yara kuruluyken, boş dizinin gerekçesi açıkça söylenmeli."""
        directory = tmp_path / "bos"
        directory.mkdir()
        engine = YaraEngine(str(directory))
        assert not engine.enabled
        assert "bulunamadı" in engine.error

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
        path = tmp_path / "temiz.txt"
        path.write_text("Bu dosyada tamamen zararsiz metin var.\n", encoding="utf-8")
        assert engine.match_file(str(path)) == []

    def test_severity_comes_from_rule_meta(self, engine, tmp_path):
        path = tmp_path / "shell.php"
        path.write_text('<?php eval($_POST["x"]); ?>', encoding="utf-8")
        finding = next(
            f for f in engine.match_file(str(path)) if "Webshell" in f.type
        )
        assert finding.severity == "high"

    def test_invalid_severity_meta_falls_back(self, tmp_path):
        """Kural dosyası bozuk bir severity yazarsa tarama düşmemeli."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "x.yar").write_text(
            'rule Bozuk { meta: severity = "felaket" strings: $a = "TETIK" condition: $a }',
            encoding="utf-8",
        )
        target = tmp_path / "a.txt"
        target.write_text("TETIK", encoding="utf-8")

        engine = YaraEngine(str(rules_dir))
        finding = engine.match_file(str(target))[0]
        assert finding.severity == "medium"  # varsayılana düştü

    def test_broken_rule_file_is_reported(self, tmp_path):
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "bozuk.yar").write_text("rule { bu yara degil", encoding="utf-8")

        engine = YaraEngine(str(rules_dir))
        assert not engine.enabled
        assert "derleme hatası" in engine.error

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
        # Hem regex deseni hem YARA kuralı aynı dosyayı yakalar.
        assert "PRIVATE_KEY" in types
        assert any(name.startswith("YARA_") for name in types)
