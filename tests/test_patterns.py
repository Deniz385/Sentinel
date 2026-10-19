"""Desen kataloğu ve eşleştirici testleri.

Not: v3.0'daki `tests/test_patterns.py` hiç çalışmıyordu — var olmayan
``TR_ID``, ``CREDIT_CARD``, ``PHONE`` isimlerini kullanıyor ve `KeyError`
veriyordu. Burada kanonik isimler ve takma adlar birlikte sınanır.
"""

from __future__ import annotations

import pytest

from sentinel.matcher import ENTROPY_RULE, Matcher
from sentinel.patterns import (
    ALIASES,
    PATTERN_DEFS,
    get_pattern_defs,
    get_patterns,
    pattern_by_name,
    resolve_name,
)
from sentinel.severity import Severity
from tests.conftest import (
    INVALID_CARD,
    INVALID_TCKN,
    VALID_TCKN,
    VALID_TR_IBAN,
    VALID_VISA,
)


def types_in(findings):
    return {finding.type for finding in findings}


# ---------------------------------------------------------------------------
class TestCatalog:
    def test_legacy_api_shape(self):
        """Eski ``get_patterns()`` sözleşmesi korunmalı."""
        patterns = get_patterns()
        assert isinstance(patterns, dict)
        for name in ("TC_KIMLIK", "EMAIL", "TELEFON", "KREDI_KARTI", "TR_IBAN"):
            assert name in patterns
            assert hasattr(patterns[name], "search")

    def test_every_definition_is_complete(self):
        for definition in PATTERN_DEFS:
            assert definition.name.isupper(), definition.name
            assert definition.title, definition.name
            assert definition.description, definition.name
            assert isinstance(definition.severity, Severity), definition.name

    def test_names_are_unique(self):
        names = [definition.name for definition in PATTERN_DEFS]
        assert len(names) == len(set(names))

    def test_aliases_point_to_real_patterns(self):
        for alias, target in ALIASES.items():
            assert pattern_by_name(alias) is not None, alias
            assert resolve_name(alias) == target

    def test_examples_match_their_own_regex(self):
        """Bir desenin örneği kendi regex'ine uymuyorsa desen bozuktur."""
        for definition in PATTERN_DEFS:
            if not definition.example:
                continue
            assert definition.regex.search(definition.example), definition.name

    def test_prescreen_accepts_each_pattern_example(self):
        """Ön süzgeç, desenin kendi örneğini elemiyorsa doğrudur."""
        for definition in PATTERN_DEFS:
            if not definition.example:
                continue
            lowered = definition.example.lower()
            if definition.prescreen:
                assert any(
                    literal in lowered for literal in definition.prescreen
                ), f"{definition.name}: ön süzgeç kendi örneğini eliyor"
            if definition.needs_digit:
                assert any(
                    char.isdigit() for char in definition.example
                ), f"{definition.name}: needs_digit ama örnekte rakam yok"

    def test_prescreen_never_hides_a_regex_match(self):
        """Ön süzgeç bir hız iyileştirmesidir; sonucu DEĞİŞTİRMEMELİ.

        Her desen için ham regex ile süzgeçli yol karşılaştırılır. Bir
        satırda regex eşleşiyor ama süzgeç onu elemişse, araç sessizce
        sızıntı kaçırıyor demektir — bu testin asıl amacı o.
        """
        corpus = [definition.example for definition in PATTERN_DEFS if definition.example]
        corpus += [
            # Büyük/küçük harf ve bağlam varyasyonları
            "AKIAIOSFODNN7EXAMPLX",
            "akiaiosfodnn7examplx".upper(),
            f"TC={VALID_TCKN}",
            f"IBAN  {VALID_TR_IBAN}",
            f"iban {VALID_TR_IBAN.lower()}",
            "TANI: ICD-10 J45",
            "Teşhis: hipertansiyon",
            "HASTA NO: 12345",
            "ENV API_TOKEN=\"Zx9Kq2mWpL7vR4tY8nB3\"",
            "DB_PASSWORD = 'S3cr3t!'",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "sunucu 10.0.14.22 üzerinde",
            "ip 192.168.1.1",
            "ip 172.16.0.9",
            "Dogum: 01.01.1990",
            "Dogum: 01/01/1990",
            "plaka 34 ABC 1234",
            "cüzdan 0X52908400098527886E0F7030069857D2E4169EE7".lower(),
            "Tel 0555 123 45 67",
            "mail Deniz@ADU.edu.TR",
        ]

        for definition in PATTERN_DEFS:
            for line in corpus:
                if not definition.regex.search(line):
                    continue
                lowered = line.lower()
                if definition.needs_digit:
                    assert any(char.isdigit() for char in line), (
                        f"{definition.name} eşleşti ama needs_digit elerdi: {line!r}"
                    )
                if definition.prescreen:
                    assert any(literal in lowered for literal in definition.prescreen), (
                        f"{definition.name} eşleşti ama ön süzgeç elerdi: {line!r}"
                    )

    def test_filtering_by_tag(self):
        secrets = get_pattern_defs(include=["secret"])
        assert secrets
        assert all("secret" in definition.tags for definition in secrets)

        without = get_pattern_defs(exclude=["secret"])
        assert all("secret" not in definition.tags for definition in without)

    def test_filtering_by_name(self):
        only = get_pattern_defs(include=["TC_KIMLIK"])
        assert [definition.name for definition in only] == ["TC_KIMLIK"]


# ---------------------------------------------------------------------------
class TestPersonalData:
    def test_valid_tckn_is_found(self, config):
        findings = Matcher(config).scan_text(f"Müşteri TC: {VALID_TCKN}", "x.txt")
        assert "TC_KIMLIK" in types_in(findings)

    def test_invalid_tckn_is_dropped(self, config):
        """Regex 11 haneyi yakalar; doğrulayıcı elemeli."""
        findings = Matcher(config).scan_text(f"Hatalı TC: {INVALID_TCKN}", "x.txt")
        assert "TC_KIMLIK" not in types_in(findings)

    def test_email(self, config):
        findings = Matcher(config).scan_text("mail: deniz@adu.edu.tr", "x.txt")
        assert "EMAIL" in types_in(findings)

    def test_reserved_domain_email_suppressed(self, config):
        findings = Matcher(config).scan_text("mail: user@example.com", "x.txt")
        assert "EMAIL" not in types_in(findings)

    @pytest.mark.parametrize(
        "line", ["Tel: 0555 123 45 67", "Tel: +905551234567", "GSM 5551234567"]
    )
    def test_phone(self, config, line):
        findings = Matcher(config).scan_text(line, "x.txt")
        assert "TELEFON" in types_in(findings)

    def test_landline_is_not_a_gsm(self, config):
        findings = Matcher(config).scan_text("Sabit hat: 0212 123 45 67", "x.txt")
        assert "TELEFON" not in types_in(findings)

    @pytest.mark.parametrize(
        "line",
        [
            "sipariş no: 8564733215512684",
            "işlem kimliği: 99955512345670001",
            "ölçüm: 123455512345678",
        ],
    )
    def test_long_number_is_not_a_phone(self, config, line):
        """Uzun sayı dizisinin ortasından telefon çıkarılmamalı."""
        findings = Matcher(config).scan_text(line, "x.txt")
        assert "TELEFON" not in types_in(findings), line


class TestFinancialData:
    def test_valid_card_is_critical(self, config):
        findings = Matcher(config).scan_text(f"Ödeme: {VALID_VISA}", "x.txt")
        card = next(f for f in findings if f.type == "KREDI_KARTI")
        assert card.severity == Severity.CRITICAL.value
        assert card.validated

    def test_card_with_separators(self, config):
        findings = Matcher(config).scan_text("Kart: 4111 1111 1111 1111", "x.txt")
        assert "KREDI_KARTI" in types_in(findings)

    def test_invalid_card_is_dropped(self, config):
        findings = Matcher(config).scan_text(f"Kart: {INVALID_CARD}", "x.txt")
        assert "KREDI_KARTI" not in types_in(findings)

    def test_tr_iban(self, config):
        """v3.0 regex'i yakalayan grup içerdiği için IBAN'ı bozuk döndürüyordu."""
        findings = Matcher(config).scan_text(f"IBAN: {VALID_TR_IBAN}", "x.txt")
        iban = next(f for f in findings if f.type == "TR_IBAN")
        assert iban.validated
        # Maskeleme tüm IBAN'ı kapsamalı, son grubu değil.
        assert len(iban.content_masked) == len(VALID_TR_IBAN)

    def test_spaced_iban(self, config):
        findings = Matcher(config).scan_text(
            "IBAN: TR33 0006 1005 1978 6457 8413 26", "x.txt"
        )
        assert "TR_IBAN" in types_in(findings)

    def test_eth_wallet(self, config):
        findings = Matcher(config).scan_text(
            "cüzdan 0x52908400098527886E0F7030069857D2E4169EE7", "x.txt"
        )
        assert "CRYPTO_ETH" in types_in(findings)


class TestSecrets:
    @pytest.mark.parametrize(
        "line,expected",
        [
            ("AKIAIOSFODNN7EXAMPLX", "AWS_ACCESS_KEY"),
            ("AIzaSyA1234567890abcdefghijklmnopqrstuv", "GOOGLE_API_KEY"),
            ("ghp_" + "A" * 36, "GITHUB_TOKEN"),
            ("sk_live_" + "a" * 24, "STRIPE_KEY"),
            ("-----BEGIN RSA PRIVATE KEY-----", "PRIVATE_KEY"),
            (
                "postgresql://admin:S3cr3tP4ssw0rd@db.internal:5432/app",
                "DB_CONNECTION_STRING",
            ),
        ],
    )
    def test_secret_patterns(self, config, line, expected):
        findings = Matcher(config).scan_text(line, "x.txt")
        assert expected in types_in(findings), line

    def test_aws_documented_example_is_allowlisted(self, config):
        """AWS dokümanlarındaki örnek anahtar gerçek bir sır değildir."""
        findings = Matcher(config).scan_text("AKIAIOSFODNN7EXAMPLE", "x.txt")
        assert "AWS_ACCESS_KEY" not in types_in(findings)

    def test_hardcoded_password(self, config):
        findings = Matcher(config).scan_text('password = "GizliSifre123"', "x.txt")
        finding = next(f for f in findings if f.type == "HARDCODED_PASS")
        # Maskelenmiş olan şifrenin kendisi olmalı, "password = ..." değil.
        assert finding.content_masked.startswith("Gi")
        assert finding.content_masked.endswith("23")
        assert "GizliSifre123" not in finding.content_masked

    @pytest.mark.parametrize(
        "line",
        [
            'API_TOKEN = "Zx9Kq2mWpL7vR4tY8nB3"',
            'DB_PASSWORD = "S3cr3tP4ssw0rd"',
            'app.secret = "cok-gizli-deger"',
            'AUTH-TOKEN: "abc12345"',
            'TOKEN_VALUE = "degerli-sir-123"',
            'parola = "Gizli123"',
        ],
    )
    def test_prefixed_and_suffixed_key_names(self, config, line):
        """`\\b` sınırı `API_TOKEN` gibi en yaygın isimleri kaçırıyordu."""
        findings = Matcher(config).scan_text(line, "x.txt")
        assert findings, line
        assert "HARDCODED_PASS" in types_in(findings), line

    def test_db_connection_string_masks_only_password(self, config):
        findings = Matcher(config).scan_text(
            "postgresql://admin:S3cr3tP4ssw0rd@db:5432/app", "x.txt"
        )
        finding = next(f for f in findings if f.type == "DB_CONNECTION_STRING")
        assert "S3cr3tP4ssw0rd" not in finding.content_masked


# ---------------------------------------------------------------------------
class TestMatcherBehaviour:
    def test_masking_never_leaks_the_value(self, config):
        findings = Matcher(config).scan_text(f"TC {VALID_TCKN}", "x.txt")
        for finding in findings:
            assert VALID_TCKN not in finding.content_masked
            assert VALID_TCKN not in finding.snippet

    def test_snippet_gives_context_but_masks_the_match(self, config):
        findings = Matcher(config).scan_text(
            f"Fatura kaydı için TC: {VALID_TCKN} onaylandı.", "x.txt"
        )
        finding = next(f for f in findings if f.type == "TC_KIMLIK")
        assert "onaylandı" in finding.snippet
        assert VALID_TCKN not in finding.snippet

    def test_snippet_masks_every_finding_on_the_line(self, config):
        """Alıntı, satırdaki TÜM hassas değerleri maskelemeli.

        Yalnızca odaktaki eşleşmeyi maskelemek, müşteri CSV'si gibi
        satırında birkaç hassas alan olan dosyalarda — DLP'nin en tipik
        hedefi — raporun koruduğunu iddia ettiği verinin neredeyse
        tamamını sızdırması demektir: kart bulgusunun alıntısı IBAN'ı,
        IBAN bulgusunun alıntısı kartı açıkta bırakır.
        """
        hassas = [VALID_VISA, VALID_TR_IBAN, VALID_TCKN, "deniz@adu.edu.tr"]
        line = f"2026-01-14,ACME,{VALID_VISA},{VALID_TR_IBAN},{VALID_TCKN},deniz@adu.edu.tr"

        findings = Matcher(config).scan_text(line, "musteriler.csv")
        assert len(findings) >= 4

        for finding in findings:
            for deger in hassas:
                assert deger not in finding.snippet, (
                    f"{finding.type} alıntısı {deger!r} değerini açıkta bıraktı: "
                    f"{finding.snippet}"
                )
                assert deger not in finding.content_masked

    def test_snippet_keeps_non_sensitive_context(self, config):
        """Maskeleme bağlamı yok etmemeli; alıntının amacı bu."""
        line = f"Fatura ACME Ltd icin kart {VALID_VISA} ile odendi"
        finding = Matcher(config).scan_text(line, "x.txt")[0]
        assert "ACME Ltd" in finding.snippet
        assert "odendi" in finding.snippet

    def test_suppressed_values_are_also_masked_in_snippets(self, config):
        """Bastırılan bir eşleşme bile alıntıda açık yazılmamalı."""
        line = f"TC {VALID_TCKN} ve ornek AKIAIOSFODNN7EXAMPLE"
        findings = Matcher(config).scan_text(line, "x.txt")
        assert findings
        for finding in findings:
            assert "AKIAIOSFODNN7EXAMPLE" not in finding.snippet

    def test_line_numbers_are_correct(self, config):
        text = "\n".join(["bos", "", f"TC: {VALID_TCKN}", "son"])
        findings = Matcher(config).scan_text(text, "x.txt")
        assert findings[0].line == 3

    def test_line_offset_is_applied(self, config):
        findings = Matcher(config).scan_text(
            f"TC: {VALID_TCKN}", "x.txt", line_offset=100
        )
        assert findings[0].line == 101

    def test_duplicates_are_deduplicated(self, config):
        text = "\n".join([f"TC: {VALID_TCKN}"] * 5)
        findings = Matcher(config).scan_text(text, "x.txt")
        assert len([f for f in findings if f.type == "TC_KIMLIK"]) == 1

    def test_overlapping_matches_resolve_to_one_rule(self, config):
        """Aynı karakter aralığı için iki kural birden raporlanmamalı."""
        findings = Matcher(config).scan_text("sk-ant-api03-" + "a" * 32, "x.txt")
        spans = [(f.line, f.column) for f in findings]
        assert len(spans) == len(set(spans))

    def test_min_severity_filter(self):
        from sentinel.config import ScanConfig

        config = ScanConfig(
            min_severity=Severity.HIGH.value, entropy_scan=False, yara_enabled=False
        )
        findings = Matcher(config).scan_text(
            f"mail deniz@adu.edu.tr ve TC {VALID_TCKN}", "x.txt"
        )
        assert types_in(findings) == {"TC_KIMLIK"}

    def test_inline_ignore_suppresses_everything_on_the_line(self, config):
        findings = Matcher(config).scan_text(
            f"TC: {VALID_TCKN}  # sentinel:ignore", "x.txt"
        )
        assert findings == []

    def test_scoped_inline_ignore(self, config):
        line = f"TC {VALID_TCKN} mail deniz@adu.edu.tr # sentinel:ignore=TC_KIMLIK"
        findings = Matcher(config).scan_text(line, "x.txt")
        assert types_in(findings) == {"EMAIL"}

    def test_long_lines_are_truncated_not_skipped(self, config):
        # Minify edilmiş dosyalarda tek satır megabaytlarca olabilir.
        line = "x" * 100 + f" TC {VALID_TCKN} " + "y" * 100
        findings = Matcher(config.replace(max_line_length=150)).scan_text(line, "x.txt")
        assert isinstance(findings, list)  # patlamamalı

    def test_fingerprint_is_stable_and_salted(self, config):
        first = Matcher(config).scan_text(f"TC {VALID_TCKN}", "a.txt")[0]
        second = Matcher(config).scan_text(f"TC {VALID_TCKN}", "b.txt")[0]
        assert first.fingerprint == second.fingerprint

        salted = Matcher(config.replace(fingerprint_salt="kurum-tuzu")).scan_text(
            f"TC {VALID_TCKN}", "a.txt"
        )[0]
        assert salted.fingerprint != first.fingerprint


class TestEntropyScan:
    def test_finds_unnamed_secret_with_context(self):
        from sentinel.config import ScanConfig

        config = ScanConfig(
            min_severity=Severity.INFO.value, entropy_scan=True, yara_enabled=False
        )
        line = 'session_token = "Zx9Kq2mWpL7vR4tY8nB3cF6hJ1sD5gA0uE"'
        findings = Matcher(config).scan_text(line, "x.txt")
        assert findings, "bağlamlı yüksek entropili dizge yakalanmalı"

    def test_ignores_prose(self):
        from sentinel.config import ScanConfig

        config = ScanConfig(
            min_severity=Severity.INFO.value, entropy_scan=True, yara_enabled=False
        )
        line = "Bu cumlede hassas hicbir veri bulunmamaktadir kesinlikle"
        findings = Matcher(config).scan_text(line, "x.txt")
        assert ENTROPY_RULE not in types_in(findings)
