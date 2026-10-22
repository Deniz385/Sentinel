"""Pattern catalogue and matcher tests.

Note: the v3.0 `tests/test_patterns.py` never ran at all - it used
the names ``TR_ID``, ``CREDIT_CARD`` and ``PHONE``, which did not
exist, and raised `KeyError`. Here canonical names and aliases are
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
        """The legacy ``get_patterns()`` contract must be preserved."""
        patterns = get_patterns()
        assert isinstance(patterns, dict)
        for name in ("TR_NATIONAL_ID", "EMAIL", "TR_PHONE", "CREDIT_CARD", "TR_IBAN"):
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
        """If a pattern's example does not match its own regex, it is broken."""
        for definition in PATTERN_DEFS:
            if not definition.example:
                continue
            assert definition.regex.search(definition.example), definition.name

    def test_prescreen_accepts_each_pattern_example(self):
        """A prescreen is correct when it does not reject the pattern's own example."""
        for definition in PATTERN_DEFS:
            if not definition.example:
                continue
            lowered = definition.example.lower()
            if definition.prescreen:
                assert any(
                    literal in lowered for literal in definition.prescreen
                ), f"{definition.name}: the prescreen rejects its own example"
            if definition.needs_digit:
                assert any(
                    char.isdigit() for char in definition.example
                ), f"{definition.name}: needs_digit is set but the example has no digit"

    def test_prescreen_never_hides_a_regex_match(self):
        """The prescreen is a speed optimisation; it must NOT change results.

        For every pattern the raw regex is compared with the screened path.
        If a line matches the regex but the screen rejected it, the tool is
        silently missing a leak - which is what this test exists to catch.
        """
        corpus = [definition.example for definition in PATTERN_DEFS if definition.example]
        corpus += [
            # Case and context variations
            "AKIAIOSFODNN7EXAMPLX",
            "akiaiosfodnn7examplx".upper(),
            f"TC={VALID_TCKN}",
            f"IBAN  {VALID_TR_IBAN}",
            f"iban {VALID_TR_IBAN.lower()}",
            "TANI: ICD-10 J45",
            "Diagnosis: hypertension",
            "HASTA NO: 12345",
            "ENV API_TOKEN=\"Zx9Kq2mWpL7vR4tY8nB3\"",
            "DB_PASSWORD = 'S3cr3t!'",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "on server 10.0.14.22",
            "ip 192.168.1.1",
            "ip 172.16.0.9",
            "Dogum: 01.01.1990",
            "Dogum: 01/01/1990",
            "plaka 34 ABC 1234",
            "wallet 0X52908400098527886E0F7030069857D2E4169EE7".lower(),
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
                        f"{definition.name} matched but needs_digit would reject it: {line!r}"
                    )
                if definition.prescreen:
                    assert any(literal in lowered for literal in definition.prescreen), (
                        f"{definition.name} matched but the prescreen would reject it: {line!r}"
                    )

    def test_filtering_by_tag(self):
        secrets = get_pattern_defs(include=["secret"])
        assert secrets
        assert all("secret" in definition.tags for definition in secrets)

        without = get_pattern_defs(exclude=["secret"])
        assert all("secret" not in definition.tags for definition in without)

    def test_filtering_by_name(self):
        only = get_pattern_defs(include=["TR_NATIONAL_ID"])
        assert [definition.name for definition in only] == ["TR_NATIONAL_ID"]


# ---------------------------------------------------------------------------
class TestPersonalData:
    def test_valid_tckn_is_found(self, config):
        findings = Matcher(config).scan_text(f"Customer ID: {VALID_TCKN}", "x.txt")
        assert "TR_NATIONAL_ID" in types_in(findings)

    def test_invalid_tckn_is_dropped(self, config):
        """The regex catches 11 digits; the validator must reject them."""
        findings = Matcher(config).scan_text(f"Invalid ID: {INVALID_TCKN}", "x.txt")
        assert "TR_NATIONAL_ID" not in types_in(findings)

    def test_email(self, config):
        findings = Matcher(config).scan_text("mail: jane@university.edu", "x.txt")
        assert "EMAIL" in types_in(findings)

    def test_reserved_domain_email_suppressed(self, config):
        findings = Matcher(config).scan_text("mail: user@example.com", "x.txt")
        assert "EMAIL" not in types_in(findings)

    @pytest.mark.parametrize(
        "line", ["Tel: 0555 123 45 67", "Tel: +905551234567", "GSM 5551234567"]
    )
    def test_phone(self, config, line):
        findings = Matcher(config).scan_text(line, "x.txt")
        assert "TR_PHONE" in types_in(findings)

    def test_landline_is_not_a_gsm(self, config):
        findings = Matcher(config).scan_text("Landline: 0212 123 45 67", "x.txt")
        assert "TR_PHONE" not in types_in(findings)

    @pytest.mark.parametrize(
        "line",
        [
            "order no: 8564733215512684",
            "transaction id: 99955512345670001",
            "measurement: 123455512345678",
        ],
    )
    def test_long_number_is_not_a_phone(self, config, line):
        """No phone number may be carved out of a longer digit run."""
        findings = Matcher(config).scan_text(line, "x.txt")
        assert "TR_PHONE" not in types_in(findings), line


class TestFinancialData:
    def test_valid_card_is_critical(self, config):
        findings = Matcher(config).scan_text(f"Payment: {VALID_VISA}", "x.txt")
        card = next(f for f in findings if f.type == "CREDIT_CARD")
        assert card.severity == Severity.CRITICAL.value
        assert card.validated

    def test_card_with_separators(self, config):
        findings = Matcher(config).scan_text("Card: 4111 1111 1111 1111", "x.txt")
        assert "CREDIT_CARD" in types_in(findings)

    def test_invalid_card_is_dropped(self, config):
        findings = Matcher(config).scan_text(f"Card: {INVALID_CARD}", "x.txt")
        assert "CREDIT_CARD" not in types_in(findings)

    def test_tr_iban(self, config):
        """The v3.0 regex had a capturing group and returned a broken IBAN."""
        findings = Matcher(config).scan_text(f"IBAN: {VALID_TR_IBAN}", "x.txt")
        iban = next(f for f in findings if f.type == "TR_IBAN")
        assert iban.validated
        # Masking must cover the whole IBAN, not just the last group.
        assert len(iban.content_masked) == len(VALID_TR_IBAN)

    def test_spaced_iban(self, config):
        findings = Matcher(config).scan_text(
            "IBAN: TR33 0006 1005 1978 6457 8413 26", "x.txt"
        )
        assert "TR_IBAN" in types_in(findings)

    def test_eth_wallet(self, config):
        findings = Matcher(config).scan_text(
            "wallet 0x52908400098527886E0F7030069857D2E4169EE7", "x.txt"
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
        """The example key from the AWS documentation is not a real secret."""
        findings = Matcher(config).scan_text("AKIAIOSFODNN7EXAMPLE", "x.txt")
        assert "AWS_ACCESS_KEY" not in types_in(findings)

    def test_hardcoded_password(self, config):
        findings = Matcher(config).scan_text('password = "SecretPass123"', "x.txt")
        finding = next(f for f in findings if f.type == "HARDCODED_PASS")
        # What is masked must be the password itself, not "password = ...".
        assert finding.content_masked.startswith("Se")
        assert finding.content_masked.endswith("23")
        assert "SecretPass123" not in finding.content_masked

    @pytest.mark.parametrize(
        "line",
        [
            'API_TOKEN = "Zx9Kq2mWpL7vR4tY8nB3"',
            'DB_PASSWORD = "S3cr3tP4ssw0rd"',
            'app.secret = "very-secret-value"',
            'AUTH-TOKEN: "abc12345"',
            'TOKEN_VALUE = "precious-secret-123"',
            # "parola" is Turkish for passphrase: the rule deliberately
        # covers Turkish credential names, so the test must too.
        'parola = "Secret123"',
        ],
    )
    def test_prefixed_and_suffixed_key_names(self, config, line):
        """The `\\b` boundary missed the most common names, such as `API_TOKEN`."""
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
        findings = Matcher(config).scan_text(f"ID {VALID_TCKN}", "x.txt")
        for finding in findings:
            assert VALID_TCKN not in finding.content_masked
            assert VALID_TCKN not in finding.snippet

    def test_snippet_gives_context_but_masks_the_match(self, config):
        findings = Matcher(config).scan_text(
            f"Invoice record: ID {VALID_TCKN} confirmed.", "x.txt"
        )
        finding = next(f for f in findings if f.type == "TR_NATIONAL_ID")
        assert "confirmed" in finding.snippet
        assert VALID_TCKN not in finding.snippet

    def test_snippet_masks_every_finding_on_the_line(self, config):
        """The snippet must mask EVERY sensitive value on the line.

        Masking only the match in focus means that in files with several
        sensitive fields per row - a customer CSV, the most typical DLP
        target of all - the report leaks nearly all of the data it claims
        to protect: the card finding's snippet exposes the IBAN, and the
        IBAN finding's snippet exposes the card.
        """
        sensitive = [VALID_VISA, VALID_TR_IBAN, VALID_TCKN, "jane@example.org"]
        line = f"2026-01-14,ACME,{VALID_VISA},{VALID_TR_IBAN},{VALID_TCKN},jane@university.edu"

        findings = Matcher(config).scan_text(line, "customers.csv")
        assert len(findings) >= 4

        for finding in findings:
            for value in sensitive:
                assert value not in finding.snippet, (
                    f"the {finding.type} snippet left {value!r} in the clear: "
                    f"{finding.snippet}"
                )
                assert value not in finding.content_masked

    def test_snippet_keeps_non_sensitive_context(self, config):
        """Masking must not destroy context; context is the point of a snippet."""
        line = f"Invoice for ACME Ltd paid with card {VALID_VISA}"
        finding = Matcher(config).scan_text(line, "x.txt")[0]
        assert "ACME Ltd" in finding.snippet
        assert "paid with card" in finding.snippet

    def test_suppressed_values_are_also_masked_in_snippets(self, config):
        """Even a suppressed match must not appear in the clear in a snippet."""
        line = f"ID {VALID_TCKN} and example AKIAIOSFODNN7EXAMPLE"
        findings = Matcher(config).scan_text(line, "x.txt")
        assert findings
        for finding in findings:
            assert "AKIAIOSFODNN7EXAMPLE" not in finding.snippet

    def test_line_numbers_are_correct(self, config):
        text = "\n".join(["bos", "", f"ID: {VALID_TCKN}", "son"])
        findings = Matcher(config).scan_text(text, "x.txt")
        assert findings[0].line == 3

    def test_line_offset_is_applied(self, config):
        findings = Matcher(config).scan_text(
            f"ID: {VALID_TCKN}", "x.txt", line_offset=100
        )
        assert findings[0].line == 101

    def test_duplicates_are_deduplicated(self, config):
        text = "\n".join([f"ID: {VALID_TCKN}"] * 5)
        findings = Matcher(config).scan_text(text, "x.txt")
        assert len([f for f in findings if f.type == "TR_NATIONAL_ID"]) == 1

    def test_overlapping_matches_resolve_to_one_rule(self, config):
        """Two rules must not both be reported for the same character range."""
        findings = Matcher(config).scan_text("sk-ant-api03-" + "a" * 32, "x.txt")
        spans = [(f.line, f.column) for f in findings]
        assert len(spans) == len(set(spans))

    def test_min_severity_filter(self):
        from sentinel.config import ScanConfig

        config = ScanConfig(
            min_severity=Severity.HIGH.value, entropy_scan=False, yara_enabled=False
        )
        findings = Matcher(config).scan_text(
            f"mail jane@university.edu ve ID {VALID_TCKN}", "x.txt"
        )
        assert types_in(findings) == {"TR_NATIONAL_ID"}

    def test_inline_ignore_suppresses_everything_on_the_line(self, config):
        findings = Matcher(config).scan_text(
            f"ID: {VALID_TCKN}  # sentinel:ignore", "x.txt"
        )
        assert findings == []

    def test_scoped_inline_ignore(self, config):
        line = f"ID {VALID_TCKN} mail jane@university.edu # sentinel:ignore=TR_NATIONAL_ID"
        findings = Matcher(config).scan_text(line, "x.txt")
        assert types_in(findings) == {"EMAIL"}

    def test_long_lines_are_truncated_not_skipped(self, config):
        # In minified files a single line can run to megabytes.
        line = "x" * 100 + f" ID {VALID_TCKN} " + "y" * 100
        findings = Matcher(config.replace(max_line_length=150)).scan_text(line, "x.txt")
        assert isinstance(findings, list)  # must not blow up

    def test_fingerprint_is_stable_and_salted(self, config):
        first = Matcher(config).scan_text(f"ID {VALID_TCKN}", "a.txt")[0]
        second = Matcher(config).scan_text(f"ID {VALID_TCKN}", "b.txt")[0]
        assert first.fingerprint == second.fingerprint

        salted = Matcher(config.replace(fingerprint_salt="org-salt")).scan_text(
            f"ID {VALID_TCKN}", "a.txt"
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
        assert findings, "a high-entropy string with context must be caught"

    def test_ignores_prose(self):
        from sentinel.config import ScanConfig

        config = ScanConfig(
            min_severity=Severity.INFO.value, entropy_scan=True, yara_enabled=False
        )
        line = "This sentence contains absolutely no sensitive data at all"
        findings = Matcher(config).scan_text(line, "x.txt")
        assert ENTROPY_RULE not in types_in(findings)


class TestLegacyRuleNames:
    """Six rules were renamed from Turkish to English identifiers.

    Allowlists, baselines and `sentinel.yml` files in the wild are
    written against the old names, so the aliases are a promise - and a
    promise without a test is a wish.
    """

    RENAMED = {
        "TC_KIMLIK": "TR_NATIONAL_ID",
        "KREDI_KARTI": "CREDIT_CARD",
        "TELEFON": "TR_PHONE",
        "TR_PLAKA": "TR_PLATE",
        "DOGUM_TARIHI": "DATE_OF_BIRTH",
        "SAGLIK_VERISI": "HEALTH_DATA",
    }

    def test_every_old_name_resolves(self):
        from sentinel.patterns import pattern_by_name, resolve_name

        for old, new in self.RENAMED.items():
            assert resolve_name(old) == new
            assert pattern_by_name(old) is not None, old

    def test_old_name_still_selects_in_only(self):
        from sentinel.patterns import get_pattern_defs

        defs = get_pattern_defs(include=["TC_KIMLIK"])
        assert [d.name for d in defs] == ["TR_NATIONAL_ID"]

    def test_old_name_still_suppresses_via_allowlist(self, config):
        from sentinel.allowlist import Allowlist

        allowed = config.replace(allowlist=Allowlist(rules=("TC_KIMLIK",)))
        findings = Matcher(allowed).scan_text(
            f"ID: {VALID_TCKN} card: {VALID_VISA}", "x.txt"
        )
        types = types_in(findings)
        assert "TR_NATIONAL_ID" not in types
        assert "CREDIT_CARD" in types

    def test_old_name_still_works_inline(self, config):
        findings = Matcher(config).scan_text(
            f"ID: {VALID_TCKN}  # sentinel:ignore=TC_KIMLIK", "x.txt"
        )
        assert "TR_NATIONAL_ID" not in types_in(findings)
