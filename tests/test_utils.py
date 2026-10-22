"""Tests for entropy, masking, severity and the allowlist."""

from __future__ import annotations

import pytest

from sentinel.allowlist import Allowlist, load_baseline, save_baseline
from sentinel.entropy import (
    is_high_entropy,
    normalized_entropy,
    shannon_entropy,
)
from sentinel.findings import Finding
from sentinel.redaction import fingerprint, mask_data, redact_snippet
from sentinel.severity import Severity, risk_score


class TestEntropy:
    def test_empty(self):
        assert shannon_entropy("") == 0.0

    def test_single_character_has_no_entropy(self):
        assert shannon_entropy("aaaaaaaa") == 0.0

    def test_uniform_binary_is_one_bit(self):
        assert shannon_entropy("abab") == pytest.approx(1.0)

    def test_random_beats_prose(self):
        random_token = "Zx9Kq2mWpL7vR4tY8nB3cF6hJ1sD5gA0"
        prose = "bu bir normal turkce cumledir"
        assert shannon_entropy(random_token) > shannon_entropy(prose)

    def test_normalized_is_bounded(self):
        for text in ("abcd", "aaaa", "Zx9Kq2mWpL7vR4tY", ""):
            assert 0.0 <= normalized_entropy(text) <= 1.0

    def test_high_entropy_detection(self):
        assert is_high_entropy("Zx9Kq2mWpL7vR4tY8nB3cF6hJ1sD5gA0uE")

    @pytest.mark.parametrize(
        "token",
        [
            "short",  # too short
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaa",  # tek karakter
            "12345678901234567890123456",  # digits only
            "my_long_snake_case_identifier",  # an identifier
            "0123456789abcdef0123456789abcdef",  # md5 - a checksum, not a secret
        ],
    )
    def test_noise_is_not_a_secret(self, token):
        assert not is_high_entropy(token)

    @pytest.mark.parametrize(
        "token",
        [
            # Alphabet and character-set constants. Every character occurs
            # exactly once, so their entropy is the HIGHEST possible - which
            # is precisely where the entropy rule goes most wrong.
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_",
            "0123456789abcdefABCDEF",
            "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
            "abcdefghijklmnopqrstuvwxyz",
            "ZYXWVUTSRQPONMLKJIHGFEDCBA",
        ],
    )
    def test_alphabet_constants_are_not_secrets(self, token):
        """Sequential strings are not random, however high their entropy."""
        assert not is_high_entropy(token)

    @pytest.mark.parametrize(
        "token",
        [
            # Code identifiers and paths: split on separators, each part is
            # either all letters or all digits. Scanning source code turns
            # up thousands of them.
            "return_when=FIRST_COMPLETED",
            "Qt_AlignmentFlag=AlignHCenter",
            "usr/local/share/applications",
            "COMPONENT_NAME=PRIMARY_DATABASE",
            "very_long_snake_case_identifier_name",
        ],
    )
    def test_code_identifiers_are_not_secrets(self, token):
        assert not is_high_entropy(token)

    @pytest.mark.parametrize(
        "token",
        [
            # The new heuristics must NOT filter out real secrets.
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKE2",  # AWS secret key shape
            "Zx9Kq2mWpL7vR4tY8nB3cF6hJ1sD5gA0uE",
            "a3f9c1e7b5d2084619fcae73bd5102f8ea",  # hex
            "ghp_AbCd1234EfGh5678IjKl9012MnOp3456",  # has a separator, mixed parts
            "xoxb-9F2kQ7mW-pL4vR8tY-nB3cF6hJ1sD5gA",
        ],
    )
    def test_real_secrets_still_detected(self, token):
        assert is_high_entropy(token)

    def test_sequential_run_detection(self):
        from sentinel.entropy import _has_sequential_run

        assert _has_sequential_run("xx123456xx")
        assert _has_sequential_run("fedcba")
        assert not _has_sequential_run("x1y2z3a4b5")
        assert not _has_sequential_run("abc")  # too short

    def test_identifier_shape_needs_a_separator(self):
        """A single-segment string with no separator may genuinely be random."""
        from sentinel.entropy import _looks_like_identifier

        assert _looks_like_identifier("FIRST_COMPLETED")
        assert not _looks_like_identifier("Zx9Kq2mWpL7vR4tY")
        assert not _looks_like_identifier("ghp_AbCd1234EfGh")  # parts are mixed

    def test_hex_threshold_is_charset_aware(self):
        """Hex carries at most 4 bits per character; a base64 threshold misses it."""
        hex_secret = "a3f9c1e7b5d2084619fcae73bd5102f8ea"
        assert is_high_entropy(hex_secret, threshold=4.0)


class TestRedaction:
    def test_masks_middle(self):
        assert mask_data("12345678901") == "12*******01"

    def test_short_values_fully_masked(self):
        assert mask_data("1234") == "****"
        assert mask_data("ab") == "**"

    def test_empty(self):
        assert mask_data("") == ""
        assert mask_data(None) == ""

    def test_length_is_preserved(self):
        for value in ("a" * 5, "a" * 16, "a" * 40):
            assert len(mask_data(value)) == len(value)

    def test_fingerprint_is_deterministic(self):
        assert fingerprint("abc") == fingerprint("abc")

    def test_fingerprint_differs_by_value(self):
        assert fingerprint("abc") != fingerprint("abd")

    def test_salt_changes_fingerprint(self):
        assert fingerprint("abc", "tuz1") != fingerprint("abc", "tuz2")
        assert fingerprint("abc", "tuz1") != fingerprint("abc")

    def test_fingerprint_does_not_contain_the_value(self):
        secret = "AKIAIOSFODNN7EXAMPLX"
        assert secret.lower() not in fingerprint(secret).lower()

    def test_snippet_masks_the_match(self):
        line = "Customer ID: 10000000146 confirmed"
        snippet = redact_snippet(line, 12, 23)
        assert "10000000146" not in snippet
        assert "confirmed" in snippet
        assert "Customer" in snippet

    def test_snippet_is_bounded(self):
        line = "x" * 500 + "SECRET" + "y" * 500
        snippet = redact_snippet(line, 500, 506, width=20)
        assert len(snippet) < 100
        assert snippet.startswith("…")
        assert snippet.endswith("…")


class TestSeverity:
    def test_ordering(self):
        assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM
        assert Severity.MEDIUM > Severity.LOW > Severity.INFO

    def test_parse_accepts_string_and_enum(self):
        assert Severity.parse("high") is Severity.HIGH
        assert Severity.parse(Severity.HIGH) is Severity.HIGH
        assert Severity.parse("HIGH") is Severity.HIGH

    def test_parse_rejects_garbage(self):
        with pytest.raises(ValueError):
            Severity.parse("very-high")

    def test_every_level_has_label_and_icon(self):
        for severity in Severity:
            assert severity.label
            assert severity.icon

    def test_risk_score_bounds(self):
        assert risk_score([]) == 0
        assert 0 <= risk_score([_finding("info")] * 3) <= 100

    def test_one_critical_outweighs_many_low(self):
        """One critical secret must outweigh hundreds of low-severity findings."""
        critical = risk_score([_finding("critical")])
        many_low = risk_score([_finding("low")] * 10)
        assert critical > many_low

    def test_score_saturates(self):
        assert risk_score([_finding("critical")] * 1000) == 100


def _finding(severity: str) -> Finding:
    return Finding(
        file="x.txt", line=1, type="T", content_masked="**", severity=severity
    )


class TestAllowlist:
    def test_empty_allows_nothing(self):
        allowlist = Allowlist(use_defaults=False)
        assert not allowlist.allows_path("a/b.txt")
        assert not allowlist.allows_value("sir")

    def test_path_glob(self):
        allowlist = Allowlist(paths=("tests/**", "*.example"))
        assert allowlist.allows_path("tests/data/leak.txt")
        assert allowlist.allows_path("config.example")
        assert not allowlist.allows_path("src/app.py")

    def test_bare_directory_name(self):
        allowlist = Allowlist(paths=("test_data",))
        assert allowlist.allows_path("proje/test_data/leak.txt")

    def test_value_literal(self):
        allowlist = Allowlist(values=("sahte-anahtar",), use_defaults=False)
        assert allowlist.allows_value("sahte-anahtar")
        assert not allowlist.allows_value("gercek-anahtar")

    def test_fingerprint(self):
        allowlist = Allowlist(fingerprints=("ABC123",), use_defaults=False)
        assert allowlist.allows_value("herhangi", "abc123")

    def test_regex(self):
        allowlist = Allowlist(patterns=(r"^TEST_",), use_defaults=False)
        assert allowlist.allows_value("TEST_KEY_123")
        assert not allowlist.allows_value("PROD_KEY_123")

    def test_rule_suppression(self):
        allowlist = Allowlist(rules=("private_ip",))
        assert allowlist.allows_rule("PRIVATE_IP")
        assert not allowlist.allows_rule("TR_NATIONAL_ID")

    def test_defaults_cover_documented_examples(self):
        allowlist = Allowlist()
        assert allowlist.allows_value("AKIAIOSFODNN7EXAMPLE")
        assert allowlist.allows_value("user@example.com")
        assert allowlist.allows_value("changeme")

    def test_inline_ignore(self):
        allowlist = Allowlist()
        assert allowlist.inline_suppressed("secret=1  # sentinel:ignore", "ANY")
        assert allowlist.inline_suppressed(
            "x # sentinel:ignore=TR_NATIONAL_ID,EMAIL", "EMAIL"
        )
        assert not allowlist.inline_suppressed("x # sentinel:ignore=EMAIL", "TR_NATIONAL_ID")
        assert not allowlist.inline_suppressed("an ordinary line", "ANY")

    def test_inline_can_be_disabled(self):
        allowlist = Allowlist(inline=False)
        assert not allowlist.inline_suppressed("x # sentinel:ignore", "ANY")

    def test_survives_pickling(self):
        """The allowlist must survive pickling (compiled regexes do not)."""
        import pickle

        original = Allowlist(patterns=(r"^TEST_",), use_defaults=False)
        assert original.allows_value("TEST_X")  # derlemeyi tetikle
        restored = pickle.loads(pickle.dumps(original))
        assert restored.allows_value("TEST_X")


class TestBaseline:
    def test_roundtrip(self, tmp_path):
        path = tmp_path / "baseline.json"
        findings = [
            Finding(file="a", line=1, type="T", content_masked="*", fingerprint="aa11"),
            Finding(file="b", line=2, type="T", content_masked="*", fingerprint="bb22"),
        ]
        assert save_baseline(str(path), findings) == 2
        assert load_baseline(str(path)) == {"aa11", "bb22"}

    def test_missing_file_is_empty(self, tmp_path):
        assert load_baseline(str(tmp_path / "yok.json")) == set()
