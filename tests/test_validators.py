"""Tests for the algorithmic validators.

This layer decides the tool's false-positive rate, so both sides are
tested separately: "accept what is valid" and "reject what matches
the regex but is invalid".
"""

from __future__ import annotations

import pytest

from sentinel.validators import (
    card_brand,
    luhn_check,
    validate_base58check,
    validate_credit_card,
    validate_email,
    validate_iban,
    validate_jwt,
    validate_phone_tr,
    validate_tc,
    validate_tckn,
    validate_tr_iban,
)
from tests.conftest import (
    INVALID_CARD,
    INVALID_IBAN,
    INVALID_TCKN,
    VALID_BTC,
    VALID_DE_IBAN,
    VALID_MASTERCARD,
    VALID_TCKN,
    VALID_TR_IBAN,
    VALID_VISA,
)


class TestTckn:
    def test_valid(self):
        assert validate_tckn(VALID_TCKN)

    def test_invalid_checksum(self):
        # 11 hane ve regex'e uyar, ama kontrol haneleri tutmaz.
        assert not validate_tckn(INVALID_TCKN)

    @pytest.mark.parametrize(
        "value",
        [
            "0123456789 0".replace(" ", ""),  # starts with 0
            "1234567890",  # 10 hane
            "123456789012",  # 12 hane
            "1000000014a",  # contains a letter
            "",
            "11111111110",  # passes the algorithm but every digit is the same
        ],
    )
    def test_rejects(self, value):
        assert not validate_tckn(value)

    def test_legacy_alias(self):
        assert validate_tc is validate_tckn


class TestCreditCard:
    @pytest.mark.parametrize("value", [VALID_VISA, VALID_MASTERCARD, "378282246310005"])
    def test_valid(self, value):
        assert validate_credit_card(value)

    def test_accepts_separators(self):
        assert validate_credit_card("4111 1111 1111 1111")
        assert validate_credit_card("4111-1111-1111-1111")

    def test_rejects_bad_luhn(self):
        assert not validate_credit_card(INVALID_CARD)

    def test_rejects_unknown_brand_even_if_luhn_passes(self):
        # Sixteen digits that pass Luhn but carry no known card prefix:
        # relying on Luhn alone produces false positives.
        candidate = "9999999999999995"
        assert luhn_check(candidate)
        assert not validate_credit_card(candidate)

    def test_rejects_wrong_length(self):
        assert not validate_credit_card("411111111111")  # 12 hane
        assert not validate_credit_card("4" * 20)

    def test_brand_detection(self):
        assert card_brand(VALID_VISA) == "Visa"
        assert card_brand(VALID_MASTERCARD) == "Mastercard"
        assert card_brand("378282246310005") == "American Express"
        assert card_brand("1234567812345678") is None


class TestIban:
    def test_valid_tr(self):
        assert validate_iban(VALID_TR_IBAN)
        assert validate_tr_iban(VALID_TR_IBAN)

    def test_valid_international(self):
        assert validate_iban(VALID_DE_IBAN)
        assert not validate_tr_iban(VALID_DE_IBAN)

    def test_accepts_spaces(self):
        spaced = "TR33 0006 1005 1978 6457 8413 26"
        assert validate_iban(spaced)

    def test_rejects_bad_checksum(self):
        assert not validate_iban(INVALID_IBAN)

    def test_rejects_wrong_country_length(self):
        # A Turkish IBAN must be 26 characters; 25 is rejected even if mod-97 passes.
        assert not validate_iban("TR3300061005197864578413")


class TestJwt:
    def test_valid_structure(self):
        # {"alg":"HS256","typ":"JWT"} . {"sub":"1"} . imza
        token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
            ".dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        )
        assert validate_jwt(token)

    @pytest.mark.parametrize(
        "token",
        [
            "eyJhbGciOiJIUzI1NiJ9.only-two-parts",
            "not.a.jwt",
            "eyJub3RhbGciOiJ4In0.eyJhIjoxfQ.sig",  # no alg in the header
            "",
        ],
    )
    def test_rejects(self, token):
        assert not validate_jwt(token)


class TestBase58Check:
    def test_valid_btc(self):
        assert validate_base58check(VALID_BTC)

    def test_rejects_tampered(self):
        tampered = VALID_BTC[:-1] + ("a" if VALID_BTC[-1] != "a" else "b")
        assert not validate_base58check(tampered)

    def test_rejects_invalid_alphabet(self):
        assert not validate_base58check("1A1zP1eP5QGefi2DMPTfTL5SLmv7Div0Na")  # '0' yok


class TestEmail:
    @pytest.mark.parametrize(
        "value", ["jane.doe@university.edu", "test_user123@gmail.com", "a+b@sub.co.uk"]
    )
    def test_valid(self, value):
        assert validate_email(value)

    @pytest.mark.parametrize(
        "value",
        [
            "deniz.celik@",
            "deniz@.com",
            "@gmail.com",
            "iki@at@var.com",
            "user@example.com",  # RFC 2606: reserved, not a real address
            "admin@localhost",
        ],
    )
    def test_rejects(self, value):
        assert not validate_email(value)


class TestPhoneTr:
    @pytest.mark.parametrize(
        "value", ["0555 123 45 67", "+905551234567", "5551234567", "0555-123-45-67"]
    )
    def test_valid(self, value):
        assert validate_phone_tr(value)

    @pytest.mark.parametrize("value", ["0212 123 45 67", "555123456", "12345"])
    def test_rejects(self, value):
        assert not validate_phone_tr(value)
