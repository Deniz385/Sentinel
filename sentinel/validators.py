"""Algoritmik doğrulayıcılar.

Regex "11 haneli sayı" bulur; doğrulayıcı onun gerçekten bir TC Kimlik
Numarası olup olmadığını söyler. DLP araçlarının kullanılabilirliği
büyük ölçüde bu katmana bağlıdır: doğrulama olmadan 50 MB'lık bir log
dosyası binlerce yanlış pozitif üretir.
"""

from __future__ import annotations

import base64
import json
import re

__all__ = [
    "validate_tckn",
    "validate_tc",
    "luhn_check",
    "validate_credit_card",
    "card_brand",
    "validate_iban",
    "validate_tr_iban",
    "validate_jwt",
    "validate_base58check",
    "validate_email",
    "validate_phone_tr",
    "VALIDATORS",
]


# --------------------------------------------------------------------------
# TC Kimlik Numarası
# --------------------------------------------------------------------------
def validate_tckn(value: str) -> bool:
    """TC Kimlik Numarası algoritma kontrolü.

    1. 11 hane, ilk hane 0 olamaz.
    2. (1,3,5,7,9. hanelerin toplamı × 7 − 2,4,6,8. hanelerin toplamı) mod 10
       = 10. hane.
    3. İlk 10 hanenin toplamı mod 10 = 11. hane.
    """
    value = str(value).strip()
    if len(value) != 11 or not value.isdigit() or value[0] == "0":
        return False

    digits = [int(d) for d in value]

    # 11111111110 gibi tüm haneleri aynı olan sayılar algoritmayı geçer ama
    # gerçek bir kimlik numarası değildir; test verisi gürültüsünü keser.
    if len(set(digits[:10])) == 1:
        return False

    odd_sum = sum(digits[0:9:2])  # 1., 3., 5., 7., 9. haneler
    even_sum = sum(digits[1:8:2])  # 2., 4., 6., 8. haneler

    check_10 = ((odd_sum * 7) - even_sum) % 10
    check_11 = sum(digits[:10]) % 10

    return digits[9] == check_10 and digits[10] == check_11


# Eski API adı (src/validators.py ile uyumluluk).
validate_tc = validate_tckn


# --------------------------------------------------------------------------
# Kredi kartı
# --------------------------------------------------------------------------
def luhn_check(value: str) -> bool:
    """Luhn (mod 10) kontrol toplamı."""
    clean = re.sub(r"[ \-]", "", str(value))
    if not clean.isdigit() or not clean:
        return False

    checksum = 0
    double = False
    for char in reversed(clean):
        digit = int(char)
        if double:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
        double = not double
    return checksum % 10 == 0


# Kart markası ön ekleri (BIN aralıkları). Marka bilgisi raporu
# anlamlandırır: "Visa" bir ödeme kartıdır, rastgele 16 hane değildir.
_BRANDS = (
    ("Visa", re.compile(r"^4\d{12}(?:\d{3})?(?:\d{3})?$")),
    ("Mastercard", re.compile(r"^(?:5[1-5]\d{14}|2(?:2[2-9]|[3-6]\d|7[01])\d{12}|2720\d{12})$")),
    ("American Express", re.compile(r"^3[47]\d{13}$")),
    ("Troy", re.compile(r"^9792\d{12}$")),
    ("Discover", re.compile(r"^6(?:011|5\d{2}|4[4-9]\d)\d{12}$")),
    ("Diners Club", re.compile(r"^3(?:0[0-5]|[68]\d)\d{11}$")),
    ("JCB", re.compile(r"^35(?:2[89]|[3-8]\d)\d{12}$")),
    ("UnionPay", re.compile(r"^62\d{14,17}$")),
)


def card_brand(value: str) -> str | None:
    """Kart numarasının markasını döndürür, bilinmiyorsa ``None``."""
    clean = re.sub(r"[ \-]", "", str(value))
    for name, pattern in _BRANDS:
        if pattern.match(clean):
            return name
    return None


def validate_credit_card(value: str) -> bool:
    """Luhn + uzunluk + bilinen marka ön eki kontrolü.

    Sadece Luhn yetersizdir: rastgele 16 hanenin ~%10'u Luhn'u geçer.
    Marka ön eki şartı yanlış pozitifleri belirgin şekilde azaltır.
    """
    clean = re.sub(r"[ \-]", "", str(value))
    if not clean.isdigit() or not 13 <= len(clean) <= 19:
        return False
    if not luhn_check(clean):
        return False
    return card_brand(clean) is not None


# --------------------------------------------------------------------------
# IBAN
# --------------------------------------------------------------------------
# Ülke bazlı IBAN uzunlukları (ISO 13616). Eksik ülke = bilinmeyen,
# uzunluk kontrolü atlanır ama mod-97 yine uygulanır.
IBAN_LENGTHS = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16,
    "BG": 22, "BH": 22, "BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28,
    "CZ": 24, "DE": 22, "DK": 18, "DO": 28, "EE": 20, "EG": 29, "ES": 24,
    "FI": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18,
    "GR": 27, "GT": 28, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23,
    "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LC": 32,
    "LI": 21, "LT": 20, "LU": 20, "LV": 21, "LY": 25, "MC": 27, "MD": 24,
    "ME": 22, "MK": 19, "MR": 27, "MT": 31, "MU": 30, "NL": 18, "NO": 15,
    "PK": 24, "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22,
    "SA": 24, "SC": 31, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "ST": 25,
    "SV": 28, "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24,
    "XK": 20,
}


def validate_iban(iban: str) -> bool:
    """IBAN doğrulaması (ISO 7064 Mod 97-10)."""
    clean = re.sub(r"[\s\-]", "", str(iban)).upper()

    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{10,30}", clean):
        return False

    expected = IBAN_LENGTHS.get(clean[:2])
    if expected is not None and len(clean) != expected:
        return False

    # İlk 4 karakteri sona taşı, harfleri sayıya çevir (A=10 ... Z=35),
    # sonucun 97'ye bölümünden kalan 1 olmalı.
    rearranged = clean[4:] + clean[:4]
    numeric = "".join(
        char if char.isdigit() else str(ord(char) - 55) for char in rearranged
    )
    try:
        return int(numeric) % 97 == 1
    except ValueError:
        return False


def validate_tr_iban(iban: str) -> bool:
    """Sadece TR IBAN kabul eder."""
    clean = re.sub(r"[\s\-]", "", str(iban)).upper()
    return clean.startswith("TR") and validate_iban(clean)


# --------------------------------------------------------------------------
# JWT
# --------------------------------------------------------------------------
def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def validate_jwt(token: str) -> bool:
    """Yapısal JWT kontrolü: başlık gerçekten çözülüp ``alg`` içeriyor mu?

    İmza doğrulanmaz (anahtar bizde yok); amaç "JWT'ye benzeyen base64
    çöpü" ile gerçek bir token'ı ayırmak.
    """
    parts = str(token).strip().split(".")
    if len(parts) != 3 or not all(parts[:2]):
        return False
    try:
        header = json.loads(_b64url_decode(parts[0]))
    except Exception:
        return False
    return isinstance(header, dict) and "alg" in header


# --------------------------------------------------------------------------
# Bitcoin (Base58Check)
# --------------------------------------------------------------------------
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58decode(value: str) -> bytes | None:
    number = 0
    for char in value:
        index = _B58_ALPHABET.find(char)
        if index < 0:
            return None
        number = number * 58 + index

    body = number.to_bytes((number.bit_length() + 7) // 8, "big")
    # Baştaki '1' karakterleri sıfır bayta karşılık gelir.
    leading_zeros = len(value) - len(value.lstrip("1"))
    return b"\x00" * leading_zeros + body


def validate_base58check(address: str) -> bool:
    """Base58Check (Bitcoin adres) kontrol toplamı doğrulaması."""
    import hashlib

    address = str(address).strip()
    if not 26 <= len(address) <= 35:
        return False

    raw = _b58decode(address)
    if raw is None or len(raw) != 25:
        return False

    payload, checksum = raw[:-4], raw[-4:]
    expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return checksum == expected


# --------------------------------------------------------------------------
# Hafif doğrulayıcılar
# --------------------------------------------------------------------------
_PLACEHOLDER_EMAIL_RE = re.compile(
    r"(?i)@(example\.(com|org|net)|test|localhost|invalid|domain\.com|email\.com)$"
)


def validate_email(value: str) -> bool:
    """Belirgin şablon/örnek adresleri eler."""
    value = str(value).strip()
    if "@" not in value or value.count("@") != 1:
        return False
    local, _, domain = value.partition("@")
    if not local or not domain or "." not in domain:
        return False
    if domain.startswith(".") or domain.endswith(".") or ".." in domain:
        return False
    return not _PLACEHOLDER_EMAIL_RE.search(value)


def validate_phone_tr(value: str) -> bool:
    """TR GSM numarası: normalize edildiğinde 5XXXXXXXXX olmalı."""
    digits = re.sub(r"\D", "", str(value))
    if digits.startswith("90"):
        digits = digits[2:]
    digits = digits.lstrip("0")
    return len(digits) == 10 and digits.startswith("5")


# Desen kataloğunun isimle referans verdiği doğrulayıcı tablosu.
# Fonksiyon nesnesi yerine isim tutmak, yapılandırmanın (ve alt
# süreçlere gönderilen `ScanConfig`'in) picklable kalmasını sağlar.
VALIDATORS = {
    "tckn": validate_tckn,
    "credit_card": validate_credit_card,
    "iban": validate_iban,
    "tr_iban": validate_tr_iban,
    "jwt": validate_jwt,
    "base58check": validate_base58check,
    "email": validate_email,
    "phone_tr": validate_phone_tr,
    "luhn": luhn_check,
}
