#!/usr/bin/env python3
"""Sentetik test verisi üreteci.

Üretilen tüm değerler **algoritmik olarak doğru ama tamamen uydurma**dır;
hiçbiri gerçek bir kişiye, hesaba ya da servise ait değildir. Amaç
doğrulayıcıların ve performans davranışının gerçekçi veriyle sınanması.

v3.0'daki sürüm yalnızca tek bir büyük metin dosyası üretiyor ve boyutu
`input()` ile soruyordu — yani CI'da çalıştırılamıyordu. Bu sürüm
argümanla çalışır ve bir klasör ağacı kurar.

Kullanım:
    python tools/generate_data.py --out demo_veri
    python tools/generate_data.py --out demo_veri --big 50   # +50 MB dosya
"""

from __future__ import annotations

import argparse
import os
import random
import zipfile

# --- geçerli değer üreteçleri ------------------------------------------


def valid_tckn(rng: random.Random) -> str:
    """TCKN algoritmasına uygun numara üretir."""
    digits = [rng.randint(1, 9)] + [rng.randint(0, 9) for _ in range(8)]
    check_10 = ((sum(digits[0:9:2]) * 7) - sum(digits[1:8:2])) % 10
    check_11 = (sum(digits) + check_10) % 10
    return "".join(map(str, digits)) + f"{check_10}{check_11}"


def valid_card(rng: random.Random, prefix: str = "4") -> str:
    """Luhn'u geçen kart numarası (varsayılan: Visa)."""
    body = [int(char) for char in prefix]
    body += [rng.randint(0, 9) for _ in range(15 - len(body))]

    checksum = 0
    double = True  # son hane eklenince sondan ikinci 'double' olur
    for digit in reversed(body):
        value = digit * 2 if double else digit
        checksum += value - 9 if value > 9 else value
        double = not double

    return "".join(map(str, body)) + str((10 - checksum % 10) % 10)


def valid_tr_iban(rng: random.Random) -> str:
    """Mod 97-10 kontrolünü geçen TR IBAN üretir."""
    body = "".join(str(rng.randint(0, 9)) for _ in range(22))
    # TR00<body> dizesini sayıya çevirip kontrol hanelerini hesapla.
    numeric = int(body + "2927" + "00")
    check = 98 - (numeric % 97)
    return f"TR{check:02d}{body}"


def invalid_tckn(rng: random.Random) -> str:
    """11 haneli ama algoritmayı geçmeyen numara (yanlış pozitif yemi)."""
    while True:
        candidate = str(rng.randint(10_000_000_000, 99_999_999_999))
        digits = [int(d) for d in candidate]
        check_10 = ((sum(digits[0:9:2]) * 7) - sum(digits[1:8:2])) % 10
        if digits[9] != check_10:
            return candidate


# --- dosya üreteçleri --------------------------------------------------
_WORDS = ["lorem", "ipsum", "dolor", "sit", "amet", "consectetur", "guvenlik", "veri", "analiz", "rapor", "musteri", "kayit", "islem", "sistem", "modul", "servis"]


def _noise(rng: random.Random, count: int = 10) -> str:
    return " ".join(rng.choices(_WORDS, k=count))


def write_customer_file(path: str, rng: random.Random, rows: int = 40):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("# Müşteri kayıtları (SENTETİK TEST VERİSİ)\n")
        handle.write("tckn,telefon,eposta,iban\n")
        for index in range(rows):
            handle.write(
                f"{valid_tckn(rng)},"
                f"05{rng.randint(10, 59)}{rng.randint(1000000, 9999999)},"
                f"kullanici{index}@ornek-firma.com.tr,"
                f"{valid_tr_iban(rng)}\n"
            )


def write_payments_file(path: str, rng: random.Random, rows: int = 25):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("# Ödeme kayıtları (SENTETİK TEST VERİSİ)\n")
        for _ in range(rows):
            brand_prefix = rng.choice(["4", "51", "52", "9792"])
            handle.write(
                f"Ödeme alındı: {valid_card(rng, brand_prefix)} "
                f"tutar={rng.randint(50, 5000)}₺\n"
            )


def write_secrets_file(path: str, rng: random.Random):
    """Koda sızmış kimlik bilgisi örnekleri (hepsi uydurma)."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    aws_id = "AKIA" + "".join(rng.choices(alphabet, k=16))
    aws_secret = "".join(
        rng.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+", k=40)
    )
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(
            "# SENTETİK test yapılandırması — hiçbiri gerçek değildir\n"
            f'AWS_ACCESS_KEY_ID = "{aws_id}"\n'
            f'aws_secret_access_key = "{aws_secret}"\n'
            f'DB_PASSWORD = "P4ssw0rd-{rng.randint(1000, 9999)}!"\n'
            "DATABASE_URL = "
            f'"postgresql://app:S3cr3t{rng.randint(100, 999)}@db.internal:5432/prod"\n'
            f'API_TOKEN = "{"".join(rng.choices(alphabet.lower() + alphabet, k=36))}"\n'
        )


def write_false_positive_file(path: str, rng: random.Random, rows: int = 30):
    """Regex'e uyan ama geçersiz değerler — doğrulayıcı bunları elemeli."""
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("# Yanlış pozitif yemi: regex uyar, algoritma tutmaz\n")
        for _ in range(rows):
            handle.write(
                f"Hatalı TC girişi: {invalid_tckn(rng)} | "
                f"sipariş no: {rng.randint(10**15, 10**16 - 1)} | "
                f"{_noise(rng, 6)}\n"
            )
        handle.write("# Bunlar bastırılmalı (allowlist / satır içi):\n")
        handle.write('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        handle.write("iletisim: destek@example.com\n")
        handle.write(f'TEST_TC = "{valid_tckn(rng)}"  # sentinel:ignore\n')


def write_archive(path: str, rng: random.Random):
    """İç içe ZIP: arşiv taramasını sınar."""
    inner = os.path.join(os.path.dirname(path), "_ic.zip")
    with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "derin/gizli_notlar.txt",
            f"Yönetici TC: {valid_tckn(rng)}\nKart: {valid_card(rng)}\n",
        )
    try:
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(
                "ik/personel.csv",
                "tckn,ad\n" + "\n".join(f"{valid_tckn(rng)},Personel{i}" for i in range(10)),
            )
            archive.write(inner, "arsiv_icinde.zip")
    finally:
        if os.path.exists(inner):
            os.remove(inner)


def write_big_file(path: str, rng: random.Random, megabytes: int):
    """Akışlı okuma ve performansı sınamak için büyük dosya.

    Bu dosya **asla commit edilmez**; `.gitignore` içindedir. v3.0'da
    52 MB'lık bir kopyası depoya girmişti.
    """
    target = megabytes * 1024 * 1024
    written = 0
    next_report = 10 * 1024 * 1024

    with open(path, "w", encoding="utf-8") as handle:
        while written < target:
            roll = rng.random()
            if roll < 0.02:
                line = f"Müşteri TC: {valid_tckn(rng)} onaylandı."
            elif roll < 0.04:
                line = f"Ödeme: {valid_card(rng)} işlendi."
            elif roll < 0.08:
                line = f"Hatalı TC: {invalid_tckn(rng)}"
            else:
                line = _noise(rng, 12)
            line += "\n"
            handle.write(line)
            written += len(line.encode("utf-8"))

            if written >= next_report:
                print(f"  {written / 1024 / 1024:.0f} MB…")
                next_report += 10 * 1024 * 1024


# ----------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(
        description="Sentinel için sentetik test verisi üretir."
    )
    parser.add_argument("--out", "-o", default="demo_veri", help="Çıktı dizini")
    parser.add_argument(
        "--big",
        type=int,
        default=0,
        metavar="MB",
        help="Ek olarak bu boyutta büyük bir metin dosyası üret (0 = üretme)",
    )
    parser.add_argument("--seed", type=int, default=None, help="Tekrarlanabilirlik için")
    args = parser.parse_args()

    rng = random.Random(args.seed)
    out = args.out
    os.makedirs(os.path.join(out, "ik"), exist_ok=True)
    os.makedirs(os.path.join(out, "finans"), exist_ok=True)

    print(f"Sentetik veri üretiliyor: {out}/")
    write_customer_file(os.path.join(out, "ik", "musteriler.csv"), rng)
    write_payments_file(os.path.join(out, "finans", "odemeler.txt"), rng)
    write_secrets_file(os.path.join(out, ".env.ornek"), rng)
    write_false_positive_file(os.path.join(out, "yanlis_pozitif.txt"), rng)
    write_archive(os.path.join(out, "arsiv.zip"), rng)

    if args.big > 0:
        path = os.path.join(out, "big_test_data.txt")
        print(f"{args.big} MB'lık dosya üretiliyor: {path}")
        write_big_file(path, rng, args.big)

    print("\nTamam. Şimdi deneyin:")
    print(f"  sentinel scan {out} --format html --verbose")
    print("\nNOT: Üretilen veriler sentetiktir; depoya commit ETMEYİN.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
