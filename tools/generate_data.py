#!/usr/bin/env python3
"""Synthetic test data generator.

Every value produced here is **algorithmically valid but entirely
invented**; none of it belongs to a real person, account or service.
The point is to exercise the validators and performance behaviour
against realistic data.

The v3.0 version produced a single large text file and asked for its
size with `input()`, so it could not run in CI. This version takes
arguments and builds a directory tree.

Usage:
    python tools/generate_data.py --out demo_data
    python tools/generate_data.py --out demo_data --big 50   # +50 MB file
"""

from __future__ import annotations

import argparse
import os
import random
import zipfile

# --- valid value generators --------------------------------------------


def valid_tckn(rng: random.Random) -> str:
    """Generate a number that satisfies the TCKN algorithm."""
    digits = [rng.randint(1, 9)] + [rng.randint(0, 9) for _ in range(8)]
    check_10 = ((sum(digits[0:9:2]) * 7) - sum(digits[1:8:2])) % 10
    check_11 = (sum(digits) + check_10) % 10
    return "".join(map(str, digits)) + f"{check_10}{check_11}"


def valid_card(rng: random.Random, prefix: str = "4") -> str:
    """A card number that passes Luhn (Visa by default)."""
    body = [int(char) for char in prefix]
    body += [rng.randint(0, 9) for _ in range(15 - len(body))]

    checksum = 0
    double = True  # once the check digit is appended, the second-to-last doubles
    for digit in reversed(body):
        value = digit * 2 if double else digit
        checksum += value - 9 if value > 9 else value
        double = not double

    return "".join(map(str, body)) + str((10 - checksum % 10) % 10)


def valid_tr_iban(rng: random.Random) -> str:
    """Generate a Turkish IBAN that passes the mod 97-10 check."""
    body = "".join(str(rng.randint(0, 9)) for _ in range(22))
    # Convert the TR00<body> string to a number and compute the check digits.
    numeric = int(body + "2927" + "00")
    check = 98 - (numeric % 97)
    return f"TR{check:02d}{body}"


def invalid_tckn(rng: random.Random) -> str:
    """Eleven digits that fail the algorithm (false-positive bait)."""
    while True:
        candidate = str(rng.randint(10_000_000_000, 99_999_999_999))
        digits = [int(d) for d in candidate]
        check_10 = ((sum(digits[0:9:2]) * 7) - sum(digits[1:8:2])) % 10
        if digits[9] != check_10:
            return candidate


# --- file generators ---------------------------------------------------
_WORDS = ["lorem", "ipsum", "dolor", "sit", "amet", "consectetur", "security",
          "data", "analysis", "report", "customer", "record", "transaction",
          "system", "module", "service"]


def _noise(rng: random.Random, count: int = 10) -> str:
    return " ".join(rng.choices(_WORDS, k=count))


def write_customer_file(path: str, rng: random.Random, rows: int = 40):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("# Customer records (SYNTHETIC TEST DATA)\n")
        handle.write("national_id,phone,email,iban\n")
        for index in range(rows):
            handle.write(
                f"{valid_tckn(rng)},"
                f"05{rng.randint(10, 59)}{rng.randint(1000000, 9999999)},"
                f"user{index}@example-company.com,"
                f"{valid_tr_iban(rng)}\n"
            )


def write_payments_file(path: str, rng: random.Random, rows: int = 25):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("# Payment records (SYNTHETIC TEST DATA)\n")
        for _ in range(rows):
            brand_prefix = rng.choice(["4", "51", "52", "9792"])
            handle.write(
                f"Payment received: {valid_card(rng, brand_prefix)} "
                f"amount={rng.randint(50, 5000)}\n"
            )


def write_secrets_file(path: str, rng: random.Random):
    """Examples of credentials leaked into code (all invented)."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    aws_id = "AKIA" + "".join(rng.choices(alphabet, k=16))
    aws_secret = "".join(
        rng.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+", k=40)
    )
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(
            "# SYNTHETIC test configuration - none of this is real\n"
            f'AWS_ACCESS_KEY_ID = "{aws_id}"\n'
            f'aws_secret_access_key = "{aws_secret}"\n'
            f'DB_PASSWORD = "P4ssw0rd-{rng.randint(1000, 9999)}!"\n'
            "DATABASE_URL = "
            f'"postgresql://app:S3cr3t{rng.randint(100, 999)}@db.internal:5432/prod"\n'
            f'API_TOKEN = "{"".join(rng.choices(alphabet.lower() + alphabet, k=36))}"\n'
        )


def write_false_positive_file(path: str, rng: random.Random, rows: int = 30):
    """Values that match the regex but are invalid - validators must drop them."""
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("# False-positive bait: the regex matches, the algorithm does not\n")
        for _ in range(rows):
            handle.write(
                f"Invalid national ID entry: {invalid_tckn(rng)} | "
                f"order no: {rng.randint(10**15, 10**16 - 1)} | "
                f"{_noise(rng, 6)}\n"
            )
        handle.write("# These must be suppressed (allowlist or inline):\n")
        handle.write('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        handle.write("contact: support@example.com\n")
        handle.write(f'TEST_ID = "{valid_tckn(rng)}"  # sentinel:ignore\n')


def write_archive(path: str, rng: random.Random):
    """A nested ZIP, to exercise archive scanning."""
    inner = os.path.join(os.path.dirname(path), "_inner.zip")
    with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "deep/secret_notes.txt",
            f"Administrator ID: {valid_tckn(rng)}\nCard: {valid_card(rng)}\n",
        )
    try:
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(
                "hr/staff.csv",
                "national_id,name\n"
                + "\n".join(f"{valid_tckn(rng)},Employee{i}" for i in range(10)),
            )
            archive.write(inner, "nested_archive.zip")
    finally:
        if os.path.exists(inner):
            os.remove(inner)


def write_big_file(path: str, rng: random.Random, megabytes: int):
    """A large file for exercising streaming reads and performance.

    This file is **never committed**; it is in `.gitignore`. In v3.0 a
    52 MB copy of it made it into the repository.
    """
    target = megabytes * 1024 * 1024
    written = 0
    next_report = 10 * 1024 * 1024

    with open(path, "w", encoding="utf-8") as handle:
        while written < target:
            roll = rng.random()
            if roll < 0.02:
                line = f"Customer ID: {valid_tckn(rng)} confirmed."
            elif roll < 0.04:
                line = f"Payment: {valid_card(rng)} processed."
            elif roll < 0.08:
                line = f"Invalid ID: {invalid_tckn(rng)}"
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
        description="Generate synthetic test data for Sentinel."
    )
    parser.add_argument("--out", "-o", default="demo_data", help="Output directory")
    parser.add_argument(
        "--big",
        type=int,
        default=0,
        metavar="MB",
        help="Also generate a large text file of this size in MB (0 = none)",
    )
    parser.add_argument("--seed", type=int, default=None, help="For reproducibility")
    args = parser.parse_args()

    rng = random.Random(args.seed)
    out = args.out
    os.makedirs(os.path.join(out, "hr"), exist_ok=True)
    os.makedirs(os.path.join(out, "finance"), exist_ok=True)

    print(f"Generating synthetic data: {out}/")
    write_customer_file(os.path.join(out, "hr", "customers.csv"), rng)
    write_payments_file(os.path.join(out, "finance", "payments.txt"), rng)
    write_secrets_file(os.path.join(out, ".env.example"), rng)
    write_false_positive_file(os.path.join(out, "false_positives.txt"), rng)
    write_archive(os.path.join(out, "archive.zip"), rng)

    if args.big > 0:
        path = os.path.join(out, "big_test_data.txt")
        print(f"Generating a {args.big} MB file: {path}")
        write_big_file(path, rng, args.big)

    print("\nDone. Now try:")
    print(f"  sentinel scan {out} --format html --verbose")
    print("\nNOTE: the generated data is synthetic; do NOT commit it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
