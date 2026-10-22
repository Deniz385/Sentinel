"""Shared test helpers."""

from __future__ import annotations

import os
import sys

import pytest

# Add the repository root to the path so tests run without installing.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sentinel.config import ScanConfig  # noqa: E402
from sentinel.severity import Severity  # noqa: E402

#: Algorithmically VALID test values. They belong to no real person;
#: they are produced the same way as in `tools/generate_data.py`.
VALID_TCKN = "10000000146"
VALID_VISA = "4111111111111111"
VALID_MASTERCARD = "5555555555554444"
VALID_TR_IBAN = "TR330006100519786457841326"
VALID_DE_IBAN = "DE89370400440532013000"
VALID_BTC = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"

#: Values that match the regex but FAIL the algorithm (false-positive tests).
INVALID_TCKN = "12345678901"
INVALID_CARD = "1234567812345678"
INVALID_IBAN = "TR330006100519786457841327"


@pytest.fixture
def config():
    """A deterministic configuration for tests.

    Entropy scanning and YARA are off: these tests measure pattern
    behaviour, and results must not depend on which extras happen to be
    installed.
    """
    return ScanConfig(
        min_severity=Severity.INFO.value,
        entropy_scan=False,
        yara_enabled=False,
        workers=1,
        executor="serial",
    )


@pytest.fixture
def tree(tmp_path):
    """Helper for building a file tree."""

    def build(files: dict):
        for name, content in files.items():
            path = tmp_path / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                path.write_bytes(content)
            else:
                # Write bytes even for text: on Windows `write_text`
                # translates `\n` to `\r\n`, so the file bytes differ
                # from what the test expects. Tests that compare hashes
                # or bytes would then fail on Windows only.
                path.write_bytes(content.encode("utf-8"))
        return tmp_path

    return build
