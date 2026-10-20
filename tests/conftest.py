"""Paylaşılan test araçları."""

from __future__ import annotations

import os
import sys

import pytest

# Depoyu kurulum yapmadan da test edebilmek için kök dizini yola ekle.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sentinel.config import ScanConfig  # noqa: E402
from sentinel.severity import Severity  # noqa: E402

#: Algoritmik olarak GEÇERLİ test değerleri. Gerçek kişilere ait değildir;
#: `tools/generate_data.py` ile aynı yöntemle üretilmiştir.
VALID_TCKN = "10000000146"
VALID_VISA = "4111111111111111"
VALID_MASTERCARD = "5555555555554444"
VALID_TR_IBAN = "TR330006100519786457841326"
VALID_DE_IBAN = "DE89370400440532013000"
VALID_BTC = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"

#: Regex'e uyan ama algoritmayı GEÇMEYEN değerler (yanlış pozitif testleri).
INVALID_TCKN = "12345678901"
INVALID_CARD = "1234567812345678"
INVALID_IBAN = "TR330006100519786457841327"


@pytest.fixture
def config():
    """Testler için belirlenimci (deterministik) yapılandırma.

    Entropi taraması ve YARA kapalı: bu testler desen davranışını ölçer,
    eklentilerin varlığına göre sonuç değişmemeli.
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
    """Dosya ağacı kurmak için yardımcı."""

    def build(files: dict):
        for name, content in files.items():
            path = tmp_path / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                path.write_bytes(content)
            else:
                # Metin bile olsa bayt olarak yaz: `write_text` Windows'ta
                # `\n` -> `\r\n` çevirisi yapar ve dosya baytları testin
                # beklediğinden farklı olur. Hash ve bayt karşılaştırması
                # yapan testler yalnızca Windows'ta düşer.
                path.write_bytes(content.encode("utf-8"))
        return tmp_path

    return build
