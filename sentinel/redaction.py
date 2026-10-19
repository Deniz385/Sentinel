"""Maskeleme ve parmak izi üretimi.

Yönerge gereği rapor, log ve webhook yüklerinde **açık hassas veri
bulunmamalıdır**. Ancak maskeleme tek başına yetmez: aynı kredi kartının üç
farklı dosyada geçtiğini anlamak için korelasyon gerekir. Bunu, veriyi
sızdırmadan, HMAC-SHA256 parmak izi ile yaparız.
"""

from __future__ import annotations

import hashlib
import hmac

__all__ = ["mask_data", "fingerprint", "redact_snippet", "SNIPPET_WIDTH"]

SNIPPET_WIDTH = 60


def mask_data(data: str, keep: int = 2) -> str:
    """Hassas veriyi maskeler: ``12345678901`` -> ``12*******01``.

    Çok kısa veriler (<= 2*keep) tamamen yıldızlanır, çünkü baş ve son
    karakterleri göstermek verinin tamamını açığa çıkarırdı.
    """
    if not data:
        return ""
    data = str(data)
    if len(data) <= keep * 2:
        return "*" * len(data)
    return f"{data[:keep]}{'*' * (len(data) - keep * 2)}{data[-keep:]}"


def fingerprint(value: str, salt: str = "", length: int = 16) -> str:
    """Değerin geri döndürülemez kimliği.

    `salt` verildiğinde HMAC kullanılır; böylece aynı değer farklı
    kurumlarda farklı parmak izi üretir ve hazır tablo (rainbow table)
    saldırısıyla çözülemez. Salt boşsa düz SHA-256 kullanılır.
    """
    value = str(value)
    if salt:
        digest = hmac.new(
            salt.encode("utf-8"), value.encode("utf-8"), hashlib.sha256
        ).hexdigest()
    else:
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return digest[:length]


def redact_snippet(
    line: str,
    start: int,
    end: int,
    width: int = SNIPPET_WIDTH,
    spans: list | tuple | None = None,
) -> str:
    """Bulgunun etrafındaki bağlamı, bulgunun kendisi maskelenmiş olarak verir.

    Analist "bu neden tetiklendi?" sorusunu rapora bakarak cevaplayabilsin
    diye bağlam şart; ama bağlamdaki **hiçbir** hassas değer açıkta
    kalmamalı. `spans` verildiğinde o aralıkların hepsi maskelenir.
    """
    if not line:
        return ""

    # Satırdaki TÜM hassas değerleri maskele, yalnızca odaktakini değil.
    # Aksi hâlde "kart,IBAN,TC" gibi bir CSV satırında kart bulgusunun
    # alıntısı IBAN'ı, IBAN bulgusunun alıntısı kartı açıkta bırakır —
    # rapor, koruduğunu iddia ettiği verinin neredeyse tamamını sızdırır.
    targets = list(spans) if spans else []
    if (start, end) not in targets:
        targets.append((start, end))

    # `mask_data` uzunluğu korur, bu yüzden yerinde değiştirmek kaydırma
    # yaratmaz; yine de savunmacı davranıp uzunluğu doğruluyoruz.
    chars = list(line)
    for span_start, span_end in targets:
        span_start = max(0, span_start)
        span_end = min(len(line), span_end)
        if span_start >= span_end:
            continue
        masked = mask_data(line[span_start:span_end])
        if len(masked) != span_end - span_start:
            masked = "*" * (span_end - span_start)
        chars[span_start:span_end] = masked

    redacted = "".join(chars)
    before = redacted[max(0, start - width) : start]
    focus = redacted[start:end]
    after = redacted[end : end + width]
    prefix = "…" if start - width > 0 else ""
    suffix = "…" if end + width < len(line) else ""
    return f"{prefix}{before}{focus}{after}{suffix}".strip()
