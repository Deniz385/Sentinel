"""Masking and fingerprint generation.

By policy there must be **no cleartext sensitive data** in reports, logs
or webhook payloads. Masking alone is not enough, though: telling that
the same credit card appears in three different files requires
correlation. We do that without leaking the value, via an HMAC-SHA256
fingerprint.
"""

from __future__ import annotations

import hashlib
import hmac

__all__ = ["mask_data", "fingerprint", "redact_snippet", "SNIPPET_WIDTH"]

SNIPPET_WIDTH = 60


def mask_data(data: str, keep: int = 2) -> str:
    """Mask sensitive data: ``12345678901`` -> ``12*******01``.

    Very short values (<= 2*keep) are starred out completely, because
    showing their first and last characters would reveal the whole thing.
    """
    if not data:
        return ""
    data = str(data)
    if len(data) <= keep * 2:
        return "*" * len(data)
    return f"{data[:keep]}{'*' * (len(data) - keep * 2)}{data[-keep:]}"


def fingerprint(value: str, salt: str = "", length: int = 16) -> str:
    """An irreversible identity for a value.

    With a `salt` this uses HMAC, so the same value yields a different
    fingerprint at different organizations and cannot be reversed with a
    rainbow table. With an empty salt it falls back to plain SHA-256.
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
    """Give the context around a finding, with the finding itself masked.

    Context is essential so an analyst can answer "why did this fire?"
    from the report alone - but **no** sensitive value in that context
    may be left in the clear. When `spans` is given, all of those ranges
    are masked.
    """
    if not line:
        return ""

    # Mask EVERY sensitive value on the line, not only the one in focus.
    # Otherwise, on a CSV row like "card,iban,id", the card finding's
    # snippet exposes the IBAN and the IBAN finding's snippet exposes the
    # card - the report leaks nearly all of the data it claims to protect.
    targets = list(spans) if spans else []
    if (start, end) not in targets:
        targets.append((start, end))

    # `mask_data` preserves length, so replacing in place introduces no
    # shift; we still verify the length defensively.
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
