"""Shannon entropy and generic secret-candidate detection.

The old `utils.calculate_entropy` called `str.count()` 256 times, i.e.
O(256*n) for every piece of text. This computes it in a single pass with
`Counter`, in O(n), and the function is actually put to use: entropy
catches API keys that have no named pattern (random 40-character strings
that do not start with `xoxb-` and friends).
"""

from __future__ import annotations

import math
import re
from collections import Counter

__all__ = [
    "shannon_entropy",
    "normalized_entropy",
    "is_high_entropy",
    "iter_secret_candidates",
    "SECRET_CONTEXT_RE",
]

_BASE64_CHARS = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_"
)
_HEX_CHARS = set("0123456789abcdefABCDEF")

# When a context word such as "token", "secret" or "api_key" appears on the
# same line we lower the entropy threshold: context cuts false positives
# dramatically.
#
# The last three alternatives are Turkish ("sifre" = password, "anahtar" =
# key, "parola" = passphrase). They are detection data, not prose: this
# scanner targets Turkish codebases, where secrets are routinely named in
# Turkish. Dropping them would blind the rule on its main audience, the
# same way dropping the TR national-ID validator would.
SECRET_CONTEXT_RE = re.compile(
    r"(?i)\b(secret|token|api[_-]?key|apikey|auth|bearer|credential|passwd|"
    r"password|private[_-]?key|access[_-]?key|client[_-]?secret|signature|"
    r"session|cookie|salt|sifre|anahtar|parola)\b"
)

# Candidate strings for entropy scanning: long enough, contiguous, no spaces.
_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/=_\-]{20,120}")

# Obvious "not a secret" shapes that entropy scanning should ignore.
_OBVIOUS_NOISE_RE = re.compile(
    r"(?i)^(?:"
    r"[0-9]+|"  # pure digits (date, size, id)
    r"[a-f0-9]{32}|"  # md5 - usually a checksum, not a secret
    r"(?:[a-z]+[_-]){2,}[a-z]+|"  # snake_case / kebab-case identifier
    r"[A-Za-z]+"  # a single word
    r")$"
)

#: Characters that separate identifier and path segments.
_SEGMENT_RE = re.compile(r"[_\-/=+]")

#: If an ascending/descending run of consecutive characters reaches this
#: length, the string is *ordered* rather than random.
_SEQUENTIAL_RUN = 6


def _has_sequential_run(token: str, length: int = _SEQUENTIAL_RUN) -> bool:
    """Does the token contain a sequential run such as ``abcdef`` or ``0123456789``?

    Alphabet and character-set constants (copies of
    ``string.ascii_letters``, base64/hex/base58 alphabets) carry the
    highest entropy possible by construction - every character occurs
    exactly once. That makes them the place where entropy is most likely
    to mistake a constant for a secret. A genuinely random secret, on the
    other hand, practically never contains a six-character run.
    """
    if len(token) < length:
        return False

    ascending = descending = 1
    # strict=False on purpose: `token[1:]` is one shorter by design.
    for previous, current in zip(token, token[1:], strict=False):
        step = ord(current) - ord(previous)
        ascending = ascending + 1 if step == 1 else 1
        descending = descending + 1 if step == -1 else 1
        if ascending >= length or descending >= length:
            return True
    return False


def _looks_like_identifier(token: str) -> bool:
    """Does the token look like a code identifier or a path?

    Strings such as ``return_when=FIRST_COMPLETED``,
    ``Qt_AlignmentFlag=AlignHCenter`` or ``usr/local/share`` split on
    separators into segments that are each either all letters or all
    digits. In a random secret at least one segment mixes the two
    (``K7MDENG``, ``AbCd1234``).

    The rule applies only to strings that **contain a separator**; a
    single-segment string may genuinely be random, so we leave that to
    entropy.
    """
    segments = [part for part in _SEGMENT_RE.split(token) if part]
    if len(segments) < 2:
        return False
    return all(part.isalpha() or part.isdigit() for part in segments)


def shannon_entropy(text: str) -> float:
    """Return the Shannon entropy of the text, in bits per character."""
    if not text:
        return 0.0
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length) for count in Counter(text).values()
    )


def normalized_entropy(text: str) -> float:
    """Normalize entropy into the 0..1 range.

    Scales by the size of the alphabet in use, so a hex string and a
    base64 string can be compared against the same threshold.
    """
    if not text:
        return 0.0
    alphabet = len(set(text))
    if alphabet < 2:
        return 0.0
    return shannon_entropy(text) / math.log2(alphabet)


def _charset_threshold(token: str, base: float) -> float:
    """Entropy threshold adjusted for the alphabet.

    A hex alphabet can carry at most 4 bits per character; base64 carries
    6. Applying one threshold to both means missing hex secrets entirely.
    """
    chars = set(token)
    if chars <= _HEX_CHARS:
        return min(base, 3.2)
    if chars <= _BASE64_CHARS:
        return base
    return base


def is_high_entropy(token: str, threshold: float = 4.0, min_length: int = 20) -> bool:
    """Does the string look like a randomly generated secret?"""
    if len(token) < min_length:
        return False
    if _OBVIOUS_NOISE_RE.match(token):
        return False
    # Long runs drawn from a single character class (aaaa..., 1111...)
    # are not secrets.
    if len(set(token)) <= 4:
        return False
    # The two most common false-positive classes when scanning source
    # code: alphabet constants and identifier/path expressions. Both are
    # high entropy yet not random, so they are filtered before entropy.
    if _has_sequential_run(token):
        return False
    if _looks_like_identifier(token):
        return False
    return shannon_entropy(token) >= _charset_threshold(token, threshold)


def iter_secret_candidates(line: str):
    """Yield entropy candidates in a line as ``(token, start, end)``."""
    for match in _CANDIDATE_RE.finditer(line):
        yield match.group(0), match.start(), match.end()
