"""Shannon entropisi ve generic sır (secret) adayı tespiti.

Eski `utils.calculate_entropy` 256 kez `str.count()` çağırıyordu — yani her
metin için O(256·n). Burada tek geçişte `Counter` ile O(n) hesaplanır ve
fonksiyon gerçekten kullanılır: adlandırılmış deseni olmayan API
anahtarlarını (`xoxb-...` olmayan rastgele 40 hane) entropi yakalar.
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

# "token", "secret", "api_key" gibi bir bağlam kelimesi aynı satırdaysa
# entropi eşiğini düşürürüz: bağlam, yanlış pozitifi büyük ölçüde keser.
SECRET_CONTEXT_RE = re.compile(
    r"(?i)\b(secret|token|api[_-]?key|apikey|auth|bearer|credential|passwd|"
    r"password|private[_-]?key|access[_-]?key|client[_-]?secret|signature|"
    r"session|cookie|salt|sifre|anahtar|parola)\b"
)

# Entropi taraması için aday dizgeler: yeterince uzun, tek parça, ayraçsız.
_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/=_\-]{20,120}")

# Entropi taramasının görmezden geleceği belirgin "sır değil" kalıpları.
_OBVIOUS_NOISE_RE = re.compile(
    r"(?i)^(?:"
    r"[0-9]+|"  # salt sayı (tarih, boyut, id)
    r"[a-f0-9]{32}|"  # md5 — çoğunlukla checksum, sır değil
    r"(?:[a-z]+[_-]){2,}[a-z]+|"  # snake_case / kebab-case kimlik
    r"[A-Za-z]+"  # tek kelime
    r")$"
)

#: Kimlik/yol parçalarını ayıran karakterler.
_SEGMENT_RE = re.compile(r"[_\-/=+]")

#: Artan/azalan ardışık karakter dizisi bu uzunluğa ulaşırsa, dizge
#: rastgele değil *sıralı* demektir.
_SEQUENTIAL_RUN = 6


def _has_sequential_run(token: str, length: int = _SEQUENTIAL_RUN) -> bool:
    """``abcdef`` / ``0123456789`` gibi sıralı bir dizi içeriyor mu?

    Alfabe ve karakter kümesi sabitleri (``string.ascii_letters``
    kopyaları, base64/hex/base58 alfabeleri) tanım gereği mümkün olan en
    yüksek entropiye sahiptir — her karakter tam bir kez geçer. Yani
    entropi onları sır sanmaya en yatkın olduğu yerdir. Rastgele üretilmiş
    gerçek bir sır ise altı karakterlik ardışık bir diziyi pratikte hiç
    içermez.
    """
    if len(token) < length:
        return False

    ascending = descending = 1
    # strict=False bilinçli: `token[1:]` tasarım gereği bir kısa.
    for previous, current in zip(token, token[1:], strict=False):
        step = ord(current) - ord(previous)
        ascending = ascending + 1 if step == 1 else 1
        descending = descending + 1 if step == -1 else 1
        if ascending >= length or descending >= length:
            return True
    return False


def _looks_like_identifier(token: str) -> bool:
    """Kod kimliği ya da yol gibi mi görünüyor?

    ``return_when=FIRST_COMPLETED``, ``Qt_AlignmentFlag=AlignHCenter``,
    ``usr/local/share`` gibi dizgeler ayraçla bölündüğünde her parçası ya
    tamamen harf ya tamamen rakamdır. Rastgele bir sırda ise en az bir
    parça harf ve rakamı birlikte taşır (``K7MDENG``, ``AbCd1234``).

    Kural yalnızca **ayraç içeren** dizgelere uygulanır; tek parça bir
    dizge gerçekten rastgele olabilir, onu entropiye bırakırız.
    """
    segments = [part for part in _SEGMENT_RE.split(token) if part]
    if len(segments) < 2:
        return False
    return all(part.isalpha() or part.isdigit() for part in segments)


def shannon_entropy(text: str) -> float:
    """Metnin Shannon entropisini (bit/karakter) döndürür."""
    if not text:
        return 0.0
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length) for count in Counter(text).values()
    )


def normalized_entropy(text: str) -> float:
    """Entropiyi 0..1 aralığına normalize eder.

    Kullanılan alfabenin boyutuna göre ölçekler; böylece hex bir dizge ile
    base64 bir dizge aynı eşikle karşılaştırılabilir.
    """
    if not text:
        return 0.0
    alphabet = len(set(text))
    if alphabet < 2:
        return 0.0
    return shannon_entropy(text) / math.log2(alphabet)


def _charset_threshold(token: str, base: float) -> float:
    """Alfabeye göre entropi eşiği.

    Hex alfabesi en fazla 4 bit/karakter taşıyabilir; base64 ise 6. Aynı
    eşiği ikisine uygulamak hex sırlarını tamamen kaçırmak demektir.
    """
    chars = set(token)
    if chars <= _HEX_CHARS:
        return min(base, 3.2)
    if chars <= _BASE64_CHARS:
        return base
    return base


def is_high_entropy(token: str, threshold: float = 4.0, min_length: int = 20) -> bool:
    """Dizge, rastgele üretilmiş bir sır gibi mi görünüyor?"""
    if len(token) < min_length:
        return False
    if _OBVIOUS_NOISE_RE.match(token):
        return False
    # Tek karakter sınıfından oluşan uzun diziler (aaaa..., 1111...) sır değil.
    if len(set(token)) <= 4:
        return False
    # Kaynak kodu taranırken en sık gelen iki yanlış pozitif sınıfı:
    # alfabe sabitleri ve kimlik/yol ifadeleri. İkisi de yüksek entropilidir
    # ama rastgele değildir; entropiden önce elenirler.
    if _has_sequential_run(token):
        return False
    if _looks_like_identifier(token):
        return False
    return shannon_entropy(token) >= _charset_threshold(token, threshold)


def iter_secret_candidates(line: str):
    """Satırdaki entropi adaylarını `(token, start, end)` olarak üretir."""
    for match in _CANDIDATE_RE.finditer(line):
        yield match.group(0), match.start(), match.end()
