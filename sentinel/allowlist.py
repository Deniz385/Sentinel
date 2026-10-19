"""Yanlış pozitif (false positive) yönetimi.

Bir DLP aracının kullanılıp kullanılmayacağını belirleyen asıl özellik bu:
ekip, test verisi yüzünden her taramada aynı 40 bulguyu görmeye devam
ederse aracı kapatır. Üç bastırma yolu sunulur:

1. **Yapılandırma**: yol glob'ları, birebir değerler, parmak izleri, regex.
2. **Satır içi**: ilgili satırda ``sentinel:ignore`` yorumu.
3. **Baz çizgisi (baseline)**: mevcut bulgular dondurulur, sadece yeni
   olanlar raporlanır (`sentinel scan --baseline`).
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
from dataclasses import dataclass, field

__all__ = [
    "Allowlist",
    "DEFAULT_ALLOWED_VALUES",
    "INLINE_IGNORE_RE",
    "path_matches",
]

#: Satırda bu işaret varsa o satırdaki bulgular bastırılır.
#: ``sentinel:ignore`` (tümü) veya ``sentinel:ignore=TC_KIMLIK,EMAIL``
INLINE_IGNORE_RE = re.compile(
    r"sentinel\s*:\s*ignore(?:\s*[=:]\s*([A-Za-z0-9_, \-]+))?", re.IGNORECASE
)

#: Belgelerde/örneklerde geçen, kesin olarak gerçek olmayan değerler.
DEFAULT_ALLOWED_VALUES = frozenset(
    {
        # AWS resmî dokümantasyon örnekleri
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        # Yaygın şablon/doldurma değerleri
        "changeme",
        "CHANGEME",
        "your_api_key_here",
        "YOUR_API_KEY",
        "xxxxxxxxxxxxxxxx",
        "placeholder",
        "example",
        "password",
        "secret",
        "SENIN_WEBHOOK_URL_ADRESIN_BURAYA",
    }
)

#: RFC 2606 / 6761 ile ayrılmış, gerçek trafik taşımayan alan adları.
_RESERVED_DOMAINS = (
    "@example.com",
    "@example.org",
    "@example.net",
    "@test",
    "@localhost",
    "@invalid",
)


@dataclass
class Allowlist:
    """Bastırma kuralları. Alt süreçlere gönderilebilmesi için picklable."""

    paths: tuple[str, ...] = ()
    values: tuple[str, ...] = ()
    fingerprints: tuple[str, ...] = ()
    patterns: tuple[str, ...] = ()
    rules: tuple[str, ...] = ()
    use_defaults: bool = True
    inline: bool = True
    _compiled: list = field(default_factory=list, repr=False, compare=False)

    def __post_init__(self):
        self.paths = tuple(self.paths)
        self.values = tuple(self.values)
        self.fingerprints = tuple(str(f).lower() for f in self.fingerprints)
        self.patterns = tuple(self.patterns)
        self.rules = tuple(r.upper() for r in self.rules)

    # -- kurulum ----------------------------------------------------------
    @classmethod
    def from_dict(cls, data: dict | None) -> Allowlist:
        data = data or {}
        return cls(
            paths=tuple(data.get("paths", ()) or ()),
            values=tuple(data.get("values", ()) or ()),
            fingerprints=tuple(data.get("fingerprints", ()) or ()),
            patterns=tuple(data.get("patterns", ()) or ()),
            rules=tuple(data.get("rules", ()) or ()),
            use_defaults=bool(data.get("use_defaults", True)),
            inline=bool(data.get("inline", True)),
        )

    def _regexes(self):
        if not self._compiled and self.patterns:
            # Derlemeyi tembel yap: pickle sırasında regex nesnesi taşınmaz.
            self._compiled = [re.compile(p) for p in self.patterns]
        return self._compiled

    def __getstate__(self):
        state = self.__dict__.copy()
        state["_compiled"] = []
        return state

    # -- sorgular ---------------------------------------------------------
    def allows_path(self, path: str) -> bool:
        """Dosya yolu tamamen taramadan muaf mı?"""
        return path_matches(path, self.paths)

    def allows_rule(self, rule: str) -> bool:
        return rule.upper() in self.rules

    def allows_value(self, value: str, fingerprint: str = "") -> bool:
        if fingerprint and fingerprint.lower() in self.fingerprints:
            return True
        if value in self.values:
            return True
        if self.use_defaults:
            if value in DEFAULT_ALLOWED_VALUES:
                return True
            lowered = value.lower()
            if any(lowered.endswith(domain) for domain in _RESERVED_DOMAINS):
                return True
        return any(regex.search(value) for regex in self._regexes())

    def inline_suppressed(self, line: str, rule: str) -> bool:
        """Satırda ``sentinel:ignore`` işareti var mı?"""
        if not self.inline or not line:
            return False
        match = INLINE_IGNORE_RE.search(line)
        if not match:
            return False
        scoped = match.group(1)
        if not scoped:
            return True
        wanted = {r.strip().upper() for r in scoped.split(",") if r.strip()}
        return rule.upper() in wanted


def path_matches(path: str, patterns) -> bool:
    """Yol, kalıplardan birine uyuyor mu?

    Kullanıcılar kalıpları depo köküne göre yazar (``tests/*``), ama
    taranan yol mutlak ya da ``./`` önekli olabilir. Düz `fnmatch` bu
    durumda **sessizce hiçbir şey yapmaz** — kullanıcı dosyaları dışladığını
    sanırken taranmaya devam ederler. Bu yüzden her kalıp yolun herhangi
    bir yerine de demirlenerek denenir.

    `exclude_globs` ve allowlist yolları aynı anlambilimi paylaşsın diye
    tek bir yerde toplanmıştır.
    """
    if not patterns:
        return False

    normalized = str(path).replace(os.sep, "/")
    if normalized.startswith("./"):
        normalized = normalized[2:]
    name = normalized.rsplit("/", 1)[-1]

    for raw in patterns:
        pattern = str(raw).replace(os.sep, "/").rstrip("/")
        if pattern.startswith("./"):
            pattern = pattern[2:]
        if not pattern:
            continue

        candidates = [pattern, f"*/{pattern}"]
        # "tests/**" kalıbı dizinin kendisini de kapsamalı; böylece
        # `os.walk` o dala hiç girmez.
        bare = pattern.removesuffix("/**").removesuffix("/*")
        if bare != pattern:
            candidates += [bare, f"*/{bare}"]

        if any(fnmatch.fnmatch(normalized, candidate) for candidate in candidates):
            return True
        if fnmatch.fnmatch(name, pattern):
            return True
        # Sade dizin adı ("test_data") yolun herhangi bir yerinde geçiyorsa.
        if "*" not in pattern and "?" not in pattern:
            if f"/{pattern}/" in f"/{normalized}/":
                return True
    return False


def load_baseline(path: str) -> set[str]:
    """Baz çizgisi dosyasından bastırılacak parmak izlerini okur."""
    if not path or not os.path.exists(path):
        return set()
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    entries = (
        data.get("findings", data.get("fingerprints", []))
        if isinstance(data, dict)
        else data
    )
    result = set()
    for entry in entries:
        if isinstance(entry, str):
            result.add(entry.lower())
        elif isinstance(entry, dict):
            key = entry.get("fingerprint") or entry.get("id")
            if key:
                result.add(str(key).lower())
    return result


def save_baseline(path: str, findings) -> int:
    """Mevcut bulguları baz çizgisi olarak dondurur."""
    payload = {
        "version": 1,
        "note": "Bu dosyadaki parmak izleri raporlarda bastırılır.",
        "findings": sorted(
            {f.fingerprint for f in findings if getattr(f, "fingerprint", "")}
        ),
    }
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
    return len(payload["findings"])
