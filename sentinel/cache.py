"""Artımlı tarama önbelleği.

Her gece 500 GB'lık bir dosya paylaşımını baştan taramak, o paylaşımın
%99'u değişmemişken, harcanan sürenin neredeyse tamamının israf olduğu
anlamına gelir. Burada tutulan ``(yol → mtime_ns, boyut, bulgular)``
kaydı değişmemiş dosyaları tekrar okumadan geçer.

Bir güvenlik aracında önbellek, yanlış kullanıldığında **sızıntıyı
görünmez yapan** bir mekanizmadır. Bu yüzden üç kural:

1. **Yapılandırma veya kural kataloğu değişirse önbellek tamamen
   düşer.** Yeni bir kural eklendiğinde eski kararların geçerliliği
   kalmaz; tek bir bayat kayıt, yeni kuralın bulacağı sırrı gizler.
2. **Hata kayıtları önbelleğe alınmaz.** Geçici bir okuma hatası
   (kilitli dosya, ağ kesintisi) dosyayı sonsuza kadar görünmez
   yapmamalı.
3. **Karantina açıkken önbellek hiç kullanılmaz** (motor tarafından
   uygulanır): veri silen bir karara bayat kanıtla varılmaz.

Tazelik ölçütü ``(st_mtime_ns, st_size)``. Bu bir sezgidir, kanıt değil:
mtime'ı elle geri alan bir saldırgan dosyayı atlatabilir. Adli bilişim
kesinliği gerektiğinde önbellek kullanılmaz (varsayılan: kapalı).
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field

from sentinel import __version__

__all__ = [
    "ScanCache",
    "DEFAULT_CACHE_NAME",
    "CACHE_SCHEMA",
    "config_fingerprint",
    "clear_cache",
]

DEFAULT_CACHE_NAME = ".sentinel-cache.json"

#: Biçim sürümü. Artırıldığında eski önbellekler sessizce yok sayılır.
CACHE_SCHEMA = 1

#: Önbellekte tutulan azami kayıt. Aşıldığında en eski görülenler atılır
#: (önbellek dosyası sınırsız büyüyemez).
MAX_ENTRIES = 200_000

#: Sonuçları **etkilemeyen** ayarlar: bunlar değiştiğinde önbellek geçerli
#: kalır. Geri kalan her alan parmak izine girer — şüphede kalındığında
#: önbelleği düşürmek, bir bulguyu kaçırmaktan iyidir.
_IRRELEVANT_FIELDS = frozenset(
    {
        "target",
        "workers",
        "executor",
        "audit_log",
        "webhook_url",
        "webhook_min_severity",
        "webhook_batch",
        "quarantine",
        "quarantine_dir",
        "quarantine_min_severity",
        "shred_original",
        "incremental",
        "cache_path",
        "baseline_path",
    }
)


def _yara_signature(config) -> list:
    """`rules/*.yar` dosyalarının imzası.

    YARA kuralları da tıpkı desen kataloğu gibi kararları belirler.
    Yapılandırmada yalnızca *dizin yolu* duruyor, bu yüzden bir kural
    dosyasını düzenlemek fingerprint'i değiştirmez ve yeni kuralın
    bulacağı şey önbelleğin arkasında kalırdı. Dosyaları okumaya gerek
    yok: ad + mtime + boyut yeterli bir imzadır.
    """
    if not config.yara_enabled:
        return []
    directory = config.yara_rules_dir or ""
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        return []

    signature = []
    for name in names:
        if not name.lower().endswith((".yar", ".yara")):
            continue
        try:
            info = os.stat(os.path.join(directory, name))
        except OSError:
            continue
        signature.append([name, info.st_mtime_ns, info.st_size])
    return signature


def config_fingerprint(config) -> str:
    """Yapılandırma + kural kataloğu + sürüm için kararlı özet.

    Sürüm de dâhil: bir yükseltme doğrulayıcıları ya da entropi
    buluşsallarını değiştirmiş olabilir, bu yüzden yeni sürüm eski
    kararları devralmaz.
    """
    from sentinel.patterns import PATTERN_DEFS

    payload = {
        key: value
        for key, value in sorted(config.to_dict().items())
        if key not in _IRRELEVANT_FIELDS
    }
    catalog = [
        (definition.name, definition.regex.pattern, definition.severity.value)
        for definition in PATTERN_DEFS
    ]
    blob = json.dumps(
        {
            "version": __version__,
            "config": payload,
            "catalog": catalog,
            "yara": _yara_signature(config),
        },
        sort_keys=True,
        ensure_ascii=False,
        default=str,
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:32]


@dataclass
class CacheStats:
    hits: int = 0
    misses: int = 0
    stale: int = 0

    def as_dict(self) -> dict:
        return {"hits": self.hits, "misses": self.misses, "stale": self.stale}


@dataclass
class ScanCache:
    """Diskteki artımlı tarama kaydı."""

    path: str
    config_hash: str
    entries: dict = field(default_factory=dict)
    stats: CacheStats = field(default_factory=CacheStats)
    #: Yüklenen önbellek bu çalıştırmanın yapılandırmasıyla uyuşmadı mı?
    invalidated: bool = False

    # ------------------------------------------------------------------
    @classmethod
    def open(cls, path: str, config) -> ScanCache:
        """Önbelleği okur; uyumsuz ya da bozuksa boş başlar."""
        fingerprint = config_fingerprint(config)
        cache = cls(path=path, config_hash=fingerprint)

        try:
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            # Yok, okunamıyor ya da bozuk: boş önbellek tam tarama demektir.
            return cache

        if not isinstance(data, dict):
            return cache
        if data.get("schema") != CACHE_SCHEMA:
            return cache
        if data.get("config_hash") != fingerprint:
            # Kurallar ya da ayarlar değişti: tüm kayıtlar geçersiz.
            cache.invalidated = True
            return cache

        entries = data.get("entries")
        if isinstance(entries, dict):
            cache.entries = {
                key: value
                for key, value in entries.items()
                if isinstance(value, dict)
            }
        return cache

    # ------------------------------------------------------------------
    @staticmethod
    def _key(path: str) -> str:
        return os.path.abspath(path).replace(os.sep, "/")

    def lookup(self, path: str):
        """Dosya değişmemişse önbellekten `FileReport` üretir, yoksa `None`."""
        from sentinel.engine import FileReport
        from sentinel.findings import Finding

        entry = self.entries.get(self._key(path))
        if entry is None:
            self.stats.misses += 1
            return None

        try:
            info = os.stat(path)
        except OSError:
            self.stats.misses += 1
            return None

        if entry.get("mtime_ns") != info.st_mtime_ns or entry.get("size") != info.st_size:
            self.stats.stale += 1
            return None

        try:
            findings = [Finding.from_dict(item) for item in entry.get("findings", [])]
        except (TypeError, ValueError):
            # Kayıt bozuksa önbelleği değil dosyayı tekrar tara.
            self.stats.misses += 1
            return None

        self.stats.hits += 1
        return FileReport(
            path=path,
            findings=findings,
            skipped=entry.get("skipped", ""),
            size=int(entry.get("size") or 0),
            sha256=entry.get("sha256", "N/A"),
            cached=True,
        )

    def remember(self, report) -> None:
        """Taze bir tarama sonucunu kaydeder."""
        if report.error:
            # Geçici bir hata dosyayı kalıcı olarak görünmez yapmasın.
            return
        if report.cached:
            return
        try:
            info = os.stat(report.path)
        except OSError:
            return

        self.entries[self._key(report.path)] = {
            "mtime_ns": info.st_mtime_ns,
            "size": info.st_size,
            "sha256": report.sha256,
            "skipped": report.skipped,
            "last_seen": int(time.time()),
            "findings": [finding.to_dict() for finding in report.findings],
        }

    # ------------------------------------------------------------------
    def save(self) -> bool:
        """Önbelleği atomik olarak yazar. Başarısızlık taramayı düşürmez."""
        entries = self.entries
        if len(entries) > MAX_ENTRIES:
            newest = sorted(
                entries.items(),
                key=lambda item: item[1].get("last_seen", 0),
                reverse=True,
            )[:MAX_ENTRIES]
            entries = dict(newest)

        payload = {
            "schema": CACHE_SCHEMA,
            "config_hash": self.config_hash,
            "written_at": int(time.time()),
            "entries": entries,
        }

        directory = os.path.dirname(os.path.abspath(self.path))
        temporary = f"{self.path}.tmp"
        try:
            if directory:
                os.makedirs(directory, exist_ok=True)
            with open(temporary, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False)
            os.replace(temporary, self.path)
            return True
        except OSError:
            # Yarım yazılmış bir önbellek, bozuk bir önbellekten iyidir:
            # geçici dosyayı temizle ve sessizce vazgeç.
            try:
                os.unlink(temporary)
            except OSError:
                pass
            return False


def clear_cache(path: str) -> bool:
    """Önbellek dosyasını siler. Yoksa `False` döner."""
    try:
        os.unlink(path)
        return True
    except OSError:
        return False
