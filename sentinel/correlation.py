"""Çapraz dosya korelasyonu: bulgu sayısından **tekil sır** sayısına.

Bir tarama "207 bulgu" diyorsa analist 207 ayrı iş olduğunu sanır. Oysa
aynı AWS anahtarı 40 dosyaya kopyalanmış olabilir — o 40 bulgu **tek bir
iptal işlemiyle** kapanır. Ölçüm (5 dosya × 2 sır = 10 bulgu) bunu
doğruladı: bulgu sayısı iş yükünü değil, kopyalama alışkanlığını ölçüyor.

Gruplama `(kural, parmak izi)` üzerinden yapılır. Parmak izi HMAC-SHA256
olduğu için **değerin kendisi hiçbir yerde açılmadan** aynı sırrın farklı
dosyalardaki kopyaları eşleştirilebilir — korelasyonun gizlilik bedeli
yok.

YARA bulgularının parmak izi yoktur (kural dosyanın tamamına uyar, tek
bir değere değil); onlar asla birleştirilmez, aksi hâlde farklı dosyalar
tek satıra düşerdi.
"""

from __future__ import annotations

from dataclasses import dataclass

from sentinel.severity import Severity

__all__ = ["SecretGroup", "group_findings", "MAX_LOCATIONS"]

#: Bir grup için kaydedilen azami konum. Bir sır 10.000 dosyada geçiyorsa
#: raporun 10.000 satır taşımasının analiste faydası yok; sayı + örnek yeterli.
MAX_LOCATIONS = 25


@dataclass(frozen=True)
class SecretGroup:
    """Aynı hassas değerin tüm kopyaları."""

    type: str
    title: str
    severity: str
    fingerprint: str
    content_masked: str
    count: int
    files: tuple[str, ...]
    locations: tuple[tuple[str, int], ...]
    truncated: int = 0

    @property
    def severity_enum(self) -> Severity:
        return Severity.parse(self.severity)

    @property
    def file_count(self) -> int:
        return len(self.files)

    @property
    def shared(self) -> bool:
        """Birden fazla dosyaya yayılmış mı? (Tek iptalle kapanan iş.)"""
        return self.file_count > 1

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "title": self.title,
            "severity": self.severity,
            "fingerprint": self.fingerprint,
            "content_masked": self.content_masked,
            "count": self.count,
            "file_count": self.file_count,
            "files": list(self.files),
            "locations": [{"file": f, "line": line} for f, line in self.locations],
            "truncated": self.truncated,
        }

    def sort_key(self):
        """En kritik, sonra en yaygın, sonra en çok tekrarlanan."""
        return (-self.severity_enum.rank, -self.file_count, -self.count, self.type)


def group_findings(findings, max_locations: int = MAX_LOCATIONS) -> list[SecretGroup]:
    """Bulguları tekil sırlara indirger.

    Dönen liste `SecretGroup.sort_key` sırasındadır: üstte, en kritik ve
    en çok dosyaya yayılmış sır.
    """
    buckets: dict = {}
    order: list = []

    for finding in findings:
        fp = finding.fingerprint or ""
        if fp:
            key = (finding.type, fp)
        else:
            # Parmak izi yok (YARA): birleştirme yapma, her bulgu kendi
            # grubu olsun. Aksi hâlde "aynı sır" iddiası yalan olurdu.
            key = (finding.type, "", finding.file, finding.line, finding.content_masked)

        bucket = buckets.get(key)
        if bucket is None:
            bucket = {
                "type": finding.type,
                "title": finding.title,
                "severity": finding.severity,
                "fingerprint": fp,
                "masked": finding.content_masked,
                "count": 0,
                "files": {},
                "locations": [],
                "dropped": 0,
            }
            buckets[key] = bucket
            order.append(key)

        bucket["count"] += 1
        bucket["files"][finding.file] = None  # sırayı koruyan tekil küme
        if len(bucket["locations"]) < max_locations:
            bucket["locations"].append((finding.file, finding.line))
        else:
            bucket["dropped"] += 1

        # Aynı değer farklı bağlamlarda farklı derece alabilir (ör. kural
        # doğrulanamadığı için bir kademe düşürülmüş olabilir); grup, en
        # kötü durumu temsil etmeli.
        if Severity.parse(finding.severity) > Severity.parse(bucket["severity"]):
            bucket["severity"] = finding.severity
            bucket["title"] = finding.title

    groups = [
        SecretGroup(
            type=bucket["type"],
            title=bucket["title"],
            severity=bucket["severity"],
            fingerprint=bucket["fingerprint"],
            content_masked=bucket["masked"],
            count=bucket["count"],
            files=tuple(bucket["files"]),
            locations=tuple(bucket["locations"]),
            truncated=bucket["dropped"],
        )
        for bucket in (buckets[key] for key in order)
    ]
    groups.sort(key=lambda group: group.sort_key())
    return groups
