"""Webhook bildirimleri (Discord / Slack / generic).

v3.0'da webhook adresi `scanner.py` içinde sabitti ve her bulgu için
**ayrı** bir istek atılıyordu: 500 bulgulu bir taramada 500 HTTP isteği,
rate-limit duvarı ve kanalın çöpe dönmesi. Burada:

* adres yapılandırmadan/ortamdan gelir (koda gömülmez),
* varsayılan olarak **tek özet mesaj** gönderilir,
* yük yalnızca maskelenmiş veri içerir,
* hata taramayı düşürmez.
"""

from __future__ import annotations

from sentinel.severity import Severity

__all__ = ["notify_findings", "build_payload", "detect_provider"]

#: Özet mesajda listelenecek en fazla bulgu sayısı.
_MAX_LINES = 15
_TIMEOUT = 5


def detect_provider(url: str) -> str:
    lowered = (url or "").lower()
    if "hooks.slack.com" in lowered:
        return "slack"
    if "discord" in lowered:
        return "discord"
    if "office.com" in lowered or "webhook.office" in lowered:
        return "teams"
    return "generic"


def _format_summary(result, config) -> str:
    threshold = Severity.parse(config.webhook_min_severity)
    relevant = [f for f in result.findings if f.severity_enum >= threshold]
    counts = result.counts_by_severity()

    header = (
        f"🚨 SENTINEL DLP ALARMI — risk skoru {result.risk_score}/100\n"
        f"📂 Hedef: {result.target}\n"
        f"🔍 {result.files_scanned} dosya tarandı, {len(result.findings)} bulgu "
        f"(kritik: {counts.get('critical', 0)}, yüksek: {counts.get('high', 0)})\n"
    )

    lines = []
    for finding in relevant[:_MAX_LINES]:
        severity = finding.severity_enum
        lines.append(
            f"{severity.icon} [{severity.label_tr}] {finding.type} — "
            f"{finding.file}:{finding.line} → `{finding.content_masked}`"
        )
    if len(relevant) > _MAX_LINES:
        lines.append(f"… ve {len(relevant) - _MAX_LINES} bulgu daha.")
    if not lines:
        lines.append("Eşik üstü bulgu yok.")

    return header + "\n".join(lines)


def build_payload(result, config) -> dict:
    """Sağlayıcıya uygun JSON yükünü üretir."""
    text = _format_summary(result, config)
    provider = detect_provider(config.webhook_url)

    if provider == "slack":
        return {"text": text}
    if provider == "teams":
        return {"text": text}
    if provider == "discord":
        # Discord 2000 karakter sınırı uygular.
        return {"content": text[:1990]}
    return {
        "text": text,
        "summary": result.summary(),
    }


def notify_findings(result, config) -> bool:
    """Tarama sonucunu webhook'a gönderir.

    Yapılandırma `webhook_batch=False` ise her bulgu ayrı gönderilir
    (SIEM entegrasyonları bunu isteyebilir), aksi hâlde tek özet.
    """
    url = config.webhook_url
    if not url or "SENIN_WEBHOOK" in url:
        return False

    try:
        import requests
    except ImportError:  # pragma: no cover
        return False

    threshold = Severity.parse(config.webhook_min_severity)
    relevant = [f for f in result.findings if f.severity_enum >= threshold]
    if not relevant:
        return False

    session = requests.Session()
    provider = detect_provider(url)

    if config.webhook_batch:
        payloads = [build_payload(result, config)]
    else:
        payloads = []
        for finding in relevant:
            severity = finding.severity_enum
            message = (
                f"{severity.icon} **{finding.type}** [{severity.label_tr}]\n"
                f"📂 `{finding.file}`:{finding.line}\n"
                f"🕵️ `{finding.content_masked}`"
            )
            key = "content" if provider == "discord" else "text"
            payloads.append({key: message})

    sent = False
    for payload in payloads:
        try:
            response = session.post(url, json=payload, timeout=_TIMEOUT)
            sent = sent or response.status_code < 400
        except Exception:
            # Bildirim en iyi gayret esaslıdır; tarama sonucu kaybolmaz.
            continue
    return sent
