"""Webhook notifications (Discord / Slack / generic).

In v3.0 the webhook address was hard-coded in `scanner.py` and a
**separate** request was sent per finding: a scan with 500 findings
meant 500 HTTP requests, a rate-limit wall and a channel full of noise.
Here:

* the address comes from configuration or the environment, never code,
* a **single summary message** is sent by default,
* the payload carries masked data only,
* a failure never fails the scan.
"""

from __future__ import annotations

from sentinel.severity import Severity

__all__ = ["notify_findings", "build_payload", "detect_provider"]

#: Maximum number of findings listed in the summary message.
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
        f"🚨 SENTINEL DLP ALERT - risk score {result.risk_score}/100\n"
        f"📂 Target: {result.target}\n"
        f"🔍 {result.files_scanned} files scanned, {len(result.findings)} findings "
        f"(critical: {counts.get('critical', 0)}, high: {counts.get('high', 0)})\n"
    )

    lines = []
    for finding in relevant[:_MAX_LINES]:
        severity = finding.severity_enum
        lines.append(
            f"{severity.icon} [{severity.label}] {finding.type} - "
            f"{finding.file}:{finding.line} → `{finding.content_masked}`"
        )
    if len(relevant) > _MAX_LINES:
        lines.append(f"… and {len(relevant) - _MAX_LINES} more findings.")
    if not lines:
        lines.append("No findings at or above the threshold.")

    return header + "\n".join(lines)


def build_payload(result, config) -> dict:
    """Build the JSON payload for the detected provider."""
    text = _format_summary(result, config)
    provider = detect_provider(config.webhook_url)

    if provider == "slack":
        return {"text": text}
    if provider == "teams":
        return {"text": text}
    if provider == "discord":
        # Discord enforces a 2000-character limit.
        return {"content": text[:1990]}
    return {
        "text": text,
        "summary": result.summary(),
    }


def notify_findings(result, config) -> bool:
    """Send the scan result to the webhook.

    With `webhook_batch=False` each finding is sent separately (SIEM
    integrations may want that); otherwise a single summary is sent.
    """
    url = config.webhook_url
    if not url or "YOUR_WEBHOOK" in url:
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
                f"{severity.icon} **{finding.type}** [{severity.label}]\n"
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
            # Notification is best-effort; the scan result is never lost.
            continue
    return sent
