"""Cross-file correlation: from a finding count to a **unique secret** count.

When a scan reports "207 findings" an analyst assumes 207 pieces of
work. In reality the same AWS key may have been copied into 40 files,
and all 40 close with **one revocation**. Measurement bore this out
(5 files x 2 secrets = 10 findings): the finding count measures copying
habits, not workload.

Grouping is keyed on ``(rule, fingerprint)``. Because the fingerprint is
an HMAC-SHA256, copies of the same secret can be matched across files
**without the value ever being revealed** - correlation costs nothing in
privacy.

YARA findings have no fingerprint (the rule matches a whole file, not a
single value), so they are never merged; otherwise unrelated files would
collapse into one row.
"""

from __future__ import annotations

from dataclasses import dataclass

from sentinel.severity import Severity

__all__ = ["SecretGroup", "group_findings", "MAX_LOCATIONS"]

#: Maximum number of locations recorded per group. If a secret occurs in
#: 10,000 files, carrying 10,000 rows in the report helps nobody; the
#: count plus a sample is enough.
MAX_LOCATIONS = 25


@dataclass(frozen=True)
class SecretGroup:
    """Every copy of one sensitive value."""

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
        """Spread across more than one file? (One revocation closes it.)"""
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
        """Most critical, then most widespread, then most repeated."""
        return (-self.severity_enum.rank, -self.file_count, -self.count, self.type)


def group_findings(findings, max_locations: int = MAX_LOCATIONS) -> list[SecretGroup]:
    """Reduce findings to unique secrets.

    The returned list is in `SecretGroup.sort_key` order: the most
    critical and most widely copied secret first.
    """
    buckets: dict = {}
    order: list = []

    for finding in findings:
        fp = finding.fingerprint or ""
        if fp:
            key = (finding.type, fp)
        else:
            # No fingerprint (YARA): do not merge, give each finding its
            # own group. Otherwise the claim "the same secret" would be
            # a lie.
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
        bucket["files"][finding.file] = None  # order-preserving unique set
        if len(bucket["locations"]) < max_locations:
            bucket["locations"].append((finding.file, finding.line))
        else:
            bucket["dropped"] += 1

        # The same value may be rated differently in different contexts
        # (for instance downgraded a level where a validator could not
        # confirm it); the group must represent the worst case.
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
