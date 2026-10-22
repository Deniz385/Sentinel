"""Turning text into findings.

Responsibilities: pattern matching, algorithmic validation, entropy
checks, resolving overlapping matches, suppression (allowlist and
inline) and deduplication.

Why overlap resolution is needed: ``sk-ant-api03-...`` matches both the
``ANTHROPIC_KEY`` and the ``OPENAI_KEY`` pattern. Reporting both would
be lying to the analyst; within one character range the single
highest-severity rule wins.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from sentinel.allowlist import Allowlist
from sentinel.entropy import (
    SECRET_CONTEXT_RE,
    is_high_entropy,
    iter_secret_candidates,
    shannon_entropy,
)
from sentinel.findings import Finding
from sentinel.patterns import PatternDef, get_pattern_defs
from sentinel.redaction import fingerprint, mask_data, redact_snippet
from sentinel.severity import Severity
from sentinel.validators import VALIDATORS

__all__ = ["Matcher", "ENTROPY_RULE"]

ENTROPY_RULE = "HIGH_ENTROPY_STRING"

#: Cheap digit check for the prescreen (a single pass, in C).
_DIGIT_RE = re.compile(r"\d")

#: Cache of compiled prescreens. Walking the literal list in Python
#: (``any(lit in line for lit in ...)``) cost more than the regexes
#: themselves across 27 patterns and millions of lines; one combined
#: regex does the same work inside C.
_PRESCREEN_CACHE: dict = {}


def _prescreen_regex(literals):
    """Turn a list of literals into one combined regex (cached)."""
    if not literals:
        return None
    cached = _PRESCREEN_CACHE.get(literals)
    if cached is None:
        cached = re.compile("|".join(re.escape(item) for item in literals))
        _PRESCREEN_CACHE[literals] = cached
    return cached


@dataclass
class _Candidate:
    rule: str
    title: str
    severity: Severity
    value: str
    start: int
    end: int
    validated: bool
    priority: int


class Matcher:
    """A reusable matcher prepared from a configuration."""

    def __init__(self, config=None):
        from sentinel.config import ScanConfig

        self.config = config or ScanConfig()
        self.defs: tuple[PatternDef, ...] = get_pattern_defs(
            include=self.config.include_rules or None,
            exclude=self.config.exclude_rules or None,
        )
        self.allowlist: Allowlist = self.config.allowlist or Allowlist()
        self.min_severity = self.config.min_severity_enum
        self._priority = {d.name: index for index, d in enumerate(self.defs)}
        # Keep each prescreen compiled alongside its pattern. A `Matcher`
        # is built per file, so compilation results are cached at module
        # level.
        self._plan = tuple(
            (definition, _prescreen_regex(definition.prescreen), definition.needs_digit)
            for definition in self.defs
        )

    # ------------------------------------------------------------------
    def scan_text(
        self,
        text: str,
        display_path: str,
        *,
        line_offset: int = 0,
        file_sha: str = "N/A",
        real_path: str = "",
        seen: set | None = None,
    ) -> list[Finding]:
        """Scan text and return a list of findings.

        `seen` is passed in from outside so that deduplication works
        across several chunks of the same file (streamed reads, archive
        members).
        """
        if not text:
            return []

        findings: list[Finding] = []
        seen = seen if seen is not None else set()

        for index, line in enumerate(text.splitlines()):
            if not line.strip():
                continue
            line_no = line_offset + index + 1

            # Very long lines (minified JS, an embedded base64 image)
            # choke the regex engine and almost never hold a real finding.
            if len(line) > self.config.max_line_length:
                line = line[: self.config.max_line_length]

            accepted = self._resolve_overlaps(self._candidates(line))
            # In the snippet every sensitive value on the line is masked,
            # suppressed ones included: there is no benefit to printing a
            # value that matched a pattern in the clear.
            sensitive_spans = [(item.start, item.end) for item in accepted]

            for candidate in accepted:
                if self.allowlist.inline_suppressed(line, candidate.rule):
                    continue
                if self.allowlist.allows_rule(candidate.rule):
                    continue
                if candidate.severity < self.min_severity:
                    continue

                print_value = candidate.value
                fp = fingerprint(
                    f"{candidate.rule}:{print_value}", self.config.fingerprint_salt
                )
                if self.allowlist.allows_value(print_value, fp):
                    continue

                key = (candidate.rule, fp)
                if key in seen:
                    continue
                seen.add(key)

                findings.append(
                    Finding(
                        file=display_path,
                        line=line_no,
                        column=candidate.start + 1,
                        type=candidate.rule,
                        title=candidate.title,
                        severity=candidate.severity.value,
                        content_masked=mask_data(print_value),
                        fingerprint=fp,
                        snippet=(
                            redact_snippet(
                                line,
                                candidate.start,
                                candidate.end,
                                spans=sensitive_spans,
                            )
                            if self.config.snippet_enabled
                            else ""
                        ),
                        validated=candidate.validated,
                        sha256=file_sha,
                        real_path=real_path or display_path.split("::", 1)[0],
                    )
                )

        return findings

    # ------------------------------------------------------------------
    def _candidates(self, line: str):
        # Prescreen: running all 27 regexes on every line accounted for
        # nearly all the work on a 50 MB log file. In real files most
        # lines are noise; a single `in` search (down in C) rejects
        # irrelevant patterns before the regex engine ever sees them. The
        # screens are sequences the regex *requires*, so no real finding
        # is missed.
        lowered = line.lower()
        has_digit = _DIGIT_RE.search(line) is not None

        for definition, prescreen, needs_digit in self._plan:
            if needs_digit and not has_digit:
                continue
            if prescreen is not None and prescreen.search(lowered) is None:
                continue

            for match in definition.regex.finditer(line):
                value = definition.value_of(match)
                if not value:
                    continue

                start, end = definition.span_of(match)

                if definition.requires_context and not SECRET_CONTEXT_RE.search(line):
                    continue

                if definition.min_entropy is not None:
                    if shannon_entropy(value) < definition.min_entropy:
                        continue

                validated = True
                severity = definition.severity
                if definition.validator:
                    validator = VALIDATORS.get(definition.validator)
                    if validator is not None and not validator(value):
                        if definition.drop_if_invalid:
                            continue
                        # Not validated: do not drop it, lower it a level.
                        validated = False
                        severity = _downgrade(severity)

                yield _Candidate(
                    rule=definition.name,
                    title=definition.title,
                    severity=severity,
                    value=value,
                    start=start,
                    end=end,
                    validated=validated,
                    priority=self._priority.get(definition.name, 999),
                )

        if self.config.entropy_scan:
            yield from self._entropy_candidates(line)

    def _entropy_candidates(self, line: str):
        """Catch random secrets that have no named pattern."""
        has_context = bool(SECRET_CONTEXT_RE.search(line))
        threshold = self.config.entropy_threshold
        if has_context:
            # Relax the threshold with context: "token = <40 chars>" is almost certainly a secret.
            threshold -= 0.5

        for token, start, end in iter_secret_candidates(line):
            if not is_high_entropy(token, threshold=threshold):
                continue
            yield _Candidate(
                rule=ENTROPY_RULE,
                title="High-entropy String",
                severity=Severity.MEDIUM if has_context else Severity.LOW,
                value=token,
                start=start,
                end=end,
                validated=False,
                priority=1000,
            )

    @staticmethod
    def _resolve_overlaps(candidates):
        """Pick the best candidate among those sharing a character range.

        Ordering: higher severity > validated > longer match > catalogue
        order.
        """
        ordered = sorted(
            candidates,
            key=lambda c: (
                -c.severity.rank,
                not c.validated,
                -(c.end - c.start),
                c.priority,
            ),
        )
        accepted: list[_Candidate] = []
        for candidate in ordered:
            if any(
                candidate.start < other.end and other.start < candidate.end
                for other in accepted
            ):
                continue
            accepted.append(candidate)
        accepted.sort(key=lambda c: c.start)
        return accepted


def _downgrade(severity: Severity) -> Severity:
    order = [
        Severity.INFO,
        Severity.LOW,
        Severity.MEDIUM,
        Severity.HIGH,
        Severity.CRITICAL,
    ]
    index = order.index(severity)
    return order[max(0, index - 1)]
