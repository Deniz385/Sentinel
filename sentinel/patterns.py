"""The sensitive-data pattern catalogue.

Every pattern carries a regex, a severity, an algorithmic validator
where one exists, and a human-readable description. In the previous
version patterns were a flat ``{name: regex}`` dict with no severity, no
validator binding and no description, so the report could not answer
"how bad is this?".

Some rules deliberately contain Turkish keywords in their regexes (for
example the health-data indicators and the credential names "sifre" and
"parola"). Those are detection data, not prose: this scanner targets
Turkish codebases and records. The rule *names* are English, and the
former Turkish names are kept in :data:`ALIASES` so existing allowlists,
baselines and configuration files keep working.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from sentinel.severity import Severity

__all__ = [
    "PatternDef",
    "PATTERN_DEFS",
    "PATTERNS",
    "ALIASES",
    "get_patterns",
    "get_pattern_defs",
    "resolve_name",
    "iter_pattern_defs",
]


@dataclass(frozen=True)
class PatternDef:
    """A single detection rule."""

    name: str
    regex: re.Pattern
    severity: Severity
    title: str
    description: str
    #: Regex group holding the sensitive value (0 = the whole match).
    value_group: int = 0
    #: Validator name within :data:`sentinel.validators.VALIDATORS`.
    validator: str | None = None
    #: When the validator fails, drop the finding entirely, or report it
    #: one severity level lower and marked "not validated"?
    drop_if_invalid: bool = True
    #: Minimum entropy the value must carry (for generic secrets).
    min_entropy: float | None = None
    #: Must the line contain a secret context word (``token``, ``secret``)?
    requires_context: bool = False
    tags: tuple[str, ...] = field(default_factory=tuple)
    #: Example used by the tests and by the `sentinel rules` command.
    example: str | None = None
    #: Fast prescreen: if **none** of these lowercase literals occurs in
    #: the line, the regex is never run. Only sequences the regex itself
    #: requires may be listed here, otherwise real findings are missed.
    prescreen: tuple[str, ...] = ()
    #: Does the regex require at least one digit? (same purpose, by class)
    needs_digit: bool = False

    def value_of(self, match: re.Match) -> str:
        group = self.value_group
        if group and group <= (match.re.groups or 0):
            return (match.group(group) or "").strip()
        return (match.group(0) or "").strip()

    def span_of(self, match: re.Match) -> tuple[int, int]:
        group = self.value_group
        if group and group <= (match.re.groups or 0) and match.group(group) is not None:
            return match.span(group)
        return match.span(0)


def _p(**kwargs) -> PatternDef:
    kwargs["regex"] = re.compile(kwargs["regex"])
    return PatternDef(**kwargs)


# ---------------------------------------------------------------------------
# PERSONAL DATA (Turkish KVKK scope)
# ---------------------------------------------------------------------------
_PERSONAL = [
    _p(
        name="TR_NATIONAL_ID",
        regex=r"\b[1-9]\d{10}\b",
        severity=Severity.HIGH,
        title="Turkish National Identity Number",
        description="Identity data under Turkish data-protection law (KVKK). Algorithmically validated.",
        validator="tckn",
        needs_digit=True,
        tags=("pii", "kvkk", "tr"),
        example="10000000146",
    ),
    _p(
        name="EMAIL",
        regex=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,}\b",
        severity=Severity.LOW,
        title="Email Address",
        description="Contact data. Low risk alone, high risk in bulk lists.",
        validator="email",
        drop_if_invalid=False,
        prescreen=("@",),
        tags=("pii", "kvkk"),
        example="jane.doe@university.edu",
    ),
    _p(
        name="TR_PHONE",
        # The leading `(?<![\d+])` stops a "phone number" being carved out
        # of the middle of a longer digit run (an order number, a
        # transaction id); the trailing `(?!\d)` does the same at the
        # other end. Without these boundaries every 16-digit number
        # looked like a phone number.
        regex=r"(?<![\d+])(?:\+90[ -]?|0)?5\d{2}[ -]?\d{3}[ -]?\d{2}[ -]?\d{2}(?!\d)",
        severity=Severity.MEDIUM,
        title="Phone Number (TR mobile)",
        description="Contact data under Turkish data-protection law (KVKK).",
        validator="phone_tr",
        needs_digit=True,
        prescreen=("5",),
        tags=("pii", "kvkk", "tr"),
        example="0555 123 45 67",
    ),
    _p(
        name="TR_PLATE",
        regex=r"\b(0[1-9]|[1-7]\d|8[01])\s?[A-Z]{1,3}\s?\d{2,4}\b",
        severity=Severity.LOW,
        title="Vehicle Registration Plate (TR)",
        description="Indirect identity data; can be matched to a person.",
        needs_digit=True,
        tags=("pii", "tr"),
        example="34 ABC 1234",
    ),
    _p(
        name="DATE_OF_BIRTH",
        regex=r"\b(?:0[1-9]|[12]\d|3[01])[./](?:0[1-9]|1[0-2])[./](?:19|20)\d{2}\b",
        severity=Severity.LOW,
        title="Date of Birth",
        description="Raises risk when combined with identity data.",
        needs_digit=True,
        prescreen=(".", "/"),
        tags=("pii", "kvkk"),
        example="01.01.1990",
    ),
]

# ---------------------------------------------------------------------------
# FINANCIAL DATA
# ---------------------------------------------------------------------------
_FINANCIAL = [
    _p(
        name="CREDIT_CARD",
        regex=r"\b(?:\d[ -]?){12,18}\d\b",
        severity=Severity.CRITICAL,
        title="Credit Card Number",
        description="In PCI-DSS scope. Validated by Luhn plus a brand prefix.",
        validator="credit_card",
        needs_digit=True,
        tags=("pci", "financial"),
        example="4111 1111 1111 1111",
    ),
    _p(
        name="TR_IBAN",
        regex=r"\bTR\d{2}(?:[ ]?\d{4}){5}[ ]?\d{2}\b",
        severity=Severity.HIGH,
        title="IBAN (TR)",
        description="Bank account details. Validated with ISO 7064 mod 97-10.",
        validator="tr_iban",
        needs_digit=True,
        prescreen=("tr",),
        tags=("financial", "tr"),
        example="TR330006100519786457841326",
    ),
    _p(
        name="IBAN",
        regex=r"\b(?!TR)[A-Z]{2}\d{2}[ ]?(?:[A-Z0-9]{4}[ ]?){2,7}[A-Z0-9]{1,4}\b",
        severity=Severity.HIGH,
        title="IBAN (international)",
        description="Foreign bank account. Validated with mod 97-10.",
        validator="iban",
        needs_digit=True,
        tags=("financial",),
        example="DE89370400440532013000",
    ),
    _p(
        name="CRYPTO_ETH",
        regex=r"\b0x[a-fA-F0-9]{40}\b",
        severity=Severity.MEDIUM,
        title="Ethereum / BSC Wallet Address",
        description="Crypto asset address.",
        prescreen=("0x",),
        tags=("crypto", "financial"),
        example="0x52908400098527886E0F7030069857D2E4169EE7",
    ),
    _p(
        name="CRYPTO_BTC",
        regex=r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
        severity=Severity.MEDIUM,
        title="Bitcoin Wallet Address",
        description="Validated with a Base58Check checksum.",
        validator="base58check",
        needs_digit=True,
        tags=("crypto", "financial"),
        example="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    ),
]

# ---------------------------------------------------------------------------
# TECHNICAL SECRETS (credentials and keys)
# ---------------------------------------------------------------------------
_SECRETS = [
    _p(
        name="AWS_ACCESS_KEY",
        regex=r"\b(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|AROA|A3T)[A-Z0-9]{16}\b",
        severity=Severity.CRITICAL,
        title="AWS Access Key ID",
        description="Direct access to the cloud account. Revoke immediately.",
        prescreen=(
            "akia", "asia", "abia", "acca", "agpa", "aida",
            "aipa", "anpa", "anva", "aroa", "a3t",
        ),
        tags=("secret", "cloud", "aws"),
        example="AKIAIOSFODNN7EXAMPLE",
    ),
    _p(
        name="AWS_SECRET_KEY",
        regex=r"(?i)aws[_-]?(?:secret|sec)[_-]?(?:access)?[_-]?key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        severity=Severity.CRITICAL,
        title="AWS Secret Access Key",
        description="Together with the access key ID, grants full account access.",
        value_group=1,
        min_entropy=3.5,
        prescreen=("aws",),
        tags=("secret", "cloud", "aws"),
        example='aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
    ),
    _p(
        name="GOOGLE_API_KEY",
        regex=r"\bAIza[0-9A-Za-z_\-]{35}\b",
        severity=Severity.HIGH,
        title="Google API Key",
        description="Access to metered Google services; billing exposure.",
        prescreen=("aiza",),
        tags=("secret", "cloud", "google"),
        example="AIza" + "EXAMPLEFAKEVALUE" + "0" * 19,
    ),
    _p(
        name="GITHUB_TOKEN",
        regex=r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{70,})\b",
        severity=Severity.CRITICAL,
        title="GitHub Access Token",
        description="May grant write access to repositories and CI secrets.",
        prescreen=("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"),
        tags=("secret", "vcs"),
        example="ghp_" + "A" * 36,
    ),
    _p(
        name="SLACK_TOKEN",
        regex=r"\bxox[abprs]-[A-Za-z0-9-]{10,72}\b",
        severity=Severity.HIGH,
        title="Slack Token",
        description="Access to the organization's messaging history.",
        prescreen=("xox",),
        tags=("secret", "saas"),
        example="xoxb-EXAMPLE-NOT-A-REAL-TOKEN",
    ),
    _p(
        name="SLACK_WEBHOOK",
        regex=r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+",
        severity=Severity.MEDIUM,
        title="Slack Webhook URL",
        description="Allows forged notifications into the organization (phishing).",
        prescreen=("hooks.slack.com",),
        tags=("secret", "saas"),
    ),
    _p(
        name="DISCORD_WEBHOOK",
        regex=r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+",
        severity=Severity.MEDIUM,
        title="Discord Webhook URL",
        description="Allows posting messages as the channel.",
        prescreen=("discord",),
        tags=("secret", "saas"),
    ),
    _p(
        name="STRIPE_KEY",
        regex=r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b",
        severity=Severity.CRITICAL,
        title="Stripe Secret Key",
        description="Authority to charge and refund. `sk_live` is direct money risk.",
        prescreen=("sk_live_", "sk_test_", "rk_live_", "rk_test_"),
        tags=("secret", "payment"),
        example="sk_live_" + "a" * 24,
    ),
    _p(
        name="OPENAI_KEY",
        regex=r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b",
        severity=Severity.HIGH,
        title="OpenAI API Key",
        description="Billed API usage.",
        prescreen=("sk-",),
        tags=("secret", "ai"),
        example="sk-proj-" + "a" * 40,
    ),
    _p(
        name="ANTHROPIC_KEY",
        regex=r"\bsk-ant-[A-Za-z0-9_\-]{24,}\b",
        severity=Severity.HIGH,
        title="Anthropic API Key",
        description="Billed API usage.",
        prescreen=("sk-ant-",),
        tags=("secret", "ai"),
        example="sk-ant-api03-" + "a" * 32,
    ),
    _p(
        name="PRIVATE_KEY",
        regex=r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----",
        severity=Severity.CRITICAL,
        title="Private Key",
        description="TLS/SSH/PGP private key. Impersonation risk.",
        prescreen=("-----begin",),
        tags=("secret", "crypto"),
        example="-----BEGIN RSA PRIVATE KEY-----",
    ),
    _p(
        name="JWT",
        regex=r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b",
        severity=Severity.HIGH,
        title="JWT",
        description="Session or authorization token. Validated by decoding its header.",
        validator="jwt",
        prescreen=("eyj",),
        tags=("secret", "auth"),
    ),
    _p(
        name="DB_CONNECTION_STRING",
        regex=r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|mssql|redis|amqp)://"
        r"[^\s:/@]+:([^\s/@]{3,})@[^\s/]+",
        severity=Severity.CRITICAL,
        title="Database Connection String (with password)",
        description="Direct database access via an embedded username and password.",
        value_group=1,
        prescreen=("://",),
        tags=("secret", "database"),
        example="postgresql://admin:S3cr3tP4ss@db.internal:5432/app",
    ),
    _p(
        name="HARDCODED_PASS",
        # A "not preceded by a letter" lookbehind instead of `\b`: in the
        # most common names - `API_TOKEN`, `DB_PASSWORD`, `app.secret` -
        # the underscore is a word character, so `\btoken\b` never
        # matched. A suffix is allowed too: `TOKEN_VALUE = "..."`.
        # This widens the rule with no backtracking risk.
        #
        # "sifre" and "parola" are Turkish for password and passphrase:
        # detection data for Turkish codebases, not leftover prose.
        regex=r"(?i)(?<![A-Za-z])(password|passwd|pwd|secret|api[_-]?key|token|"
        r"sifre|parola)[A-Za-z0-9_]*\s*[:=]\s*[\"']([^\"'\n]{4,})[\"']",
        severity=Severity.HIGH,
        title="Hard-coded Credential",
        description="A password or key assigned literally in source code.",
        value_group=2,
        prescreen=(
            "password", "passwd", "pwd", "secret", "api_key", "apikey",
            "api-key", "apikey", "token", "sifre", "parola",
        ),
        tags=("secret", "code"),
        example='password = "SecretPass123"',
    ),
    _p(
        name="GENERIC_SECRET",
        regex=r"(?i)(?<![A-Za-z])(?:secret|token|api[_-]?key|credential|auth)"
        r"[A-Za-z0-9_]*\s*[:=]\s*[\"']?([A-Za-z0-9+/=_\-]{24,})[\"']?",
        severity=Severity.MEDIUM,
        title="High-entropy Secret (generic)",
        description="A random-looking secret that belongs to no known provider.",
        value_group=1,
        min_entropy=4.0,
        prescreen=(
            "secret", "token", "api_key", "apikey", "api-key",
            "credential", "auth",
        ),
        tags=("secret", "entropy"),
    ),
]

# ---------------------------------------------------------------------------
# HEALTH / INFRASTRUCTURE
# ---------------------------------------------------------------------------
_OTHER = [
    _p(
        name="HEALTH_DATA",
        regex=r"(?i)\b(?:tanı|teşhis|ICD-?10|reçete|hasta\s*no|protokol\s*no|"
        r"kan\s*grubu|diagnosis|prescription)\b\s*[:=#]?\s*\S+",
        # This rule is a *context indicator*: the presence of "hasta no"
        # (patient number) is not the same as finding a validated
        # identity number. Rating it high would bury the real findings.
        #
        # The Turkish terms in the regex are detection data: Turkish
        # medical records are exactly what this rule is meant to find.
        severity=Severity.MEDIUM,
        title="Health Data Indicator",
        description="Context for special-category personal data (KVKK art. 6).",
        # Turkish case folding maps I/i and İ/ı differently, so both
        # spellings are listed; the prescreen must be looser than the regex.
        prescreen=(
            "tanı", "tani", "teşhis", "teshis", "icd", "reçete", "recete",
            "hasta", "protokol", "kan", "diagnosis", "prescription",
        ),
        tags=("pii", "kvkk", "health"),
    ),
    _p(
        name="PRIVATE_IP",
        regex=r"\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b",
        severity=Severity.INFO,
        title="Private Network IP Address",
        description="Leaks internal network topology; useful for reconnaissance.",
        needs_digit=True,
        prescreen=("10.", "172.", "192.168"),
        tags=("infra",),
        example="10.0.14.22",
    ),
]

PATTERN_DEFS: tuple[PatternDef, ...] = tuple(
    _PERSONAL + _FINANCIAL + _SECRETS + _OTHER
)

_BY_NAME = {definition.name: definition for definition in PATTERN_DEFS}

#: Accepted aliases for canonical rule names.
#:
#: The six names that used to be Turkish (``TC_KIMLIK``, ``KREDI_KARTI``,
#: ``TELEFON``, ``TR_PLAKA``, ``DOGUM_TARIHI``, ``SAGLIK_VERISI``) are
#: kept here so allowlists, baselines and ``sentinel.yml`` files written
#: against the old names keep working after the rename.
ALIASES = {
    # Former Turkish names -> current canonical names.
    "TC_KIMLIK": "TR_NATIONAL_ID",
    "KREDI_KARTI": "CREDIT_CARD",
    "TELEFON": "TR_PHONE",
    "TR_PLAKA": "TR_PLATE",
    "DOGUM_TARIHI": "DATE_OF_BIRTH",
    "SAGLIK_VERISI": "HEALTH_DATA",
    # Convenient short forms.
    "TR_ID": "TR_NATIONAL_ID",
    "TCKN": "TR_NATIONAL_ID",
    "PHONE": "TR_PHONE",
    "PLATE": "TR_PLATE",
    "BIRTH_DATE": "DATE_OF_BIRTH",
    "PASSWORD": "HARDCODED_PASS",
}

#: The legacy ``{name: compiled regex}`` dict, kept for external scripts.
PATTERNS = {definition.name: definition.regex for definition in PATTERN_DEFS}


def resolve_name(name: str) -> str:
    """Resolve an alias to the canonical pattern name."""
    upper = str(name).strip().upper()
    return ALIASES.get(upper, upper)


def get_patterns() -> dict[str, re.Pattern]:
    """Legacy API: ``{pattern_name: compiled regex}``."""
    return dict(PATTERNS)


def get_pattern_defs(
    include: list[str] | tuple[str, ...] | None = None,
    exclude: list[str] | tuple[str, ...] | None = None,
) -> tuple[PatternDef, ...]:
    """Return a filtered list of patterns.

    `include` and `exclude` accept both pattern names and tags (``pii``,
    ``secret``, ...), which makes usage such as ``--only secret``
    possible.
    """
    defs = PATTERN_DEFS

    def matches(definition: PatternDef, keys: set[str]) -> bool:
        return definition.name in keys or bool(set(definition.tags) & keys)

    if include:
        keys = {resolve_name(k) for k in include} | {str(k).lower() for k in include}
        defs = tuple(d for d in defs if matches(d, keys))
    if exclude:
        keys = {resolve_name(k) for k in exclude} | {str(k).lower() for k in exclude}
        defs = tuple(d for d in defs if not matches(d, keys))
    return defs


def iter_pattern_defs():
    return iter(PATTERN_DEFS)


def pattern_by_name(name: str) -> PatternDef | None:
    return _BY_NAME.get(resolve_name(name))
