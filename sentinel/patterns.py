"""Hassas veri deseni kataloğu.

Her desen; bir regex, bir önem derecesi, (varsa) bir algoritmik
doğrulayıcı ve insan tarafından okunabilir bir açıklama taşır. Önceki
sürümde desenler düz bir ``{isim: regex}`` sözlüğüydü; önem derecesi,
doğrulayıcı bağı ve açıklama yoktu, bu yüzden rapor "ne kadar kötü?"
sorusuna cevap veremiyordu.

Eski Türkçe desen isimleri (``TC_KIMLIK``, ``KREDI_KARTI`` ...) CSV
uyumluluğu için korunmuştur.
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
    """Tek bir tespit kuralı."""

    name: str
    regex: re.Pattern
    severity: Severity
    title: str
    description: str
    #: Hassas değerin bulunduğu regex grubu (0 = tüm eşleşme).
    value_group: int = 0
    #: :data:`sentinel.validators.VALIDATORS` içindeki doğrulayıcı adı.
    validator: str | None = None
    #: Doğrulayıcı başarısız olursa bulgu tamamen atılsın mı, yoksa
    #: önem derecesi düşürülüp "doğrulanmadı" olarak mı raporlansın?
    drop_if_invalid: bool = True
    #: Değerin en az bu kadar entropisi olmalı (generic sırlar için).
    min_entropy: float | None = None
    #: Satırda bir sır bağlam kelimesi (``token``, ``secret``...) şart mı?
    requires_context: bool = False
    tags: tuple[str, ...] = field(default_factory=tuple)
    #: Testlerin ve `sentinel rules` komutunun kullandığı örnek.
    example: str | None = None
    #: Hızlı ön süzgeç: bu küçük harfli literallerden **en az biri**
    #: satırda yoksa regex hiç çalıştırılmaz. Yalnızca regex'in zorunlu
    #: kıldığı diziler yazılabilir; aksi hâlde gerçek bulgu kaçar.
    prescreen: tuple[str, ...] = ()
    #: Regex en az bir rakam gerektiriyor mu? (aynı amaçla, karakter sınıfı)
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
# KİŞİSEL VERİLER (KVKK)
# ---------------------------------------------------------------------------
_PERSONAL = [
    _p(
        name="TC_KIMLIK",
        regex=r"\b[1-9]\d{10}\b",
        severity=Severity.HIGH,
        title="TC Kimlik Numarası",
        description="KVKK kapsamında kimlik verisi. Algoritmik olarak doğrulanır.",
        validator="tckn",
        needs_digit=True,
        tags=("pii", "kvkk", "tr"),
        example="10000000146",
    ),
    _p(
        name="EMAIL",
        regex=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,}\b",
        severity=Severity.LOW,
        title="E-posta Adresi",
        description="İletişim verisi. Tek başına düşük risk, toplu listede yüksek.",
        validator="email",
        drop_if_invalid=False,
        prescreen=("@",),
        tags=("pii", "kvkk"),
        example="deniz.celik@adu.edu.tr",
    ),
    _p(
        name="TELEFON",
        # Baştaki `(?<![\d+])`, uzun bir sayı dizisinin (sipariş numarası,
        # işlem kimliği) ortasından "telefon" çıkarmayı engeller; sondaki
        # `(?!\d)` de aynı işi diğer uçta yapar. Bu sınırlar olmadan
        # 16 haneli her numara telefon gibi görünüyordu.
        regex=r"(?<![\d+])(?:\+90[ -]?|0)?5\d{2}[ -]?\d{3}[ -]?\d{2}[ -]?\d{2}(?!\d)",
        severity=Severity.MEDIUM,
        title="Telefon Numarası (TR GSM)",
        description="KVKK kapsamında iletişim verisi.",
        validator="phone_tr",
        needs_digit=True,
        prescreen=("5",),
        tags=("pii", "kvkk", "tr"),
        example="0555 123 45 67",
    ),
    _p(
        name="TR_PLAKA",
        regex=r"\b(0[1-9]|[1-7]\d|8[01])\s?[A-Z]{1,3}\s?\d{2,4}\b",
        severity=Severity.LOW,
        title="Araç Plakası (TR)",
        description="Dolaylı kimlik verisi; kişiyle eşleştirilebilir.",
        needs_digit=True,
        tags=("pii", "tr"),
        example="34 ABC 1234",
    ),
    _p(
        name="DOGUM_TARIHI",
        regex=r"\b(?:0[1-9]|[12]\d|3[01])[./](?:0[1-9]|1[0-2])[./](?:19|20)\d{2}\b",
        severity=Severity.LOW,
        title="Doğum Tarihi Formatı",
        description="Kimlik verisiyle birleştiğinde riski yükseltir.",
        needs_digit=True,
        prescreen=(".", "/"),
        tags=("pii", "kvkk"),
        example="01.01.1990",
    ),
]

# ---------------------------------------------------------------------------
# FİNANSAL VERİLER
# ---------------------------------------------------------------------------
_FINANCIAL = [
    _p(
        name="KREDI_KARTI",
        regex=r"\b(?:\d[ -]?){12,18}\d\b",
        severity=Severity.CRITICAL,
        title="Kredi Kartı Numarası",
        description="PCI-DSS kapsamı. Luhn + marka ön eki ile doğrulanır.",
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
        description="Banka hesap bilgisi. ISO 7064 Mod 97-10 ile doğrulanır.",
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
        title="IBAN (Uluslararası)",
        description="Yabancı banka hesabı. Mod 97-10 ile doğrulanır.",
        validator="iban",
        needs_digit=True,
        tags=("financial",),
        example="DE89370400440532013000",
    ),
    _p(
        name="CRYPTO_ETH",
        regex=r"\b0x[a-fA-F0-9]{40}\b",
        severity=Severity.MEDIUM,
        title="Ethereum / BSC Cüzdan Adresi",
        description="Kripto varlık adresi.",
        prescreen=("0x",),
        tags=("crypto", "financial"),
        example="0x52908400098527886E0F7030069857D2E4169EE7",
    ),
    _p(
        name="CRYPTO_BTC",
        regex=r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
        severity=Severity.MEDIUM,
        title="Bitcoin Cüzdan Adresi",
        description="Base58Check kontrol toplamı ile doğrulanır.",
        validator="base58check",
        needs_digit=True,
        tags=("crypto", "financial"),
        example="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    ),
]

# ---------------------------------------------------------------------------
# TEKNİK SIRLAR (kimlik bilgileri / anahtarlar)
# ---------------------------------------------------------------------------
_SECRETS = [
    _p(
        name="AWS_ACCESS_KEY",
        regex=r"\b(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|AROA|A3T)[A-Z0-9]{16}\b",
        severity=Severity.CRITICAL,
        title="AWS Erişim Anahtarı Kimliği",
        description="Bulut hesabına doğrudan erişim sağlar. Derhal iptal edilmeli.",
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
        title="AWS Gizli Erişim Anahtarı",
        description="Erişim anahtarı kimliğiyle birlikte tam hesap erişimi verir.",
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
        title="Google API Anahtarı",
        description="Kotalı Google servislerine erişim; faturalandırma riski.",
        prescreen=("aiza",),
        tags=("secret", "cloud", "google"),
        example="AIza" + "ORNEKSAHTEDEGER" + "0" * 20,
    ),
    _p(
        name="GITHUB_TOKEN",
        regex=r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{70,})\b",
        severity=Severity.CRITICAL,
        title="GitHub Erişim Token'ı",
        description="Depolara yazma ve CI sırlarına erişim sağlayabilir.",
        prescreen=("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"),
        tags=("secret", "vcs"),
        example="ghp_" + "A" * 36,
    ),
    _p(
        name="SLACK_TOKEN",
        regex=r"\bxox[abprs]-[A-Za-z0-9-]{10,72}\b",
        severity=Severity.HIGH,
        title="Slack Token'ı",
        description="Kurumsal mesajlaşma geçmişine erişim.",
        prescreen=("xox",),
        tags=("secret", "saas"),
        example="xoxb-ORNEK-SAHTE-DEGER-DEGILDIR",
    ),
    _p(
        name="SLACK_WEBHOOK",
        regex=r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+",
        severity=Severity.MEDIUM,
        title="Slack Webhook URL'si",
        description="Kuruma sahte bildirim gönderilebilir (phishing).",
        prescreen=("hooks.slack.com",),
        tags=("secret", "saas"),
    ),
    _p(
        name="DISCORD_WEBHOOK",
        regex=r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+",
        severity=Severity.MEDIUM,
        title="Discord Webhook URL'si",
        description="Kanal adına mesaj gönderilebilir.",
        prescreen=("discord",),
        tags=("secret", "saas"),
    ),
    _p(
        name="STRIPE_KEY",
        regex=r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b",
        severity=Severity.CRITICAL,
        title="Stripe Gizli Anahtarı",
        description="Ödeme alma/iade yetkisi. `sk_live` doğrudan para riski.",
        prescreen=("sk_live_", "sk_test_", "rk_live_", "rk_test_"),
        tags=("secret", "payment"),
        example="sk_live_" + "a" * 24,
    ),
    _p(
        name="OPENAI_KEY",
        regex=r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b",
        severity=Severity.HIGH,
        title="OpenAI API Anahtarı",
        description="Faturalandırılan API kullanımı.",
        prescreen=("sk-",),
        tags=("secret", "ai"),
        example="sk-proj-" + "a" * 40,
    ),
    _p(
        name="ANTHROPIC_KEY",
        regex=r"\bsk-ant-[A-Za-z0-9_\-]{24,}\b",
        severity=Severity.HIGH,
        title="Anthropic API Anahtarı",
        description="Faturalandırılan API kullanımı.",
        prescreen=("sk-ant-",),
        tags=("secret", "ai"),
        example="sk-ant-api03-" + "a" * 32,
    ),
    _p(
        name="PRIVATE_KEY",
        regex=r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----",
        severity=Severity.CRITICAL,
        title="Özel Anahtar (Private Key)",
        description="TLS/SSH/PGP özel anahtarı. Kimlik taklidi riski.",
        prescreen=("-----begin",),
        tags=("secret", "crypto"),
        example="-----BEGIN RSA PRIVATE KEY-----",
    ),
    _p(
        name="JWT",
        regex=r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b",
        severity=Severity.HIGH,
        title="JWT Token'ı",
        description="Oturum/yetki token'ı. Başlığı çözülerek doğrulanır.",
        validator="jwt",
        prescreen=("eyj",),
        tags=("secret", "auth"),
    ),
    _p(
        name="DB_CONNECTION_STRING",
        regex=r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|mssql|redis|amqp)://"
        r"[^\s:/@]+:([^\s/@]{3,})@[^\s/]+",
        severity=Severity.CRITICAL,
        title="Veritabanı Bağlantı Dizesi (şifreli)",
        description="Gömülü kullanıcı adı/şifre ile veritabanına doğrudan erişim.",
        value_group=1,
        prescreen=("://",),
        tags=("secret", "database"),
        example="postgresql://admin:S3cr3tP4ss@db.internal:5432/app",
    ),
    _p(
        name="HARDCODED_PASS",
        # `\b` yerine "önünde harf olmasın" lookbehind'i kullanılır:
        # `API_TOKEN`, `DB_PASSWORD`, `app.secret` gibi en yaygın isimlerde
        # alt çizgi bir kelime karakteri olduğu için `\btoken\b` hiç
        # eşleşmiyordu. Sonek de serbest: `TOKEN_VALUE = "..."`.
        # Geri izleme (backtracking) riski olmadan genişletir.
        regex=r"(?i)(?<![A-Za-z])(password|passwd|pwd|secret|api[_-]?key|token|"
        r"sifre|parola)[A-Za-z0-9_]*\s*[:=]\s*[\"']([^\"'\n]{4,})[\"']",
        severity=Severity.HIGH,
        title="Koda Gömülü Kimlik Bilgisi",
        description="Kaynak kodda sabitlenmiş şifre/anahtar ataması.",
        value_group=2,
        prescreen=(
            "password", "passwd", "pwd", "secret", "api_key", "apikey",
            "api-key", "apikey", "token", "sifre", "parola",
        ),
        tags=("secret", "code"),
        example='password = "GizliSifre123"',
    ),
    _p(
        name="GENERIC_SECRET",
        regex=r"(?i)(?<![A-Za-z])(?:secret|token|api[_-]?key|credential|auth)"
        r"[A-Za-z0-9_]*\s*[:=]\s*[\"']?([A-Za-z0-9+/=_\-]{24,})[\"']?",
        severity=Severity.MEDIUM,
        title="Yüksek Entropili Sır (generic)",
        description="Bilinen bir sağlayıcıya ait olmayan, rastgele görünümlü sır.",
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
# SAĞLIK / ALTYAPI
# ---------------------------------------------------------------------------
_OTHER = [
    _p(
        name="SAGLIK_VERISI",
        regex=r"(?i)\b(?:tanı|teşhis|ICD-?10|reçete|hasta\s*no|protokol\s*no|"
        r"kan\s*grubu|diagnosis|prescription)\b\s*[:=#]?\s*\S+",
        # Bu kural bir *bağlam göstergesidir*: "hasta no" ifadesinin
        # varlığı, doğrulanmış bir kimlik numarası bulmakla aynı şey
        # değildir. Yüksek vermek, gerçek bulguların arasını doldurur.
        severity=Severity.MEDIUM,
        title="Sağlık Verisi İşareti",
        description="KVKK md.6 özel nitelikli kişisel veri bağlamı (gösterge).",
        # Türkçe büyük/küçük harf dönüşümü (I/ı, İ/i) nedeniyle her iki
        # yazım da listelenir; ön süzgeç regex'ten daha gevşek olmalı.
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
        title="Özel Ağ IP Adresi",
        description="İç ağ topolojisi sızıntısı; keşif (recon) değeri taşır.",
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

#: Geriye dönük / İngilizce kısa isimler.
ALIASES = {
    "TR_ID": "TC_KIMLIK",
    "TCKN": "TC_KIMLIK",
    "CREDIT_CARD": "KREDI_KARTI",
    "PHONE": "TELEFON",
    "PLATE": "TR_PLAKA",
    "BIRTH_DATE": "DOGUM_TARIHI",
    "HEALTH_DATA": "SAGLIK_VERISI",
    "PASSWORD": "HARDCODED_PASS",
}

#: Eski ``{isim: derlenmiş regex}`` sözlüğü — dış betikler için korunuyor.
PATTERNS = {definition.name: definition.regex for definition in PATTERN_DEFS}


def resolve_name(name: str) -> str:
    """Takma adı kanonik desen ismine çevirir."""
    upper = str(name).strip().upper()
    return ALIASES.get(upper, upper)


def get_patterns() -> dict[str, re.Pattern]:
    """Eski API: ``{desen_adı: derlenmiş regex}``."""
    return dict(PATTERNS)


def get_pattern_defs(
    include: list[str] | tuple[str, ...] | None = None,
    exclude: list[str] | tuple[str, ...] | None = None,
) -> tuple[PatternDef, ...]:
    """Filtrelenmiş desen listesi döndürür.

    `include`/`exclude` hem desen ismi hem etiket (``pii``, ``secret``...)
    kabul eder, böylece ``--only secret`` gibi kullanım mümkün olur.
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
