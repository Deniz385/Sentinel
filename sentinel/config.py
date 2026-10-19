"""Katmanlı yapılandırma: varsayılan < dosya (`sentinel.yml`) < ortam < CLI.

Eski sürümde webhook adresi kaynak kodda sabit, Tesseract yolu sabit,
dosya boyutu limiti kodun içine gömülüydü. Buradaki `ScanConfig` tüm bu
kararları tek ve test edilebilir bir yere toplar; ayrıca alt süreçlere
gönderilebilmesi için tamamen picklable tutulur (çağrılabilir alan yok).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, fields, replace

from sentinel.allowlist import Allowlist
from sentinel.severity import Severity

__all__ = ["ScanConfig", "DEFAULT_CONFIG_NAMES", "CONFIG_TEMPLATE"]

DEFAULT_CONFIG_NAMES = ("sentinel.yml", "sentinel.yaml", ".sentinel.yml")

#: Taranacak uzantılar. Uzantısı listede olmayan dosyalara hiç dokunulmaz.
DEFAULT_EXTENSIONS = (
    ".txt", ".csv", ".tsv", ".log", ".md", ".rst", ".ini", ".cfg", ".conf",
    ".env", ".json", ".yml", ".yaml", ".xml", ".toml", ".sql", ".properties",
    ".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".rb", ".go", ".java", ".cs",
    ".kt", ".swift", ".sh", ".bash", ".ps1", ".bat", ".html", ".htm", ".css",
    ".pdf", ".docx", ".xlsx", ".xlsm", ".pptx",
    ".zip",
    ".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff", ".webp",
    # Uzantısız dosyalar: `id_rsa`, `credentials`, `Dockerfile`, `.npmrc`
    # gibi yüksek değerli hedefler burada yaşar. Binary olanlar
    # çıkarıcıdaki NUL denetimiyle zaten anında elenir.
    "",
)

#: Hiç girilmeyecek dizinler (zaman kaybı ve gürültü kaynağı).
DEFAULT_EXCLUDE_DIRS = (
    ".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", "node_modules", "venv", ".venv", "env", "dist", "build",
    ".tox", ".idea", ".vscode", "site-packages", "KARANTINA_BOLGESI",
    "QUARANTINE_ZONE", "Windows", "Program Files", "Program Files (x86)",
    "AppData", "$Recycle.Bin", "System Volume Information",
)


@dataclass
class ScanConfig:
    """Bir tarama çalıştırmasının tüm ayarları."""

    # --- hedef ve kapsam ---
    target: str = "."
    extensions: tuple[str, ...] = DEFAULT_EXTENSIONS
    exclude_dirs: tuple[str, ...] = DEFAULT_EXCLUDE_DIRS
    exclude_globs: tuple[str, ...] = ()
    follow_symlinks: bool = False
    max_file_size: int = 100 * 1024 * 1024  # 100 MB
    #: Metin dosyaları akışlı okunur; tek seferde bellekte tutulan satır sayısı.
    chunk_lines: int = 5000
    max_line_length: int = 8192

    # --- desen seçimi ---
    include_rules: tuple[str, ...] = ()
    exclude_rules: tuple[str, ...] = ()
    min_severity: str = Severity.INFO.value
    entropy_scan: bool = True
    entropy_threshold: float = 4.2

    # --- arşiv güvenliği (zip bomb koruması) ---
    archive_enabled: bool = True
    archive_max_depth: int = 3
    archive_max_members: int = 2000
    archive_max_total_bytes: int = 512 * 1024 * 1024
    archive_max_ratio: int = 200

    # --- OCR ---
    ocr: bool = False
    ocr_langs: str = "tur+eng"
    tesseract_cmd: str = ""
    tessdata_prefix: str = ""
    ocr_pdf_images: bool = False

    # --- YARA ---
    yara_enabled: bool = True
    yara_rules_dir: str = "rules"

    # --- çalıştırma ---
    workers: int = 0  # 0 = otomatik
    executor: str = "auto"  # auto | process | thread | serial

    # --- eylemler ---
    quarantine: bool = False
    quarantine_dir: str = "KARANTINA_BOLGESI"
    quarantine_min_severity: str = Severity.HIGH.value
    shred_original: bool = False

    # --- bildirim ---
    webhook_url: str = ""
    webhook_min_severity: str = Severity.HIGH.value
    webhook_batch: bool = True

    # --- gizlilik ---
    fingerprint_salt: str = ""
    snippet_enabled: bool = True

    # --- yanlış pozitif yönetimi ---
    allowlist: Allowlist = field(default_factory=Allowlist)
    baseline_path: str = ""

    # --- denetim ---
    audit_log: str = ""

    # ------------------------------------------------------------------
    def __post_init__(self):
        # Boş dize "uzantısız dosya" demektir (id_rsa, Dockerfile,
        # credentials) ve korunmalıdır; önüne nokta eklemek bu dosyaları
        # tamamen taranamaz hâle getiriyordu.
        self.extensions = tuple(
            ""
            if not e
            else (e.lower() if e.startswith(".") else f".{e.lower()}")
            for e in self.extensions
        )
        self.exclude_dirs = tuple(self.exclude_dirs)
        self.exclude_globs = tuple(self.exclude_globs)
        self.include_rules = tuple(self.include_rules)
        self.exclude_rules = tuple(self.exclude_rules)
        self.min_severity = Severity.parse(self.min_severity).value
        self.quarantine_min_severity = Severity.parse(self.quarantine_min_severity).value
        self.webhook_min_severity = Severity.parse(self.webhook_min_severity).value
        if isinstance(self.allowlist, dict):
            self.allowlist = Allowlist.from_dict(self.allowlist)

    # ------------------------------------------------------------------
    @property
    def min_severity_enum(self) -> Severity:
        return Severity.parse(self.min_severity)

    def worker_count(self) -> int:
        if self.workers > 0:
            return self.workers
        return max(1, min(8, (os.cpu_count() or 2)))

    def replace(self, **kwargs) -> ScanConfig:
        return replace(self, **kwargs)

    def to_dict(self) -> dict:
        data = {}
        for item in fields(self):
            value = getattr(self, item.name)
            if isinstance(value, Allowlist):
                value = {
                    "paths": list(value.paths),
                    "values": list(value.values),
                    "fingerprints": list(value.fingerprints),
                    "patterns": list(value.patterns),
                    "rules": list(value.rules),
                    "use_defaults": value.use_defaults,
                    "inline": value.inline,
                }
            elif isinstance(value, tuple):
                value = list(value)
            data[item.name] = value
        return data

    # ------------------------------------------------------------------
    @classmethod
    def from_dict(cls, data: dict | None) -> ScanConfig:
        data = dict(data or {})
        known = {item.name for item in fields(cls)}
        unknown = set(data) - known
        if unknown:
            raise ValueError(
                "Bilinmeyen yapılandırma anahtar(lar)ı: " + ", ".join(sorted(unknown))
            )
        if "allowlist" in data:
            data["allowlist"] = Allowlist.from_dict(data["allowlist"])
        return cls(**data)

    @classmethod
    def from_file(cls, path: str) -> ScanConfig:
        """YAML veya JSON yapılandırma dosyası okur."""
        import json

        with open(path, encoding="utf-8") as handle:
            text = handle.read()

        data: dict
        if path.lower().endswith((".yml", ".yaml")):
            try:
                import yaml
            except ImportError as exc:  # pragma: no cover
                raise RuntimeError(
                    "YAML yapılandırması için PyYAML gerekli: pip install pyyaml"
                ) from exc
            data = yaml.safe_load(text) or {}
        else:
            data = json.loads(text or "{}")

        if not isinstance(data, dict):
            raise ValueError(f"Yapılandırma dosyası bir sözlük olmalı: {path}")
        return cls.from_dict(data)

    @classmethod
    def discover(cls, start: str = ".") -> ScanConfig | None:
        """Çalışma dizininde (ve üst dizinlerinde) yapılandırma arar."""
        current = os.path.abspath(start)
        while True:
            for name in DEFAULT_CONFIG_NAMES:
                candidate = os.path.join(current, name)
                if os.path.isfile(candidate):
                    return cls.from_file(candidate)
            parent = os.path.dirname(current)
            if parent == current:
                return None
            current = parent

    def with_env(self, environ: dict | None = None) -> ScanConfig:
        """Ortam değişkenlerini (``SENTINEL_*``) üzerine bindirir.

        Sırlar (webhook adresi, parmak izi tuzu) kaynak kodda ya da
        yapılandırma dosyasında değil, ortamda durmalıdır.
        """
        env = os.environ if environ is None else environ
        overrides: dict = {}

        mapping_str = {
            "SENTINEL_WEBHOOK_URL": "webhook_url",
            "SENTINEL_FINGERPRINT_SALT": "fingerprint_salt",
            "SENTINEL_TESSERACT_CMD": "tesseract_cmd",
            "SENTINEL_TESSDATA_PREFIX": "tessdata_prefix",
            "SENTINEL_QUARANTINE_DIR": "quarantine_dir",
            "SENTINEL_MIN_SEVERITY": "min_severity",
            "SENTINEL_AUDIT_LOG": "audit_log",
            "SENTINEL_YARA_RULES_DIR": "yara_rules_dir",
            "SENTINEL_EXECUTOR": "executor",
        }
        for key, attr in mapping_str.items():
            if env.get(key):
                overrides[attr] = env[key]

        if env.get("SENTINEL_WORKERS"):
            try:
                overrides["workers"] = int(env["SENTINEL_WORKERS"])
            except ValueError:
                pass
        if env.get("SENTINEL_MAX_FILE_SIZE"):
            try:
                overrides["max_file_size"] = int(env["SENTINEL_MAX_FILE_SIZE"])
            except ValueError:
                pass
        for key, attr in (
            ("SENTINEL_OCR", "ocr"),
            ("SENTINEL_ENTROPY_SCAN", "entropy_scan"),
            ("SENTINEL_YARA", "yara_enabled"),
        ):
            if env.get(key):
                overrides[attr] = env[key].strip().lower() in ("1", "true", "yes", "on")

        return self.replace(**overrides) if overrides else self


CONFIG_TEMPLATE = """\
# Sentinel yapılandırması
# Sırları buraya YAZMAYIN; ortam değişkeni kullanın:
#   SENTINEL_WEBHOOK_URL, SENTINEL_FINGERPRINT_SALT

target: .

# Taranacak uzantılar (boş bırakılırsa varsayılan liste kullanılır)
# extensions: [.txt, .csv, .pdf, .docx, .xlsx, .zip, .py, .env]

exclude_dirs:
  - .git
  - node_modules
  - venv
  - __pycache__

exclude_globs:
  - "*.min.js"
  - "*.lock"

# info | low | medium | high | critical
min_severity: low

# Entropi tabanlı generic sır avı
entropy_scan: true
entropy_threshold: 4.2

# Arşiv (ZIP) tarama ve zip-bomb koruması
archive_enabled: true
archive_max_depth: 3
archive_max_members: 2000

# Görsellerde OCR (Tesseract kurulu olmalı)
ocr: false
ocr_langs: tur+eng

# 0 = CPU sayısına göre otomatik
workers: 0

# Karantina (hassas dosyayı şifreleyip izole eder) — dikkatli kullanın
quarantine: false
quarantine_min_severity: critical

# Yanlış pozitif yönetimi
allowlist:
  paths:
    - "tests/**"
    - "test_data/**"
    - "*.example"
  values: []
  fingerprints: []
  patterns: []
  rules: []
  use_defaults: true
  inline: true

# Denetim izi (JSONL)
# audit_log: logs/audit.jsonl
"""
