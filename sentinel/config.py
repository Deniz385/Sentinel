"""Layered configuration: defaults < file (`sentinel.yml`) < env < CLI.

In the previous version the webhook address was hard-coded, the
Tesseract path was hard-coded and the file-size limit was buried in the
code. `ScanConfig` collects all of those decisions in one testable
place, and is kept fully picklable (no callable fields) so it can be
sent to worker processes.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, fields, replace

from sentinel.allowlist import Allowlist
from sentinel.severity import Severity

__all__ = ["ScanConfig", "DEFAULT_CONFIG_NAMES", "CONFIG_TEMPLATE"]

DEFAULT_CONFIG_NAMES = ("sentinel.yml", "sentinel.yaml", ".sentinel.yml")

#: Extensions to scan. Files whose extension is not listed are skipped.
DEFAULT_EXTENSIONS = (
    ".txt", ".csv", ".tsv", ".log", ".md", ".rst", ".ini", ".cfg", ".conf",
    ".env", ".json", ".yml", ".yaml", ".xml", ".toml", ".sql", ".properties",
    ".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".rb", ".go", ".java", ".cs",
    ".kt", ".swift", ".sh", ".bash", ".ps1", ".bat", ".html", ".htm", ".css",
    ".pdf", ".docx", ".xlsx", ".xlsm", ".pptx",
    ".zip",
    ".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff", ".webp",
    # Extensionless files: high-value targets such as `id_rsa`,
    # `credentials`, `Dockerfile` and `.npmrc` live here. Binary ones are
    # rejected immediately by the NUL check in the extractor.
    "",
)

#: Directories never descended into (a waste of time and a noise source).
DEFAULT_EXCLUDE_DIRS = (
    ".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", "node_modules", "venv", ".venv", "env", "dist", "build",
    ".tox", ".idea", ".vscode", "site-packages", "KARANTINA_BOLGESI",
    "QUARANTINE_ZONE", "Windows", "Program Files", "Program Files (x86)",
    "AppData", "$Recycle.Bin", "System Volume Information",
)


@dataclass
class ScanConfig:
    """Every setting for one scan run."""

    # --- target and scope ---
    target: str = "."
    extensions: tuple[str, ...] = DEFAULT_EXTENSIONS
    exclude_dirs: tuple[str, ...] = DEFAULT_EXCLUDE_DIRS
    exclude_globs: tuple[str, ...] = ()
    follow_symlinks: bool = False
    max_file_size: int = 100 * 1024 * 1024  # 100 MB
    #: Text files are read in a stream; lines held in memory at once.
    chunk_lines: int = 5000
    max_line_length: int = 8192

    # --- pattern selection ---
    include_rules: tuple[str, ...] = ()
    exclude_rules: tuple[str, ...] = ()
    min_severity: str = Severity.INFO.value
    entropy_scan: bool = True
    entropy_threshold: float = 4.2

    # --- archive safety (zip-bomb protection) ---
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

    # --- execution ---
    workers: int = 0  # 0 = automatic
    executor: str = "auto"  # auto | process | thread | serial

    # --- actions ---
    quarantine: bool = False
    quarantine_dir: str = "QUARANTINE_ZONE"
    quarantine_min_severity: str = Severity.HIGH.value
    shred_original: bool = False

    # --- notification ---
    webhook_url: str = ""
    webhook_min_severity: str = Severity.HIGH.value
    webhook_batch: bool = True

    # --- privacy ---
    fingerprint_salt: str = ""
    snippet_enabled: bool = True

    # --- false-positive management ---
    allowlist: Allowlist = field(default_factory=Allowlist)
    baseline_path: str = ""

    # --- audit ---
    audit_log: str = ""

    # --- incremental scanning ---
    #: Off by default: a security tool should not rely on the assumption
    #: "this file has not changed" unless asked to.
    incremental: bool = False
    cache_path: str = ""

    # ------------------------------------------------------------------
    def __post_init__(self):
        # An empty string means "file with no extension" (id_rsa,
        # Dockerfile, credentials) and must be preserved; prefixing a dot
        # made those files impossible to scan at all.
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
                "Unknown configuration key(s): " + ", ".join(sorted(unknown))
            )
        if "allowlist" in data:
            data["allowlist"] = Allowlist.from_dict(data["allowlist"])
        return cls(**data)

    @classmethod
    def from_file(cls, path: str) -> ScanConfig:
        """Read a YAML or JSON configuration file."""
        import json

        with open(path, encoding="utf-8") as handle:
            text = handle.read()

        data: dict
        if path.lower().endswith((".yml", ".yaml")):
            try:
                import yaml
            except ImportError as exc:  # pragma: no cover
                raise RuntimeError(
                    "PyYAML is required for YAML configuration: pip install pyyaml"
                ) from exc
            data = yaml.safe_load(text) or {}
        else:
            data = json.loads(text or "{}")

        if not isinstance(data, dict):
            raise ValueError(f"Configuration file must be a mapping: {path}")
        return cls.from_dict(data)

    @classmethod
    def discover(cls, start: str = ".") -> ScanConfig | None:
        """Look for a configuration file in this directory and its parents."""
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
        """Overlay environment variables (``SENTINEL_*``).

        Secrets - the webhook address, the fingerprint salt - belong in
        the environment, not in source code or a configuration file.
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
            "SENTINEL_CACHE_PATH": "cache_path",
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
            ("SENTINEL_INCREMENTAL", "incremental"),
        ):
            if env.get(key):
                overrides[attr] = env[key].strip().lower() in ("1", "true", "yes", "on")

        return self.replace(**overrides) if overrides else self


CONFIG_TEMPLATE = """\
# Sentinel configuration
# Do NOT put secrets here; use environment variables:
#   SENTINEL_WEBHOOK_URL, SENTINEL_FINGERPRINT_SALT

target: .

# Extensions to scan (leave unset to use the built-in list)
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

# Entropy-based hunting for generic secrets
entropy_scan: true
entropy_threshold: 4.2

# Archive (ZIP) scanning and zip-bomb protection
archive_enabled: true
archive_max_depth: 3
archive_max_members: 2000

# OCR on images (requires Tesseract)
ocr: false
ocr_langs: tur+eng

# 0 = automatic, based on CPU count
workers: 0

# Quarantine encrypts and isolates sensitive files - use with care
quarantine: false
quarantine_min_severity: critical

# False-positive management
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

# Incremental scanning: skip unchanged files via the cache.
# The cache drops itself when the rule catalogue or this file changes.
# It is never used while quarantine is on (a decision that deletes data
# cannot rest on stale evidence).
incremental: false
# cache_path: .sentinel-cache.json

# Audit trail (JSONL)
# audit_log: logs/audit.jsonl
"""
