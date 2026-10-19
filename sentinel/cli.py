"""Komut satırı arayüzü.

v3.0'da tek bir `main.py` vardı: üç argüman, çıkış kodu hep 0, OCR ve
karantina anahtarları erişilemezdi. Buradaki CLI alt komutlara ayrılır ve
**anlamlı çıkış kodları** döndürür — bu olmadan CI entegrasyonu mümkün
değildir:

* ``0`` — temiz (ya da eşik altında bulgu)
* ``1`` — ``--fail-on`` eşiğinde veya üstünde bulgu var
* ``2`` — çalıştırma hatası
* ``130`` — kullanıcı iptal etti (Ctrl-C)
"""

from __future__ import annotations

import argparse
import os
import sys

from sentinel import __version__
from sentinel.config import CONFIG_TEMPLATE, DEFAULT_CONFIG_NAMES, ScanConfig
from sentinel.severity import Severity

__all__ = ["main", "build_parser"]

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
EXIT_INTERRUPTED = 130

_BANNER = r"""
   ____             _   _            _
  / ___|  ___ _ __ | |_(_)_ __   ___| |
  \___ \ / _ \ '_ \| __| | '_ \ / _ \ |
   ___) |  __/ | | | |_| | | | |  __/ |
  |____/ \___|_| |_|\__|_|_| |_|\___|_|   v{version}
  Hassas Veri Keşif ve Sızıntı Önleme (DLP)
"""


# ---------------------------------------------------------------------------
# Renkli çıktı (TTY değilse ya da NO_COLOR varsa düz metin)
# ---------------------------------------------------------------------------
class _Style:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def __call__(self, text: str, code: str) -> str:
        if not self.enabled:
            return text
        return f"\033[{code}m{text}\033[0m"

    def dim(self, text):
        return self(text, "2")

    def bold(self, text):
        return self(text, "1")

    def red(self, text):
        return self(text, "31;1")

    def yellow(self, text):
        return self(text, "33")

    def green(self, text):
        return self(text, "32")

    def cyan(self, text):
        return self(text, "36")

    def severity(self, severity: Severity, text: str) -> str:
        return {
            Severity.CRITICAL: self.red,
            Severity.HIGH: self.red,
            Severity.MEDIUM: self.yellow,
            Severity.LOW: self.cyan,
            Severity.INFO: self.dim,
        }[severity](text)


def _make_style(no_color: bool) -> _Style:
    enabled = (
        not no_color
        and not os.environ.get("NO_COLOR")
        and sys.stdout.isatty()
    )
    return _Style(enabled)


# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Sentinel — hassas veri keşif ve sızıntı önleme aracı.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Örnekler:\n"
            "  sentinel scan ~/Belgeler --format html,csv\n"
            "  sentinel scan . --fail-on high --format sarif\n"
            "  sentinel scan . --ocr --quarantine --min-severity high\n"
            "  sentinel watch ~/Indirilenler\n"
            "  sentinel vault list\n"
            "  sentinel precommit\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"Sentinel {__version__}")
    parser.add_argument("--no-color", action="store_true", help="ANSI renklerini kapat")
    subparsers = parser.add_subparsers(dest="command")

    # -- scan -------------------------------------------------------------
    scan = subparsers.add_parser("scan", help="Bir dizini veya dosyayı tara")
    scan.add_argument("target", nargs="?", default=None, help="Taranacak yol")
    scan.add_argument("--target", "-t", dest="target_opt", help="Taranacak yol (eski biçim)")
    scan.add_argument("--output", "-o", default=".", help="Rapor dizini (varsayılan: .)")
    scan.add_argument(
        "--format",
        "-f",
        default="html,csv",
        help="Rapor biçimleri: html,csv,json,sarif,md,pdf (virgülle)",
    )
    scan.add_argument("--no-report", action="store_true", help="Hiç rapor yazma")
    scan.add_argument("--config", "-c", help="Yapılandırma dosyası (sentinel.yml)")
    scan.add_argument("--min-severity", help="Bu dereceden düşük bulguları yoksay")
    scan.add_argument(
        "--fail-on",
        help="Bu derecede/üstünde bulgu varsa 1 ile çık (CI kapısı)",
    )
    scan.add_argument("--only", help="Sadece bu kurallar/etiketler (virgülle)")
    scan.add_argument("--skip-rules", help="Bu kuralları atla (virgülle)")
    scan.add_argument("--exclude", action="append", default=[], help="Glob ile dışla")
    scan.add_argument("--workers", "-j", type=int, help="Paralel işçi sayısı (0=otomatik)")
    scan.add_argument(
        "--executor", choices=("auto", "process", "thread", "serial"), help="Yürütme modu"
    )
    scan.add_argument("--max-size", type=int, help="Azami dosya boyutu (bayt)")
    scan.add_argument("--ocr", action="store_true", help="Görsellerde OCR taraması")
    scan.add_argument("--no-archives", action="store_true", help="ZIP içine girme")
    scan.add_argument("--no-entropy", action="store_true", help="Entropi taramasını kapat")
    scan.add_argument("--no-yara", action="store_true", help="YARA kurallarını kapat")
    scan.add_argument("--no-snippet", action="store_true", help="Bağlam alıntısı yazma")
    scan.add_argument(
        "--quarantine", action="store_true", help="Riskli dosyaları şifreleyip izole et"
    )
    scan.add_argument("--shred", action="store_true", help="Orijinali üzerine yazarak sil")
    scan.add_argument("--baseline", help="Baz çizgisi dosyası (bulguları bastır)")
    scan.add_argument(
        "--write-baseline", help="Mevcut bulguları baz çizgisi olarak kaydet"
    )
    scan.add_argument("--webhook", help="Bildirim webhook adresi")
    scan.add_argument("--audit-log", help="JSONL denetim izi dosyası")
    scan.add_argument("--quiet", "-q", action="store_true", help="Sadece özet yaz")
    scan.add_argument("--verbose", "-v", action="store_true", help="Her bulguyu yaz")
    scan.add_argument("--no-html", action="store_true", help=argparse.SUPPRESS)

    # -- watch ------------------------------------------------------------
    watch = subparsers.add_parser("watch", help="Dizini gerçek zamanlı izle")
    watch.add_argument("target", nargs="?", default=".", help="İzlenecek dizin")
    watch.add_argument("--config", "-c", help="Yapılandırma dosyası")
    watch.add_argument("--ocr", action="store_true", help="Görsellerde OCR")
    watch.add_argument("--quarantine", action="store_true", help="Bulguda izole et")
    watch.add_argument("--min-severity", help="Alt eşik")

    # -- vault ------------------------------------------------------------
    vault = subparsers.add_parser("vault", help="Karantina kasasını yönet")
    vault.add_argument(
        "action",
        choices=("list", "restore", "verify", "purge", "migrate"),
        help="Yapılacak işlem",
    )
    vault.add_argument("name", nargs="?", help="Kasa dosyası adı (restore/purge için)")
    vault.add_argument("--dir", default="KARANTINA_BOLGESI", help="Kasa dizini")
    vault.add_argument("--to", help="Geri yüklenecek hedef yol")
    vault.add_argument("--force", action="store_true", help="Hedefin üzerine yaz")
    vault.add_argument("--all", action="store_true", help="Tüm kasayı boşalt (purge)")
    vault.add_argument("--shred", action="store_true", help="Üzerine yazarak sil")

    # -- rules ------------------------------------------------------------
    rules = subparsers.add_parser("rules", help="Tespit kurallarını listele")
    rules.add_argument("--tag", help="Sadece bu etiketi taşıyan kurallar")
    rules.add_argument("--json", action="store_true", help="JSON olarak yaz")

    # -- precommit --------------------------------------------------------
    precommit = subparsers.add_parser(
        "precommit", help="Commit edilmek üzere hazırlanmış (staged) dosyaları tara"
    )
    precommit.add_argument("--config", "-c", help="Yapılandırma dosyası")
    precommit.add_argument(
        "--fail-on", default="high", help="Bu derece ve üstünde commit'i engelle"
    )
    precommit.add_argument("--install", action="store_true", help="Git kancasını kur")

    # -- init -------------------------------------------------------------
    init = subparsers.add_parser("init", help="Örnek sentinel.yml oluştur")
    init.add_argument("--force", action="store_true", help="Varsa üzerine yaz")

    # -- doctor -----------------------------------------------------------
    subparsers.add_parser("doctor", help="Ortam ve bağımlılık kontrolü")

    return parser


# ---------------------------------------------------------------------------
def _load_config(args) -> ScanConfig:
    """Yapılandırmayı katmanlı olarak kurar: dosya → ortam → CLI."""
    path = getattr(args, "config", None)
    if path:
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Yapılandırma dosyası bulunamadı: {path}")
        config = ScanConfig.from_file(path)
    else:
        config = ScanConfig.discover() or ScanConfig()

    config = config.with_env()

    overrides: dict = {}
    target = getattr(args, "target", None) or getattr(args, "target_opt", None)
    if target:
        overrides["target"] = target

    simple = {
        "min_severity": "min_severity",
        "workers": "workers",
        "executor": "executor",
        "max_size": "max_file_size",
        "baseline": "baseline_path",
        "webhook": "webhook_url",
        "audit_log": "audit_log",
    }
    for arg_name, field_name in simple.items():
        value = getattr(args, arg_name, None)
        if value not in (None, ""):
            overrides[field_name] = value

    if getattr(args, "ocr", False):
        overrides["ocr"] = True
    if getattr(args, "quarantine", False):
        overrides["quarantine"] = True
    if getattr(args, "shred", False):
        overrides["shred_original"] = True
    if getattr(args, "no_archives", False):
        overrides["archive_enabled"] = False
    if getattr(args, "no_entropy", False):
        overrides["entropy_scan"] = False
    if getattr(args, "no_yara", False):
        overrides["yara_enabled"] = False
    if getattr(args, "no_snippet", False):
        overrides["snippet_enabled"] = False
    if getattr(args, "only", None):
        overrides["include_rules"] = tuple(
            item.strip() for item in args.only.split(",") if item.strip()
        )
    if getattr(args, "skip_rules", None):
        overrides["exclude_rules"] = tuple(
            item.strip() for item in args.skip_rules.split(",") if item.strip()
        )
    if getattr(args, "exclude", None):
        overrides["exclude_globs"] = tuple(config.exclude_globs) + tuple(args.exclude)

    return config.replace(**overrides) if overrides else config


def _formats(args) -> list:
    if getattr(args, "no_report", False):
        return []
    raw = [item.strip().lower() for item in (args.format or "").split(",") if item.strip()]
    # Eski `--no-html` anahtarı hâlâ çalışsın.
    if getattr(args, "no_html", False):
        raw = [item for item in raw if item != "html"]
    return raw


# ---------------------------------------------------------------------------
def cmd_scan(args, style: _Style) -> int:
    from sentinel.engine import Scanner

    config = _load_config(args)

    if not args.quiet:
        print(style.cyan(_BANNER.format(version=__version__)))
        print(f"  Hedef      : {os.path.abspath(config.target)}")
        print(f"  Kurallar   : {len(_rule_defs(config))} desen")
        print(f"  Alt eşik   : {config.min_severity}")
        print(
            f"  İşçi       : {config.worker_count()} ({config.executor}) · "
            f"OCR: {'açık' if config.ocr else 'kapalı'} · "
            f"Arşiv: {'açık' if config.archive_enabled else 'kapalı'}"
        )
        if config.quarantine:
            print(
                style.yellow(
                    f"  KARANTİNA AKTİF — {config.quarantine_min_severity} ve üstü "
                    f"bulgulu dosyalar {config.quarantine_dir} içine şifrelenerek taşınacak."
                )
            )
        print()

    def log(message: str):
        if args.verbose:
            print(f"  {style.dim(message)}")

    scanner = Scanner(config.target, config=config, log=log)

    state = {"last": -1}

    def progress(done, total, path):
        if args.quiet or args.verbose or not sys.stdout.isatty() or not total:
            return
        percent = int(100 * done / total)
        if percent == state["last"]:
            return
        state["last"] = percent
        bar_width = 28
        filled = int(bar_width * done / total)
        bar = "█" * filled + "·" * (bar_width - filled)
        sys.stdout.write(f"\r  [{bar}] {percent:3d}%  {done}/{total}")
        sys.stdout.flush()

    try:
        result = scanner.scan(progress=progress)
    except FileNotFoundError as exc:
        print(style.red(f"[HATA] {exc}"), file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        scanner.stop_scan()
        print("\n" + style.yellow("[İPTAL] Tarama kullanıcı tarafından durduruldu."))
        return EXIT_INTERRUPTED

    if not args.quiet and not args.verbose and sys.stdout.isatty():
        sys.stdout.write("\r" + " " * 60 + "\r")

    _print_summary(result, style, args.quiet)

    if args.verbose or (not args.quiet and result.findings):
        _print_findings(result, style)

    if args.write_baseline:
        from sentinel.allowlist import save_baseline

        count = save_baseline(args.write_baseline, result.findings)
        print(f"\n  Baz çizgisi yazıldı: {args.write_baseline} ({count} parmak izi)")

    formats = _formats(args)
    if formats:
        from sentinel.reporting import write_reports

        written = write_reports(result, args.output, formats)
        print()
        for fmt, path in written.items():
            if str(path).startswith("HATA"):
                print(style.yellow(f"  [{fmt}] {path}"))
            else:
                print(f"  {style.green('✓')} {fmt:<6} {path}")

    if result.errors and not args.quiet:
        print(style.dim(f"\n  {len(result.errors)} dosya okunamadı (ayrıntı: JSON raporu)"))

    if args.fail_on and result.findings:
        threshold = Severity.parse(args.fail_on)
        blocking = [f for f in result.findings if f.severity_enum >= threshold]
        if blocking:
            print(
                style.red(
                    f"\n  ✗ KAPI KAPALI: {len(blocking)} bulgu "
                    f"'{threshold.value}' eşiğinde veya üstünde."
                )
            )
            return EXIT_FINDINGS

    return EXIT_OK


def _rule_defs(config):
    from sentinel.patterns import get_pattern_defs

    return get_pattern_defs(
        include=config.include_rules or None, exclude=config.exclude_rules or None
    )


def _print_summary(result, style: _Style, quiet: bool):
    counts = result.counts_by_severity()
    total = len(result.findings)

    if total == 0:
        print(
            style.green(
                f"  ✓ TEMİZ — {result.files_scanned} dosya tarandı, "
                f"hassas veri bulunamadı. ({result.duration:.2f} sn)"
            )
        )
        return

    print(
        style.bold(
            f"  Risk skoru: {result.risk_score}/100  ·  {total} bulgu  ·  "
            f"{result.files_scanned} dosya  ·  {result.duration:.2f} sn"
        )
    )
    parts = []
    for severity in sorted(Severity, key=lambda s: -s.rank):
        count = counts.get(severity.value, 0)
        if count:
            parts.append(style.severity(severity, f"{severity.label_tr}: {count}"))
    if parts:
        print("  " + "  ·  ".join(parts))

    if result.quarantined:
        print(style.yellow(f"  {len(result.quarantined)} dosya karantinaya alındı."))


def _print_findings(result, style: _Style, limit: int = 40):
    if not result.findings:
        return
    print()
    for finding in result.findings[:limit]:
        severity = finding.severity_enum
        tag = style.severity(severity, f"{severity.icon} {severity.label_tr:<7}")
        location = f"{finding.file}:{finding.line}" if finding.line else finding.file
        print(f"  {tag} {finding.type:<22} {location}")
        print(f"            {style.dim(finding.content_masked)}")
    remaining = len(result.findings) - limit
    if remaining > 0:
        print(style.dim(f"  … ve {remaining} bulgu daha (tam liste: rapor dosyaları)"))


# ---------------------------------------------------------------------------
def cmd_watch(args, style: _Style) -> int:
    import time

    from sentinel.engine import Scanner
    from sentinel.monitor import RealTimeMonitor, watchdog_available

    if not watchdog_available():
        print(
            style.red(
                "[HATA] Gerçek zamanlı izleme için watchdog gerekli:\n"
                "       pip install 'sentinel-dlp[monitor]'"
            ),
            file=sys.stderr,
        )
        return EXIT_ERROR

    config = _load_config(args)
    if not os.path.isdir(config.target):
        print(style.red(f"[HATA] Dizin bulunamadı: {config.target}"), file=sys.stderr)
        return EXIT_ERROR

    scanner = Scanner(config.target, config=config)
    print(style.cyan(_BANNER.format(version=__version__)))
    print(f"  İzleniyor: {os.path.abspath(config.target)}")
    print(style.dim("  Durdurmak için Ctrl-C.\n"))

    monitor = RealTimeMonitor(config.target, scanner, log_callback=lambda m: print(f"  {m}"))
    try:
        with monitor:
            while True:
                time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n  İzleme durduruldu.")
        return EXIT_OK


# ---------------------------------------------------------------------------
def cmd_vault(args, style: _Style) -> int:
    from sentinel.quarantine import QuarantineManager, migrate_legacy_dirs

    manager = QuarantineManager(args.dir)

    if args.action == "list":
        items = manager.list_items()
        if not items:
            print(f"  Kasa boş: {manager.q_dir}")
            return EXIT_OK
        print(f"  {manager.q_dir} — {len(items)} dosya\n")
        for item in items:
            flag = style.yellow(" [eski format]") if item.get("legacy") else ""
            print(f"  {style.bold(item['name'])}{flag}")
            print(f"    orijinal : {item.get('original_path') or '(bilinmiyor)'}")
            print(f"    tarih    : {item.get('quarantined_at', '-')}")
            print(f"    boyut    : {item.get('enc_size', 0)} bayt")
        return EXIT_OK

    if args.action == "verify":
        results = manager.verify_all()
        if not results:
            print("  Kasa boş.")
            return EXIT_OK
        failed = 0
        for entry in results:
            if entry["ok"]:
                print(f"  {style.green('✓')} {entry['name']} — {entry['detail']}")
            else:
                failed += 1
                print(f"  {style.red('✗')} {entry['name']} — {entry['detail']}")
        return EXIT_FINDINGS if failed else EXIT_OK

    if args.action == "restore":
        if not args.name:
            print(style.red("[HATA] Geri yüklenecek dosya adı gerekli."), file=sys.stderr)
            return EXIT_ERROR
        ok, message = manager.restore_file(args.name, args.to, force=args.force)
        if ok:
            print(f"  {style.green('✓')} Geri yüklendi: {message}")
            return EXIT_OK
        print(style.red(f"  ✗ {message}"), file=sys.stderr)
        return EXIT_ERROR

    if args.action == "purge":
        if not args.name and not args.all:
            print(
                style.red("[HATA] Dosya adı verin ya da --all kullanın."), file=sys.stderr
            )
            return EXIT_ERROR
        removed = manager.purge(args.name, shred=args.shred)
        print(f"  {removed} dosya kasadan kalıcı olarak silindi.")
        return EXIT_OK

    if args.action == "migrate":
        moved = migrate_legacy_dirs(args.dir)
        print(f"  {moved} dosya eski karantina dizinlerinden taşındı.")
        return EXIT_OK

    return EXIT_ERROR


# ---------------------------------------------------------------------------
def cmd_rules(args, style: _Style) -> int:
    from sentinel.patterns import PATTERN_DEFS

    defs = PATTERN_DEFS
    if args.tag:
        wanted = args.tag.strip().lower()
        defs = tuple(d for d in defs if wanted in d.tags)

    if args.json:
        import json

        print(
            json.dumps(
                [
                    {
                        "name": d.name,
                        "title": d.title,
                        "description": d.description,
                        "severity": d.severity.value,
                        "validator": d.validator,
                        "tags": list(d.tags),
                    }
                    for d in defs
                ],
                indent=2,
                ensure_ascii=False,
            )
        )
        return EXIT_OK

    print(f"  {len(defs)} tespit kuralı\n")
    for definition in defs:
        severity = definition.severity
        marker = style.severity(severity, f"{severity.icon} {severity.label_tr:<7}")
        validator = f" ✓{definition.validator}" if definition.validator else ""
        print(f"  {marker} {style.bold(definition.name)}{style.dim(validator)}")
        print(f"            {definition.title} — {definition.description}")
        if definition.tags:
            print(f"            {style.dim('etiketler: ' + ', '.join(definition.tags))}")
    return EXIT_OK


# ---------------------------------------------------------------------------
_HOOK_SCRIPT = """\
#!/bin/sh
# Sentinel DLP pre-commit kancası
exec sentinel precommit --fail-on high
"""


def cmd_precommit(args, style: _Style) -> int:
    import subprocess

    if args.install:
        hooks_dir = os.path.join(".git", "hooks")
        if not os.path.isdir(hooks_dir):
            print(style.red("[HATA] .git/hooks bulunamadı (git deposu değil?)"), file=sys.stderr)
            return EXIT_ERROR
        hook_path = os.path.join(hooks_dir, "pre-commit")
        if os.path.exists(hook_path):
            print(style.yellow(f"[UYARI] Kanca zaten var: {hook_path}"))
            return EXIT_ERROR
        with open(hook_path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(_HOOK_SCRIPT)
        os.chmod(hook_path, 0o755)
        print(f"  {style.green('✓')} pre-commit kancası kuruldu: {hook_path}")
        return EXIT_OK

    try:
        completed = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        print(style.red(f"[HATA] git çalıştırılamadı: {exc}"), file=sys.stderr)
        return EXIT_ERROR

    staged = [line for line in completed.stdout.splitlines() if line and os.path.isfile(line)]
    if not staged:
        print("  Taranacak hazırlanmış dosya yok.")
        return EXIT_OK

    from sentinel.engine import Scanner

    config = _load_config(args)
    threshold = Severity.parse(args.fail_on)
    findings = []
    for path in staged:
        scanner = Scanner(path, config=config.replace(target=path, quarantine=False))
        findings.extend(scanner.scan_file(path))

    blocking = [f for f in findings if f.severity_enum >= threshold]
    if not blocking:
        print(
            f"  {style.green('✓')} {len(staged)} dosya tarandı, "
            f"'{threshold.value}' eşiğinde bulgu yok."
        )
        return EXIT_OK

    print(style.red(f"\n  ✗ COMMIT ENGELLENDİ — {len(blocking)} hassas veri bulgusu:\n"))
    for finding in blocking[:20]:
        severity = finding.severity_enum
        print(
            f"    {style.severity(severity, severity.label_tr)} {finding.type} "
            f"→ {finding.file}:{finding.line}  {style.dim(finding.content_masked)}"
        )
    print(
        style.dim(
            "\n  Yanlış pozitifse ilgili satıra `sentinel:ignore` yorumu ekleyin\n"
            "  ya da sentinel.yml içindeki allowlist'e yazın."
        )
    )
    return EXIT_FINDINGS


# ---------------------------------------------------------------------------
def cmd_init(args, style: _Style) -> int:
    path = DEFAULT_CONFIG_NAMES[0]
    if os.path.exists(path) and not args.force:
        print(style.yellow(f"[UYARI] {path} zaten var (--force ile üzerine yazın)."))
        return EXIT_ERROR
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(CONFIG_TEMPLATE)
    print(f"  {style.green('✓')} {path} oluşturuldu.")
    return EXIT_OK


def cmd_doctor(args, style: _Style) -> int:
    from sentinel.extractors import image
    from sentinel.monitor import watchdog_available
    from sentinel.quarantine import QuarantineManager
    from sentinel.yara_engine import yara_available

    def check(label: str, ok: bool, detail: str = ""):
        mark = style.green("✓") if ok else style.yellow("○")
        print(f"  {mark} {label:<34} {style.dim(detail)}")

    print(style.cyan(_BANNER.format(version=__version__)))
    print(f"  Python {sys.version.split()[0]} · {sys.platform}\n")

    modules = {
        "Metin / kod taraması": ("stdlib", True),
        "PDF (pypdf)": ("pypdf", _importable("pypdf")),
        "Word (python-docx)": ("docx", _importable("docx")),
        "Excel (openpyxl)": ("openpyxl", _importable("openpyxl")),
        "PowerPoint (python-pptx)": ("pptx", _importable("pptx")),
        "HTML raporu (jinja2)": ("jinja2", _importable("jinja2")),
        "PDF raporu (reportlab)": ("reportlab", _importable("reportlab")),
        "Şifreli karantina (cryptography)": (
            "cryptography",
            QuarantineManager.crypto_available(),
        ),
        "Webhook (requests)": ("requests", _importable("requests")),
        "YAML yapılandırma (pyyaml)": ("yaml", _importable("yaml")),
    }
    for label, (module, ok) in modules.items():
        check(label, ok, "kurulu" if ok else f"eksik: pip install {module}")

    check(
        "Gerçek zamanlı izleme (watchdog)",
        watchdog_available(),
        "kurulu" if watchdog_available() else "eksik: pip install watchdog",
    )
    check(
        "YARA kuralları (yara-python)",
        yara_available(),
        "kurulu" if yara_available() else "eksik: pip install yara-python",
    )

    tesseract = image.find_tesseract()
    check(
        "OCR motoru (Tesseract)",
        bool(tesseract) and _importable("pytesseract"),
        tesseract or "bulunamadı — görsel taraması devre dışı",
    )

    print()
    config = ScanConfig.discover()
    if config:
        print(f"  Yapılandırma bulundu, hedef: {config.target}")
    else:
        print(style.dim("  Yapılandırma dosyası yok — `sentinel init` ile oluşturabilirsiniz."))
    return EXIT_OK


def _importable(name: str) -> bool:
    import importlib.util

    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


# ---------------------------------------------------------------------------
_COMMANDS = {
    "scan": cmd_scan,
    "watch": cmd_watch,
    "vault": cmd_vault,
    "rules": cmd_rules,
    "precommit": cmd_precommit,
    "init": cmd_init,
    "doctor": cmd_doctor,
}


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    style = _make_style(args.no_color)

    if not args.command:
        parser.print_help()
        return EXIT_OK

    handler = _COMMANDS[args.command]
    try:
        return handler(args, style)
    except KeyboardInterrupt:
        print("\n  İptal edildi.")
        return EXIT_INTERRUPTED
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        print(style.red(f"[HATA] {exc}"), file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
