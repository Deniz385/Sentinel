"""The command-line interface.

v3.0 had a single `main.py`: three arguments, an exit code that was
always 0, and no way to reach the OCR or quarantine switches. This CLI
is split into subcommands and returns **meaningful exit codes** -
without them CI integration is impossible:

* ``0`` - clean (or findings below the threshold)
* ``1`` - findings at or above the ``--fail-on`` threshold
* ``2`` - execution error
* ``130`` - cancelled by the user (Ctrl-C)
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


def _ensure_utf8_output():
    """Make sure the output streams can carry non-ASCII characters.

    On Windows, when output is redirected to a file or a pipe, Python
    uses the system's legacy code page (usually cp1252) rather than the
    console writer. That code page has no Turkish letters, so the first
    one raises ``UnicodeEncodeError``:

        sentinel doctor > report.txt
        [ERROR] 'charmap' codec can't encode character '\\u015f'

    This made the tool unusable on Windows in any redirection, script or
    CI step. Switching to UTF-8 writes the file or pipe correctly, and
    ``errors="replace"`` guarantees the output **never** crashes
    whatever the code page - a security tool must not die over one
    letter while writing its report.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError, AttributeError):
            # If the stream cannot be reconfigured (it may be captured
            # or wrapped), at least try to pass lost characters through
            # without crashing.
            try:
                reconfigure(errors="replace")
            except Exception:
                pass

_BANNER = r"""
   ____             _   _            _
  / ___|  ___ _ __ | |_(_)_ __   ___| |
  \___ \ / _ \ '_ \| __| | '_ \ / _ \ |
   ___) |  __/ | | | |_| | | | |  __/ |
  |____/ \___|_| |_|\__|_|_| |_|\___|_|   v{version}
  Sensitive Data Discovery and Loss Prevention (DLP)
"""


# ---------------------------------------------------------------------------
# Coloured output (plain text when not a TTY, or when NO_COLOR is set)
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
        description="Sentinel - sensitive data discovery and loss prevention.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  sentinel scan ~/Documents --format html,csv\n"
            "  sentinel scan . --fail-on high --format sarif\n"
            "  sentinel scan . --ocr --quarantine --min-severity high\n"
            "  sentinel watch ~/Downloads\n"
            "  sentinel vault list\n"
            "  sentinel precommit\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"Sentinel {__version__}")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colours")
    subparsers = parser.add_subparsers(dest="command")

    # -- scan -------------------------------------------------------------
    scan = subparsers.add_parser("scan", help="Scan a directory or a file")
    scan.add_argument("target", nargs="?", default=None, help="Path to scan")
    scan.add_argument("--target", "-t", dest="target_opt", help="Path to scan (legacy form)")
    scan.add_argument("--output", "-o", default=".", help="Report directory (default: .)")
    scan.add_argument(
        "--format",
        "-f",
        default="html,csv",
        help="Report formats: html,csv,json,sarif,md,pdf (comma separated)",
    )
    scan.add_argument("--no-report", action="store_true", help="Write no reports")
    scan.add_argument("--config", "-c", help="Configuration file (sentinel.yml)")
    scan.add_argument("--min-severity", help="Ignore findings below this severity")
    scan.add_argument(
        "--fail-on",
        help="Exit 1 when findings reach this severity (CI gate)",
    )
    scan.add_argument("--only", help="Only these rules or tags (comma separated)")
    scan.add_argument("--skip-rules", help="Skip these rules (comma separated)")
    scan.add_argument("--exclude", action="append", default=[], help="Exclude by glob")
    scan.add_argument("--workers", "-j", type=int, help="Parallel workers (0 = automatic)")
    scan.add_argument(
        "--executor", choices=("auto", "process", "thread", "serial"), help="Execution mode"
    )
    scan.add_argument("--max-size", type=int, help="Maximum file size (bytes)")
    scan.add_argument("--ocr", action="store_true", help="Run OCR over images")
    scan.add_argument("--no-archives", action="store_true", help="Do not descend into ZIPs")
    scan.add_argument("--no-entropy", action="store_true", help="Disable entropy scanning")
    scan.add_argument("--no-yara", action="store_true", help="Disable YARA rules")
    scan.add_argument("--no-snippet", action="store_true", help="Omit context snippets")
    scan.add_argument(
        "--quarantine", action="store_true", help="Encrypt and isolate risky files"
    )
    scan.add_argument("--shred", action="store_true", help="Overwrite the original before deleting")
    scan.add_argument(
        "--incremental",
        action="store_true",
        help="Skip unchanged files via the cache (not usable with quarantine)",
    )
    scan.add_argument("--cache-path", help="Incremental scan cache file")
    scan.add_argument(
        "--clear-cache", action="store_true", help="Delete the cache and run a full scan"
    )
    scan.add_argument("--baseline", help="Baseline file (suppress known findings)")
    scan.add_argument(
        "--write-baseline", help="Save the current findings as a baseline"
    )
    scan.add_argument("--webhook", help="Notification webhook URL")
    scan.add_argument("--audit-log", help="JSONL audit trail file")
    scan.add_argument("--quiet", "-q", action="store_true", help="Print only the summary")
    scan.add_argument("--verbose", "-v", action="store_true", help="Print every finding")
    scan.add_argument("--no-html", action="store_true", help=argparse.SUPPRESS)

    # -- watch ------------------------------------------------------------
    watch = subparsers.add_parser("watch", help="Watch a directory in real time")
    watch.add_argument("target", nargs="?", default=".", help="Directory to watch")
    watch.add_argument("--config", "-c", help="Configuration file")
    watch.add_argument("--ocr", action="store_true", help="Run OCR over images")
    watch.add_argument("--quarantine", action="store_true", help="Isolate on a finding")
    watch.add_argument("--min-severity", help="Lower threshold")

    # -- vault ------------------------------------------------------------
    vault = subparsers.add_parser("vault", help="Manage the quarantine vault")
    vault.add_argument(
        "action",
        choices=("list", "restore", "verify", "purge", "migrate"),
        help="Action to perform",
    )
    vault.add_argument("name", nargs="?", help="Vault file name (for restore/purge)")
    vault.add_argument("--dir", default="KARANTINA_BOLGESI", help="Vault directory")
    vault.add_argument("--to", help="Destination path to restore to")
    vault.add_argument("--force", action="store_true", help="Overwrite the destination")
    vault.add_argument("--all", action="store_true", help="Empty the whole vault (purge)")
    vault.add_argument("--shred", action="store_true", help="Overwrite before deleting")

    # -- rules ------------------------------------------------------------
    rules = subparsers.add_parser("rules", help="List the detection rules")
    rules.add_argument("--tag", help="Only rules carrying this tag")
    rules.add_argument("--json", action="store_true", help="Print as JSON")

    # -- precommit --------------------------------------------------------
    precommit = subparsers.add_parser(
        "precommit", help="Scan the files staged for commit"
    )
    precommit.add_argument("--config", "-c", help="Configuration file")
    precommit.add_argument(
        "--fail-on", default="high", help="Block the commit at this severity or above"
    )
    precommit.add_argument("--install", action="store_true", help="Install the git hook")

    # -- init -------------------------------------------------------------
    init = subparsers.add_parser("init", help="Create an example sentinel.yml")
    init.add_argument("--force", action="store_true", help="Overwrite an existing file")

    # -- doctor -----------------------------------------------------------
    subparsers.add_parser("doctor", help="Check the environment and dependencies")

    return parser


# ---------------------------------------------------------------------------
def _load_config(args) -> ScanConfig:
    """Build the configuration in layers: file -> environment -> CLI."""
    path = getattr(args, "config", None)
    if path:
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Configuration file not found: {path}")
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
        "cache_path": "cache_path",
    }
    for arg_name, field_name in simple.items():
        value = getattr(args, arg_name, None)
        if value not in (None, ""):
            overrides[field_name] = value

    if getattr(args, "incremental", False):
        overrides["incremental"] = True
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
    # Keep the legacy `--no-html` switch working.
    if getattr(args, "no_html", False):
        raw = [item for item in raw if item != "html"]
    return raw


# ---------------------------------------------------------------------------
def cmd_scan(args, style: _Style) -> int:
    from sentinel.engine import Scanner

    config = _load_config(args)

    if not args.quiet:
        print(style.cyan(_BANNER.format(version=__version__)))
        print(f"  Target     : {os.path.abspath(config.target)}")
        print(f"  Rules      : {len(_rule_defs(config))} patterns")
        print(f"  Threshold  : {config.min_severity}")
        print(
            f"  Workers    : {config.worker_count()} ({config.executor}) · "
            f"OCR: {'on' if config.ocr else 'off'} · "
            f"Archives: {'on' if config.archive_enabled else 'off'}"
        )
        if config.incremental and not config.quarantine:
            print(f"  Incremental: on · cache {_cache_path(config)}")
        if config.quarantine:
            print(
                style.yellow(
                    f"  QUARANTINE ACTIVE - files with findings at "
                    f"{config.quarantine_min_severity} or above will be encrypted "
                    f"and moved into {config.quarantine_dir}."
                )
            )
        print()

    if getattr(args, "clear_cache", False):
        from sentinel.cache import clear_cache

        path = _cache_path(config)
        removed = clear_cache(path)
        if not args.quiet:
            print(
                f"  Cache deleted: {path}"
                if removed
                else f"  No cache to delete: {path}"
            )

    if config.incremental and config.quarantine:
        # Say it rather than ignoring it silently: the user expects a
        # fast scan, will get a full one, and should know why.
        print(
            style.yellow(
                "  [WARNING] Quarantine is on - the incremental cache will "
                "not be used. A decision that deletes data cannot rest on "
                "stale evidence."
            )
        )

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
        print(style.red(f"[ERROR] {exc}"), file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        scanner.stop_scan()
        print("\n" + style.yellow("[CANCELLED] The scan was stopped by the user."))
        return EXIT_INTERRUPTED

    if not args.quiet and not args.verbose and sys.stdout.isatty():
        sys.stdout.write("\r" + " " * 60 + "\r")

    _print_summary(result, style, args.quiet)

    if args.verbose or (not args.quiet and result.findings):
        _print_findings(result, style)

    if args.write_baseline:
        from sentinel.allowlist import save_baseline

        count = save_baseline(args.write_baseline, result.findings)
        print(f"\n  Baseline written: {args.write_baseline} ({count} fingerprints)")

    formats = _formats(args)
    if formats:
        from sentinel.reporting import write_reports

        written = write_reports(result, args.output, formats)
        print()
        for fmt, path in written.items():
            if str(path).startswith("ERROR"):
                print(style.yellow(f"  [{fmt}] {path}"))
            else:
                print(f"  {style.green('✓')} {fmt:<6} {path}")

    if result.errors and not args.quiet:
        print(style.dim(f"\n  {len(result.errors)} files could not be read (details: JSON report)"))

    if args.fail_on and result.findings:
        threshold = Severity.parse(args.fail_on)
        blocking = [f for f in result.findings if f.severity_enum >= threshold]
        if blocking:
            print(
                style.red(
                    f"\n  ✗ GATE CLOSED: {len(blocking)} findings at or above "
                    f"'{threshold.value}'."
                )
            )
            return EXIT_FINDINGS

    return EXIT_OK


def _cache_path(config) -> str:
    from sentinel.cache import DEFAULT_CACHE_NAME

    return config.cache_path or DEFAULT_CACHE_NAME


def _rule_defs(config):
    from sentinel.patterns import get_pattern_defs

    return get_pattern_defs(
        include=config.include_rules or None, exclude=config.exclude_rules or None
    )


def _print_summary(result, style: _Style, quiet: bool):
    counts = result.counts_by_severity()
    total = len(result.findings)
    cached = (
        style.dim(f"  ({result.files_cached} files from cache)")
        if result.files_cached
        else ""
    )

    if total == 0:
        print(
            style.green(
                f"  ✓ CLEAN - {result.files_scanned} files scanned, "
                f"no sensitive data found. ({result.duration:.2f} s)"
            )
            + cached
        )
        return

    unique = result.unique_count
    # "207 findings" tells the analyst there are 207 items of work, yet
    # 40 copies of one key close with a single revocation. Print both.
    found = f"{total} findings"
    if unique != total:
        found += f" / {unique} unique secrets"
    print(
        style.bold(
            f"  Risk score: {result.risk_score}/100  ·  {found}  ·  "
            f"{result.files_scanned} files  ·  {result.duration:.2f} s"
        )
        + cached
    )
    parts = []
    for severity in sorted(Severity, key=lambda s: -s.rank):
        count = counts.get(severity.value, 0)
        if count:
            parts.append(style.severity(severity, f"{severity.label}: {count}"))
    if parts:
        print("  " + "  ·  ".join(parts))

    if result.quarantined:
        print(style.yellow(f"  {len(result.quarantined)} files moved to quarantine."))

    _print_shared_secrets(result, style)


def _print_shared_secrets(result, style: _Style, limit: int = 5):
    """Surface the secrets copied into more than one file.

    When a secret occurs in 40 files, one line beats scrolling 40 rows:
    the work is revoking that one key.
    """
    shared = result.shared_secrets()
    if not shared:
        return
    print()
    print(
        style.bold(
            f"  {len(shared)} secrets copied into more than one file "
            "(each closes with a single revocation):"
        )
    )
    for group in shared[:limit]:
        severity = group.severity_enum
        print(
            f"    {style.severity(severity, severity.icon)} "
            f"{group.type:<22} in {group.file_count} files  "
            f"{style.dim(group.content_masked)}"
        )
    remaining = len(shared) - limit
    if remaining > 0:
        print(style.dim(f"    … and {remaining} more secrets (full list: reports)"))


def _print_findings(result, style: _Style, limit: int = 40):
    if not result.findings:
        return
    print()
    for finding in result.findings[:limit]:
        severity = finding.severity_enum
        tag = style.severity(severity, f"{severity.icon} {severity.label:<8}")
        location = f"{finding.file}:{finding.line}" if finding.line else finding.file
        print(f"  {tag} {finding.type:<22} {location}")
        print(f"            {style.dim(finding.content_masked)}")
    remaining = len(result.findings) - limit
    if remaining > 0:
        print(style.dim(f"  … and {remaining} more findings (full list: report files)"))


# ---------------------------------------------------------------------------
def cmd_watch(args, style: _Style) -> int:
    import time

    from sentinel.engine import Scanner
    from sentinel.monitor import RealTimeMonitor, watchdog_available

    if not watchdog_available():
        print(
            style.red(
                "[ERROR] Real-time monitoring requires watchdog:\n"
                "        pip install 'sentinel-dlp[monitor]'"
            ),
            file=sys.stderr,
        )
        return EXIT_ERROR

    config = _load_config(args)
    if not os.path.isdir(config.target):
        print(style.red(f"[ERROR] Directory not found: {config.target}"), file=sys.stderr)
        return EXIT_ERROR

    scanner = Scanner(config.target, config=config)
    print(style.cyan(_BANNER.format(version=__version__)))
    print(f"  Watching: {os.path.abspath(config.target)}")
    print(style.dim("  Press Ctrl-C to stop.\n"))

    monitor = RealTimeMonitor(config.target, scanner, log_callback=lambda m: print(f"  {m}"))
    try:
        with monitor:
            while True:
                time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n  Monitoring stopped.")
        return EXIT_OK


# ---------------------------------------------------------------------------
def cmd_vault(args, style: _Style) -> int:
    from sentinel.quarantine import QuarantineManager, migrate_legacy_dirs

    manager = QuarantineManager(args.dir)

    if args.action == "list":
        items = manager.list_items()
        if not items:
            print(f"  Vault is empty: {manager.q_dir}")
            return EXIT_OK
        print(f"  {manager.q_dir} - {len(items)} files\n")
        for item in items:
            flag = style.yellow(" [legacy format]") if item.get("legacy") else ""
            print(f"  {style.bold(item['name'])}{flag}")
            print(f"    original : {item.get('original_path') or '(unknown)'}")
            print(f"    date     : {item.get('quarantined_at', '-')}")
            print(f"    size     : {item.get('enc_size', 0)} bytes")
        return EXIT_OK

    if args.action == "verify":
        results = manager.verify_all()
        if not results:
            print("  Vault is empty.")
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
            print(style.red("[ERROR] A file name to restore is required."), file=sys.stderr)
            return EXIT_ERROR
        ok, message = manager.restore_file(args.name, args.to, force=args.force)
        if ok:
            print(f"  {style.green('✓')} Restored: {message}")
            return EXIT_OK
        print(style.red(f"  ✗ {message}"), file=sys.stderr)
        return EXIT_ERROR

    if args.action == "purge":
        if not args.name and not args.all:
            print(
                style.red("[ERROR] Give a file name or use --all."), file=sys.stderr
            )
            return EXIT_ERROR
        removed = manager.purge(args.name, shred=args.shred)
        print(f"  {removed} files permanently deleted from the vault.")
        return EXIT_OK

    if args.action == "migrate":
        moved = migrate_legacy_dirs(args.dir)
        print(f"  {moved} files moved from legacy quarantine directories.")
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

    print(f"  {len(defs)} detection rules\n")
    for definition in defs:
        severity = definition.severity
        marker = style.severity(severity, f"{severity.icon} {severity.label:<7}")
        validator = f" ✓{definition.validator}" if definition.validator else ""
        print(f"  {marker} {style.bold(definition.name)}{style.dim(validator)}")
        print(f"            {definition.title} — {definition.description}")
        if definition.tags:
            print(f"            {style.dim('tags: ' + ', '.join(definition.tags))}")
    return EXIT_OK


# ---------------------------------------------------------------------------
_HOOK_SCRIPT = """\
#!/bin/sh
# Sentinel DLP pre-commit hook
exec sentinel precommit --fail-on high
"""


def cmd_precommit(args, style: _Style) -> int:
    import subprocess

    if args.install:
        hooks_dir = os.path.join(".git", "hooks")
        if not os.path.isdir(hooks_dir):
            print(style.red("[ERROR] .git/hooks not found (not a git repository?)"), file=sys.stderr)
            return EXIT_ERROR
        hook_path = os.path.join(hooks_dir, "pre-commit")
        if os.path.exists(hook_path):
            print(style.yellow(f"[WARNING] The hook already exists: {hook_path}"))
            return EXIT_ERROR
        with open(hook_path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(_HOOK_SCRIPT)
        os.chmod(hook_path, 0o755)
        print(f"  {style.green('✓')} pre-commit hook installed: {hook_path}")
        return EXIT_OK

    try:
        completed = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        print(style.red(f"[ERROR] Could not run git: {exc}"), file=sys.stderr)
        return EXIT_ERROR

    staged = [line for line in completed.stdout.splitlines() if line and os.path.isfile(line)]
    if not staged:
        print("  No staged files to scan.")
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
            f"  {style.green('✓')} {len(staged)} files scanned, "
            f"no findings at '{threshold.value}' or above."
        )
        return EXIT_OK

    print(style.red(f"\n  ✗ COMMIT BLOCKED - {len(blocking)} sensitive-data findings:\n"))
    for finding in blocking[:20]:
        severity = finding.severity_enum
        print(
            f"    {style.severity(severity, severity.label)} {finding.type} "
            f"→ {finding.file}:{finding.line}  {style.dim(finding.content_masked)}"
        )
    print(
        style.dim(
            "\n  If this is a false positive, add a `sentinel:ignore` comment on\n"
            "  that line, or list it in the allowlist in sentinel.yml."
        )
    )
    return EXIT_FINDINGS


# ---------------------------------------------------------------------------
def cmd_init(args, style: _Style) -> int:
    path = DEFAULT_CONFIG_NAMES[0]
    if os.path.exists(path) and not args.force:
        print(style.yellow(f"[WARNING] {path} already exists (use --force to overwrite)."))
        return EXIT_ERROR
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(CONFIG_TEMPLATE)
    print(f"  {style.green('✓')} {path} created.")
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
        "Text / code scanning": ("stdlib", True),
        "PDF (pypdf)": ("pypdf", _importable("pypdf")),
        "Word (python-docx)": ("docx", _importable("docx")),
        "Excel (openpyxl)": ("openpyxl", _importable("openpyxl")),
        "PowerPoint (python-pptx)": ("pptx", _importable("pptx")),
        "HTML report (jinja2)": ("jinja2", _importable("jinja2")),
        "PDF report (reportlab)": ("reportlab", _importable("reportlab")),
        "Encrypted quarantine (cryptography)": (
            "cryptography",
            QuarantineManager.crypto_available(),
        ),
        "Webhook (requests)": ("requests", _importable("requests")),
        "YAML configuration (pyyaml)": ("yaml", _importable("yaml")),
    }
    for label, (module, ok) in modules.items():
        check(label, ok, "installed" if ok else f"missing: pip install {module}")

    check(
        "Real-time monitoring (watchdog)",
        watchdog_available(),
        "installed" if watchdog_available() else "missing: pip install watchdog",
    )
    check(
        "YARA rules (yara-python)",
        yara_available(),
        "installed" if yara_available() else "missing: pip install yara-python",
    )

    tesseract = image.find_tesseract()
    check(
        "OCR engine (Tesseract)",
        bool(tesseract) and _importable("pytesseract"),
        tesseract or "not found - image scanning disabled",
    )

    print()
    config = ScanConfig.discover()
    if config:
        print(f"  Configuration found, target: {config.target}")
    else:
        print(style.dim("  No configuration file - create one with `sentinel init`."))
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
    # BEFORE anything is written: on Windows, redirected output
    # otherwise crashes on the first non-ASCII character.
    _ensure_utf8_output()

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
        print("\n  Cancelled.")
        return EXIT_INTERRUPTED
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        print(style.red(f"[ERROR] {exc}"), file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
