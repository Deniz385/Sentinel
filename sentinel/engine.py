"""The scan engine.

Three fundamental defects of the previous version are fixed here:

1. ``start_scan_parallel()`` promised parallelism by its name but was a
   plain ``os.walk`` loop. It is now genuinely multi-process or
   multi-threaded.
2. The file hash was recomputed **for every finding**; 1000 findings in
   a 50 MB file meant 50 GB of disk reads. Now it is computed once per
   file.
3. The whole file was pulled into memory with ``f.read()``. Reads are
   now streamed.

The legacy API (``Scanner(target).start_scan_parallel()``) is preserved.
"""

from __future__ import annotations

import hashlib
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sentinel.allowlist import path_matches
from sentinel.config import ScanConfig
from sentinel.findings import Finding
from sentinel.matcher import Matcher
from sentinel.severity import Severity, risk_score

__all__ = ["Scanner", "ScanResult", "FileReport", "scan_single_file"]


# ---------------------------------------------------------------------------
@dataclass
class FileReport:
    """The scan result for one file (the packet returned by a worker)."""

    path: str
    findings: list = field(default_factory=list)
    error: str = ""
    skipped: str = ""
    size: int = 0
    sha256: str = "N/A"
    #: The file was never read; the result came from the incremental cache.
    cached: bool = False


@dataclass
class ScanResult:
    """Everything one scan run produced."""

    findings: list = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    errors: list = field(default_factory=list)
    duration: float = 0.0
    target: str = ""
    started_at: str = ""
    cancelled: bool = False
    quarantined: list = field(default_factory=list)
    #: Number of files served from the incremental cache (never read).
    files_cached: int = 0
    #: Memo for `groups()`. Reporters ask for the same grouping several
    #: times; regrouping 200k findings on each call makes no sense.
    _groups: tuple | None = field(default=None, repr=False, compare=False)

    @property
    def risk_score(self) -> int:
        return risk_score(self.findings)

    # -- cross-file correlation -------------------------------------------
    def groups(self, max_locations: int | None = None) -> list:
        """Reduce findings to unique secrets (see `sentinel.correlation`)."""
        from sentinel.correlation import MAX_LOCATIONS, group_findings

        limit = MAX_LOCATIONS if max_locations is None else max_locations
        signature = (len(self.findings), limit)
        if self._groups is not None and self._groups[0] == signature:
            return self._groups[1]
        computed = group_findings(self.findings, max_locations=limit)
        self._groups = (signature, computed)
        return computed

    @property
    def unique_count(self) -> int:
        """Unique sensitive values - the real number of items to close."""
        return len(self.groups())

    def shared_secrets(self) -> list:
        """Secrets copied into more than one file, most widespread first."""
        return [group for group in self.groups() if group.shared]

    def counts_by_severity(self) -> dict:
        counts = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def counts_by_type(self) -> dict:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.type] = counts.get(finding.type, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))

    def highest_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity_enum for f in self.findings), key=lambda s: s.rank)

    def to_rows(self) -> list:
        return [finding.to_row() for finding in self.findings]

    def summary(self) -> dict:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "duration_seconds": round(self.duration, 4),
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "files_cached": self.files_cached,
            "bytes_scanned": self.bytes_scanned,
            "findings": len(self.findings),
            # The finding count measures copying habits; the unique-secret
            # count measures the real work to be done.
            "unique_secrets": self.unique_count,
            "shared_secrets": len(self.shared_secrets()),
            "risk_score": self.risk_score,
            "highest_severity": (
                self.highest_severity().value if self.findings else None
            ),
            "by_severity": self.counts_by_severity(),
            "by_type": self.counts_by_type(),
            "errors": len(self.errors),
            "cancelled": self.cancelled,
        }


# ---------------------------------------------------------------------------
def calculate_file_hash(path: str, block_size: int = 1 << 20) -> str:
    """The file's SHA-256 fingerprint (for forensic evidence integrity).

    Computed **once** per call; the result is copied onto every finding
    from that file.
    """
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for block in iter(lambda: handle.read(block_size), b""):
                digest.update(block)
        return digest.hexdigest()
    except OSError:
        return "HASH_HESAPLANAMADI"


def scan_single_file(path: str, config: ScanConfig) -> FileReport:
    """Scan a single file. At module level so it runs in a process pool.

    Exceptions are caught here: one corrupt file must not bring the
    whole scan down.
    """
    from sentinel.extractors import extract

    report = FileReport(path=path)

    try:
        report.size = os.path.getsize(path)
    except OSError as exc:
        report.error = f"{type(exc).__name__}: {exc}"
        return report

    if report.size == 0:
        report.skipped = "empty-file"
        return report
    if report.size > config.max_file_size:
        report.skipped = f"size-limit ({report.size} bytes)"
        return report

    report.sha256 = calculate_file_hash(path)
    matcher = Matcher(config)
    seen: set = set()
    findings: list[Finding] = []

    try:
        for chunk in extract(path, config):
            findings.extend(
                matcher.scan_text(
                    chunk.text,
                    chunk.source,
                    line_offset=chunk.line_offset,
                    file_sha=report.sha256,
                    real_path=chunk.real_path or path,
                    seen=seen,
                )
            )
    except Exception as exc:  # pragma: no cover - format-specific corruption
        report.error = f"{type(exc).__name__}: {exc}"

    if config.yara_enabled:
        findings.extend(_yara_findings(path, config, report.sha256))

    report.findings = findings
    return report


_YARA_CACHE: dict = {}


def _yara_findings(path: str, config: ScanConfig, file_sha: str) -> list:
    """Apply the YARA engine, compiling once per process."""
    from sentinel.yara_engine import YaraEngine, yara_available

    if not yara_available():
        return []
    key = config.yara_rules_dir
    engine = _YARA_CACHE.get(key)
    if engine is None:
        engine = YaraEngine(key)
        _YARA_CACHE[key] = engine
    if not engine.enabled:
        return []
    return engine.match_file(path, path, file_sha)


# ---------------------------------------------------------------------------
class Scanner:
    """The parallel scan manager that walks a directory tree.

    The legacy signature is preserved::

        Scanner("test_data", use_ocr=True, quarantine_mode=False)
    """

    def __init__(
        self,
        target_dir: str = ".",
        use_ocr: bool | None = None,
        quarantine_mode: bool | None = None,
        config: ScanConfig | None = None,
        log: callable | None = None,
    ):
        self.config = (config or ScanConfig()).replace(target=target_dir)
        if use_ocr is not None:
            self.config = self.config.replace(ocr=bool(use_ocr))
        if quarantine_mode is not None:
            self.config = self.config.replace(quarantine=bool(quarantine_mode))

        self.target_dir = target_dir
        self._log = log or (lambda message: None)
        self._stop = threading.Event()
        self.patterns = None  # legacy field; managed inside Matcher now
        self.qm = None
        self._baseline: set = set()

        if self.config.baseline_path:
            from sentinel.allowlist import load_baseline

            self._baseline = load_baseline(self.config.baseline_path)

        if self.config.quarantine:
            from sentinel.quarantine import QuarantineManager

            self.qm = QuarantineManager(self.config.quarantine_dir)

        self._cache = self._open_cache()

    def _open_cache(self):
        """Open the incremental scan cache (`None` when disabled)."""
        if not self.config.incremental:
            return None
        if self.config.quarantine:
            # The cache inherits the verdict "this file held a secret"
            # without proving it is still fresh; when that verdict turns
            # into an action that DELETES the file, acting on stale
            # evidence is not acceptable.
            self._log(
                "Quarantine is on - the incremental cache is disabled "
                "(a decision that deletes data cannot rest on stale evidence)."
            )
            return None

        from sentinel.cache import DEFAULT_CACHE_NAME, ScanCache

        cache = ScanCache.open(self.config.cache_path or DEFAULT_CACHE_NAME, self.config)
        if cache.invalidated:
            self._log(
                "Configuration or rule catalogue changed - the cache is "
                "entirely invalid, running a full scan."
            )
        return cache

    # -- legacy API -------------------------------------------------------
    @property
    def use_ocr(self) -> bool:
        return self.config.ocr

    @property
    def quarantine_mode(self) -> bool:
        return self.config.quarantine

    @property
    def stop_requested(self) -> bool:
        return self._stop.is_set()

    def stop_scan(self):
        """Cancel the scan from outside (for example the GUI Stop button)."""
        self._stop.set()

    def scan_file(self, filepath: str) -> list:
        """Scan one file and return a list of findings."""
        report = scan_single_file(filepath, self.config)
        findings = self._filter(report.findings)
        if findings and self.config.quarantine:
            self._quarantine(filepath, findings)
        return findings

    def scan_file_wrapper(self, filepath: str) -> list:
        """The name `monitor.py` expects.

        In v3.0 this method was never defined, so real-time monitoring
        raised ``AttributeError`` on every event.
        """
        return self.scan_file(filepath)

    def start_scan_parallel(self) -> list:
        """Legacy API: return findings as a list of dicts."""
        return [finding.to_row() for finding in self.scan().findings]

    # -- main flow --------------------------------------------------------
    def iter_targets(self):
        """Yield the file paths to scan."""
        target = self.config.target
        if os.path.isfile(target):
            yield target
            return

        extensions = set(self.config.extensions)
        excluded = set(self.config.exclude_dirs)
        allowlist = self.config.allowlist
        # Scanning our own cache file is pointless: it holds masked
        # values and fingerprints that trigger the entropy rule for no
        # reason, and the report ends up reporting itself.
        own_cache = (
            os.path.abspath(self._cache.path) if self._cache is not None else None
        )

        for root, dirs, files in os.walk(target, followlinks=self.config.follow_symlinks):
            if self._stop.is_set():
                return

            dirs[:] = [
                d
                for d in dirs
                if d not in excluded
                and not (d.startswith(".") and d not in (".github",))
                and not allowlist.allows_path(os.path.join(root, d))
                and not path_matches(os.path.join(root, d), self.config.exclude_globs)
            ]

            for name in files:
                if self._stop.is_set():
                    return
                path = os.path.join(root, name)
                extension = os.path.splitext(name)[1].lower()
                if extensions and extension not in extensions:
                    continue
                if path_matches(path, self.config.exclude_globs):
                    continue
                if allowlist.allows_path(path):
                    continue
                if not self.config.follow_symlinks and os.path.islink(path):
                    continue
                if own_cache is not None and os.path.abspath(path) == own_cache:
                    continue
                yield path

    def scan(self, progress=None) -> ScanResult:
        """Run the scan.

        When `progress` is given it is called after each file as
        ``progress(done, total, path)``.
        """
        started = time.monotonic()
        result = ScanResult(
            target=os.path.abspath(self.config.target),
            started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )

        if not os.path.exists(self.config.target):
            raise FileNotFoundError(f"Target not found: {self.config.target}")

        paths = list(self.iter_targets())
        total = len(paths)
        self._log(f"{total} files queued.")

        for index, report in enumerate(self._run(paths), 1):
            self._collect(report, result)
            if progress is not None:
                progress(index, total, report.path)

        result.cancelled = self._stop.is_set()
        result.findings.sort(key=lambda f: f.sort_key())
        result.duration = time.monotonic() - started

        if self._cache is not None:
            self._cache.save()
            self._log(
                f"Cache: {self._cache.stats.hits} files skipped, "
                f"{self._cache.stats.stale} changed, "
                f"{self._cache.stats.misses} new."
            )

        self._audit(result)
        self._notify(result)
        return result

    # -- execution strategy ------------------------------------------------
    def _run(self, paths):
        """Yield cache hits first, then freshly scanned files."""
        if self._cache is None:
            yield from self._execute(paths)
            return

        fresh = []
        for path in paths:
            if self._stop.is_set():
                return
            report = self._cache.lookup(path)
            if report is None:
                fresh.append(path)
            else:
                yield report

        for report in self._execute(fresh):
            self._cache.remember(report)
            yield report

    def _execute(self, paths):
        mode = self._executor_mode(len(paths))

        if mode == "serial":
            for path in paths:
                if self._stop.is_set():
                    return
                yield scan_single_file(path, self.config)
            return

        if mode == "thread":
            from concurrent.futures import ThreadPoolExecutor

            yield from self._run_pool(ThreadPoolExecutor, paths)
            return

        try:
            from concurrent.futures import ProcessPoolExecutor

            yield from self._run_pool(ProcessPoolExecutor, paths)
        except (OSError, RuntimeError, ImportError) as exc:
            # In restricted environments (containers without /dev/shm, a
            # frozen exe) a process pool cannot be created; fall back to
            # threads quietly.
            self._log(f"Process pool unavailable ({exc}); switching to threads.")
            from concurrent.futures import ThreadPoolExecutor

            yield from self._run_pool(ThreadPoolExecutor, paths)

    def _executor_mode(self, count: int) -> str:
        mode = (self.config.executor or "auto").lower()
        if mode in ("serial", "thread", "process"):
            if mode != "serial" and (count < 4 or self.config.worker_count() == 1):
                return "serial"
            return mode
        # auto
        if count < 8 or self.config.worker_count() == 1:
            return "serial"
        import sys

        if getattr(sys, "frozen", False):
            return "thread"
        return "process"

    def _run_pool(self, executor_cls, paths):
        from concurrent.futures import FIRST_COMPLETED, wait

        workers = self.config.worker_count()
        # Submit through a window instead of filling the pool with the
        # whole list: memory stays bounded on a million-file target and
        # cancellation stays responsive.
        window = workers * 4
        iterator = iter(paths)
        pending = set()

        with executor_cls(max_workers=workers) as pool:
            try:
                for path in iterator:
                    if self._stop.is_set():
                        break
                    pending.add(pool.submit(scan_single_file, path, self.config))
                    if len(pending) < window:
                        continue
                    done, pending = wait(pending, return_when=FIRST_COMPLETED)
                    for future in done:
                        yield self._harvest(future)

                while pending:
                    done, pending = wait(pending, return_when=FIRST_COMPLETED)
                    for future in done:
                        yield self._harvest(future)
            finally:
                for future in pending:
                    future.cancel()

    @staticmethod
    def _harvest(future) -> FileReport:
        try:
            return future.result()
        except Exception as exc:  # pragma: no cover
            return FileReport(path="<unknown>", error=f"{type(exc).__name__}: {exc}")

    # -- result collection -------------------------------------------------
    def _collect(self, report: FileReport, result: ScanResult):
        if report.error:
            result.errors.append({"file": report.path, "error": report.error})
        if report.skipped:
            result.files_skipped += 1
            return

        result.files_scanned += 1
        result.bytes_scanned += report.size
        if report.cached:
            result.files_cached += 1

        findings = self._filter(report.findings)
        if not findings:
            return

        result.findings.extend(findings)
        highest = max(f.severity_enum for f in findings)
        self._log(
            f"[{highest.value.upper()}] {report.path}: {len(findings)} findings"
        )

        if self.config.quarantine:
            moved = self._quarantine(report.path, findings)
            if moved:
                result.quarantined.append(report.path)

    def _filter(self, findings) -> list:
        """Baseline and minimum-severity filter."""
        minimum = self.config.min_severity_enum
        output = []
        for finding in findings:
            if finding.severity_enum < minimum:
                continue
            if finding.fingerprint and finding.fingerprint.lower() in self._baseline:
                continue
            output.append(finding)
        return output

    def _quarantine(self, path: str, findings) -> bool:
        """Quarantine the file when a finding is at or above the threshold."""
        if self.qm is None:
            return False
        threshold = Severity.parse(self.config.quarantine_min_severity)
        if not any(f.severity_enum >= threshold for f in findings):
            return False
        if not os.path.isfile(path):
            return False
        try:
            success, message = self.qm.quarantine_file(
                path, shred=self.config.shred_original
            )
        except Exception as exc:
            self._log(f"[QUARANTINE ERROR] {path}: {exc}")
            return False
        if success:
            self._log(f"[QUARANTINE] {path} encrypted and isolated.")
        else:
            self._log(f"[QUARANTINE ERROR] {path}: {message}")
        return bool(success)

    # -- side effects -------------------------------------------------------
    def _audit(self, result: ScanResult):
        if not self.config.audit_log:
            return
        import json

        path = self.config.audit_log
        directory = os.path.dirname(os.path.abspath(path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        try:
            with open(path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(result.summary(), ensure_ascii=False) + "\n")
        except OSError as exc:
            self._log(f"Could not write the audit trail: {exc}")

    def _notify(self, result: ScanResult):
        if not self.config.webhook_url or not result.findings:
            return
        from sentinel.notify import notify_findings

        try:
            notify_findings(result, self.config)
        except Exception as exc:  # a notification failure never fails the scan
            self._log(f"Could not send the webhook: {exc}")
