"""Tarama motoru.

Önceki sürümün üç temel kusuru burada giderilir:

1. ``start_scan_parallel()`` adı paralellik vaat ediyordu ama düz bir
   ``os.walk`` döngüsüydü. Artık gerçekten çok süreçli/çok iş parçacıklı.
2. Dosya hash'i **her bulgu için** yeniden hesaplanıyordu; 50 MB'lık bir
   dosyada 1000 bulgu 50 GB disk okuması demekti. Artık dosya başına bir kez.
3. Dosyanın tamamı ``f.read()`` ile belleğe alınıyordu. Artık akışlı.

Eski API (``Scanner(target).start_scan_parallel()``) korunmuştur.
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
    """Tek bir dosyanın tarama sonucu (alt süreçten dönen paket)."""

    path: str
    findings: list = field(default_factory=list)
    error: str = ""
    skipped: str = ""
    size: int = 0
    sha256: str = "N/A"


@dataclass
class ScanResult:
    """Bir tarama çalıştırmasının tüm çıktısı."""

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

    @property
    def risk_score(self) -> int:
        return risk_score(self.findings)

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
            "bytes_scanned": self.bytes_scanned,
            "findings": len(self.findings),
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
    """Dosyanın SHA-256 parmak izi (adli bilişim delil bütünlüğü için).

    Çağrı başına **bir kez** hesaplanır; sonuç o dosyanın tüm bulgularına
    kopyalanır.
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
    """Tek dosyayı tarar. Süreç havuzunda çalıştığı için modül seviyesinde.

    İstisnalar burada yakalanır: tek bozuk dosya tüm taramayı düşürmemeli.
    """
    from sentinel.extractors import extract

    report = FileReport(path=path)

    try:
        report.size = os.path.getsize(path)
    except OSError as exc:
        report.error = f"{type(exc).__name__}: {exc}"
        return report

    if report.size == 0:
        report.skipped = "bos-dosya"
        return report
    if report.size > config.max_file_size:
        report.skipped = f"boyut-limiti ({report.size} bayt)"
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
    except Exception as exc:  # pragma: no cover - biçime özgü bozulmalar
        report.error = f"{type(exc).__name__}: {exc}"

    if config.yara_enabled:
        findings.extend(_yara_findings(path, config, report.sha256))

    report.findings = findings
    return report


_YARA_CACHE: dict = {}


def _yara_findings(path: str, config: ScanConfig, file_sha: str) -> list:
    """YARA motorunu (süreç başına bir kez derleyerek) uygular."""
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
    """Dizin ağacını yürüyen, paralel tarama yöneticisi.

    Eski imza korunur::

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
        self.patterns = None  # geriye dönük alan; Matcher içinde yönetiliyor
        self.qm = None
        self._baseline: set = set()

        if self.config.baseline_path:
            from sentinel.allowlist import load_baseline

            self._baseline = load_baseline(self.config.baseline_path)

        if self.config.quarantine:
            from sentinel.quarantine import QuarantineManager

            self.qm = QuarantineManager(self.config.quarantine_dir)

    # -- eski API ---------------------------------------------------------
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
        """Dışarıdan (ör. GUI'deki Durdur düğmesi) taramayı iptal eder."""
        self._stop.set()

    def scan_file(self, filepath: str) -> list:
        """Tek dosyayı tarar ve bulgu listesi döndürür."""
        report = scan_single_file(filepath, self.config)
        findings = self._filter(report.findings)
        if findings and self.config.quarantine:
            self._quarantine(filepath, findings)
        return findings

    def scan_file_wrapper(self, filepath: str) -> list:
        """`monitor.py`'nin beklediği ad.

        v3.0'da bu metot hiç tanımlanmamıştı, bu yüzden gerçek zamanlı
        izleme her olayda ``AttributeError`` veriyordu.
        """
        return self.scan_file(filepath)

    def start_scan_parallel(self) -> list:
        """Eski API: bulguları sözlük listesi olarak döndürür."""
        return [finding.to_row() for finding in self.scan().findings]

    # -- ana akış ---------------------------------------------------------
    def iter_targets(self):
        """Taranacak dosya yollarını üretir."""
        target = self.config.target
        if os.path.isfile(target):
            yield target
            return

        extensions = set(self.config.extensions)
        excluded = set(self.config.exclude_dirs)
        allowlist = self.config.allowlist

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
                yield path

    def scan(self, progress=None) -> ScanResult:
        """Taramayı çalıştırır.

        `progress` verilirse her dosya sonrası
        ``progress(done, total, path)`` ile çağrılır.
        """
        started = time.monotonic()
        result = ScanResult(
            target=os.path.abspath(self.config.target),
            started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )

        if not os.path.exists(self.config.target):
            raise FileNotFoundError(f"Hedef bulunamadı: {self.config.target}")

        paths = list(self.iter_targets())
        total = len(paths)
        self._log(f"{total} dosya kuyruğa alındı.")

        for index, report in enumerate(self._run(paths), 1):
            self._collect(report, result)
            if progress is not None:
                progress(index, total, report.path)

        result.cancelled = self._stop.is_set()
        result.findings.sort(key=lambda f: f.sort_key())
        result.duration = time.monotonic() - started

        self._audit(result)
        self._notify(result)
        return result

    # -- yürütme stratejisi ----------------------------------------------
    def _run(self, paths):
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
            # Kısıtlı ortamlarda (konteyner, /dev/shm yok, frozen exe)
            # süreç havuzu kurulamaz; sessizce iş parçacıklarına düş.
            self._log(f"Süreç havuzu kullanılamadı ({exc}); iş parçacığına geçiliyor.")
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
        # Havuzu tüm listeyle doldurmak yerine pencere kullan: 1 milyon
        # dosyalık bir hedefte bellek patlamasın ve iptal hızlı olsun.
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
            return FileReport(path="<bilinmiyor>", error=f"{type(exc).__name__}: {exc}")

    # -- sonuç toplama ----------------------------------------------------
    def _collect(self, report: FileReport, result: ScanResult):
        if report.error:
            result.errors.append({"file": report.path, "error": report.error})
        if report.skipped:
            result.files_skipped += 1
            return

        result.files_scanned += 1
        result.bytes_scanned += report.size

        findings = self._filter(report.findings)
        if not findings:
            return

        result.findings.extend(findings)
        highest = max(f.severity_enum for f in findings)
        self._log(
            f"[{highest.value.upper()}] {report.path}: {len(findings)} bulgu"
        )

        if self.config.quarantine:
            moved = self._quarantine(report.path, findings)
            if moved:
                result.quarantined.append(report.path)

    def _filter(self, findings) -> list:
        """Baz çizgisi ve minimum önem derecesi süzgeci."""
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
        """Eşik üstü bulgu varsa dosyayı karantinaya alır."""
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
            self._log(f"[KARANTİNA HATASI] {path}: {exc}")
            return False
        if success:
            self._log(f"[KARANTİNA] {path} şifrelenip izole edildi.")
        else:
            self._log(f"[KARANTİNA HATASI] {path}: {message}")
        return bool(success)

    # -- yan etkiler ------------------------------------------------------
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
            self._log(f"Denetim izi yazılamadı: {exc}")

    def _notify(self, result: ScanResult):
        if not self.config.webhook_url or not result.findings:
            return
        from sentinel.notify import notify_findings

        try:
            notify_findings(result, self.config)
        except Exception as exc:  # bildirim hatası taramayı düşürmez
            self._log(f"Webhook gönderilemedi: {exc}")
