"""Gerçek zamanlı dosya sistemi izleme.

v3.0'daki `monitor.py`, `Scanner` üzerinde hiç tanımlanmamış
``scan_file_wrapper()`` metodunu çağırıyordu: izleme her olayda
``AttributeError`` veriyordu, yani özellik hiç çalışmıyordu. Ayrıca
`watchdog` bağımlılıklarda bile yoktu.

Buradaki sürüm ek olarak **debounce** uygular: editörler tek kaydetmede
3-10 `modified` olayı üretir; her biri için yeniden tarama yapmak CPU'yu
boşa harcar.
"""

from __future__ import annotations

import os
import threading
import time

__all__ = ["RealTimeMonitor", "DLPEventHandler", "watchdog_available"]

#: Aynı dosya için bu süre içinde gelen tekrar olaylar yoksayılır (saniye).
_DEBOUNCE_SECONDS = 1.5

#: Geçici/çöp dosya kalıpları — editör ve Office ara dosyaları.
_IGNORED_SUFFIXES = (".tmp", ".swp", ".swx", ".part", ".crdownload", "~")
_IGNORED_PREFIXES = ("~$", ".~lock.", ".goutputstream")


def watchdog_available() -> bool:
    try:
        import watchdog  # noqa: F401
    except ImportError:
        return False
    return True


def _should_ignore(path: str) -> bool:
    name = os.path.basename(path)
    if name.startswith(_IGNORED_PREFIXES):
        return True
    return name.endswith(_IGNORED_SUFFIXES)


def _base_handler():
    from watchdog.events import FileSystemEventHandler

    return FileSystemEventHandler


class DLPEventHandler:
    """Dosya olaylarını tarayıcıya yönlendirir (debounce'lu).

    `watchdog` kurulu olmadığında bu sınıf da import edilebilsin diye
    taban sınıf çalışma anında bağlanır.
    """

    def __init__(self, scanner, log_callback=None, on_finding=None):
        self.scanner = scanner
        self.log = log_callback or (lambda message: None)
        self.on_finding = on_finding
        self._last_seen: dict[str, float] = {}
        self._lock = threading.Lock()

    # watchdog arayüzü
    def dispatch(self, event):
        if getattr(event, "is_directory", False):
            return
        kind = getattr(event, "event_type", "")
        if kind not in ("created", "modified", "moved"):
            return
        path = getattr(event, "dest_path", "") or getattr(event, "src_path", "")
        label = {"created": "YENİ DOSYA", "modified": "DEĞİŞİKLİK", "moved": "TAŞIMA"}[kind]
        self.process(path, label)

    def process(self, filepath: str, event_type: str = "OLAY"):
        if not filepath or _should_ignore(filepath):
            return
        if not os.path.isfile(filepath):
            return

        now = time.monotonic()
        with self._lock:
            last = self._last_seen.get(filepath, 0.0)
            if now - last < _DEBOUNCE_SECONDS:
                return
            self._last_seen[filepath] = now
            # Sözlüğü sınırla: uzun süre çalışan izleyicide bellek sızmasın.
            if len(self._last_seen) > 5000:
                cutoff = now - 60
                self._last_seen = {
                    key: value
                    for key, value in self._last_seen.items()
                    if value > cutoff
                }

        self.log(f"[{event_type}] {filepath}")

        try:
            findings = self.scanner.scan_file(filepath)
        except Exception as exc:
            self.log(f"[HATA] {filepath}: {exc}")
            return

        if findings:
            highest = max(f.severity_enum for f in findings)
            self.log(
                f"⚠️ TEHDİT: {len(findings)} bulgu "
                f"({highest.label_tr}) — {os.path.basename(filepath)}"
            )
            if self.on_finding is not None:
                self.on_finding(filepath, findings)
        else:
            self.log(f"✅ Temiz: {os.path.basename(filepath)}")


class RealTimeMonitor:
    """Bir dizini özyinelemeli olarak izler."""

    def __init__(self, target_dir: str, scanner, log_callback=None, on_finding=None):
        if not watchdog_available():
            raise RuntimeError(
                "Gerçek zamanlı izleme için watchdog gerekli: "
                "pip install 'sentinel-dlp[monitor]'"
            )
        from watchdog.observers import Observer

        self.target_dir = target_dir
        self.handler = DLPEventHandler(scanner, log_callback, on_finding)
        self.observer = Observer()
        self.observer.schedule(self.handler, target_dir, recursive=True)
        self._running = False

    def start(self):
        if not self._running:
            self.observer.start()
            self._running = True

    def stop(self, timeout: float = 5.0):
        if not self._running:
            return
        self.observer.stop()
        self.observer.join(timeout)
        self._running = False

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc_info):
        self.stop()
        return False
