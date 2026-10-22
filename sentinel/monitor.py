"""Real-time filesystem monitoring.

The v3.0 `monitor.py` called ``scan_file_wrapper()``, a method that was
never defined on `Scanner`: monitoring raised ``AttributeError`` on
every event, so the feature never worked at all. `watchdog` was not even
listed as a dependency.

This version also applies **debouncing**: editors emit 3-10 `modified`
events for a single save, and rescanning on each one wastes CPU.
"""

from __future__ import annotations

import os
import threading
import time

__all__ = ["RealTimeMonitor", "DLPEventHandler", "watchdog_available"]

#: Repeat events for the same file within this window are ignored (seconds).
_DEBOUNCE_SECONDS = 1.5

#: Temporary and junk file shapes - editor and Office intermediate files.
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
    """Route file events to the scanner, with debouncing.

    The base class is bound at runtime so this class can still be
    imported when `watchdog` is not installed.
    """

    def __init__(self, scanner, log_callback=None, on_finding=None):
        self.scanner = scanner
        self.log = log_callback or (lambda message: None)
        self.on_finding = on_finding
        self._last_seen: dict[str, float] = {}
        self._lock = threading.Lock()

    # watchdog interface
    def dispatch(self, event):
        if getattr(event, "is_directory", False):
            return
        kind = getattr(event, "event_type", "")
        if kind not in ("created", "modified", "moved"):
            return
        path = getattr(event, "dest_path", "") or getattr(event, "src_path", "")
        label = {"created": "NEW FILE", "modified": "CHANGED", "moved": "MOVED"}[kind]
        self.process(path, label)

    def process(self, filepath: str, event_type: str = "EVENT"):
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
            # Bound the dict so a long-running monitor does not leak memory.
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
            self.log(f"[ERROR] {filepath}: {exc}")
            return

        if findings:
            highest = max(f.severity_enum for f in findings)
            self.log(
                f"⚠️ THREAT: {len(findings)} findings "
                f"({highest.label}) - {os.path.basename(filepath)}"
            )
            if self.on_finding is not None:
                self.on_finding(filepath, findings)
        else:
            self.log(f"✅ Clean: {os.path.basename(filepath)}")


class RealTimeMonitor:
    """Watch a directory recursively."""

    def __init__(self, target_dir: str, scanner, log_callback=None, on_finding=None):
        if not watchdog_available():
            raise RuntimeError(
                "Real-time monitoring requires watchdog: "
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
