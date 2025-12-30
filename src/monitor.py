# src/monitor.py
import time
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from scanner import Scanner

class DLPEventHandler(FileSystemEventHandler):
    """Dosya sistemi olaylarını dinleyen sınıf."""
    def __init__(self, scanner_instance, log_callback):
        self.scanner = scanner_instance
        self.log_callback = log_callback

    def on_created(self, event):
        if not event.is_directory:
            self.process(event.src_path, "YENİ DOSYA")

    def on_modified(self, event):
        if not event.is_directory:
            self.process(event.src_path, "DEĞİŞİKLİK")

    def process(self, filepath, event_type):
        # Geçici dosyaları yoksay (Word/Excel tmp dosyaları vb.)
        if "~" in filepath or ".tmp" in filepath: return
        
        self.log_callback(f"[{event_type}] Algılandı: {filepath}")
        
        # Dosyayı tarayıcıya gönder
        results = self.scanner.scan_file_wrapper(filepath)
        
        if results:
            self.log_callback(f"⚠️ TEHDİT BULUNDU! ({len(results)} veri)")
            # Windows uyarı sesi (Opsiyonel)
            print('\a')
        else:
            self.log_callback(f"✅ Temiz: {os.path.basename(filepath)}")

class RealTimeMonitor:
    def __init__(self, target_dir, scanner, log_callback):
        self.observer = Observer()
        self.handler = DLPEventHandler(scanner, log_callback)
        self.target_dir = target_dir
        self.observer.schedule(self.handler, target_dir, recursive=True)

    def start(self):
        self.observer.start()
    
    def stop(self):
        self.observer.stop()
        self.observer.join()