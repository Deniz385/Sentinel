#!/usr/bin/env python3
"""Karantina kurtarma aracı (bağımsız).

GUI açılmadan tek bir dosyayı kasadan geri almak için. Tkinter varsa
dosya seçici açar; yoksa komut satırı argümanıyla çalışır:

    python restore_tool.py KARANTINA_BOLGESI/1700000000_ab12cd34_veri.txt.enc

`sentinel vault restore <ad>` komutu da aynı işi yapar.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sentinel.quarantine import QuarantineManager  # noqa: E402

DEFAULT_DIRS = ("KARANTINA_BOLGESI", "QUARANTINE_ZONE")


def _pick_dir() -> str:
    for candidate in DEFAULT_DIRS:
        if os.path.isdir(candidate):
            return candidate
    return DEFAULT_DIRS[0]


def _restore(manager: QuarantineManager, path: str, notify) -> bool:
    ok, message = manager.restore_file(path)
    if not ok and "üzerine yazılmadı" in message:
        if notify("confirm", message):
            ok, message = manager.restore_file(path, force=True)
    notify("ok" if ok else "error", message)
    return ok


def _cli(path: str) -> int:
    manager = QuarantineManager(os.path.dirname(path) or _pick_dir())

    def notify(kind, message):
        if kind == "confirm":
            answer = input(f"{message}\nÜzerine yazılsın mı? [e/H] ").strip().lower()
            return answer in ("e", "y", "evet", "yes")
        prefix = "[OK]" if kind == "ok" else "[HATA]"
        print(f"{prefix} {message}", file=sys.stderr if kind == "error" else sys.stdout)
        return None

    return 0 if _restore(manager, path, notify) else 1


def _gui() -> int:
    import tkinter as tk
    from tkinter import filedialog, messagebox

    root = tk.Tk()
    root.withdraw()

    quarantine_dir = _pick_dir()
    manager = QuarantineManager(quarantine_dir)

    messagebox.showinfo(
        "Dosya Seç",
        "Kurtarılacak şifreli (.enc) dosyayı seçin.\n"
        "Dosya, manifestteki orijinal konumuna geri yüklenecek.",
    )
    selected = filedialog.askopenfilename(
        initialdir=quarantine_dir,
        title="Kurtarılacak Dosyayı Seç",
        filetypes=[("Şifreli Dosyalar", "*.enc"), ("Tüm Dosyalar", "*.*")],
    )
    if not selected:
        return 0

    def notify(kind, message):
        if kind == "confirm":
            return messagebox.askyesno("Dosya mevcut", f"{message}\n\nÜzerine yazılsın mı?")
        if kind == "ok":
            messagebox.showinfo("Başarılı", f"Dosya geri yüklendi:\n\n{message}")
        else:
            messagebox.showerror("Hata", f"Dosya kurtarılamadı:\n{message}")
        return None

    return 0 if _restore(manager, selected, notify) else 1


def main() -> int:
    if len(sys.argv) > 1:
        return _cli(sys.argv[1])
    try:
        return _gui()
    except ImportError:
        print(
            "Tkinter yok. Dosya yolunu argüman olarak verin:\n"
            "    python restore_tool.py <yol>/<dosya>.enc",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())
