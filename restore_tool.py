#!/usr/bin/env python3
"""Standalone quarantine recovery tool.

For pulling a single file back out of the vault without opening the
GUI. With Tkinter available it shows a file picker; otherwise it takes
a command-line argument:

    python restore_tool.py QUARANTINE_ZONE/<time>_<digest>_data.txt.enc

The `sentinel vault restore <name>` command does the same thing.
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
    if not ok and "not overwritten" in message:
        if notify("confirm", message):
            ok, message = manager.restore_file(path, force=True)
    notify("ok" if ok else "error", message)
    return ok


def _cli(path: str) -> int:
    manager = QuarantineManager(os.path.dirname(path) or _pick_dir())

    def notify(kind, message):
        if kind == "confirm":
            answer = input(f"{message}\nOverwrite it? [y/N] ").strip().lower()
            return answer in ("y", "yes")
        prefix = "[OK]" if kind == "ok" else "[ERROR]"
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
        "Select a file",
        "Choose the encrypted (.enc) file to recover.\n"
        "It will be restored to the original location in the manifest.",
    )
    selected = filedialog.askopenfilename(
        initialdir=quarantine_dir,
        title="Select the file to recover",
        filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")],
    )
    if not selected:
        return 0

    def notify(kind, message):
        if kind == "confirm":
            return messagebox.askyesno("File exists", f"{message}\n\nOverwrite it?")
        if kind == "ok":
            messagebox.showinfo("Success", f"File restored:\n\n{message}")
        else:
            messagebox.showerror("Error", f"Could not recover the file:\n{message}")
        return None

    return 0 if _restore(manager, selected, notify) else 1


def main() -> int:
    if len(sys.argv) > 1:
        return _cli(sys.argv[1])
    try:
        return _gui()
    except ImportError:
        print(
            "Tkinter is unavailable. Pass the file path as an argument:\n"
            "    python restore_tool.py <path>/<file>.enc",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())
