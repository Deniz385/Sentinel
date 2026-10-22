"""Sentinel desktop interface (CustomTkinter).

The core logic lives in the `sentinel` package; this file is only the
presentation layer. What changed since v3.0:

* scanning runs in a **thread pool** (`executor="thread"`, to avoid the
  risks of `fork` inside a GUI) and the progress bar shows a real
  percentage rather than an indeterminate animation,
* findings are coloured by severity and listed in a filterable table;
  there used to be only a log stream,
* writing reports and opening files is **cross-platform**
  (`os.startfile` exists only on Windows),
* matplotlib is optional: without it a textual distribution replaces
  the chart and the application still starts.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import webbrowser

# When packaged with PyInstaller, resources live under _MEIPASS.
_BASE = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
if _BASE not in sys.path:
    sys.path.insert(0, _BASE)

try:
    from tkinter import filedialog, messagebox

    import customtkinter as ctk
except ImportError:  # pragma: no cover - GUI dependencies missing
    sys.stderr.write(
        "The desktop interface requires customtkinter:\n"
        "    pip install 'sentinel-dlp[gui]'\n"
        "The command-line version works on its own:  sentinel scan <folder>\n"
    )
    raise SystemExit(1) from None

from sentinel import __version__
from sentinel.config import ScanConfig
from sentinel.engine import Scanner
from sentinel.quarantine import QuarantineManager
from sentinel.reporting import write_reports
from sentinel.severity import Severity

try:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")

#: Severity colours - a status palette, not a categorical series.
SEVERITY_COLORS = {
    Severity.CRITICAL: "#d03b3b",
    Severity.HIGH: "#ec835a",
    Severity.MEDIUM: "#fab219",
    Severity.LOW: "#0ca30c",
    Severity.INFO: "#8f8e85",
}

#: Maximum rows rendered in the table - Tk stalls on thousands of widgets.
MAX_ROWS = 300


def open_path(path: str):
    """Open a file or directory in the operating system's default application."""
    path = os.path.abspath(path)
    try:
        if sys.platform.startswith("win"):
            os.startfile(path)  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
    except (OSError, AttributeError):
        webbrowser.open(f"file://{path}")


class SentinelPro(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title(f"SENTINEL {__version__} | Endpoint Security Dashboard")
        self.geometry("1280x840")
        self.minsize(1060, 720)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.config_obj = ScanConfig.discover() or ScanConfig()
        self.config_obj = self.config_obj.with_env()
        self.qm = QuarantineManager(self.config_obj.quarantine_dir)

        self.result = None
        self.current_scanner: Scanner | None = None
        self._rows: list = []

        self._build_sidebar()
        self._build_scan_page()
        self._build_vault_page()
        self.show_frame("scan")

    # ------------------------------------------------------------------
    def _build_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=230, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(5, weight=1)

        ctk.CTkLabel(
            self.sidebar, text="🛡️ SENTINEL", font=ctk.CTkFont(size=26, weight="bold")
        ).grid(row=0, column=0, padx=20, pady=(30, 4))
        ctk.CTkLabel(
            self.sidebar,
            text=f"DLP & Threat Hunter · v{__version__}",
            text_color="gray",
            font=ctk.CTkFont(size=11),
        ).grid(row=1, column=0, padx=20, pady=(0, 28))

        self.btn_nav_scan = self._nav_button("🔍  Scan Centre", "scan", 2)
        self.btn_nav_vault = self._nav_button("☣️  Quarantine Vault", "quarantine", 3)

        self.lbl_status = ctk.CTkLabel(
            self.sidebar,
            text="System: ONLINE",
            text_color="#0ca30c",
            font=ctk.CTkFont(size=11, weight="bold"),
        )
        self.lbl_status.grid(row=6, column=0, padx=20, pady=20)

    def _nav_button(self, text: str, page: str, row: int):
        button = ctk.CTkButton(
            self.sidebar,
            text=text,
            height=45,
            corner_radius=8,
            fg_color="transparent",
            text_color=("gray10", "gray90"),
            hover_color=("gray70", "gray30"),
            anchor="w",
            font=ctk.CTkFont(weight="bold"),
            command=lambda: self.show_frame(page),
        )
        button.grid(row=row, column=0, padx=15, pady=5, sticky="ew")
        return button

    # ------------------------------------------------------------------
    def _build_scan_page(self):
        self.frame_scan = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")

        top = ctk.CTkFrame(self.frame_scan, corner_radius=15)
        top.pack(fill="x", padx=26, pady=(20, 14))

        ctk.CTkLabel(
            top, text="NEW SCAN TASK", font=ctk.CTkFont(weight="bold", size=14)
        ).pack(anchor="w", padx=20, pady=(15, 6))

        path_row = ctk.CTkFrame(top, fg_color="transparent")
        path_row.pack(fill="x", padx=10, pady=(0, 10))
        self.entry_path = ctk.CTkEntry(
            path_row, placeholder_text="Choose a folder to scan…", height=40
        )
        self.entry_path.pack(side="left", fill="x", expand=True, padx=(10, 10))
        self.entry_path.insert(0, os.path.abspath(self.config_obj.target))

        # In Tk, Ctrl+A means "go to start of line" by default, while
        # every user expects "select all". Without this binding a newly
        # typed path is prepended to the existing text and the scan
        # fails inexplicably - exactly what happened in GUI testing.
        self.entry_path.bind("<Control-a>", self._select_all_path)
        self.entry_path.bind("<Control-A>", self._select_all_path)
        ctk.CTkButton(
            path_row, text="📂 Browse", width=86, height=40, command=self.browse_folder
        ).pack(side="left", padx=(0, 10))

        switches = ctk.CTkFrame(top, fg_color="transparent")
        switches.pack(fill="x", padx=20, pady=(0, 14))

        self.switch_ocr = ctk.CTkSwitch(
            switches, text="OCR (image analysis)", progress_color="#eb6834"
        )
        self.switch_ocr.pack(side="left", padx=(10, 22))

        self.switch_archive = ctk.CTkSwitch(
            switches, text="Descend into archives (ZIP)", progress_color="#2a78d6"
        )
        self.switch_archive.select()
        self.switch_archive.pack(side="left", padx=(0, 22))

        self.switch_quarantine = ctk.CTkSwitch(
            switches, text="Active quarantine", progress_color="#d03b3b"
        )
        self.switch_quarantine.pack(side="left", padx=(0, 22))

        ctk.CTkLabel(switches, text="Threshold:", font=ctk.CTkFont(size=12)).pack(
            side="left", padx=(10, 6)
        )
        self.option_severity = ctk.CTkOptionMenu(
            switches,
            width=120,
            values=[severity.label for severity in Severity],
        )
        self.option_severity.set(Severity.LOW.label)
        self.option_severity.pack(side="left")

        self.btn_start = ctk.CTkButton(
            self.frame_scan,
            text="🚀 START ANALYSIS",
            height=50,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color="#00695c",
            hover_color="#004d40",
            command=self.start_scan,
        )
        self.btn_start.pack(fill="x", padx=26, pady=(0, 8))

        self.progress = ctk.CTkProgressBar(self.frame_scan, height=8)
        self.progress.pack(fill="x", padx=26, pady=(6, 2))
        self.progress.set(0)

        self.lbl_progress = ctk.CTkLabel(
            self.frame_scan, text="", text_color="gray", font=ctk.CTkFont(size=11)
        )
        self.lbl_progress.pack(anchor="w", padx=26, pady=(0, 10))

        # Summary strip
        self.summary_bar = ctk.CTkFrame(self.frame_scan, fg_color="transparent")
        self.summary_bar.pack(fill="x", padx=26, pady=(0, 10))
        self.summary_labels = {}
        for key, title in (
            ("risk", "RISK SCORE"),
            ("total", "FINDINGS"),
            ("files", "FILES"),
            ("duration", "DURATION"),
        ):
            tile = ctk.CTkFrame(self.summary_bar, corner_radius=10)
            tile.pack(side="left", expand=True, fill="x", padx=4)
            ctk.CTkLabel(
                tile, text=title, text_color="gray", font=ctk.CTkFont(size=10, weight="bold")
            ).pack(pady=(10, 0))
            value = ctk.CTkLabel(tile, text="—", font=ctk.CTkFont(size=22, weight="bold"))
            value.pack(pady=(0, 10))
            self.summary_labels[key] = value

        # Lower section: findings plus log and chart
        split = ctk.CTkFrame(self.frame_scan, fg_color="transparent")
        split.pack(fill="both", expand=True, padx=26, pady=(4, 10))

        left = ctk.CTkFrame(split, fg_color="transparent")
        left.pack(side="left", fill="both", expand=True, padx=(0, 10))

        filter_row = ctk.CTkFrame(left, fg_color="transparent")
        filter_row.pack(fill="x", pady=(0, 6))
        ctk.CTkLabel(
            filter_row, text="Findings", font=ctk.CTkFont(size=12, weight="bold")
        ).pack(side="left")
        self.entry_filter = ctk.CTkEntry(
            filter_row, placeholder_text="filter…", width=200, height=28
        )
        self.entry_filter.pack(side="right")
        self.entry_filter.bind("<KeyRelease>", lambda _event: self.refresh_findings())

        self.findings_frame = ctk.CTkScrollableFrame(left, fg_color="#1a1a19")
        self.findings_frame.pack(fill="both", expand=True)

        right = ctk.CTkFrame(split, width=320, corner_radius=14)
        right.pack(side="right", fill="y")
        right.pack_propagate(False)

        ctk.CTkLabel(
            right, text="Risk Distribution", font=ctk.CTkFont(size=12, weight="bold")
        ).pack(pady=(12, 4))
        self.chart_area = ctk.CTkFrame(right, fg_color="transparent")
        self.chart_area.pack(fill="both", expand=True, padx=10, pady=(0, 6))

        ctk.CTkLabel(
            right, text="Live Terminal", font=ctk.CTkFont(size=12, weight="bold")
        ).pack(pady=(4, 4))
        self.log_area = ctk.CTkTextbox(
            right,
            height=170,
            font=ctk.CTkFont(family="Consolas", size=11),
            fg_color="#121211",
            text_color="#3987e5",
        )
        self.log_area.pack(fill="x", expand=False, padx=10, pady=(0, 12))
        self.log_area.insert("0.0", "> Sentinel Security Core loaded…\n")
        self.log_area.configure(state="disabled")

        reports = ctk.CTkFrame(self.frame_scan, fg_color="transparent")
        reports.pack(fill="x", padx=26, pady=(0, 18))
        self.btn_html = ctk.CTkButton(
            reports, text="🌐 HTML", state="disabled", fg_color="#2a78d6",
            command=lambda: self.save_report("html"),
        )
        self.btn_pdf = ctk.CTkButton(
            reports, text="📄 PDF", state="disabled", fg_color="#d03b3b",
            command=lambda: self.save_report("pdf"),
        )
        self.btn_csv = ctk.CTkButton(
            reports, text="📊 CSV", state="disabled", fg_color="#1baf7a",
            command=lambda: self.save_report("csv"),
        )
        self.btn_sarif = ctk.CTkButton(
            reports, text="🧩 SARIF", state="disabled", fg_color="#6250d6",
            command=lambda: self.save_report("sarif"),
        )
        for button in (self.btn_html, self.btn_pdf, self.btn_csv, self.btn_sarif):
            button.pack(side="left", expand=True, fill="x", padx=4)

    def _build_vault_page(self):
        self.frame_vault = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")

        ctk.CTkLabel(
            self.frame_vault,
            text="QUARANTINE VAULT",
            font=ctk.CTkFont(size=24, weight="bold"),
        ).pack(pady=(30, 6))
        ctk.CTkLabel(
            self.frame_vault,
            text="Files are encrypted with AES-256-GCM. "
            "Recovery happens only after integrity is verified.",
            text_color="gray",
            font=ctk.CTkFont(size=12),
        ).pack(pady=(0, 16))

        actions = ctk.CTkFrame(self.frame_vault, fg_color="transparent")
        actions.pack(pady=(0, 10))
        ctk.CTkButton(actions, text="🔄 Refresh", width=130,
                      command=self.refresh_vault).pack(side="left", padx=6)
        ctk.CTkButton(actions, text="🔎 Integrity Check", width=180,
                      fg_color="#2a78d6", command=self.verify_vault).pack(
            side="left", padx=6
        )

        self.vault_list = ctk.CTkScrollableFrame(
            self.frame_vault, label_text="Encrypted Files"
        )
        self.vault_list.pack(fill="both", expand=True, padx=44, pady=(10, 26))

    # ------------------------------------------------------------------
    def show_frame(self, page: str):
        if page == "scan":
            self.frame_vault.grid_forget()
            self.frame_scan.grid(row=0, column=1, sticky="nsew")
            self.btn_nav_scan.configure(fg_color=("gray75", "gray25"))
            self.btn_nav_vault.configure(fg_color="transparent")
        else:
            self.frame_scan.grid_forget()
            self.frame_vault.grid(row=0, column=1, sticky="nsew")
            self.btn_nav_scan.configure(fg_color="transparent")
            self.btn_nav_vault.configure(fg_color=("gray75", "gray25"))
            self.refresh_vault()

    def browse_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.entry_path.delete(0, "end")
            self.entry_path.insert(0, folder)

    def log(self, message: str):
        self.log_area.configure(state="normal")
        self.log_area.insert("end", f"> {message}\n")
        self.log_area.see("end")
        self.log_area.configure(state="disabled")

    # ------------------------------------------------------------------
    def _select_all_path(self, _event=None):
        self.entry_path.select_range(0, "end")
        self.entry_path.icursor("end")
        return "break"  # block Tk's default "go to start of line"

    def _selected_severity_enum(self) -> Severity:
        label = self.option_severity.get()
        for severity in Severity:
            if severity.label == label:
                return severity
        return Severity.LOW

    def _selected_severity(self) -> str:
        return self._selected_severity_enum().value

    def start_scan(self):
        target = self.entry_path.get().strip()
        if not target or not os.path.exists(target):
            messagebox.showwarning("Warning", "Select a valid folder or file.")
            return

        # The confirmation must use the label the user sees. Printing
        # the raw enum value ('critical') contradicted the rest of the
        # interface ("Critical") and reduced clarity in the one dialog
        # that confirms an action which DELETES data.
        threshold = self._selected_severity_enum()
        if self.switch_quarantine.get() and not messagebox.askyesno(
            "Quarantine confirmation",
            "Active quarantine is enabled.\n\n"
            f"Files with findings at \u201c{threshold.label}\u201d or above "
            "will be encrypted, moved into the vault, and THE ORIGINALS "
            "DELETED.\n\n"
            "Continue?",
        ):
            return

        self.btn_start.configure(
            text="🛑 STOP",
            fg_color="#d03b3b",
            hover_color="#e66767",
            command=self.stop_scan,
        )
        for button in (self.btn_html, self.btn_pdf, self.btn_csv, self.btn_sarif):
            button.configure(state="disabled")

        self.progress.set(0)
        self.lbl_progress.configure(text="Enumerating files…")
        self.log_area.configure(state="normal")
        self.log_area.delete("1.0", "end")
        self.log_area.configure(state="disabled")
        for widget in self.findings_frame.winfo_children():
            widget.destroy()
        for widget in self.chart_area.winfo_children():
            widget.destroy()
        for label in self.summary_labels.values():
            label.configure(text="—")

        self.log(f"Target: {target}")

        thread = threading.Thread(target=self._run_scan, args=(target,), daemon=True)
        thread.start()

    def stop_scan(self):
        if self.current_scanner is not None:
            self.log("⚠️ Stop signal sent…")
            self.current_scanner.stop_scan()
            self.btn_start.configure(state="disabled", text="STOPPING…")

    def _run_scan(self, target: str):
        try:
            config = self.config_obj.replace(
                target=target,
                ocr=bool(self.switch_ocr.get()),
                archive_enabled=bool(self.switch_archive.get()),
                quarantine=bool(self.switch_quarantine.get()),
                quarantine_min_severity=self._selected_severity(),
                min_severity=self._selected_severity(),
                # Forking processes inside a GUI causes problems with Tk.
                executor="thread",
            )
            self.current_scanner = Scanner(
                target,
                config=config,
                log=lambda message: self.after(0, self.log, message),
            )
            result = self.current_scanner.scan(progress=self._on_progress)
            self.after(0, self._finish, result, None)
        except Exception as exc:  # pragma: no cover - the GUI error path
            self.after(0, self._finish, None, exc)

    def _on_progress(self, done: int, total: int, path: str):
        fraction = (done / total) if total else 0
        self.after(0, self.progress.set, fraction)
        self.after(
            0,
            self.lbl_progress.configure,
            {"text": f"{done}/{total} files - {os.path.basename(path)}"},
        )

    def _finish(self, result, error):
        self.current_scanner = None
        self.btn_start.configure(
            state="normal",
            text="🚀 START ANALYSIS",
            fg_color="#00695c",
            hover_color="#004d40",
            command=self.start_scan,
        )

        if error is not None:
            self.lbl_progress.configure(text="")
            self.log(f"❌ CRITICAL ERROR: {error}")
            messagebox.showerror("Error", f"The scan failed:\n{error}")
            return

        self.result = result
        self.progress.set(1)
        self.lbl_progress.configure(
            text=f"{result.files_scanned} files scanned · "
            f"{result.files_skipped} skipped · {len(result.errors)} errors"
        )

        self.summary_labels["risk"].configure(text=str(result.risk_score))
        self.summary_labels["total"].configure(text=str(len(result.findings)))
        self.summary_labels["files"].configure(text=str(result.files_scanned))
        self.summary_labels["duration"].configure(text=f"{result.duration:.1f}s")

        self.refresh_findings()
        self._draw_chart()

        if not result.findings:
            self.log("✅ System clean - no sensitive data at or above the threshold.")
            messagebox.showinfo("Clean", "No threats found.")
            return

        for button in (self.btn_html, self.btn_pdf, self.btn_csv, self.btn_sarif):
            button.configure(state="normal")

        counts = result.counts_by_severity()
        self.log(
            f"⚠️ {len(result.findings)} findings - critical: {counts.get('critical', 0)}, "
            f"high: {counts.get('high', 0)}"
        )
        if result.quarantined:
            self.log(f"☣️ {len(result.quarantined)} files moved to quarantine.")

        messagebox.showwarning(
            "Alarm",
            f"{len(result.findings)} risky values detected.\n"
            f"Risk score: {result.risk_score}/100",
        )

    # ------------------------------------------------------------------
    def refresh_findings(self):
        for widget in self.findings_frame.winfo_children():
            widget.destroy()
        if self.result is None:
            return

        needle = self.entry_filter.get().strip().lower()
        findings = [
            finding
            for finding in self.result.findings
            if not needle
            or needle in finding.file.lower()
            or needle in finding.type.lower()
        ]

        if not findings:
            ctk.CTkLabel(
                self.findings_frame,
                text="No findings to show." if needle else "No scan has run yet.",
                text_color="gray",
            ).pack(pady=20)
            return

        for finding in findings[:MAX_ROWS]:
            severity = finding.severity_enum
            row = ctk.CTkFrame(self.findings_frame, fg_color="#242423", corner_radius=8)
            row.pack(fill="x", padx=6, pady=3)

            ctk.CTkLabel(
                row,
                text=f"{severity.icon} {severity.label}",
                text_color=SEVERITY_COLORS[severity],
                font=ctk.CTkFont(size=11, weight="bold"),
                width=84,
                anchor="w",
            ).pack(side="left", padx=(10, 6), pady=7)

            ctk.CTkLabel(
                row,
                text=finding.type,
                font=ctk.CTkFont(size=11, weight="bold"),
                width=150,
                anchor="w",
            ).pack(side="left", padx=(0, 6))

            location = f"{finding.file}:{finding.line}" if finding.line else finding.file
            ctk.CTkLabel(
                row,
                text=location,
                text_color="#c3c2b7",
                font=ctk.CTkFont(size=11),
                anchor="w",
            ).pack(side="left", fill="x", expand=True)

            ctk.CTkLabel(
                row,
                text=finding.content_masked,
                text_color="#8f8e85",
                font=ctk.CTkFont(family="Consolas", size=11),
                anchor="e",
            ).pack(side="right", padx=10)

        if len(findings) > MAX_ROWS:
            ctk.CTkLabel(
                self.findings_frame,
                text=f"… and {len(findings) - MAX_ROWS} more findings "
                "(save a report for the full list)",
                text_color="gray",
            ).pack(pady=10)

    def _draw_chart(self):
        for widget in self.chart_area.winfo_children():
            widget.destroy()
        if self.result is None or not self.result.findings:
            return

        counts = self.result.counts_by_severity()
        rows = [
            (severity, counts.get(severity.value, 0))
            for severity in sorted(Severity, key=lambda s: -s.rank)
            if counts.get(severity.value, 0)
        ]

        if not HAS_MATPLOTLIB:
            # Without a charting library, show the same information as bars.
            total = sum(count for _, count in rows) or 1
            for severity, count in rows:
                line = ctk.CTkFrame(self.chart_area, fg_color="transparent")
                line.pack(fill="x", pady=4)
                ctk.CTkLabel(
                    line,
                    text=f"{severity.icon} {severity.label}",
                    text_color=SEVERITY_COLORS[severity],
                    font=ctk.CTkFont(size=11, weight="bold"),
                    width=90,
                    anchor="w",
                ).pack(side="left")
                bar = ctk.CTkProgressBar(
                    line, progress_color=SEVERITY_COLORS[severity], height=8
                )
                bar.pack(side="left", fill="x", expand=True, padx=6)
                bar.set(count / total)
                ctk.CTkLabel(line, text=str(count), width=34, anchor="e").pack(
                    side="right"
                )
            return

        figure, axes = plt.subplots(figsize=(3.2, 2.6), dpi=100)
        figure.patch.set_facecolor("#1a1a19")
        axes.set_facecolor("#1a1a19")

        labels = [severity.label for severity, _ in rows]
        values = [count for _, count in rows]
        colors = [SEVERITY_COLORS[severity] for severity, _ in rows]

        bars = axes.barh(labels, values, color=colors, height=0.6)
        axes.invert_yaxis()
        axes.tick_params(colors="#c3c2b7", labelsize=8, length=0)
        for spine in axes.spines.values():
            spine.set_visible(False)
        axes.set_xticks([])
        for bar, value in zip(bars, values, strict=True):
            axes.text(
                bar.get_width() + max(values) * 0.02,
                bar.get_y() + bar.get_height() / 2,
                str(value),
                va="center",
                color="#f0efec",
                fontsize=8,
            )
        figure.tight_layout()

        canvas = FigureCanvasTkAgg(figure, master=self.chart_area)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)
        plt.close(figure)

    # ------------------------------------------------------------------
    def save_report(self, fmt: str):
        if self.result is None or not self.result.findings:
            return

        extensions = {"html": ".html", "pdf": ".pdf", "csv": ".csv", "sarif": ".sarif"}
        path = filedialog.asksaveasfilename(
            defaultextension=extensions[fmt],
            initialfile=f"sentinel_report{extensions[fmt]}",
            filetypes=[(f"{fmt.upper()} file", f"*{extensions[fmt]}")],
        )
        if not path:
            return

        directory = os.path.dirname(path) or "."
        written = write_reports(self.result, directory, [fmt])
        produced = written.get(fmt, "")

        if str(produced).startswith("ERROR"):
            messagebox.showerror("Error", f"Could not write the report:\n{produced}")
            return

        if os.path.abspath(produced) != os.path.abspath(path):
            os.replace(produced, path)

        self.log(f"Report saved: {path}")
        open_path(path)

    # ------------------------------------------------------------------
    def refresh_vault(self):
        for widget in self.vault_list.winfo_children():
            widget.destroy()

        items = self.qm.list_items()
        if not items:
            ctk.CTkLabel(
                self.vault_list,
                text=f"The vault is empty.\n{self.qm.q_dir}",
                text_color="gray",
            ).pack(pady=24)
            return

        for item in items:
            row = ctk.CTkFrame(self.vault_list)
            row.pack(fill="x", padx=5, pady=5)

            info = ctk.CTkFrame(row, fg_color="transparent")
            info.pack(side="left", fill="x", expand=True, padx=10, pady=8)

            title = "🔒 " + item["name"]
            if item.get("legacy"):
                title += "   (legacy format)"
            ctk.CTkLabel(
                info, text=title, font=ctk.CTkFont(size=12, weight="bold"), anchor="w"
            ).pack(fill="x")
            ctk.CTkLabel(
                info,
                text=item.get("original_path") or "(original location unknown)",
                text_color="gray",
                font=ctk.CTkFont(size=10),
                anchor="w",
            ).pack(fill="x")

            ctk.CTkButton(
                row,
                text="Recover",
                width=84,
                fg_color="#6250d6",
                command=lambda name=item["name"]: self.restore(name),
            ).pack(side="right", padx=(0, 10), pady=8)

    def verify_vault(self):
        results = self.qm.verify_all()
        if not results:
            messagebox.showinfo("Integrity", "The vault is empty.")
            return
        bad = [entry for entry in results if not entry["ok"]]
        if bad:
            detail = "\n".join(f"✗ {entry['name']}: {entry['detail']}" for entry in bad)
            messagebox.showerror(
                "Integrity error", f"{len(bad)} files failed verification:\n\n{detail}"
            )
        else:
            messagebox.showinfo(
                "Integrity", f"All {len(results)} files verified."
            )

    def restore(self, name: str):
        full = os.path.join(self.qm.q_dir, name)
        ok, message = self.qm.restore_file(full)

        if not ok and "not overwritten" in message:
            if messagebox.askyesno(
                "File exists",
                f"{message}\n\nOverwrite it?",
            ):
                ok, message = self.qm.restore_file(full, force=True)

        if ok:
            messagebox.showinfo("Success", f"File recovered:\n{message}")
            self.refresh_vault()
        else:
            messagebox.showerror("Error", f"Could not recover it:\n{message}")


def main():
    SentinelPro().mainloop()


if __name__ == "__main__":
    main()
