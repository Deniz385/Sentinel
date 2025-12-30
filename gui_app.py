import sys
import os
import threading
import webbrowser
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk

# --- GRAFİK KÜTÜPHANESİ ---
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# --- AYARLAR VE TEMA ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")

# --- PATH AYARLARI ---
def get_base_path():
    if getattr(sys, 'frozen', False): return sys._MEIPASS
    return os.path.dirname(os.path.abspath(__file__))

base_path = get_base_path()
src_path = os.path.join(base_path, 'src')
if src_path not in sys.path: sys.path.insert(0, src_path)

try:
    from scanner import Scanner
    from reporter import generate_html_report
    from quarantine import QuarantineManager
    from pdf_gen import create_pdf_report
except ImportError as e:
    messagebox.showerror("Kritik Hata", f"Modüller eksik: {e}")
    sys.exit(1)

class SentinelPro(ctk.CTk):
    def __init__(self):
        super().__init__()

        # PENCERE YAPILANDIRMASI
        self.title("SENTINEL | Endpoint Security Dashboard")
        self.geometry("1200x800")
        self.minsize(1000, 700)
        
        # Grid Layout (Sidebar | Main)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.qm = QuarantineManager()
        self.last_results = []
        self.current_scanner = None # Aktif tarayıcıyı tutmak için
        
        self.create_sidebar()
        self.create_main_area()

    def create_sidebar(self):
        """Sol Menü Paneli"""
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(4, weight=1)

        # Logo
        self.lbl_logo = ctk.CTkLabel(self.sidebar, text="🛡️ SENTINEL", 
                                     font=ctk.CTkFont(size=26, weight="bold"))
        self.lbl_logo.grid(row=0, column=0, padx=20, pady=(30, 10))
        
        self.lbl_sub = ctk.CTkLabel(self.sidebar, text="DLP & Threat Hunter", 
                                    text_color="gray", font=ctk.CTkFont(size=12))
        self.lbl_sub.grid(row=1, column=0, padx=20, pady=(0, 30))

        # Butonlar
        self.btn_nav_scan = ctk.CTkButton(self.sidebar, text="🔍  Tarama Merkezi", height=45, corner_radius=8,
                                          fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                          anchor="w", font=ctk.CTkFont(weight="bold"), 
                                          command=lambda: self.show_frame("scan"))
        self.btn_nav_scan.grid(row=2, column=0, padx=15, pady=5, sticky="ew")

        self.btn_nav_quarantine = ctk.CTkButton(self.sidebar, text="☣️  Karantina Kasası", height=45, corner_radius=8,
                                                fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                anchor="w", font=ctk.CTkFont(weight="bold"),
                                                command=lambda: self.show_frame("quarantine"))
        self.btn_nav_quarantine.grid(row=3, column=0, padx=15, pady=5, sticky="ew")

        # Footer
        self.lbl_status = ctk.CTkLabel(self.sidebar, text="System: ONLINE", text_color="#00e676", font=ctk.CTkFont(size=11, weight="bold"))
        self.lbl_status.grid(row=5, column=0, padx=20, pady=20)

    def create_main_area(self):
        """Sağ İçerik Alanı"""
        # --- 1. TARAMA SAYFASI ---
        self.frame_scan = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        
        # Üst Panel (Input ve Ayarlar)
        self.top_panel = ctk.CTkFrame(self.frame_scan, corner_radius=15, fg_color=("#2b2b2b"))
        self.top_panel.pack(fill="x", padx=30, pady=20)
        
        ctk.CTkLabel(self.top_panel, text="YENİ TARAMA GÖREVİ", font=ctk.CTkFont(weight="bold", size=14)).pack(anchor="w", padx=20, pady=(15, 5))
        
        # Dosya Yolu
        self.path_frame = ctk.CTkFrame(self.top_panel, fg_color="transparent")
        self.path_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        self.entry_path = ctk.CTkEntry(self.path_frame, placeholder_text="C:\\Users\\Data...", height=40)
        self.entry_path.pack(side="left", fill="x", expand=True, padx=(10, 10))
        
        self.btn_browse = ctk.CTkButton(self.path_frame, text="📂 Seç", width=80, height=40, command=self.browse_folder)
        self.btn_browse.pack(side="left", padx=(0, 10))

        # Switchler
        self.switch_frame = ctk.CTkFrame(self.top_panel, fg_color="transparent")
        self.switch_frame.pack(fill="x", padx=20, pady=10)
        
        self.switch_ocr = ctk.CTkSwitch(self.switch_frame, text="OCR (Görsel Analiz)", progress_color="#f39c12")
        self.switch_ocr.pack(side="left", padx=10)
        
        self.switch_quarantine = ctk.CTkSwitch(self.switch_frame, text="Aktif Karantina", progress_color="#e74c3c")
        self.switch_quarantine.pack(side="left", padx=20)

        # Başlat / Durdur Butonu (Değişken Buton)
        self.btn_start = ctk.CTkButton(self.frame_scan, text="🚀 ANALİZİ BAŞLAT", height=50, 
                                       font=ctk.CTkFont(size=16, weight="bold"), fg_color="#00695c", hover_color="#004d40",
                                       command=self.start_scan_process)
        self.btn_start.pack(fill="x", padx=30, pady=(0, 10))

        # İlerleme Çubuğu
        self.progress = ctk.CTkProgressBar(self.frame_scan, height=10)
        self.progress.pack(fill="x", padx=30, pady=(10, 5))
        self.progress.set(0)

        # --- ALT PANEL (Loglar ve Grafik) ---
        self.bottom_split = ctk.CTkFrame(self.frame_scan, fg_color="transparent")
        self.bottom_split.pack(fill="both", expand=True, padx=30, pady=20)
        
        # Sol: Log
        self.log_container = ctk.CTkFrame(self.bottom_split, fg_color="transparent")
        self.log_container.pack(side="left", fill="both", expand=True, padx=(0, 10))
        
        ctk.CTkLabel(self.log_container, text="Canlı Terminal", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w")
        self.log_area = ctk.CTkTextbox(self.log_container, font=ctk.CTkFont(family="Consolas", size=12), 
                                       fg_color="#1a1a1a", text_color="#00ff41")
        self.log_area.pack(fill="both", expand=True, pady=(5, 0))
        self.log_area.insert("0.0", "> Sentinel Security Core loaded...\n")
        self.log_area.configure(state="disabled")

        # Sağ: Grafik Alanı
        self.chart_container = ctk.CTkFrame(self.bottom_split, width=300, fg_color="#2b2b2b", corner_radius=15)
        self.chart_container.pack(side="right", fill="y", padx=(10, 0))
        self.chart_container.pack_propagate(False) 
        
        ctk.CTkLabel(self.chart_container, text="Risk Analizi", font=ctk.CTkFont(size=12, weight="bold")).pack(pady=10)
        self.chart_canvas_area = ctk.CTkFrame(self.chart_container, fg_color="transparent")
        self.chart_canvas_area.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Rapor Butonları
        self.report_frame = ctk.CTkFrame(self.frame_scan, fg_color="transparent")
        self.report_frame.pack(fill="x", padx=30, pady=(0, 20))
        
        self.btn_html = ctk.CTkButton(self.report_frame, text="🌐 HTML Rapor", state="disabled", fg_color="#2980b9", command=self.open_html_report)
        self.btn_html.pack(side="left", expand=True, fill="x", padx=5)
        
        self.btn_pdf = ctk.CTkButton(self.report_frame, text="📄 PDF Rapor", state="disabled", fg_color="#c0392b", command=self.save_pdf_report)
        self.btn_pdf.pack(side="left", expand=True, fill="x", padx=5)

        # --- 2. KARANTİNA SAYFASI ---
        self.frame_quarantine = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        
        ctk.CTkLabel(self.frame_quarantine, text="KARANTİNA KASASI", font=ctk.CTkFont(size=24, weight="bold")).pack(pady=30)
        
        self.btn_refresh = ctk.CTkButton(self.frame_quarantine, text="🔄 Listeyi Yenile", command=self.refresh_quarantine_list)
        self.btn_refresh.pack(pady=10)
        
        self.q_list_frame = ctk.CTkScrollableFrame(self.frame_quarantine, label_text="Şifreli Dosyalar")
        self.q_list_frame.pack(fill="both", expand=True, padx=50, pady=20)

        # Başlangıç
        self.show_frame("scan")

    def show_frame(self, page_name):
        if page_name == "scan":
            self.frame_quarantine.grid_forget()
            self.frame_scan.grid(row=0, column=1, sticky="nsew")
            self.btn_nav_scan.configure(fg_color=("gray75", "gray25"))
            self.btn_nav_quarantine.configure(fg_color="transparent")
        elif page_name == "quarantine":
            self.frame_scan.grid_forget()
            self.frame_quarantine.grid(row=0, column=1, sticky="nsew")
            self.btn_nav_scan.configure(fg_color="transparent")
            self.btn_nav_quarantine.configure(fg_color=("gray75", "gray25"))
            self.refresh_quarantine_list()

    def browse_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.entry_path.delete(0, tk.END)
            self.entry_path.insert(0, folder)

    def log(self, msg):
        self.log_area.configure(state="normal")
        self.log_area.insert("end", f"> {msg}\n")
        self.log_area.see("end")
        self.log_area.configure(state="disabled")

    # --- TARAMA YÖNETİMİ (BAŞLAT / DURDUR) ---
    def start_scan_process(self):
        target = self.entry_path.get()
        if not target:
            messagebox.showwarning("Uyarı", "Lütfen bir klasör seçin!")
            return
        
        # Butonu "DURDUR" moduna çevir
        self.btn_start.configure(text="🛑 DURDUR", fg_color="#c0392b", hover_color="#e74c3c", command=self.stop_scan_process)
        
        # UI Hazırlığı
        self.btn_html.configure(state="disabled")
        self.btn_pdf.configure(state="disabled")
        self.progress.start()
        
        # Log ve Grafik Temizliği
        self.log_area.configure(state="normal")
        self.log_area.delete("1.0", "end")
        self.log_area.configure(state="disabled")
        
        # Eski grafiği temizle
        for widget in self.chart_canvas_area.winfo_children():
            widget.destroy()

        self.log(f"Hedef analiz ediliyor: {target}")
        
        # Thread başlat
        t = threading.Thread(target=self.run_scan_thread, args=(target,))
        t.daemon = True
        t.start()

    def stop_scan_process(self):
        """Kullanıcı Durdur'a bastığında çalışır"""
        if self.current_scanner:
            self.log("⚠️ DURDURMA SİNYALİ GÖNDERİLDİ...")
            self.current_scanner.stop_scan()
            self.btn_start.configure(state="disabled", text="DURDURULUYOR...")

    def run_scan_thread(self, target):
        try:
            ocr_val = bool(self.switch_ocr.get())
            quar_val = bool(self.switch_quarantine.get())

            # Scanner nesnesini oluştur ve referansını sakla (Durdurabilmek için)
            self.current_scanner = Scanner(target, use_ocr=ocr_val, quarantine_mode=quar_val)
            
            # Taramayı başlat
            self.last_results = self.current_scanner.start_scan_parallel()
            
            if self.last_results:
                generate_html_report(self.last_results, "dashboard.html")
                self.after(0, lambda: self.finish_scan(True, False))
            else:
                self.after(0, lambda: self.finish_scan(False, False))
                
        except Exception as e:
            self.after(0, lambda: self.log(f"KRİTİK HATA: {e}"))
            self.after(0, lambda: self.finish_scan(False, True))

    def finish_scan(self, found_threats, is_error):
        self.progress.stop()
        self.progress.set(1 if found_threats else 0)
        
        # Butonu tekrar "BAŞLAT" moduna çevir
        self.btn_start.configure(state="normal", text="🚀 ANALİZİ BAŞLAT", fg_color="#00695c", hover_color="#004d40", command=self.start_scan_process)
        
        self.current_scanner = None # Referansı temizle

        if is_error:
            self.log("❌ Tarama hata ile sonlandı.")
            return

        if found_threats:
            count = len(self.last_results)
            self.log(f"⚠️ İŞLEM TAMAMLANDI: {count} tehdit bulundu.")
            self.btn_html.configure(state="normal")
            self.btn_pdf.configure(state="normal")
            messagebox.showwarning("Alarm", f"{count} adet riskli veri tespit edildi.")
            self.create_chart()
        else:
            self.log("✅ İŞLEM TAMAMLANDI: Sistem temiz.")
            messagebox.showinfo("Temiz", "Tehdit bulunamadı.")

    def create_chart(self):
        # Verileri Say
        counts = {}
        for item in self.last_results:
            typ = item['type']
            counts[typ] = counts.get(typ, 0) + 1
            
        labels = list(counts.keys())
        sizes = list(counts.values())
        
        # Matplotlib ile Pasta Grafiği
        fig, ax = plt.subplots(figsize=(4, 4), dpi=100)
        fig.patch.set_facecolor('#2b2b2b')
        ax.set_facecolor('#2b2b2b')
        
        colors = ['#e74c3c', '#3498db', '#f1c40f', '#9b59b6', '#2ecc71']
        
        wedges, texts, autotexts = ax.pie(sizes, labels=labels, autopct='%1.1f%%', 
                                          startangle=90, colors=colors[:len(labels)],
                                          textprops={'color':"white", 'fontsize': 9})
        
        ax.axis('equal')
        plt.title("Risk Dağılımı", color="white", fontsize=11, pad=10)
        plt.tight_layout()

        canvas = FigureCanvasTkAgg(fig, master=self.chart_canvas_area)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)

    def open_html_report(self):
        webbrowser.open('file://' + os.path.abspath("dashboard.html"))

    def save_pdf_report(self):
        if not self.last_results: return
        path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF Dosyası", "*.pdf")])
        if path:
            success, msg = create_pdf_report(self.last_results, path)
            if success:
                self.log(f"PDF Kaydedildi: {path}")
                try: os.startfile(path)
                except: pass

    # --- KARANTİNA YÖNETİMİ ---
    def refresh_quarantine_list(self):
        for widget in self.q_list_frame.winfo_children():
            widget.destroy()
            
        folder = self.qm.q_dir
        if not os.path.exists(folder): return

        files = [f for f in os.listdir(folder) if f.endswith('.enc')]
        
        if not files:
            ctk.CTkLabel(self.q_list_frame, text="Karantina boş.", text_color="gray").pack(pady=20)
            return

        for f in files:
            row = ctk.CTkFrame(self.q_list_frame)
            row.pack(fill="x", padx=5, pady=5)
            
            ctk.CTkLabel(row, text="🔒 " + f, font=("Consolas", 12)).pack(side="left", padx=10)
            
            ctk.CTkButton(row, text="Kurtar", width=80, fg_color="#8e44ad", 
                          command=lambda fname=f: self.restore_single_file(fname)).pack(side="right", padx=10, pady=5)

    def restore_single_file(self, filename):
        full_path = os.path.join(self.qm.q_dir, filename)
        status, res_path = self.qm.restore_file(full_path)
        if status:
            messagebox.showinfo("Başarılı", f"Dosya kurtarıldı:\n{res_path}")
            self.refresh_quarantine_list()
        else:
            messagebox.showerror("Hata", f"Kurtarılamadı: {res_path}")

if __name__ == "__main__":
    app = SentinelPro()
    app.mainloop()