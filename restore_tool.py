# restore_tool.py (OTOMATİK VERSİYON)
import sys
import os
import tkinter as tk
from tkinter import filedialog, messagebox

# src yolunu tanıt
base_path = os.path.dirname(os.path.abspath(__file__))
src_path = os.path.join(base_path, 'src')
if src_path not in sys.path:
    sys.path.append(src_path)

from quarantine import QuarantineManager

def main():
    root = tk.Tk()
    root.withdraw()

    qm = QuarantineManager()
    
    # Sadece dosyayı seçtiriyoruz
    messagebox.showinfo("Dosya Seç", "Kurtarılacak şifreli (.enc) dosyayı seçin.\nOtomatik olarak eski yerine yüklenecektir.")
    
    enc_file = filedialog.askopenfilename(
        initialdir="QUARANTINE_ZONE",
        title="Kurtarılacak Dosyayı Seç",
        filetypes=[("Şifreli Dosyalar", "*.enc")]
    )

    if not enc_file:
        return

    # Soru sormadan direkt restore_file fonksiyonunu çağırıyoruz
    # (Adresi artık sormuyoruz, çünkü fonksiyon metadata'dan okuyacak)
    success, msg = qm.restore_file(enc_file)

    if success:
        messagebox.showinfo("Başarılı", f"Dosya orijinal konumuna geri yüklendi:\n\n{msg}")
    else:
        messagebox.showerror("Hata", f"Dosya kurtarılamadı!\n{msg}")

if __name__ == "__main__":
    main()