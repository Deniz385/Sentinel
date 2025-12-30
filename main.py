# main.py (CLI VERSION)
import os
import sys
import time
import argparse
import pandas as pd

sys.path.append(os.path.abspath('src'))

from scanner import Scanner
from reporter import generate_html_report

def main():
    # CLI Argümanlarını Tanımla
    parser = argparse.ArgumentParser(description="Advanced Sensitive Data Discovery Tool (DLP)")
    parser.add_argument("--target", "-t", help="Taranacak hedef klasör", default="test_data")
    parser.add_argument("--output", "-o", help="Raporların kaydedileceği dizin", default=".")
    parser.add_argument("--no-html", help="HTML raporu oluşturma", action="store_true")
    
    args = parser.parse_args()

    print("==========================================")
    print("   🛡️ SENTINEL DATA SCANNER v3.0 (CLI)    ")
    print("==========================================")
    
    # Hedef klasör kontrolü
    target_folder = args.target
    if not os.path.exists(target_folder):
        # Demo modu: Klasör yoksa oluştur
        if target_folder == "test_data":
            os.makedirs(target_folder)
            print("[INIT] Demo klasörü oluşturuldu.")
            # Buraya demo data oluşturma fonksiyonu çağrılabilir
        else:
            print(f"[HATA] Hedef klasör bulunamadı: {target_folder}")
            return

    print(f"[INFO] Hedef: {os.path.abspath(target_folder)}")
    print(f"[INFO] Modüller: PDF, Excel, ZIP, Text, Regex, Algoritmik Doğrulama")
    
    scanner = Scanner(target_folder)
    
    start_time = time.time()
    results = scanner.start_scan_parallel() # Paralel tarama
    duration = time.time() - start_time
    
    print(f"\n[SONUÇ] Analiz Tamamlandı.")
    print(f"[PERFORMANS] Süre: {duration:.4f} sn | Taranan: {target_folder}")
    
    if results:
        print(f"[ALARM] {len(results)} kritik veri tespit edildi.")
        
        # DataFrame oluştur
        df = pd.DataFrame(results)
        
        # CSV Kaydet
        csv_path = os.path.join(args.output, "scan_results.csv")
        df.to_csv(csv_path, index=False)
        print(f"[+] CSV Rapor: {csv_path}")
        
        # HTML Kaydet (İstenirse)
        if not args.no_html:
            html_path = os.path.join(args.output, "dashboard.html")
            generate_html_report(results, html_path)
            # Windows'ta otomatik aç
            if os.name == 'nt':
                os.system(f"start {html_path}")
    else:
        print("[OK] Sistem temiz. Sızıntı tespit edilmedi.")

if __name__ == "__main__":
    main()