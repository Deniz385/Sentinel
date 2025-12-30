# src/reporter.py
import os

def generate_html_report(results, output_file="scan_report.html"):
    """
    Bulunan sonuçlardan şık bir HTML Dashboard oluşturur.
    """
    if not results:
        print("[INFO] Raporlanacak veri yok.")
        return

    # İstatistikleri hesapla
    total_count = len(results)
    type_counts = {}
    for r in results:
        type_counts[r['type']] = type_counts.get(r['type'], 0) + 1

    # HTML Şablonu (CSS ile stil verilmiş)
    html_content = f"""
    <!DOCTYPE html>
    <html lang="tr">
    <head>
        <meta charset="UTF-8">
        <title>Hassas Veri Tarama Raporu</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f4f9; padding: 20px; }}
            .header {{ background-color: #2c3e50; color: white; padding: 15px; border-radius: 8px; text-align: center; }}
            .summary-box {{ display: flex; justify-content: space-around; margin: 20px 0; }}
            .card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); width: 30%; text-align: center; }}
            .card h3 {{ margin: 0; color: #7f8c8d; }}
            .card p {{ font-size: 2em; font-weight: bold; color: #e74c3c; margin: 10px 0 0 0; }}
            table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
            th {{ background-color: #3498db; color: white; }}
            tr:hover {{ background-color: #f1f1f1; }}
            .footer {{ margin-top: 20px; text-align: center; color: #95a5a6; font-size: 0.9em; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Hassas Veri Keşif Raporu (DLP)</h1>
            <p>Oluşturulma Tarihi: {os.popen('date /t').read().strip() if os.name=='nt' else 'Bugün'}</p>
        </div>

        <div class="summary-box">
            <div class="card">
                <h3>Toplam Riskli Veri</h3>
                <p>{total_count}</p>
            </div>
            <div class="card">
                <h3>En Çok Bulunan Tür</h3>
                <p>{max(type_counts, key=type_counts.get) if type_counts else 'Yok'}</p>
            </div>
            <div class="card">
                <h3>Taranan Konum Sayısı</h3>
                <p>{len(set(r['file'] for r in results))}</p>
            </div>
        </div>

        <h2>Detaylı Bulgular (Maskelenmiş)</h2>
        <table>
            <thead>
                <tr>
                    <th>Dosya Yolu</th>
                    <th>Satır</th>
                    <th>Veri Tipi</th>
                    <th>İçerik (Maskeli)</th>
                </tr>
            </thead>
            <tbody>
    """

    # Tablo satırlarını ekle
    for r in results:
        html_content += f"""
                <tr>
                    <td>{r['file']}</td>
                    <td>{r['line']}</td>
                    <td><strong>{r['type']}</strong></td>
                    <td style="font-family: monospace;">{r['content_masked']}</td>
                </tr>
        """

    html_content += """
            </tbody>
        </table>
        <div class="footer">
            <p>Bu rapor Sensitive Data Discovery Tool tarafından otomatik oluşturulmuştur. Gizli bilgiler içerir.</p>
        </div>
    </body>
    </html>
    """

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)
    
    print(f"[RAPOR] HTML Dashboard oluşturuldu: {os.path.abspath(output_file)}")