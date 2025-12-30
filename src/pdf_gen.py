import os
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from datetime import datetime

def create_pdf_report(results, filename):
    try:
        doc = SimpleDocTemplate(filename, pagesize=A4)
        elements = []
        styles = getSampleStyleSheet()

        # --- BAŞLIK ---
        title_style = styles['Title']
        elements.append(Paragraph("SENTINEL - Hassas Veri Tarama Raporu", title_style))
        elements.append(Spacer(1, 12))
        
        # Tarih Bilgisi
        date_str = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
        elements.append(Paragraph(f"Oluşturulma Tarihi: {date_str}", styles['Normal']))
        elements.append(Spacer(1, 20))

        # --- TABLO VERİLERİ ---
        # Tablo Başlıkları
        data = [['Dosya Yolu', 'Satır', 'Risk Türü', 'İçerik (Maskeli)']]
        
        # Verileri Ekle
        for item in results:
            # Dosya yolu çok uzunsa satır kaydırsın diye Paragraph kullanıyoruz
            file_para = Paragraph(os.path.basename(item['file']), styles['BodyText'])
            content_para = Paragraph(item['content_masked'], styles['BodyText'])
            
            row = [
                file_para,
                item['line'],
                item['type'],
                content_para
            ]
            data.append(row)

        # --- TABLO STİLİ ---
        # Sütun Genişlikleri
        col_widths = [200, 40, 100, 150]
        
        t = Table(data, colWidths=col_widths)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue), # Başlık Rengi
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),   # Satır Rengi
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        
        elements.append(t)
        
        # PDF OLUŞTUR
        doc.build(elements)
        return True, "Başarılı"
        
    except Exception as e:
        return False, str(e)