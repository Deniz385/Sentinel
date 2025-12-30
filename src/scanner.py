import os
import io
import re
import sys
import requests
import logging
from datetime import datetime

# --- CUSTOM MODÜLLER ---
# Bu dosyaların src klasöründe olduğundan emin ol
from patterns import get_patterns
from utils import setup_logger, mask_data, calculate_file_hash
from quarantine import QuarantineManager
from validators import validate_tc, validate_credit_card, validate_iban 

# --- AYARLAR ---
# Discord/Teams Webhook URL'nizi buraya yapıştırın.
WEBHOOK_URL = "SENIN_WEBHOOK_URL_ADRESIN_BURAYA"

# --- HARİCİ KÜTÜPHANE KONTROLLERİ ---
try: from pypdf import PdfReader
except ImportError: PdfReader = None

try: import openpyxl
except ImportError: openpyxl = None

# --- TESSERACT OCR AYARLARI ---
pytesseract = None
try:
    from PIL import Image
    import pytesseract as pt
    
    # 1. Tesseract EXE Yolu
    t_path = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
    # 2. Dil Dosyaları Yolu (tessdata)
    t_data_path = r"C:\Program Files\Tesseract-OCR\tessdata"
    
    if os.path.exists(t_path):
        pt.pytesseract.tesseract_cmd = t_path
        
        # Ortam Değişkenini Ayarla
        if os.path.exists(t_data_path):
            os.environ['TESSDATA_PREFIX'] = t_data_path
        else:
            os.environ['TESSDATA_PREFIX'] = r"C:\Program Files\Tesseract-OCR"

        pytesseract = pt 
        print(f"[BİLGİ] Tesseract OCR motoru aktif.")
    else:
        print(f"[UYARI] Tesseract EXE bulunamadı. Resim taraması devre dışı.")

except ImportError:
    print("[UYARI] OCR modülleri (pytesseract/pillow) eksik.")

# --- WEBHOOK FONKSİYONU ---
def send_webhook(filename, line_num, risk_type, content):
    """Hassas veri bulunduğunda bildirim gönderir."""
    if not WEBHOOK_URL or "SENIN_WEBHOOK" in WEBHOOK_URL:
        return 

    msg = (
        f"🚨 **HASSAS VERİ TESPİT EDİLDİ!**\n"
        f"📂 **Dosya:** `{filename}`\n"
        f"🔢 **Satır:** {line_num}\n"
        f"⚠️ **Tür:** {risk_type}\n"
        f"🕵️ **İçerik:** `{content}`\n"
        f"⏰ **Tarih:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )
    
    payload = {"content": msg}
    try:
        requests.post(WEBHOOK_URL, json=payload, timeout=2)
    except Exception:
        pass 

# --- TARAMA VE EŞLEŞTİRME MANTIĞI ---
def check_content_matches(content, file_source, original_path, patterns):
    local_results = []
    seen_values = set()
    
    lines = content.splitlines()
    for line_num, line in enumerate(lines, 1):
        if not line.strip(): continue
        
        for p_name, p_regex in patterns.items():
            for match in p_regex.findall(line):
                
                # Regex Gruplarını İşleme (Şifreler için)
                if isinstance(match, tuple):
                    match_str = f"{match[0]} = {match[1]}"
                    clean_match = match[1] 
                else:
                    match_str = match
                    clean_match = match_str.strip()
                
                if match_str in seen_values: continue
                
                # --- VALIDASYON (DOĞRULAMA) ---
                is_valid = True
                
                if p_name == "TC_KIMLIK":
                    if not validate_tc(clean_match): is_valid = False
                elif p_name == "KREDI_KARTI":
                    if not validate_credit_card(clean_match): is_valid = False
                elif p_name == "TR_IBAN":
                    if not validate_iban(clean_match): is_valid = False
                
                if not is_valid: continue 
                # ------------------------------

                seen_values.add(match_str)
                masked_content = mask_data(match_str)
                
                print(f"  -> [TESPİT] {p_name}: {match_str} ({file_source})")
                
                # Webhook Gönder
                send_webhook(file_source, line_num, p_name, masked_content)

                local_results.append({
                    "file": file_source, "line": line_num, "type": p_name,
                    "content_masked": masked_content,
                    "sha256": calculate_file_hash(original_path) if original_path else "N/A"
                })
    return local_results

class Scanner:
    def __init__(self, target_dir, use_ocr=False, quarantine_mode=False):
        self.target_dir = target_dir
        self.use_ocr = use_ocr
        self.quarantine_mode = quarantine_mode
        self.patterns = get_patterns()
        self.qm = QuarantineManager() if quarantine_mode else None
        
        # Taramayı durdurmak için bayrak
        self.stop_requested = False

    def stop_scan(self):
        """Dışarıdan çağrılınca taramayı durdurur"""
        self.stop_requested = True

    def scan_file(self, filepath):
        results = []
        filename = os.path.basename(filepath).lower()
        
        # --- 1. RESİM DOSYALARI (OCR) ---
        if filename.endswith(('.png', '.jpg', '.jpeg', '.bmp')):
            if self.use_ocr and pytesseract:
                print(f"[*] OCR Taranıyor: {filepath}")
                try:
                    try:
                        text = pytesseract.image_to_string(Image.open(filepath), lang='tur+eng')
                    except Exception:
                        text = pytesseract.image_to_string(Image.open(filepath), lang='eng')
                    
                    if text.strip():
                        results = check_content_matches(text, filepath, filepath, self.patterns)
                except Exception as e:
                    print(f"  -> [OCR HATASI] {e}")
        
        # --- 2. PDF DOSYALARI ---
        elif filename.endswith('.pdf') and PdfReader:
            try:
                reader = PdfReader(filepath)
                text_content = ""
                for page in reader.pages:
                    extracted = page.extract_text()
                    if extracted: text_content += extracted + "\n"
                    
                    if self.use_ocr and pytesseract and hasattr(page, 'images'):
                        for image_file in page.images:
                            try:
                                image_data = io.BytesIO(image_file.data)
                                ocr_text = pytesseract.image_to_string(Image.open(image_data), lang='eng')
                                text_content += f"\n {ocr_text}\n"
                            except: pass
                
                if text_content:
                    results = check_content_matches(text_content, filepath, filepath, self.patterns)
            except Exception as e:
                print(f"  -> [PDF HATASI] {e}")

        # --- 3. EXCEL DOSYALARI ---
        elif filename.endswith(('.xlsx', '.xls')) and openpyxl:
            try:
                text = ""
                wb = openpyxl.load_workbook(filepath, data_only=True)
                for sheet in wb.sheetnames:
                    for row in wb[sheet].iter_rows(values_only=True):
                        text += " ".join([str(c) for c in row if c]) + "\n"
                results = check_content_matches(text, filepath, filepath, self.patterns)
            except: pass
        
        # --- 4. TEXT / KOD DOSYALARI ---
        elif filename.endswith(('.txt', '.csv', '.py', '.json', '.xml', '.log', '.php', '.js', '.html', '.docx')):
            # print(f"[*] İşleniyor: {filename}") # Log kirliliği olmasın diye kapattım
            
            try:
                if os.path.getsize(filepath) == 0: return results
            except: pass

            content = ""
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
            except UnicodeDecodeError:
                try:
                    with open(filepath, 'r', encoding='cp1254') as f:
                        content = f.read()
                except:
                    with open(filepath, 'rb') as f:
                        content = str(f.read())

            if content:
                results = check_content_matches(content, filepath, filepath, self.patterns)

        # --- KARANTİNA İŞLEMİ ---
        if results and self.quarantine_mode:
            print(f"   [KARANTİNA] {len(results)} tehdit bulundu. Dosya taşınıyor.")
            try:
                self.qm.quarantine_file(filepath)
            except Exception as e:
                print(f"   [KARANTİNA HATASI] {e}")

        return results

    def start_scan_parallel(self):
        all_results = []
        
        # 1. Hız Ayarı: Sadece bu uzantıları tara
        valid_exts = ('.txt', '.csv', '.pdf', '.xlsx', '.xls', '.png', '.jpg', '.jpeg', '.py', '.json', '.xml', '.php', '.js', '.html')
        
        # 2. Hız Ayarı: Bu klasörlere hiç girme (Vakit kaybı)
        skip_dirs = {'Windows', 'Program Files', 'Program Files (x86)', 'AppData', 'node_modules', '.git', '__pycache__', 'venv', 'env'}
        
        print(f"--- Tarama Başlatılıyor: {self.target_dir} ---")
        
        for root, dirs, files in os.walk(self.target_dir):
            # Durdurma isteği geldi mi?
            if self.stop_requested:
                print("--- [İPTAL] Tarama kullanıcı tarafından durduruldu. ---")
                break

            # Gereksiz klasörleri ele (dirs listesini değiştirerek)
            dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith('.')]
            
            for f in files:
                if self.stop_requested: break

                if f.lower().endswith(valid_exts):
                    full_path = os.path.join(root, f)
                    
                    # 3. Hız Ayarı: 50MB üstü dosyaları atla (Takılmayı önler)
                    try:
                        if os.path.getsize(full_path) > 50 * 1024 * 1024:
                            continue
                    except: pass

                    res = self.scan_file(full_path)
                    if res: all_results.extend(res)
        
        return all_results