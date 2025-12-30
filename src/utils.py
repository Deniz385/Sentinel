# src/utils.py
import math
import requests
import logging
import os
import hashlib

def setup_logger(name='SensitiveDataScanner', log_file='logs/scanner.log'):
    """
    Loglama yapılandırmasını kurar.
    Hem dosyaya hem de konsola log basar.
    """
    # Logs klasörü yoksa oluştur
    if not os.path.exists('logs'):
        os.makedirs('logs')

    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    # Format: Zaman - Seviye - Mesaj
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    # Dosyaya yazma (File Handler)
    # encoding='utf-8' Türkçe karakter sorunu olmaması için önemli
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setFormatter(formatter)

    # Ekrana yazma (Stream Handler)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)

    # Logger'a handler'ları sadece bir kez ekle (Çift logu önlemek için)
    if not logger.handlers:
        logger.addHandler(file_handler)
        logger.addHandler(stream_handler)
    
    return logger

def mask_data(data):
    """
    Hassas veriyi maskeler (PII Protection).
    Örnek: 12345678901 -> 12*******01
    Yönerge gereği loglarda açık veri bulunmamalıdır.
    """
    if not data:
        return ""
        
    # Eğer veri çok kısaysa (örn 4 hane), tamamını yıldızla
    if len(data) <= 4:
        return "*" * len(data)
    
    # İlk 2 ve son 2 karakteri göster, arasını yıldızla
    return f"{data[:2]}{'*' * (len(data) - 4)}{data[-2:]}"

def calculate_file_hash(filepath):
    """
    Dosyanın SHA256 dijital parmak izini (Hash) hesaplar.
    
    Amaç: Adli Bilişim (Digital Forensics) standartlarına göre,
    bulunan delilin (dosyanın) bütünlüğünün bozulmadığını ve 
    benzersiz kimliğini kanıtlamaktır.
    """
    sha256_hash = hashlib.sha256()
    try:
        # Dosyayı binary modda (rb) aç
        with open(filepath, "rb") as f:
            # Büyük dosyaları (örn. 1GB+) belleği şişirmeden
            # 4KB'lık bloklar halinde oku.
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        # Dosya kilitliyse veya erişim hatası varsa
        return "HASH_HESAPLANAMADI"
    
    
def calculate_entropy(text):
    """Metnin Shannon Entropisini hesaplar. (Rastgelelik ölçüsü)"""
    if not text:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(text.count(chr(x))) / len(text)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

# --- YENİ ÖZELLİK: WEBHOOK BİLDİRİMİ ---
def send_webhook_alert(message, webhook_url):
    """Discord veya Slack'e bildirim atar."""
    if not webhook_url:
        return
    data = {"content": f"🚨 **DLP ALARMI:** {message}"}
    try:
        requests.post(webhook_url, json=data)
    except Exception as e:
        print(f"Webhook hatası: {e}")