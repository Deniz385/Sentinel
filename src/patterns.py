import re

# GELİŞMİŞ HASSAS VERİ DESENLERİ
PATTERNS = {
    # --- KİŞİSEL VERİLER ---
    "TC_KIMLIK": re.compile(r'\b[1-9]\d{10}\b'),
    
    "EMAIL": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
    
    "TELEFON": re.compile(r'\b(?:\+90|0)?5\d{2}[- ]?\d{3}[- ]?\d{2}[- ]?\d{2}\b'),

    # --- FİNANSAL VERİLER ---
    "KREDI_KARTI": re.compile(r'\b(?:\d{4}[- ]?){3}\d{4}\b'),
    
    # TR IBAN (Boşluklu veya boşluksuz yakalar)
    "TR_IBAN": re.compile(r'TR\d{2}\s?(\d{4}\s?){6}'),

    # Kripto Cüzdan (Ethereum / BSC - 0x ile başlayan 40 hane)
    "CRYPTO_ETH": re.compile(r'\b0x[a-fA-F0-9]{40}\b'),

    # --- TEKNİK SIRLAR (YENİ) ---
    # AWS Access Key ID (AKIA ile başlar)
    "AWS_ACCESS_KEY": re.compile(r'(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'),
    
    # Google API Key (AIza ile başlar)
    "GOOGLE_API_KEY": re.compile(r'AIza[0-9A-Za-z\\-_]{35}'),
    
    # Generic "Password =" atamaları (Kod içindeki unutulmuş şifreler)
    # Örn: password = "GizliSifre123"
    "HARDCODED_PASS": re.compile(r'(?i)(password|passwd|pwd|secret|api_key)\s*[:=]\s*["\'](.*?)["\']')
}

def get_patterns():
    return PATTERNS