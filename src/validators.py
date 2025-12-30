def validate_tc(value):
    """
    TC Kimlik Numarası Algoritma Kontrolü.
    """
    value = str(value)
    if not value.isdigit() or len(value) != 11 or value[0] == '0':
        return False
    
    digits = [int(d) for d in value]
    
    # 1. Kural: 1,3,5,7,9. hanelerin toplamının 7 katından, 2,4,6,8. hanelerin toplamı çıkarılırsa,
    # sonucun 10'a bölümünden kalan 10. haneyi verir.
    d1 = sum(digits[0:9:2])
    d2 = sum(digits[1:8:2])
    
    check_10 = ((d1 * 7) - d2) % 10
    
    # 2. Kural: İlk 10 hanenin toplamının 10'a bölümünden kalan 11. haneyi verir.
    check_11 = (sum(digits[:10])) % 10
    
    if digits[9] == check_10 and digits[10] == check_11:
        return True
    return False

def validate_credit_card(value):
    """
    Luhn Algoritması ile Kredi Kartı Doğrulama.
    """
    # Boşluk ve tireleri temizle
    clean_value = value.replace(' ', '').replace('-', '')
    
    if not clean_value.isdigit() or len(clean_value) < 13:
        return False
        
    digits = [int(d) for d in clean_value]
    checksum = 0
    is_second = False
    
    # Sondan başa doğru git
    for digit in reversed(digits):
        if is_second:
            digit = digit * 2
            if digit > 9:
                digit -= 9
        checksum += digit
        is_second = not is_second
        
    return checksum % 10 == 0
# Mevcut kodların altına ekle:

def validate_iban(iban):
    """
    TR IBAN Doğrulama Algoritması (ISO 7064 Mod 97-10).
    """
    # Boşlukları temizle ve büyüt
    iban = iban.replace(' ', '').upper()
    
    # Uzunluk kontrolü (TR IBAN 26 hanedir)
    if len(iban) != 26:
        return False
    
    if not iban.startswith("TR"):
        return False

    # Algoritma:
    # 1. İlk 4 karakteri (Ülke kodu ve kontrol basamağı) sona at.
    # Örn: TR12 XXXXX -> XXXXX TR12
    moved_iban = iban[4:] + iban[:4]
    
    # 2. Harfleri sayıya çevir (A=10, B=11 ... Z=35)
    # TR için T=29, R=27
    numeric_iban = ""
    for char in moved_iban:
        if char.isdigit():
            numeric_iban += char
        else:
            numeric_iban += str(ord(char) - 55)
            
    # 3. Sayıyı 97'ye böl, kalan 1 olmalı.
    try:
        return int(numeric_iban) % 97 == 1
    except:
        return False