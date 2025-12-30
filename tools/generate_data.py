# tools/generate_data.py
import random
import os

def generate_valid_tc():
    """Algoritmaya uygun geçerli TC üretir."""
    digits = [random.randint(1, 9)] + [random.randint(0, 9) for _ in range(8)]
    d1 = sum(digits[0:9:2])
    d2 = sum(digits[1:8:2])
    check_10 = ((d1 * 7) - d2) % 10
    check_11 = (sum(digits[:9]) + check_10) % 10
    return "".join(map(str, digits)) + str(check_10) + str(check_11)

def generate_valid_cc():
    """Luhn algoritmasına uygun Visa kart no üretir."""
    digits = [4] + [random.randint(0, 9) for _ in range(14)] # 15 hane
    checksum = 0
    is_second = True # Son haneyi hesaplayacağımız için sondan ikinci zaten 'second' olur
    
    for digit in reversed(digits):
        if is_second:
            digit = digit * 2
            if digit > 9: digit -= 9
        checksum += digit
        is_second = not is_second
    
    check_digit = (10 - (checksum % 10)) % 10
    return "".join(map(str, digits)) + str(check_digit)

def create_large_file(filename="big_test_data.txt", target_size_mb=50):
    """
    Belirtilen boyutta (MB) test dosyası oluşturur.
    """
    print(f"Generating {target_size_mb} MB file: {filename}...")
    
    with open(filename, "w", encoding="utf-8") as f:
        current_size = 0
        target_bytes = target_size_mb * 1024 * 1024
        
        # Rastgele kelime havuzu
        words = ["lorem", "ipsum", "dolor", "sit", "amet", "consectetur", "security", 
                 "data", "leak", "privacy", "project", "analysis", "report", "fake"]
        
        while current_size < target_bytes:
            # Rastgele bir senaryo seç
            choice = random.random()
            
            line = ""
            
            # %5 ihtimalle GEÇERLİ TC
            if choice < 0.05:
                line = f"Müşteri TC: {generate_valid_tc()} onaylandı. "
            
            # %5 ihtimalle GEÇERLİ Kredi Kartı
            elif choice < 0.10:
                line = f"Ödeme alındı: {generate_valid_cc()} başarıyla işlendi. "
            
            # %5 ihtimalle GEÇERSİZ TC (Regex yakalar, Scanner elemeli)
            elif choice < 0.15:
                # 11 haneli ama algoritması bozuk sayı
                fake_tc = str(random.randint(10000000000, 99999999999))
                line = f"Hatalı TC girişi: {fake_tc} "
            
            # Geri kalanı gürültü (Random text)
            else:
                line = " ".join(random.choices(words, k=10)) + ". "
            
            # Satırı yaz ve boyutu güncelle
            line += "\n"
            f.write(line)
            current_size += len(line.encode('utf-8'))
            
            # İlerleme çubuğu gibi her 10MB'da bir bilgi ver
            if current_size % (10 * 1024 * 1024) < 100: 
                print(f"Generated: {current_size / (1024*1024):.2f} MB")

    print(f"DONE! File created: {filename}")

if __name__ == "__main__":
    # Kullanıcıdan boyut isteyelim
    try:
        size = int(input("Kaç MB'lık dosya oluşturulsun? (Örn: 50): "))
    except:
        size = 10
    
    create_large_file("big_test_data.txt", size)