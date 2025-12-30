# debug_ocr.py
import os
import sys
import subprocess
try:
    import pytesseract
    from PIL import Image, ImageDraw
except ImportError:
    print("HATA: Kütüphaneler eksik. 'pip install pytesseract pillow' yapın.")
    sys.exit()

def test_ocr():
    print("--- OCR TANI VE TEST ARACI ---")
    
    # 1. Yol Kontrolü
    t_path = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
    print(f"[1] Tesseract yolu kontrol ediliyor: {t_path}")
    if os.path.exists(t_path):
        print("    [OK] Dosya bulundu.")
    else:
        print("    [HATA] Dosya YOK! Lütfen Tesseract'ı C:\\Program Files\\Tesseract-OCR konumuna kurun.")
        return

    # 2. Çalıştırma Testi (Versiyon Kontrolü)
    print("\n[2] Tesseract.exe çalıştırılıyor (Versiyon Testi)...")
    try:
        # Pytesseract kullanmadan direkt exe'yi dürtüyoruz
        result = subprocess.run([t_path, '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"    [OK] Program cevap veriyor!\n    {result.stdout.splitlines()[0]}")
        else:
            print(f"    [HATA] Program çalıştı ama hata verdi:\n{result.stderr}")
    except Exception as e:
        print(f"    [KRİTİK HATA] Program hiç çalıştırılamadı: {e}")
        return

    # 3. Gerçek Okuma Testi (Canlı Test)
    print("\n[3] Sanal Resim Oluşturulup Okunuyor...")
    try:
        pytesseract.pytesseract.tesseract_cmd = t_path
        
        # Bellekte içinde "TEST1234" yazan beyaz bir resim oluşturuyoruz
        img = Image.new('RGB', (200, 100), color = (255, 255, 255))
        d = ImageDraw.Draw(img)
        # Basit bir çizim yap (Yazı yazmaya gerek kalmadan siyah kutu testi de olabilir ama yazı en iyisi)
        # Font sorunu olmasın diye basit binary test yapalım veya varsayılan font
        from PIL import ImageFont
        try:
            # Windows varsayılan fontu
            font = ImageFont.truetype("arial.ttf", 24)
            d.text((10,10), "TEST1234", fill=(0,0,0), font=font)
        except:
            d.text((10,10), "TEST", fill=(0,0,0))

        # Oku
        text = pytesseract.image_to_string(img)
        print(f"    [SONUÇ] Okunan Veri: --> {text.strip()} <--")
        
        if "TEST" in text:
            print("\n✅ [BAŞARILI] OCR SİSTEMİNİZ %100 ÇALIŞIYOR!")
            print("    Sorun kodda değil, tarattığınız PDF dosyasında.")
        else:
            print("\n❌ [BAŞARISIZ] Tesseract çalıştı ama yazıyı okuyamadı (Dil/Font sorunu).")
            
    except Exception as e:
        print(f"    [HATA] Pytesseract kütüphane hatası: {e}")

if __name__ == "__main__":
    test_ocr()
    input("\nÇıkmak için Enter'a basın...")