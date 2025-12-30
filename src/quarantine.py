import os
import json
import shutil
import time
from datetime import datetime
import base64

class QuarantineManager:
    def __init__(self):
        # Karantina klasörü (Proje içinde)
        self.q_dir = os.path.abspath("KARANTINA_BOLGESI")
        
        # Log dosyası (Hangi dosya nereden geldi?)
        self.log_file = os.path.join(self.q_dir, "karantina_kayitlari.json")

        if not os.path.exists(self.q_dir):
            os.makedirs(self.q_dir)

    def _get_logs(self):
        """Log dosyasını okur."""
        if not os.path.exists(self.log_file):
            return {}
        try:
            with open(self.log_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return {}

    def _save_logs(self, data):
        """Log dosyasını kaydeder."""
        with open(self.log_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

    def _obfuscate(self, data):
        """Basit şifreleme (Ters çevir + Base64)"""
        encoded = base64.b64encode(data[::-1])
        return encoded

    def _deobfuscate(self, data):
        """Şifre çözme"""
        decoded = base64.b64decode(data)
        return decoded[::-1]

    def quarantine_file(self, filepath):
        """Dosyayı şifreler, karantinaya taşır ve orijinalini siler."""
        try:
            filename = os.path.basename(filepath)
            # Benzersiz isim (Timestamp ekle)
            timestamp = int(time.time())
            enc_filename = f"{timestamp}_{filename}.enc"
            enc_path = os.path.join(self.q_dir, enc_filename)

            # 1. Dosyayı Oku
            with open(filepath, 'rb') as f:
                content = f.read()

            # 2. Şifrele
            encrypted_content = self._obfuscate(content)

            # 3. Karantinaya Yaz
            with open(enc_path, 'wb') as f:
                f.write(encrypted_content)

            # 4. Loga Kaydet (BURASI ÇOK ÖNEMLİ: Orijinal yolu saklıyoruz)
            logs = self._get_logs()
            logs[enc_filename] = {
                "original_path": os.path.abspath(filepath), # Tam yolu kaydet
                "original_name": filename,
                "quarantine_date": str(datetime.now())
            }
            self._save_logs(logs)

            # 5. Orijinal Dosyayı Sil
            os.remove(filepath)
            print(f" -> [KARANTİNA] Dosya taşındı: {filename}")
            return True

        except Exception as e:
            print(f" -> [KARANTİNA HATASI] {e}")
            return False

    def restore_file(self, enc_filepath):
        """Dosyayı şifreden çıkarıp ESKİ YERİNE koyar."""
        try:
            filename = os.path.basename(enc_filepath)
            logs = self._get_logs()
            
            file_info = logs.get(filename)
            
            if file_info and "original_path" in file_info:
                target_path = file_info["original_path"]
            else:
                # Eğer log silindiyse mecburen dosya adıyla kurtarmaya çalışır (proje klasörüne)
                print(" -> [UYARI] Orijinal konum kaydı bulunamadı, proje dizinine çıkarılıyor.")
                clean_name = filename.split('_', 1)[-1].replace('.enc', '')
                target_path = os.path.abspath(clean_name)

            # Eğer orijinal klasör silinmişse tekrar oluştur
            target_dir = os.path.dirname(target_path)
            if not os.path.exists(target_dir):
                os.makedirs(target_dir)
                print(f" -> [BİLGİ] Silinen klasör tekrar oluşturuldu: {target_dir}")

            # 1. Şifreli Dosyayı Oku
            with open(enc_filepath, 'rb') as f:
                enc_content = f.read()

            # 2. Şifreyi Çöz
            decrypted_content = self._deobfuscate(enc_content)

            # 3. ESKİ YERİNE Yaz
            with open(target_path, 'wb') as f:
                f.write(decrypted_content)

            # 4. Karantinadan Temizle (Artık kurtardık, şifreliye gerek yok)
            try:
                os.remove(enc_filepath)
                if filename in logs:
                    del logs[filename]
                    self._save_logs(logs)
            except: pass

            print(f" -> [KURTARILDI] Dosya eski yerine konuldu: {target_path}")
            
            # Kullanıcıya dosyanın olduğu klasörü aç
            try:
                # Windows dosya gezgininde o dosyayı seçili halde açar
                subprocess.Popen(r'explorer /select,"' + target_path + '"')
            except:
                pass
            
            return True, target_path

        except Exception as e:
            print(f" -> [KURTARMA HATASI] {e}")
            return False, str(e)