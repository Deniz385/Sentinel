# 🛡️ Sentinel

**Hassas veri keşif ve sızıntı önleme (DLP) aracı.** Dosya sistemindeki
KVKK / GDPR / PCI-DSS kapsamındaki verileri ve koda sızmış kimlik
bilgilerini bulur, önem derecesine göre sıralar, raporlar ve isterseniz
şifreleyip karantinaya alır.

Çapraz platform (Linux · macOS · Windows) · Python 3.10+ · sıfır zorunlu
ağ erişimi.

```
sentinel scan ~/Belgeler --format html,sarif --fail-on high
```

---

## Neden

Hassas veri genelde bulunması gereken yerde durmaz: bir müşteri listesi
ZIP'in içindeki Excel'e, bir API anahtarı test betiğine, bir kimlik
fotokopisi taranmış PDF'e düşer. Sentinel bu yerlere bakar ve **"ne kadar
kötü?"** sorusunu cevaplar — 500 e-posta adresiyle 1 AWS anahtarını aynı
listede eşit göstermez.

## Özellikler

| | |
|---|---|
| **27 tespit kuralı** | TC Kimlik · IBAN · kredi kartı · telefon · plaka · AWS/Google/GitHub/Slack/Stripe/OpenAI anahtarları · özel anahtar · JWT · veritabanı bağlantı dizesi · kripto cüzdan · sağlık verisi |
| **Algoritmik doğrulama** | TCKN kontrol hanesi · Luhn + kart markası · IBAN mod-97 · JWT başlık çözümü · Base58Check. Yanlış pozitifleri kökten keser |
| **Entropi taraması** | Adlandırılmış deseni olmayan rastgele sırları yakalar |
| **Biçim desteği** | Metin/kod · PDF · Word · Excel · PowerPoint · **ZIP (özyinelemeli)** · görsel (OCR) |
| **5 kademeli önem derecesi** | `info` → `critical`, 0-100 toplu risk skoru |
| **Yanlış pozitif yönetimi** | Allowlist (yol/değer/parmak izi/regex) · satır içi `sentinel:ignore` · baz çizgisi |
| **6 rapor biçimi** | HTML panosu · CSV · JSON · **SARIF** · Markdown · PDF |
| **Şifreli karantina** | AES-256-GCM, doğrulanmış silme, bütünlük denetimi |
| **Gerçek zamanlı izleme** | `sentinel watch` — yeni/değişen dosyaları anında tarar |
| **CI entegrasyonu** | Anlamlı çıkış kodları · `--fail-on` kapısı · git pre-commit kancası |
| **Gizlilik** | Rapor, log ve webhook yüklerinde **açık hassas veri yoktur** — hepsi maskelenir |

---

## Kurulum

```bash
git clone https://github.com/deniz385/Sentinel.git
cd Sentinel

# Çekirdek (CLI + metin/kod taraması)
pip install -e .

# Tüm eklentiler (PDF, Office, OCR, izleme, GUI, raporlar)
pip install -e ".[all]"
```

İsteğe bağlı eklentiler tek tek de kurulabilir:

```bash
pip install -e ".[docs]"     # PDF, Word, Excel, PowerPoint
pip install -e ".[ocr]"      # görsel / taranmış belge analizi
pip install -e ".[monitor]"  # gerçek zamanlı izleme
pip install -e ".[pdf]"      # PDF raporu
pip install -e ".[yara]"     # YARA kural motoru
pip install -e ".[gui]"      # masaüstü arayüzü
```

OCR için Tesseract motorunun ayrıca kurulması gerekir:

```bash
apt install tesseract-ocr tesseract-ocr-tur    # Debian/Ubuntu
brew install tesseract tesseract-lang          # macOS
# Windows: https://github.com/UB-Mannheim/tesseract/wiki
```

Neyin kurulu olduğunu görmek için:

```bash
sentinel doctor
```

---

## Kullanım

### Tarama

```bash
sentinel scan ~/Belgeler                      # varsayılan: HTML + CSV raporu
sentinel scan . --format html,csv,json,sarif  # birden çok biçim
sentinel scan . --min-severity high           # sadece ciddi bulgular
sentinel scan . --only secret                 # sadece sır/anahtar kuralları
sentinel scan . --skip-rules EMAIL,PRIVATE_IP # gürültülü kuralları kapat
sentinel scan . --ocr                         # görselleri de tara
sentinel scan . -j 8                          # 8 paralel işçi
sentinel scan . --verbose                     # her bulguyu ekrana yaz
```

### Kuralları görmek

```bash
sentinel rules                 # tüm kurallar, önem dereceleriyle
sentinel rules --tag secret    # sadece sır avı kuralları
sentinel rules --json          # makine okunur
```

### Gerçek zamanlı izleme

```bash
sentinel watch ~/Indirilenler
```

### Karantina kasası

Riskli dosyaları AES-256-GCM ile şifreleyip izole eder. **Orijinal dosya
yalnızca şifreli kopya geri çözülüp SHA-256'sı eşleştikten sonra silinir.**

```bash
sentinel scan ~/Belgeler --quarantine --min-severity critical
sentinel vault list                      # kasadaki dosyalar
sentinel vault verify                    # bütünlük denetimi
sentinel vault restore <dosya.enc>       # orijinal konumuna geri yükle
sentinel vault purge --all               # kalıcı sil
sentinel vault migrate                   # eski karantina dizinlerini taşı
```

Kasa anahtarı sırayla şu kaynaklardan alınır:

1. `SENTINEL_VAULT_KEY` ortam değişkeni (base64, hex ya da parola),
2. yapılandırmadaki anahtar dosyası,
3. `~/.sentinel/vault.key` — ilk kullanımda `0600` izniyle üretilir.

> **Anahtar kaybolursa karantinadaki dosyalar geri alınamaz.** Üretim
> kullanımında `SENTINEL_VAULT_KEY`'i bir sır yöneticisinde tutun.

---

## CI entegrasyonu

### Çıkış kodları

| Kod | Anlam |
|---|---|
| `0` | Temiz, ya da `--fail-on` eşiğinin altında bulgu |
| `1` | `--fail-on` eşiğinde veya üstünde bulgu var |
| `2` | Çalıştırma hatası (hedef yok, geçersiz ayar) |
| `130` | Kullanıcı iptal etti |

### GitHub Actions + Code Scanning

SARIF çıktısı, bulguları doğrudan pull request'in "Files changed"
görünümüne ve **Security** sekmesine taşır:

```yaml
- run: pip install -e ".[docs]"
- run: sentinel scan . --format sarif --fail-on critical
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: sentinel.sarif
```

### Git pre-commit kancası

Sır içeren bir commit'i daha gönderilmeden engeller:

```bash
sentinel precommit --install     # .git/hooks/pre-commit yazar
sentinel precommit               # elle çalıştır (staged dosyaları tarar)
```

---

## Yapılandırma

```bash
sentinel init     # örnek sentinel.yml oluşturur
```

Ayarlar katmanlıdır; sağdaki soldakini ezer:

```
varsayılan  <  sentinel.yml  <  SENTINEL_* ortam değişkenleri  <  CLI argümanları
```

`sentinel.yml` çalışma dizininden başlayarak üst dizinlerde aranır, yani
alt klasörlerden çalıştırıldığında da bulunur.

```yaml
target: .
min_severity: low

exclude_dirs: [.git, node_modules, venv]
exclude_globs: ["*.min.js", "*.lock"]

entropy_scan: true
archive_enabled: true
ocr: false
workers: 0            # 0 = CPU sayısına göre otomatik

allowlist:
  paths: ["tests/**", "test_data/**"]
  values: []
  rules: [PRIVATE_IP]
  use_defaults: true  # AWS örnek anahtarı, example.com vb.
  inline: true        # `sentinel:ignore` yorumları
```

**Sırları yapılandırma dosyasına yazmayın**; ortam değişkeni kullanın:

| Değişken | Açıklama |
|---|---|
| `SENTINEL_VAULT_KEY` | Karantina kasası anahtarı |
| `SENTINEL_WEBHOOK_URL` | Discord / Slack / Teams bildirim adresi |
| `SENTINEL_FINGERPRINT_SALT` | Parmak izi tuzu (kuruma özel korelasyon) |
| `SENTINEL_WORKERS`, `SENTINEL_OCR`, `SENTINEL_MIN_SEVERITY` | Tarama ayarları |

---

## Yanlış pozitifle başa çıkma

Üç yol var; en dar olanı seçin.

**1. Satır içi** — tek bir satır için:

```python
TEST_KEY = "AKIAIOSFODNN7EXAMPLE"   # sentinel:ignore
TEST_TC = "10000000146"             # sentinel:ignore=TC_KIMLIK
```

**2. Allowlist** — tekrar eden bir yol ya da değer için (`sentinel.yml`).

**3. Baz çizgisi** — mevcut durumu dondurup yalnızca **yeni** sızıntıları
raporlamak için. Eski borcu temizlemeden CI kapısını açmanın yolu:

```bash
sentinel scan . --write-baseline baseline.json   # bir kez
sentinel scan . --baseline baseline.json --fail-on high
```

---

## Masaüstü arayüzü

```bash
pip install -e ".[gui]"
sentinel-gui      # ya da: python gui_app.py
```

Klasör seçimi, canlı ilerleme, durdurulabilir tarama, önem derecesine
göre renkli bulgu listesi, risk dağılımı grafiği, karantina kasası
yönetimi ve tek tuşla rapor kaydı.

---

## Python API

```python
from sentinel import ScanConfig, Scanner

config = ScanConfig(target="veri", min_severity="high", workers=4)
result = Scanner("veri", config=config).scan()

print(result.risk_score, "/100")
for finding in result.findings:
    print(finding.severity, finding.type, finding.file, finding.content_masked)
```

`Finding` nesneleri **asla açık hassas veri taşımaz**: `content_masked`
maskelenmiş değeri, `fingerprint` ise veriyi sızdırmadan korelasyon
kurmaya yarayan HMAC-SHA256 kimliğini verir.

---

## Geliştirme

```bash
pip install -e ".[dev,all]"
pytest                    # 313 test
pytest --cov=sentinel
ruff check .
```

### Mimari

```
sentinel/
  config.py        katmanlı yapılandırma (dosya → ortam → CLI)
  severity.py      önem derecesi + risk skoru
  patterns.py      desen kataloğu (regex + önem + doğrulayıcı bağı)
  validators.py    TCKN · Luhn · IBAN · JWT · Base58Check
  entropy.py       Shannon entropisi, generic sır adayları
  redaction.py     maskeleme + HMAC parmak izi
  allowlist.py     yanlış pozitif bastırma + baz çizgisi
  matcher.py       metin → bulgu (doğrula, bastır, örtüşme çöz, tekilleştir)
  extractors/      plain · pdf · office · archive · image
  engine.py        paralel tarama, akışlı okuma, iptal, ilerleme
  quarantine.py    AES-256-GCM kasa (eski formatı da okur)
  yara_engine.py   rules/*.yar motoru
  notify.py        webhook bildirimleri
  monitor.py       gerçek zamanlı izleme
  reporting/       html · csv · json · sarif · markdown · pdf
  cli.py           scan · watch · vault · rules · precommit · init · doctor
```

Yeni kural eklemek: `sentinel/patterns.py` içindeki kataloğa bir
`PatternDef` ekleyin — önem derecesi, açıklama, varsa doğrulayıcı adı ve
bir `example`. Testler örneğin kendi regex'ine uyduğunu otomatik denetler.

### Eskiye uyumluluk

- `scan_results.csv` sütun düzeni korunur; yeni alanlar sona eklenir.
- `Scanner(target).start_scan_parallel()` ve `get_patterns()` çalışmaya
  devam eder.
- Karantina kasası v3.0'ın base64 formatındaki dosyalarını ve
  `.enc.meta` / `karantina_kayitlari.json` kayıtlarını okur.
- `python main.py --target test_data` eski çağrı biçimi geçerlidir.

---

## Yol haritası

Kapatılan kusurların teşhisi ve sıradaki işler: [ROADMAP.md](ROADMAP.md).

## Uyarı

Sentinel **hassas veri işler**. Ürettiği raporlar maskelenmiş olsa bile
nerede ne bulunduğunu gösterir; rapor dosyalarını da gizli kabul edin.
Karantina özelliği dosyaları **taşır ve orijinallerini siler** — önce
`--min-severity critical` gibi dar bir eşikle ve yedeği olan bir dizinde
deneyin.

Yalnızca **yetkili olduğunuz** sistemlerde kullanın.

## Lisans

MIT — bkz. [LICENSE](LICENSE).
