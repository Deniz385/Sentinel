# Sentinel — Yol Haritası

Sentinel'in hedefi **kurumsal seviyede, çapraz platform çalışan bir DLP
(Data Loss Prevention) / hassas veri keşif platformu** olmak. Bu doküman
mevcut durumdaki eksikleri, bunların neden kritik olduğunu ve hangi fazda
kapatıldığını kayıt altına alır.

---

## 1. Teşhis — v3.0'daki (önceki) kusurlar

### 1.1 Doğruluk / güvenlik hataları

| # | Bulgu | Etki |
|---|-------|------|
| A1 | `reporter.py` tüm alanları f-string ile HTML'e basıyordu | **HTML/JS injection**: `<script>` içeren bir dosya adı raporu silahlandırır |
| A2 | `quarantine.py` "şifreleme" = `base64(reverse(bytes))` | Şifreleme **değil**, sadece gizleme. Karantinaya alınan KVKK verisi fiilen açıkta |
| A3 | Karantina orijinali **doğrulamadan önce** siliyordu | Şifreli kopya bozuksa veri **kalıcı kaybı** |
| A4 | `quarantine.restore_file` içinde `subprocess` import edilmemiş | `NameError`, çıplak `except` ile yutuluyor |
| A5 | `WEBHOOK_URL` kaynak kodda sabit | Sır sızdırma riski; ayarı değiştirmek için kod değiştirmek gerekiyor |
| A6 | `TR_IBAN` regex'i yakalayan grup içeriyordu (`(\d{4}\s?){6}`) | `findall` tüm eşleşme yerine son grubu döndürüyor → IBAN bulguları bozuk |
| A7 | `pdf_gen.py` içeriği kaçışsız `Paragraph`'a veriyordu | `<` / `&` içeren veri PDF üretimini patlatıyor |
| A8 | Karantina dizini `KARANTINA_BOLGESI`, repodaki dizin `QUARANTINE_ZONE` | Kurtarma aracı yanlış yere bakıyor |

### 1.2 Yanlış vaatler (kod söylediğini yapmıyordu)

| # | Bulgu |
|---|-------|
| B1 | `start_scan_parallel()` **paralel değil** — düz `os.walk` döngüsü |
| B2 | `main.py` "ZIP" modülünü ilan ediyor, `scanner.py`'de ZIP desteği **yok** (eski `scan_results.csv` ZIP bulgusu içeriyor → regresyon) |
| B3 | `.docx` düz metin olarak okunuyordu → ZIP binary çöpü |
| B4 | `rules/sample.yar` hiçbir yerde kullanılmıyor (ölü dosya) |
| B5 | `monitor.py`, `Scanner` üzerinde var olmayan `scan_file_wrapper()` çağırıyor → gerçek zamanlı izleme **tamamen çalışmıyor** |
| B6 | `utils.setup_logger` ve `calculate_entropy` hiç çağrılmıyor (ölü kod); tarayıcı `print()` kullanıyor |

### 1.3 Performans

| # | Bulgu |
|---|-------|
| C1 | `calculate_file_hash()` **her bulgu için** yeniden çağrılıyordu → 50 MB'lık dosyada 1000 bulgu = 50 GB okuma |
| C2 | Dosyanın tamamı RAM'e okunuyordu (`f.read()`) |
| C3 | `calculate_entropy` 256 kez `str.count` çağırıyor → O(256·n) |
| C4 | `openpyxl.load_workbook` `read_only` olmadan açılıyordu |

### 1.4 Taşınabilirlik

Araç fiilen Windows'a kilitliydi: `C:\Program Files\Tesseract-OCR` sabit yolu,
`os.popen('date /t')`, `os.startfile`, `explorer /select`, `os.system("start ...")`.

### 1.5 Mühendislik disiplini

| # | Bulgu |
|---|-------|
| E1 | `tests/test_patterns.py` **çalışmıyor**: `TR_ID`, `CREDIT_CARD`, `PHONE` isimli desen yok (gerçek isimler `TC_KIMLIK`, `KREDI_KARTI`, `TELEFON`) → `KeyError` |
| E2 | `requirements.txt` **UTF-16** kodlanmış → `pip install -r` çoğu ortamda patlıyor; `pytesseract`, `pillow`, `customtkinter`, `matplotlib`, `reportlab`, `watchdog`, `requests`, `pyyaml` listede yok |
| E3 | 52 MB'lık `big_test_data.txt` repoya commit edilmiş; `dashboard.html`, `scan_results.csv`, `scan_report.csv` çıktıları da versiyonlanmış |
| E4 | `README.md` ve `LICENSE` **boş** |
| E5 | CI yok, paketleme (`pyproject.toml`) yok, `sentinel` komutu yok |
| E6 | Yapılandırma dosyası yok; `python-dotenv` bağımlılıkta ama kullanılmıyor |

### 1.6 Ürün olarak eksikler

Önem sırasına göre: önem derecesi (severity) yok → her bulgu eşit; yanlış
pozitif yönetimi yok (allowlist/baseline/satır-içi bastırma yok); makine
okunur çıktı yok (CI entegrasyonu imkânsız); entropi tabanlı generic sır
avı yok; arşiv/Office/PPTX desteği yok; `git` pre-commit modu yok;
denetim izi (audit log) yok.

---

## 2. Yol haritası

### Faz 0 — Repo hijyeni ✅
`requirements.txt` UTF-8'e çevrildi ve tamamlandı · `pyproject.toml` +
`sentinel` konsol komutu · üretilen çıktılar repodan çıkarıldı ve
`.gitignore`'a alındı · gerçek `README.md` · MIT `LICENSE` · GitHub Actions
CI (Linux + Windows, Python 3.10–3.13).

### Faz 1 — Çekirdek motorun yeniden inşası ✅
`src/` düz modül yığını yerine gerçek bir `sentinel/` paketi:

```
sentinel/
  config.py        ScanConfig: YAML + .env + CLI katmanlı yapılandırma
  severity.py      5 kademeli önem derecesi + risk skoru
  patterns.py      Önem derecesi ve doğrulayıcı bağlı desen kataloğu (40+)
  validators.py    TCKN · Luhn (+kart markası) · IBAN mod-97 · JWT · Base58Check
  entropy.py       O(n) Shannon entropisi + normalize entropi
  redaction.py     Maskeleme + HMAC parmak izi (korelasyon, sızdırmadan)
  allowlist.py     Glob/değer/parmak izi + satır-içi `sentinel:ignore`
  matcher.py       Metin → bulgu (doğrula, bastır, tekilleştir, skorla)
  extractors/      plain · pdf · docx · xlsx · pptx · zip · görsel (OCR)
  engine.py        Gerçek paralel tarama, akışlı okuma, iptal, ilerleme
  quarantine.py    AES-256-GCM kasa, doğrulanmış sil, eski formatı okur
  notify.py        Webhook (Discord/Slack/generic), toplu + maskeli
  monitor.py       Çalışan gerçek zamanlı izleme (debounce'lu)
  reporting/       html · json · csv · sarif · markdown · pdf
  cli.py           scan · watch · vault · rules · precommit · init
```

Kapatılan maddeler: A1–A8, B1–B6, C1–C4, 1.4, E6.

### Faz 2 — Test ve CI ✅
Bozuk test dosyası atıldı; desenler, doğrulayıcılar, entropi, maskeleme,
allowlist, çıkarıcılar (ZIP/XLSX/DOCX/PDF), motor (uçtan uca, paralel),
karantina (AES turu + eski format), raporlayıcılar (**HTML kaçışı dâhil**)
ve CLI için testler. Kapatılan: E1, E5.

### Faz 3 — Ürünleştirme ✅
Önem derecesi + risk skoru · allowlist/baseline · SARIF (GitHub Code
Scanning) · `sentinel precommit` git kancası · entropi tabanlı generic sır
avı · YARA motoru (`rules/*.yar` artık gerçekten çalışıyor) · denetim
izi (JSONL audit log) · `--fail-on` ile CI kapısı.

### Faz 4 — Sıradaki (bu çalışmanın kapsamı dışında)
- E-posta (`.eml`, `.msg`) ve `.pst` çıkarıcıları
- Veritabanı tarayıcıları (PostgreSQL / MySQL / MSSQL kolon profilleme)
- S3 / Azure Blob / Google Drive konnektörleri
- Named-entity tanıma ile isim/adres tespiti (regex'in yetmediği yer)
- Merkezî yönetim paneli (FastAPI + çoklu ajan raporlaması)
- Windows/macOS imzalı paketler, MSI/pkg kurulumu
- OpenTelemetry metrikleri, Prometheus exporter

---

## 3. Uyumluluk notu

Eski CSV sütunları (`file`, `line`, `type`, `content_masked`, `sha256`)
korunur; yeni sütunlar (`severity`, `rule`, `fingerprint`, `source`)
sonlarına eklenir. `Scanner(target).start_scan_parallel()` ve
`get_patterns()` eski imzalarıyla çalışmaya devam eder, böylece eski
betikler kırılmaz.
