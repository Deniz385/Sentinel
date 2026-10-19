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

### Faz 4 — Ölçümden çıkan geliştirmeler ✅

v4.0 yeşile döndükten sonra "daha ne yapılabilir?" sorusunu tahminle
değil **ölçümle** yanıtladım. Üç ölçüm, bu fazın gerekçesidir:

| Ölçüm | Sonuç |
|---|---|
| Modül başına test kapsamı | `notify.py` **%0** (gece 3'te birini uyandıracak webhook hiç çalıştırılmamış), `monitor.py` %27, `extractors/image.py` %36, `extractors/pdf.py` %54; toplam %81 |
| Çapraz dosya tekrarı | Aynı 2 sırrı taşıyan 5 dosya → **10 bulgu, 2 tekil sır** |
| Profil (40.000 satır) | **1.000.000 `re.search` çağrısı** (satır başına ~25 desen); `_candidates` 1,0 sn + `re.search` 0,93 sn / toplam 3,4 sn |

#### 4.1 Çapraz dosya korelasyonu ✅

**Sorun.** "207 bulgu" analiste 207 iş kalemi olduğunu söyler. Oysa aynı
AWS anahtarının 40 kopyası **tek bir iptalle** kapanır. Bulgu sayısı iş
yükünü değil kopyalama alışkanlığını ölçüyordu.

**Çözüm.** `sentinel/correlation.py`: bulgular `(kural, parmak izi)`
üzerinden tekil sırlara indirgenir. Parmak izi HMAC-SHA256 olduğu için
**değer hiçbir yerde açılmadan** kopyalar eşleştirilebilir. Raporların
hepsi (CLI özeti, HTML panosu, Markdown, JSON, PDF) artık iki sayıyı
birlikte verir: *bulgu* ve *tekil sır*. Birden fazla dosyaya yayılmış
sırlar ayrı bir bölümde, en yaygın önce.

Kenar durumları test altında: YARA bulguları (tek değere değil dosyanın
tamamına uyarlar) **asla** birleştirilmez; bir değer farklı dosyalarda
farklı derece aldıysa grup en kötü durumu gösterir; konum listesi
kırpılır ama dosya sayısı tam kalır. Ayrı bir test, grup çıktısının açık
hassas değer taşımadığını doğrular.

#### 4.2 Artımlı tarama ✅

**Sorun.** 500 GB'lık bir paylaşımı her gece baştan taramak, o
paylaşımın %99'u değişmemişken, harcanan sürenin neredeyse tamamının
israf olması demek.

**Çözüm.** `sentinel/cache.py`: `(yol → mtime_ns, boyut, bulgular)`
kaydı. `sentinel scan --incremental`.

| 400 dosya · 4,3 MB | Süre |
|---|---|
| Tam tarama | 0,87 sn |
| Tamamı önbellekten | **0,03 sn** (≈29×) |
| 1 dosya değişmiş | 0,04 sn (399 önbellekten) |

Bir güvenlik aracında önbellek, yanlış kurgulandığında **sızıntıyı
görünmez yapan** bir mekanizmadır. Bu yüzden dört kural koda ve testlere
gömülü:

1. **Kural kataloğu, yapılandırma ya da sürüm değişirse önbellek tamamen
   düşer.** Tek bir bayat kayıt, yeni bir kuralın bulacağı sırrı gizler.
2. **Geçici hatalar önbelleğe alınmaz.** Kilitli bir dosya sonsuza kadar
   görünmez olmamalı.
3. **Karantina açıkken önbellek hiç kullanılmaz.** Veri *silen* bir
   karar bayat kanıta dayanamaz; CLI bunu sessizce yapmaz, uyarır.
4. **Varsayılan kapalı.** Araç, sorulmadan "bu dosya değişmemiş"
   varsayımına dayanmaz.

Bilinen ödün, gizlenmek yerine teste çivilenmiştir
(`test_mtime_rollback_is_a_known_limitation`): tazelik ölçütü
`(mtime, boyut)` bir *sezgidir*, kanıt değil. mtime'ı geri alıp boyutu
koruyan bir değişiklik önbelleği atlatır. Adli kesinlik gerektiğinde
artımlı tarama kapalı kalmalı.

#### 4.3 Hâlâ açık olanlar (öncelik sırasıyla)

1. **Ham hız.** Tek iş parçacığında 2–3 MB/sn, 500 GB'lık bir paylaşımda
   günler demek. Seçenekler: birleşik tek regex (3–5×), hyperscan
   (10–100×), çekirdeğin Rust'a taşınması (20–50×). Hangisine
   girişmeden önce prototipleyip ölçmek gerekir — ön süzgeçte bir
   "iki kademeli birleşik regex" denemesi ölçümde **hiç kazanç
   vermediği için geri alınmıştı**; aynı hatayı tekrarlamamak lazım.
2. **Yapısal veri / kolon farkındalığı.** Luhn'dan geçen sipariş
   numarası sorununun ilkeli çözümü satır değil **kolon** görmekten
   geçiyor: CSV başlığı `siparis_no` ise kart kuralı o kolonda
   çalışmamalı.
3. **Ölçülen test boşlukları.** `notify.py` %0 kapsam kabul edilemez:
   webhook, bulgu *olduğunda* susarsa kimse fark etmez.
4. **Karantina anahtar yönetimi.** Kendi demomda, geçici anahtarla
   karantinaya aldığım bir dosyayı kalıcı olarak kaybettim — belgelenmiş
   riskin canlı gösterimi. Çoklu alıcı, anahtar emaneti (escrow) ve
   rotasyon gerekli.
5. **Akışlı çıktı.** Tüm bulgular bellekte tutuluyor; milyonlarca
   bulguda rapor yazımı değil taramanın kendisi düşer.
6. **Düzeltme (remediation) iş akışı.** Bulmak işin yarısı; sahip atama,
   durum takibi, yeniden tarama ile kapatma eksik.
7. **Gözden geçirilecek karar:** entropi taramasının varsayılan açık
   olması. Kendi kaynağımızda 5 yanlış pozitif üretti (düzeltildi), ama
   her kaynak ağacında benzer sınıflar var.

### Faz 5 — Uzun vade (bu çalışmanın kapsamı dışında)
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
