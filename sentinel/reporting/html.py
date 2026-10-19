"""HTML panosu (dashboard).

**Düzeltilen güvenlik açığı:** v3.0'ın `reporter.py`'si dosya yollarını ve
bulgu içeriğini f-string ile doğrudan HTML'e basıyordu. `<script>` içeren
bir dosya adı raporu silahlandırabiliyordu (HTML/JS injection) — hem de
raporu açan kişi tam olarak güvenlik analistiydi. Burada şablon Jinja2
ile ``autoescape=True`` olarak işlenir; kaçış yapısal olarak garanti
altındadır, programcı disiplinine bırakılmaz.

Rapor tek dosyadır: dış CSS/JS/font yok. Çevrimdışı bir olay müdahale
makinesinde de, e-posta ekinde de aynı görünür.
"""

from __future__ import annotations

import os
from datetime import datetime

from sentinel.severity import Severity

__all__ = ["write", "render", "generate_html_report"]

#: Tabloya basılacak en fazla satır — 200 bin satırlık HTML tarayıcıyı kilitler.
MAX_TABLE_ROWS = 2000

#: Tür grafiğinde gösterilecek en fazla kategori; kalanı "Diğer"e katlanır.
MAX_TYPE_BARS = 8


def _severity_rows(result):
    """Önem derecesi dağılımı (yüksekten düşüğe, sıfır olanlar atılır)."""
    counts = result.counts_by_severity()
    total = sum(counts.values()) or 1
    rows = []
    for severity in sorted(Severity, key=lambda s: -s.rank):
        count = counts.get(severity.value, 0)
        if not count:
            continue
        rows.append(
            {
                "key": severity.value,
                "label": severity.label_tr,
                "icon": severity.icon,
                "count": count,
                "percent": round(100 * count / total, 1),
            }
        )
    return rows


def _type_rows(result):
    """Tür dağılımı: en çok görülen ilk sekiz, kalanı 'Diğer'.

    Dokuzuncu kategori için yeni bir renk üretmek yerine katlama yapılır;
    tek seri olduğu için tüm çubuklar aynı rengi kullanır.
    """
    counts = result.counts_by_type()
    items = list(counts.items())
    head, tail = items[:MAX_TYPE_BARS], items[MAX_TYPE_BARS:]
    if tail:
        head.append(("Diğer", sum(count for _, count in tail)))
    maximum = max((count for _, count in head), default=1) or 1
    return [
        {
            "label": name,
            "count": count,
            "percent": round(100 * count / maximum, 2),
        }
        for name, count in head
    ]


def _context(result, title: str) -> dict:
    findings = result.findings
    truncated = max(0, len(findings) - MAX_TABLE_ROWS)
    counts = result.counts_by_severity()

    return {
        "title": title,
        "generated_at": datetime.now().strftime("%d.%m.%Y %H:%M:%S"),
        "summary": result.summary(),
        "risk_score": result.risk_score,
        "total": len(findings),
        "critical": counts.get("critical", 0),
        "high": counts.get("high", 0),
        "files_scanned": result.files_scanned,
        "files_affected": len({f.source for f in findings}),
        "duration": f"{result.duration:.2f}",
        "target": result.target,
        "cancelled": result.cancelled,
        "errors": result.errors[:50],
        "error_count": len(result.errors),
        "severity_rows": _severity_rows(result),
        "type_rows": _type_rows(result),
        "findings": [
            {
                "file": finding.file,
                "line": finding.line,
                "type": finding.type,
                "title": finding.title or finding.type,
                "severity": finding.severity,
                "severity_label": finding.severity_enum.label_tr,
                "severity_icon": finding.severity_enum.icon,
                "masked": finding.content_masked,
                "snippet": finding.snippet,
                "validated": finding.validated,
                "fingerprint": finding.fingerprint,
                "sha256": finding.sha256,
            }
            for finding in findings[:MAX_TABLE_ROWS]
        ],
        "truncated": truncated,
        "severity_order": [s.value for s in sorted(Severity, key=lambda s: -s.rank)],
        "types": sorted({f.type for f in findings}),
    }


def render(result, title: str = "Sentinel — Hassas Veri Keşif Raporu") -> str:
    """Raporu HTML dizgesi olarak üretir."""
    try:
        from jinja2 import Environment
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "HTML raporu için Jinja2 gerekli: pip install jinja2"
        ) from exc

    # autoescape=True: enjeksiyon sınıfını yapısal olarak kapatır.
    environment = Environment(autoescape=True, trim_blocks=True, lstrip_blocks=True)
    template = environment.from_string(_TEMPLATE)
    return template.render(**_context(result, title))


def write(result, output_path: str, title: str = "Sentinel — Hassas Veri Keşif Raporu") -> str:
    directory = os.path.dirname(os.path.abspath(output_path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(render(result, title))
    return output_path


def generate_html_report(results, output_file: str = "dashboard.html"):
    """Eski API uyumluluğu: sözlük listesi kabul eder.

    v3.0'daki ``generate_html_report(results, path)`` çağrıları kırılmasın
    diye korunmuştur.
    """
    from sentinel.engine import ScanResult
    from sentinel.findings import Finding

    if hasattr(results, "findings"):
        return write(results, output_file)

    findings = [
        item if isinstance(item, Finding) else Finding.from_dict(item)
        for item in (results or [])
    ]
    result = ScanResult(findings=findings, files_scanned=len({f.source for f in findings}))
    return write(result, output_file)


# ---------------------------------------------------------------------------
# Şablon
# ---------------------------------------------------------------------------
# Renk rolleri `:root` üzerinde token olarak tanımlanır; koyu değerler hem
# `prefers-color-scheme` hem `data-theme` kapsamında verilir, böylece hem
# işletim sistemi ayarı hem de sayfadaki tema düğmesi çalışır.
#
# Önem derecesi renkleri **durum (status) paleti**dir ve asla kategorik
# seri rengi olarak kullanılmaz; her zaman ikon + etiketle birlikte
# gider, çünkü renk tek başına anlam taşımamalıdır.
_TEMPLATE = """\
<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }}</title>
<style>
:root {
  color-scheme: light;
  --surface-0: #f4f4f2;
  --surface-1: #fcfcfb;
  --surface-2: #f0efec;
  --border: #e2e1dc;
  --text-primary: #0b0b0b;
  --text-secondary: #52514e;
  --text-muted: #7c7b76;
  --series-1: #2a78d6;
  --sev-critical: #d03b3b;
  --sev-high: #ec835a;
  --sev-medium: #fab219;
  --sev-low: #0ca30c;
  --sev-info: #7c7b76;
  --shadow: 0 1px 2px rgba(11,11,11,.06), 0 4px 12px rgba(11,11,11,.04);
}
@media (prefers-color-scheme: dark) {
  :root:where(:not([data-theme="light"])) {
    color-scheme: dark;
    --surface-0: #121211;
    --surface-1: #1a1a19;
    --surface-2: #242423;
    --border: #35352f;
    --text-primary: #f0efec;
    --text-secondary: #c3c2b7;
    --text-muted: #8f8e85;
    --series-1: #3987e5;
    --shadow: 0 1px 2px rgba(0,0,0,.4), 0 4px 12px rgba(0,0,0,.3);
  }
}
:root[data-theme="dark"] {
  color-scheme: dark;
  --surface-0: #121211;
  --surface-1: #1a1a19;
  --surface-2: #242423;
  --border: #35352f;
  --text-primary: #f0efec;
  --text-secondary: #c3c2b7;
  --text-muted: #8f8e85;
  --series-1: #3987e5;
  --shadow: 0 1px 2px rgba(0,0,0,.4), 0 4px 12px rgba(0,0,0,.3);
}

* { box-sizing: border-box; }
body {
  margin: 0;
  padding: 24px 16px 64px;
  background: var(--surface-0);
  color: var(--text-primary);
  font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
        "Helvetica Neue", Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
}
.wrap { max-width: 1180px; margin: 0 auto; }

header.page { display: flex; flex-wrap: wrap; gap: 16px; align-items: flex-start;
  justify-content: space-between; margin-bottom: 28px; }
h1 { font-size: 22px; font-weight: 650; margin: 0 0 6px; letter-spacing: -.01em; }
.meta { color: var(--text-secondary); font-size: 13px; margin: 0; }
.meta code { background: var(--surface-2); padding: 1px 5px; border-radius: 4px;
  font-size: 12px; word-break: break-all; }

button.theme {
  background: var(--surface-1); color: var(--text-secondary);
  border: 1px solid var(--border); border-radius: 8px;
  padding: 7px 12px; font: inherit; font-size: 13px; cursor: pointer;
}
button.theme:hover { color: var(--text-primary); }

/* --- Durum tileları: sayı grafiğin kendisidir --- */
.tiles { display: grid; gap: 12px; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
  margin-bottom: 24px; }
.tile { background: var(--surface-1); border: 1px solid var(--border);
  border-radius: 12px; padding: 16px 18px; box-shadow: var(--shadow); }
.tile h3 { margin: 0 0 8px; font-size: 12px; font-weight: 550; letter-spacing: .02em;
  text-transform: uppercase; color: var(--text-muted); }
.tile .value { font-size: 30px; font-weight: 600; line-height: 1.1;
  letter-spacing: -.02em; }
.tile .unit { font-size: 14px; color: var(--text-muted); font-weight: 450; }
.tile.risk .value { color: var(--sev-critical); }
.tile.ok .value { color: var(--sev-low); }

/* --- Filtre satırı: kapsadığı her şeyin üstünde, tek sıra --- */
.filters { display: flex; flex-wrap: wrap; gap: 10px; align-items: center;
  background: var(--surface-1); border: 1px solid var(--border);
  border-radius: 12px; padding: 12px 14px; margin-bottom: 20px; }
.filters input, .filters select {
  background: var(--surface-2); color: var(--text-primary);
  border: 1px solid var(--border); border-radius: 8px;
  padding: 8px 10px; font: inherit; font-size: 13px; min-height: 36px;
}
.filters input { flex: 1 1 240px; }
.filters .count { margin-left: auto; color: var(--text-secondary); font-size: 13px; }

.panels { display: grid; gap: 16px; grid-template-columns: repeat(auto-fit, minmax(330px, 1fr));
  margin-bottom: 24px; }
.panel { background: var(--surface-1); border: 1px solid var(--border);
  border-radius: 12px; padding: 18px; box-shadow: var(--shadow); }
.panel h2 { font-size: 14px; font-weight: 600; margin: 0 0 4px; }
.panel p.hint { margin: 0 0 16px; font-size: 12px; color: var(--text-muted); }

/* --- Önem derecesi: yığılmış tek çubuk, aralarda 2px yüzey boşluğu --- */
.stack { display: flex; gap: 2px; height: 10px; margin-bottom: 14px; }
.stack div { border-radius: 2px; min-width: 3px; }
.stack div:first-child { border-radius: 4px 2px 2px 4px; }
.stack div:last-child { border-radius: 2px 4px 4px 2px; }
.legend { display: flex; flex-direction: column; gap: 9px; }
.legend-row { display: flex; align-items: center; gap: 9px; font-size: 13px; }
.legend-row .swatch { width: 10px; height: 10px; border-radius: 3px; flex: none; }
.legend-row .ico { width: 14px; text-align: center; color: var(--text-secondary);
  font-size: 11px; flex: none; }
.legend-row .name { color: var(--text-secondary); }
.legend-row .n { margin-left: auto; font-variant-numeric: tabular-nums;
  color: var(--text-primary); font-weight: 550; }
.legend-row .pct { color: var(--text-muted); font-size: 12px;
  font-variant-numeric: tabular-nums; width: 46px; text-align: right; }

/* --- Tür dağılımı: tek seri, tek renk; değer çubuğun ucunda --- */
.bars { display: flex; flex-direction: column; gap: 11px; }
.bar-row { display: grid; grid-template-columns: 1fr; gap: 4px; }
.bar-head { display: flex; justify-content: space-between; align-items: baseline;
  gap: 10px; font-size: 12px; }
.bar-head .name { color: var(--text-secondary); overflow: hidden;
  text-overflow: ellipsis; white-space: nowrap; }
.bar-head .n { color: var(--text-primary); font-weight: 550;
  font-variant-numeric: tabular-nums; flex: none; }
.bar-track { height: 8px; background: var(--surface-2); border-radius: 4px; }
.bar-fill { height: 100%; background: var(--series-1); border-radius: 4px;
  min-width: 3px; }

.sev { display: inline-flex; align-items: center; gap: 6px; font-size: 12px;
  font-weight: 550; white-space: nowrap; }
.sev .dot { width: 8px; height: 8px; border-radius: 3px; flex: none; }
.sev-critical .dot { background: var(--sev-critical); }
.sev-high .dot { background: var(--sev-high); }
.sev-medium .dot { background: var(--sev-medium); }
.sev-low .dot { background: var(--sev-low); }
.sev-info .dot { background: var(--sev-info); }

/* --- Tablo: her değerin okunabildiği asıl görünüm --- */
.table-wrap { background: var(--surface-1); border: 1px solid var(--border);
  border-radius: 12px; overflow: hidden; box-shadow: var(--shadow); }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
thead th { position: sticky; top: 0; background: var(--surface-2);
  color: var(--text-secondary); text-align: left; font-weight: 600;
  font-size: 11px; letter-spacing: .03em; text-transform: uppercase;
  padding: 11px 14px; border-bottom: 1px solid var(--border); }
tbody td { padding: 11px 14px; border-bottom: 1px solid var(--border);
  vertical-align: top; }
tbody tr:last-child td { border-bottom: 0; }
tbody tr:hover { background: var(--surface-2); }
td.path { max-width: 320px; word-break: break-all; color: var(--text-secondary); }
td.path strong { color: var(--text-primary); font-weight: 550; }
td.num { font-variant-numeric: tabular-nums; color: var(--text-muted);
  text-align: right; }
code.masked { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px; background: var(--surface-2); padding: 2px 6px;
  border-radius: 4px; word-break: break-all; }
.snippet { display: block; margin-top: 5px; font-size: 11px;
  color: var(--text-muted); font-family: ui-monospace, Menlo, Consolas, monospace;
  word-break: break-all; }
.tag { display: inline-block; font-size: 10px; padding: 1px 6px; border-radius: 4px;
  border: 1px solid var(--border); color: var(--text-muted); margin-left: 6px; }

.empty { padding: 48px 20px; text-align: center; color: var(--text-secondary); }
.empty .big { font-size: 20px; color: var(--sev-low); font-weight: 600;
  margin-bottom: 6px; }
.note { background: var(--surface-1); border: 1px solid var(--border);
  border-left: 3px solid var(--sev-medium); border-radius: 8px;
  padding: 12px 14px; margin-bottom: 20px; font-size: 13px;
  color: var(--text-secondary); }
footer { margin-top: 28px; text-align: center; color: var(--text-muted);
  font-size: 12px; }
details.errors { margin-top: 20px; font-size: 13px; color: var(--text-secondary); }
details.errors summary { cursor: pointer; }
details.errors li { word-break: break-all; }

@media print {
  body { background: #fff; padding: 0; }
  .filters, button.theme { display: none; }
  .panel, .tile, .table-wrap { box-shadow: none; }
}
</style>
</head>
<body>
<div class="wrap">

<header class="page">
  <div>
    <h1>{{ title }}</h1>
    <p class="meta">
      {{ generated_at }} · hedef <code>{{ target }}</code> ·
      {{ duration }} sn · {{ files_scanned }} dosya tarandı
    </p>
  </div>
  <button class="theme" type="button" id="themeToggle"
          aria-label="Açık/koyu temayı değiştir">◐ Tema</button>
</header>

{% if cancelled %}
<div class="note">Bu tarama tamamlanmadan durduruldu; sonuçlar kısmi olabilir.</div>
{% endif %}

<section class="tiles" aria-label="Özet">
  <div class="tile risk">
    <h3>Risk Skoru</h3>
    <div class="value">{{ risk_score }}<span class="unit"> / 100</span></div>
  </div>
  <div class="tile{% if total == 0 %} ok{% endif %}">
    <h3>Toplam Bulgu</h3>
    <div class="value">{{ total }}</div>
  </div>
  <div class="tile">
    <h3>Kritik + Yüksek</h3>
    <div class="value">{{ critical + high }}</div>
  </div>
  <div class="tile">
    <h3>Etkilenen Dosya</h3>
    <div class="value">{{ files_affected }}</div>
  </div>
</section>

{% if findings %}
<section class="panels">
  <div class="panel">
    <h2>Önem Derecesi Dağılımı</h2>
    <p class="hint">Durum renkleri ikon ve etiketle birlikte verilir.</p>
    <div class="stack" role="img"
         aria-label="Önem derecesine göre bulgu dağılımı">
      {% for row in severity_rows %}
      <div style="width: {{ row.percent }}%; background: var(--sev-{{ row.key }});"
           title="{{ row.label }}: {{ row.count }} bulgu ({{ row.percent }}%)"></div>
      {% endfor %}
    </div>
    <div class="legend">
      {% for row in severity_rows %}
      <div class="legend-row">
        <span class="swatch" style="background: var(--sev-{{ row.key }});"></span>
        <span class="ico" aria-hidden="true">{{ row.icon }}</span>
        <span class="name">{{ row.label }}</span>
        <span class="n">{{ row.count }}</span>
        <span class="pct">{{ row.percent }}%</span>
      </div>
      {% endfor %}
    </div>
  </div>

  <div class="panel">
    <h2>Veri Türüne Göre Bulgular</h2>
    <p class="hint">En çok görülen {{ type_rows|length }} tür; tek seri, tek renk.</p>
    <div class="bars">
      {% for row in type_rows %}
      <div class="bar-row">
        <div class="bar-head">
          <span class="name" title="{{ row.label }}">{{ row.label }}</span>
          <span class="n">{{ row.count }}</span>
        </div>
        <div class="bar-track">
          <div class="bar-fill" style="width: {{ row.percent }}%;"
               title="{{ row.label }}: {{ row.count }} bulgu"></div>
        </div>
      </div>
      {% endfor %}
    </div>
  </div>
</section>

<div class="filters">
  <input type="search" id="q" placeholder="Dosya, tür veya içerikte ara…"
         aria-label="Bulgularda ara">
  <select id="sev" aria-label="Önem derecesine göre filtrele">
    <option value="">Tüm önem dereceleri</option>
    {% for value in severity_order %}
    <option value="{{ value }}">{{ value }}</option>
    {% endfor %}
  </select>
  <select id="typ" aria-label="Veri türüne göre filtrele">
    <option value="">Tüm türler</option>
    {% for value in types %}
    <option value="{{ value }}">{{ value }}</option>
    {% endfor %}
  </select>
  <span class="count" id="count">{{ findings|length }} satır</span>
</div>

<div class="table-wrap">
<table id="tbl">
  <thead>
    <tr>
      <th scope="col">Önem</th>
      <th scope="col">Tür</th>
      <th scope="col">Konum</th>
      <th scope="col">Satır</th>
      <th scope="col">İçerik (maskeli)</th>
    </tr>
  </thead>
  <tbody>
    {% for item in findings %}
    <tr data-sev="{{ item.severity }}" data-typ="{{ item.type }}"
        data-text="{{ (item.file ~ ' ' ~ item.type ~ ' ' ~ item.title ~ ' ' ~ item.masked)|lower }}">
      <td>
        <span class="sev sev-{{ item.severity }}">
          <span class="dot"></span>{{ item.severity_label }}
        </span>
      </td>
      <td>
        <strong>{{ item.type }}</strong>
        {% if not item.validated %}<span class="tag">doğrulanmadı</span>{% endif %}
        <span class="snippet">{{ item.title }}</span>
      </td>
      <td class="path">{{ item.file }}</td>
      <td class="num">{{ item.line if item.line else '—' }}</td>
      <td>
        <code class="masked">{{ item.masked }}</code>
        {% if item.snippet %}<span class="snippet">{{ item.snippet }}</span>{% endif %}
      </td>
    </tr>
    {% endfor %}
  </tbody>
</table>
</div>

{% if truncated %}
<div class="note" style="margin-top:20px">
  Tabloda ilk {{ findings|length }} bulgu gösteriliyor; {{ truncated }} bulgu daha var.
  Tamamı için CSV ya da JSON raporunu kullanın.
</div>
{% endif %}

{% else %}
<div class="table-wrap">
  <div class="empty">
    <div class="big">Sızıntı tespit edilmedi</div>
    <div>{{ files_scanned }} dosya tarandı, eşik üstü hassas veri bulunamadı.</div>
  </div>
</div>
{% endif %}

{% if error_count %}
<details class="errors">
  <summary>{{ error_count }} dosya okunamadı</summary>
  <ul>
    {% for item in errors %}
    <li><code>{{ item.file }}</code> — {{ item.error }}</li>
    {% endfor %}
  </ul>
</details>
{% endif %}

<footer>
  Sentinel DLP tarafından otomatik üretildi · tüm hassas değerler maskelenmiştir
</footer>
</div>

<script>
(function () {
  var root = document.documentElement;
  var stored = null;
  try { stored = localStorage.getItem('sentinel-theme'); } catch (e) {}
  if (stored) { root.setAttribute('data-theme', stored); }

  var toggle = document.getElementById('themeToggle');
  if (toggle) {
    toggle.addEventListener('click', function () {
      var dark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      var current = root.getAttribute('data-theme') || (dark ? 'dark' : 'light');
      var next = current === 'dark' ? 'light' : 'dark';
      root.setAttribute('data-theme', next);
      try { localStorage.setItem('sentinel-theme', next); } catch (e) {}
    });
  }

  var q = document.getElementById('q');
  var sev = document.getElementById('sev');
  var typ = document.getElementById('typ');
  var table = document.getElementById('tbl');
  var label = document.getElementById('count');
  if (!table || !q) { return; }
  var rows = Array.prototype.slice.call(table.tBodies[0].rows);

  function apply() {
    var text = q.value.trim().toLowerCase();
    var wantSev = sev.value;
    var wantTyp = typ.value;
    var shown = 0;
    for (var i = 0; i < rows.length; i++) {
      var row = rows[i];
      var ok = (!text || row.dataset.text.indexOf(text) !== -1) &&
               (!wantSev || row.dataset.sev === wantSev) &&
               (!wantTyp || row.dataset.typ === wantTyp);
      row.hidden = !ok;
      if (ok) { shown++; }
    }
    label.textContent = shown + ' / ' + rows.length + ' satır';
  }

  q.addEventListener('input', apply);
  sev.addEventListener('change', apply);
  typ.addEventListener('change', apply);
})();
</script>
</body>
</html>
"""
