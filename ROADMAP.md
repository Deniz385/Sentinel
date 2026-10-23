# Sentinel - Roadmap

Sentinel's goal is to be an **enterprise-grade, cross-platform DLP (data
loss prevention) and sensitive-data discovery platform**. This document
records the gaps in the current state, why each one mattered, and in
which phase it was closed.

---

## 1. Diagnosis - the defects in v3.0 (the previous version)

### 1.1 Correctness and security faults

| # | Finding | Impact |
|---|---------|--------|
| A1 | `reporter.py` wrote every field into HTML with f-strings | **HTML/JS injection**: a filename containing `<script>` weaponises the report |
| A2 | `quarantine.py` "encryption" was `base64(reverse(bytes))` | **Not** encryption, only obfuscation. Quarantined personal data was effectively in the clear |
| A3 | Quarantine deleted the original **before verifying** | **Permanent data loss** if the encrypted copy was corrupt |
| A4 | `subprocess` was not imported in `quarantine.restore_file` | `NameError`, swallowed by a bare `except` |
| A5 | `WEBHOOK_URL` hard-coded in the source | Secret-leak risk; changing a setting required changing code |
| A6 | The `TR_IBAN` regex had a capturing group (`(\d{4}\s?){6}`) | `findall` returned the last group instead of the whole match, so IBAN findings were broken |
| A7 | `pdf_gen.py` passed content to `Paragraph` unescaped | Data containing `<` or `&` blew up PDF generation |
| A8 | Quarantine directory was `KARANTINA_BOLGESI` while the repo held `QUARANTINE_ZONE` | The recovery tool looked in the wrong place |

### 1.2 False promises (the code did not do what it said)

| # | Finding |
|---|---------|
| B1 | `start_scan_parallel()` was **not parallel** - a plain `os.walk` loop |
| B2 | `main.py` advertised a "ZIP" module while `scanner.py` had **no** ZIP support (the old `scan_results.csv` contained a ZIP finding, so this was a regression) |
| B3 | `.docx` was read as plain text, i.e. ZIP binary noise |
| B4 | `rules/sample.yar` was used nowhere (a dead file) |
| B5 | `monitor.py` called `scan_file_wrapper()`, which did not exist on `Scanner`, so real-time monitoring **never worked at all** |
| B6 | `utils.setup_logger` and `calculate_entropy` were never called (dead code); the scanner used `print()` |

### 1.3 Performance

| # | Finding |
|---|---------|
| C1 | `calculate_file_hash()` ran again **for every finding** - 1000 findings in a 50 MB file meant 50 GB of reads |
| C2 | Whole files were read into RAM (`f.read()`) |
| C3 | `calculate_entropy` called `str.count` 256 times - O(256*n) |
| C4 | `openpyxl.load_workbook` was opened without `read_only` |

### 1.4 Portability

The tool was effectively locked to Windows: a hard-coded
`C:\Program Files\Tesseract-OCR` path, `os.popen('date /t')`,
`os.startfile`, `explorer /select`, `os.system("start ...")`.

### 1.5 Engineering discipline

| # | Finding |
|---|---------|
| E1 | `tests/test_patterns.py` **did not run**: there were no patterns named `TR_ID`, `CREDIT_CARD` or `PHONE` (the real names were `TC_KIMLIK`, `KREDI_KARTI`, `TELEFON`), so it raised `KeyError` |
| E2 | `requirements.txt` was **UTF-16** encoded, so `pip install -r` failed in most environments; `pytesseract`, `pillow`, `customtkinter`, `matplotlib`, `reportlab`, `watchdog`, `requests` and `pyyaml` were missing from it |
| E3 | A 52 MB `big_test_data.txt` was committed, along with generated `dashboard.html`, `scan_results.csv` and `scan_report.csv` output |
| E4 | `README.md` and `LICENSE` were **empty** |
| E5 | No CI, no packaging (`pyproject.toml`), no `sentinel` command |
| E6 | No configuration file; `python-dotenv` was a dependency but unused |

### 1.6 Gaps as a product

In order of importance: no severity, so every finding weighed the same;
no false-positive management (no allowlist, baseline or inline
suppression); no machine-readable output, making CI integration
impossible; no entropy-based hunting for generic secrets; no archive,
Office or PPTX support; no `git` pre-commit mode; no audit trail.

---

## 2. Roadmap

### Phase 0 - Repository hygiene ✅
`requirements.txt` converted to UTF-8 and completed · `pyproject.toml`
plus the `sentinel` console command · generated output removed from the
repository and added to `.gitignore` · a real `README.md` · an MIT
`LICENSE` · GitHub Actions CI (Linux and Windows, Python 3.10-3.13).

### Phase 1 - Rebuilding the core engine ✅
A real `sentinel/` package in place of the flat `src/` module pile:

```
sentinel/
  config.py        ScanConfig: layered YAML + .env + CLI configuration
  severity.py      five severity levels plus a risk score
  patterns.py      pattern catalogue with severity and validator bindings
  validators.py    national ID · Luhn (+ card brand) · IBAN mod-97 · JWT · Base58Check
  entropy.py       O(n) Shannon entropy and normalized entropy
  redaction.py     masking plus HMAC fingerprints (correlation without leaking)
  allowlist.py     glob/value/fingerprint plus inline `sentinel:ignore`
  matcher.py       text -> findings (validate, suppress, dedupe, score)
  extractors/      plain · pdf · docx · xlsx · pptx · zip · images (OCR)
  engine.py        real parallel scanning, streaming reads, cancellation, progress
  quarantine.py    AES-256-GCM vault, verified deletion, reads the legacy format
  notify.py        webhooks (Discord/Slack/generic), batched and masked
  monitor.py       real-time monitoring that works (with debouncing)
  reporting/       html · json · csv · sarif · markdown · pdf
  cli.py           scan · watch · vault · rules · precommit · init
```

Closed here: A1-A8, B1-B6, C1-C4, 1.4, E6.

### Phase 2 - Tests and CI ✅
The broken test file was discarded and replaced with tests for patterns,
validators, entropy, masking, the allowlist, extractors (ZIP/XLSX/DOCX/
PDF), the engine (end to end, in parallel), quarantine (an AES round
trip plus the legacy format), the reporters (**including HTML
escaping**) and the CLI. Closed: E1, E5.

### Phase 3 - Making it a product ✅
Severity and risk score · allowlist and baseline · SARIF (GitHub Code
Scanning) · the `sentinel precommit` git hook · entropy-based hunting
for generic secrets · the YARA engine (`rules/*.yar` finally runs) · a
JSONL audit trail · a CI gate via `--fail-on`.

### Phase 4 - Improvements that came out of measurement ✅

Once v4.0 was green, the question "what else is worth doing?" was
answered by **measurement** rather than guesswork. Three measurements
justify this phase:

| Measurement | Result |
|---|---|
| Test coverage per module | `notify.py` **0%** (the webhook that would wake someone at 3am had never been executed), `monitor.py` 27%, `extractors/image.py` 36%, `extractors/pdf.py` 54%; 81% overall |
| Cross-file duplication | 5 files carrying the same 2 secrets → **10 findings, 2 unique secrets** |
| Profile (40,000 lines) | **1,000,000 `re.search` calls** (~25 patterns per line); `_candidates` 1.0 s plus `re.search` 0.93 s out of 3.4 s total |

#### 4.1 Cross-file correlation ✅

**The problem.** "207 findings" tells an analyst there are 207 items of
work. Yet 40 copies of the same AWS key close with **one revocation**.
The finding count measured copying habits, not workload.

**The fix.** `sentinel/correlation.py` reduces findings to unique
secrets keyed on `(rule, fingerprint)`. Because the fingerprint is an
HMAC-SHA256, copies can be matched **without the value ever being
revealed**. Every report (the CLI summary, the HTML dashboard, Markdown,
JSON, PDF) now gives both numbers: *findings* and *unique secrets*.
Secrets spread across more than one file get their own section, most
widespread first.

Edge cases are under test: YARA findings (which match a whole file, not
one value) are **never** merged; where a value was rated differently in
different files the group shows the worst case; the location list is
truncated while the file count stays exact. A separate test verifies
that group output carries no cleartext sensitive value.

#### 4.2 Incremental scanning ✅

**The problem.** Re-scanning a 500 GB share from scratch every night,
when 99% of it has not changed, wastes nearly all of that time.

**The fix.** `sentinel/cache.py` keeps a `(path -> mtime_ns, size,
findings)` record. `sentinel scan --incremental`.

| 400 files · 4.3 MB | Duration |
|---|---|
| Full scan | 0.87 s |
| Entirely from cache | **0.03 s** (~29x) |
| One file changed | 0.04 s (399 from cache) |

In a security tool a cache is, if built carelessly, the mechanism that
makes a leak **invisible**. So four rules are embedded in the code and
in the tests:

1. **If the rule catalogue, the configuration or the version changes,
   the cache is dropped entirely.** A single stale entry hides the
   secret a new rule would have found.
2. **Transient errors are not cached.** A locked file must not become
   invisible forever.
3. **The cache is never used while quarantine is on.** A decision that
   *deletes* data cannot rest on stale evidence; the CLI says so rather
   than doing it silently.
4. **Off by default.** The tool does not assume "this file has not
   changed" unless asked to.

The known trade-off is pinned in a test rather than hidden
(`test_mtime_rollback_is_a_known_limitation`): the freshness test
`(mtime, size)` is a *heuristic*, not proof. A change that restores
mtime and preserves size slips past the cache. Where forensic certainty
is required, incremental scanning stays off.

#### 4.3 Still open (in priority order)

1. **Raw speed.** 2-3 MB/s single-threaded means days on a 500 GB share.
   The options: one combined regex (3-5x), hyperscan (10-100x), moving
   the core to Rust (20-50x). Prototype and measure before committing to
   any of them - a "two-tier combined regex" attempt in the prescreen
   **was reverted because measurement showed no gain at all**, and that
   mistake should not be repeated.
2. **Structural data and column awareness.** The principled fix for
   order numbers that pass Luhn is seeing **columns** rather than lines:
   if a CSV header reads `order_no`, the card rule should not run in
   that column.
3. **The measured test gaps.** 0% coverage on `notify.py` is not
   acceptable: if the webhook goes quiet exactly when there *is* a
   finding, nobody notices.
4. **Quarantine key management.** During my own demo I permanently lost
   a file I had quarantined with an ephemeral key - a live demonstration
   of a documented risk. Multiple recipients, key escrow and rotation
   are needed.
5. **Streaming output.** All findings are held in memory; with millions
   of them it is the scan itself, not report writing, that falls over.
6. **A remediation workflow.** Finding is half the job; assigning an
   owner, tracking status and closing via a rescan are missing.
7. **A decision to revisit:** entropy scanning being on by default. It
   produced 5 false positives in our own source (since fixed), and
   similar classes exist in every source tree.

### Phase 5 - Longer term (outside the scope of this work)
- Email (`.eml`, `.msg`) and `.pst` extractors
- Database scanners (PostgreSQL / MySQL / MSSQL column profiling)
- S3 / Azure Blob / Google Drive connectors
- Named-entity recognition for names and addresses (where regex is not enough)
- A central management panel (FastAPI plus multi-agent reporting)
- Signed Windows and macOS packages, MSI/pkg installers
- OpenTelemetry metrics, a Prometheus exporter

---

## 3. Compatibility note

The legacy CSV columns (`file`, `line`, `type`, `content_masked`,
`sha256`) are preserved and the new columns (`severity`, `rule`,
`fingerprint`, `source`) are appended after them.
`Scanner(target).start_scan_parallel()` and `get_patterns()` keep their
old signatures, so existing scripts do not break.

Six rules were renamed from Turkish to English identifiers
(`TC_KIMLIK` → `TR_NATIONAL_ID`, `KREDI_KARTI` → `CREDIT_CARD`,
`TELEFON` → `TR_PHONE`, `TR_PLAKA` → `TR_PLATE`, `DOGUM_TARIHI` →
`DATE_OF_BIRTH`, `SAGLIK_VERISI` → `HEALTH_DATA`). The old names remain
valid in allowlists, in `--only` and `--skip-rules`, and in inline
`sentinel:ignore` comments. Baselines, however, must be regenerated: a
fingerprint is derived from `rule:value`, so renaming a rule changes it.

---

## 4. What comes next

This document covers the work that is finished. The next phases - the
corrections that have to land before any new feature, the move from a
single command to a fleet, and the path to a commercial product - are in
[PRODUCT-ROADMAP.md](PRODUCT-ROADMAP.md).
