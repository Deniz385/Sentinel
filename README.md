# 🛡️ Sentinel

**Sensitive data discovery and loss prevention (DLP).** Finds data in
scope for KVKK / GDPR / PCI-DSS on a filesystem, along with credentials
leaked into source code; ranks findings by severity, reports them, and
optionally encrypts and quarantines the files.

Cross-platform (Linux · macOS · Windows) · Python 3.10+ · no network
access required.

```
sentinel scan ~/Documents --format html,sarif --fail-on high
```

---

## Why

Sensitive data rarely stays where it belongs: a customer list ends up in
a spreadsheet inside a ZIP, an API key in a test script, a scan of an ID
card in a PDF. Sentinel looks in those places and answers **"how bad is
it?"** - it does not show 500 email addresses and one AWS key as equals
in a flat list.

## Features

| | |
|---|---|
| **27 detection rules** | National ID · IBAN · credit card · phone · vehicle plate · AWS/Google/GitHub/Slack/Stripe/OpenAI keys · private key · JWT · database connection string · crypto wallet · health data |
| **Algorithmic validation** | National-ID check digits · Luhn plus card brand · IBAN mod-97 · JWT header decode · Base58Check. Cuts false positives at the root |
| **Entropy scanning** | Catches random secrets that have no named pattern |
| **Format support** | Text and code · PDF · Word · Excel · PowerPoint · **ZIP (recursive)** · images (OCR) |
| **Five severity levels** | `info` → `critical`, plus an aggregate 0-100 risk score |
| **Cross-file correlation** | Every copy of a secret in one item: "21 findings / 1 unique secret". Matched on the fingerprint, with the value never revealed |
| **Incremental scanning** | `--incremental` skips unchanged files (measured: 400 files, 0.87 s → **0.03 s**) |
| **False-positive management** | Allowlist (path/value/fingerprint/regex) · inline `sentinel:ignore` · baseline |
| **Six report formats** | HTML dashboard · CSV · JSON · **SARIF** · Markdown · PDF |
| **Encrypted quarantine** | AES-256-GCM, verified deletion, integrity checking |
| **Real-time monitoring** | `sentinel watch` scans new and changed files as they appear |
| **CI integration** | Meaningful exit codes · a `--fail-on` gate · a git pre-commit hook |
| **Privacy** | **No cleartext sensitive data** in reports, logs or webhook payloads - everything is masked |

---

## Installation

```bash
git clone https://github.com/deniz385/Sentinel.git
cd Sentinel

# Core (CLI plus text and code scanning)
pip install -e .

# Every extra (PDF, Office, OCR, monitoring, GUI, reports)
pip install -e ".[all]"
```

Optional extras can also be installed individually:

```bash
pip install -e ".[docs]"     # PDF, Word, Excel, PowerPoint
pip install -e ".[ocr]"      # images and scanned documents
pip install -e ".[monitor]"  # real-time monitoring
pip install -e ".[pdf]"      # PDF report
pip install -e ".[yara]"     # YARA rule engine
pip install -e ".[gui]"      # desktop interface
```

OCR needs the Tesseract engine installed separately:

```bash
apt install tesseract-ocr tesseract-ocr-tur    # Debian/Ubuntu
brew install tesseract tesseract-lang          # macOS
# Windows: https://github.com/UB-Mannheim/tesseract/wiki
```

To see what is installed:

```bash
sentinel doctor
```

---

## Usage

### Scanning

```bash
sentinel scan ~/Documents                     # default: HTML + CSV report
sentinel scan . --format html,csv,json,sarif  # several formats
sentinel scan . --min-severity high           # serious findings only
sentinel scan . --only secret                 # secret and key rules only
sentinel scan . --skip-rules EMAIL,PRIVATE_IP # turn off noisy rules
sentinel scan . --ocr                         # scan images too
sentinel scan . -j 8                          # 8 parallel workers
sentinel scan . --verbose                     # print every finding
```

### Incremental scanning

When you scan a large share regularly, there is no point re-reading the
files that have not changed:

```bash
sentinel scan /mnt/share --incremental                  # skip unchanged files
sentinel scan /mnt/share --incremental --cache-path /var/lib/sentinel.json
sentinel scan /mnt/share --incremental --clear-cache    # reset the cache
```

Measured (400 files · 4.3 MB): a full scan takes **0.87 s**, entirely
from cache **0.03 s**, and with one file changed **0.04 s**.

The limits that keep the cache safe:

- **Off by default.** The tool does not assume "this file has not
  changed" unless asked to.
- If the rule catalogue, the configuration or the Sentinel version
  changes, the cache is dropped **entirely** - a stale entry hides the
  secret a new rule would have found.
- Files that fail to read are **not** written to the cache; a locked
  file does not become invisible forever.
- With `--quarantine` the cache is **never used**: a decision that
  deletes data cannot rest on stale evidence (the CLI says so).
- The freshness test `(mtime, size)` is a heuristic, not proof. A change
  that restores mtime and preserves size slips past it - if you need
  forensic certainty, leave incremental scanning off.

### Listing the rules

```bash
sentinel rules                 # every rule, with severities
sentinel rules --tag secret    # secret-hunting rules only
sentinel rules --json          # machine readable
```

### Real-time monitoring

```bash
sentinel watch ~/Downloads
```

### The quarantine vault

Encrypts risky files with AES-256-GCM and isolates them. **The original
is deleted only after the encrypted copy has been decrypted again and
its SHA-256 matched.**

```bash
sentinel scan ~/Documents --quarantine --min-severity critical
sentinel vault list                      # files in the vault
sentinel vault verify                    # integrity check
sentinel vault restore <file.enc>        # restore to the original location
sentinel vault purge --all               # delete permanently
sentinel vault migrate                   # move legacy quarantine directories
```

The vault key is taken from these sources, in order:

1. the `SENTINEL_VAULT_KEY` environment variable (base64, hex or a
   passphrase),
2. the key file named in the configuration,
3. `~/.sentinel/vault.key` - generated with `0600` permissions on first
   use.

> **If the key is lost, quarantined files cannot be recovered.** In
> production, keep `SENTINEL_VAULT_KEY` in a secret manager.

---

## CI integration

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean, or findings below the `--fail-on` threshold |
| `1` | Findings at or above the `--fail-on` threshold |
| `2` | Execution error (missing target, invalid setting) |
| `130` | Cancelled by the user |

### GitHub Actions and Code Scanning

SARIF output puts findings directly into a pull request's "Files
changed" view and the **Security** tab:

```yaml
- run: pip install -e ".[docs]"
- run: sentinel scan . --format sarif --fail-on critical
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: sentinel.sarif
```

### Git pre-commit hook

Blocks a commit that contains a secret before it is ever pushed:

```bash
sentinel precommit --install     # writes .git/hooks/pre-commit
sentinel precommit               # run by hand (scans staged files)
```

---

## Configuration

```bash
sentinel init     # creates an example sentinel.yml
```

Settings are layered; each level overrides the one to its left:

```
defaults  <  sentinel.yml  <  SENTINEL_* environment  <  CLI arguments
```

`sentinel.yml` is looked up from the working directory upwards, so it is
found when you run from a subfolder too.

```yaml
target: .
min_severity: low

exclude_dirs: [.git, node_modules, venv]
exclude_globs: ["*.min.js", "*.lock"]

entropy_scan: true
archive_enabled: true
ocr: false
workers: 0            # 0 = automatic, based on CPU count

incremental: false    # skip unchanged files via the cache
# cache_path: .sentinel-cache.json

allowlist:
  paths: ["tests/**", "test_data/**"]
  values: []
  rules: [PRIVATE_IP]
  use_defaults: true  # AWS example key, example.com, and so on
  inline: true        # `sentinel:ignore` comments
```

**Do not put secrets in the configuration file**; use environment
variables:

| Variable | Description |
|---|---|
| `SENTINEL_VAULT_KEY` | Quarantine vault key |
| `SENTINEL_WEBHOOK_URL` | Discord / Slack / Teams notification URL |
| `SENTINEL_FINGERPRINT_SALT` | Fingerprint salt (organization-specific correlation) |
| `SENTINEL_WORKERS`, `SENTINEL_OCR`, `SENTINEL_MIN_SEVERITY` | Scan settings |
| `SENTINEL_INCREMENTAL`, `SENTINEL_CACHE_PATH` | Incremental scanning |

---

## Dealing with false positives

There are three ways; pick the narrowest one.

**1. Inline** - for a single line:

```python
TEST_KEY = "AKIAIOSFODNN7EXAMPLE"   # sentinel:ignore
TEST_ID = "10000000146"             # sentinel:ignore=TR_NATIONAL_ID
```

**2. Allowlist** - for a recurring path or value (`sentinel.yml`).

**3. Baseline** - to freeze the current state and report only **new**
leaks. This is how you open the CI gate without first clearing the
existing debt:

```bash
sentinel scan . --write-baseline baseline.json   # once
sentinel scan . --baseline baseline.json --fail-on high
```

---

## Desktop interface

```bash
pip install -e ".[gui]"
sentinel-gui      # or: python gui_app.py
```

Folder selection, live progress, a cancellable scan, a findings list
coloured by severity, a risk distribution chart, quarantine vault
management, and one-click report saving.

---

## Python API

```python
from sentinel import ScanConfig, Scanner

config = ScanConfig(target="data", min_severity="high", workers=4)
result = Scanner("data", config=config).scan()

print(result.risk_score, "/100")
for finding in result.findings:
    print(finding.severity, finding.type, finding.file, finding.content_masked)

# Not findings, but items of work: copies of one value share a group.
print(len(result.findings), "findings /", result.unique_count, "unique secrets")
for group in result.shared_secrets():
    print(group.type, "in", group.file_count, "files", group.content_masked)
```

`Finding` objects **never carry cleartext sensitive data**:
`content_masked` holds the masked value, and `fingerprint` gives an
HMAC-SHA256 identity that supports correlation without leaking the data.
`SecretGroup` carries the same guarantee - grouping runs on the
fingerprint and the value is never revealed.

---

## Development

```bash
pip install -e ".[dev,all]"
pytest                    # 419 tests
pytest --cov=sentinel
ruff check .
```

### Architecture

```
sentinel/
  config.py        layered configuration (file -> environment -> CLI)
  severity.py      severity levels and the risk score
  patterns.py      pattern catalogue (regex + severity + validator binding)
  validators.py    national ID · Luhn · IBAN · JWT · Base58Check
  entropy.py       Shannon entropy, generic secret candidates
  redaction.py     masking and HMAC fingerprints
  allowlist.py     false-positive suppression and baselines
  matcher.py       text -> findings (validate, suppress, resolve overlaps, dedupe)
  correlation.py   findings -> unique secrets (cross-file grouping)
  cache.py         incremental scan cache (including invalidation rules)
  extractors/      plain · pdf · office · archive · image
  engine.py        parallel scanning, streaming reads, cancellation, progress
  quarantine.py    AES-256-GCM vault (reads the legacy format too)
  yara_engine.py   the rules/*.yar engine
  notify.py        webhook notifications
  monitor.py       real-time monitoring
  reporting/       html · csv · json · sarif · markdown · pdf
  cli.py           scan · watch · vault · rules · precommit · init · doctor
```

To add a rule: append a `PatternDef` to the catalogue in
`sentinel/patterns.py` - severity, description, a validator name where
one applies, and an `example`. The tests automatically check that the
example matches its own regex.

### Detection rules and language

Rule *names* and all documentation are English. Some rules deliberately
contain Turkish keywords in their regexes - the health-data indicators,
the credential names `sifre` and `parola`, the table names in the
database-dump YARA rule. Those are detection data, not leftover prose:
this scanner targets Turkish records and codebases, where secrets are
routinely named in Turkish. Removing them would blind the rules on their
main audience, the same way removing the national-ID validator would.

### Backward compatibility

- The `scan_results.csv` column order is preserved; new fields are
  appended at the end.
- `Scanner(target).start_scan_parallel()` and `get_patterns()` keep
  working.
- The quarantine vault still reads v3.0's base64 files and its
  `.enc.meta` / `karantina_kayitlari.json` records.
- The legacy `python main.py --target test_data` invocation is valid.
- Six rules were renamed from Turkish to English identifiers
  (`TC_KIMLIK` → `TR_NATIONAL_ID`, `KREDI_KARTI` → `CREDIT_CARD`,
  `TELEFON` → `TR_PHONE`, `TR_PLAKA` → `TR_PLATE`, `DOGUM_TARIHI` →
  `DATE_OF_BIRTH`, `SAGLIK_VERISI` → `HEALTH_DATA`). The old names are
  still accepted in allowlists, `--only`/`--skip-rules`, and inline
  `sentinel:ignore` comments. **Baselines must be regenerated**: a
  fingerprint is derived from `rule:value`, so renaming a rule changes
  it.

---

## Roadmap

Diagnosis of the defects that were closed, and what is next:
[ROADMAP.md](ROADMAP.md).

## Warning

Sentinel **handles sensitive data**. Even though its reports are masked,
they show where things were found; treat the report files as
confidential too. The quarantine feature **moves files and deletes the
originals** - try it first with a narrow threshold such as
`--min-severity critical`, in a directory you have backed up.

Use it only on systems you are **authorized** to scan.

## License

MIT - see [LICENSE](LICENSE).
