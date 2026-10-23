# Sentinel - Engineering and Commercialization Roadmap

`ROADMAP.md` records how v3.0 became v4.0: a list of defects and the
phases that closed them. That work is finished. This document is about
the next question, which is a different kind of question:

> Sentinel is a good tool. What would have to be true for it to be a
> product someone pays for?

The answer is not "more features". It is roughly: three defects that
make the current claims untrue, one architectural change that turns a
command into a service, and one licensing decision that has a closing
window. The features come after those, and the revenue comes after the
features - in that order, because the reverse order is how security
tools get sold once and never renewed.

**Method.** Every number below was measured on the commit this file was
added in, not estimated. The measurement command is given with each
figure so it can be re-run and disputed. Where a figure comes from
outside the repository it is sourced and the uncertainty is stated.

**Benchmark machine.** 4 vCPU Intel Xeon @ 2.10 GHz, 15 GB RAM, Linux,
Python 3.13. All timings are from this machine and are comparative, not
absolute - treat ratios as meaningful and wall-clock as indicative.

---

## Contents

1. [Where the product actually stands](#1-where-the-product-actually-stands)
2. [P0 - what is untrue today](#2-p0---what-is-untrue-today)
3. [The licensing window](#3-the-licensing-window)
4. [Phase 5 - trustworthy on one machine](#4-phase-5---trustworthy-on-one-machine)
5. [Phase 6 - from a command to a fleet](#5-phase-6---from-a-command-to-a-fleet)
6. [Phase 7 - from a scanner to a product](#6-phase-7---from-a-scanner-to-a-product)
7. [Phase 8 - from a product to revenue](#7-phase-8---from-a-product-to-revenue)
8. [Architecture decisions and trade-offs](#8-architecture-decisions-and-trade-offs)
9. [The anti-roadmap](#9-the-anti-roadmap---what-not-to-build)
10. [Risk register](#10-risk-register)
11. [Gates - how to know a phase is done](#11-gates---how-to-know-a-phase-is-done)

---

## 1. Where the product actually stands

### 1.1 Size and shape

| | Lines | Note |
|---|---:|---|
| `sentinel/` package | 7,085 | 24 modules |
| `gui_app.py`, `main.py`, `restore_tool.py` | 918 | desktop interface and legacy entry points |
| `tests/` | 3,746 | 429 tests |

Largest modules: `cli.py` 885, `reporting/html.py` 677, `engine.py` 608,
`quarantine.py` 541, `patterns.py` 502.

`cli.py` at 885 lines is the single largest file and holds argument
parsing, configuration layering, output formatting and six subcommand
bodies. It is the first thing that will resist change in phase 6 and is
named again there.

### 1.2 Test coverage

`python -m pytest --cov=sentinel` - **82%** overall, 429 tests. The
average hides the distribution, and the distribution is the finding:

| Module | Coverage | What that means |
|---|---:|---|
| `correlation.py`, `reporting/{__init__,csv_report,json_report}.py` | 100% | |
| `config.py`, `validators.py`, `allowlist.py`, `matcher.py`, `html.py` | 95-96% | |
| `engine.py` | 90% | |
| `cache.py`, `archive.py`, `yara_engine.py` | 89% | |
| `quarantine.py` | 83% | **deletes files** |
| `cli.py` | 77% | every user's entry point |
| `extractors/office.py` | 63% | |
| `extractors/pdf.py` | 54% | |
| `extractors/image.py` | 36% | |
| **`monitor.py`** | **27%** | runs unattended for days |
| **`notify.py`** | **0%** | sends data over the network |

The two worst-covered modules are the two that run without a human
watching: the real-time monitor and the webhook sender. `notify.py` is
the only module in the project that transmits anything off the machine
and not one line of it is executed by the test suite. That is the exact
inversion of where the testing should be.

### 1.3 Measured performance

Corpus: 2,000 text files, 24 MB, 40 directories.

```
python -m sentinel.cli scan <corpus> --no-report --quiet --executor <mode>
```

| Executor | Wall | Throughput | |
|---|---:|---:|---|
| `serial` | 5.56 s | 4.3 MB/s | |
| `thread` | 7.18 s | 3.3 MB/s | **slower than serial** |
| `process` | 1.89 s | 12.7 MB/s | 2.9x over serial on 4 cores |

Incremental, same corpus, `--executor process --incremental`:

| Run | Wall |
|---|---:|
| Cold (cache empty) | 2.01 s |
| Warm (nothing changed) | 0.21 s |

**~10x on a warm cache**, lower than the ~29x recorded in phase 4
because that measurement used a smaller corpus where fixed startup cost
dominated less. The phase 4 figure is not wrong, but it is not the
number to quote for a realistic tree; 10x is.

### 1.4 Where it structurally stops

These are not bugs. They are the boundaries of what the current shape
can do, and each one is a phase below.

| Boundary | Evidence |
|---|---|
| One machine, one run | There is no server, no API, no database, no agent. A scan is a process that starts, prints and exits. |
| Results are not durable | Findings live in memory and are then rendered. Nothing can answer "what changed since Tuesday" except by diffing two report files by hand. |
| The cache is a single JSON file | 580 KB per 2,000 files (~290 B/file), loaded and rewritten whole. `MAX_ENTRIES` is 200,000, so above ~200k files incremental scanning silently stops helping - at that size the cache alone is ~58 MB of JSON parsed on every run. |
| Reports truncate silently | 10,000 and 50,000 findings both render a 1.43 MB HTML page in 0.33 s, because the table is capped. Capping is correct for a static file; it also means the HTML report cannot be the interface for an estate that has 50,000 findings. |
| No policy, only filters | The allowlist and baseline suppress. There is no notion of a rule being *required*, of an owner, a due date, or an exception that expires. |
| No identity | No users, no roles, no tenancy. Every operator is root. |
| Quarantine is local and manual | AES-256-GCM, verified deletion, a real vault - but one vault per machine, with a key on that machine. |

---

## 2. P0 - what is untrue today

Everything in section 1 is a limitation honestly arrived at. This
section is different: three places where the software or its
documentation currently claims something that is not so. These are not
roadmap items to schedule. They are corrections, and they come before
any feature, because the whole value proposition of a DLP tool is that
its output can be trusted.

### P0-1. Fingerprints are reversible for exactly the data they protect

**The claim.** `README.md` and the phase 4 notes say correlation matches
copies of a secret "with the value never revealed", because the
fingerprint is an HMAC-SHA256.

**The reality.** `ScanConfig().fingerprint_salt` defaults to `""`, and
`redaction.fingerprint()` falls back to plain SHA-256 when the salt is
empty. Fingerprints are written into JSON reports and into baseline
files - artifacts explicitly designed to be committed to repositories
and shared between people.

A fingerprint of a high-entropy secret (an AWS key) is safe. A
fingerprint of the PII this scanner exists to find is not, because that
data has almost no entropy. Demonstrated on the benchmark machine:

```python
fp = fingerprint("TR_PHONE:05321234567")      # as published in a baseline
for n in range(10_000_000):                   # 0532 + 7 digits
    if fingerprint(f"TR_PHONE:0532{n:07d}") == fp:
        break
# recovered 05321234567 in 1.4 s after 1,234,567 tries
```

1.4 seconds, single-threaded, pure Python, no precomputation. The
national-ID space is comparable, dates of birth are trivial, and a card
number is bounded by its BIN plus Luhn. In other words: a baseline file
committed to a public repository is a rainbow table of the organization's
own personal data, published under the belief that it is masked.

**The fix.**
1. Generate a random salt at first run and persist it next to the
   configuration; never ship an empty default.
2. Refuse to write a fingerprint into any exported artifact when the
   salt is absent - fail loudly rather than export a reversible one.
3. Use a memory-hard KDF, not a bare HMAC, for low-entropy rule classes.
   scrypt is already a dependency (the vault uses it). An HMAC is the
   wrong primitive when the plaintext space is 10^7.
4. Widen the output beyond 16 hex characters for those classes.
5. Correct the README and the phase 4 notes. The claim must describe what
   the code does.

**Cost.** Two to three days including the migration note - a changed
salt invalidates existing baselines, which is a breaking change and has
to be versioned and announced.

### P0-2. The `thread` executor is slower than no executor

Measured above: 7.18 s against serial's 5.56 s on the same corpus. This
is not surprising - matching regexes over decoded text is CPU-bound and
holds the GIL - but it is offered to users as one of three equal
choices, and the one with the reassuring name is the worst of the three.

**The fix.** Either delete the option, or restrict it to the workload it
actually suits (many small files where `os.stat` and open dominate) and
say so in the help text. Benchmark both shapes first and let the
measurement decide. Whatever the outcome, `--executor` must not present
a slower-than-nothing option without a word of warning.

**Cost.** One day, most of it benchmarking.

### P0-3. The unattended code is the untested code

`notify.py` 0%, `monitor.py` 27%. The webhook is how a scan reaches a
SIEM or a Slack channel; the monitor is what runs for weeks. Both fail
silently by construction - nobody is watching a background process, and
a webhook that stops posting looks exactly like a quiet week.

**The fix.** `notify.py` to meaningful coverage against a local HTTP
server, covering the cases that matter in production and not just the
happy path: non-2xx, timeout, connection refused, redirect, oversized
payload, and - most importantly - a test that asserts **no cleartext
sensitive value is ever in the request body**. That last one is a
privacy guarantee the project makes and does not currently verify
anywhere. `monitor.py` to coverage of the debounce window, rapid
create-modify-delete sequences, and a file that disappears mid-scan.

**Cost.** Three to four days.

---

## 3. The licensing window

This section is short, is not an engineering task, and is the most
consequential decision in the document.

Sentinel is MIT licensed with a single copyright holder. MIT permits
anyone to take the code, close it, rebrand it and sell it, with no
obligation to contribute back and no obligation to say they did. For a
hobby library that is the right trade. For something intended to earn,
it means the product has no defensible core: the moment it is worth
selling, it is worth someone else selling.

The relevant fact is that **this is currently reversible and will not
stay that way.** Relicensing requires the agreement of every copyright
holder. Today that is one person. The first outside pull request that is
merged without a contributor licence agreement makes relicensing require
that contributor's consent too, and the tenth makes it practically
impossible.

The standard resolution is open-core, and it should be decided before
the first external contribution, not after:

| Component | Licence | Why |
|---|---|---|
| Engine, rules, CLI, formats | Apache-2.0 | Permissive drives adoption, and adoption is the only distribution a new security tool has. Apache over MIT for the explicit patent grant, which enterprise legal review asks about. |
| Server, multi-tenancy, policy engine, integrations | BUSL-1.1, converting to Apache-2.0 after four years | Hosting and fleet management are what a company pays for. BUSL stops a competitor reselling it while leaving self-hosted use by the end user free. |

Two things to do now, both small:

1. Add a CLA (the Apache ICLA is fine unmodified) and a bot that enforces
   it, **before** accepting any outside contribution.
2. Write the licensing intent into `CONTRIBUTING.md` so nobody
   contributes under a misunderstanding.

**Cost.** One day. Do it before phase 5.

---

## 4. Phase 5 - trustworthy on one machine

Goal: everything the tool currently claims is verifiably true, and the
output is good enough that a stranger would act on it. No new surface.
This is the phase that makes the rest worth building.

### 5.1 Close P0-1, P0-2, P0-3

As above. Nothing else in this phase starts until these are done.

### 5.2 Measure detection quality, then publish it

The project has 429 tests proving the code does what the author
intended. It has **no measurement of whether the detection is any good** -
no labelled corpus, no precision, no recall. Those are the only two
numbers a buyer cares about, and the only two the project cannot
currently answer.

- Build a labelled corpus: synthetic Turkish records (`tools/generate_data.py`
  is the start), real-shaped source trees, and a deliberate false-positive
  suite - test fixtures, documentation examples, base64 blobs, UUIDs,
  git hashes, lockfiles, minified JS.
- A `make eval` target that prints precision and recall per rule.
- Wire it into CI and **fail the build on regression**. A rule change that
  improves recall by 2% and costs 20% precision should not merge quietly.
- Publish the numbers in the README. Competitors do not. It is cheap
  credibility and it keeps the project honest.

Expect this to be uncomfortable. Entropy rules in particular tend to
look much worse against a real corpus than against hand-written tests.
Better to find that here than in a customer's trial.

### 5.3 Make the reports answer the second question

The HTML dashboard answers "what did you find". The question an analyst
asks next is "what changed since last time", and nothing answers it.

- Persist each scan as a run record (see phase 6 - locally, SQLite is
  enough for this).
- `sentinel diff <run-a> <run-b>`: new, resolved, still open.
- A trend line in the dashboard: findings and unique secrets over the
  last N runs.

This is also the feature that turns a one-off scan into a habit, and a
habit into a renewal.

### 5.4 Pay down the three structural debts

- **`cli.py` (885 lines).** Split into `cli/` with one module per
  subcommand and a shared configuration layer. Phase 6 adds an API that
  must call the same logic the CLI calls; today that logic is tangled
  with argument parsing and printing. Do this before the API exists, not
  after.
- **The cache ceiling.** `MAX_ENTRIES = 200_000` with whole-file JSON
  rewrite. Move to SQLite with a real index. Same file-based deployment,
  no ceiling, incremental writes, and it is the same store phase 5.3 and
  phase 6 need anyway.
- **Extractor coverage** (`office.py` 63%, `pdf.py` 54%, `image.py` 36%).
  These parse untrusted input - the highest-risk code in the project
  after the vault. Fuzz them with malformed and hostile documents.

### 5.5 Supply chain

A security tool that cannot prove what it is made of will not pass
procurement.

- Generate an SBOM (CycloneDX) in CI, attach it to each release.
- Sign releases with Sigstore.
- Pin and hash-verify dependencies; add `pip-audit` to CI.
- Automate the release: tag, build wheel plus signed artifacts, publish
  to PyPI. The current v1.0 release is a hand-built `.exe`, which is not
  reproducible and not verifiable.

**Phase 5 estimate: 6-9 weeks** of focused part-time work.

---

## 5. Phase 6 - from a command to a fleet

Goal: one operator can see the state of many machines without logging
into any of them. This is the single change that moves the product from
"a tool an engineer runs" to "a system a company buys", because the buyer
is not the person running the scan - it is the person who has to answer
for all the machines.

### 6.1 The architecture

Keep the engine exactly as it is. Add two things around it.

```
┌──────────┐   results (mTLS)   ┌───────────────────────┐
│  agent   │ ─────────────────▶ │        server         │
│ (engine) │ ◀───────────────── │  REST + Postgres      │
└──────────┘   policy, rules    │  policy · dedup · API │
     ...                        └───────────┬───────────┘
┌──────────┐                                │
│  agent   │                          ┌─────┴─────┐
└──────────┘                          │    UI     │
                                      └───────────┘
```

**The agent** is today's scanner plus a scheduler, a result shipper and a
policy fetcher. It must keep working when the server is unreachable:
queue locally, ship later. A DLP agent that stops scanning because a
server is down is worse than no agent, because it is silently absent.

**The server** owns durable state, deduplication across hosts, policy,
and the API. Postgres, not SQLite - this is the point where concurrent
writers and real queries begin.

**The UI** is a web application, not the static HTML report. The static
report stays: it is the air-gapped and single-machine story, and that is
a genuine differentiator worth keeping.

### 6.2 Data model sketch

```sql
hosts     (id, name, os, agent_version, last_seen, tenant_id)
runs      (id, host_id, started_at, finished_at, files_scanned,
           duration_ms, config_hash, agent_version)
findings  (id, run_id, host_id, path, line, rule, severity,
           fingerprint, masked, first_seen, last_seen, state)
secrets   (fingerprint, tenant_id, rule, severity, first_seen,
           host_count, finding_count, state, owner, due_at)
policies  (id, tenant_id, name, body_json, version, created_by)
events    (id, tenant_id, actor, action, subject, at, detail_json)
```

`secrets` is the table that matters commercially. It is the phase 4
correlation idea extended across machines: one row per unique secret in
the estate, however many copies exist. "You have 14,000 findings" is
noise. "You have 212 unique secrets, 38 of them on more than one host,
and 9 are older than 90 days" is a work plan - and a renewal argument.

The fingerprint is what makes this join possible, which is precisely why
**P0-1 blocks this phase**: cross-host correlation means transmitting
fingerprints over a network and storing them centrally. Shipping
reversible fingerprints to a server turns a local weakness into a
breach-shaped one.

### 6.3 Non-negotiables for the server

- mTLS between agent and server; the agent's identity is its client
  certificate, and enrolment is explicit.
- The server stores **masked values and fingerprints only**. It must not
  be possible to reconstruct an organization's personal data from a
  compromised Sentinel server. This is both correct and the answer to
  the first question every security reviewer will ask.
- Every state change in `events`, append-only.
- Tenancy from the first migration. Retrofitting `tenant_id` into a
  schema with live customers is a rewrite.

### 6.4 What this breaks

Honest accounting:

- Deployment goes from `pip install` to "run a server and a database".
  Offer a single-container quick start and a Helm chart, and accept that
  the support burden changes character entirely.
- Upgrades become a compatibility matrix: agent version against server
  version. Pick a policy now - server supports agents N-2 - and test it.
- The project becomes two products with one name. The CLI must stay
  first-class and fully usable standalone, or the open-source adoption
  that feeds the commercial funnel dries up.

**Phase 6 estimate: 4-6 months.** This is the largest phase and the one
most likely to be underestimated. The engine is done; everything here is
new.

---

## 6. Phase 7 - from a scanner to a product

Finding data is table stakes. What is sold is everything after the
finding.

### 7.1 A policy engine

Replace "allowlist and baseline" with declarative policy:

```yaml
policy: kvkk-baseline
rules:
  - match: { rule: TR_NATIONAL_ID, path: "/srv/exports/**" }
    severity: critical
    action: [quarantine, notify]
    sla_days: 1
  - match: { rule: EMAIL }
    severity: low
    action: [report]
    exception_until: 2027-01-01   # expires, deliberately
```

The properties that matter: exceptions **expire** (a permanent
suppression is how DLP programmes rot), every rule has an owner, and an
SLA breach is itself an event. Policies are versioned and diffable,
because an auditor will ask what the policy was in March.

### 7.2 Remediation, not just reporting

The gap between "found" and "fixed" is where the money is.

- Ticket integration: Jira, Azure DevOps, GitHub Issues - one ticket per
  unique secret, not per finding.
- Verified revocation: for cloud credentials, check whether the key is
  still live. "You have an AWS key in a file" is a finding; "you have a
  **live** AWS key in a file" is an incident. This single distinction is
  worth more than twenty new rules.
- Guided remediation per rule class, written once.

### 7.3 Evidence

Turkish data controllers must be able to demonstrate compliance, not
merely claim it. A signed, timestamped discovery report is a sellable
artifact in its own right:

- Point-in-time attestation: scope, coverage, findings, signature.
- Coverage reporting: which hosts were scanned, which were missed, and
  why. **Unscanned machines are the real finding** and no competitor's
  dashboard leads with that number.
- Exportable evidence pack for an audit file.

### 7.4 Rules as a maintained asset

27 rules is a demo. A product needs a rule catalogue that is versioned
and shipped independently of the binary, with provenance and tests per
rule, and a path for customers to add their own without forking.

Depth in Turkish coverage is where the remaining advantage is - not its
existence, which Presidio already matches (8.1), but its breadth.
Concrete gaps, in order of value:

| Rule | Why | Note |
|---|---|---|
| **VKN** (tax number) | 10 digits with its own check digit. Appears in every invoice, contract and accounting export in the country. | **Neither Sentinel nor Presidio has it.** The clearest single gap. |
| **SGK** registration number | Payroll and HR exports | |
| **Turkish address and name NER** | The one place Presidio's NLP is genuinely ahead | Depend on Presidio here rather than reimplement |
| Bank account / branch formats | Pre-IBAN records persist in legacy systems | |
| E-Devlet and KEP identifiers | Appear in correspondence archives | |

A rule is only finished when it has an entry in the labelled corpus
from 5.2 and measured precision and recall. Adding rules without that
is how a detector quietly gets worse.

### 7.5 Integrations, in blunt priority order

Entra ID / LDAP for identity · Splunk, Sentinel, QRadar for SIEM ·
SMB and NFS shares · Microsoft 365 and Google Workspace · S3 and Azure
Blob · database column scanning.

File shares and Microsoft 365 are where Turkish mid-market PII actually
lives. Do those two first; everything else can wait for a customer to
ask.

**Phase 7 estimate: 4-6 months**, overlapping phase 6.

---

## 7. Phase 8 - from a product to revenue

### 8.1 The honest competitive position

**Correction.** An earlier revision of this file claimed Turkish PII
validation as Sentinel's native differentiator against competitors
marked "No". That was wrong, and it was wrong in the most expensive
direction - it would have been said to a customer. Microsoft's
Presidio, MIT licensed and free, ships `TrNationalIdRecognizer` and
`TrLicensePlateRecognizer`. Verified directly on presidio-analyzer
2.2.364:

```
valid TCKN     10000000146 -> [('TR_NATIONAL_ID', 1.0)]
invalid TCKN   12345678901 -> no match
plate 34 ABC 1234          -> [('TR_LICENSE_PLATE', 1.0)]
plate 99 ABC 1234          -> no match        # province 99 does not exist
```

Checksum-validated TCKN and province-validated plates, correct on both
the accept and the reject case. Secondary sources claiming Presidio has
no Turkish recognizer are out of date; the test above is the citable
evidence. Any positioning built on "only we validate Turkish IDs" is
built on sand.

#### Commercial competitors

| | Sentinel | GitGuardian | Nightfall | Purview / Forcepoint |
|---|---|---|---|---|
| Focus | Filesystem PII + secrets | Secrets in git | SaaS DLP | Enterprise DLP suite |
| On-prem / air-gapped | **Yes** | Limited | No | Yes |
| Price point | Low | Mid | Mid | High |
| Maturity | Early | Mature | Mature | Mature |

#### Open-source competitors - the ones that matter more

| Project | Licence | Shape | Turkish PII | Overlap |
|---|---|---|---|---|
| **Presidio** (Microsoft) | MIT | Library | **Yes** - TCKN + plate, checksum validated | The PII engine, entirely |
| **TruffleHog** | AGPL-3.0 + paid enterprise | Tool | No | Secrets, and it **verifies credentials are live** |
| **gitleaks** | MIT | Tool | No | Secrets in git |
| **detect-secrets** (Yelp) | Apache-2.0 | Tool | No | Secrets, baseline workflow |
| **Hawk-Eye** | - | Tool, ~500 stars | No | Closest in shape: crawls filesystems, S3, Drive, Slack; OCR; JSON out |
| **OpenDLP** | GPL | Tool | No | Data-at-rest discovery; unmaintained for over a decade |
| **MyDLP** | GPL, Turkish origin | Suite | Partial | Acquired by Comodo 2014; community edition stale since |

Read that table honestly and two things follow. Sentinel's secret
detection is **behind** TruffleHog and gitleaks and always will be -
they are dedicated, funded and years ahead, and TruffleHog's live
credential verification is a capability Sentinel does not have at all.
Sentinel's Turkish PII detection is **matched** by a Microsoft-backed
MIT library.

#### What is actually left, stated narrowly

Three things survive that comparison, and only together:

1. **It is a tool, not a library.** Presidio gives you a classifier.
   Sentinel gives you a crawler, extractors for PDF/Office/ZIP/OCR, a
   severity model, a risk score, six report formats, SARIF, a CI gate, a
   pre-commit hook, encrypted quarantine with verified deletion, and a
   desktop interface - `pip install` and one command. Building that
   around Presidio is months of work that nobody in the Turkish
   mid-market is going to do.
2. **Depth of Turkish coverage, not its existence.** Presidio has two
   Turkish entities. Sentinel has national ID, phone, plate, IBAN, plus
   health-data indicators tied to KVKK art. 6. Neither has **VKN** (the
   tax identification number), which is a concrete gap to close and a
   defensible addition.
3. **No model, no network.** Presidio's strength is NER, which means a
   spaCy model and the weight that comes with it. Sentinel is
   deterministic regex plus algorithmic validation: fast, reproducible,
   explainable to an auditor, and genuinely air-gapped.

The honest summary is that Sentinel's moat is **the workflow, not the
detection**. Detection is a commodity with a free Microsoft-backed
implementation. What is not commodity is the end-to-end path from "point
it at a file share" to "here is a signed report an auditor accepts", in
Turkish, on-premises, for a price a 200-person company will pay.

Positioning should therefore be **KVKK compliance evidence for file
estates**, not "Turkish PII detection". The first is defensible; the
second is a feature Microsoft gives away.

The buyer is a Turkish mid-market company - 50 to 500 employees,
regulated or with regulated customers - that has VERBİS obligations, no
security team, and cannot justify Purview. The budget line is compliance,
not security, and that matters: compliance budgets are annual, defended
by someone with a deadline, and survive cost-cutting better than
security tooling does.

For context on the penalty that funds that budget line: for 2026, after
the 25.49% revaluation published in the Official Gazette on 27 November
2025, the data-security obligations of KVKK art. 12 - which include
breach notification - are widely reported at **₺256,357 to ₺17,092,242**,
with notification to the Board required within 72 hours of becoming
aware. Published figures from different legal commentaries **do not
agree**; confirm against the Authority's own announcement before using
any number in sales material. Overstating a regulatory penalty to a
compliance buyer is the fastest way to lose one.

### 8.2 Pricing

Public anchors, all quote-based and third-party estimated: GitGuardian
prices per active developer, with Vendr's transaction data putting
annual contracts from mid-four figures for small teams to six figures
for enterprises. Nightfall prices per user per year, with typical
contract minimums estimated at $8,000-15,000 and $25,000-60,000 for a
100-250 user deployment.

Sentinel should not price per user. The buyer has no idea how many users
a DLP tool has, and per-seat pricing punishes exactly the behaviour the
product wants to encourage - scanning more things. Price per **scanned
host**, which the customer can count and which grows with the value
delivered.

| Tier | Scope | Indicative |
|---|---|---|
| Community | CLI, all rules, all formats, single machine | Free, Apache-2.0 |
| Team | Server, up to 25 hosts, policy, ticket integration | ~₺4,000/host/year |
| Business | Unlimited hosts, SSO, SIEM, evidence packs, SLA | ~₺6,500/host/year + platform fee |
| Audit | Fixed-scope engagement, signed report, remediation plan | ₺150,000-400,000 per engagement |

These are starting hypotheses to be destroyed by the first ten sales
conversations, not a price list. The only honest way to price a first
product is to quote, lose some, and watch where the losses cluster.

### 8.3 The sequence that actually produces money

The temptation is to build the SaaS and wait. The faster path inverts it,
because services revenue arrives in month one and tells you what to build:

1. **Months 0-3 - Audit engagements.** Sell the *outcome*, delivered by
   hand with today's CLI. Scope a company's file estate, run it,
   interpret it, write the report, present it. Reference customers,
   immediate revenue, and - most valuable - you watch real people react
   to real output. Every phase 7 feature should be something a customer
   asked for during one of these.
2. **Months 3-9 - Self-hosted licence.** For audit customers who want it
   continuously. Phase 6 server, annual licence, installed on their
   hardware. No hosting burden, no data-residency conversation, and
   Turkish buyers are more comfortable with on-prem anyway.
3. **Months 9-18 - Managed service.** Host it, or run it as a monthly
   retainer for customers who have no one to run it. Higher margin,
   recurring, and it is where the SaaS later comes from if it ever
   should.
4. **Month 18+ - Product-led.** Only once the rule catalogue, the
   evaluation numbers and the reference customers exist. A security
   product with no references does not sell itself however good the
   landing page is.

### 8.4 What must exist before the first invoice

Unglamorous and non-optional:

- A support commitment that is written down, even if it is "best effort,
  one business day".
- A security questionnaire answer pack. Every enterprise buyer sends one
  and the first takes two weeks to answer.
- A documented vulnerability disclosure process and a security contact.
- Professional liability insurance. A tool that deletes files and tells
  people their data is safe carries real exposure.
- A company, a contract template, and an accountant.

### 8.5 The uncomfortable part

A solo-maintained Python DLP tool will not displace Microsoft Purview,
and planning as if it might is how the next two years get wasted. What it
can realistically become, with the phases above executed well, is a
profitable niche product for Turkish mid-market compliance, earning
somewhere between a good salary and a small team's payroll. That is a
genuinely good outcome and it should be stated as the goal rather than
discovered as a disappointment.

The single largest risk is not competition or technology. It is that
phase 5 - the dull one, with the corrections and the labelled corpus and
the coverage - gets skipped in favour of phase 6, which is more fun to
build. A fleet of agents shipping reversible fingerprints from an engine
whose precision nobody has measured is not a product. It is a liability
with a dashboard.

---

## 8. Architecture decisions and trade-offs

Decisions worth recording now, with the reasoning, so they can be
revisited deliberately rather than drifted away from.

| # | Decision | Alternative | Why |
|---|---|---|---|
| D1 | Agent ships results, server never pulls | Server-initiated scanning | Agents work behind NAT and through firewalls without inbound rules. Nearly every mid-market network makes inbound impossible. |
| D2 | Server stores masked values and fingerprints only | Store full findings | A compromised Sentinel server must not be a data breach. Costs some UI richness; worth it. |
| D3 | Postgres, not a document store | Mongo, Elastic | The access patterns are relational - joins across hosts, runs and secrets. Elastic can come later for full-text if needed. |
| D4 | Python stays the engine language | Rewrite in Go or Rust | Throughput is already 12.7 MB/s with processes, and the bottleneck in real deployments is disk and network. Rewriting would buy perhaps 3-5x for a year of work and would discard a 429-test suite. Revisit only if measurement, not instinct, demands it. |
| D5 | Rules shipped separately from the binary | Rules compiled in | Rules must update faster than releases, and customers need their own without forking. |
| D6 | Static HTML report stays forever | Replace with the web UI | It is the air-gapped story and the single-machine story, and it costs almost nothing to keep. |
| D7 | Open core: Apache engine, BUSL server | All-MIT, or all-commercial | Adoption needs permissive; a business needs something a competitor cannot resell. |

---

## 9. The anti-roadmap - what NOT to build

Deciding what not to do is most of the value of a roadmap.

- **No AI/LLM classification, for now.** Tempting, demos beautifully, and
  it would make the output non-deterministic, slow, expensive and
  impossible to run air-gapped - discarding the three things Sentinel
  actually wins on. Revisit only when the labelled corpus from 5.2 exists
  and can prove a measured improvement over the regex and validator path.
- **No network DLP.** Inspecting traffic is a different product with a
  different architecture and buyer. Saying "DLP" invites the question;
  answer it clearly and stay on data at rest.
- **No endpoint blocking.** Preventing a USB copy means a kernel driver,
  a support nightmare and liability for every machine that blue-screens.
- **No chasing GitGuardian's or TruffleHog's rule count.** Hundreds of
  generic token formats is their moat, not a target, and Sentinel's
  secret detection is already behind theirs. Recommend running gitleaks
  or TruffleHog alongside Sentinel rather than pretending to replace
  them - saying so openly costs nothing and buys credibility.
- **No reimplementing Presidio.** It is MIT, Microsoft-backed and
  already does checksum-validated TCKN. If the NLP path is ever needed,
  depend on it; do not compete with it.
- **No mobile app.** Nobody remediates a data leak from a phone.
- **No marketplace or plugin ecosystem** before there are customers. It
  is a tax on every internal interface in exchange for contributions
  that will not arrive at this stage.

---

## 10. Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Phase 5 skipped for phase 6 | **High** | **High** | Gate 6 on gate 5 and treat it as hard. This is the one that sinks the project. |
| Detection quality turns out poor under measurement | Medium | High | Find out in 5.2, cheaply, before a customer does. |
| A competitor has already added Turkish PII validation | **Certain - it has happened** | High | Presidio ships checksum-validated TCKN today (8.1). The detection moat does not exist. Compete on workflow, depth and local presence, and stop describing detection as a differentiator. |
| TruffleHog or Hawk-Eye adds filesystem KVKK reporting | Low | **High** | This is the actual existential risk, not the PII regexes. Watch both releases. The defence is the compliance workflow and Turkish customer relationships, neither of which is in a repository. |
| Solo maintainer bus factor | **High** | **High** | Documented architecture, high coverage, no undocumented deploy steps. This also directly governs valuation if the project is ever sold. |
| Support burden exceeds capacity after first sales | Medium | Medium | Price in support from day one; cap the number of customers deliberately. |
| False positive deletes a customer's file via quarantine | Low | **Severe** | Keep quarantine off by default, keep verified deletion, keep restore tested, add a dry-run mode and a mandatory retention window before any permanent purge. |
| MIT fork by a competitor | Medium | High | Section 3, acted on before the first outside contribution. |
| Regulatory figures quoted wrong in sales material | Medium | High | Cite the Authority's own announcement, never a secondary commentary. |

---

## 11. Gates - how to know a phase is done

No phase starts until the previous gate passes. Each criterion is
measurable; none of them is a judgement call.

**Gate 5 - trustworthy.**
- P0-1, P0-2, P0-3 closed, each with a test that fails when the fix is reverted.
- Labelled corpus exists; precision and recall published per rule; CI fails on regression.
- No module below 70% coverage; `notify.py` and `monitor.py` above 85%.
- SBOM and signed artifacts attached to a release built entirely by CI.
- `sentinel diff` ships.

**Gate 6 - fleet.**
- 50 agents reporting to one server for 30 continuous days without data loss.
- Agent survives a 24-hour server outage and reconstitutes without gaps.
- Server stores nothing from which plaintext PII can be reconstructed - verified by an external reviewer, not by the author.
- Documented, tested upgrade path across two agent versions.

**Gate 7 - product.**
- A customer writes a policy without help.
- Live-credential verification working for at least AWS, Google and GitHub.
- An evidence pack accepted by a real auditor in a real audit.

**Gate 8 - business.**
- Three paying audit engagements completed.
- One self-hosted licence renewed - renewal, not first sale, is the signal.
- Gross margin per customer measured and positive after support cost.

---

## Appendix A - reproducing the measurements

```bash
# Coverage
python -m pytest -q --cov=sentinel --cov-report=term-missing

# Throughput (2,000 files / 24 MB corpus)
for m in serial thread process; do
  python -m sentinel.cli scan <corpus> --no-report --quiet --executor $m
done

# Incremental
python -m sentinel.cli scan <corpus> --no-report --quiet \
  --executor process --incremental --cache-path /tmp/bench.json   # twice

# Fingerprint reversibility (P0-1)
python - <<'PY'
from sentinel.redaction import fingerprint
fp = fingerprint("TR_PHONE:05321234567")
for n in range(10_000_000):
    if fingerprint(f"TR_PHONE:0532{n:07d}") == fp:
        print("recovered", f"0532{n:07d}"); break
PY
```

## Appendix B - sources

Market and regulatory figures are external and were current when this
file was written. Both are quote-based or disputed; re-verify before
using either in a commercial document.

- Presidio Turkish recognizers - verified locally against presidio-analyzer 2.2.364; see also [supported entities](https://github.com/microsoft/presidio/blob/main/docs/supported_entities.md)
- Open-source landscape survey - [Bytebase](https://www.bytebase.com/blog/top-open-source-sensitive-data-discovery-tools/), [Hawk-Eye](https://github.com/rohitcoder/hawk-eye)
- MyDLP history and Comodo acquisition - [Wikipedia](https://en.wikipedia.org/wiki/MyDLP), [repository](https://github.com/mydlp/mydlp)
- GitGuardian pricing model and contract ranges - [Vendr](https://www.vendr.com/marketplace/gitguardian)
- Nightfall pricing model - [Nightfall](https://www.nightfall.ai/pricing), contract ranges - [Vendr](https://www.vendr.com/marketplace/nightfall)
- KVKK 2026 administrative fines and the 25.49% revaluation - [Mondaq](https://www.mondaq.com/turkey/data-protection/1726256/2026-y%C4%B1l%C4%B1-kvkk-%C4%B0dari-para-cezalar%C4%B1-g%C3%BCncel-tutarlar-ve-uyar%C4%B1lar), [Köksal & Partners](https://www.koksalpartners.com/tr/kvkk-cezalari)
- KVKK 72-hour breach notification - [Hukukçular Evi](https://hukukcularevi.com/kvkk-veri-ihlali-bildirim-72-saat-6698-12-madde/)

Published figures for KVKK penalties differ between commentaries. The
Authority's own announcement is the only citable source.
