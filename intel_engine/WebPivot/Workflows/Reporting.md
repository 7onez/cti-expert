# Reporting, evidence & monitoring

Everything for turning raw pivots into an analyst deliverable, packaging evidence, exporting
IOCs, and watching a brand over time. All of it is `WebPivot/tools/evidence_report.py`,
`WebPivot/tools/ct_monitor.py`, and a few `pivot_extract.py` flags. **A WebPivot run is only "done"
when it ends with a readable ICD-203 assessment, not raw JSON.**

## 🎯 Trigger: "output full report for that cluster" → the WHOLE-CASE rollup

When the analyst says **"output full report for that cluster"** (or "full report", "cluster
report", "campaign report", "report the whole cluster"), that means the **whole-case ICD-203
rollup over `cases/<case>/raw/*.json`** — NOT a single-host `--report`. The goal of this workflow
is cluster attribution: rolling every domain **and every analyzed binary** (BinaryPivot JSON lands
in the same `raw/` dir) into one assessment that surfaces the shared identifiers exposing the
operator's real identity. Run this, and lead with its BLUF + Key Judgments + Confirmed Sub-Clusters:

```bash
# THE cluster deliverable — every host + binary in the case, one ICD-203 assessment
python3 WebPivot/tools/evidence_report.py cases/<case>/raw/*.json --case <name> \
    -o cases/<case>/assessment.md
# share-ready IOC bundle for the whole cluster
python3 WebPivot/tools/evidence_report.py cases/<case>/raw/*.json --case <name> \
    --misp cases/<case>/iocs.misp.json
```

A single-domain `--report` (below) is only for eyeballing one page in isolation — it is **not** the
cluster deliverable and should not be presented when the request was for the cluster.

## Finished-intelligence reporting (ICD-203 / CIA analytic tradecraft) — `WebPivot/tools/evidence_report.py`

Two levels, both in US IC style: classification banner, **BLUF**, **Key Judgments** with ICD-203
estimative language (*almost certainly / likely / roughly even chance*) kept distinct from
calibrated **analytic confidence** (high/moderate/low), a clean fact-vs-assessment split, and an
intelligence-gaps section.

### Per host — `--report`
```bash
python3 tools/pivot_extract.py <host> --report [PATH] --case <name>
```
Bare `--report` prints to stdout; `--report PATH` writes a file. **Reports never carry an analyst
name** (opsec — that's an attribution leak); the header stamps only Subject / Case / **Date (UTC)**. Registrar-privacy emails, CDN
edge IPs and boilerplate are **suppressed before any Key Judgment** (disclosed in a
"suppressed as noise" line); when the host is CDN/cloud-fronted the BLUF caveats that the hosting
IP has low attribution value.

### Whole case (cluster) — the campaign deliverable
```bash
python3 WebPivot/tools/evidence_report.py cases/<case>/raw/*.json --case <name> \
    -o cases/<case>/assessment.md
```
Rolls ALL hosts into **one** ICD-203 assessment: BLUF verdict, cluster **Key Judgments** (hosts
sharing ≥2 independent identity artifacts → *almost certainly one operator, high confidence*; ≥3
types → high even without a live reverse, since the types corroborate each other), a **Confirmed
Sub-Clusters** table (union-find over shared favicon / analytics / verification / SaaS token / TLS
fingerprint), a **Discovered Infrastructure** section (hosts found via origin-IP reverse — FOFA and
PDNS — not in the input set; DNS-provider nameservers and verification tokens filtered out), a
per-host facts table, and a **Suppressed-as-Noise** transparency block.

`intel.py open` writes this to `cases/<case>/assessment.md` automatically (`--no-report` to skip;
`--classification` to set the banner). The report header shows **Date (UTC)** and never an analyst
name. Present the BLUF + Key Judgments to the user (table
/ verdict / estimative wording) — never end a run by pasting raw pivot JSON.

## Court-ready evidence ledger — `--master`
```bash
python3 tools/pivot_extract.py <host> --report --master PATH.csv|.xlsx --case <name>
```
Appends one row per pivot to a master ledger, deduping on a stable `evidence_id` (re-running a host
UPDATES its rows, never duplicates; `first_collected` is preserved for chain-of-custody). CSV is
stdlib; `.xlsx` needs openpyxl (falls back to CSV). Bare `--master` + `--case` drops it into
`cases/<case>/evidence/master_pivots.csv`.

## IOC bundle for sharing — `--misp`
```bash
python3 tools/pivot_extract.py <host> --misp [PATH]                       # single host
python3 WebPivot/tools/evidence_report.py cases/<case>/raw/*.json --case <c> \
    --misp cases/<c>/iocs.misp.json                                       # whole case
```
Writes a **MISP-event JSON** of the extracted artifacts (domains, IPs, TLS cert fingerprints,
wallets, tokens, emails, socials → MISP attribute types), deduped, with registrar-privacy /
boilerplate filtered out. Importable into MISP or convertible to STIX by MISP's own exporters.

## Evidentiary screenshot — `--screenshot`
```bash
python3 tools/pivot_extract.py <host> --screenshot [PATH]   # implies --render
```
Full-page PNG of what the target actually served (phishing-kit evidence). Implies `--render`
(needs the playwright venv); path recorded in `result.archives.screenshot`. Bare flag →
`<out>.png` / `<host>.png`.

## Dead / blocked targets recover passively
If the live fetch fails (NXDOMAIN, firewall, Cloudflare block), `pivot_extract.py` falls back to
the most recent **urlscan stored DOM**, then a **Wayback** snapshot, and — even when nothing is
recoverable — still records the intended host with its passive intel (urlscan related domains/IPs)
so the target is a persisted fact, not a silent miss. `meta.recovered_via` records the source;
`--no-fallback` disables it.

## Continuous CT brand monitoring — `tools/ct_monitor.py`
A zero-dependency, poll-based stand-in for certstream (certstream is a websocket firehose needing a
websocket lib). Polls Certificate Transparency (crt.sh, Certspotter fallback), remembers seen certs
in a state file, and on each run reports only **newly-issued** certs for a brand — the fresh SANs
print as ready-to-pivot seeds.
```bash
# first run baselines silently; run on a loop/cron thereafter
python3 tools/ct_monitor.py watch brand-a.example brand-b.example --state "$CASE/ct_state.json"
python3 tools/ct_monitor.py watch -f brands.txt --state "$CASE/ct_state.json" --json
```
Domain monitoring is reliable (include-subdomains); a bare `%keyword%` is best-effort (crt.sh
throttles broad LIKE queries). Feed the emitted seed domains straight into `intel.py open`.
