# IOC / Indicator & Selector Export

Spec for exporting **every indicator that can profile or reach an actor or a victim** —
not just classic network IOCs — in machine-readable formats for SIEM/TIP ingest and
threat-intel sharing.

> **Generator:** [`scripts/generate-cti-iocs.py`](../scripts/generate-cti-iocs.py) (PEP 723 / `uv run`, stdlib-only).
> The interactive HTML report ([`scripts/cti-report-template.html`](../scripts/cti-report-template.html))
> performs the **same** extraction client-side for its *Indicators & Selectors* panel — the
> patterns and category model below are the single source of truth for both; keep them in sync.

---

## Command

```
/report ioc [--format stix|flat|csv|all]
```

```bash
S="$SKILL_DIR/scripts"
uv run "$S/generate-cti-iocs.py" "CTI-REPORT-[CASE-ID]-[DATE].json" "IOC-[CASE-ID]-[DATE]" --format all
# single format: --format stix | flat | csv   (then arg2 is the exact output path)
```

`--format all` (default) writes `<prefix>.stix.json`, `<prefix>.txt`, and `<prefix>.csv`.
The IOC bundle is part of the **default auto-save export set** (see `output/reports/export-specs.md`).

---

## Category model

Every extracted indicator carries a **category**, a **type**, a **value**, a **role**, a
**confidence**, and (where known) a **platform** and **source**.

| Category | Types | Why it matters |
|----------|-------|----------------|
| `network` | `ipv4`, `ipv6`, `domain`, `url`, `md5`, `sha1`, `sha256`, `device` | Classic IOCs — infrastructure & malware |
| `contact` | `email`, `phone` | **How a threat actor reaches a victim** (and vice-versa) |
| `identity` | `name`, `org-name`, `username`, `alias` | Profiles the actor / victim |
| `social` | platform handle (LinkedIn, X, Facebook, Instagram, GitHub, TikTok, Reddit, YouTube, Medium, Bluesky, VK, Threads…) | Web presence; pivot & attribution |
| `messaging` | Telegram, WhatsApp, Discord, Signal, Skype | Direct outreach channels |
| `financial` | `btc-wallet`, `eth-wallet`, `iban`, `bank-account`, `bic`, payment handles | Money flow, monetization. **IBANs are mod-97 verified before export** — a checksum-invalid account on a payment page is a *behavioural* finding, not an indicator. See [`fiat-payment-osint.md`](fiat-payment-osint.md) |
| `geo` | `location` | Physical nexus |
| *attribution* | relationship edges between subjects | **Who is linked to / can reach whom** (actor ↔ victim ↔ associate) |

The goal is **comprehensive coverage**: anything that can profile an actor or a victim, or
that a threat actor could use to reach victims, is captured.

---

## Role model

Each indicator inherits the **role** of the subject it came from:

| Role | Meaning |
|------|---------|
| `actor` | Threat actor / operator selector |
| `victim` | Targeted/affected party selector |
| `infrastructure` | Hosting, network, domains, devices |
| `associate` | Linked third party |
| `witness` | Reporter / observer |
| `unknown` | Role not determined |

Role comes from `subjects[].role` when present; otherwise it is inferred (network types →
`infrastructure`; everything else → `unknown`). Set `role` explicitly in the report JSON to
drive clean actor/victim separation in both the bundle and the HTML report.

---

## Extraction sources

1. **Subjects** — typed by `subject.type` (see mapping below); plus `aliases[]` (a domain's
   aliases stay `network/domain`, a person's stay `identity/alias`); plus attached
   `selectors[]` (`{type,value,platform,url}`); plus a regex sweep of `notes`.
2. **Top-level `indicators[]`** — analyst-curated entries forced in verbatim.
3. **Findings** — regex sweep of `description` + `source_url` + `tags`, attributed to the
   linked subject's role.
4. **Sources** — `source.url` scanned for social/messaging profile links.
5. **Connections** → **attribution** edges (with a `reach` flag for `communicated_with` /
   `reaches` / `contacted` relationships).

All indicators are **de-duplicated** by `(category, type, value)`, keeping the highest
confidence and the most specific role.

### Subject-type → indicator mapping

| `subject.type` | category / type |
|----------------|-----------------|
| `domain` | network / domain |
| `url` | network / url |
| `ip`, `network_addr` | network / ipv4 |
| `device` | network / device |
| `email` | contact / email |
| `phone` | contact / phone |
| `username`, `handle` | identity / username |
| `person`, `individual` | identity / name |
| `organization`, `org` | identity / org-name |
| `wallet`, `crypto_address` | financial / wallet |
| `iban` | financial / iban |
| `bank_account` | financial / bank-account |
| `bic`, `swift` | financial / bic |
| `location` | geo / location |

---

## Canonical extraction patterns

Used identically by the Python generator and the HTML report's JS. Research/tool/source
hosts (`haveibeenpwned.com`, `shodan.io`, `crt.sh`, `virustotal.com`, …) are filtered from
domain/URL IOCs — they are *where we looked*, not indicators of the target.

```
ipv4    \b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b
ipv6    \b(?:[A-F0-9]{1,4}:){3,7}[A-F0-9]{1,4}\b           (i)
url     \bhttps?://[^\s"'<>)\]]+                            (i)
email   \b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b           (i)
domain  \b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b   (i, after stripping urls+emails)
md5     \b[a-f0-9]{32}\b      sha1  \b[a-f0-9]{40}\b      sha256  \b[a-f0-9]{64}\b   (i)
btc     \b(?:bc1[a-z0-9]{25,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b
eth     \b0x[a-fA-F0-9]{40}\b
```

Phone numbers are **not** regex-swept from free text (too noisy) — they come only from
`phone` subjects and explicit `selectors[]`. Social/messaging handles are detected by
matching known platform URL shapes (e.g. `linkedin.com/in/<h>`, `t.me/<h>`, `wa.me/<phone>`)
**before** a URL is recorded as a generic `network/url`, so a profile link becomes a
`social`/`messaging` selector rather than a bare URL.

---

## STIX 2.1 mapping

| Indicator | STIX object |
|-----------|-------------|
| ipv4 / ipv6 / domain / url / email | `ipv4-addr` / `ipv6-addr` / `domain-name` / `url` / `email-addr` SCO |
| md5 / sha1 / sha256 | `file` SCO with `hashes` |
| username / social / messaging | `user-account` SCO (`account_login`, `account_type` = platform) |
| name / org-name | `identity` SDO (`identity_class` individual / organization) |
| phone / wallet / alias / location / device | `x-cti-selector` custom SCO (`selector_type`, `category`, `value`, `role`) |
| each network IOC | an `indicator` SDO with a STIX `pattern` |
| connection | `relationship` SDO (`source_ref` → `target_ref`; reach links described "can reach / contacted") |

A producer `identity` SDO (`identity_class: system`) is emitted and referenced by
`created_by_ref`. The whole set is wrapped in a `bundle`.

```json
{
  "type": "bundle",
  "id": "bundle--{uuid4}",
  "objects": [
    {"type": "identity", "spec_version": "2.1", "id": "identity--{uuid4}", "name": "cti-expert case {CASE_ID}", "identity_class": "system"},
    {"type": "domain-name", "spec_version": "2.1", "id": "domain-name--{uuid4}", "value": "{domain}"},
    {"type": "user-account", "spec_version": "2.1", "id": "user-account--{uuid4}", "account_login": "{handle}", "account_type": "telegram"},
    {"type": "x-cti-selector", "spec_version": "2.1", "id": "x-cti-selector--{uuid4}", "selector_type": "phone", "category": "contact", "value": "{phone}", "role": "victim"},
    {"type": "indicator", "spec_version": "2.1", "id": "indicator--{uuid4}", "created_by_ref": "identity--{uuid}", "name": "domain {domain}", "pattern": "[domain-name:value = '{domain}']", "pattern_type": "stix", "valid_from": "{ISO}", "confidence": 90, "labels": ["network", "infrastructure"]},
    {"type": "relationship", "spec_version": "2.1", "id": "relationship--{uuid4}", "relationship_type": "communicated-with", "source_ref": "identity--{actor}", "target_ref": "identity--{victim}", "description": "can reach / contacted"}
  ]
}
```

---

## Flat list

Grouped by category, one `type:value` per line — compatible with most SIEM/grep pipelines.
An `ATTRIBUTION` block lists the relationship edges.

```
# CTI Expert indicator/selector export
# Case: {CASE_ID}   Generated: {ISO}
# Fields: type:value  (role / confidence in CSV/STIX export)

# --- NETWORK (n) ---
domain:target.com
ipv4:203.0.113.50
sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

# --- CONTACT (n) ---
email:victim@client.example
phone:+15555550123

# --- SOCIAL (n) ---
LinkedIn:jordanvale
GitHub:jvale

# --- MESSAGING (n) ---
Telegram:jv_ops

# --- ATTRIBUTION / RELATIONSHIPS (n) ---
rel:Jordan Vale|communicated_with [reach]|victim@client.example
```

---

## CSV

```csv
category,type,value,role,confidence,platform,source,subject_id
network,domain,target.com,infrastructure,98,,dig axfr …,SUB-001
contact,email,victim@client.example,victim,92,,https://…,SUB-005
social,LinkedIn,jordanvale,actor,82,LinkedIn,https://linkedin.com/in/jordanvale,SUB-002
messaging,Telegram,jv_ops,actor,66,Telegram,https://t.me/jv_ops,SUB-006
```

| Column | Notes |
|--------|-------|
| `category` | network / contact / identity / social / messaging / financial / geo |
| `type` | indicator type within the category (or platform name for social/messaging) |
| `value` | normalized indicator value |
| `role` | actor / victim / infrastructure / associate / witness / unknown |
| `confidence` | 0–100 |
| `platform` | social/messaging platform, when applicable |
| `source` | originating `source_url` |
| `subject_id` | linked subject ID |

---

## Output files

Auto-saved alongside the case report per the `output/reports/export-specs.md` auto-save rule:

```
IOC-{CASE_ID}-{YYYY-MM-DD}.stix.json   # STIX 2.1 bundle (SCOs + indicators + identities + relationships)
IOC-{CASE_ID}-{YYYY-MM-DD}.txt         # flat list, grouped by category, with attribution block
IOC-{CASE_ID}-{YYYY-MM-DD}.csv         # full indicator table (columns above)
```

---

## Cross-References

- `scripts/generate-cti-iocs.py` — the extractor (canonical implementation)
- `scripts/cti-report-template.html` — the same extraction, client-side, for the HTML *Indicators & Selectors* panel
- `output/reports/export-specs.md` — HTML / IOC / DOCX export specs + optional `role` / `selectors` / `indicators` schema fields
- `engine/subject-registry.md` — subject type definitions and confidence fields
- `engine/finding-framework.md` — finding types used as STIX indicator labels
