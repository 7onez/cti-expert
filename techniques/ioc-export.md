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
3. **Findings** — regex sweep of `description` + `tags`, attributed to the linked subject's role.
   `source_url` is PROVENANCE (kept as the record's `source`), never scanned; a finding marked
   `ioc_scan: false` (analyst-graded, indicators tagged explicitly on its subjects) is not swept.
4. **Sources** — provenance only; a `sources[]` row is scanned only when tagged `"indicator": true`.
   Cited registries / search platforms / scam-check sites in
   `scripts/references/ioc_reference_hosts.json` are never harvested from any prose.
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
| md5 / sha1 / sha256 | `file` SCO with `hashes` (one hash per object) |
| username / social / messaging | `user-account` SCO (`account_login`; `account_type` = the platform, `twitter` / `facebook` / `skype` from `account-type-ov` where one exists) |
| name / org-name | `identity` SDO (`identity_class` individual / organization) |
| phone / wallet / alias / location / device | `x-cti-selector` custom object (STIX 2.1 §11.2, deprecated mechanism; `selector_type`, `category`, `value`, `role`) |
| each network IOC | an `indicator` SDO with a STIX `pattern` |
| connection | `relationship` SRO (`source_ref` → `target_ref`; reach links described "can reach / contacted") |
| case TLP marking | one TLP 2.0 `marking-definition`, referenced by every object's `object_marking_refs` |

A producer `identity` SDO (`identity_class: system`) is emitted and referenced by
`created_by_ref`. The whole set is wrapped in a `bundle`.

### What the exporter guarantees

Checked by `tests/test_stix_conformance.py` (stdlib only, no `stix2`; registered in `scripts/audit.sh` §6)
against the OASIS STIX 2.1 Standard:

- **Identifiers** are `<type>--<RFC 4122 UUID>`, the prefix equals `type`, and no UUID repeats within
  the bundle (§2.9). Type and property names are lowercase, 3–250 characters (§3.1).
- **`spec_version: "2.1"`** on every object; none on the bundle (§8).
- **Timestamps** are RFC 3339 UTC with a `Z` and millisecond precision; `modified` ≥ `created` (§2.16, §3.2).
  Versioned objects (identity, indicator, relationship, the custom selector) carry both.
- **Indicators** have `pattern_type: "stix"`, `pattern_version: "2.1"` and `valid_from`; string literals
  in the pattern escape only `'` and `\` (§4.7, §9).
- **Confidence** is an integer 0–100. An unstated confidence is omitted (§3.2: absent = unspecified),
  never exported as `0`, which would assert "no confidence".
- **SCO ids are deterministic** UUIDv5s in namespace `00abedb4-aa42-466c-9c01-fed23315a9b7` over the
  RFC 8785 canonical JSON of the ID Contributing Properties (`value`; `hashes` with one hash;
  `account_type` + `account_login`) (§2.9, §3.4). Another producer emitting the same value gets the
  same id, and a repeated value collapses to one object. SCOs carry no `created`, `modified`,
  `created_by_ref`, `labels` or `confidence` (not applicable to SCOs).
- **References resolve inside the bundle**: `created_by_ref`, `object_marking_refs`, `source_ref`,
  `target_ref`; relationship endpoints are SDOs/SCOs, and `relationship_type` is `[a-z0-9-]`
  (e.g. `linked_to` becomes `linked-to`; an unusable value becomes `related-to`) (§5.1).
- **TLP** uses the five official TLP 2.0 marking-definition objects published by the OASIS CTI TC
  (extension `extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d`), copied verbatim, never
  minted: CLEAR `…94868c89-83c2-464b-929b-a1a8aa3c8487`, GREEN `…bab4a63c-aed9-4cf5-a766-dfca5abac2bb`,
  AMBER `…55d920b0-5e8b-4f79-9ee9-91f868d9b421`, AMBER+STRICT `…939a9414-2ddd-4d32-a0cd-375ea402b003`,
  RED `…e828b379-4e03-4974-9ac4-e53a884c97c1`. The level is the most restrictive marking across
  `case.classification`, `case.tlp`, `classification` and `tlp`. Bare levels and `TLP:` prefixes are
  accepted case-insensitively, including spaced `AMBER + STRICT`; the retired TLP 1.0 label WHITE is
  read as `TLP:CLEAR`. With no marking the default is `TLP:AMBER`. An unreadable marking stops the
  STIX export unless `--tlp LEVEL` sets the marking explicitly. REPORT.json keeps every readable
  source in `tlp_sources` and unreadable values in `tlp_unreadable`, so an unreadable marking in one
  file can never hide a RED in another: any recorded readable RED requires `--allow-red`, even
  with `--tlp`; an explicit `--tlp` less restrictive than the case's strictest readable marking is
  refused (exit 2, nothing written) unless `--allow-downgrade` is given, in which case the downgrade
  warning still prints, and a RED case exported below RED needs both flags. `/misp-export` applies
  the same rule with the same flags.

### What it does not guarantee

- **No `observed-data` or `sighting`.** SCOs stand alone; indicators are not linked to the SCO they
  match. When or how often a value was seen is not encoded. A consumer that needs this must build it.
- **No `indicator_types`, `kill_chain_phases` or `valid_until`.** `valid_from` is export time, not
  first-seen. `labels` carry the category and role, not an indicator type.
- **Phones, wallets, aliases, locations and devices** use the deprecated custom-object mechanism
  (`x-cti-selector`). A strict consumer MAY drop them (§11). `name` / `org-name` identities and the
  custom selector use random UUIDv4 ids, so they do not deduplicate across exports.
- **`relationship_type`** is the case's own verb, normalised, not necessarily a spec-defined
  relationship for that source/target pair.
- **No full validation.** The test checks the MUST rules above; it does not parse the pattern
  grammar or validate the JSON schema. Bundle custom properties (`x_cti_generator*`) may be
  dropped by consumers (§8).
- **TLP 2.0 in STIX is an extension.** Consumers that know only the STIX 2.1 §7.2.1.4 TLP 1.0
  objects will not recognise these markings. The marking `name` still states the label.

```json
{
  "type": "bundle",
  "id": "bundle--{uuid4}",
  "objects": [
    {"type": "marking-definition", "spec_version": "2.1", "id": "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421", "created": "2022-10-01T00:00:00.000Z", "name": "TLP:AMBER", "extensions": {"extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d": {"extension_type": "property-extension", "tlp_2_0": "amber"}}},
    {"type": "identity", "spec_version": "2.1", "id": "identity--{uuid4}", "created": "{ISO}", "modified": "{ISO}", "name": "CTI Expert case {CASE_ID}", "identity_class": "system", "object_marking_refs": ["marking-definition--55d920b0-…"]},
    {"type": "domain-name", "spec_version": "2.1", "id": "domain-name--{uuid5}", "value": "{domain}", "object_marking_refs": ["…"]},
    {"type": "user-account", "spec_version": "2.1", "id": "user-account--{uuid5}", "account_login": "{handle}", "account_type": "telegram", "object_marking_refs": ["…"]},
    {"type": "x-cti-selector", "spec_version": "2.1", "id": "x-cti-selector--{uuid4}", "created": "{ISO}", "modified": "{ISO}", "created_by_ref": "identity--{uuid}", "selector_type": "phone", "category": "contact", "value": "{phone}", "role": "victim", "object_marking_refs": ["…"]},
    {"type": "indicator", "spec_version": "2.1", "id": "indicator--{uuid4}", "created": "{ISO}", "modified": "{ISO}", "created_by_ref": "identity--{uuid}", "name": "domain {domain}", "pattern": "[domain-name:value = '{domain}']", "pattern_type": "stix", "pattern_version": "2.1", "valid_from": "{ISO}", "confidence": 90, "labels": ["network", "infrastructure"], "object_marking_refs": ["…"]},
    {"type": "relationship", "spec_version": "2.1", "id": "relationship--{uuid4}", "created": "{ISO}", "modified": "{ISO}", "relationship_type": "communicated-with", "source_ref": "identity--{actor}", "target_ref": "x-cti-selector--{victim}", "description": "can reach / contacted", "object_marking_refs": ["…"]}
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
