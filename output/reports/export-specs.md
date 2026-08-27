# Export Specs

Schema definitions for case data export. Machine-readable formats.

---

## Format Options

| Format | Use case | Schema type |
|--------|----------|-------------|
| **HTML (interactive)** | **Primary deliverable — analyst→exec; self-contained & OFFLINE** | **`cti-report-template.html` + `generate-cti-html.py` (report JSON injected)** |
| JSON | API integration, tooling | Object schema below |
| CSV | Spreadsheet import | Flat row per finding |
| **IOC / selector bundle** | **SIEM/TIP ingest, threat-intel sharing; comprehensive actor/victim selectors** | **STIX 2.1 + flat + CSV via `generate-cti-iocs.py` — see [`techniques/ioc-export.md`](../../techniques/ioc-export.md)** |
| STIX 2.1 | Threat intel sharing | OASIS standard (emitted as part of the IOC bundle) |
| Markdown bundle | Archive, human review | Directory + index |
| DOCX | Formal reports — **on request** / `/report legal` | Hybrid MD+JSON via `generate-cti-docx-hybrid.py` |

---

## JSON Schema

### Top-level structure

```json
{
  "schema_version": "2.0",
  "exported_at": "<ISO-8601>",
  "case": { ... },
  "subjects": [ ... ],
  "findings": [ ... ],
  "connections": [ ... ],
  "discovery_paths": [ ... ]
}
```

### case object

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `id` | string | yes | unique case identifier |
| `label` | string | yes | human name |
| `classification` | enum | yes | PUBLIC / INTERNAL / RESTRICTED / CONFIDENTIAL |
| `analyst` | string | yes | assigned analyst |
| `opened_at` | ISO-8601 | yes | |
| `updated_at` | ISO-8601 | yes | |
| `status` | enum | yes | active / closed / archived |
| `exposure_score` | integer 0–100 | no | latest aggregate score |

### subjects array item

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `id` | string | yes | `SUB-NNN` |
| `label` | string | yes | name or handle |
| `type` | enum | yes | person / org / domain / ip / handle / document |
| `confidence` | integer 0–100 | yes | |
| `verified` | boolean | yes | |
| `aliases` | string[] | no | |
| `first_seen` | ISO-8601 | no | |
| `notes` | string | no | |

### findings array item

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `id` | string | yes | `FND-NNN` |
| `subject_id` | string | yes | links to subject |
| `type` | enum | yes | credential / infrastructure / identity / exposure / behavioral / legal |
| `weight` | enum | yes | CRITICAL / HIGH / MEDIUM / LOW / INFO |
| `description` | string | yes | |
| `source_url` | string | yes | |
| `archive_url` | string | no | |
| `collected_at` | ISO-8601 | yes | |
| `confidence` | integer 0–100 | yes | |
| `tags` | string[] | no | |

### connections array item

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `id` | string | yes | `CON-NNN` |
| `from_id` | string | yes | subject or finding ID |
| `to_id` | string | yes | subject or finding ID |
| `relationship` | enum | yes | employs / owns / associated_with / operates / aliases / linked_by_finding |
| `strength` | enum | yes | confirmed / probable / possible |
| `finding_id` | string | no | supporting finding ID |

### discovery_paths array item

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `id` | string | yes | `DP-NNN` |
| `label` | string | yes | e.g. "email header analysis" |
| `status` | enum | yes | completed / null / partial / skipped |
| `subject_id` | string | yes | |
| `findings_count` | integer | no | |
| `completed_at` | ISO-8601 | no | |

---

## CSV Layout (findings export)

```
finding_id,subject_id,type,weight,description,source_url,collected_at,confidence,tags
FND-001,SUB-001,infrastructure,HIGH,"Open SMTP relay on mail.target.com",https://...,2026-03-10T08:00Z,85,"smtp;relay"
```

---

## Markdown Bundle Layout

```
export-CASE-ID-YYYYMMDD/
├── index.md          # case summary
├── subjects.md       # subject registry table
├── findings.md       # findings log table
├── connections.md    # connection map
└── citations.md      # full citation list
```

---

## HTML Export Specification (PRIMARY)

### Generation

```bash
S="$SKILL_DIR/scripts"
uv run "$S/generate-cti-html.py" "CTI-REPORT-[CASE-ID]-[DATE].json" "CTI-REPORT-[CASE-ID]-[DATE].html"
# no uv installed: python3 "$S/generate-cti-html.py" …   (Windows: py …)
```

The generator injects the report JSON into `cti-report-template.html` (replacing the
`__CTI_CASE_DATA__` data island, with `<` escaped for `</script>` safety) and writes a
single file. **Stdlib only — no external dependencies.**

### Guarantees

- **Self-contained & OFFLINE** — all CSS/JS inlined; no CDN, fonts, scripts, or network calls. Safe for air-gapped / classified handling; leaks no "report-opened" telemetry.
- **Zero toolchain to view** — opens in any browser, on any OS.
- Charts, the 2D force-directed entity graph, topology, timeline and the indicator extraction all run client-side in vanilla JS/SVG (no D3 / Chart.js).

### What's included

| Element | Rendering |
|---------|-----------|
| Classification banner | Top + bottom, colored by OPEN / INTERNAL / RESTRICTED / CONFIDENTIAL |
| Overview | KPI cards, exposure gauge, finding-type pie, severity bars, indicators-by-role, traffic/geo (if `visitor_stats`) |
| Entities | Profile cards by type with role chips (actor / victim / infra / …), confidence, aliases |
| Findings | Severity-colored cards; sortable; severity filter; source links |
| Network graph | Draggable / zoomable 2D force-directed graph; click node → detail drawer; filter by type; search-highlight |
| Topology | Org → domain → host tiers |
| Timeline | Interactive event timeline |
| Indicators & Selectors | Grouped: network IOCs, contacts, identities, social, messaging, financial, geo + attribution; copy / copy-all; defang toggle |
| Sources / Gaps / Recommendations / Caveats | Tables and lists |
| Search · menus · themes · print | Global search, category nav, dark/light toggle, print-to-PDF stylesheet |

### Optional enrichment fields (backward-compatible)

Used by the HTML report and the IOC export when present; safely ignored otherwise:

| Field | Type | Purpose |
|-------|------|---------|
| `subjects[].role` | enum: actor / victim / infrastructure / associate / witness | Role chips + actor↔victim attribution (otherwise inferred from type/links) |
| `subjects[].selectors[]` | `{type, value, platform, url}[]` | Contact/social points attached to a person/org (victim phone, actor Telegram/LinkedIn…) |
| `indicators[]` | `{type, value, category, role, confidence, source_url}[]` | Analyst-curated indicators forced into the export verbatim |

---

## DOCX Export Specification

### Generation Method

**Primary: hybrid generator** (`generate-cti-docx-hybrid.py`) — full narrative from the Markdown **plus** charts/diagrams from the JSON (zero content loss). This is the DOCX path `SKILL.md` and `AGENTS.md` prescribe; produce it on request / for `/report legal`:

```bash
# Narrative (MD) + charts/diagrams (JSON) — the primary DOCX
uv run ~/.claude/skills/cti-expert/scripts/generate-cti-docx-hybrid.py \
  "${MD_FILE}" "${JSON_DATA_FILE}" "${DOCX_FILE}"
```

**Fallback 1: JSON-only generator** (`generate-cti-docx.py`) — charts + structured data, no pandoc required (use when the Markdown narrative is unavailable):

```bash
uv run ~/.claude/skills/cti-expert/scripts/generate-cti-docx.py \
  "${JSON_DATA_FILE}" "${DOCX_FILE}"
```

The JSON-only generator (`scripts/generate-cti-docx.py`) produces:
- Professional cover page with "CTI REPORT" title
- Table of contents
- Styled headings, tables, and finding cards
- Pie chart (finding type distribution)
- Bar chart (severity distribution)
- Risk gauge (exposure score 0-100)
- Timeline chart (chronological events)
- Entity relationship diagram (networkx)
- Network topology diagram
- Header/footer with classification and page numbers

**Fallback 2: MD-only** (`generate-cti-docx-hybrid.py "${MD_FILE}" "${DOCX_FILE}"`) — styled narrative, no charts. Plain pandoc remains available too:

```bash
command -v pandoc >/dev/null 2>&1 || apt install -y pandoc
pandoc "${MD_FILE}" -o "${DOCX_FILE}" --from markdown --to docx --standalone
```

### Naming Convention

```
CTI-REPORT-[CASE-ID]-[YYYY-MM-DD].md        # Markdown source
CTI-REPORT-[CASE-ID]-[YYYY-MM-DD].docx      # Word document (rich format)
CTI-REPORT-[CASE-ID]-[YYYY-MM-DD].json      # Structured data (input to DOCX generator)
```

### What's Included in Rich DOCX

| Element | DOCX Rendering |
|---------|---------------|
| Cover page | "CTI REPORT" title, case metadata, classification |
| Table of contents | Word TOC field (update on open) |
| Headings | Word heading styles (H1–H3) with navy/cyan colors |
| Tables | Styled Word tables with colored headers |
| Pie chart | Finding type distribution (embedded PNG) |
| Bar chart | Severity distribution (embedded PNG) |
| Risk gauge | Semi-circular exposure score meter (embedded PNG) |
| Timeline | Chronological event chart (embedded PNG) |
| Entity diagram | NetworkX relationship map (embedded PNG) |
| Network topology | Infrastructure topology diagram (embedded PNG) |
| Header | Classification + report ID |
| Footer | Page numbers + report ID |
| Finding cards | Severity-colored styled tables per finding |
| Sources table | Formatted citation table |

### Mandatory Auto-Save Rule

**Every `/report`, `/brief`, and `/case` command must auto-save the default export set** — `.md` + `.html` + `.json` + `.csv` + the IOC bundle (`.stix.json` / `.txt` / `.csv`) — to disk. No user action required; files appear in CWD or `./osint-reports/` if it exists. Confirm all paths to the user after saving. DOCX is generated only on request (`/report docx`) or for `/report legal`. In `--yolo`, save the default set with no prompt; in interactive mode, offer DOCX/PDF at the end.

### Redacted variant (`/redact`) — opt-in, never automatic

The default export set is **unredacted** — it is the analyst's working record. A redacted copy
is a deliberately *weaker* artifact, so it is only produced when asked for: `/redact`, or
`/case … --redact`. That way no one silently works from a degraded report, and no one hands
over PII by accident either.

```bash
S="$SKILL_DIR/scripts"
uv run "$S/redact.py" REPORT.md   -o REPORT.redacted.md   --map REPORT.map.json
uv run "$S/redact.py" REPORT.json -o REPORT.redacted.json --map REPORT.map.json   # same map
uv run "$S/redact.py" REPORT.csv  -o REPORT.redacted.csv  --map REPORT.map.json
# reverse it later
uv run "$S/redact.py" --restore REPORT.redacted.md --map REPORT.map.json -o REPORT.restored.md
```

- Pass the **same `--map`** across all files of one case so a given selector carries the same
  placeholder everywhere (`[EMAIL_1]` means one address across the .md, .json and .csv).
- Infrastructure (`URL`/`DOMAIN`/`IPV4`/`IPV6`) is **not** redacted by default — in a CTI
  report the actor's infrastructure is the subject of the analysis, not incidental PII. Add
  `--all-types` when the recipient must not see it either.
- **Never ship the map with the redacted report.** The map is the key; it carries the same
  classification as the original.
- Omitting `--map` makes the redaction irreversible — the tool warns loudly when you do.

---

---

## IOC Export

**Command:** `/report ioc [--format stix|flat|csv]`

Exports Indicators of Compromise extracted from case subjects as standalone machine-readable files for ingestion into SIEMs, threat intelligence platforms, and sharing with external parties.

**Three formats available:**

| Format | Output File | Best For |
|--------|-------------|----------|
| `stix` | `IOC-{CASE_ID}-{date}.stix.json` | TAXII feeds, OpenCTI, MISP |
| `flat` | `IOC-{CASE_ID}-{date}.txt` | Firewall blocklists, grep pipelines |
| `csv`  | `IOC-{CASE_ID}-{date}.csv` | Excel, Splunk lookup tables, bulk import |

**IOC type coverage:** IPv4/IPv6 addresses, domains, URLs, email addresses, file hashes (MD5, SHA-1, SHA-256), usernames.

**Inclusion filter:** Only subjects with `confidence >= 60` and `verified = true` are exported by default. Override with `--min-confidence <n>`.

Full specification, STIX bundle template, flat list format, and CSV column definitions:
**[`techniques/ioc-export.md`](../../techniques/ioc-export.md)**

---

*See also: [`output/reports/format-catalog.md`](./format-catalog.md) | [`output/reports/citation-guide.md`](./citation-guide.md)*
