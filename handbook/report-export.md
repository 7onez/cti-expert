# Report export — file export steps, formats, visual outputs, connectors

The detail behind the Deliver contract in `SKILL.md` §8. **Read this before the Deliver phase of
any `/report`, `/brief` or `/case` run**: it defines the import prompt, the always-saved base
bundle, the presentation prompt and every generator command.

### Mandatory File Export (CRITICAL)

**Every `/report`, `/brief`, and `/case` command runs four steps at the end of delivery — an import prompt, then the always-saved base bundle, then the presentation prompt, then an export confirmation whenever HTML is among the outputs:**

**Step 0 — ASK whether to import more manually-collected evidence** (before building ANYTHING, so it enriches every artifact). Ask the user — via `AskUserQuestion` — **"Import more evidence data collected by manual investigation? (extra findings, subjects, indicators, selectors, timeline events, sources, screenshots, notes)"**. If **yes**, fold it into the report JSON (see Step 1) BEFORE Step A:
- **Findings / subjects / indicators / selectors / timeline / sources** — append them to the corresponding arrays of the report JSON (same schema as Step 1); each still needs a `source_url`/source note and a confidence.
- **Screenshots / evidence images** — base64-embed into `evidence_images[]` with `evidence-images.py`: explicit files `uv run "$SKILL_DIR/scripts/evidence-images.py" shot1.png shot2.png --caption "…" [--finding FND-003] --into REPORT.json`, or a whole case dir `… --case <case-dir> --into REPORT.json`.
Re-run the Step 1 build / dash-normalizer after merging, then continue. Only once the manual evidence is in the JSON do Step A and Step B run — so the base bundle, the IOC bundle, and the chosen presentation report all include it. If **no**, proceed straight to Step A. (`--yolo`/guided-auto skip this prompt.)

**Step A — ALWAYS auto-save the base data bundle** (no prompt, every run):

| # | Format | File | Role |
|---|--------|------|------|
| 1 | **Markdown** | `CTI-REPORT-[CASE-ID]-[YYYY-MM-DD].md` | Diffable, greppable source of truth; also the input to the HTML/DOCX/PDF generators. **Pipeline case** (`/cti` · `/case` · `/harness`): composed from the case directory by `python3 "$SKILL_DIR/scripts/backend/intel.py" house-report <CASE-ID> --md-only` (written under `cases/<CASE-ID>/report/`), never hand-authored; no case directory → the analyst-authored report |
| 2 | **JSON** | `CTI-REPORT-[CASE-ID]-[YYYY-MM-DD].json` | Structured case data (the report JSON below); feeds the generators and downstream tooling |
| 3 | **CSV** | `CTI-REPORT-[CASE-ID]-[YYYY-MM-DD].csv` | Findings **and** indicators, one row each with a `kind` column, credit + caveat header, formula-leading cells defused; written from the **finalized** JSON (after the Step 0 merge) by `build_report_data.py --from-report <JSON> --csv <CSV>`, for spreadsheets / SIEM lookups |
| 4 | **IOC / selector bundle** | `IOC-[CASE-ID]-[YYYY-MM-DD].{stix.json,txt,csv,jsonl}` | Comprehensive indicators & selectors — STIX 2.1 + flat + CSV + JSONL |

**Step B — ASK which presentation report to render**, then build the choice on top of the base bundle. This prompt is the default (interactive) behavior:

| Choice | Format | Builder |
|--------|--------|---------|
| **a** | **PDF** — the **editorial house report** (IntelReport: cover, Roman-numbered sections I–XI, Methodology with the Admiralty × ICD-203 scales, relationship graph, entity relationship map, attribution inference chain, temporal view, registration heatmap + domain × shared-indicator matrix, ICD-203 × Admiralty confidence scatter, a captured landing page per estate host inline in the cluster section, per-domain dossiers, Appendices A–E incl. glossary). For a case dir this is **deterministic**: `python3 "$SKILL_DIR/scripts/backend/intel.py" house-report <CASE-ID>` writes `cases/<CASE-ID>/report/CTI-REPORT-<CASE-ID>-<date>.{pdf,docx,house.md}` + figures. **Egress caveat:** hosts with no screenshot on disk are rendered in headless Chromium through the research-egress proxy policy (proxied, or direct only if the store allows it; blocked → stated in the report, never forced); when the live page will not render or renders empty, a public web-scan screenshot or a rendered web-archive snapshot stands in — captioned as such, dated by the archive, linked in Appendix B, and flagged as a previous owner's page when it predates the current registration; `--no-screenshots` keeps the build fully offline, `--no-archive-fallback` disables the stand-in, `--max-screenshots N` / `--screenshot-timeout S` bound it. The four analytic charts are the dashboard's own (`scripts/cti_report_figures.py`, shared with `generate-cti-docx-hybrid.py`), drawn from `report/report-data.json` that `build_report_data.py` derives from the case dir. No case dir → `generate-cti-docx-hybrid.py … --pdf` (dashboard style) | `intel.py house-report` · fallback `generate-cti-docx-hybrid.py --pdf` |
| **b** | **DOCX** — the editable twin of (a), emitted by the same `house-report` run; dashboard-style alternative (charts + confidence matrix + heatmaps) via `generate-cti-docx-hybrid.py` | `intel.py house-report` · alt `generate-cti-docx-hybrid.py` |
| **c** | **HTML** — interactive, self-contained, OFFLINE (charts + 2D entity graph + topology + timeline + indicator panel + search); the primary human-facing deliverable | `generate-cti-html.py` |
| **d** | **All** — build PDF **and** DOCX **and** HTML | all of the above |

**Step C — CONFIRM before exporting HTML** (choice **c** or **d**, and the explicit `/report html`). Before running `generate-cti-html.py`, get the Blueprint plan — `python3 "$SKILL_DIR/scripts/cti_archify.py" REPORT.json --plan` prints, offline and without rendering, what **auto** and **force** would embed (e.g. `auto  embed — apex level: 10 of 45 apexes shown for 105 hosts …` / `force embed — … 23 of 45 apexes …`) — state it with the output path, then ask, via `AskUserQuestion`, **"Export the HTML report now? Blueprint: (1) Auto — full graph if it fits, else the compact apex-level fold (recommended) · (2) Force — the widest map Archify's grid holds (`CTI_ARCHIFY=force`: up to 25 nodes, smaller labels, may need the frame's zoom) · (3) No Blueprint (`CTI_ARCHIFY=0`) · (4) Skip the HTML export"**. Run the generator with the matching env var and quote its `Blueprint (Archify):` line back so the analyst sees what was embedded (or the renderer's exact rejection). `--yolo`/guided-auto skip this prompt and build with Auto.

> **Why two PDF/DOCX builders.** `house-report` composes the *document* — the analyst assessment folded
> into the house structure with figures rendered from the case data (IntelGraph Mermaid graph with a
> representative subset above 14 nodes, Graphviz inference chain from `assessment.json`, temporal view
> from the raw pivots, temporal-correlation tables from the timeline events JSON, landing pages from
> `screenshots/` + `evidence/screenshots/manifest.json` with full SHA-256 in the evidence ledger) and
> pandoc + the LaTeX house template. It scrubs internal tool / vendor / path
> names to public source classes (house Rule 12) and never emits the impersonated brand's genuine domain
> as an indicator. `generate-cti-docx-hybrid.py` is the *dashboard* rendering of the flat report JSON —
> keep it for report-JSON-only cases and for the chart appendix.
**Save location:** Current working directory, or `./osint-reports/` subdirectory if it exists.

**Attribution (MANDATORY — every exported artifact).** Every deliverable MUST credit this
skill: `Generated by CTI Expert — https://github.com/7onez/cti-expert`. The generators
inject it automatically — HTML (sidebar + page footer), DOCX (page footer, both generators),
and the IOC bundle (flat header comment, CSV header comment, STIX producer identity
`description` + bundle `x_cti_generator`). For the analyst-authored **Markdown** report,
end the file with a footer line carrying that exact credit, e.g.:
```markdown
---
*Generated by [CTI Expert](https://github.com/7onez/cti-expert) — OSINT/CTI toolkit.*
```
The JSON deliverable carries a top-level `"generator"` field (see the report-JSON schema in
Step 1) — generators ignore unknown keys, so it is safe and shipped in the file itself. Never
strip the credit — the redactor leaves it intact (it is not PII).

**The default set is unredacted** — it is the analyst's working record. A shareable variant is
**opt-in**, never automatic, so nothing is ever quietly weakened. Request it with
`/redact` or `/case … --redact`:
```bash
S="$SKILL_DIR/scripts"; R="CTI-REPORT-[CASE-ID]-[YYYY-MM-DD]"
for f in md json csv; do
  uv run "$S/redact.py" "$R.$f" -o "$R.redacted.$f" --map "$R.map.json"
done
```
One `--map` across all three files keeps a selector's placeholder identical everywhere.
Infrastructure (URL/domain/IP) stays visible even then — in a CTI report the actor's
infrastructure is the analysis, not incidental PII; add `--all-types` to cover it too.
**Never ship the `.map.json`** — it reverses the redaction.

- **Interactive mode (DEFAULT) — three prompts, in order:** (1) first ask **"Import more evidence data collected by manual investigation?"** (Step 0) and merge any supplied data into the report JSON; (2) then, after saving the base data bundle, ask — via `AskUserQuestion` — **"Which report format(s) do you want? (a) PDF · (b) DOCX · (c) HTML · (d) All"** (multi-select allowed); (3) when HTML is among them, confirm the export and its Blueprint mode (Step C: Auto · `CTI_ARCHIFY=force` · `CTI_ARCHIFY=0` · skip) before running `generate-cti-html.py`, then build exactly the chosen presentation format(s). Every choice ships alongside the base bundle (.md + .json + .csv + IOC .stix.json/.txt/.csv/.jsonl).
- **`--yolo` / guided-auto / non-interactive:** skip **all three** prompts — no evidence-import question, no export confirmation (Blueprint runs in Auto), and default to **HTML** (lightest, zero external toolchain) on top of the base bundle. `/report legal` defaults to **All** (evidentiary — a fixed Word/PDF artifact is expected).
- **Explicit subcommands bypass the format prompt** and emit that format directly on top of the base bundle: `/report html`, `/report docx`, `/report pdf`, plus the machine-only `/report json`, `/report csv`, `/report ioc`. `/report html` still runs the Step C export confirmation (it is the prompt that lets the analyst pick the Blueprint mode).
- **DOCX/PDF caveat:** two builders, two toolchains. **Case dir → `intel.py house-report`** (IntelReport: pandoc + xelatex; the editorial document with sections I–XI, both confidence scales, relationship graph, entity map, inference chain, temporal view, heatmaps, confidence scatter, landing-page captures with web-scan / web-archive stand-ins, domain dossiers, Appendices A–E; PDF and DOCX are one composition rendered twice; the landing-page step is the only egress — proxy-gated, `--no-screenshots` to skip, `--no-archive-fallback` to forbid the stand-ins). **No case dir → `generate-cti-docx-hybrid.py`** (python-docx + LibreOffice; the dashboard DOCX with the two-axis ICD-203 × Admiralty confidence matrix and the campaign heatmaps, and `--pdf` renders that same DOCX to PDF via `scripts/cti_docx_pdf.py`). Both are the heaviest, most failure-prone step: check `pandoc`, `xelatex`, `dot` and `node` — Pele's runtime for the Mermaid figures, `IntelGraph/scripts/pele_fetch.py --check` — (house) or LibreOffice (dashboard) before promising a PDF, and fall back to HTML — which needs nothing — when a toolchain is missing. `house-report` scrubs internal tool/vendor/path names and masks third-party e-mails/phones/case ids (keeping the operator's own join key); the dashboard path relies on the analyst masking the Markdown first.
- **Dash normalization (MANDATORY — covers every deliverable).** Em/en dashes (—, –) read as machine-authored, so no export may ship them. Two layers guarantee this: (1) the HTML, DOCX and pandoc PDF/DOCX generators normalize their prose automatically via `scripts/cti_text_normalize.py`; (2) for the on-disk **Markdown and JSON** deliverables — which no generator rewrites — run the normalizer in place as the final step before confirming files:
  ```bash
  S="$SKILL_DIR/scripts"; R="CTI-REPORT-[CASE-ID]-[YYYY-MM-DD]"
  uv run "$S/cti_text_normalize.py" "$R.md" "$R.json"   # rewrites — → - in place; no-op if clean
  ```
  Prefer writing plain `-` while drafting so this step is a no-op. It rewrites only when a dash is present and is safe for .md/.json/.csv alike (typographic dashes occur only inside string content, never in structural syntax).

**The HTML, JSON, CSV and IOC outputs all derive from one `report JSON`.** Build it once, then run the generators below.

**Step 1 — Build the report JSON file.** The generators expect a SPECIFIC flat format (NOT the engine `case-schema.json`).

- **For a case produced by the pipeline (`/cti` · `/case` · `/harness`) — build it deterministically. Do NOT hand-author.** Run the converter; it reads `raw/*.json`, `whois/*.json`, `assessment.md` (BLUF + recommendations), `evidence/*.json` (leak-sweep, estate-seo-sweep) and the operator ledger (`knowledge/operators.jsonl`) — and consults `clusters.json` only to flag a multi-operator case — then emits the exact flat schema below: operator/registrant subject with selectors, the full domain estate as network indicators, findings/timeline/connections, and the §2.5 exclusion set (CDN/shared IPs, registrar, nameservers) in `ioc_exclude` so no excluded value ever leaves as an IOC:
  ```bash
  uv run "$SKILL_DIR/scripts/build_report_data.py" "${INTEL_HOME:-$SKILL_DIR/intel_engine}/cases/[CASE-ID]" -o "CTI-REPORT-[CASE-ID]-[YYYY-MM-DD].json"
  ```
  Then apply the Step 0 import (merge any analyst-supplied findings/subjects/selectors/timeline) onto that JSON before rendering, and write the bundle CSV from the finalized JSON so the imported rows are in it: `uv run "$SKILL_DIR/scripts/build_report_data.py" --from-report "CTI-REPORT-[CASE-ID]-[YYYY-MM-DD].json" --csv "CTI-REPORT-[CASE-ID]-[YYYY-MM-DD].csv"` (`--csv` on the build itself is the same writer, for a report nothing is merged into). The manual schema below is the field reference for that enrichment — and the fallback when there is no case dir (e.g. a report authored purely from pasted evidence).
- **Otherwise (no case dir) — construct the JSON by hand** matching this exact structure. Reference: `scripts/sample-cti-report-data.json`.

```json
{
  "generator": "CTI Expert — https://github.com/7onez/cti-expert", // MANDATORY attribution (top-level)
  "case": {
    "id": "CTI-2026-001",          // string, case identifier
    "label": "Case Title",         // string, human-readable name
    "classification": "OPEN SOURCE", // string
    "analyst": "AI-Assisted CTI",  // string
    "date": "2026-04-08",          // ISO date
    "subject": "target.com",       // string, primary subject
    "status": "active"             // string
  },
  "executive_summary": "Full paragraph summarizing investigation findings...",
  "subjects": [
    {
      "id": "SUB-001",            // string ID (not UUID)
      "label": "target.com",      // human-readable name — REQUIRED for display
      "type": "domain",           // lowercase: domain, person, ip, organization, email, username
      "confidence": 95,           // INTEGER 0-100 (not string like "VERIFIED")
      "verified": true,           // boolean
      "aliases": ["alias1"],      // string array
      "first_seen": "2025-01-15", // ISO date string
      "notes": "Primary domain"   // string
    }
  ],
  "findings": [
    {
      "id": "FND-001",            // string ID
      "subject_id": "SUB-001",    // links to subject
      "type": "infrastructure",   // credential, infrastructure, identity, exposure, behavioral, legal
      "weight": "HIGH",           // CRITICAL, HIGH, MEDIUM, LOW, INFO — drives severity colors
      "description": "Full description of the finding...",
      "source_url": "https://...",
      "collected_at": "2026-04-08T10:00:00Z",
      "confidence": 88,           // INTEGER 0-100 (not string)
      "tags": ["tag1", "tag2"]
    }
  ],
  "connections": [
    {
      "id": "CON-001",
      "from_id": "SUB-001",       // subject ID
      "to_id": "SUB-002",         // subject ID
      "relationship": "owns",     // string describing relationship
      "strength": "confirmed"     // confirmed, probable, possible
    }
  ],
  "timeline": [
    {"date": "2025-01-15", "event": "Domain registered"}
  ],
  "sources": [
    {"name": "Source Name", "url": "https://...", "date": "2026-04-08"}
  ],
  "intelligence_gaps": [
    "Gap description string"
  ],
  "recommendations": [
    "Action item string"
  ],
  "visitor_stats": {              // optional — enables visitor intelligence charts
    "domain": "target.com",
    "monthly_visits": 150000,
    "traffic_sources": {"direct": 42, "search": 28, "referral": 15, "social": 10, "paid": 5},
    "top_countries": [{"country": "Vietnam", "share": 60}, {"country": "US", "share": 20}]
  },
  "caveats": ["Caveat string"],  // optional — overrides default methodology notes
  "evidence_images": [           // optional — screenshots that visually back findings
    {
      "caption": "Phishing login impersonating Bank X",  // human label
      "host": "phish.example",                            // optional
      "data_uri": "data:image/png;base64,....",           // REQUIRED — offline-safe base64
      "sha256": "....",                                   // citable; auto-added by evidence-images.py
      "captured_at": "2026-04-08T10:00:00Z",              // optional
      "source_url": "https://phish.example/login",        // optional
      "finding_id": "FND-001",                            // optional — ties the shot to a finding
      "subject_id": "SUB-001"                             // optional
    }
  ]
}
```

**CRITICAL FORMAT RULES:**
- `confidence` on subjects and findings MUST be an **integer** (e.g., `85`), NOT a string (e.g., `"VERIFIED"`)
- `findings` MUST be a **flat top-level array**, NOT nested inside subjects
- `label` is REQUIRED on each subject (this is what displays in the report — not `value` or `display_name`)
- `weight` on findings drives severity coloring — use CRITICAL/HIGH/MEDIUM/LOW/INFO
- `recommendations` must be an array of **strings** (not objects with `priority`/`action` keys)
- All fields shown above should be **populated with actual data** — empty strings or "N/A" defeat the purpose
- Populate `executive_summary` with a full paragraph — this is the most-read section of the report

**Optional enrichment fields (backward-compatible — used by the HTML report & IOC export when present):**
- `subjects[].role` — `actor` | `victim` | `infrastructure` | `associate` | `witness` (drives the role chips and actor↔victim attribution; otherwise inferred from type/links)
- `subjects[].selectors[]` — contact/social points attached to a person/org: `{type, value, platform, url}` (e.g. a victim's phone, an actor's Telegram or LinkedIn) — surfaced in the Indicators panel and IOC export
- `indicators[]` — analyst-curated indicators to force into the export verbatim: `{type, value, category, role, confidence, source_url}`
- `evidence_images[]` — screenshots that back findings, embedded into the HTML **Evidence** view and the DOCX **Visual Analytics → Evidence Screenshots** section (base64, offline-safe): `{caption, host, data_uri, sha256, captured_at, source_url, finding_id, subject_id}`. **`/cti` captures them automatically**: every host collected live, or recovered from a Wayback capture, gets one full-page PNG at `cases/<case>/evidence/screenshots/<host>/<UTC>.png` (sha256, custody line, seal; `HARNESS_SCREENSHOT=0` disables). Add more whenever it fits — a confirmed phishing/login page, a scam members-panel, a defacement — via the `capture_screenshot` tool (same store), or the deterministic pipeline's `--screenshots` flag. `--case` always writes under `$INTEL_HOME/cases/<id>/` whatever the cwd. Then build the array mechanically: `uv run "$SKILL_DIR/scripts/evidence-images.py" --case <case-dir> --into REPORT.json` (base64-embeds each PNG, dedupes by sha256; `--finding FND-00X` ties shots to a finding). A hostile target is shot only through the pool exit its fetch used, never direct.

**Step 2 — Generate the interactive HTML report (PRIMARY human-facing deliverable).** Self-contained, OFFLINE, zero toolchain to view — opens in any browser:
```bash
S="$SKILL_DIR/scripts"     # $SKILL_DIR = dir containing SKILL.md
uv run "$S/generate-cti-html.py" "REPORT.json" "REPORT.html"   # any OS, zero setup
# no uv installed: python3 "$S/generate-cti-html.py" "REPORT.json" "REPORT.html"   (Windows: py …)
```
It injects the report JSON into `cti-report-template.html` and renders, entirely client-side and offline (no CDN, no network calls): KPI cards, a finding-type pie, severity bars, a draggable/zoomable **2D entity graph**, **infrastructure topology**, an **event timeline**, and the **comprehensive Indicators & Selectors panel** (network IOCs + contacts + identities + social/messaging handles + wallets + actor↔victim attribution) — with global search, category menus, dark/light themes and a print-to-PDF stylesheet.

The report also embeds an interactive **Blueprint** view — the case entity graph
rendered as an [Archify](https://github.com/tt-a1i/archify) `architecture` diagram
(typed nodes, directional relationships, exposure/finding cards) and inlined into
the single offline file via an isolated iframe (theme + PNG/SVG export live inside
it). This is the one build step that uses **Node.js** (a trimmed, zero-dependency
Archify copy is vendored at `scripts/vendor/archify/`). It is best-effort: if
Node.js is unavailable, the case has no subjects, or `CTI_ARCHIFY=0` is set, the
report is still produced and the Blueprint tab is simply omitted — every other
view (including the always-present 2D entity graph) is unaffected.

Archify's architecture type draws small maps (≤ 12 nodes · 18 edges,
`cti_archify.BLUEPRINT_LIMITS`), so a dense estate is **folded to apex level**
automatically: every host under its registrable domain (PSL-aware, `Estate · N
hosts`), the long tail of apexes into one `+N more apexes` node, apexes carrying a
finding ranked first, the operator hub placed mid-row with its spokes above and
below. The full host list stays in the Network Graph and Editorial views. The
`CTI_ARCHIFY` env var selects the mode and the generator prints the outcome on its
`Blueprint (Archify):` line — quote that line back to the analyst:

| `CTI_ARCHIFY` | Blueprint |
|---|---|
| `1` (default) | full graph when it fits, else the apex-level fold, else skipped with the reason |
| `force` | past the density gate: the full graph when it has ≤ 25 nodes, else the apex fold at the widest grid Archify holds (12 spokes above and below the hub, `cti_archify.FORCE_MAX_NODES`) — more apexes, smaller labels; Archify's own validator still has the last word and any rejection is printed verbatim |
| `0` | never embedded |

It also renders two print-ready figures shared across HTML, **PDF** and **DOCX**:
an **Editorial** view — the entity map and infrastructure topology drawn as
[Diagram Design](https://github.com/cathrynlavery/diagram-design) editorial SVG
(atomic-tangerine accent on 1–2 focal nodes, hairlines, no shadows), inlined as
vector in HTML/PDF and rasterized via **cairosvg** for DOCX; and, only when a case
reveals cloud infrastructure, a **Cloud Architecture** figure applying
[Diagram AI Generator](https://github.com/carlosmgv02/diagram-ai-generator) —
real AWS/Azure/GCP/K8s provider icons via the `diagrams` library + **graphviz**.
Both are best-effort: the editorial figures fall back to the matplotlib DOCX
diagrams if cairosvg is unavailable, and the cloud figure auto-skips when no cloud
infra is detected, graphviz/`diagrams` are missing, or `CTI_CLOUD_ARCH=0` is set.

**Step 3 — Generate the comprehensive IOC / selector bundle.**
```bash
uv run "$S/generate-cti-iocs.py" "REPORT.json" "IOC-[CASE-ID]-[YYYY-MM-DD]" --format all
# single format: --format stix | flat | csv
```
Extracts EVERY indicator that profiles or can reach an actor/victim — network IOCs, emails/phones, usernames/names/aliases, social-media profiles, messaging handles, crypto wallets, and the attribution links between subjects. A finding's `source_url` and the `sources[]` list are provenance, never indicators (a `sources[]` row only when tagged `"indicator": true`); cited registries / search platforms / scam-check sites (`scripts/references/ioc_reference_hosts.json`) are never harvested from prose, and analyst-graded findings (`ioc_scan: false`) export only their explicitly tagged indicators. Full spec: [`techniques/ioc-export.md`](../techniques/ioc-export.md).

**Step 4 — DOCX (on request, or automatically for `/report legal`).** Word is no longer auto-generated by default. When the user asks for it (or for evidentiary reports), build it from the SAME report JSON + MD. The generators carry **PEP 723 inline dependency metadata**, so the simplest, most portable runner is **`uv run`** — it provisions the deps on the fly with zero venv/pip setup, identically on every OS. The generator is also **self-healing**: it forces UTF-8 output and auto-locates pandoc (including Windows `%LOCALAPPDATA%\Pandoc`), so **no `PYTHONUTF8` / PATH prelude is needed**. Replace `REPORT` with `CTI-REPORT-[CASE-ID]-[YYYY-MM-DD]`.

**Preferred — `uv run` (any OS, any agent, zero setup):**
```bash
S="$SKILL_DIR/scripts"     # $SKILL_DIR = dir containing SKILL.md (Claude Code: ~/.claude/skills/cti-expert; Codex/clone: the repo)
# Primary: HYBRID — full narrative from MD + charts/diagrams from JSON (zero content loss)
uv run "$S/generate-cti-docx-hybrid.py" "REPORT.md" "REPORT.json" "REPORT.docx"
# PDF — DOCX-STYLE document (the DOCX rendered by LibreOffice), NOT an HTML print:
uv run "$S/generate-cti-docx-hybrid.py" "REPORT.md" "REPORT.json" "REPORT.docx" --pdf
# Fallback 1: JSON-only (charts + structured data; no pandoc needed)
uv run "$S/generate-cti-docx.py" "REPORT.json" "REPORT.docx"
# Fallback 2: MD-only (styled narrative, no charts)
uv run "$S/generate-cti-docx-hybrid.py" "REPORT.md" "REPORT.docx"
```
> Both DOCX generators take `--lang en|vi` (cover, header/footer, TOC and generated appendix headings from `scripts/references/docx_i18n.json`; the Markdown body is never translated). The hybrid generator draws the campaign heatmaps only when the report JSON `verdict.malicious_supported` (from the case's `scope.json` target_class + `assessment.json` premise_verdict, `scripts/references/malicious_verdict.json`) supports a malicious classification; `--no-heatmaps` suppresses them outright.
> Windows PowerShell: set `$S = "$env:USERPROFILE\.claude\skills\cti-expert\scripts"` (Claude Code) or `"<repo>\scripts"` (Codex/clone), and use backslash paths.

**Fallback — no uv installed.** Use the OS interpreter; the script's `ensure_deps()` installs the libs on first run (via uv if present, else pip):
- macOS / Linux (Bash): `python3 "$S/generate-cti-docx-hybrid.py" "REPORT.md" "REPORT.json" "REPORT.docx"`
- Windows (PowerShell): `py "$S\generate-cti-docx-hybrid.py" "REPORT.md" "REPORT.json" "REPORT.docx"` — the Store `python3` stub will not run; use `py` or the venv python
- Last resort (no styling/charts): `pandoc "REPORT.md" -o "REPORT.docx" --from markdown --to docx --standalone`

**How the hybrid generator works:**
1. **Phase 1:** pandoc converts the MD file to a base DOCX (preserving ALL narrative content — tables, lists, formatting)
2. **Phase 2:** python-docx post-processes to add CTI professional styling, prepend cover page + TOC, and inject charts/diagrams from JSON at matching section headings

**The MD file is the primary content source.** It carries the full narrative (detailed person profiles, infrastructure tables, wallet addresses, corporate structure, legal history, etc.). The JSON file provides structured data for visual elements (charts, diagrams, the ICD-203 × Admiralty confidence matrix, and the campaign heatmaps). Using both together produces a complete report with zero content loss.

**Rich hybrid DOCX includes:** Cover page titled "CTI REPORT", table of contents, **all narrative content from MD** (every paragraph, table, list, code block), pie chart (finding types), bar chart (severity), **two-axis ICD-203 × Admiralty confidence matrix**, **campaign heatmaps** (malicious-domain registration timeline, domain×indicator correlation, domain×domain possible-relation), timeline chart, entity relationship diagram, network topology diagram, traffic/geo charts, CTI-themed styling (navy headings, styled tables), header/footer with classification and page numbers. **No overall exposure score / risk gauge** (removed). The PDF (`--pdf`) is this same DOCX rendered by LibreOffice.

**After saving, confirm all files to the user:**
```
📄 Base data bundle saved (always):
   → CTI-REPORT-CASE001-2026-03-30.md
   → CTI-REPORT-CASE001-2026-03-30.json
   → CTI-REPORT-CASE001-2026-03-30.csv
   → IOC-CASE001-2026-03-30.stix.json / .txt / .csv / .jsonl   (indicators & selectors)

📄 Presentation report (your choice) — e.g. when (c) HTML was chosen:
   → CTI-REPORT-CASE001-2026-03-30.html   (interactive — open in any browser, fully offline)
```

### Report Formats

| Format | Command | Audience |
|--------|---------|---------|
| Interactive HTML | `/report html` · choose **c** at the prompt | Everyone — analysts to execs; the primary deliverable |
| Technical INTSUM | `/report` | Analysts, security teams |
| Executive Brief | `/report brief` | Decision-makers, management |
| Plain-Language Summary | `/brief` | Non-technical stakeholders |
| Legal Evidence Format | `/report legal` | Attorneys, compliance teams (auto-adds DOCX/PDF) |
| Journalist Format | `/report journalist` | Reporters, media |
| JSON Export | `/report json` | Downstream tools, pipelines |
| CSV Export | `/report csv` | Spreadsheets, databases |
| IOC / selector bundle | `/report ioc` | SIEM/TIP ingest, threat-intel sharing |
| Word document | `/report docx` · **b**/**d** at the prompt | Formal sharing |
| PDF document | `/report pdf` · **a**/**d** at the prompt | Formal sharing / print (the DOCX rendered by LibreOffice) |

Every narrative report **always** auto-saves the **base data bundle** (.md + .json + .csv + IOC bundle: .stix.json/.txt/.csv/.jsonl — see Mandatory File Export above), then **asks which presentation format to render** — (a) PDF · (b) DOCX · (c) HTML · (d) all. `/report legal` defaults to **all**; `--yolo`/guided-auto default to **HTML**. Machine-only subcommands (`json`, `csv`, `ioc`) emit their native format directly.

### Visual Outputs

| Type | Command | Format |
|------|---------|--------|
| Subject relationship map | `/render entities` | **ASCII** (default) — `--mermaid` for Mermaid |
| Chronological timeline | `/render timeline` | **ASCII** Gantt |
| Exposure heatmap | `/render risk` | **ASCII** |
| Network topology | `/render network` | **ASCII** |

**All visual outputs use ASCII box-drawing by default.** Mermaid only on explicit `--mermaid` flag.

**Diagram tradecraft:** [`output/visuals/diagram-patterns.md`](../output/visuals/diagram-patterns.md) — compile-check a Mermaid diagram before presenting it, and pick the right diagram type per CTI question (attack → sequence, lifecycle → state, handoffs → swimlane, infra → graph).

The **interactive HTML report** (the primary human-facing deliverable, and the `--yolo`/guided-auto default) renders all of these as live, explorable visuals — a draggable/zoomable 2D force-directed entity graph, infrastructure topology, an event timeline, and SVG charts (pie/bar/gauge/donut) — alongside the ASCII versions in the `.md`.

**IntelGraph — use it whenever a case has a graph.** For any multi-node case
(`/case`, `/pipeline`, `/harness`, or a `/report` with an entity/infra graph),
render the publication-quality figure with `/graph --render` and embed it in the
report; do not reserve it for explicit requests. It degrades to a note when the
`dot`/mermaid renderer is missing, so calling it is always safe. **But check fidelity
first:** `case_graph.json` contains only raw-backed hosts, so KB/reverse-WHOIS-attributed
clusters can be absent — if the graph's node count is below the attributed cluster count,
hand-scope the figure (Mermaid/DOT of the real clusters) or caption it as the raw-backed
subset, rather than auto-rendering a figure that under-represents the finding.

**Relationship card maps — who the subject is connected to.** A hub-and-panel figure (subject at the
top, grouped panels of cards: name, role, dates, country-code chip, relation chip, Admiralty badge;
**dashed = claim not confirmed**). The house report draws a person map (`subject_profile` +
`relationships` rows), a threat-landscape map (`actors` rows, grouped by type) and a suppliers map
(`cases/<id>/suppliers.json`) — only when that data exists; card text passes the report's
scrub/masking, and the builders strip e-mail, phone and birth-date patterns (full dates on person cards
or next to a birth cue; ordinary year ranges stay) — pattern-based reduction, not guaranteed
anonymisation of arbitrary prose. Standalone from a JSON spec, where `--mask` always reduces person names
to initials and drops logos (logos load only from the spec or case `report/` directory):
`python3 intel_engine/IntelGraph/scripts/card_map.py spec.json -o map.svg --png map.png [--mask]`
(schema + example: `intel_engine/IntelGraph/SKILL.reference.md`, `references/card_map_example.json`).

**Large infrastructure — show a representative example, point to the full list.**
A case with hundreds of nodes is unreadable in one figure. Above `--max-nodes`
(default 45) IntelGraph automatically renders a **representative subset** — the
operator anchor, one hub per cluster, and the highest-degree nodes, dropping
fan-out infrastructure (nameservers, registrars) first — and stamps the figure
title `representative subset: N of M nodes`. **The complete indicator set is never
lost:** it lives in the IOC bundle (`generate-cti-iocs.py` → `.csv` openable in
**Excel**, plus the report `.md` and the JSON/JSONL exports). Always tell the
reader, in the figure caption, that the graph is an example and the full details
are in the IOC list. Use `--full` to force the entire graph, or `--split-clusters`
for one readable figure per cluster.

### Connectors

| Tool | File | What It Exports |
|------|------|----------------|
| Maltego | `connectors/maltego-export.md` | GraphML entity graph |
| Obsidian | `connectors/obsidian-setup.md` | Linked markdown notes |
| Notion | `connectors/notion-schema.md` | Structured database |
| Intel backend | `connectors/intel-backend.md` | **Optional** persistent KB + cross-case correlation via the `intel_engine` engine (MCP/CLI). Absent → stateless as normal. Enables `/backend`, `/kb`, `/recall`, `/binary` |
| **ChongLuaDao** ⭐ | `connectors/chongluadao-api.md` | **First-party** premium connector (`scripts/cld/cld_api.py`) — IoC/denylist/breach/data-leak/AI/feeds. Enables `/cld`; upgrades `/scam-check`,`/threat-check`,`/phone`,`/breach-deep`,`/email-deep`,`/email-hygiene`,`/vuln-check`,`/impersonate`. Needs `CHONGLUADAO_API_KEY` |

