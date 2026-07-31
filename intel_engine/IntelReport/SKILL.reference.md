---
name: IntelReport
description: Render a finished assessment MARKDOWN file into a polished, report-ready PDF and/or editable DOCX using pandoc — with a muted editorial house template that matches IntelGraph (cover page, table of contents, running header/footer carrying the classification + case id, embedded figures, and Vietnamese-safe typography). Use this skill WHENEVER the user has a written assessment/report in markdown (e.g. from pivot_extract --report, evidence_report, or an IntelHarness assessment) and asks to "make a PDF", "export to Word/docx", "produce the report", "render the report", "turn this into a document", "beautiful report", or "deliverable". Produces both PDF and DOCX by default. Supports English and Vietnamese.
---

> **OPSEC — this skill is portable/shared. Never write case data into it.** No real operator
> names, emails, domains, IPs, wallets, tracking IDs, hashes, or case IDs in this file, its
> template, tool code, or examples. Investigation data lives only in the git-ignored
> `cases/` / `knowledge/` / `MEMORY/`. Use placeholders (`example.com`, `CASE-0001`,
> `TLP:AMBER`). Reports never stamp an analyst name; the date defaults to UTC today.
> See the repo-root `CLAUDE.md` for the full rule.

# IntelReport — markdown → polished PDF / DOCX

Turn a finished assessment written in Markdown into a credible, print-native document.
The house style is the same understated editorial look as IntelGraph — muted slate/steel
palette, no gradients, generous margins, the kind of report a SOC analyst files, not an
auto-generated dashboard. **PDF** is the shareable deliverable; **DOCX** is the editable
copy a reviewer can redline.

## Report structure — house rules (follow for EVERY report)

These are the standing rules for the assessment markdown you hand to the renderer. The template
enforces the typography (Roman numbering, compact tables, wrapped code); YOU enforce the structure.

1. **Important-first, detail-later.** Lead the document with the conclusion. Section **I** is always
   the **Executive Summary — Key Judgments (BLUF)**: a table of findings + attribution + confidence,
   before any narrative.
1a. **Write in IC / CIA estimative language.** The analyst voice is *"We assess…"*, *"We judge with
   high confidence…"*, *"…almost certainly…"*. Use the **ICD-203 / Sherman-Kent** probability words
   (almost certain / very likely / likely / roughly even chance / unlikely / very unlikely / almost
   no chance) in the PROSE, not just the tables — and never mix a percentage with the word in the
   same clause. State an explicit **confidence level** (low / moderate / high) for each key judgment.
1b. **Explanatory, cause-and-effect narrative — show the trail.** A reader (not just an analyst)
   must be able to FOLLOW how each finding was reached. Write it as *found → via → therefore*:
   name what you did, what it returned, and what that let you conclude. Prefer plain sentences over
   terse shorthand. Estimative words still carry the confidence, but the sentence explains itself.
   - Shorthand (avoid): *"Shared origin IP 203.0.113.10 (AS64500); same-day reg 2020-01-01 → same operator."*
   - Explanatory (use): *"When we reverse-looked-up the two sites' hosting, both resolved to the same
     server (203.0.113.10, a small VPS that hosts almost nothing else); and WHOIS shows both domains
     were registered on the same day through the same registrar. Because a shared private server and a
     same-day registration are things unrelated operators do not share by accident, we assess the two
     sites are run by one operator."*
2. **Table → info → context, in that order.** In every finding section, put the structured table
   first, then the tight bullet/number facts, then the prose context. Never open with a paragraph.
3. **Overview → Details in every long section.** If a section runs long, split it: a `## X.1 Overview`
   (2–4 lines) then `## X.2 Details`. The reader gets the gist without reading the whole section.
4. **Roman top-level, arabic sub.** Use `#` for top-level sections (rendered `I`, `II`, …) and `##`
   for sub-sections (`I.1`, `I.2`). Appendices come after a raw-LaTeX `\appendix` marker and render
   as `Appendix A`, `Appendix B` (see below).
5. **Methodology section (required), placed EARLY.** Put `# Methodology` immediately AFTER the
   Executive Summary (i.e. Section **II**), before the findings — the reader learns *how* the
   investigation was conducted before reading *what* it found. State the tools and the collection
   process so the work can be reproduced or challenged.
5a. **Keep index columns narrow.** A leading `#`/`No.` column must not eat width — give it a tiny
   share by making its delimiter dashes short relative to the others, e.g.
   `| # | Judgment | … |` with `|:-:|:------------------|…|` (one dash for `#`, many for the rest).
   Pandoc allocates column width by the dash ratio. Better still, drop the index column unless rows
   are cited by number.
5b. **Page breaks are automatic.** The template starts every top-level section on a fresh page
   (`\sectionbreak=\clearpage`) — do NOT add manual `\newpage`. Author in **Markdown** and let
   `render_report.py` port to LaTeX; never hand-write LaTeX (markdown is far cheaper in tokens and
   pandoc does the conversion for free).
6. **Confidence via BOTH the NATO Admiralty matrix AND ICD 203.** Grade each source/artifact with an
   Admiralty code (source reliability **A–F** × information credibility **1–6**) and express each
   analytic judgment with an ICD-203 probability word. Include the two reference tables in Methodology:

   | Reliability | Meaning | | Credibility | Meaning |
   |---|---|---|---|---|
   | A | Completely reliable | | 1 | Confirmed by other sources |
   | B | Usually reliable | | 2 | Probably true |
   | C | Fairly reliable | | 3 | Possibly true |
   | D | Not usually reliable | | 4 | Doubtful |
   | E | Unreliable | | 5 | Improbable |
   | F | Reliability cannot be judged | | 6 | Truth cannot be judged |

   ICD-203 bands: *almost no chance* (01–05%) · *very unlikely* (05–20) · *unlikely* (20–45) ·
   *roughly even chance* (45–55) · *likely* (55–80) · *very likely* (80–95) · *almost certain* (95–99%).
7. **Appendix — artifact register (required).** The last section is an appendix table with ONE ROW
   PER ARTIFACT, columns: **Artifact · Value · Source (public class) · Admiralty grade** — this is the
   authoritative schema (Rule 13 restates it). "Source" is the PUBLIC source CLASS only — WHOIS,
   passive DNS / IP, certificate transparency, public web-scan data, live page — never a specific
   product/vendor, an internal file path, a tool/script name, or a "how we found it" column (that
   would leak methodology; see Rules 12 & 14). Grade every row with its Admiralty code (source
   reliability **A–F** × information credibility **1–6**).
8. **Wrap code in a code block.** Any config/JSON/command goes in a fenced ```` ``` ```` block — the
   template line-wraps it so it never overflows the page. Never paste code as prose.
9. **Compact, text-heavy tables are fine.** The template shrinks table font automatically; prefer a
   dense table over splitting facts into prose. Use grid tables when cells hold long text.
10. **No "prepared by" / analyst identity.** Never add a "Prepared by…", author, or sign-off line.
    The cover already carries the reference, date, and classification; that is the whole provenance block.
11. **External reference ≠ internal case id (OPSEC), tracked in a private registry.** The document
    displays a report reference (`report_id` / `--report-ref`) that DIFFERS from the internal case
    folder — a leaked report must not tie back to the store. The renderer **auto-maintains the map**
    in `cases/report_registry.jsonl` (git-ignored): it derives the internal case from the report's
    path under `cases/<id>/`, and if no reference is given it **reuses** the one already logged for
    that case (reproducible) or **mints** `RPT-YYYY-MMDD-NN`. Every render records
    `{report_ref → case_id, title, date, outputs}` there, so we can always resolve a reference
    privately (`grep <ref> cases/report_registry.jsonl`) while the shared PDF never carries the case id.
12. **Never expose internal working anywhere in the report.** No internal tool / script / MCP / API
    names (the collectors, the KB, the registry, Claude APIs), no internal file paths, no case-store
    ids. In the body and appendix, cite only **public source CLASSES** — WHOIS, passive DNS / IP,
    certificate transparency, public web-scan data, live page — never the specific product/service.
13. **Appendix = collected EVIDENCE only.** The final appendix is the evidence table: **Artifact ·
    Value · Source (public class) · Admiralty grade**. No "how we found it", no file paths, no
    reproduction/credit-log appendix. It is what we observed, not how our harness observed it.
14. **Methodology overview = general OSINT tradecraft, not our process.** Describe the *method*
    (start from seeds → **pivot** outward → form a **hypothesis** → **prove or disprove** it against
    independent data sources → weight owner-controlled evidence, state the alternative ruled out),
    never the specific tools/commands. The NATO + ICD reference tables still follow.
15. **Figures are centred, and regenerated on every render (IntelReport ⇄ IntelGraph chain).**
    Emit the figure as a centred block; the renderer sets `\graphicspath` so a raw
    ` ```{=latex}\begin{center}\includegraphics[...]{fig.png}\end{center}``` ` resolves. The report
    declares its figures in a sibling **`figures.json`** —
    `{"figures":[{"raw":["../raw/a.json", …], "graph":"case_graph.json", "stem":"case_diagram",
    "title":"…", "direction":"LR", "legend":true, "drop_types":["nameserver","registrar","template",
    "theme","email"]}]}` (paths relative to the md dir). Before rendering, `render_report.py` rebuilds
    each figure via WebPivot `graph_build.py` → IntelGraph `graph_to_diagram.py --drop-types …`, so the
    chart is **never stale**. Prune noise node types (`--drop-types`) so the meaningful nodes render
    large. Opt out with `--no-figures`.
    - **Prefer MULTIPLE focused figures over one dense overview.** `figures.json` takes a *list* — give
      each major section its own small chart built from just that section's domains (e.g. a tenant
      figure, a platform figure, a second-cluster figure), each with its own `graph`/`stem`, then embed
      each PNG in its section. Keep one whole-case overview at the end. A reader follows three small
      graphs far more easily than one 30-node hairball.

16. **Always include per-domain profiles.** A report must carry a "Domain & infrastructure profiles"
    appendix — one small **Field · Value** table per domain covering, at minimum: status
    (live / dead / parked), registrar + **created** date, registrant (country / org, noting privacy
    masking), nameservers, origin host (IP · ASN), and the **distinctive artifacts** found on that
    site (favicon mmh3, TLS SHA-256, analytics/telemetry ids, tech stack, contact handles, notable
    sub-sites). This is the WHOIS + unique-findings dossier a reader expects for every domain in scope.

Note: top-level sections are Roman (I, II); sub-sections number as **arabic `1.1`, `2.1`** (not I.1).

## Audience — ASK first, then tailor the report

A report has a reader, and different readers need different reports. When the user asks to "produce
/ output / render a report" **without naming the audience, ASK before writing** — use
`AskUserQuestion` with these options (add "All three" — render one file per profile):

| Profile | Reader | Tone & length | Lead with | Include | Cut / push to appendix |
|---|---|---|---|---|---|
| **Technical** | analyst, IR, threat-intel | precise, dense, jargon OK | the two-layer finding + evidence tables | every artifact, exact IOCs, Admiralty/ICD grades, config dumps, methodology depth | nothing — this is the full build |
| **Executive** | leadership, decision-maker | plain business language, short (≤2 pp body) | 3–5 bullet BLUF: what it is, our exposure, the ONE recommendation | risk/impact framing, cost, "what it means for us", a single clear action | raw indicators, tool names, hashes → appendix only |
| **Law Enforcement** | investigator, prosecutor | neutral, factual, court-mindful; separate *confirmed* from *assessed* | the actors/infrastructure + the evidence chain | provenance (source/where/how) up front, UTC timestamps, jurisdictions (registrar, hosting country, offshore), preservation targets, and the concrete legal-process leads (who to subpoena: registrar, NS/anonymity provider, host, telemetry vendor, scanner submitter) | speculation and analyst labels unless clearly marked as assessment |

All three still obey the house rules above (Exec Summary first, Methodology second, NATO+ICD,
artifact appendix, explanatory tone). The audience changes *emphasis, depth, and vocabulary* — not
the underlying facts. Carry the choice into the render with `--audience {technical|executive|le}`
(it stamps the audience on the cover subtitle and sets a sensible TOC depth).

### The appendix marker (Roman → letter switch)

Pandoc has no `\appendix` hook, so emit one raw-LaTeX block in the markdown immediately before the
first appendix heading — everything after it numbers as `Appendix A`, `B`, …:

````markdown
```{=latex}
\appendix
```

# Artifact register
````

## Zero new dependencies

Everything is already on the machine the harness uses:
- `pandoc` — the converter (markdown → PDF and → DOCX).
- `xelatex` — the PDF engine (Unicode/Vietnamese-safe; picks an installed Vietnamese-capable
  font automatically, see below).

No Python packages are required — `render_report.py` is stdlib-only and shells out to pandoc.

## Running the tool — paths (read first)

Registered as `IntelReport`, symlinked to the repo's `IntelReport/` folder.

```bash
REPORT=~/.claude/skills/IntelReport            # absolute — works from any CWD (preferred)
# or, inside the repo:  REPORT="$ROOT/IntelReport"

python3 "$REPORT/scripts/render_report.py" assessment.md out/report
```

That writes `out/report.pdf` **and** `out/report.docx` (both by default). Pass `--pdf` or
`--docx` to produce just one.

## Core workflow

1. **Have the assessment as Markdown.** Any assessment markdown works — from
   `pivot_extract.py --report`, `evidence_report.py`, an IntelHarness assessment, or written
   by hand. Standard Markdown: `#`/`##` headings, `|` pipe tables, fenced code, `**bold**`,
   `> quotes`, and image embeds.
2. **(Optional) add YAML frontmatter** so the cover/header fill in without CLI flags:
   ```markdown
   ---
   title: "Operator A — infrastructure assessment"
   subtitle: "Passive OSINT · N sites attributed to one operator"
   case_id: CASE-0001
   classification: "TLP:AMBER"
   ---
   ```
   CLI flags (`--title`, `--case-id`, `--classification`, `--subtitle`, `--date`) override
   the frontmatter. Anything missing gets a sensible default (`classification` →
   `UNCLASSIFIED`, `date` → UTC today, `title` → first `#` heading or the filename).
3. **Embed IntelGraph figures** as ordinary Markdown images — the alt text becomes the
   figure caption, styled in the house palette:
   ```markdown
   ![Operator A — two sites, shared GA4 + registrant](case_diagram_hires.png)
   ```
   Image paths are resolved **relative to the markdown file's directory**. Put the assessment
   `.md` in the case folder next to its figures (see the IntelGraph output contract) and they
   embed cleanly. Use the `_hires.png` (300 DPI) figure for print, or the `.svg` for vector.
4. **Render:**
   ```bash
   python3 "$REPORT/scripts/render_report.py" cases/CASE-0001/assessment.md \
       cases/CASE-0001/report --case-id CASE-0001 --classification "TLP:AMBER"
   ```
5. **Present** the PDF (and DOCX if the user wants to edit it).

## The end-to-end pipeline (charts + report)

```bash
# 1) collect + build the clustered case graph (WebPivot)
python3 <WebPivot>/tools/graph_build.py cases/CASE-0001/raw/*.json \
    --operator "Operator A" -o cases/CASE-0001/case_graph.json

# 2) editable diagram -> PNG/SVG (IntelGraph); the .mmd is hand-editable
python3 <IntelGraph>/scripts/graph_to_diagram.py cases/CASE-0001/case_graph.json \
    cases/CASE-0001/case_diagram --title "One operator, N sites" --legend

# 3) reference the figure in the assessment markdown, then render the document
python3 <IntelReport>/scripts/render_report.py cases/CASE-0001/assessment.md \
    cases/CASE-0001/report --case-id CASE-0001 --classification "TLP:AMBER"
```

`<IntelGraph>` = `~/.claude/skills/IntelGraph`, `<WebPivot>` = `~/.claude/skills/WebPivot`.

## Template & house style

- **Cover page** — classification banner (brick), large slate title, grey subtitle, and a
  Case / Date / Basis block. No logo, no analyst name.
- **Body** — numbered sections in slate/steel sans headings with a hairline rule, booktabs
  tables, house-palette figure captions, coloured hyperlinks. Auto table of contents.
- **Header/footer** — classification top-left, case id top-right, classification + page
  number in the footer, hairline rules.
- The LaTeX template is `templates/house-header.tex` (xelatex, palette copied from
  `IntelGraph/scripts/theme.py`). Edit it to adjust the house look; keep it case-data-free.

### Fonts / Vietnamese

`render_report.py` auto-selects an installed serif + sans that actually **declare Vietnamese
coverage** (`fc-list :lang=vi`) — many otherwise-nice serifs (PT Serif, Charter, DejaVu on
macOS) miss the stacked-diacritic glyphs (ộ, ừ, ả) and render tofu, so they are skipped in
favour of e.g. Noto Serif / Georgia / Times. Diacritics render correctly (cà phê, Hà Nội,
lừa đảo). Latin Modern is the last-resort TeX-bundled fallback.

### DOCX styling

DOCX uses pandoc's default reference styling plus a title block (title / subtitle-with-
classification / date). To brand it further, drop a customised `templates/reference.docx`
into the skill — `render_report.py` picks it up automatically if present (else uses the
clean default). Generate a starting point with
`pandoc -o templates/reference.docx --print-default-data-file reference.docx`, restyle it in
Word/LibreOffice, and keep it case-data-free.

## Quality checklist before presenting

- Both requested files exist (PDF and/or DOCX).
- Cover shows the right title, case id, and classification; NO analyst name.
- Vietnamese text renders with correct diacritics (no tofu boxes).
- Embedded figures appear (use the `_hires.png`); tables render with rules.
- Header/footer carry the classification + case id + page numbers on every body page.
- The classification and case id came from an argument or frontmatter — never hardcoded.
