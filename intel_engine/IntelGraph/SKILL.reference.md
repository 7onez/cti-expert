---
name: IntelGraph
description: Generate publication-quality charts, graphs, timelines, Gantt charts, and relationship diagrams from threat-intelligence and OSINT reports. Produces TWO outputs per figure — a high-resolution PNG/SVG/PDF for embedding in reports, and a lower-res analytical thumbnail for quick review. Use this skill WHENEVER the user pastes or uploads an intelligence report, IOC table, incident timeline, campaign summary, actor-infrastructure mapping, or asks for a "chart", "graph", "timeline", "Gantt", "diagram", "network graph", or "visualization" from investigative/CTI data — even if they don't say the word "skill". Also renders WebPivot case graphs via scripts/render_network.py. Output is deliberately non-AI-looking, using matplotlib, Mermaid, or Graphviz with a clean editorial theme. Supports English and Vietnamese labels.
---

> **OPSEC — this skill is portable/shared. Never write case data into it.** No real operator
> names, emails, domains, IPs, wallets, tracking IDs, hashes, or case IDs in this file, its
> workflows, tool code, or test fixtures. Investigation data lives only in the git-ignored
> `cases/` / `knowledge/` / `MEMORY/`. In examples use placeholders (`example.com`,
> `G-XXXXXXXXXX`, `CASE-0001`). See the repo-root `CLAUDE.md` for the full rule.

# IntelGraph — Graph Design

Turn intelligence reports into clean, credible, report-ready graphics. The house style is understated and editorial — the kind of figure that looks hand-built by an analyst in a SOC report, not auto-generated. No gradients, no drop shadows, no rainbow palettes, no 3D.

## Running the tools — paths & working directory (read first)

This skill is registered as `IntelGraph`, symlinked to the repo's `IntelGraph/` folder.
Pick **one** anchor and use it consistently:

```bash
GRAPH=~/.claude/skills/IntelGraph          # absolute — works from any CWD (preferred)
# or, when working inside the repo:  GRAPH="$ROOT/IntelGraph"
python3 "$GRAPH/scripts/render_mermaid.py"  diagram.mmd  outputs/stem   # via mmdc
python3 "$GRAPH/scripts/render_graphviz.py" graph.dot    outputs/stem   # needs graphviz/dot
python3 "$GRAPH/scripts/render_network.py"  case_graph.json network.html --title "..."
# theme.py + gantt.py:  sys.path.insert(0, "<GRAPH>/scripts")
```

Every `IntelGraph/scripts/…` or bare `scripts/…` path shown later in this file means
`$GRAPH/scripts/…`; any `<WebPivot>/tools/…` means `~/.claude/skills/WebPivot/tools/…`.

Dependencies: see `requirements.txt` (`matplotlib`, `graphviz`; Mermaid uses the `mmdc` binary).
`render_mermaid.py` works out of the box wherever `mmdc` is installed; matplotlib/Graphviz paths
need their deps present.

## Core workflow

1. **Read the input.** Extract the structured data hiding in the prose: dates, IOCs, actor names, kill-chain phases, victim counts, ASN/infra links, TTPs, confidence gradings (Admiralty A1–F6). If a table or JSON is provided, use it directly.
2. **Pick the chart type** (see selection table below).
3. **Choose the engine** — matplotlib for data plots, Mermaid for flows/timelines/simple Gantt, Graphviz for entity-relationship / infrastructure graphs.
4. **Set language.** Default English. If the user asks for Vietnamese (or the report is in Vietnamese), pass `--lang vi`. Labels come from `references/i18n.md`.
5. **Render TWO artifacts per figure:**
   - `*_hires.png` (300 DPI) **and** `*.svg` / `*.pdf` — for embedding in the report.
   - `*_thumb.png` (110 DPI, smaller canvas) — the "analytical" quick-look for understanding your own work at a glance.
6. **Present both** with `present_files`, hi-res first.

**Output contract:** when the figure belongs to a case, save it into that case, not a loose
`outputs/`. Network graphs → `knowledge/reports/<case>/` beside the assessment (or `cases/<case>/`);
standalone/ad-hoc figures → `outputs/`. Always emit the full artifact set the figure type
promises (hi-res PNG + SVG/PDF + thumb for matplotlib; the single self-contained `network.html`
for `render_network.py`). Same case + same input JSON → same output filenames, so a re-render
overwrites rather than accumulating stray files.

## Network / link-analysis graphs (clustered, interactive) — USE THIS for relationship webs

For OSINT/CTI **link analysis** (domains ↔ trackers ↔ IPs ↔ wallets ↔ operator), do **not** use Mermaid or Graphviz — a dense relationship web becomes a hairball. Use the interactive network engine:

```bash
# 1) build a clustered graph model from WebPivot pivot JSON (Louvain communities + betweenness centrality)
python3 <WebPivot>/tools/graph_build.py out/*.json --operator "name" --operator-links a.com,b.com -o case_graph.json
# 2) render ONE self-contained interactive HTML (Cytoscape.js + fcose, all inlined — CSP-safe, no server)
python3 scripts/render_network.py case_graph.json network.html \
  --title "One operator, N sites — clustered by shared artifacts" \
  --subtitle "size = broker centrality · color = cluster · shape = type. Red = same-operator, purple = same-kit."
```
Encoding (research-backed): **node size = betweenness centrality**, **color = Louvain community**, **shape = entity type**, **solid = confirmed / dashed = inferred**, edge color = operator(red)/kit(purple)/link(grey)/infra(steel). Interactions: focus+context click, filters (edge evidence class, node type), color-by toggle (cluster↔type), layout toggle (organic/radial/hierarchy), search, detail panel. Libraries are vendored in `vendor/` (~760 KB, MIT). Tell the story: title = the claim; lead seed → mechanism → network → operator convergence; keep "same kit" and "same operator" edges visually separate.

**Engine choice:** relationship web / clustering → `render_network.py` (this). Attack flow / kill-chain / provenance tree → Mermaid or Graphviz. Data charts / Gantt / timeline → matplotlib (`theme.py`, `gantt.py`).

### Editable diagram export (for reports) — `graph_to_diagram.py`

`render_network.py` produces an opaque, interactive HTML — perfect for exploring a dense web
live, but you can't hand-edit it or embed it in a PDF/DOCX. When you need the case graph as a
**static, editable figure for a report**, convert the *same* `case_graph.json` into an
**editable Mermaid source** (`.mmd`) and render it to the PNG/SVG/thumb triple:

```bash
python3 scripts/graph_to_diagram.py case_graph.json out/case_diagram \
    --title "One operator, N sites" --legend        # + --direction LR|TB  --no-render
```
Writes `out/case_diagram.mmd` (hand-editable — rename a cluster, prune a node, fix a label)
then `out/case_diagram.svg`, `_hires.png`, `_thumb.png` via `render_mermaid.py`. Encoding is
faithful to the HTML: **node shape = entity type**, **node fill = Louvain cluster**, operator
= red anchor, **edge color = evidence class** (operator/kit/infra/link), **dashed = inferred**.
Use this figure with the **IntelReport** skill to build the PDF/DOCX. Both outputs coexist —
`render_network.py` (interactive HTML) is unchanged and still the right tool for live triage.
Rendering needs `mmdc` + headless Chrome (same as any Mermaid figure).

## Chart type selection

| Input signal | Chart | Engine |
|---|---|---|
| Counts over categories (malware families, targeted banks, ASNs) | Horizontal bar | matplotlib |
| Trend over time (phishing domains/day, detections/week) | Line / step | matplotlib |
| Proportions (infra by country, IOC by type) | Donut (never pie-3D) | matplotlib |
| Two-metric relationship | Scatter | matplotlib |
| Event sequence with dates | Timeline | `gantt.py` (matplotlib) |
| Overlapping activity windows (campaign phases, IR tasks) | Gantt | `gantt.py` (matplotlib) |
| Attack progression | Kill-chain / flow | Mermaid or Graphviz |
| Actor ↔ infra ↔ victim links | Relationship graph | Graphviz |
| Matrix (Diamond Model, MITRE coverage, C1–C8 scoring) | Heatmap | matplotlib |

When unsure which of two fits, generate the matplotlib version — it's the most reliable and most "report-native."

## The theme (non-negotiable house style)

All matplotlib output MUST load the shared theme so figures are visually consistent:

```python
import sys; sys.path.insert(0, "SCRIPTS_DIR")
from theme import apply_theme, PALETTE, save_dual
apply_theme(lang="en")   # or "vi"
```

Theme rules baked into `scripts/theme.py`:
- Font: DejaVu Sans (renders Vietnamese diacritics correctly — cà phê, Hà Nội, lừa đảo).
- Muted, colorblind-safe palette (slate/steel/ochre/brick), no neon.
- Left-aligned title + smaller grey subtitle, hairline gridlines on one axis only, despined top/right.
- A caption footer line for source + Admiralty grading + date stamp.
- White background, generous margins — reads as print, not dashboard.

## Rendering matplotlib figures

Use `scripts/theme.py` helpers. Minimal pattern:

```python
import sys; sys.path.insert(0, "IntelGraph/scripts")
from theme import apply_theme, PALETTE, save_dual, caption
import matplotlib.pyplot as plt

apply_theme(lang="en")
fig, ax = plt.subplots(figsize=(9, 5))
ax.barh(labels, values, color=PALETTE["primary"])
ax.set_title("Fake banking APK families observed", loc="left", fontweight="bold")
caption(fig, source="CTI team", grading="B2", date="2026-07-05")
save_dual(fig, "outputs/apk_families")  # writes _hires.png (300dpi), .svg, _thumb.png
```

`save_dual(fig, stem)` produces `stem_hires.png`, `stem.svg`, and `stem_thumb.png` in one call. Add `pdf=True` for a vector PDF too.

See `references/matplotlib_recipes.md` for ready-to-adapt code for bar, line, donut, scatter, heatmap (Diamond Model / C1–C8), and matplotlib-native timeline.

## Rendering Gantt & timeline (default: browser-free)

Prefer the matplotlib-native `scripts/gantt.py` — it needs no browser, matches the data-chart house style exactly, and handles Vietnamese. Use it for Gantt charts and event timelines:

```python
import sys; sys.path.insert(0, "IntelGraph/scripts")
from gantt import gantt, timeline
tasks = [
  {"section":"Infrastructure","name":"Domain registration","start":"2026-05-01","end":"2026-05-07"},
  {"section":"Response","name":"Detection & report","start":"2026-05-16","end":"2026-05-18","crit":True},
]
gantt(tasks, title="Campaign timeline — fake banking APK",
      stem="outputs/campaign_gantt",
      lang="en", source="CTI team", grading="B2", date="2026-07-05")
```
`crit=True` highlights a task (brick); `done=True` greys it. `timeline([(date,label),...], ...)` renders an alternating event timeline. Both emit the hi-res + SVG + thumb triple.

## Rendering Mermaid (flow, kill-chain — needs headless Chrome)

Mermaid is best for attack flows / kill-chains. It requires `mmdc` **and headless Chrome**. If Chrome isn't installed, run once:
```bash
npx puppeteer browsers install chrome-headless-shell
```
(this needs network access to the puppeteer CDN; if the environment blocks it, use Graphviz for flows instead). Then:
```bash
python IntelGraph/scripts/render_mermaid.py diagram.mmd outputs/killchain
```
See `references/mermaid_recipes.md` for Gantt, timeline, kill-chain, and flow templates (English + Vietnamese). For flows without Chrome, use the Graphviz `flowchart` equivalent in `references/graphviz_recipes.md`.

## Rendering Graphviz (entity / infrastructure graphs)

For actor→infrastructure→victim link analysis:

```bash
python IntelGraph/scripts/render_graphviz.py graph.dot outputs/infra_map
```

See `references/graphviz_recipes.md` for the DOT template with node shapes per entity type (actor=box, domain=ellipse, IP=hexagon, victim=folder, wallet=cylinder).

## Vietnamese output

When `--lang vi` / `lang="vi"`:
- matplotlib: `apply_theme(lang="vi")` keeps DejaVu Sans and switches built-in furniture (axis defaults, caption words like "Nguồn", "Độ tin cậy", "Cập nhật").
- Look up chart titles / recurring analytic terms in `references/i18n.md` (kill-chain phases, Diamond Model vertices, Admiralty labels, common CTI nouns).
- Translate the substantive labels the user gives you; keep proper nouns (brand names, FOFA, ASN numbers) as-is.
- If the user provides English data but wants a Vietnamese figure, translate labels but leave IOCs, hashes, domains untouched.

## Quality checklist before presenting

- Two files exist: a hi-res AND a thumbnail.
- Vietnamese text renders with correct diacritics (no tofu boxes).
- Caption footer has source + confidence grading + date.
- No 3D, no default matplotlib blue, no gradient fills.
- Numbers in the figure match the source report.
- Title states the finding, not just the variable ("Phishing infra concentrated in 3 ASNs", not "ASN counts").
