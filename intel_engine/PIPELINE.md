# Pipeline — how to run an investigation end to end

**The goal of a run is to unmask the operator behind the infrastructure** — a named actor, or the
strongest honest substitute (a persona, or an unnamed-but-characterised operator), with its
evidence and confidence. Collecting artifacts and converging a cluster are the *machinery*; a run
that never answers *who* — or never states why who is unknown and what pivot would settle it —
is unfinished. See `WebPivot/SKILL.md` §*The GOAL* and `IntelAnalysis/SKILL.md` §*The GOAL*.

The bundle is a four-stage pipeline. You can drive it two ways: from the **CLI**
(`tools/intel.py` — deterministic, scriptable) or from **inside Claude Code** (natural
language — the skills do the steps for you).

```
   Collect            Ingest              Correlate            Visualize
 ┌──────────┐      ┌──────────┐        ┌──────────────┐     ┌───────────┐
 │ WebPivot │ ───► │ knowledge│  ───►  │ IntelAnalysis│ ──► │ IntelGraph│
 │ (extract)│      │   base   │        │ (judgment)   │     │ (graph)   │
 └──────────┘      └──────────┘        └──────────────┘     └───────────┘
   raw/*.json       entities+edges       assessment.md        network.html
```

Everything lands on disk in the case folder — a run is only "done" when it's persisted.

---

## 0. One-time setup (per machine / per shell)

```bash
cd /path/to/intelligence_assist          # the project root — run ALL commands from here
set -a; [ -f .env ] && source .env; set +a   # load FOFA / URLSCAN / WHOISXML keys (optional)
```

- No keys? Everything still works (extraction + query generation + **keyless-RDAP WHOIS** + passive Wayback/urlscan). WHOIS now resolves on every domain with no key (keyless RDAP + `.vn` port-43 fallback); `WHOISXML_API_KEY` only adds registrant *history*.
- With keys, the HIGH-confidence pivots run live. Key setup: `WebPivot/INSTALL.md §5`.

---

## 1. The fast path — one command for a whole domain list

```bash
# put your seed domains (one per line) in a file
mkdir -p cases/mycase
printf 'suspicious-site.example\nother-domain.example\n' > cases/mycase/domains.txt

# run the pipeline: extract every domain → ingest into the KB → save cluster seeds
python3 tools/intel.py open mycase cases/mycase/domains.txt

# add a rendered network graph + an operator persona node:
python3 tools/intel.py open mycase cases/mycase/domains.txt --render --operator "SomeName"

# audit what the case has persisted so far:
python3 tools/intel.py status mycase

# partition the case into same-operator clusters (pure KB read — judge one cluster at a time):
python3 tools/intel.py clusters mycase
```

**Or run it as a resumable convergence loop** — collect → assess → chase the *free* frontier → repeat,
pausing at a round cap and resuming exactly where it left off (per-case `state.json`). The default
pivots are free-only, so a loop spends **zero** API credits until you hand it a metered lead:

```bash
python3 tools/intel.py loop mycase cases/mycase/domains.txt   # first run (or add evidence)
python3 tools/intel.py loop mycase                            # resume where it paused
python3 tools/intel.py loop mycase --max-rounds 6 --max-new 8 --stale 2   # tune the stop condition
```

A round that adds no new shared artifact for `--stale` rounds (default 2) means **CONVERGED**;
the loop writes `assessment.json` (gaps / next_pivots / metered_leads) so you can see what a paid
pivot would buy before spending. It never auto-seeds **co-tenancy** — a multi-tenant TLS cert, a
shared/CDN hosting IP, or a bulk/privacy registrant term names other *customers*, so those are held
back as `co_tenancy_leads` rather than collected (a bad seed is ingested, and then pollutes every
later case).

**It produces** (all under `cases/mycase/`):
- `raw/<host>.json` — one pivot-extract JSON per domain (overwrites on re-run → reproducible)
- `shared.txt` — the cluster seeds (shared indicators across ≥2 domains), **scoped to this case's
  hosts**, with each indicator's KB-wide count alongside as the prevalence/noise signal
- `clusters.json` — the case partitioned into **same-operator components** + the indicators binding
  each. Judge **per cluster, not per case**; a big case is N attribution questions, not one
- `case_graph.json` + `network.html` — the clustered graph (unless `--no-graph`)
- and the whole run **ingested into `knowledge/`** so IntelAnalysis can reason over it.

> ⚠️ `intel.py open --render` renders the **network graph**. It does a **static** page fetch
> per domain. For hosted-builder funnels (GoHighLevel, etc.) whose operator tokens are injected
> by JavaScript, collect those pages with the per-page `--render` in §2 instead.

---

## 2. A single page — with rendered DOM + archiving

Use this for one URL, or when you need the post-JS DOM (inline form scripts, GoHighLevel
`msgsndr` location IDs, backend Google-Sheet IDs, Make/Zapier webhooks live only there).

```bash
WP=~/.claude/skills/WebPivot
CASE=cases/mycase; mkdir -p "$CASE/raw" "$CASE/dom"

python3 "$WP/tools/pivot_extract.py" https://target.example \
    --render \                                        # post-JS DOM (needs Playwright)
    -o "$CASE/raw/target.example.json" \              # persist the artifacts+pivots
    --save-dom "$CASE/dom/target.example.html" \      # store the raw collected DOM
    --submit                                          # archive to Wayback + urlscan

# quick human-readable view of the ranked leads (no file):
python3 "$WP/tools/pivot_extract.py" https://target.example --leads

# then fold it into the KB (same as intel.py does):
python3 tools/kb/ingest_webpivot.py --kb knowledge "$CASE"/raw/*.json
```

`--render` runs Playwright, so install it once: `pip install playwright && playwright install chromium`.

---

## 3. Correlate — turn the collected facts into a finding (IntelAnalysis)

This stage is **judgment**, so run it inside Claude Code (it reasons; it doesn't fetch):

> "Correlate the **mycase** case in the knowledge base — who is the operator, and how confident are you?"

or invoke the skill directly: `/IntelAnalysis`. It will:
- query the KB for shared indicators (`tools/kb/query.py --shared`),
- triage them (attribution-grade vs corroborating vs noise), attribute (same-kit / same-operator / same-actor),
- and **save a cited assessment** to `cases/mycase/assessment.md`.

Everything a case produces lives under `cases/<case>/` — raw collection, DOM, figures, and the
assessment. `knowledge/` is the cross-case KB only (entities, edges, cached payloads); it holds no
per-case deliverables. If the convergence loop has also run, its machine-rendered view sits beside
yours as `loop_assessment.md` — the loop never overwrites a hand-written `assessment.md`.

The raw correlation math is also available directly:
```bash
python3 tools/kb/query.py --kb knowledge --stats                 # store overview
python3 tools/kb/query.py --kb knowledge --shared --min 2        # cluster seeds
python3 tools/kb/query.py --kb knowledge --cluster target.example # peers of one domain
python3 tools/kb/query.py --kb knowledge --entity <value>        # one entity + provenance
```

---

## 4. Visualize — render the case graph (IntelGraph)

Inside Claude Code:

> "Render the **mycase** case graph with IntelGraph."

or from the CLI (this is what `intel.py --render` calls under the hood):
```bash
python3 ~/.claude/skills/IntelGraph/scripts/render_network.py \
    cases/mycase/case_graph.json cases/mycase/network.html \
    --title "One operator, N sites — clustered by shared artifacts"
```
Open `network.html` in a browser — it's a self-contained interactive graph
(node size = centrality, color = cluster, red edges = same-operator).

**Then time-order it — the graph shows *what* is connected, not *whether it was connected at the
same time*.** Build the lifecycle timeline + evidence ledger before writing the assessment:
```bash
python3 ~/.claude/skills/IntelGraph/scripts/case_timeline.py cases/mycase/out/*.json \
    --stem cases/mycase/timeline --markdown --title "Infrastructure lifecycle"
```
Emits the swimlane figure (registration spans, registrant eras, hosting windows, cert validity),
`timeline_events.json` and a paste-ready evidence table where every row cites **when · source · an
online link** (Wayback / urlscan / crt.sh / RDAP / BGP) — plus the derived expiry/renewal cohorts
and IP-tenancy overlaps. Tradecraft: `IntelAnalysis` §1.5 + `Workflows/Timeline.md`.

---

## 5. Driving the whole thing from inside Claude Code (no CLI)

You can skip the terminal entirely — just ask:

1. **Collect:** "Analyze `https://target.example` with WebPivot and save it to the **mycase** case."
   (add "render the page" for JS-heavy funnels)
2. **Correlate:** "Correlate the mycase case — build the operator cluster and assess confidence."
3. **Visualize:** "Render the mycase network graph, then build the mycase timeline."

The skills persist to the same `cases/` + `knowledge/` folders, so CLI and chat are interchangeable.

---

## 6. Flags cheat-sheet

**`tools/intel.py open <case> <domains-file>`**
| Flag | Effect |
|---|---|
| `--render` | also build + render the interactive **network graph** |
| `--no-graph` | skip the graph build |
| `--operator NAME` | add an operator persona node to the graph |
| `--operator-links a.com,b.com` | domains tied to that operator |
| `--whois-reverse` | run reverse-WHOIS live (costs WhoisXML credits) |
| `--jobs N` | parallel extractions (default 4) |
| `--min N` | `--shared` threshold (default 2) |
| `--timeout S` | per-fetch timeout (default 20) |

**`tools/intel.py loop <case> [seeds]`** — resumable convergence loop (omit seeds to resume)
| Flag | Effect |
|---|---|
| `--max-rounds N` | round cap before pausing (default 6) |
| `--max-new N` | new frontier seeds collected per round (default 8) |
| `--stale N` | consecutive zero-growth rounds = CONVERGED (default 2) |
| `--render-extract` | render post-JS DOM per page (needs Playwright) |
| `--jobs N` / `--min N` / `--timeout S` | as in `open` |

**`WebPivot/tools/pivot_extract.py <url|file|->`**
| Flag | Effect |
|---|---|
| `--render` | render the post-JS **page DOM** (needs Playwright) |
| `--free-only` | emit only free/keyless pivots — spends **zero** API credits (the loop's default) |
| `--hunt-impersonation` | sweep typosquats / TLD permutations / crt.sh keyword hits for lookalike domains of the seed |
| `--leads` | print ranked pivot leads (markdown) instead of JSON |
| `--pretty` | pretty-print the JSON |
| `-o PATH` | write the artifacts+pivots JSON to a file |
| `--save-dom [PATH]` | store the raw collected DOM |
| `--submit` | archive the URL to Wayback + urlscan |
| `--no-enrich` / `--no-whois` | skip live enrichment / WHOIS |
| `--report [PATH]` | render a CIA-tradecraft intelligence assessment (BLUF, Key Judgments, ICD 203 estimative language + confidence). Bare → stdout; PATH → Markdown file |
| `--master [PATH]` | append every pivot to a master evidence ledger for the evidence folder (dedupes on host+kind+value, never loses rows). Bare → `evidence/master_pivots.csv`; `.xlsx` → Excel (needs openpyxl) + sibling CSV |
| `--case NAME` | tag the report + every ledger row with a case name |
| `--classification BANNER` | report banner (default `UNCLASSIFIED//FOR OFFICIAL USE ONLY`) |
| `--analyst NAME` | analyst handle stamped on the assessment header |

**Evidence workflow example** — one command produces the analyst product *and* grows the master exhibit register:

```bash
python3 "$WP/tools/pivot_extract.py" https://target.example \
    --case acme --report "$CASE/reports/target.example.md" \
    --master "$CASE/evidence/master_pivots.csv"
# re-running any host updates its rows in place — the ledger is one clean export.
```

---

## 7. Worked example (the flow, start to finish)

```bash
cd /path/to/intelligence_assist
set -a; source .env; set +a

# 1) collect a two-page funnel with rendered DOM + archive
WP=~/.claude/skills/WebPivot; CASE=cases/acme; mkdir -p "$CASE/raw" "$CASE/dom"
for u in https://acme.example https://acme.example/intake; do
  host=$(echo "$u" | sed -E 's#https?://##; s#/#_#g')
  python3 "$WP/tools/pivot_extract.py" "$u" --render \
      -o "$CASE/raw/$host.json" --save-dom "$CASE/dom/$host.html" --submit
done

# 2) ingest + see the cluster seeds
python3 tools/kb/ingest_webpivot.py --kb knowledge "$CASE"/raw/*.json
python3 tools/kb/query.py --kb knowledge --shared --min 2

# 3) correlate  → in Claude Code: "correlate the acme case, who's the operator?"
# 4) visualize  → in Claude Code: "render the acme network graph"
```

---

## 8. Troubleshooting
| Symptom | Fix |
|---|---|
| `No such file or directory: tools/pivot_extract.py` | You're not at the project root, or used the wrong path. Skill scripts are `~/.claude/skills/WebPivot/tools/…`; KB/case tools are project-root-relative. |
| `intel.py open` shows `MISS` for a host | Rate-limit or unreachable — re-run; the summary lists which hosts to retry. |
| SaaS tokens (GHL/Sheet/webhook) don't appear | They're client-side — use `pivot_extract.py --render` (not the static `intel.py` fetch). |
| `--render` errors | `pip install playwright && playwright install chromium`. |
| urlscan / FOFA return nothing live | Set the API keys (`WebPivot/INSTALL.md §5`); anonymous searches are limited. |
| Wayback `--submit` times out | Save-Page-Now is slow; the capture usually still completes server-side. |
