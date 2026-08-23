# Workflow: NetworkGraph — clustered, interactive link analysis

Turn many WebPivot analyses into ONE clustered, interactive network you can
explore and use to tell the story (seed → mechanism → network → operator).

Pipeline: `pivot_extract.py` (per site) → `graph_build.py` (case model +
clustering) → `render_network.py` (self-contained interactive HTML).

**Output convention:** write all generated artifacts to a **case workspace**, never
inside the skill folder — e.g. `<project>/cases/<case-name>/` with `raw/` for the
per-site JSON. Skills stay code-only; investigations are data.
```
cases/<case>/raw/*.json   case_graph.json   <case>_network.html   history.json
```

## Steps

1. **Extract every site** (live, or passive via Wayback/urlscan) into per-site JSON:
   ```bash
   mkdir -p out
   for u in $(cat urls.txt); do
     n=$(echo "$u" | sed 's#[^a-zA-Z0-9]#_#g')
     python3 tools/pivot_extract.py "$u" -o "out/$n.json" 2>/dev/null
   done
   ```

2. **Build the case graph** — normalizes typed nodes (domains + shared artifacts
   as hub nodes) and typed, evidence-graded edges, then computes connected
   components, communities, and **betweenness centrality**:
   ```bash
   python3 tools/graph_build.py cases/<case>/raw/*.json \
     --operator "operator-a / Operator A" \
     --operator-links site-a.example,site-b.example \
     --history cases/<case>/history.json \   # optional: from wayback_ga.py → timeline
     --leiden \                               # optional: Leiden clustering (needs igraph+leidenalg; else Louvain)
     -o cases/<case>/case_graph.json
   ```
   Shared artifacts become hubs, so two sites sharing a favicon/wallet/email both
   connect to it — that convergence is the "same operator / same kit" signal.
   `--history` (a `wayback_ga.py` JSON) attaches first-seen dates and builds the timeline.

3. **Render the interactive HTML** (Cytoscape + fcose, fully inlined, CSP-safe —
   opens in any browser, no server):
   ```bash
   python3 ~/.claude/skills/IntelGraph/scripts/render_network.py case_graph.json network.html \
     --title "One operator, N sites — clustered by shared artifacts" \
     --subtitle "Node size = broker centrality · color = cluster · shape = type. Red = same-operator, purple = same-kit."
   ```
   Encoding: **size = betweenness** (brokers biggest), **color = community**,
   **shape = entity type**, **solid = confirmed / dashed = inferred**, edge color
   = operator(red) / kit(purple) / link(grey) / infra(steel). The page ships the
   **triad**: the graph, a **timeline** (first-archived dates), and a cited
   **evidence ledger** — clicking a node cross-highlights its rows and timeline marker.

## Reading it (tell the story)
- Start zoomed to a **seed** domain; click it → focus its neighbourhood.
- Follow the **red (operator) edges** — they converge on the persona = attribution.
- **Purple (kit) edges** cluster sites that share a favicon/tracker = same builder.
- The biggest nodes are the **brokers** (highest betweenness) — the sites/artifacts
  whose removal fragments the network; your highest-value pivots.
- Toggle **Color by → Type** to review entity types; **Radial** layout to put the
  top pivot at centre; filter edges to isolate operator vs kit links.
- Title states the **claim**; pair the graph with the artifact table + a timeline
  (wayback_ga history) for a court-ready exhibit. Distinguish "same kit" from
  "same operator" — never conflate them.
