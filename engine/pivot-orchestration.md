# Pivot Orchestration Engine — the recursive "spider-map" behind `/case`

This is what makes `/case` more than a one-pass collector. Given **any** seed (person,
domain, IP, email, company, username, wallet, phone), the engine treats every
discovered identifier as a **new seed** and expands the relationship graph **hop by
hop until the frontier is exhausted** or a budget cap is hit — mapping the whole
network and profiling the subject.

The deterministic bookkeeping (identifier typing, dedup / cycle prevention, per-node
depth, the pivot edge-matrix, confidence gating, per-depth checkpoints) lives in
[`scripts/pivot_orchestrator.py`](../scripts/pivot_orchestrator.py). **This engine plans and
tracks; the agent executes.** The script never touches the network — it owns the queue so
the recursion stays reliable and the map is reproducible.

---

## Defaults (this skill)

| Knob | Default | Meaning |
|------|---------|---------|
| **posture** | `active` | May directly fetch/scan targets (live DOM, favicon, ports) — but still **passive-first for hostile infra** (archives/urlscan/passive DNS), and prefer non-attributable egress when a proxy/VPS is set. |
| **reach** | `exhaustive` | Expand until the frontier is empty or budget hit. Exact-match links (≥95%) expand unbounded; weaker links gated by the priority matrix. |
| **autonomy** | `checkpoint` | Pause after **each depth level**, present new nodes + proposed next pivots, wait for approval before expanding further. |
| budget | `max_nodes=500`, `max_depth=6` | Safety caps even under `exhaustive`. |

Override per run: `/case <target> --passive|--passive-first`, `--reach balanced|focused`,
`--auto` (no checkpointing), `--depth N`, `--budget N`, `--authorization confirmed`.

---

## The loop (BFS)

```
seed ─▶ [orchestrator --seed]  → depth-0 plan
  └─▶ agent runs the plan's actions for the current frontier (the technique commands)
        └─▶ collect discovered identifiers  ─▶ [orchestrator --ingest]
               → adds them as depth+1 nodes: deduped, cycle-checked, gated
               → prints the DEPTH CHECKPOINT (new nodes / edges / held / suppressed)
        ┌── autonomy=checkpoint → PAUSE: show checkpoint, await approval ──┐
        └─▶ approved → [orchestrator --plan] → next frontier's gated actions ┘
repeat until  --plan is empty (frontier exhausted)  OR  budget hit
final ─▶ emit edges → graph_build.py → interactive HTML map + /report
```

Concretely, per depth:

```bash
ORCH="$SKILL_DIR/scripts/pivot_orchestrator.py"; ST="<case>/pivot-state.json"

# 1. seed (once)
uv run "$ORCH" --state "$ST" --seed <target> --posture active --reach exhaustive --autonomy checkpoint

# 2. run the printed actions (the agent executes /webpivot, whois_enrich, /breach-deep, …)
# 3. feed results back — discoveries.json = [{from, value, type?, method?, confidence?, rel?}]
uv run "$ORCH" --state "$ST" --ingest discoveries.json         # prints the depth checkpoint

# 4. CHECKPOINT: present the summary to the analyst; on approval:
uv run "$ORCH" --state "$ST" --plan                            # next frontier's gated pivots
# → back to step 2 for the next depth. When --plan is empty:
uv run "$ORCH" --state "$ST" --edges                           # → connections for the graph/report
```

`discoveries.json` is assembled from technique output. Many collectors already emit the
right shape — e.g. `wayback_harvest.py --indicators` and `pivot_extract.py` JSON — map each
artifact to `{from: "<parent node key>", value, type, method, confidence}`.

---

## Identifier-type → pivot-action matrix (the edges)

Encoded in `EDGE_MATRIX` in the orchestrator. Each seed type expands via concrete skill
commands; **bold** yields feed back as the next hop's seeds:

| Seed type | Pivots (tool) → **yields** |
|-----------|----------------------------|
| **email** | reverse-WHOIS (`whois_enrich --reverse`)→**domain**; `/breach-deep`→**email/username/phone**; `/github-osint`→**username/domain/person**; `/dork-sweep`→**username/person/social** |
| **domain/url** | `/webpivot` (`pivot_extract`)→**email/phone/wallet/GA/social/favicon**; `wayback_harvest`→**historical selectors**; `whois_enrich` (current+history+reverse)→**registrant email/name/other-domains**; `/subdomain`→**subdomains**; `cert_pivot`→**sibling hosts/IPs**; DNS→**IP/MX/TXT**; `wayback_ga`→**shared GA/AdSense**; `/msftrecon`/`/saas-map`→**tenant/org** |
| **ipv4/ipv6** | reverse-DNS + passive-DNS (co-hosted)→**domains**; Shodan InternetDB / `/appliance-scan`→**services/hostnames**; ASN→**netblock/related IPs** |
| **username/handle** | `/username` platform-enum→**profiles/other-platforms/email/person**; `pivot_suggest` variants (leet/sequential)→**username**; `/github-osint`→**email/domain** |
| **person/name** | `/username` guess+enum→**handles**; people-search+`/dork-sweep`→**email/phone/org**; `/docleak` authorship→**email/org/domain** |
| **company/org** | primary+brand domains→**domain**; personnel→**person/email**; `/msftrecon` tenant→**domain**; GitHub org→**username/domain** |
| **wallet (btc/eth)** | `crypto_balance` on-chain flow→**counterparty wallets/exchanges** |
| **phone** | `/phone` reverse+carrier→**person/messaging handle** |
| **GA / AdSense ID** | reverse-analytics (PublicWWW/DNSlytics/urlscan)→**sibling domains** (high-value same-operator link) |
| **cert fingerprint** | `cert_pivot --hash`→**other hosts/domains** |
| **favicon mmh3** | Shodan/FOFA `http.favicon.hash`→**hosts/domains** |
| **ASN** | member IPs/domains→**IP/domain** |
| **social handle** | profile→**person/domain/username** |

Edges are recorded with the case-schema connection type (`CONTROLS`, `REGISTERED`,
`HOSTS`, `LINKED_TO`, `ALSO_KNOWN_AS`, `REACHES`, `WORKS_AT`, `ENCOMPASSES`,
`AUTHENTICATES`, `COMMUNICATES`, …) so the graph and report render the relationships.

---

## Gating — auto-pursue vs. hold vs. suppress

Reuses [`analysis/auto-branch-rules.md`](../analysis/auto-branch-rules.md) (Branch Priority
Matrix §5 + Suppression §6). Confidence → priority:

- **≥95% CRITICAL** — exact-match reuse (same GA ID / cert / favicon / registrant email
  across domains; handle exact-match on another platform). **Auto-pursue, unbounded.**
- **≥78% HIGH** — strong correlations. Auto-pursue, capped at 5 expansions per type/session.
- **≥63% MEDIUM** — plausible. Pursued under `balanced`/`exhaustive`, capped at 5.
- **<63% LOW** — weak. **Held** unless ≥2 corroborating findings; only under `exhaustive`.

Always **suppressed**: already-visited nodes (dedup / cycle prevention), anything past the
depth cap, global-budget overflow. Always **held**: privacy-protected/PII targets
(`person`, `phone`) unless `--authorization confirmed`. Under `posture=passive` (or
`passive-first` on a hostile node), **active** actions are held and only passive collection
runs.

This is the answer to "only pivot on things 100% related": exact-match links auto-expand;
everything softer is gated, and under `checkpoint` autonomy you approve each depth.

---

## Stopping conditions

1. **Frontier exhausted** — no new gated nodes (`--plan` empty). The natural "till the end."
2. **Budget hit** — `max_nodes` or `max_depth` reached (safety cap even under exhaustive).
3. **Diminishing returns** — a depth level yields little/no new non-duplicate nodes.
4. **Analyst stop** — at any checkpoint, choose to render the map instead of expanding.

On stop: `--edges` → `graph_build.py` → the interactive HTML force-graph + topology +
timeline, and the findings/indicators roll into the auto-saved report + IOC bundle.

---

## Cross-references

- `scripts/pivot_orchestrator.py` — the state machine (classify · dedup · depth · gate · checkpoint · edges)
- `analysis/auto-branch-rules.md` — the WHEN/THEN branch rules + priority/suppression matrix it enforces
- `scripts/webpivot/pivot_suggest.py` — ranks identity/domain variant pivots (feeds username/email/domain hops)
- `scripts/webpivot/graph_build.py` — clusters the emitted edges into the link graph
- `engine/subject-registry.md`, `engine/case-schema.json` — subject/connection model the edges map onto
```
