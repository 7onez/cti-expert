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
| **autonomy** | `auto` | **Run to closure unattended** — no approval prompts. Depth summaries still print as each level completes, so the expansion stays auditable after the fact. Pass `--autonomy checkpoint` to pause for approval at each depth instead. |
| **authorization** | `confirmed` | PII (`person`/`phone`) discoveries **auto-expand**. Set `unconfirmed` to hold them for manual review instead. |
| budget | `max_nodes=500`, `max_depth=6` | Safety caps even under `exhaustive`. |

Override per run — every flag **narrows**, since the defaults are already maximal:
`/case <target> --passive|--passive-first`, `--reach balanced|focused`,
`--checkpoint` (pause for approval each depth), `--depth N`, `--budget N`,
`--authorization unconfirmed` (re-hold PII), `--no-cn`. (`--redact` is the one *widening*
flag — it adds the redacted export variant, which is off by default.)

---

## The loop (BFS)

```
seed ─▶ [orchestrator --seed]  → depth-0 plan
  └─▶ agent runs the plan's actions for the current frontier (the technique commands)
        └─▶ collect discovered identifiers  ─▶ [orchestrator --ingest]
               → adds them as depth+1 nodes: deduped, cycle-checked, gated
               → prints the DEPTH SUMMARY (new nodes / edges / held / suppressed)
        ┌── autonomy=auto (DEFAULT) → continue straight through ───────────┐
        │   autonomy=checkpoint     → PAUSE: show summary, await approval  │
        └─▶ [orchestrator --plan] → next frontier's gated actions ─────────┘
repeat until  --plan is empty (frontier exhausted)  OR  budget hit
final ─▶ emit edges → graph_build.py → interactive HTML map + /report
```

Concretely, per depth:

```bash
ORCH="$SKILL_DIR/scripts/pivot_orchestrator.py"; ST="<case>/pivot-state.json"

# 1. seed (once) — the defaults are already active/exhaustive/auto, so no flags needed
uv run "$ORCH" --state "$ST" --seed <target>

# 2. run the printed actions (the agent executes /webpivot, /icp, whois_enrich, /breach-deep, …)
# 3. feed results back — discoveries.json = [{from, value, type?, method?, confidence?, rel?}]
uv run "$ORCH" --state "$ST" --ingest discoveries.json         # prints the depth summary

# 4. under autonomy=auto, go straight on (no approval step):
uv run "$ORCH" --state "$ST" --plan                            # next frontier's gated pivots
# → back to step 2 for the next depth. When --plan is empty:
uv run "$ORCH" --state "$ST" --edges                           # → connections for the graph/report
```

Loop this until `--plan` prints nothing. Under `--autonomy checkpoint` the same sequence runs,
but step 4 becomes an approval gate: present the summary and wait before calling `--plan`.

> **Backend-aware seeding (optional).** When the persistent intelligence backend is reachable
> (`/backend` resolves `$INTEL_HOME`), check each new seed against prior cases *before* expanding
> it — `which_cases` / `domain_verdict` (Tier-1 MCP) or `python3 $INTEL_HOME/tools/kb/query.py
> --kb knowledge --entity <seed>` (Tier-2). A hit means the operator is already known: fold in the
> historical edges and prioritise the frontier accordingly instead of re-walking it cold. Backend
> absent → skip this check, expand as normal. See [`../connectors/intel-backend.md`](../connectors/intel-backend.md).

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
| **ICP licence** | serial reverse-search (PublicWWW/FOFA/Quake)→**sibling domains** (same registrant — as strong as a shared GA ID); filing→**registrant company/USCC** |
| **USCC / CN company name** | `/cn-corp` registry chain (GSXT→aggregators)→**officers/shareholders/subsidiaries/domains**; `enscan`→**domains/ICP filings**; `pivot_suggest --cjk`→**pinyin & Traditional handle variants** |
| **IBAN** | `iban_analyze.py`→**issuing bank/org**; account-string reuse search→**domains/emails/persons** |
| **document** (pdf/office) | `exiftool`+`oletools` metadata/authorship→**person/email/org/coordinates** |
| **image** (jpg/png/…) | EXIF GPS→**coordinates**; reverse-image + face search→**person/domain/username/social** (LOW — held pending corroboration; face matches never auto-merge) |
| **coordinates** | reverse-geocode (Nominatim/Overpass) → location finding *(enrichment; no new seed)* |
| **VIN** | NHTSA vPIC + NICB decode → vehicle attributes *(enrichment; no new seed)* |
| **youtube channel** | about/links panel→**domain/social handle/email** |

Typing note: ICP nodes dedupe on the **licence serial**, so `苏ICP备12345678号-1` and `-3`
collapse to one operator node. IBANs normalize to unspaced uppercase. **document/image** are
typed by file extension and classified *before* `url`, so a discovered `.pdf`/`.jpg` link routes
to metadata/EXIF/face forensics rather than the generic web-DOM pivot. **coordinates / VIN** are
recognized and actioned (reverse-geocode, VIN decode) but yield no new clustering seed — wiring
them stops the loop silently dead-ending a typed value without inventing a false attribution.

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
depth cap, global-budget overflow. PII targets (`person`, `phone`) **auto-expand by default**;
pass `--authorization unconfirmed` to hold them for manual review. Under `posture=passive` (or
`passive-first` on a hostile node), **active** actions are held and only passive collection
runs.

This is the answer to "only pivot on things 100% related": exact-match links auto-expand and
everything softer is gated by confidence — **the gate, not a human prompt, is what keeps the
expansion tight**. That is why `autonomy=auto` is safe as a default; add
`--autonomy checkpoint` when you want to approve each depth as well.

---

## Stopping conditions

1. **Frontier exhausted** — no new gated nodes (`--plan` empty). The natural "till the end."
2. **Budget hit** — `max_nodes` or `max_depth` reached (safety cap even under exhaustive).
3. **Diminishing returns** — a depth level yields little/no new non-duplicate nodes.
4. **Analyst stop** — interrupt at any depth summary and render the map instead of expanding
   (the explicit gate under `--autonomy checkpoint`).

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
