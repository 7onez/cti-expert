---
name: IntelHarness
description: Run a whole OSINT case end-to-end — the Collect → Correlate → Assess pipeline over one or many seed domains, driven by Claude Code (no Agent SDK) using WebPivot + IntelAnalysis + the KB tools. Handles evidence archiving, versioned assessments, convergence, cluster-level judgment at scale, cross-case provenance, and false-positive control. USE WHEN work a case, run the harness, investigate these domains end to end, build the case from seeds, collect correlate assess, full investigation pipeline, cluster these domains, converge the case, batch of scam domains, attribute this cluster, produce an assessment with evidence, scale to many domains, run a case without the SDK.
---

> **OPSEC — this skill is portable/shared. Never write case data into it.** No real operator
> names, emails, domains, IPs, wallets, tracking IDs, hashes, or case IDs in this file, its
> workflows, tool code, or fixtures. Investigation data lives only in the git-ignored
> `cases/` / `knowledge/` / `MEMORY/`. In examples use placeholders (`example.com`,
> `site-a.example`, `G-XXXXXXXXXX`, `CASE-0001`). See the repo-root `CLAUDE.md` for the full rule.

# IntelHarness — run a case end-to-end, inside Claude Code

## 🎯 The GOAL of a case — an attributed OPERATOR, not a converged cluster

A case is run to **unmask the operator behind the infrastructure**. Collect → Correlate → Assess
is the machinery; the output that matters is *who runs this estate*, at the strongest rung the
evidence supports (named actor → persona → characterised-but-unnamed), with its confidence, or an
explicit **identity gap** plus the pivot that would close it.

That changes two things in how you drive the phases:

- **Collection is not finished when the seeds are collected.** It is finished when every host in
  the cluster has been mined for *identity-bearing* artifacts — registrant (current + historical,
  then reverse-WHOIS), owner-account tokens, advertiser/payer identity, document + source-map
  metadata, contact rails, wallets, leak-corpus hits. Estate-expanding artifacts (favicon, TLS,
  ASN, kit path) exist to hand you **more hosts to mine**, and expansion alone is not progress.
- **Convergence is not the stop condition; an answer is.** `converged` / `cold` describe the free
  search space, not the case. Before ending, state the operator (or "unattributed" and why) and
  the next identity-closing pivot — a run that stops on "no new domains" while never asking who
  has stopped early.

🚫 The goal does not relax the rails: adversarial verification, base rates, same-kit vs
same-operator, and persona-not-person still gate every identity claim. Unattributed is an
acceptable outcome; an unearned name is not.

This is the **Claude-Code-native front-end** to the OSINT harness: *you* (the agent) are the
orchestrator, following the phases below and calling the repo's CLIs directly. Same tools, same
KB, same evidence discipline as the Agent-SDK driver — but on the subscription, interactive, no
`claude_agent_sdk` and no `ANTHROPIC_API_KEY` needed.

**Two front-ends over one core — pick per situation:**

| | `harness/orchestrator.py` (Agent SDK) | **this skill** (Claude Code) |
|---|---|---|
| Auth | `ANTHROPIC_API_KEY`, pay-per-token | your Claude subscription |
| Run mode | headless / scriptable / cron | interactive, agent-in-the-loop |
| Output | schema-forced `Assessment` JSON | you write the assessment; `case_store.py` versions it |
| Best for | batch, unattended, reproducible pipelines | exploratory work, one case at a time, mid-case judgement |

Both read/write the same git-ignored `cases/` + `knowledge/` and produce the **same** versioned
snapshots + evidence manifest, so a case worked either way is continuous.

The tradecraft for each phase lives in the sibling skills — **read/apply `WebPivot` for collection
and `IntelAnalysis` for judgement.** This skill is the *orchestration*: what to run, in what order,
what to reject, and when to stop.

**Prefer the typed MCP tools when connected.** If the `intel` MCP server (repo-root `.mcp.json`,
`harness/mcp_server.py`) is available, the phase tools are exposed as native, typed tools —
`pivot_extract`, `fallback_probe`, `kb_ingest`, `kb_cluster`, `kb_entity`, `cert_overlap`,
`reference_check`, `which_cases`, `domain_verdict`, … — backed by the *same* CLIs. Use them instead
of shelling out; they're typed and permission-gated, and you skip the bash quoting. The `python3 …`
command forms shown in the phases below are the **fallback** for when the server isn't connected
(check `/mcp`), and remain the reference for exact flags.

---

## Setup (every run)

- **Case id**: `CASE-YYYY-NN` or a short slug (a CLI arg — never hardcode one).
- **KB dir**: defaults to `knowledge/`. For a throwaway/smoke run, `export HARNESS_KB=knowledge_scratch`
  and pass `--kb "$HARNESS_KB"` to the KB tools.
- Run all commands from the **repo root**.
- **Before collecting, check what's already known** (don't re-investigate):
  ```bash
  python3 tools/case_index.py <seed>                 # which case(s) is this domain/indicator already in?
  python3 tools/kb/operator_registry.py find <seed>  # already attributed to a known operator?
  ```
  If a seed is already attributed, show that verdict and skip re-collection unless the user wants a refresh.

---

## Phase 1 — COLLECT  (apply `WebPivot`; cheap, mechanical)

For **each NEW seed**, collect with full enrichment + evidence capture:
```bash
python3 WebPivot/tools/pivot_extract.py <url> --pretty \
    -o cases/<CASE>/raw/<host>.json --save-dom cases/<CASE>/dom/<host>.html \
    --archive-missing --master --case <CASE>
```
- `--archive-missing` submits a Wayback snapshot so the copy survives takedown; `--master` appends
  every pivot to the case evidence ledger. Add `--render --screenshot cases/<CASE>/screenshots/<host>.png`
  for visual evidence (needs the WebPivot `.venv` / Playwright).
- **HOSTILE target** → never a bare live fetch: use `--proxy-range <cidr>` or feed an
  already-saved/archived HTML file. (See `WebPivot/EthicalFramework.md`.)
- **Cloudflare** interstitial → retry with `--render` (browser) or `--solve-cf --flaresolverr <url>`.

**EMPTY-RESULT RULE — never end a seed on silence.** If `pivot_extract` returns zero/near-zero
pivots or a parked / empty-favicon / NXDOMAIN page (WHOIS+FOFA+urlscan all cold), run the keyless
last-resort probe and report its **VERDICT**:
```bash
python3 tools/fallback_probe.py <host> --kb "${HARNESS_KB:-knowledge}"
```
It sweeps CT certs through the shared `wp_ct` client (SAN-sibling domains = strongest same-owner
link), the full Wayback timeline (parked-today was often live last year), archive.today, ready-to-run
search dorks, and the local KB → `PIVOTABLE` (leads), `NO-PIVOT-YET` (cold + next steps) or
`INCONCLUSIVE-CT-DEGRADED` (cold, but crt.sh was unreachable — re-run before calling it cold).

Then **ingest** so collection becomes correlatable, and (re)build the evidence manifest:
```bash
python3 tools/kb/ingest_webpivot.py --kb "${HARNESS_KB:-knowledge}" cases/<CASE>/raw/*.json
python3 tools/case_store.py manifest <CASE>
```

---

## Phase 2 — CORRELATE  (apply `IntelAnalysis`; the judgement)

Reason over the ingested KB. For each seed, its focused subgraph is the primary evidence:
```bash
python3 tools/kb/query.py --kb "${HARNESS_KB:-knowledge}" --cluster <host> --strong   # same-operator peers
python3 tools/kb/query.py --kb "${HARNESS_KB:-knowledge}" --entity  <host>            # facts + edges + provenance
python3 tools/kb/risk_signals.py --case <CASE>                                        # NRD / BPH / money-trail
```
Corroborate and control false positives with:
```bash
python3 tools/cert_overlap.py <domain-a> <domain-b> [...]     # shared TLS cert / SAN cross-cover = near-decisive
python3 tools/case_index.py <domain-or-indicator>            # which prior case(s) — cross-case links
python3 tools/kb/reference.py --kb "${HARNESS_KB:-knowledge}" check <hash-or-keyword>  # benign / signal / unknown
```

### Noise discipline — the golden rules (this is what separates real clusters from false ones)
1. **`--strong` for clustering.** It drops boilerplate edges (shared WP-Rocket CSS / HTML comments /
   DOM skeleton) and indicators shared by > 8 domains (`--max-prevalence`), so only **owner-set**
   indicators cluster (favicon / GA / GTM / verification / wallet / brand-theme / socials).
2. **`reference_check` before trusting a shared hash.** BENIGN = a common logo/CDN/CSS artifact →
   discard it. If you confirm a new benign or a distinctive signal, remember it:
   `reference.py add --value <ind> --verdict benign|signal --label "..." [--case <CASE>]`.
3. **Managed DNS / parking favicons / registrar-privacy emails are NOT operator links** (see
   `tools/kb/noise_filters.py`). A shared Cloudflare nameserver clusters nothing.
4. **A cert whose SAN list covers two otherwise-unrelated domains is near-decisive same-owner.**
5. **State the competing explanation you ruled out** — that's what makes an attribution defensible.

### Chain further: high-value HTML string / unique subdomain → FOFA body & CT
When correlation surfaces a **distinctive HTML string** (a slogan, brand phrase, unique class or
template literal — the kind of thing `IntelAnalysis` calls out as high-value) or a **unique
subdomain label**, feed it straight back into collection as a new search — this is how a case grows
past its seed set:
```bash
# HTML-string pivot — FOFA body-searches the served HTML for every host running the same page
python3 WebPivot/tools/pivot_extract.py <url> --fofa-keyword "<distinctive phrase>" \
    --fofa-keyword "<second phrase>" --pretty -o cases/<CASE>/raw/<host>.json
# unique subdomain label (e.g. svc-a.site-a.example) is auto-emitted as a `subdomain` pivot with
#   FOFA host="<label>." · crt.sh <label>.% · Censys names:<label>.*   (Shodan host search is not a CT source)
```
`pivot_extract` already auto-emits a FOFA `body=` query for every HTML-string artifact and runs the
keyword/subdomain reverse **live** when a `FOFA_KEY` is set. Collect the new hosts (Phase 1),
re-ingest, and re-correlate — repeat until convergence. Prefer FOFA `body=` / CT over PublicWWW on
**freshly-registered** domains PublicWWW hasn't indexed yet.

**General-web search pivot (`search_pivot`).** FOFA/PublicWWW only see served HTML; the open web
indexes the *off-infrastructure* mentions (forums, complaints, pastebin, social, RU-CIS sites) that
name an operator's other domains. For a distinctive indicator (domain, slogan, tracking ID, wallet,
Telegram/Zalo handle), call **`search_pivot`** (MCP tool, or `python3 tools/search_pivot.py
"<indicator>" --engines google,yandex,duckduckgo`) to get ready-to-open dork URLs across Google /
Yandex / DuckDuckGo / Bing / Brave — Yandex especially for Cyrillic/RU-CIS + reverse-image. It does
**not** scrape (SERPs are bot-walled); **fire the queries with Claude Code's own `WebSearch` +
`WebFetch`** (WebFetch the readable `html.duckduckgo.com` URL — Google/Yandex bot-wall a plain
fetch), extract candidate hosts from the results, and feed the NEW ones back into Phase 1. The
`cti-fanout-case` workflow runs this as an opt-in `Search-expand` phase (`args.expand` /
`args.keywords`). Free, no keys.

---

### Adversarial verify — refute every link before you commit it

Before writing the assessment, switch sides and try HARD to **break** each same-operator link you
drew. A link that survives a genuine refutation attempt is defensible; one you never attacked is not.
For each shared-artifact link: `reference.py check` it (BENIGN → discard), `query.py --entity` it for
**prevalence** (shared by many unrelated domains → managed-DNS/parking/platform noise, not an operator
link), re-run `cert_overlap.py` on the specific pair (only a SAN cross-cover survives — a shared CA
does not), and name the innocent **competing explanation** (shared host/CDN/registrar/SaaS/brand
coincidence). **Default to refuted when uncertain.** Keep only the links that survive; fold the
refuted ones into the assessment's `gaps` as competing explanations ruled out. The SDK harness does
this automatically as a phase between correlate and assess (`HARNESS_VERIFY`, disable per run with
`--no-verify`); the `cti-fanout-case` workflow runs it as a 3-skeptic panel vote (2-of-3 refuted kills
a link). This is the harness's core false-positive control — don't skip it.

**Collecting ≠ attributing (cross-type tiers).** Kit-rung and neighbour-rung hits the loop collects are `add_fact` only — they render as kit siblings / neighbours with a rung caveat and must never appear in the attributed `cluster`. Mentions (news/pdf/EoT/mediacloud) stay observational. Owner-link classes alone may cluster.

## Phase 3 — ASSESS  (write it, then version it)

Write the assessment as JSON to a temp file, following the `IntelAnalysis` estimative discipline and
this schema:
```json
{
  "bluf": "one sentence with an estimative word (assessed / likely / possible)",
  "cluster": [{"domain": "site-a.example", "shared_artifacts": ["favicon:123456789", "ga:G-XXXXXXXXXX"]}],
  "attribution_level": "same-kit | same-operator | same-actor | inconclusive",
  "confidence": "low | moderate | high",
  "evidence": ["cited artifacts justifying the attribution level"],
  "gaps": ["what could not be verified + the competing explanation ruled out"],
  "next_pivots": ["prioritised open leads, highest yield/cost first"]
}
```
Then snapshot it (immutable history + living `SUMMARY.md` + `CHANGELOG.md`), with the standard table:
```bash
python3 tools/domain_table.py cases/<CASE>/raw/*.json --case <CASE> --kb "${HARNESS_KB:-knowledge}" > /tmp/<CASE>_table.md
python3 tools/case_store.py snapshot <CASE> --assessment /tmp/<CASE>_assessment.json --table /tmp/<CASE>_table.md
```
Every run appends `assessments/<UTC>_r<n>.{md,json}` — **nothing is overwritten**; `SUMMARY.md` is the
current head. Show the BLUF + attribution/confidence + the evidence trail (full, unshortened URLs).

### Deliverables — auto-emit the figure + PDF/DOCX

Right after the snapshot, produce the shareable deliverables so a finished case ships with a
relationship figure and a polished report. Both are best-effort — skip on a missing
diagram renderer (Node/Bun for Pele, or an SVG rasteriser) or `pandoc`, don't fail the case.

> **LOAD THE `IntelGraph` AND `IntelReport` SKILLS FIRST — the `render_diagram` / `render_report`
> MCP tools are renderers, not the deliverable.** They apply the figure encoding and the LaTeX
> template; they do **not** supply the report's structure or its OPSEC rules. Calling them on a raw
> `case_store` snapshot yields a document that is *typeset* correctly and *wrong* as a report: no
> Executive-Summary-first Key Judgments, no early Methodology with the Admiralty + ICD-203 tables,
> no artifact-register or per-domain-profile appendices — and, because the snapshot is an internal
> working artifact, it leaks collector/vendor names while leaving the actual indicators unnamed.
> Two specifics the tools cannot fix for you:
> - pass **`report_ref`**, never `case_id` — `case_id` stamps the internal case-store id on the
>   cover and every page header (IntelReport Rule 11);
> - **name every indicator in the body** — seed domain, IPs, hashes, impersonated brands — and keep
>   tool/vendor/case-store names out (IntelReport Rules 12a/12b). Redacting evidence is the single
>   most common defect; a findings section that never says *which domain* it is about has failed.
>
> Write the assessment markdown to the `IntelReport` contract, then call the tools to render it.

0. **Write the figure recipe (`figures.json`) so the report ⇄ chart stay chained.** At assess-time,
   drop `cases/<CASE>/report/figures.json` (only if absent — don't clobber a curated one) so a later
   `render_report.py` rebuilds the chart from current raw data automatically:
   ```json
   {"figures": [{"raw_glob": "../raw/*.json", "graph": "case_graph.json", "stem": "case_diagram",
     "title": "<case title>", "direction": "LR", "legend": true,
     "drop_types": ["nameserver","registrar","template","theme","email"]}]}
   ```
   (The SDK's `_ensure_case_diagram` writes this automatically; do the same on the Claude-Code path.)
1. **Editable relationship diagram** — build the case graph, then `render_diagram`:
   ```bash
   python3 WebPivot/tools/graph_build.py cases/<CASE>/raw/*.json -o cases/<CASE>/report/case_graph.json
   ```
   then call the **`render_diagram`** MCP tool (`graph_json=cases/<CASE>/report/case_graph.json`,
   `stem=cases/<CASE>/report/case_diagram`, `legend=true`, `drop_types` to prune noise nodes) →
   editable `.mmd` + PNG/SVG. From here on, `render_report.py` refreshes this figure on every render
   (via `figures.json`), so you don't rebuild it by hand after edits.
2. **Report PDF + DOCX** — reference the figure from the snapshot markdown (add a
   `## Relationship graph` + `![...](case_diagram_hires.png)` section, and a YAML frontmatter
   block with `title` / `case_id: <CASE>` / `classification`), then call the **`render_report`**
   MCP tool (`markdown=<that md>`, `stem=cases/<CASE>/report/<UTC>_r<n>`, `case_id=<CASE>`) →
   `report/<...>.pdf` + `.docx`. No analyst name is stamped; the date defaults to UTC today.

Deliverables land in `cases/<CASE>/report/` (figure + report md + PDF/DOCX in one dir so the
image path resolves). See the **IntelGraph** and **IntelReport** skills for detail.

---

## Iterate to convergence — the resumable gap-chasing loop

The whole feedback loop — **collect → assess → read the assessment's gaps → chase them back into
WebPivot → repeat until nothing new can be collected for free or you say stop** — is one resumable
command. It never spends metered credits on its own (free-only collection; FOFA/WhoisXML pivots are
deferred for your approval), and it **checkpoints every round** so an interrupt resumes and a cold
case picks up later breakthroughs:

```bash
python3 tools/intel.py loop <CASE> seeds.txt        # first run (or a comma list: a.com,b.com)
python3 tools/intel.py loop <CASE>                  # RESUME — omit seeds; continues from state.json
python3 tools/intel.py loop <CASE> --max-rounds 8 --max-new 10
```

Each round: collect the pending seeds with `pivot_extract --free-only` (keyless crt.sh / passive-DNS /
urlscan / RDAP WHOIS — **zero credits**) → ingest → `convergence.py snapshot` → write
`assessment.md` **and** machine-readable **`assessment.json`** → mine every collected `raw/*.json` for
the next **free frontier** (new registrable apexes from crt.sh SAN siblings, passive-DNS co-hosts,
urlscan-related, TLS co-SAN, CORS origins, impersonation lookalikes, reverse-WHOIS siblings of a
registrant **email/phone** — a registrant NAME/ORG reverse is a namesake search and is only a
`whois` lead; shared
infra/noise filtered) → checkpoint. CT seeding is re-registration-safe: the flat crt.sh name list
seeds only the case's own subdomains; a foreign apex seeds only from an examined narrow cert issued
on/after the host's current WHOIS `created` date. Foreign names from unexamined (truncated) certs, a
previous-owner-era cert, or an unknown registration date become `cert_overlap` leads, never seeds.
It **stops** when `convergence.py` says **CONVERGED** (last `--stale` rounds added nothing **and no
host failed to collect** — a failed host is labelled `[fail]`, retried next round, and after 2
consecutive failures written off as an `assessment.json` gap), the frontier is empty (**cold**), or
the round cap is hit (**awaiting-analyst**).

**Historical origin IPs ride the same frontier.** `frontier()` also returns `ips_pending` — the
non-CDN addresses each expanding host (apex or subdomain) ever resolved to, from the merged
`origin_history` block (`WebPivot/tools/wp_origin_history.py`: passive DNS, SecurityTrails history,
Validin, urlscan hostname index, Webamon, passive SSL, keyless urlscan scans; CDN / WAF / parking /
bogon dropped by CIDR **and** source-reported ASN/org). The loop (`_promote`) and the harness
(`propose()` → free kit-rung `collect` of type `ip`) collect them as IPPivot seeds at the host's hop,
capped per host and per round (`references/origin_history.json → sweep_policy`). Each IP's raw is
then mined like any reverse-IP: co-tenants pass the co-host guards as neighbour-rung seeds — unless
the case's hosts used that box only **historically/undated** (`meta.origin_context.stale`) or its
network is `ambiguous` (DDoS-Guard / StackPath), in which case they become a dated held lead; an
address last seen before the current registration is a `previous-owner origin IP` lead and is never
collected. The box's OWN lookup (IPinfo ASN/org) is classified again, so a CDN / parking network the
history sources never named yields an `edge network (IP lookup)` lead instead of seeds. On a
**cloud/VPS** network (`ip_intel.noise` from the ASN registry, verdict still origin) up to
`sweep_policy.vps_auto_max_cotenants` (10) co-tenants seed and link automatically — the count is
`wp_origin_history.cotenant_count` on BOTH the frontier and KB-ingest side (case hosts and
shared-infrastructure apexes excluded, `ip_intel.cohost_total` honoured); above it a
`vps co-tenancy — approve` lead lists every domain and `propose()` offers each as an approval item
(`est_hits` above auto_max, source `approve_ip:<ip>`) — nothing is collected or linked until the
analyst approves. An approved run (`_run_approved`) records each domain that RAN in `state.json →
approved_cohosts {ip: {domains, hosts}}` (the loop's analyst-run equivalent is
`scripts/backend/intel.py approve-cohost <case> <ip> <domain…|--all>`; no MCP tool exists for it).
From then the frontier seeds exactly those domains, ingest links exactly those, and the partition
(`query._components(allow_edge=case_state.approved_edge_allow)` and the `binding_indicators` filter in
`intel._write_clusters`) lets only their `hosted_on` edges and those of the case hosts that led to the
box bind past the landlord rule AND the `max_prevalence` cap (8); automatic VPS links keep the cap.
Domains are compared with `wp_origin_history._apex`, which keeps a shared-platform tenant label
(`noise_filters.SAAS_TENANT_SUFFIXES`, the frontier's own list). Unapproved sites keep
the rules — the automatic-vs-approval decision stays on the WHOLE tenant set, so a rejected site never
turns automatic. Stale / ambiguous / edge verdicts are never overridden by approval. Every
origin-sweep lead carries the full `domains` list. `--free-only` IPPivot runs IPinfo keyless,
keyless HackerTarget reverse-IP and free Validin, and skips FOFA / Shodan / Censys / CIRCL.

Each round also writes **`clusters.json`** — this case's hosts partitioned into same-operator
components (strong edges only, the same partition `orchestrator.py --parallel` judges over) with the
indicators binding each one and their **KB-wide prevalence**. Judge **per cluster, not per case**: a
200-domain case is N attribution questions, not one, and `assessment.json.next_pivots` now names each
multi-domain cluster as its own judgement task. `shared.txt` is scoped to the case's hosts for the
same reason — unscoped it reported every past case's indicators.

> 🔑 **`--free-only` is analytically keyless — say so when reporting a loop result.** Every metered
> index (FOFA, urlscan-authenticated, WhoisXML history/reverse, Censys, CIRCL pDNS) is suppressed by
> design, so a converged loop means *"the free frontier is exhausted"*, **not** *"the operator has no
> more infrastructure"*. Run `python3 WebPivot/tools/wp_capabilities.py --free-only` (or the
> `capability_check` MCP tool) and state which indexes went unqueried before presenting a CONVERGED
> or **cold** verdict; each round's `raw/*.json` already carries it as `meta.capability`. The
> metered leads the loop deliberately did not chase are listed in `assessment.json.metered_leads` —
> that list, plus the missing-key list, is the honest answer to "is that everything?".

The frontier will **not auto-seed co-tenancy**: a multi-tenant TLS cert, a shared/bulk-hosting or CDN
IP, and a bulk or privacy/registrar registrant term all name other *customers*, so they are held back
as `co_tenancy_leads` (free to check by hand with `cert_overlap`) instead of collected. This matters
more than a wasted fetch — a bad seed gets **ingested**, and then pollutes every later case.

Two persisted artifacts drive it (both under `cases/<CASE>/`):
- **`state.json`** — the stage machine: `status` (expanding · converged · cold · awaiting-analyst),
  round cursor, the `collected` / `pending` / `consumed` queues, deferred `metered_leads`, and history.
  Ground truth is reconciled from `raw/*.json` each run, so a mid-round interrupt never corrupts it.
- **`assessment.json`** — the **same schema the SDK/IntelAnalysis path writes** (`bluf`, `cluster`,
  `attribution_level`, `confidence`, `evidence`, `gaps`, `next_pivots[str]`) so both front-ends are
  interchangeable; the loop stamps `attribution_level:"inconclusive"` (it never attributes — that's
  IntelAnalysis's job) and keeps its structured detail under an additive `loop` key
  (`loop.frontier`, `loop.metered_leads` — the FOFA/WhoisXML pivots deferred for approval, **never
  auto-run**). **The loop never clobbers an analyst-written assessment.json** — if one exists it
  reads its `next_pivots`/`gaps` for domain leads (folding them into the frontier, analyst-first)
  and drops its own view in `loop_assessment.json`. This is the WebPivot⇄IntelAnalysis chain: run
  the loop, invoke **IntelAnalysis** to judge/attribute over the KB and write the real assessment,
  then re-run the loop — it picks up the analyst's next_pivots automatically.

Inspect or steer the loop without collecting (also exposed as MCP tools `case_frontier` / `case_loop`
/ `case_reopen`, and to the SDK harness):
```bash
python3 tools/case_state.py status   <CASE>              # stage, queues, convergence verdict
python3 tools/case_state.py frontier <CASE> --json       # the gaps + deferred metered leads
python3 tools/case_state.py reopen   <CASE> newlead.com  # COLD-CASE reopen: re-mine vs the current KB
```

**Analyst override** — the loop chases the *free* frontier automatically; your judgment enters by
feeding seeds (`intel.py loop <CASE> a.com,b.com` merges them into pending and re-opens a finished
case) or by approving a `metered_leads` pivot and running it by hand. **Cold-case benefit:** because
`reopen` re-mines against the *current* KB + operator registry, an old case re-run after a later case
proves a new operator link automatically inherits that breakthrough.

*(Low-level pieces still work standalone: `convergence.py snapshot/status` owns `rounds.jsonl`; the
SDK mirror is `orchestrator.py --continue`. `intel.py loop` is the deterministic Claude-Code driver
that ties them together with resumable state + gap-chasing.)*

---

## Scale — many domains (10s–100s)

Don't loop one giant reasoning pass over 100 domains. **Partition first, judge per cluster** — use
the `case_clusters` MCP tool, or the CLI:
```bash
python3 tools/intel.py clusters <CASE>            # components + the indicators binding each
python3 tools/intel.py clusters <CASE> --json     # machine-readable (also written to clusters.json)
```
Each cluster lists its binding indicators with their **KB-wide prevalence**, so an indicator binding
3 domains here but sitting on 400 KB-wide is visibly noise. (The raw form is
`query.py --components --domains "$DOMS"`.) Then, per cluster:
- if **every** member is already attributed (`operator_registry.py find`) → reuse the prior verdict, **skip judgement**;
- else run Phase 2 + Phase 3 for **just that cluster's domains**, and snapshot it.

Collection scales by fanning `pivot_extract` across seeds (independent processes / background Bash);
each cluster is a small, focused judgement, so cost tracks cluster count, not domain count. (This
mirrors `orchestrator.py --parallel`.)

**Reactive parallel collect (`--fanout`).** `--parallel`'s `collect_many` is a deterministic
thread-pool — fast, but it runs one fixed `pivot_extract` per seed with no per-seed reasoning. When
seeds each need the *reactive* tradecraft (empty→`fallback_probe`, hostile→passive, CF→render) **and**
you want it concurrent, `orchestrator.py --fanout [--collect-conc N]` spins one WebPivot collector
agent per seed (the wired `agents.py` `collector` persona, `collect_fanout`) under a semaphore, then
ingests once. Use `--parallel` for large/mechanical sweeps, `--fanout` for small–medium seed sets
where per-seed collection judgement matters.

In Claude Code, the `cti-fanout-case` **workflow** (`.claude/workflows/`) mirrors both: collector
per seed → ingest → **`case_clusters` partition** → then Correlate → Verify → Assess **per cluster**,
pipelined. Verification is a 3-lens skeptic panel per cluster (benign/prevalence ·
competing-explanation · TLS/infra), 2-of-3 refuted kills a link. Fan-out is capped
(`args.maxClusters` default 3, `args.maxLinks` default 6) and **whatever a cap drops is logged** —
an unjudged cluster or an unverified link must never be reported as established.

---

## Close the loop — LEARN (do this when an attribution is confirmed)

```bash
python3 tools/kb/operator_registry.py add "<Operator label>" --domains <d1,d2,...> --case <CASE> \
    --confidence assessed --basis "the artifacts that tied them (cited)"
python3 tools/kb/reference.py --kb "${HARNESS_KB:-knowledge}" ingest-case <CASE>   # bank the case's unique hashes as a watchlist
```
Attributing the cluster + banking its distinctive fingerprints is what makes the NEXT case faster —
future collections that hit a `signal` fingerprint or an attributed domain resolve instantly.

---

## Cost per run

- **Interactive (this skill / Claude Code):** the model can't read its own spend — run **`/cost`**
  to see the Anthropic model cost of the session/run.
- **Headless (`harness/orchestrator.py`, Agent SDK):** each run prints per-phase + total
  `total_cost_usd` and appends a line to **`cases/<CASE>/run_cost.jsonl`** — sum that file for the
  case's model cost over time.
- **API credits (FOFA / urlscan / WhoisXML / IPinfo / Shodan)** are separate from `total_cost_usd`
  and now **logged locally** every collection: each licensed call appends to
  `MEMORY/api_usage.jsonl` (git-ignored, tagged with case + skill), and every `pivot_extract` run
  prints an "API usage this run" summary. See totals with:
  ```bash
  python3 WebPivot/tools/api_usage.py report [--case <CASE>] [--since YYYY-MM-DD] [--last 20]
  ```
  or the `api_usage` MCP tool. Credits are best-effort **unit counts** (1 = one query/request;
  urlscan_search = 1 per page), plus the provider's reported quota-remaining where exposed (urlscan
  headers) — a usage log, not an invoice. The report splits the total into **free / quota /
  metered** subtotals (classes in `WebPivot/references/api_cost_classes.json`: a reverse-WHOIS
  preview or keyless call is free, a capped plan like urlscan is quota, per-call billing is
  metered) and labels the total "estimated units". `pivot_extract.py` makes **zero** Anthropic calls.

## Phase ↔ tool map (parity with `harness/orchestrator.py`)

| Phase / step | This skill runs | SDK-harness counterpart |
|---|---|---|
| prior-knowledge | `case_index.py`, `operator_registry.py find` | `_prior_knowledge`, `domain_verdict` |
| collect | `pivot_extract.py --archive-missing --master` | `collect_one` / `collect_many` / `collect_fanout` (`--fanout`) |
| empty-seed | `fallback_probe.py` | `fallback_probe` tool |
| ingest | `ingest_webpivot.py` | `ingest` |
| plan (cross-type) | read-only KB/status tools only — no spend/approve | Plan phase (`PLAN_TOOLS`); consumes `propose` candidates |
| propose / approve | `case_state.py propose`; `harness approve` / `case_approve` / TTY | digest-bound `proposal.json`; `audit.gate` enforces |
| corpus-search | `pivot_routes.py` / `corpus_search` | Collect phase route runner |
| correlate | `query.py --cluster --strong`/`--entity`, `cert_overlap.py`, `reference.py check`, `risk_signals.py` | Correlate phase tools |
| verify (adversarial) | refute each link — `reference.py check`, `query.py --entity` (prevalence), `cert_overlap.py` | verify phase (`HARNESS_VERIFY`, `--no-verify`) |
| cross-case | `case_index.py` | `which_cases` |
| assess + version | write JSON → `case_store.py snapshot` | schema-forced `Assessment` (owner `cluster` only; `kit_siblings`/`neighbours`/`mentions` never attributed) + `_persist_assessment` |
| deliverables | **load `IntelGraph` + `IntelReport` skills**, author the assessment md to the IntelReport contract, then `graph_build.py` → `render_diagram` + `render_report` (pass `report_ref`, not `case_id`) | `_render_deliverables` (auto, best-effort) |
| evidence manifest | `case_store.py manifest` | `_append_manifest` |
| converge | `convergence.py snapshot/status` | `--continue` loop |
| **gap-chasing loop (resumable)** | `intel.py loop <CASE>` = collect(free-only)→assess→`case_state.py frontier`→repeat, checkpointed to `state.json` (`case_frontier`/`case_loop`/`case_reopen` MCP tools) | `run_case` / `run_case_parallel` (`--continue`) |
| scale | `intel.py clusters <CASE>` (`case_clusters`) + per-cluster judge | `--parallel` / `run_case_parallel` |
| learn | `operator_registry.py add`, `reference.py ingest-case` | close-out step |
