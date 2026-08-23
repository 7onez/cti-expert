# OSINT harness (skeleton)

> **Two front-ends over the same tools/KB.** This directory is the **Agent-SDK** driver
> (`ANTHROPIC_API_KEY`, pay-per-token, headless/scriptable, schema-forced output). The
> **`IntelHarness` skill** (repo root) runs the *same* Collect→Correlate→Assess pipeline from
> inside **Claude Code** (your subscription, interactive) by driving the same CLIs. Both produce
> identical versioned assessments + evidence via the shared, SDK-free `tools/case_store.py`. Use the
> SDK driver for batch/unattended runs; use the skill for interactive, one-case work.

A **controlled agent loop** around the existing skills + tools. The LLM still
reasons and picks tools — the harness fixes the *environment* so a run is
repeatable. This is the middle of the spectrum:

```
Interactive Claude Code  ──►  THIS HARNESS  ──►  Deterministic pipeline (intel.py open)
  reasoning, unconstrained      reasoning inside a fixed scaffold      no reasoning
```

## How it works

Three phases; each is one `query()` call, wired so consistency comes from the scaffold:

| Phase | Skill as `system_prompt` | Tools exposed | Output |
|---|---|---|---|
| **Collect** | `WebPivot/SKILL.md` | `pivot_extract`, `fallback_probe`, `kb_ingest` | raw JSON in `cases/<case>/raw/`, ingested to KB |
| **Correlate** | `IntelAnalysis/SKILL.md` | `kb_cluster`, `kb_entity`, `kb_query_shared`, `risk_signals`, `reverse_whois`, `cert_overlap`, `domain_verdict` (read-only) | in-context reasoning |
| **Assess** | `IntelAnalysis/SKILL.md` | read-only | **schema-forced `Assessment` JSON** |

- Context carries across phases via `resume=<session_id>`.
- The final phase uses `output_format={"type":"json_schema", ...}` → validated
  `Assessment` (see `schemas.py`). That's the deterministic checkpoint.
- **Model cascade** (cost lever): `COLLECT` = `haiku`/`low` (mechanical), `JUDGE` = `sonnet`/`high`
  (default — capable but ~3–5× cheaper than Opus), and the **assess phase escalates to `opus`
  only when Sonnet returns low confidence** (`HARNESS_ESCALATE=0` to disable). Opus is paid for
  only where it earns it. All env-overridable:
  ```bash
  HARNESS_COLLECT_MODEL=haiku  HARNESS_JUDGE_MODEL=sonnet \
  HARNESS_ESCALATE_MODEL=opus  HARNESS_ESCALATE=1 \
  python3 harness/orchestrator.py CASE-0001 https://site-a.example
  ```
- **Focused retrieval** (cost lever): the judge is steered to `kb_cluster(seed)` / `kb_entity(seed)`
  (a seed's subgraph) instead of dumping the whole KB via `kb_query_shared` — far less context per
  Opus/Sonnet turn.
- Each run prints its **cost breakdown** (SDK `total_cost_usd`, per phase + total) to stderr,
  so stdout stays clean JSON. Use it to measure real cost-per-case on your first runs.

## Scope the case before you collect (`case_scope.py`)

WebPivot's §0 intake is a conversation, and the harness has nobody to talk to. `intel.py open`,
the SDK driver, the MCP server and every batch run start from a bare seed list — so the scoping a
Claude Code session gets by *asking* was simply absent from the path that does the volume.
`case_scope.py` is where the answers live instead: given once, persisted to
`cases/<case>/scope.json`, and rendered into **every** phase prompt (`{{scope}}`) on every later
round and resume.

```bash
python3 harness/orchestrator.py CASE-0001 \
    --target-class victim_host --purpose attribution \
    --claim "compromised CMS serving a phishing kit" --basis "victim complaint" \
    --brand "Example Brand" --how ad --window 2026-03 \
    --falsifier "the whole site is the operator's, not an injected path" \
    https://host-a.example
python3 harness/case_scope.py questions        # what to ask when an analyst IS in the loop
python3 harness/case_scope.py show CASE-0001   # what a phase is actually being told
```

It changes three things that were previously guesses:

| | |
|---|---|
| **Posture — and it is ENFORCED** | `target_class` resolves to a `fetch_posture`. `threat_actor_infra` (`never_direct_from_analyst_egress`) and `--no-direct-contact` both derive `hostile=True`, which the `audit.py` PreToolUse gate turns into a **hard denial** of outbound collection. A posture that only lives in a prompt is one the model can talk itself out of. `passive_first` deliberately does **not** derive it — passive-first is an *ordering* instruction, and conflating it with a prohibition would turn every unscoped run into a no-fetch run. |
| **Ownership — what may be clustered** | On `victim_host` the page's WHOIS, favicon, certificate and analytics belong to the **victim**; clustering on them fuses unrelated victims into one imaginary operator estate. The class's `clustering_rule` goes into the collect **and** the judgment prompts — the collector labelling it correctly is no use if the correlator still clusters on it. |
| **The claim, as a hypothesis** | The requester's assertion is recorded with its **source** and put in front of correlate/verify/assess with its falsifier — never written to the KB as a fact. The structured `Assessment` now carries `premise` + `premise_verdict` (`supported` / `partially_supported` / `not_supported` / `contradicted` / `inconclusive`), so the claim gets **answered** instead of becoming the frame the whole assessment was written inside. |

**It never blocks.** No flags, a corrupt `scope.json`, an unwritable case dir or a typo'd class →
the run continues under `unknown` (the conservative class) and every prompt tells the model to
disclose that it is assuming. `premise_verdict` defaults to `inconclusive`, so an omission can
never read as a claim confirmed. Interactively, the `case_scope` MCP tool reads and writes the
same record — that is how an analyst's answers reach the automated path.

Vocabulary (classes, postures, questions, verdicts, prohibitions, switches) is tunable data in
`WebPivot/references/intake.json`, one owner shared with the skill so the two front-ends cannot
drift. Gate: `tests/test_case_scope.py`.

## Debug dashboard — where the tokens went, and what looks wrong (`dashboard/`)

```bash
python3 harness/dashboard/serve.py            # → http://127.0.0.1:7788
python3 harness/dashboard/serve.py --sessions 200 --no-browser
python3 harness/dashboard/collect.py findings  # same data, as JSON, no server
```

Python stdlib only — no framework, no npm, no build step. It **reads** five append-only sources
that already exist and joins them; it instruments nothing, writes nothing, and makes no outbound
request.

| Source | What it contributes |
|---|---|
| `~/.claude/projects/<this repo>/*.jsonl` | Claude Code sessions — exact per-turn tokens (input / output / cache read / cache write, 1h vs 5m), model, effort, tool calls, `stop_reason`, subagent turns |
| `MEMORY/` + `cases/*/tool_calls.jsonl` | the gate ledger — every call, allowed or **DENIED**, with the reason |
| `MEMORY/api_usage.jsonl` | third-party credits by provider / case / day |
| `cases/*/run_cost.jsonl` | the SDK's own per-phase Anthropic cost |
| `SKILL.md` / `prompts/*.md` / `CLAUDE.md` | the context floor each phase carries before turn 1 |

**Six panels.** *Overview* leads with a findings list, so you learn something is wrong without
knowing which tab to open. *Trace* **replays one session** — the prompt that went in, the pinned
context it carried, every tool call with its **arguments** and the **raw result** that came back,
the reply that came out, and what each turn cost, in order; a run-flow ribbon puts the whole
session on one line and jumps to any step. It is the panel for *why* an answer was wrong rather
than *how much* it cost. *Tokens & cache* gives per-session and per-turn input/cache-read/
cache-write splits, peak context, and cost. *Prompt surface* shows what occupies the window
before anyone types — the harness pins whole `SKILL.md` bodies as phase system prompts, so a
paragraph added to a skill is paid for on **every phase of every case** from then on.
*Tool calls* is the gate ledger with denials and repeated-identical-call detection. *Cost &
credits* puts the Anthropic estimate next to third-party credits — different ledgers, different
currencies, never summed.

**Two kinds of number, never mixed.** Anything from a transcript's `usage` is **exact**. Anything
measured off a file on disk is an **estimate** from chars-per-token and renders differently
(`≈`, distinct colour). Dollar figures are estimates at pay-as-you-go list prices — on a Pro/Max
plan your real cost is the flat subscription. `tools/cost_report.py` owns the price table and the
per-iteration cache-tier accounting; the dashboard imports it rather than restating a price.

**Honest about its own limits.** A bounded scan says it is bounded (a truncated total presented as
a total is a wrong number, not a partial one). An absent ledger reports *absence of record*, never
"nothing happened". An unpriced model becomes a finding, because its tokens make every total an
under-estimate. In the trace, a blob shortened for display states exactly how many characters it
dropped and offers to re-read the whole value — a silently shortened tool result reads as a tool
that found little.

**One API response can span several transcript records** — Claude Code writes the thinking block
and each `tool_use` as its own record and repeats the *same* `usage` object on every one. Billing
per record therefore multiplies a tool-heavy turn's tokens and cost (2× is routine) while each row
still looks plausible, so every reader here bills once per `requestId`. Note `tools/cost_report.py`
does **not** do this yet: its per-session totals are inflated by the same factor.

**Loopback only.** The pages render case names, target domains, operator artifacts and full prompt
text, with no authentication. A non-loopback bind is refused and the refusal names the right
answer — `ssh -N -L 7788:127.0.0.1:7788 <host>`. Flip `server.allow_nonlocal_bind` in
`references/dashboard.json` only if you accept that anyone who can route to the port can read the
case data.

Thresholds, the findings rules and their explanations, the scan bounds and the prompt-surface
list are tunable data in `harness/references/dashboard.json` — raise a threshold when a check
cries wolf, but don't delete the check, or the failure it watches for goes back to being
invisible. Gate: `tests/test_dashboard.py`.

## Swappable reasoning backend (`HARNESS_BACKEND`)
The orchestrator is written against the Anthropic Agent SDK, but the reasoning model is **not**
hard-wired to Anthropic. `harness/sdk_compat.py` reads `HARNESS_BACKEND` and transparently swaps in
`harness/openai_backend.py` — a drop-in shim over the slice of `claude_agent_sdk` the orchestrator
uses — so the *same* Collect→Correlate→Assess driver runs against **any OpenAI-compatible
`/chat/completions` endpoint**. The orchestrator code is untouched.

```bash
HARNESS_BACKEND=deepseek  python3 harness/orchestrator.py CASE-0001 https://site-a.example
# HARNESS_BACKEND ∈ { claude (default) | openai | deepseek | kimi | local }
```
- Unset / `claude` → the real Anthropic SDK (schema-forced `output_format`, prompt cache, cost meter).
- `openai|deepseek|kimi|local` → the shim, pointed at the matching base URL + `*_API_KEY`.
- Note: some reasoning models (e.g. `deepseek-reasoner`) don't do tool-calling, so the tool-driven
  phases stay on a chat model (e.g. `deepseek-chat`). Use for cost control or air-gapped/local runs.

## Reactive fan-out + adversarial verify (`--fanout`, `--no-verify`)
Two quality levers on top of the base loop:
- **`--fanout`** replaces the single sequential Collect session with **one reactive collector agent
  per seed**, run concurrently (`collect_fanout`). Each seed gets its own hostile/Cloudflare/empty
  handling instead of sharing one context — better coverage, and faster on multi-seed cases.
- **Adversarial verify** (on by default; `HARNESS_VERIFY=0` or `--no-verify` to skip) inserts a phase
  between Correlate and Assess that tries to **refute** every proposed same-operator link before it's
  committed — a skeptic pass so a plausible-but-wrong cluster edge doesn't survive into the
  assessment. `HARNESS_VERIFY_MODEL` / `HARNESS_VERIFY_EFFORT` tune it.

## Files
- `cli.py` — the `intel` console entrypoint (`open` / `continue` / `status`); `../intel` is the shim.
- `tools.py` — your CLI scripts wrapped as in-process `@tool`s (+ the egress guardrail).
- `schemas.py` — the `Assessment` Pydantic model (the structured checkpoint).
- `orchestrator.py` — the Collect→Correlate→Assess driver + CLI (incl. `--fanout` + adversarial verify).
- `sdk_compat.py` — the `HARNESS_BACKEND` switch: real `claude_agent_sdk`, or the OpenAI-compat shim.
- `openai_backend.py` — the drop-in shim that runs the driver on any `/chat/completions` endpoint.
- `prompts/` — the per-phase **task** prompts (`collect.md` / `correlate.md` / `assess.md`), the
  single editable source of truth for what each phase instructs. `orchestrator._prompt(name, **kw)`
  loads and fills them (`{{token}}`); the phase *system* prompt still comes from the SKILL body.
- `mcp_server.py` — a standalone **stdio MCP server** that serves the *same* `tools.py` tool
  objects to Claude Code / any MCP client (auto-discovered, so it never drifts); `mcp-server` is
  its launch shim, wired up by the repo-root `.mcp.json`.
- `agents.py` — *optional* subagent definitions for parallel fan-out (ParallelBatch).
- `audit.py` — the **tool-call gate + ledger**, shared by all three front-ends (see
  *The guardrail seam*); its policy DATA is `references/tool_policy.json`.
- `dashboard/` — the **local debug dashboard** (`serve.py` + `collect.py` + `static/`); see
  *Debug dashboard*. Its tunable rules are `references/dashboard.json`.
- `case_scope.py` — the **case intake record** (see *Scope the case before you collect*); its
  vocabulary DATA is `WebPivot/references/intake.json`, shared with the WebPivot §0 intake.

## Run
```bash
python3 -m venv harness/.venv && source harness/.venv/bin/activate
pip install -r harness/requirements.txt
export ANTHROPIC_API_KEY=...        # or be logged into Claude Code

python3 harness/orchestrator.py CASE-0001 https://site-a.example https://site-b.example
python3 harness/orchestrator.py CASE-0001 --hostile https://sketchy.example
```
Prints the validated `Assessment` as JSON. Reads/writes the same `cases/` + `knowledge/`
stores as the skills (both git-ignored).

### `intel` — the console entrypoint
Prefer the repo-root `intel` shim over the long `python3 harness/orchestrator.py …` form. `open`
and `continue` forward every flag straight through to `orchestrator.py`; `status` reads the
`cases/` store directly — **no LLM, no `ANTHROPIC_API_KEY`** — so it works mid-run:
```bash
./intel status                                   # one line per case (fleet view)
./intel status CASE-0001                          # detail: rounds, attribution, BLUF, next pivots
./intel open     CASE-0001 https://site-a.example https://site-b.example
./intel continue CASE-0001 --depth 4 https://site-a.example   # iterate to convergence
```

## Never end a seed on silent "nothing found"
When `pivot_extract` comes back cold — zero/near-zero pivots, an empty-favicon/parked page, or
NXDOMAIN (WHOIS + FOFA + urlscan all empty) — the Collect phase is now required to call
**`fallback_probe`** (`tools/fallback_probe.py`), a keyless last-resort sweep of the corners that
survive a dead front page:
- **crt.sh** — CT/SSL certs; a **SAN-sibling** domain (a different domain on the same cert) is the
  strongest same-owner link there is;
- **Wayback CDX** — the full capture **timeline** (first→last→count), because a parked-today domain
  was routinely a live scam last year and the old DOM is the pivot;
- **archive.today** — the mirror to use when Wayback is empty;
- **search dorks** — ready-to-run Google/Bing queries (SERP scraping is bot-walled; WebPivot's
  contract is runnable queries, so it hands them back);
- **local KB** — is any part of the domain already known/attributed? (a hit = show the prior verdict).

It always returns a **VERDICT** — `PIVOTABLE` (surviving leads, ranked) or `NO-PIVOT-YET` (genuinely
cold, with explicit next steps) — so the analyst gets a verdict, not silence. Standalone too:
`python3 tools/fallback_probe.py <domain> --kb knowledge`.

## Don't re-investigate what's already known
Before collecting, the harness prints a **prior-knowledge** line per seed (already-collected / attributed / NEW), and `pivot_extract` **reuses the cached pivot JSON** if the domain was investigated in *any* prior case — no re-fetch, no API spend. Pass `force=true` (or `HARNESS_FORCE=1`) to refresh. The judgment phase also has a **`domain_verdict`** tool that returns a domain's prior verdict (operator-registry attribution + KB facts), so a resolved seed is *shown*, not re-worked.

## Iterate to convergence (`--continue`)
By default the harness runs one Collect→Correlate→Assess round. With `--continue` it loops:
after each round it snapshots convergence (`tools/kb/convergence.py`), discovers the next frontier —
uncollected KB cluster-peers of the case's domains — and re-runs, stopping when the case CONVERGES
(the last `--stale` rounds added no new host/indicator), the `--depth` cap is hit, or nothing new is
found. Each round writes its own immutable assessment snapshot (r1, r2, …).

```bash
python3 orchestrator.py CASE-0001 --continue --depth 4 --stale 2 --max-new 8 https://site-a.example
```
`--depth N` max rounds (default 4 with `--continue`) · `--stale N` zero-growth rounds = converged
(default 2) · `--max-new N` cap on new seeds pulled in per round (default 8).

**Frontier discovery is noise-guarded.** New seeds come from `query.py --cluster <d> --strong`, which
excludes (a) boilerplate edges — shared WP-Rocket CSS / HTML comments / DOM skeleton — and (b)
indicators shared by more than `--max-prevalence` domains (default 8: generic kit favicons, registrar
emails, g-recaptcha). Without this the loop would re-pull exactly the false clusters an analyst
rejects; with it, a real seed set expands only along owner-set indicators (favicon/GA/GTM/verification/
wallet/theme/socials). `--strong` is also available to the analyst directly for a clean cluster view.

## Scale to many domains (`--parallel`, cluster-level judgment)
One Collect session looping over 100 domains blows a single model's context and turn budget, and
one Assess over 100 domains is unfocused. `--parallel` fixes both by separating mechanical work from
judgment:
1. **Collect** — all seeds fan out concurrently through `collect_many` (deterministic, **no LLM** —
   collection is mechanical), each with the same cache-reuse + evidence capture as the normal path.
2. **Ingest once**, then **partition** the case into same-operator clusters via `query.py --components`
   (STRONG connected components — boilerplate/benign/over-prevalent edges excluded).
3. **Judge each cluster in parallel** (Correlate→Assess), bounded by `--judge-conc`. The LLM's unit of
   work is the **cluster, not the domain**, so judgment cost scales with cluster count (a handful),
   not domain count.

Each cluster gets its own immutable assessment snapshot (`assessments/<UTC>_c<i>.{md,json}`) and the
case `SUMMARY.md` becomes a roll-up listing every cluster.
```bash
python3 orchestrator.py CASE-0001 --parallel --collect-conc 8 --judge-conc 3 seed1.example seed2.example …
python3 orchestrator.py CASE-0001 --parallel --continue --depth 4 seed1.example …   # expand to convergence, then judge
```
`--collect-conc N` concurrent collectors (default 8) · `--judge-conc N` concurrent cluster judges
(default 3). Large seed sets auto-switch to parallel at `HARNESS_PARALLEL_AT` domains (default 12).

**`--parallel --continue`** combines Phase 2 + 3 the token-efficient way: the expansion rounds are
**cheap and LLM-free** (parallel collect + convergence snapshot + frontier discovery), and the
expensive Correlate→Assess runs **once** on the final converged graph — not every round. Clusters
whose domains are **already attributed** in the operator registry skip the LLM entirely (their prior
verdict is reused in the roll-up).

### Where the tokens go (and how this saves them)
- **Collection is now LLM-free.** The old Collect phase was a model session that looped over every
  seed, and each `pivot_extract` result (~6 KB of JSON) landed in a context that grew with N. Phase 3's
  `collect_many` is plain subprocesses — **zero collection tokens**, the single biggest saving at scale.
- **Judgment is per-cluster, not per-case.** Each cluster session pulls only its own subgraph, so
  contexts stay small; there's no one giant session holding all N domains' peers. Cost scales with
  cluster count (a handful), not domain count.
- **Judge once at convergence** (`--parallel --continue`) instead of every round; **skip resolved
  clusters** — both cut whole Correlate→Assess cycles.
- **The repeated skill system-prompt is cache-friendly.** Correlate/Assess re-send `IntelAnalysis/SKILL.md`
  (~5 K tokens) per cluster; because it's byte-identical across clusters, the Agent SDK's prompt cache
  serves clusters 2..K from the warm cache (~90 % off) when they run in the same window — which parallel
  fan-out does. Keep `--judge-conc` ≥ 2 so clusters overlap the cache window.
- **Model cascade** (unchanged): Haiku is irrelevant now that collection is deterministic; Sonnet judges;
  Opus is paid only when a cluster returns low confidence (`HARNESS_ESCALATE`).

## Fingerprint reference (benign vs. signal) — false-positive control
A hash match is only as good as the artifact's uniqueness: a shared favicon/CSS/DOM hash can just
mean both sites ship the same jQuery/Bootstrap/logo/CDN bundle — a **false positive**. `noise_filters.py`
hardcodes the well-known offenders and `--max-prevalence` catches what's common *within our KB*, but
neither remembers a specific globally-common hash learned once. `tools/kb/reference.py` is that living
memory (`<kb>/reference.jsonl`), with two verdicts:
- **benign** — a common logo/CDN/CSS-framework/template artifact. **Suppressed from clustering**
  everywhere (`query.py --cluster --strong` drops benign-marked indicators regardless of prevalence).
- **signal** — a distinctive hash/keyword harvested from a confirmed case; a watchlist/IOC so a future
  collection hitting one is a high-value lead tied back to its origin case.

The Correlate phase has `reference_check` (is this shared hash benign / a known signal / unknown?) and
`reference_add` (remember a new benign or signal fingerprint), so the reference improves with every case.
Bulk-harvest a solved case's distinctive artifacts (auto-skipping ones too common in the KB) with:
```bash
python3 tools/kb/reference.py --kb knowledge ingest-case CASE-0001   # unique artifacts → signal watchlist
python3 tools/kb/reference.py --kb knowledge add --value favicon:0 --verdict benign --label "empty favicon"
python3 tools/kb/reference.py --kb knowledge check <hash-or-keyword>
```

## Cross-case provenance (which case is an artifact in?)
The KB stores facts sourced to a collector but not to a case, so the Correlate phase has a
**`which_cases`** tool (`tools/case_index.py`) that answers "which case(s) has this domain / indicator
appeared in?" by indexing `cases/*/raw/*.json`. A domain or an indicator string (`favicon:<h>`,
`ga:<id>`, `wallet:<coin>:<addr>`, `email:<addr>`) resolves to the case(s) + host(s) it was seen in —
so a pivot on a known artifact shows its prior case context instead of starting cold, and an indicator
seen across multiple cases is flagged as a cross-case link. `domain_verdict` now includes this line
automatically.

## Evidence, provenance & assessment versioning
Every run is now an **append-only, archived** record — nothing is overwritten, so a case's
attribution history is auditable:

```
cases/<case>/
  SUMMARY.md                          ← living head: the current assessment (refreshed each run)
  CHANGELOG.md                        ← one line per round (attribution/confidence + BLUF)
  assessment.json                     ← back-compat pointer to the latest snapshot
  assessments/<UTC>_r<round>.{md,json}← IMMUTABLE snapshot per run (the audit trail)
  evidence/
    manifest.jsonl                    ← one row per collection: WHERE (source_url + enriched_with),
                                          WHEN (collected_at, UTC), WHAT WAS ARCHIVED (dom/screenshot
                                          paths, Wayback flag), reused_cache
    master_pivots.csv                 ← every pivot (kind/value/query), dedup'd, --case tagged
  dom/<host>.html   screenshots/<host>.png
```

Collection captures evidence **by default** (not the model's choice): `pivot_extract` runs with
`--archive-missing` (submits a Wayback Save-Page-Now snapshot so the copy survives takedown),
`--master` (appends to the case evidence ledger), and always `--save-dom`. Each pivot JSON carries
`meta.collected_at` (UTC). Knobs: `HARNESS_SCREENSHOT=1` adds a browser screenshot (visual evidence,
routed through the playwright python); `HARNESS_NO_ARCHIVE=1` disables Wayback+ledger; `HARNESS_NO_ENRICH=1`
(smoke) skips all of it.

## TLS cert / SAN-overlap as a correlation signal
The Correlate phase has a **`cert_overlap`** tool (`tools/cert_overlap.py`, keyless, dual-source
crt.sh + Shodan CTL). Two domains sharing a TLS certificate — or one domain's cert SAN list naming
another — is near-decisive same-operator proof, because the SAN list is chosen by whoever controls
the cert. It returns `SHARED-CERT` / SAN cross-cover (decisive), `SIBLING-OVERLAP` (certs carry a
common third domain = strong), or `NO-CT-OVERLAP` (a clean negative you can also weigh). The
correlate prompt now **requires** it whenever there are 2+ candidate same-operator domains.
Standalone: `python3 tools/cert_overlap.py <domain-a> <domain-b> [<domain-c> …]`.

## API keys (.env)
`pivot_extract` reads keys (`WHOISXML_API_KEY`, `FOFA_KEY`, `URLSCAN_API_KEY`, `PDNS_*`) from the
environment first, then from the first `.env` it finds among: the **invocation cwd** (the repo root
the harness runs from), the **repo root** relative to the script, a skill-local `.env`, and the PAI
customization dir. Keep your keys in the git-ignored repo-root `.env`. Missing `WHOISXML_API_KEY` is
why a run's Domain Summary WHOIS columns come back blank.

## Collection behavior & outputs
Every `pivot_extract` call now, by default:
- runs **full enrichment** — WHOIS + FOFA + urlscan (needs the API keys in `.env`); `HARNESS_NO_ENRICH=1` turns it off for cheap smoke runs only;
- resolves **WHOIS with no key** — keyless RDAP (rdap.org bootstrap) + a `.vn` port-43 fallback fill registrar/dates/NS/status on every domain; `WHOISXML_API_KEY` only adds registrant history;
- emits an active **JARM TLS-stack fingerprint** (`artifacts.jarm`) + a `jarm:<hash>` pivot on Shodan `ssl.jarm:` — it survives a full domain+cert rotation, so it re-finds an operator's origin. Suppressed under `--proxy` (raw-socket probe);
- **saves the raw DOM** to `cases/<case>/dom/<host>.html` so you can manually analyze it or re-run a pivoting script over it;
- **detects Cloudflare** (`meta.cloudflare`) and auto-retries the bypass — a real browser via `--render` (uses `WebPivot/.venv`), or FlareSolverr if `HARNESS_FLARESOLVERR=http://host:8191/v1` is set.

The judgment phase also has a **`reverse_whois`** tool that returns only high-value pivots: it refuses privacy/registrar terms and flags a bulk registrant (`> max_domains` = reseller = noise) instead of dumping it.

Every run prints/saves the standard **Domain Summary table** (`tools/domain_table.py`) — Domain · Status · Registered · Expires · Registrar · Nameservers · Registrant · IP·ASN · Attribution · Context — for the domains collected this run, above the assessment.

New env knobs: `HARNESS_FLARESOLVERR` (CF solver URL) · `HARNESS_RENDER_PY` (playwright python, default `WebPivot/.venv`).

## One typed tool surface for both front-ends (`mcp_server.py` + `.mcp.json`)
The SDK driver already gets clean, typed MCP tools (built-ins stripped, no shell-flailing). The
Claude-Code front-end historically did the opposite — driving the same work via raw
`python3 …/pivot_extract.py` bash. `mcp_server.py` closes that gap: a **standalone stdio MCP
server** that serves the *same* `tools.py` tool objects to Claude Code (or any MCP client), so both
front-ends share one typed, permission-gated surface.

- **Zero duplication / no drift** — it re-implements nothing. It imports `tools.py` and
  auto-discovers every `@tool` (`pivot_extract`, `kb_cluster`, `cert_overlap`, `impersonation_hunt`,
  `search_pivot`, `case_clusters`/`case_frontier`/`case_loop`/`case_reopen`, … — all 23); the handlers and the CLIs
  under them stay the source of truth. Add a tool to `tools.py` and it appears here automatically.
- **Wired up** by the repo-root `.mcp.json` (`command: ./harness/mcp-server`). The shim runs the
  server under the **WebPivot venv** (tools.py imports `claude_agent_sdk`); edit `PY` in the shim if
  your SDK venv lives elsewhere.
- **Smoke test** (newline-delimited JSON-RPC on stdin):
  ```bash
  ./harness/mcp-server        # then send: {"jsonrpc":"2.0","id":1,"method":"tools/list"}
  ```
- **Verification boundary**: the server's `initialize` / `tools/list` / `tools/call` handshake is
  tested; confirming Claude Code *loads* it needs a Claude Code restart in this repo (it reads
  `.mcp.json` at startup — check `/mcp`). Egress policy still defaults to non-hostile here; enforce
  hostile egress out of process (below).

## The guardrail seam — the tool-call gate (`audit.py`)
Every tool call passes **one** policy point before it runs, and lands on a ledger whether it
ran or not. `harness/audit.py` is front-end neutral, so the three drivers cannot drift:

| Front-end | How it reaches the gate |
|---|---|
| SDK driver (Anthropic) | a **`PreToolUse` hook**, built per phase by `orchestrator._gate_hook` |
| DeepSeek / OpenAI shim | `audit.gate()` inline in `openai_backend.query`'s tool loop |
| Claude Code (stdio MCP) | `audit.gate()` in `mcp_server._call_tool` |

**Why a hook and not `can_use_tool`.** The SDK only consults `can_use_tool` for calls that would
otherwise *prompt* — and both `permission_mode="bypassPermissions"` **and** `allowed_tools` entries
that allow a whole tool (exactly what `COLLECT_TOOLS` / `ANALYZE_TOOLS` are) shadow it. The SDK says
so itself and emits `CanUseToolShadowedWarning`; its own guidance is to use a `PreToolUse` hook to
gate every call. `tests/test_tool_gate.py` turns that warning into an error so the config can never
drift back into a gate that is wired but never consulted. The hook is a **closure** over its phase's
case + posture, because phases run concurrently and hooks fire on the SDK's task.

What it denies (everything else is allowed — and still logged):
- **hostile posture + an outbound tool** with no `passive=` / `proxy=` — now covering *every*
  outbound collector, not only the one that implemented its own refusal (`pivot_extract`'s
  internal check stays, as defence in depth);
- **`anyrun_submit` without `HARNESS_ALLOW_SUBMIT=1`** — outbound, attributable, irreversible;
- **a metered call past the run's credit budget** (`budget.max_metered_calls_per_run`, override
  with `HARNESS_METERED_BUDGET`) — the backstop against a loop re-querying FOFA every round.

A denial is returned **to the model** as text, so it adapts (`passive=true`, `free_only=true`)
instead of the run dying. The lists, budget and approval env-vars are DATA —
`harness/references/tool_policy.json` (contributor RULE 3) — so re-classifying a tool needs no
code change.

**The ledger.** One JSON line per call to `cases/<case>/tool_calls.jsonl`
(`MEMORY/tool_calls.jsonl` for interactive calls with no case): timestamp, case, phase, backend,
tool, risk classes, redacted+truncated args, and `allow` / `DENY` with the reason. Credential-shaped
arguments are never written. An unwritable ledger warns and the run continues — losing a case at
round 4 costs more evidence than it protects. Each run prints a gate summary beside the cost ledger.

Note the split this completes: `run_cost.jsonl` = what the run *spent* on Anthropic,
`MEMORY/api_usage.jsonl` = what it spent on third-party credits, `tool_calls.jsonl` = what it
actually *did*.

**Reading it back** — the `tool_calls` MCP tool, or the CLI:
```bash
python3 harness/audit.py report CASE-0001              # summary: classes, by tool, by phase
python3 harness/audit.py report CASE-0001 --denied     # only what the gate blocked, and why
python3 harness/audit.py report CASE-0001 --tool pivot_extract --last 20
python3 harness/audit.py report --all                  # every case + the interactive ledger
python3 harness/audit.py report CASE-0001 --json       # raw records
```
A missing ledger is reported as **absence of record** (the case predates the gate, or nothing has
run) — never as "the run did nothing", the same discipline as the keyless-capability banner.

## Auth & billing (read before running)
The Agent SDK authenticates with an **`ANTHROPIC_API_KEY` (pay-per-token)**, or Bedrock /
Vertex / AWS / Foundry — **not** a Claude Pro/Max subscription. Per the docs, claude.ai
login is not a supported/allowed auth path for SDK-built agents. To run on your existing
subscription instead, drive **Claude Code headless** (`claude -p "<prompt>" --output-format
json`) as a subprocess rather than this SDK library (personal/internal use only; you lose
schema-forced `output_format`). If you ever distribute this to other users, they each need
API-key auth — subscription auth can't power a shared product.

## Two SDK gotchas baked in (verified against the docs)
1. **We inline each `SKILL.md` as the phase `system_prompt`** for explicitness/portability.
   (The SDK *can* auto-load skills from `.claude/` when `setting_sources` includes
   `"project"`/`"user"` — same as Claude Code — but inlining doesn't depend on the skills
   being registered/symlinked into `.claude/`, so it's self-contained.)
2. **The Python `@tool` decorator forwards only `content` + `is_error`** — *not*
   `structuredContent`. So tools return JSON as text (the model reads it), and machine
   validation happens only at the final `output_format` checkpoint.

## Adjust before real use (integration seams)
- **CLI flags** in `tools.py` are illustrative — match them to your actual scripts
  (`pivot_extract` `--crawl`/`--rotate-ua`, `risk_signals` options, etc.).
- **Model aliases** `sonnet`/`opus` — pin exact IDs if you want reproducibility across
  model updates.
- **Regression-gate the agent**: add end-to-end golden cases to `tools/eval/` (fixed
  seed → expected `Assessment` shape) so a prompt/tool change can't silently drift it.
- Verified against the Agent SDK docs (code.claude.com/docs/en/agent-sdk) at build time;
  re-check `query` / `ClaudeAgentOptions` / `@tool` signatures if you bump the SDK.
