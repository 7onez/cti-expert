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

## Files
- `cli.py` — the `intel` console entrypoint (`open` / `continue` / `status`); `../intel` is the shim.
- `tools.py` — your CLI scripts wrapped as in-process `@tool`s (+ the egress guardrail).
- `schemas.py` — the `Assessment` Pydantic model (the structured checkpoint).
- `orchestrator.py` — the Collect→Correlate→Assess driver + CLI.
- `prompts/` — the per-phase **task** prompts (`collect.md` / `correlate.md` / `assess.md`), the
  single editable source of truth for what each phase instructs. `orchestrator._prompt(name, **kw)`
  loads and fills them (`{{token}}`); the phase *system* prompt still comes from the SKILL body.
- `mcp_server.py` — a standalone **stdio MCP server** that serves the *same* `tools.py` tool
  objects to Claude Code / any MCP client (auto-discovered, so it never drifts); `mcp-server` is
  its launch shim, wired up by the repo-root `.mcp.json`.
- `agents.py` — *optional* subagent definitions for parallel fan-out (ParallelBatch).

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
  auto-discovers every `@tool` (`pivot_extract`, `kb_cluster`, `cert_overlap`, … — all 13); the
  handlers and the CLIs under them stay the source of truth. Add a tool to `tools.py` and it appears
  here automatically.
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

## The guardrail seam
`tools.POLICY["hostile"]` is flipped by the orchestrator for `--hostile` runs; the
`pivot_extract` tool then **refuses a live fetch** unless called with `passive=true`
or a `proxy`. That's your egress tradecraft as code. For production, enforce the same
rule with a `PreToolUse` hook or the `can_use_tool` callback so it can't be bypassed
in-process, and drop `permission_mode="bypassPermissions"`.

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
