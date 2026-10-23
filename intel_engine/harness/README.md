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
| **Collect** | `WebPivot/SKILL.md` | collectors + `kb_ingest`, `corpus_search` (not an exhaustive roster) | raw JSON in `cases/<case>/raw/`, ingested to KB |
| **Plan** | (cross-type loop) | read-only `PLAN_TOOLS` only | re-rank `propose()` candidates; add typed pivots |
| **Correlate** | `IntelAnalysis/SKILL.md` | KB/timeline/reference tools (read-mostly; not an exhaustive roster) | in-context reasoning |
| **Assess** | `IntelAnalysis/SKILL.md` | read-only | **schema-forced `Assessment` JSON** (owner `cluster` + `kit_siblings` / `neighbours` / `mentions`) |

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
hard-wired to Anthropic. `harness/sdk_compat.py` reads `HARNESS_BACKEND` and swaps in one of two
drop-ins over the slice of `claude_agent_sdk` the orchestrator uses, so the *same*
Collect→Correlate→Assess driver runs on whatever this machine can actually reach:

| `HARNESS_BACKEND` | Runs on | Auth |
|---|---|---|
| `claude` | the Anthropic Agent SDK → Claude Code CLI | `claude /login` (subscription) or `ANTHROPIC_API_KEY` |
| `codex` | `codex exec --json` (`harness/cli_backend.py`) | the machine's `codex login` |
| `omp` | `omp -p --mode json` (`harness/cli_backend.py`) | the machine's omp login |
| `openai\|deepseek\|kimi\|local` | `harness/openai_backend.py` over `/chat/completions` | `OPENAI_API_KEY` / `DEEPSEEK_API_KEY` / `MOONSHOT_API_KEY` (+ `OPENAI_BASE_URL`) |
| `orcarouter` | `harness/openai_backend.py` over OrcaRouter's `/v1/chat/completions` | `ORCAROUTER_API_KEY`, or an OAuth 2.0 + PKCE credential (`intel.py provider login --method oauth`) |
| unset / `auto` | **resolved once per run** by `harness/backend_select.py` | — |

`auto` tries the host agent this process runs inside first (Codex → OMP → Claude Code; the
markers are inherited, so the inner-most wins), then `claude`, `codex`, `omp`, then an OpenAI key.
Each run decides with the CLIs' **free** login-presence checks (`claude auth status`,
`codex login status`; omp has none) — no model request, no tokens. These only show a stored login
exists; they do **not** prove it works (an expired OAuth session whose refresh fails can still read
as logged in, and they never see credits). A backend that passes them but cannot answer fails the
first phase within seconds, and that failure becomes a failover (below). `python3 scripts/backend/intel.py harness doctor
[--backend X]` goes further: one tiny real request per backend ("Reply with exactly: OK"), which
also catches a logged-in account with no credits left, and lists the fallbacks that are ready. Its
answers are cached in `MEMORY/backend_probe.json` (a pass for 30 min, a failure for 10 —
`HARNESS_PROBE_PASS_TTL` / `HARNESS_PROBE_FAIL_TTL`), so the next runs reuse them for free. No
usable backend → the run exits naming every candidate and why, never as "✓ phase · $0.00".

**Mid-run failover.** If the backend dies *during* a case on a login / credit / rate-limit error
(not a tool or schema fault), the orchestrator exits 75 with the case intact. `harness open` /
`continue` then probes the remaining backends and, per `--failover` (or `HARNESS_FAILOVER`):
`ask` (default on a terminal) — "omp is usable. Resume case X on omp? [Y/n]"; `auto` — switch
without asking; `off` (default without a terminal: cron, CI) — stop and print the command to
resume. The resumed run reuses the cached collection, so nothing is re-bought; in `--parallel`
mode the clusters judged before the failure are kept (`cases/<case>/failover_progress.json`) and
only the unfinished ones are judged again. A backend that failed is skipped for 10 minutes. For unattended VPS
runs set `HARNESS_BACKEND` / `HARNESS_FAILOVER` in the crontab line or the systemd unit's
`Environment=` — `~/.bashrc` is not read by cron or systemd.

**Egress.** Model traffic (Anthropic / OpenAI / DeepSeek / Moonshot / Google / OpenRouter API
hosts, `references/model_hosts.json`) always goes **direct** — those hosts are added to `NO_PROXY`
for every model CLI the harness starts. Target traffic keeps using the research proxy pool
(`scripts/proxy`): `mcp_server.py` installs that pool itself at startup, so collectors stay proxied
even when the server is launched by Claude Code, Codex or OMP rather than `scripts/backend/intel.py`.

As **root** (a typical VPS) the Claude CLI refuses headless permissions unless
`IS_SANDBOX=1`; the harness sets it itself, because safety never rested on that flag — every tool
call still passes `audit.gate`.

```bash
python3 scripts/backend/intel.py harness doctor   # which backend, and why the others were skipped
HARNESS_BACKEND=codex python3 scripts/backend/intel.py harness open CASE-0001 https://site-a.example
HARNESS_BACKEND=deepseek python3 harness/orchestrator.py CASE-0001 https://site-a.example
```

**OrcaRouter Cyber Inference (`HARNESS_BACKEND=orcarouter`).** A named backend, not a generic
"any base URL" knob: `harness/orcarouter.py` owns its origin, its credential and its catalog, and
`backend_select.py` probes it with a free `GET /v1/models` (never a billed completion) and skips it
while its credential is marked rejected. It exists for security teams doing authorised, scoped
work: the cyber tier is where a red team's authorised requests and a blue team's gateway controls
share one endpoint — see the provider page at <https://www.orcarouter.ai/cyber> and the cyber-tier
catalog at <https://www.orcarouter.ai/models?tier=cyber>. Two ways in, one credential seam behind
them:

- **API key** — `ORCAROUTER_API_KEY` (env first, then the skill-root `.env`, like every other key).
- **OAuth 2.0 + PKCE** — `intel.py provider login --method oauth`: a fresh CSPRNG verifier/state per
  attempt, `S256` challenge, loopback callback by default (`--flow oob` prints the code for a
  headless VPS), state compared in constant time, and a single-use 10-minute code exchanged at the
  auth origin (`https://www.orcarouter.ai/api/v1/auth/keys` — never the inference origin). The
  resulting key is stored exactly like a pasted one, so no downstream code can tell which method
  was used. There is no refresh grant: a terminal `401` marks that credential generation
  `needs_reauth` and the harness asks for a new login instead of retrying in a loop.

Both `www` (auth) and `api` (inference) origins are separate and override-able
(`ORCA_AUTH_BASE_URL` / `ORCA_API_BASE_URL` / `ORCA_BASE_URL`) for a test double, but HTTPS is
required except on loopback. The catalog is read live, bounded, and treated as authoritative;
when it is unreachable the harness falls back to a verified seed or last-known-good snapshot and
labels the result `degraded` in the UI rather than silently inventing model ids. Tiers follow the
provider's own offering: **`orcarouter/auto`** is the default (auto-routing, any key), **OrcaCyber
Ultra `orca/orcacyber-ultra-1.0`** and **OrcaCyber Zero `orca/orcacyber-zero-1.5`** are the
recommended cyber models for teams that have completed business verification, and
**`orcarouter/fusion`** is the general fallback. Both origins are in `references/model_hosts.json`,
so model traffic stays direct while target traffic keeps the research proxy pool.

```bash
python3 scripts/backend/intel.py provider status          # masked credential + live catalog
python3 scripts/backend/intel.py provider models --capability chat --modality text
python3 scripts/backend/intel.py provider login --method oauth     # PKCE, opens the browser
HARNESS_BACKEND=orcarouter python3 harness/orchestrator.py CASE-0001 https://site-a.example
```

The same surface is in the debug dashboard (**Provider** tab): both methods side by side, the
catalog as a filtered dropdown, and cancel-on-navigate so a half-finished login never leaves a
listener bound to loopback.

**CLI backends are isolated by construction.** Each phase is one `codex exec` / `omp -p` process
in a throwaway home under `cases/<case>/harness_home/` (own `CODEX_HOME` config / `.omp/mcp.json`;
the user's login is reused, their config, skills, hooks, plugins and other MCP servers are not).
Its only tools are this repo's `@tool`s, served by `harness/mcp_server.py` over stdio and narrowed
to the phase's allowlist (`HARNESS_ALLOWED_TOOLS`), pre-approved, with shell / exec / browser /
web-search / multi-agent features disabled. The phase's case, label and hostile posture travel to
the server (`INTEL_CASE` / `HARNESS_PHASE` / `HARNESS_HOSTILE`) so `audit.gate` decides exactly as
on the SDK path, and the JSON event stream — not the final text — is the judge: a phase **fails** if
the host executed anything outside the `intel` server (a shell command, a built-in, another MCP
server) or refused an MCP call at its own approval layer. Structured output (Assess) uses a
server-side `emit_result` tool validated against the `Assessment` schema; sessions resume
(`codex exec resume` / `omp --resume`) so Correlate → Verify → Assess share one transcript.
`HARNESS_CLI_MODEL_MAP='{"haiku":"…","sonnet":"…"}'` maps tiers to host model ids;
`HARNESS_CLI_TIMEOUT` (default 1800 s) bounds a phase process.

- Note: some reasoning models (e.g. `deepseek-reasoner`) don't do tool-calling, so the tool-driven
  phases stay on a chat model (e.g. `deepseek-chat`). Use for cost control or air-gapped/local runs.
- Metered-call counting is on the ledger; a per-run **denial** on count is opt-in only
  (`HARNESS_METERED_BUDGET=<n>`) — project decision: vendor 402/429 responses are the limit.

## Reactive fan-out + adversarial verify (`--fanout`, `--no-verify`)
Two quality levers on top of the base loop:
- **`--fanout`** replaces the single sequential Collect session with **one reactive collector agent
  per seed**, run concurrently (`collect_fanout`). Each seed gets its own hostile/Cloudflare/empty
  handling instead of sharing one context — better coverage, and faster on multi-seed cases.
- **Adversarial verify** (on by default; `HARNESS_VERIFY=0` or `--no-verify` to skip) inserts a phase
  between Correlate and Assess that tries to **refute** every proposed same-operator link before it's
  committed — a skeptic pass so a plausible-but-wrong cluster edge doesn't survive into the
  assessment. `HARNESS_VERIFY_MODEL` / `HARNESS_VERIFY_EFFORT` tune it.


## Cross-type auto-pivot loop (typed nodes + Plan + proposal gate)
Every selector type (`domain`, `email`, `phone`, `wallet`, `ip`, `hash`, `string`, `filename`,
`telegram`) is a frontier node. Each round:

1. **`case_state.propose()`** (dispatcher op `propose`) emits typed candidates from the frontier,
   prior SDK seed sources, and corpus hints — rung-tagged via `selector_types.rung_for` /
   `kb/references/rungs.json`.
2. **Plan phase** (required, read-only `PLAN_TOOLS`) re-ranks and may add pivots; it cannot spend,
   mutate shared state, or approve.
3. **Auto vs proposal.** Free or urlscan (quota-backed) pivots with ≤ `PIVOT_AUTO_MAX_HITS` = **25**
   hits run automatically. Metered, oversized, or unknown-count pivots land in digest-bound
   `cases/<case>/proposal.json`. `audit.gate` denies `proposal_gated_tools` (`corpus_search`,
   `reverse_whois`, …) while the loop is active unless the pivot id was approved for this digest.
4. **Approve once per round** via `harness approve CASE [--only ids|--all] [--reject ids] [--show]`,
   the MCP `case_approve` tool (ANALYZE; briefing then confirm), or a TTY prompt when a run stops
   at awaiting-approval. Approvals bind pivot ids + state digest; a stale digest is refused.
5. **Dispatcher op `corpus-search`** / MCP `corpus_search` runs one `pivot_map.json` route
   (urlscan fields, Wayback collection search, FOFA, PublicWWW, …) into typed hits.
6. **Collecting ≠ attributing.** Owner-rung hits may edge/cluster; kit and neighbour hits are
   `add_fact` only (`ingest_typed.py`) and surface on the Assessment as `kit_siblings` /
   `neighbours` (mentions for news/pdf/EoT/mediacloud). They never enter `cluster`: the
   orchestrator enforces it deterministically — `_compute_components` drops every host the loop
   reached only through kit/neighbour rows (`case_state.tier_hosts`, from `state.json` `nodes`)
   and writes `cases/<case>/tiers.json`; `_enforce_tiers` moves any such host the judge still
   names out of `cluster`. The legacy `clusters.json` (written by `tools/intel.py`) is not
   changed, so it can still group such a host with the estate by a shared favicon/handle.
7. **Seeds of any type.** `harness open CASE ops@operator.example` works: a non-domain seed becomes
   a hop-0 typed node and is pivoted on, never collected; a filename seed (`invoice.zip`) is never
   a host. Nodes expand to `max_typed_hops` (pivot_map.json, 6). `harness continue CASE` with no
   seeds resumes from the case's own hosts/nodes — the step after `harness approve`.
8. **Spend.** A `no_spend` scope drops every metered candidate, runs every count probe
   free_only (no reverse-WHOIS preview, keyless urlscan counts), and the gate denies ANY metered
   call on that case (pivot_extract, censys, intelx_search, … without `free_only`). A metered
   tool with no keyless mode REFUSES `free_only=true` rather than spend (`tool_policy.json
   free_only_capable_tools`); `reverse_whois` with `free_only` returns the preview count only.
   **Who pays for collection (per HOST, `proposal.collect_free_only`):** the analyst's own typed
   seeds (`cases/<case>/harness_seeds.json`) collect with the keyed layers, as before. Every other
   host — including any an agent reaches inside round 1 — collects `--free-only`, and the gate
   denies other metered calls (`deep_profile`, `censys`, …) while the loop runs. Keyed enrichment
   of a found host is a metered `enrich.host` proposal item, run only after approval, and is never
   offered for a host whose raw already carries keyed layers.
   Approvals are single-use (one approved id → one call) and digest-bound to the raw files,
   `pivoted` ids and typed nodes (not state.json bookkeeping); `loop_active`/`running` carry a
   lease (`HARNESS_LOOP_LEASE`, 6 h) so a killed run neither holds the gate shut nor leaves an
   approval open. `case_approve` is operator-only (`tool_policy.json operator_only_tools`) —
   denied from every harness phase.

`intel.py loop` and `case_state.frontier()` keep their prior behaviour; this path is the SDK
harness / MCP deepening loop.

## Files
- `cli.py` — the `intel` console entrypoint (`open` / `continue` / `status`); `../intel` is the shim.
- `tools.py` — your CLI scripts wrapped as in-process `@tool`s (+ the egress guardrail).
- `schemas.py` — `Assessment` (owner cluster + kit_siblings/neighbours/mentions) and Plan models.
- `proposal.py` — digest-bound `proposal.json` split/approve/gate helpers for the cross-type loop.
- `references/pivot_map.json` — corpus routes + `auto_max_hits` / `max_typed_hops` for `pivot_routes`.
- `orchestrator.py` — the Collect→Correlate→Assess driver + CLI (incl. `--fanout` + adversarial verify).
- `sdk_compat.py` — the `HARNESS_BACKEND` switch: real `claude_agent_sdk`, the CLI backend, or the OpenAI-compat shim.
- `backend_select.py` — `auto` resolution + auth probes (`intel.py harness doctor`); exports `HARNESS_BACKEND` for the run.
- `cli_backend.py` — the Codex / OMP drop-in: isolated host home, MCP-only tools, event-stream judge, `emit_result`.
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

It always returns a **VERDICT** — `PIVOTABLE` (surviving leads, ranked), `NO-PIVOT-YET` (genuinely
cold, with explicit next steps) or `INCONCLUSIVE-CT-DEGRADED` (cold, but crt.sh was unreachable so the
CT corner was not really swept — re-run) — so the analyst gets a verdict, not silence. Standalone too:
`python3 tools/fallback_probe.py <domain> --kb knowledge`.

## Don't re-investigate what's already known
Before collecting, the harness prints a **prior-knowledge** line per seed (already-collected / attributed / NEW), and `pivot_extract` **reuses the cached pivot JSON** if the domain was investigated in *any* prior case — no re-fetch, no API spend. Pass `force=true` (or `HARNESS_FORCE=1`) to refresh. The judgment phase also has a **`domain_verdict`** tool that returns a domain's prior verdict (operator-registry attribution + KB facts), so a resolved seed is *shown*, not re-worked.

## Iterate to convergence (`--continue`)
By default the harness runs one Collect→Correlate→Assess round. With `--continue` it loops:
after each round it snapshots convergence (`tools/kb/convergence.py`), discovers the next frontier —
uncollected KB cluster-peers of the case's domains — and re-runs, stopping when the case CONVERGES
(the last `--stale` rounds added no new host/indicator **and none of them had a host fail to
collect** — a round that collected 0/N is a retry, never convergence), the `--depth` cap is hit, or
nothing new is found. Each round writes its own immutable assessment snapshot (r1, r2, …).

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

Each cluster gets its own immutable assessment snapshot (`assessments/<UTC>_c<i>.{md,json}`, where
`<i>` is always the cluster's own index) and the case `SUMMARY.md` becomes a roll-up listing every
cluster. The case **head** (`assessment.json` + `assessment.md`, what `house-report` and
`build_report_data.py` read) is refreshed from the judged cluster holding the most seeds, with
every cluster's verdict/failure indexed under `clusters` (`_generator: harness-parallel`); an
analyst-authored head is never overwritten. The judged partition IS `clusters.json` (the pipeline's
own `intel.py clusters`, written every run), and every host a round collects gets a hop in
`state.json` (a subdomain inherits its apex's hop), so the loop and the harness agree on members and
leaves. `--depth N` counts collection ROUNDS: the last round's discoveries stay pending. Each judge is told its exact member list and its `cluster` must stay inside it: a judge
that assesses other hosts (e.g. a neighbouring estate it found in the KB) is re-prompted once and
otherwise refused. A cluster whose judge fails is listed as **JUDGMENT FAILED** with its reason (also under
`failover_progress.json` → `__failed__`) while the others still persist; the run exits non-zero and
a re-run re-judges only the failed clusters. With a CLI backend (`codex`/`omp`) each cluster's
judge chain runs in its own host-config slot (`harness_home/<backend>_runs/<uuid>`), so concurrent
judges cannot swap results; a resumed phase (correlate → verify → assess) restarts in the slot that
created its session, because the host CLIs bind a session to its starting directory.
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
The Correlate phase has a **`cert_overlap`** tool (`tools/cert_overlap.py`, keyless, through the
shared `wp_ct` client: crt.sh, then Shodan CTL + CertSpotter when crt.sh is down). Two domains sharing
a TLS certificate — or one domain's cert SAN list naming another — is near-decisive same-operator
proof, because the SAN list is chosen by whoever controls the cert. It returns `SHARED-CERT` / SAN
cross-cover (decisive), `SIBLING-OVERLAP` (certs carry a common third domain = strong),
`NO-CT-OVERLAP` (a clean negative you can also weigh — only when crt.sh answered for every input) or
`INCONCLUSIVE-CT-DEGRADED` (crt.sh unreachable: backups hold ~1 year, so this is NOT a negative). The
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
- runs the **premium-engine set** when keyed — Censys, Hunter.how, **Validin** (FREE key: DNS +
  certs + favicon + response-body-hash reverse), **SecurityTrails** (subdomains + DNS history),
  **DNSLytics** (reverse GA/AdSense → sibling domains). They all ride this SAME
  `collect_core.collect_host` → `pivot_extract` → `enrich_live` path, so they **auto-flow into
  harness deepening + `--fanout`** with no orchestrator change. **Validin is quota-governed and
  runs even under `--free-only`** (it is free); the metered engines (FOFA/Censys/SecurityTrails/
  DNSLytics/Hunter.how) are held back under `--free-only` and opt in via `intel.py loop --full`;
- **detects Cloudflare** (`meta.cloudflare`) and auto-retries the bypass — a real browser via `--render` (uses `WebPivot/.venv`), or FlareSolverr if `HARNESS_FLARESOLVERR=http://host:8191/v1` is set.

The judgment phase also has a **`reverse_whois`** tool that returns only high-value pivots: it refuses privacy/registrar terms and flags a bulk registrant (`> max_domains` = reseller = noise) instead of dumping it.

Every run prints/saves the standard **Domain Summary table** (`tools/domain_table.py`) — Domain · Status · Registered · Expires · Registrar · Nameservers · Registrant · IP·ASN · Attribution · Context — for the domains collected this run, above the assessment.

New env knobs: `HARNESS_FLARESOLVERR` (CF solver URL) · `HARNESS_RENDER_PY` (Playwright/Chromium python for screenshots and the CF retry, default `WebPivot/.venv`; plain DOM renders use Moli and need no Playwright) · `CTI_BROWSER` (`auto`|`moli`|`chromium`, see `WebPivot/tools/wp_browser.py`).

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
