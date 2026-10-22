# Repository Guidelines

`cti-expert` is a cyber-threat-intelligence / OSINT analysis **skill** (Claude Code, Codex, any
`AGENTS.md`-reading agent) wrapped around a deterministic Python **intel engine**. This file is the
cross-agent entry point for working *on* and *with* the repository. The analyst workflow and command
catalog live in `SKILL.md`; contributor rules in `CLAUDE.md`; install detail in
`scripts/platform-setup.md`. `$SKILL_DIR` below = the directory containing `SKILL.md` (resolve it
by locating that file — never assume `~/.claude/skills/cti-expert`).

## Project Overview

- Purpose: turn a seed (domain, e-mail, phone, IP, image, wallet, file) into an evidence-backed,
  ICD-203-graded assessment and a deliverable report — without ever naming a third party as the
  operator on a single shared-infrastructure signal.
- Two layers: root = analyst-facing scripts/commands/docs (`scripts/`, `commands/`, `SKILL.md`);
  `intel_engine/` = vendored engine (collector, knowledge base, resumable case pipeline, LLM
  harness + MCP server, graph and report renderers). `STRUCTURE.md` maps both.
- Canonical entry: `/cti <target>` (alias `/case`). Nine cold-prompt commands live in `commands/`
  (`/cti`, `/cti-recall`, `/cti-case`, `/cti-pivot`, `/cti-cluster`, `/cti-check`, `/cti-report`,
  `/cti-status`, `/cti-proxy`); everything else in `SKILL.md` §3 is a loaded-skill convention.

## Architecture & Data Flow

```
seeds ──► collect_core.collect_many() ─► WebPivot/tools/pivot_extract.py (analyze + enrich_live + WHOIS)
             │                              writes cases/<id>/raw/<host>.json, dom/, screenshots/
             ▼
   tools/kb/ingest_webpivot.py ──► knowledge/ (entities + edges; noise_filters decide fact vs edge)
             ▼
   tools/intel.py open|loop ──► shared.txt, clusters.json, case_graph.json, rounds.jsonl, state.json
             │        └─ case_state.frontier(): free next-round seeds, co-tenancy leads held back
             ▼
   evidence_report.render_cluster_report ──► assessment.md / assessment.json (+ whois/<domain>.json sidecar)
             ▼
   tools/house_report.py ──► cases/<id>/report/CTI-REPORT-*.{md,pdf,docx}   (IntelReport/IntelGraph)
   scripts/build_report_data.py ──► REPORT.json ──► generate-cti-{html,iocs,docx-hybrid}.py
```

- **Two `intel.py` files.** `scripts/backend/intel.py` is the Tier-2 *dispatcher* (op → engine
  script, runs with `cwd=$INTEL_HOME`, injects `--kb knowledge`); `intel_engine/tools/intel.py` is
  the deterministic *pipeline* (`open`, `loop`, `clusters`, `status`). Dispatcher has no `status`
  op — use `pipeline status <case>` or `harness status <case>`.
- **Spend vs egress are separate gates.** `--free-only` (and `scope.json` `no_spend`, mapped in
  `harness/case_scope.py`) means *no metered credits*; every metered engine in
  `wp_analyze.enrich_live` is `have_x = configured() and not free_only`. Hostile-target egress is a
  different gate (`collect_core.py` egress block, `harness/audit.gate()`: passive/proxy required).
- **Attribution safety is structural.** Only registrant e-mail/phone are decisive join keys
  (`evidence_report.py`); `KB.shared_indicators()` clusters on *edges* only, so co-tenancy is
  written with `add_fact` (never `add_edge`); `case_state._HOST_YIELDING_SOURCES` lists the only
  live-result blocks that auto-seed the frontier, and co-tenancy guards (`MAX_CERT_APEXES`,
  `MAX_IP_COHOSTS`, `BULK_IP_RESULTS`, `MAX_WHOIS_SIBLINGS`) hold multi-tenant certs / shared IPs /
  reseller terms back as leads instead of seeds.
- **Harness** (`intel_engine/harness/`) is the LLM front-end over the same artifacts: `tools.py`
  `@tool` wrappers, `mcp_server.py` (stdio JSON-RPC, auto-discovers every `@tool`), `cli.py`.
  Cross-type loop: typed nodes → `propose` → Plan phase (`PLAN_TOOLS`, read-only) → auto free/urlscan
  pivots with ≤ N=25 hits, else digest-bound `proposal.json` gated in `audit.gate` (`harness approve`,
  `case_approve`, TTY). Dispatcher ops `propose` and `corpus-search`; weak links stay `add_fact` only.
  Plan-phase drops persist in `state.json` `dropped` (cleared by `reopen`); `propose` never offers a
  route whose key is absent (`pivot_routes.route_runnable`) or a `pivot_map.json`
  `propose_type_exclude` pair (anyrun on IPs); `rungs.json` `fact_only_node_classes` (Quarry
  page.phone/page.email) stay KB facts, never nodes.
  Needs a venv + a reasoning backend; the deterministic layers do not. `HARNESS_BACKEND`
  (`harness/backend_select.py`, `intel.py harness doctor`) resolves the backend per run: `claude` (Agent
  SDK / Claude Code login or `ANTHROPIC_API_KEY`), `codex` / `omp` (`harness/cli_backend.py` —
  the host CLI's own login, each phase an isolated MCP-only process judged by its event stream),
  or an OpenAI-compatible key (`harness/openai_backend.py`). `auto` prefers the host agent the
  process runs inside; an unusable backend fails the run by name, never as a `✓ $0.00` phase.

## Key Directories

| Path | Purpose |
|---|---|
|`SKILL.md`, `commands/*.md`|analyst workflow, registered slash commands (`scripts/register.sh` → Claude Code, `scripts/register_agents.py` → every other agent)|
| `scripts/` | report generators (PEP 723), `redact.py`, `build_report_data.py`, `audit.sh`, installers, `backend/intel.py` dispatcher |
| `scripts/webpivot/*.py` | **re-export shims** onto the canonical engine collectors — never edit or fork |
| `intel_engine/WebPivot/tools/` | canonical collector: `pivot_extract.py`, `wp_*.py` vendor clients, `wp_analyze.py` (enrich_live), `whois_enrich.py`, `evidence_report.py` |
| `intel_engine/WebPivot/references/*.json` | reference DATA (thresholds, denylists, endpoint maps, key registry `api_keys.json`) |
| `intel_engine/tools/` | pipeline `intel.py`, `case_state.py` (frontier + `propose`), `selector_types.py`, `pivot_routes.py` (`corpus-search`), `collect_core.py`, `domain_table.py`, `house_report*.py` |
| `intel_engine/tools/kb/` | `knowledge_base.py`, `ingest_*.py` (+ `ingest_typed.py`), `noise_filters.py`, `convergence.py`, `reference.py`, `references/rungs.json` (owner/kit/neighbour) |
| `intel_engine/harness/` | SDK harness, `@tool` registry, MCP server, `case_scope.py` posture, `proposal.py` (digest-bound approval), Plan phase |
| `intel_engine/IntelGraph/`, `intel_engine/IntelReport/` | figure/timeline scripts; pandoc+xelatex renderer; each has `SKILL.reference.md` (not README) |
| `intel_engine/cases/`, `intel_engine/knowledge/`, `intel_engine/MEMORY/`, `.orca/`, `plans/` | runtime / private data — gitignored, never fixtures, never quoted in tracked files |
| `tests/`, `intel_engine/tests/`, `intel_engine/tools/eval/` | regression homes (see Testing) |

## Development Commands

```bash
# Repository gate (leak scan, dispatch/shim/@tool parity, py_compile, §6 tests, hooks, command counts)
bash scripts/audit.sh                      # must end with "AUDIT: clean"

# One regression file (all are self-contained scripts; pytest is optional convenience)
python3 tests/test_house_report_compose.py
python3 intel_engine/tools/eval/test_frontier_guards.py
python3 intel_engine/tools/eval/run_eval.py --case qr_funnel   # ONE frozen fixture, offline
# NEVER run run_eval.py unscoped casually: the unit modules are offline, but a full pass has
# spent real metered credits before; its spend guard is post-hoc.

# Engine entry points (Tier-2 dispatcher; it cd's into the engine, so existing caller-relative paths are absolutized — output names are not, pass those absolute)
uv run scripts/backend/intel.py list
uv run scripts/backend/intel.py pipeline open CASE-0001 /abs/seeds.txt [--free-only] [--whois-history off|preview|purchase]
uv run scripts/backend/intel.py pipeline status CASE-0001
uv run scripts/backend/intel.py frontier CASE-0001 | convergence CASE-0001 | recall <selector>
uv run scripts/backend/intel.py house-report CASE-0001 [--md-only --no-screenshots --mask-personas]
python3 scripts/backend/intel.py mcp --write      # regenerates the local, gitignored .mcp.json (Claude Code)
python3 scripts/backend/intel.py mcp --host codex|omp|all --write   # Codex: [mcp_servers.intel] in $CODEX_HOME/config.toml · OMP: .omp/mcp.json
python3 scripts/backend/intel.py harness doctor [--backend X]      # which LLM backend a harness run would use (probes auth)

# Report pipeline (see §Runtime for the ask-first / always-save contract)
S="$SKILL_DIR/scripts"
uv run "$S/build_report_data.py" "${INTEL_HOME:-$SKILL_DIR/intel_engine}/cases/<CASE-ID>" -o REPORT.json
uv run "$S/generate-cti-html.py"  REPORT.json REPORT.html
uv run "$S/generate-cti-iocs.py"  REPORT.json IOC-PREFIX --format all
python3 "$SKILL_DIR/scripts/backend/intel.py" house-report <CASE-ID>          # case dir → editorial PDF+DOCX
uv run "$S/generate-cti-docx-hybrid.py" REPORT.md REPORT.json REPORT.docx --pdf # no case dir → dashboard DOCX/PDF
uv run "$S/redact.py" REPORT.md -o REPORT.redacted.md --map REPORT.map.json     # opt-in; never ship the map

# Install (bootstraps uv, venv at ~/.claude/skills/.venv; OS-native binaries)
bash scripts/install.sh [--headless] [--all]      # Windows: scripts/install.ps1 [-Headless] [-All]
```

There is no formatter, linter, or lockfile in the repo; `audit.sh` is the only gate.

## Code Conventions & Common Patterns

- **Stdlib-only deterministic layers.** `intel_engine/tools/`, `WebPivot/tools/`, `tools/kb/`
  import nothing third-party at module level (optional deps guarded by `try/except`). SDK/model
  code lives only under `harness/`. Root `scripts/*.py` carry PEP 723 `# /// script` headers.
- **Path-relative imports.** `HERE/ROOT/WP/KB_TOOLS` from `__file__`, `sys.path.insert(0, …)` then
  `import x  # noqa: E402`. Lazy-import across the `wp_analyze ↔ wp_ippivot` cycle at the call site.
- **Reference data, not literals** (the "RULE 3" label inside the `*_refs.py` loaders). Tunables live in the component's `references/*.json`,
  loaded via `load_ref(ref_path(__file__, "x.json"), _X_FALLBACK)` where `_X_FALLBACK` is the
  *conservative minimum*. Every new constant gets a parity row in `tests/test_references.py`.
  Example: `wp_net.URLSCAN_STRUCTURAL_LABELS` ← `urlscan_endpoints.json → verdict.structural_labels`.
- **Canonical + shim (CLAUDE.md Rule 4).** Edit `intel_engine/WebPivot/tools/*`; `scripts/webpivot/*` stay
  importlib re-exports. `audit.sh` §3 fails on a second implementation.
- **Tri-state, never raise.** Vendor clients return `dict | None | {"error"|"skipped": …}`; wrappers
  in `enrich_live` catch everything (`fu.result()` re-raises inside the executor). Ledger every
  metered call through `api_usage.record`.
- **Naming.** `wp_<vendor>.py`, `<x>_configured()` gates, `render_*` composers, `cmd_*` CLI
  handlers, `_<x>_cached` / `_<X>_CACHE` memos, `_write_<artifact>` persisters in `intel.py`.
- **Attribution rails (SKILL.md RULE 5 — never name an innocent party).** New live-result blocks join `_HOST_YIELDING_SOURCES` only if
  every row is an owner link; anything provider-level (co-tenancy, same-MO) is classified
  case-wide, persisted as its own `cases/<id>/*.json`, ingested as `add_fact` only, never
  `operator_lead`, never an edge; the harness cross-type loop MAY collect such hosts (source
  `kit:`/`cotenant:`/`cpty:`) but they never cluster, never attribute, and render as kit siblings /
  neighbours with a rung caveat.
- **Report scrub (IntelReport Rule 12) and citations (Rule 21).** `house_report.scrub()` maps vendor/tool/path
  names to public source classes and keeps indicator values; URLs pass through it untouched. Every public
  evidence URL (archive capture, published document, live page) is cited inline as a hyperlinked `[n]` and
  listed in a `# References` section before the appendices; only loopback/private links are dropped.
  Third-party e-mails/phones/case-ids are masked unless in the case-scoped `_KEEP`.
- **Analyst ownership.** Never clobber a hand-written `assessment.md`/`.json`; the loop writes
  `loop_assessment.*` when the producer signature does not match (`may_overwrite_assessment`).
- **Synthetic data only in tracked files**: `example.com`, `*.example`, RFC 5737 IPs, `CASE-0001`,
  obviously fake contacts. No real PII, targets, tracker IDs, hashes, or case IDs.

## Important Files

| File | Why it matters |
|---|---|
| `SKILL.md` | analyst contract: §2.5 reference checks, RULE numbering, command catalog, Deliver contract |
| `CLAUDE.md` | contributor Rules 1–6 (case data, single case store, `@tool`+dispatch+doc, shims, classification tests, hooks) |
| `scripts/backend/intel.py` | op → script `DISPATCH` map; `--dry-run` prints the resolved command |
| `intel_engine/tools/intel.py` | `cmd_open` (collect → ingest → clusters → graph → assessment → sidecar → MO-neighbours), `cmd_loop` |
| `intel_engine/tools/case_state.py` | `state.json` schema, frontier miner, `propose()` typed candidates, co-tenancy constants, `mo_neighbour_classification` |
| `intel_engine/tools/selector_types.py` | typed selectors + `rung_for` (owner/kit/neighbour); pairs with `kb/references/rungs.json` |
| `intel_engine/tools/pivot_routes.py` | corpus route dispatch (`corpus-search`); urlscan/Wayback/FOFA/PublicWWW |
| `intel_engine/harness/proposal.py` | digest-bound `proposal.json`; `harness approve` / `case_approve` / TTY gate |
| `intel_engine/WebPivot/tools/wp_analyze.py` | `enrich_live` `have_*` gate block and per-pivot branches |
| `intel_engine/WebPivot/tools/wp_refs.py` | `ref_path` / `load_ref` (also vendored as `kb_refs.py`, `ig_refs.py`) |
| `intel_engine/tools/kb/noise_filters.py` | the single shared-infrastructure denylist (frontier and ingest both read it) |
| `intel_engine/harness/tools.py`, `mcp_server.py`, `case_scope.py` | `@tool` registry (MCP auto-discovers), posture → `free_only`/hostile |
| `intel_engine/WebPivot/references/api_keys.json`, `scripts/apikeys/registry.json` | key NAMES, aliases and unlocks — values live only in the gitignored `.env` |
| `scripts/audit.sh` | the gate; §6 is the explicit root-test list |
| `.env.example`, `.mcp.json` (local) | env var names; MCP registration generated, never committed |

## Runtime/Tooling Preferences

- **Python 3.10+**, **uv first** (`uv run` scripts, `uv pip install --python <venv>` libs,
  `uv tool install` CLIs); fallback `python3`/`py` + pip/pipx. A uv venv has no pip. On Windows
  `python` may be a Store stub — prefer uv or the `py` launcher.
- **Detect the OS once** (`uname -s` / `$IsWindows`) and dispatch shell + package manager
  (winget / brew / apt · dnf/yum · pacman · zypper · apk). Never run Linux package commands on Windows.
- Dependency truth = `requirements.txt`, `scripts/requirements.txt`, per-engine
  `intel_engine/*/requirements.txt`, PEP 723 headers. No `pyproject`, no lockfile, no Node manifest
  except vendored `scripts/vendor/archify`.
- Optional, feature-scoped tooling — never make baseline: pandoc + xelatex (IntelReport PDF/DOCX),
  Graphviz `dot` (graphs/cloud figure), Node ≥ 18 (Archify blueprint; `CTI_ARCHIFY=0` skips),
  Node ≥ 20 or Bun (Pele, the pinned Mermaid renderer behind IntelGraph figures — `references/pele.json`,
  fetched into the gitignored `IntelGraph/vendor/pele/`; PNG/PDF via `rsvg-convert` → headless
  Chrome/Edge → cairosvg, last because it drops label emoji), Playwright/Chromium (screenshots,
  engage, Cloudflare escalation — `--headless`), Moli (DOM renders, default install;
  `CTI_BROWSER=auto|moli|chromium`). All degrade loudly.
- `INTEL_HOME` defaults to the vendored `intel_engine/`; to override, **export** it in the process
  (an `.env`-only value loses to the resolver). Cases live only under `$INTEL_HOME/cases/<id>/`.
- Secrets: process env first, then gitignored root `.env` (`CTI_API_KEYS_ENV` overrides the path).
  Never write key values into tracked files, tests, plans, or chat.
- **Report contract (all agents):** first ask whether to import manual evidence
  (`evidence-images.py`, extra findings) and merge into REPORT.json; always save the base bundle
  (MD + JSON + CSV + STIX/txt/csv/jsonl IOCs); then ask PDF / DOCX / HTML / all (`--yolo` → HTML,
  `/report legal` → all). Pipeline cases build REPORT.json with `build_report_data.py`, never by hand.
- **No-exec / ephemeral environments** (ChatGPT web, cloud sandboxes): deliver the Markdown report
  + report JSON, list the HTML/IOC/DOCX builds and CLI recon as steps to run locally, and never
  claim a tool ran. Say so when you detect such an environment.
- **Codex:** opening the repo auto-loads this file; add a pointer line to `~/.codex/AGENTS.md` for a
  global default. `scripts/register_agents.py` installs `$cti` as the `~/.agents/skills/cti` skill
  (Codex removed `~/.codex/prompts` custom prompts in 0.117; skills are invoked with `$`, never `/`).
- **Other agents:** `register_agents.py` writes pointer stubs for omp, pi, OpenCode, Gemini CLI,
  Qwen Code, Factory droid and Windsurf (`/cti*`) and the shared skill for Cursor / Copilot CLI /
  ChatGPT desktop; each stub carries the `cti-expert:generated` marker, the only files it rewrites or removes.
  `register.sh --uninstall` likewise removes only `~/.claude` symlinks that resolve into this repo —
  a user's same-named file or foreign link is reported and kept. On Git Bash (Windows) `register.sh`
  requests native symlinks and, when Windows refuses, writes marked stubs via the non-auto
  `--host claude`; default `--uninstall` removes those too.

## Testing & QA

- **Tests are local-only.** Every suite below, the eval harness and its fixtures are gitignored and
  never committed or pushed (`scripts/install-hooks.sh` installs pre-commit/pre-push guards); run
  `bash scripts/audit.sh` locally, where they exist. A checkout without them skips the test sections.
- Framework: plain scripts, no pytest dependency. Root `tests/test_<subject>.py` hold a `_TESTS`
  list + `check() -> (passed, failed, lines)` and end with `raise SystemExit(bool(failed))`.
  Engine/eval modules (`intel_engine/tests/`, `intel_engine/tools/eval/test_*.py`) expose the same
  `check()` triple and are importable by `run_eval.py`.
- **Registration is explicit, twice:** add a root script to `scripts/audit.sh` §6; add an eval/engine
  module to `run_eval.py unit_mods` (distinct basenames — root `tests/` shadows engine `tests/`).
  Unregistered files run only by hand.
- Golden extractor fixtures: `intel_engine/tools/eval/cases/<name>/{input.html,expected.json}` with
  `expect_*` and `forbid_*`; auto-discovered.
- Build schema-faithful synthetic cases in `TemporaryDirectory` (`tests/test_house_report_compose.py
  _synthetic_case`, `test_case_pipeline_smoke._make_case`); point `hr.KB`/`ip.KB` at an empty temp
  KB; stub network seams (`urllib.request.urlopen`, vendor module functions) and restore in `finally`.
- Expectations are behavioural, not coverage %: each test defends a rail (spend gate, co-tenancy
  guard, privacy/unverifiable buckets, scrub/mask scope, honest degradation). Classification changes
  need both a managed-provider and a self-hosted-NS case (`CLAUDE.md` Rule 5).
- Live verification (real vendors, real case) is a separate, non-gating smoke on a case copy; record
  its diff under `intel_engine/cases/<id>/report/`, never under `plans/`.
- CI: `.github/workflows/audit.yml` runs `bash scripts/audit.sh` (structural + leak sections only;
  no tests run on GitHub). The installer readiness check `scripts/smoke-test.sh` is local-only too:
  run it by hand after `scripts/install.sh` on a fresh machine.
