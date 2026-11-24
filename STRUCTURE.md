# cti-expert — repository structure & anti-drift rules

cti-expert is **one skill, two layers**: a **broad collector** (cti-expert's own tools) plus the
**vendored `intel_engine` engine** (pipeline chains + deeper pivoting logic). This file is
the map, and the rules that keep the two from drifting.

## Top-level layout

**cti-expert's own** (the collector + presentation + docs):
- `SKILL.md` — the single skill entrypoint (there is exactly one SKILL.md in the repo)
- `scripts/` — collectors (`scripts/webpivot/`), the backend dispatcher (`scripts/backend/`), report generators,
  `register.sh` (Claude Code) + `register_agents.py` (`/cti` for every other coding agent)
- `scripts/cti_report_sections.py` (shared report-section spec + anti-inflation check), `scripts/references/report_metrics.json`, `email_spoofability.json`, `stealer_triage.json`, `handle_rarity.json` (pivot_suggest handle-rarity grade)
- `scripts/osint/references/phone_osint.json`, `exposure_executive.json`, `exposure_organisation.json` (organisation risk-by-domain model, weight-engine §8), `exposure_actor.json` (actor Threat Score model, §9), `severity_tiers.json` (Severity Tier Matrix, §10; operator reference `handbook/severity-tiers.md`), `agentic_signatures.json`
- `scripts/osint/references/dork_builder.json`, `username_enum.json`
- `techniques/`, `handbook/`, `connectors/`, `analysis/`, `validation/`, `experience/`, `guides/`,
  `workflows/`, `engine/` (case data-model design docs — distinct from the `intel_engine/` pipeline),
  `assets/`, `output/`
- `handbook/command-reference.md`, `report-export.md`, `technique-activation.md`, `architecture-reference.md`, `case-pipeline-detail.md` — reference moved out of `SKILL.md` (full command rows, Deliver steps + report JSON, auto-fire matrix, directory tree, §2 pipeline detail); `SKILL.md` links each with when to read it
- `tests/` — zero-dep regression tests (`python3 tests/test_*.py`, no pytest needed): RULE 5
  indicator classification + the shared collector core (`collect_core`). **Local-only:** gitignored,
  never pushed (same for `intel_engine/tests/`, `intel_engine/tools/eval/` and every `test_*.py`)
- `scripts/audit.sh` — structural drift + leak gate (DISPATCH resolves, shims are re-exports and
  match the table below, collection HTTP goes through `wp_http` / `wp_ua`, and the vendored
  JS/markup under `scripts/vendor/` makes no network calls and loads no remote resources, with
  exceptions listed in `scripts/references/http_allowlist.json`, `@tool` count matches CLAUDE.md, compile, tests, every
  registered hook resolves);
  `scripts/install-hooks.sh` wires `scripts/leakcheck.sh` as a pre-commit hook. Both run in CI via
  `.github/workflows/audit.yml`
- `scripts/backup-local-suites.sh` — encrypted (`gpg` AES-256) archive of the local-only suites
  to a directory outside the repository and outside any Git work tree; `--verify` restores it to a
  temporary directory and compiles it. The file list comes from the same pattern the no-tests
  hooks enforce (`TEST_RE` in `install-hooks.sh`)
- `hooks/` + `.claude-plugin/plugin.json` — the **Claude Code harness layer**. `plugin.json`
  bundles the skill, `commands/`, the `intel` MCP server and `hooks/hooks.json` into one
  installable plugin, so a machine gets all four by installing one thing instead of running
  `register.sh` and hand-writing `.mcp.json`. The three hooks are safety rails that deliberately
  do **not** live in the vendored engine:
  - `leakguard.py` (PreToolUse · Write/Edit) — RULE 1 at *write* time. The git pre-commit hook
    fires only at commit and `--no-verify` skips it; an agent harness writes constantly and
    commits rarely. Delegates to `scripts/leakcheck.sh` rather than re-implementing the patterns,
    and only denies inside a cti-expert checkout on a path git does not ignore.
  - `actionguard.py` (PreToolUse · Bash + `mcp__*`) — `ask` on outbound, irreversible actions.
    The in-code gates are real but live in `intel_engine/`, which is vendored; this one is in
    cti-expert's own tree so an engine sync cannot revert it. Denylist is DATA
    (`hooks/references/outbound_actions.json`).
  - `sessionguard.py` (SessionStart) — backend tier, plus a warning when the `@tool` count changed,
    because Claude Code caches an MCP tool list at connect time and a stale one fails silently.

  Both PreToolUse hooks **fail open**: a hook bug must never brick the repo. Covered by
  `tests/test_hooks.py` in both directions (fires on the target / silent on the neighbour).
- `requirements.txt` — deps for the vendored deep layer (installed into `.venv`)

**Vendored engine — one subtree** (`intel_engine/`, copied one-way from the `intel_engine`
archive; that archive is **read-only**, cti-expert never writes back to it):
- `intel_engine/harness/` — the pipeline brain (`cli.py`, `orchestrator.py`, `mcp_server.py`),
  plus `audit.py` (what the model actually called; proposal digest gate), `case_scope.py` (intake +
  egress gate), `proposal.py` (digest-bound approval), `schemas.py` (Assessment tiers + Plan),
  `sdk_compat.py` / `openai_backend.py` (run the loop on an open-weight backend) and
  `dashboard/` (loopback-only run inspector)
- `intel_engine/tools/` — `intel.py` (deterministic pipeline), `case_state.py` (frontier/reopen +
  `propose`; `ips_pending` = historical origin IPs from `WebPivot/tools/wp_origin_history.py`),
  `selector_types.py`, `pivot_routes.py` (`corpus-search` dispatcher op), `ghw_exposure.py`
  (GrayHatWarfare per-apex exposure → `cases/<id>/grayhatwarfare/`, facts only),
  `kb/*` (KB + correlation + `ingest_typed.py` + `references/rungs.json`), `cert_overlap`,
  `case_store`, …
- `intel_engine/tools/masked_hint.py` (masked recovery-hint correlation), `report_sections.py` (analyst report block + sources-checked; `attack_coverage()`, `tactic_rank()`, `priority_label()`, actor-profile lint), `house_report_sections.py` (house-report renderers for the report block, incl. the "Actor Profile" chapter), `house_report_exposure_charts.py` (infected-computer charts by year / country / stealer family for the affiliate-exposure section, counts only), `tools/kb/references/masked_hint.json`, `report_sections.json`; `scripts/cti_report_sections.py` `actor_blocks()` is the chapter structure shared by the HTML and DOCX generators
- `intel_engine/WebPivot/` — engine collector helpers (`wp_*`) + de-dup shims (see below)
- `intel_engine/WebPivot/tools/wp_ua.py` — the one User-Agent source (`DEFAULT_UA`, `UA_POOL` from `WebPivot/references/fetch_profile.json → ua_pool`; side-effect free, re-exported by `wp_common`); the service-required exceptions are listed in `fetch_profile.json → ua_exceptions`
- `intel_engine/WebPivot/tools/wp_http.py` — the one transport for API calls (`request()` → `Response`, never raises; opt-in retry policy in `WebPivot/references/http_client.json`). `wp_net.fetch` stays the target-page fetcher
- `intel_engine/WebPivot/tools/wp_pgp.py` (keyless PGP keyserver pivot), `wp_container.py` (public container-registry OSINT), `wp_takedown.py` (RDAP hold / DNS sinkhole + successor leads), `WebPivot/references/pgp.json`, `container_registry.json`, `takedown.json`
- `intel_engine/WebPivot/tools/wp_corp.py` (global company/officer registry pivot), `wp_google.py` (GHunt wrapper: Google-account leads), `wp_telegram.py` (Telegram phone/username lookup, confirm-gated), `wp_revimg.py` (reverse-image search); `WebPivot/references/corp_registry.json`, `google_account.json`, `telegram.json`, `reverse_image.json`
- `intel_engine/BinaryPivot/tools/bp_git.py` (embedded .git + module identifiers in leaked archives/dirs), `bp_archive_time.py` (archive timestamp forensics, packer UTC offset), `bp_keys.py` (keys/certs deduped by SPKI SHA-256), `intel_engine/BinaryPivot/references/leak_forensics.json`
- `intel_engine/WebPivot/tools/wp_suppliers.py` (supplier map from case raws → `cases/<id>/suppliers.json`, KB facts only, single-layer CLI), `wp_custody.py` (custody log, seal, working copy, fixity sample); `WebPivot/references/suppliers.json`, `custody.json`
- `intel_engine/WebPivot/tools/wp_appliance.py` (passive edge-appliance scan: InternetDB / keyed Shodan host + Censys → product + version → CISA KEV (cached `cache/kev.json`) → patch lag + "no reboot since"; `cases/<id>/appliances.json`, KB facts only, single-layer CLI); `WebPivot/references/appliance.json`
- `intel_engine/IntelGraph/scripts/card_map.py` — relationship card map (hub, trunk, panels, Admiralty badges) from a JSON spec; stdlib SVG, PNG/PDF via the existing render chain; `IntelGraph/references/card_map.json` (tunables), `card_map_example.json` (synthetic spec)
- `intel_engine/IntelGraph/scripts/operator_tempo.py` — lead-only operator tempo read behind `case_timeline --tempo` (event filter, UTC-offset working-window scan, two-rhythm check, confounders; no KB writes); `IntelGraph/references/operator_tempo.json` (floor, windows, offsets, event kinds, automated issuers, bot patterns, confounders)
- `intel_engine/IntelAnalysis/references/hunt_packages.json` — link-only hunt-package library (67 upstream queries, no query text, URLs pinned to commit 0f76fbc; ABLE hypothesis, CAR telemetry, prerequisites, method, FP notes per entry); read by people, not code — procedure in `workflows/wf-threat-analyst.md` Phase 5
- `intel_engine/IntelAnalysis/references/hunt_rules_yamato.json` — GENERATED link-only index of Yamato Security detection content by ATT&CK technique: hayabusa-rules @73f990f and suzaku-rules @b5b2e1b (DRL 1.1; per technique the rule count, top 5 rule refs with verbatim author, directories for the rest; every Sigma rule id in `sources.<repo>.rule_ids`; correlation files indexed per document as `kind: correlation` / `kind: base`) and Senrigan hunts @8d92511 — CloudTrail, Suzaku-timeline and VPC Flow Log (`senrigan-vpcflow-…`, telemetry `vpcflow/<column>`) — (AGPL-3.0, metadata + links only); totals in the top-level `counts`; no detection logic; read by people and by `report_sections.py` (hunt_package_ref lint) — procedure in `workflows/wf-threat-analyst.md` Phase 5
- `intel_engine/IntelAnalysis/scripts/build_yamato_index.py` — stdlib generator that rebuilds `hunt_rules_yamato.json` from local clones at their HEAD commit (deterministic; `--per-technique N`)
- `intel_engine/IntelAnalysis/references/telemetry_baselines.json` — Windows telemetry need → audit subcategory / defaults / baseline settings / log sizes (Yamato Security EventLog-Baseline-Guide, MIT, pinned 9a253a39); valid `telemetry_priorities[].baseline_ref` keys
- `intel_engine/IntelGraph|IntelReport|BinaryPivot|IntelAnalysis|Engage|IntelHarness|IntelShare/` —
  render, analysis, engagement and dissemination skills (their `SKILL.reference.md` are docs, not skill entrypoints —
  the repo has exactly one `SKILL.md`, at the root)
- `intel_engine/tests/` — the vendored engine's own gates (`test_tool_registry` RULE 2,
  `test_tool_gate` submission approval, `test_engage`, …); `run_eval.py` puts both this
  directory and the repo-root `tests/` on the path so neither suite silently stops running.
  Local-only, like `tests/`
- `intel_engine/tools/notice_pack.py` (drafts registrar / host / CDN / platform / bank / referral / compromise notices from stored case artifacts → `cases/<id>/notices/`; no network, nothing sent; subjects limited to the seed and owner-rung cluster members), `tools/kb/references/notice_templates.json`, `case_disposition.json` (closing outcomes behind `case_state.close()` / `log_action()`)
- `intel_engine/tools/watchlist.py` (watch-list over `ct_monitor` / `wp_impersonate` / `wp_takedown` / `case_drift`: due-run, leads only, state in `MEMORY/watchlist.json` + `MEMORY/watch/<id>/`), `tools/kb/references/watchlist.json`
- `intel_engine/WebPivot/tools/wp_kitsig.py` (named kit-signature matcher → `artifacts.kit_matches`, kit-rung facts; nested all/any/not terms), `wp_iok.py` (converter from phish.report IOK's Sigma rules to matcher rules), `scripts/kit_rules_import.py` (`uv run … update|status`: downloads IOK, ODbL-1.0, into the git-ignored `intel_engine/cache/kit_rules/iok.json` — never redistributed), `wp_emvqr.py` (EMVCo / VietQR payment-QR parser, CRC-verified → `artifacts.payment_accounts`), `WebPivot/references/kit_signatures.json` (tracked rules: one synthetic example; real kit rules come from the import or the reference ledger), `payment_rails.json`, `drainer_markers.json` (connect-library / approval-harvest / legitimate-app markers behind `artifacts.web3`)
- `intel_engine/tools/kb/references/route_yield.json` (how measured vendor yield is used by `case_state.propose`; the measurement itself is `MEMORY/route_yield.json`, written by `api_usage.py report --yield`), `harness/references/context_budget.json → batch` (list-argument lookups); `tool_outcomes.jsonl` beside each `tool_calls.jsonl` records what a tool call returned
- **Local patches an upstream re-sync must keep** (added with the measured-improvement work): `harness/audit.py` (`record_outcome`, analyst-only tools), `harness/tools.py` (outcome row and `INTEL_CASE` tag in `_governed`, batched lookups, `case_close` / `notice_draft` / `watchlist`), `harness/mcp_server.py` (`set_context` before the handler), `tools/case_state.py` (`close`, `log_action`, yield tie-breaker), `tools/intel.py` (`close`, `action-log`, `notice`, closed-case stops), `harness/orchestrator.py` and `harness/cli.py` (closed-case stops, lifecycle in status), `tools/kb/query.py` (repeatable `--entity` / `--cluster`), `WebPivot/tools/api_usage.py` (`report --yield`), `WebPivot/tools/whois_enrich.py` (RDAP abuse contact)
- `intel_engine/knowledge/` + `intel_engine/cases/` — **local runtime data, gitignored** (a fresh KB; the old data stays in the archive)

## Anti-drift rule — single source per collector (do NOT create a second copy)

Nine collectors exist in both layers. Each has **one canonical file** and, because both import
paths must keep working, a **short re-export shim** (Windows-safe; no symlinks). Never turn a shim
back into a real copy — edit the canonical. `scripts/audit.sh` §3 derives the pair list from the
two directories and fails when this table disagrees with the files:

<!-- shim-table:begin -->
| collector | canonical (edit here) | shim (do not edit) |
|---|---|---|
| `pivot_extract`, `whois_enrich`, `wp_appdev`, `wp_github`, `wp_sellers`, `wp_subenum` | `intel_engine/WebPivot/tools/` | `scripts/webpivot/` |
| `cdn_ranges`, `graph_build`, `wayback_ga` | `scripts/webpivot/` | `intel_engine/WebPivot/tools/` |
<!-- shim-table:end -->

Single-layer collectors — real code in `scripts/webpivot/` only, no engine twin, edit in place:
`cert_pivot`, `crypto_balance`, `email_hygiene`, `pivot_suggest`, `rank_relations`,
`sensitive_paths`, `wayback_fetch`, `wayback_harvest`.

A shim is: `importlib.util.spec_from_file_location(__name__, <canonical>)` → exec → `sys.modules`
swap. If you move a directory, fix the shims' relative depth.

## Resolution (self-contained)

`scripts/backend/backend.py` resolves the backend to **SELF** — `intel_engine/` in this repo (via
`in-repo (self-contained)`). An explicit `$INTEL_HOME` still overrides for a shared external KB.
The pipeline (`intel_engine/tools/intel.py`) imports `pivot_extract` through the
`scripts/webpivot/pivot_extract.py` shim (resolved one level up from `intel_engine/`); the
canonical collector is `intel_engine/WebPivot/tools/pivot_extract.py`.

## Re-syncing from the upstream engine

Upstream is the `intelligence_assist` working tree (GitHub `0xdefh/Intelligence-AS`). The sync is
**one-way** — cti-expert never writes back.

**It is a three-way merge, not a copy.** "Copy, then re-apply the 5 shims" is not enough: the
vendored tree also carries a dozen files cti-expert has patched on purpose, and overwriting them
fails *silently* — the collectors still run, they just stop finding things. Known examples:
`wp_common` walks one extra level up for `.env` (cti-expert nests deeper; upstream's version
resolves every API key to empty); `pivot_extract` has reverse-WHOIS ON with
`--no-whois-reverse` as the opt-out (upstream made it opt-in); `harness/orchestrator.py`
`_skill()` tries `SKILL.reference.md` before `SKILL.md` (the vendoring renames every component's
`SKILL.md`, so upstream's bare `open(.../SKILL.md)` raises FileNotFoundError on the first Collect
phase and takes `/harness` down entirely — mirror `agents._load_skill`'s reference-first fallback);
and `IntelReport/scripts/render_report.py` `pick_fonts()` pins `Times New Roman`/`Arial`/`Consolas`
as the win32 defaults (Windows has no `fc-list`, so upstream's `Latin Modern` default — which lacks
Vietnamese coverage — silently tofus every VN PDF there).

Find the divergence mechanically rather than from memory — **blob identity against all upstream
history**. Index every `(blob, path)` pair upstream has ever committed, plus its current working
tree; then hash each vendored file. Three outcomes:

| vendored blob | meaning | action |
|---|---|---|
| matches some upstream blob for that path | pure vendored copy | safe to overwrite |
| path exists upstream, blob matches none | **cti-expert local patch** | 3-way merge |
| path does not exist upstream | **cti-expert-only** | must survive; never `rsync --delete` |

For each local patch, pick the merge base by minimum diff distance over that path's historical
blobs, then `git merge-file <ours> <base> <theirs>`. Expect duplicate `@tool`/`def` blocks where
the base predates a tool that both sides then added — check with
`grep -oE '^async def [a-z_]+' … | sort | uniq -d`.

Also: exclude `.venv`, `__pycache__`, `cases/`, `knowledge/`, `MEMORY/`, `.env`; rename each
component's `SKILL.md` to `SKILL.reference.md` (the repo has exactly one `SKILL.md`); and note that
**zsh does not word-split unquoted parameters** — an `rsync $EXCLUDES` built as one string silently
excludes nothing and will drag a 500 MB `.venv` into the tree.

Then wire per RULE 3 (new `@tool`s → `DISPATCH` + the CLAUDE.md count) and verify with
`bash scripts/audit.sh`, the repo-root `tests/`, the vendored `intel_engine/tests/`, a
`tools/list` against `intel_engine/harness/mcp_server.py`, and
`python3 scripts/backend/intel.py pipeline open …`.
