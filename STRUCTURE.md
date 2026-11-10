# cti-expert — repository structure & anti-drift rules

cti-expert is **one skill, two layers**: a **broad collector** (cti-expert's own tools) plus the
**vendored `intel_engine` engine** (pipeline chains + deeper pivoting logic). This file is
the map, and the rules that keep the two from drifting.

## Top-level layout

**cti-expert's own** (the collector + presentation + docs):
- `SKILL.md` — the single skill entrypoint (there is exactly one SKILL.md in the repo)
- `scripts/` — collectors (`scripts/webpivot/`), the backend dispatcher (`scripts/backend/`), report generators,
  `register.sh` (Claude Code) + `register_agents.py` (`/cti` for every other coding agent)
- `scripts/cti_report_sections.py` (shared report-section spec + anti-inflation check), `scripts/references/report_metrics.json`, `email_spoofability.json`, `stealer_triage.json`
- `scripts/osint/references/phone_osint.json`, `exposure_executive.json`, `agentic_signatures.json`
- `scripts/osint/references/dork_builder.json`, `username_enum.json`
- `techniques/`, `handbook/`, `connectors/`, `analysis/`, `validation/`, `experience/`, `guides/`,
  `workflows/`, `engine/` (case data-model design docs — distinct from the `intel_engine/` pipeline),
  `assets/`, `output/`
- `tests/` — zero-dep regression tests (`python3 tests/test_*.py`, no pytest needed): RULE 5
  indicator classification + the shared collector core (`collect_core`). **Local-only:** gitignored,
  never pushed (same for `intel_engine/tests/`, `intel_engine/tools/eval/` and every `test_*.py`)
- `scripts/audit.sh` — structural drift + leak gate (DISPATCH resolves, shims are re-exports and
  match the table below, collection HTTP goes through `wp_http` / `wp_ua` with exceptions listed in
  `scripts/references/http_allowlist.json`, `@tool` count matches CLAUDE.md, compile, tests, every
  registered hook resolves);
  `scripts/install-hooks.sh` wires `scripts/leakcheck.sh` as a pre-commit hook. Both run in CI via
  `.github/workflows/audit.yml`
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
- `intel_engine/tools/masked_hint.py` (masked recovery-hint correlation), `report_sections.py` (analyst report block + sources-checked), `house_report_sections.py` (house-report renderers for the report block), `tools/kb/references/masked_hint.json`, `report_sections.json`
- `intel_engine/WebPivot/` — engine collector helpers (`wp_*`) + de-dup shims (see below)
- `intel_engine/WebPivot/tools/wp_ua.py` — the one User-Agent source (`DEFAULT_UA`, `UA_POOL` from `WebPivot/references/fetch_profile.json → ua_pool`; side-effect free, re-exported by `wp_common`); the service-required exceptions are listed in `fetch_profile.json → ua_exceptions`
- `intel_engine/WebPivot/tools/wp_http.py` — the one transport for API calls (`request()` → `Response`, never raises; opt-in retry policy in `WebPivot/references/http_client.json`). `wp_net.fetch` stays the target-page fetcher
- `intel_engine/WebPivot/tools/wp_pgp.py` (keyless PGP keyserver pivot), `wp_container.py` (public container-registry OSINT), `wp_takedown.py` (RDAP hold / DNS sinkhole + successor leads), `WebPivot/references/pgp.json`, `container_registry.json`, `takedown.json`
- `intel_engine/WebPivot/tools/wp_corp.py` (global company/officer registry pivot), `wp_google.py` (GHunt wrapper: Google-account leads), `wp_telegram.py` (Telegram phone/username lookup, confirm-gated), `wp_revimg.py` (reverse-image search); `WebPivot/references/corp_registry.json`, `google_account.json`, `telegram.json`, `reverse_image.json`
- `intel_engine/BinaryPivot/tools/bp_git.py` (embedded .git + module identifiers in leaked archives/dirs), `bp_archive_time.py` (archive timestamp forensics, packer UTC offset), `bp_keys.py` (keys/certs deduped by SPKI SHA-256), `intel_engine/BinaryPivot/references/leak_forensics.json`
- `intel_engine/IntelGraph|IntelReport|BinaryPivot|IntelAnalysis|Engage|IntelHarness|IntelShare/` —
  render, analysis, engagement and dissemination skills (their `SKILL.reference.md` are docs, not skill entrypoints —
  the repo has exactly one `SKILL.md`, at the root)
- `intel_engine/tests/` — the vendored engine's own gates (`test_tool_registry` RULE 2,
  `test_tool_gate` submission approval, `test_engage`, …); `run_eval.py` puts both this
  directory and the repo-root `tests/` on the path so neither suite silently stops running.
  Local-only, like `tests/`
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
