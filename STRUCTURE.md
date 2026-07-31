# cti-expert — repository structure & anti-drift rules

cti-expert is **one skill, two layers**: a **broad collector** (cti-expert's own tools) plus the
**vendored `intel_engine` engine** (pipeline chains + deeper pivoting logic). This file is
the map, and the rules that keep the two from drifting.

## Top-level layout

**cti-expert's own** (the collector + presentation + docs):
- `SKILL.md` — the single skill entrypoint (there is exactly one SKILL.md in the repo)
- `scripts/` — collectors (`scripts/webpivot/`), the backend dispatcher (`scripts/backend/`), report generators
- `techniques/`, `handbook/`, `connectors/`, `analysis/`, `validation/`, `experience/`, `guides/`,
  `workflows/`, `engine/` (design docs), `assets/`, `codex/`, `output/`
- `requirements.txt` — deps for the vendored deep layer (installed into `.venv`)

**Vendored engine — one subtree** (`intel_engine/`, copied one-way from the `intel_engine`
archive; that archive is **read-only**, cti-expert never writes back to it):
- `intel_engine/harness/` — the pipeline brain (`cli.py`, `orchestrator.py`, `mcp_server.py`)
- `intel_engine/tools/` — `intel.py` (deterministic pipeline), `kb/*` (KB + correlation), `cert_overlap`, `case_store`, …
- `intel_engine/WebPivot/` — engine collector helpers (`wp_*`) + de-dup shims (see below)
- `intel_engine/IntelGraph|IntelReport|BinaryPivot|IntelAnalysis/` — render + analysis skills (their `SKILL.reference.md` are docs, not skill entrypoints)
- `intel_engine/knowledge/` + `intel_engine/cases/` — **local runtime data, gitignored** (a fresh KB; the old data stays in the archive)

## Anti-drift rule — single source per collector (do NOT create a second copy)

Five collectors exist in both layers historically. Each now has **one canonical file** and, where
both import paths must keep working, a **9-line re-export shim** (Windows-safe; no symlinks). Never
turn a shim back into a real copy — edit the canonical:

| collector | canonical (edit here) | shim (do not edit) |
|---|---|---|
| `pivot_extract`, `cdn_ranges`, `graph_build`, `wayback_ga` | `scripts/webpivot/` | `intel_engine/WebPivot/tools/` |
| `whois_enrich` | `intel_engine/WebPivot/tools/` | `scripts/webpivot/` |

A shim is: `importlib.util.spec_from_file_location(__name__, <canonical>)` → exec → `sys.modules`
swap. If you move a directory, fix the shims' relative depth.

## Resolution (self-contained)

`scripts/backend/backend.py` resolves the backend to **SELF** — `intel_engine/` in this repo (via
`in-repo (self-contained)`). An explicit `$INTEL_HOME` still overrides for a shared external KB.
The pipeline (`intel_engine/tools/intel.py`) drives cti-expert's own
`scripts/webpivot/pivot_extract.py` collector (resolved one level up from `intel_engine/`).

## Re-syncing from the archive

To pull engine updates from `intel_engine`: copy into `intel_engine/` (code only, never
`knowledge/`/`cases/`), then re-apply the 5 shims so no duplicate collector is reintroduced.
Verify with `bash scripts/smoke-test.sh` + `python3 scripts/backend/intel.py pipeline open …`.
