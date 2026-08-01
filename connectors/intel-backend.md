# Intelligence Backend Connector (now vendored in-repo)

> **UPDATE — the engine is now vendored INTO cti-expert (one self-contained skill).**
> The `intel_engine` code (harness/pipeline, KB tools, correlation/assessment, IntelGraph/
> IntelReport/BinaryPivot/IntelAnalysis, WebPivot helpers) lives under **`intel_engine/`** — one
> vendored subtree (`intel_engine/harness/`, `intel_engine/tools/`, `intel_engine/WebPivot/`,
> `intel_engine/{IntelGraph,IntelReport,BinaryPivot,IntelAnalysis}/`), with a
> **fresh local `intel_engine/knowledge/` + `intel_engine/cases/`**. `backend.py` resolves to **SELF** ("in-repo /
> self-contained"), and the pipeline drives cti-expert's own `scripts/webpivot/pivot_extract.py`.
> The external `intel_engine` folder is treated as a **read-only archive** — cti-expert
> never writes to it. The three-tier / `$INTEL_HOME` machinery below is retained for portability
> (an explicit `$INTEL_HOME` still overrides self), but the default is now in-repo.

## Overview

CTI Expert is a **portable analyst skill** that now **vendors** the `intel_engine` OSINT
harness  in-repo, so a single skill carries what a stateless
skill otherwise cannot:

- a **persistent knowledge base** (`knowledge/` — operators, entities, relationships,
  archived evidence, calibration, analyst profile);
- **versioned cases** (`cases/` + `case_store.py`) with cross-case provenance;
- **cross-case correlation** — *"have I seen this operator/wallet/tracker before?"*;
- a **typed MCP server** (`intel-harness`) exposing collection + correlation tools;
- the **BinaryPivot** skill (APK/exe IOC extraction), which CTI Expert otherwise lacks.

**Design rule — the engine is the single source of truth; CTI Expert is a client.** When
the engine is present, CTI Expert *reads and writes it* but never stores case data in its
own repo. When the engine is absent, CTI Expert degrades to its normal stateless behavior.
Portability is never broken: in Codex/ChatGPT you simply get the stateless tier.

> **OPSEC.** All case data (operator names, domains, IPs, wallets, IDs, hashes, case IDs)
> lives only under `$INTEL_HOME` in the git-ignored `cases/` / `knowledge/` / `MEMORY/`.
> Never write case data into the CTI Expert repo or this connector. Use placeholders in
> examples (`example.com`, `G-XXXXXXXXXX`, `CASE-0001`).

---

## 1. Resolve `$INTEL_HOME` (once per session)

`$INTEL_HOME` = the root of the `intel_engine` repo (the directory containing
`harness/`, `knowledge/`, `cases/`, and `.mcp.json`). Resolve in this order and cache:

1. **Env var** — `$INTEL_HOME` if set (see `.env.example`).
2. **`.mcp.json`** — if the current project exposes an `intel` MCP server, its `command`
   (`./harness/mcp-server`) locates the repo root.
3. **Sibling path** — a `intel_engine/` directory beside `$SKILL_DIR` or beside the
   CTI Expert repo (both commonly live under one dev folder).
4. **Symlink** — Claude Code installs the sibling skills as symlinks under
   `~/.claude/skills/{WebPivot,IntelHarness,…}`; follow one to its target's parent.

If none resolve, the engine is absent → operate at **Tier 3** (below).

This whole cascade is automated by **`scripts/backend/backend.py`** (the `/backend`
command): `backend.py` prints the tier line, `backend.py check` shows every candidate
tried, `backend.py path` prints just the resolved root (use it to locate the engine for
`/kb` and `/recall`), and `backend.py env` emits `INTEL_HOME=<path>` for `eval`. It is
stdlib-only and anchors to the skill install location, so it resolves the same engine
regardless of the current working directory.

---

## 2. Three-tier binding (graceful degradation)

Detect the strongest available tier once, then use it for the whole session:

| Tier | Condition | How CTI Expert talks to the engine |
|------|-----------|-------------------------------------|
| **1 — MCP** | `intel-harness` MCP server connected | Call the **typed MCP tools** directly (§4). Preferred: typed, permission-gated, no bash quoting. |
| **2 — CLI** | `$INTEL_HOME` present, no MCP | Shell to `python3 $INTEL_HOME/harness/cli.py …` and `python3 $INTEL_HOME/tools/kb/*.py …` (§5). Same code, same KB. |
| **3 — Stateless** | neither present | Today's behavior — the AEAD lifecycle runs entirely from `SKILL.md`, no persistence. Codex/ChatGPT default. |

Never fail because a higher tier is missing — **downgrade silently and note the tier once**
in the run header (e.g. *"Intel backend: Tier 1 (MCP)"* / *"Tier 3 (stateless — no engine)"*).

---

## 3. The evidence envelope (the interop contract)

CTI Expert and the engine already share one JSON shape — **verified by round-trip**
(cti-expert `scripts/webpivot/pivot_extract.py` → engine `tools/kb/ingest_webpivot.py`,
exit 0, entities + evidence + edges created). No conversion layer is needed.

```jsonc
{
  "meta":      { "source", "final_url", "host", "archived_via_wayback", "fetched_with" },
  "artifacts": { /* the operator-clustering identifiers — see table below */ },
  "pivots":    [ { "kind", "value", "confidence", "note", "queries":[…] } ]
}
```

- **`artifacts.*`** is what the KB indexes. `ingest_webpivot.py` reads it to build typed
  **entities** (domain, indicator), **facts** on those entities, and **edges**.
- **`meta` + the whole blob** is archived verbatim to
  `knowledge/evidence/webpivot/<host>/<date>.json` — **lossless**: nothing is ever dropped
  from the record, even keys the indexer doesn't promote.
- **`pivots[]`** is CTI Expert's ranked-query presentation layer. The KB **ignores it** by
  design (pivots are derived from artifacts) — so it never needs to match the engine.

### Which `artifacts.*` keys cluster today

| Promoted → entities / facts / edges ✓ | Archived only — not yet clustered ⚠️ |
|---|---|
| `title`, `tech_fingerprint`, `trackers` (GA/GTM), `favicon`, `verifications`, `saas_ids`, `crypto` (wallets), `emails`, `socials`, `inline_style_sha256` → css_hash, `dom_skeleton_sha1`, `wp_themes`, `html_comments` | `phones`, `inline_script_sha256`, `third_party_hosts`, `wp_plugins` |

Network-side keys from CTI Expert's `--whois` / ip-pivot enrichment also cluster:
`co_hosted_domains`, `urlscan_cotenants`, `ptr`, `ports`, `services`, `whois`, `ipinfo`,
`mail`, `git_servers`.

> **Compatibility note (4 archive-but-don't-cluster keys).** `phones`,
> `inline_script_sha256`, `third_party_hosts`, and `wp_plugins` are captured and archived
> but do **not** yet create entities/edges, so they don't drive cross-case clustering. All
> are preserved in the evidence blob and can be promoted later by extending the key map in
> `$INTEL_HOME/tools/kb/ingest_webpivot.py` (~4–6 lines each, mirroring the `emails` /
> `wp_themes` handlers). Until then, treat these four as evidence, not as cluster signals.

---

## 4. Tier 1 — typed MCP tools (`intel-harness`)

When connected, prefer these over shelling out. Grouped by AEAD phase:

**Acquire (collect):** `pivot_extract`, `fallback_probe`
**Enrich (correlate):** `kb_ingest`, `kb_cluster`, `kb_entity`, `kb_query_shared`,
`risk_signals`, `reverse_whois`, `cert_overlap`, `reference_check`, `reference_add`,
`which_cases`, `domain_verdict`, `api_usage`
**Deliver (render):** `render_diagram`, `render_report`

Full MCP tool ids are namespaced (`mcp__collect__pivot_extract`,
`mcp__analyze__kb_cluster`, …). CTI Expert may also keep using its own
`scripts/webpivot/*` collectors — their output is a valid `kb_ingest` input (§3).

> **MCP subset vs. full CLI parity.** The MCP server exposes ~16 curated, permission-gated
> tools (the ones above). The Tier-2 dispatcher (§5) reaches **every** standalone engine
> CLI (~39 ops) — `cdn-ranges`, `graph-build`, `hypothesize`, `calibration`, `evidence-report`,
> `case-store`, `cost`, the deterministic `pipeline`, and more. So when you need a tool that
> isn't in the MCP list, drop to Tier 2 — same engine, same KB. Run `intel.py list` for the
> live map.

**Enabling Tier 1 ("the server").** `intel.py mcp` prints the `.mcp.json` that registers the
engine's `intel` MCP server, resolved to an absolute `harness/mcp-server` path;
`intel.py mcp --write` drops it into the current project (gitignored — machine-specific).
Restart the client to pick it up.

---

## 5. Tier 2 — CLI fallback (no MCP)

Same engine, same KB. The **unified dispatcher `scripts/backend/intel.py`** (in the
CTI Expert repo) is the one entry point: it resolves `$INTEL_HOME` via `backend.py`,
runs the right engine script **from the engine root** (so `knowledge/`, `WebPivot/tools/…`
resolve), injects `--kb knowledge` where needed, and forwards the rest of the args
verbatim. Backend absent → it prints one note and exits 3. `intel.py list` prints the
op → script map; `intel.py --dry-run <op> …` prints the exact command without running it.

> **Shared collector core.** The deterministic `pipeline` (`intel.py open …`) and the MCP
> harness now delegate to **one** host-collection routine (`intel_engine/tools/collect_core.py`),
> so both inherit the same cache-reuse, egress policy, Cloudflare retry and DOM capture. Two
> consequences for `open`: a seed already collected in **any** case is **reused by default** (pass
> `--force` to re-collect), and evidence archiving (Wayback SPN + manifest) stays **opt-in** via
> `--archive` so the pipeline's cost profile is unchanged unless you ask for it. The MCP harness
> still archives by default.

```bash
# Every op maps 1:1 to a Tier-1 MCP tool — same engine underneath.
uv run scripts/backend/intel.py kb --stats                    # KB overview
uv run scripts/backend/intel.py kb --entity example.com       # facts + edges (kb_entity)
uv run scripts/backend/intel.py kb --cluster example.com      # shared-indicator peers (kb_cluster)
uv run scripts/backend/intel.py kb --shared --min 2           # whole-KB view (kb_query_shared)
uv run scripts/backend/intel.py recall scam-site.top          # "seen before?" (query.py --entity)
uv run scripts/backend/intel.py risk --case CASE-0001         # NRD/BPH/money-trail (risk_signals)
uv run scripts/backend/intel.py reverse-whois --reverse-email owner@x.com --search-type historic --json
uv run scripts/backend/intel.py cert-overlap a.example b.example    # TLS/SAN verdict (cert_overlap)
uv run scripts/backend/intel.py reference check favicon:123    # BENIGN/SIGNAL/UNKNOWN (reference_check)
uv run scripts/backend/intel.py operators list -v             # confirmed-operator ledger (add|list|find)
uv run scripts/backend/intel.py convergence status CASE-0001  # stop-condition (snapshot|status)
uv run scripts/backend/intel.py clean                         # dry-run hygiene sweep (--apply to write)
uv run scripts/backend/intel.py ingest <cti_pivot.json> […]   # round-trip a pivot_extract into the KB

# Whole-case orchestration (IntelHarness) — no LLM key needed for status
uv run scripts/backend/intel.py harness open     CASE-0001 https://a.example https://b.example
uv run scripts/backend/intel.py harness continue CASE-0001 --depth 4 https://a.example
uv run scripts/backend/intel.py harness status   [CASE-0001]

# Rendering hand-offs (IntelGraph / IntelReport)
uv run scripts/backend/intel.py graph  case_graph.json out --legend    # → out.png/.svg (render_diagram)
uv run scripts/backend/intel.py report assessment.md out --pdf --docx  # → out.pdf/.docx (render_report)

# BinaryPivot — the file half of a scam funnel (see §7)
uv run scripts/backend/intel.py binary ./trader.apk --leads
```

The bare `python3 $INTEL_HOME/tools/kb/*.py …` forms still work (the dispatcher just runs
them for you); reach for them only when debugging the engine directly.

### 5.1 Cases live engine-side — cti-expert reads them

Whole-case runs (`pipeline`, `harness`) and their outputs live under `$INTEL_HOME/cases/<case>/`
(`raw/`, `whois/`, `shared.txt`, `assessment.md`, `report/`) — the **engine is the source of
truth**. See them from cti-expert with `intel.py cases` (list), `intel.py cases <name>` (file
tree), `intel.py cases --path [name]`. **cti-expert never modifies the engine folder** — it
resolves and reads it; any write into `$INTEL_HOME` happens only when the engine itself runs.

---

## 6. Where the engine hooks into the AEAD lifecycle

The backend attaches at the four `SKILL.md` phases. Each hook is a no-op at Tier 3.

| Phase | Engine hook (Tier 1/2) | Payoff |
|-------|------------------------|--------|
| **Acquire** | After `pivot_extract`, check each seed against prior cases — Tier 1: `which_cases` / `domain_verdict` (MCP); Tier 2: `query.py --entity <seed>` (those two tools are MCP-only) — then `kb_ingest` the evidence | *"Have I seen this operator before?"* + persistent evidence archive |
| **Enrich** | `kb_cluster` / `kb_entity` / `cert_overlap` / `kb_query_shared` correlate against the **whole KB**, not just this session (T2: `intel.py kb --cluster/--entity/--shared`, `intel.py cert-overlap`). Screen every candidate link with `reference check` (kill BENIGN false positives), and `reverse-whois` a leaked registrant to widen the cluster | The recursive pivot loop gains historical seeds + false-positive control |
| **Assess** | Before writing `/threat-model` (ACH) or `/report`, pull the analyst's own priors to calibrate confidence — `intel.py operators list` (who's already attributed, at what confidence), `intel.py risk --case <id>` (NRD/BPH/money-trail), and read `$INTEL_HOME/knowledge/{calibration.jsonl,analyst_profile.md}`. Weigh evidence against these, not from scratch | Judgment layer (IntelAnalysis) calibrated on your own past cases |
| **Deliver** | Write the versioned `Assessment` via `case_store.py` into `cases/`; register in `report_registry.jsonl`. Reports still render via CTI Expert generators **or** hand off to `intel.py graph` (figures) + `intel.py report` (PDF/DOCX house style) | Continuous, versioned case history + publication-quality deliverables |

The engine's `Assessment` schema (`bluf`, `cluster[]`, `attribution_level` ∈
{same-kit, same-operator, same-actor, inconclusive}, `confidence`, `evidence[]`, `gaps[]`,
`next_pivots[]`) is exactly what CTI Expert's `/threat-model` (ACH) and `/report` already
produce in prose — so Deliver is a structuring step, not new analysis.

---

## 7. BinaryPivot (fills a CTI Expert gap)

CTI Expert has no binary-analysis command. When the engine is present, `/binary [file|url]`
shells to `$INTEL_HOME/BinaryPivot` (APK signing-cert SHA-256, package name/permissions,
embedded C2/backend hosts, Firebase/S3 tenants, wallets, Telegram/WhatsApp handles). Its
output is **WebPivot-shaped**, so it flows through the same `kb_ingest` → the scam **app**
clusters with the scam **web** infrastructure in one graph. Tier 3: note as *"run locally
where the engine is available."*

---

## 8. Quick verification

```bash
# Round-trip: CTI Expert collect → engine KB (throwaway KB, benign domain)
python3 $SKILL_DIR/scripts/webpivot/pivot_extract.py https://example.com \
        --no-whois --no-enrich -o /tmp/cti_pivot.json
python3 $INTEL_HOME/tools/kb/ingest_webpivot.py --kb /tmp/kb_test /tmp/cti_pivot.json
find /tmp/kb_test -type f        # → entities/ + evidence/ + relationships/edges.jsonl
```

A clean exit with entities + an `evidence/webpivot/<host>/<date>.json` archive confirms the
binding works end-to-end.
