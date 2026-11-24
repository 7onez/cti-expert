# Case pipeline detail — origin sweep, archive harvest, deep-pipeline handoff

The full text behind the summaries in `SKILL.md` §2 (AEAD Case Lifecycle); read it when a `/case` or `/cti` run reaches the origin-IP sweep, the archive harvest or the handoff to the deep pipeline.

## Historical origin-IP sweep

> **Historical origin-IP sweep (automatic, offline join).** Every A/AAAA record any source ever saw
> for a collected host or subdomain — CIRCL/HackerTarget passive DNS, SecurityTrails history,
> Validin, urlscan's hostname index, Webamon servers, passive-SSL cert→IP, keyless urlscan scans — is
> merged into one dated `origin_history` block on the domain pivot and classified: **CDN / WAF /
> DDoS-protection edge** (CIDR index *plus* the ASN / org the source named: Cloudflare, Akamai,
> Imperva, Sucuri …), **parking**, **bogon**, **ambiguous** (DDoS-Guard / StackPath — they sell both
> proxying and servers), or **origin** (customer Google Cloud VMs included). The loop and the harness
> then collect each **origin** and **ambiguous** IP as an IPPivot seed (ASN + abuse contact,
> ports/banners, PTR, self-hosted MX, passive-SSL certificates, co-hosted domains — keyless
> reverse-IP under `--free-only`). Rails: an address last seen **before the current registration**
> is the previous owner's (lead, never collected); the **current co-tenants** of a
> `historical`/`undated` origin or of an `ambiguous` network are held as dated leads, never seeds or
> KB edges; a recent origin's co-tenants pass the usual shared-hosting guard and stay
> neighbour-rung. The box's own IP lookup is checked again after collection, so an edge or
> DDoS-Guard network the history could not name still holds its tenants. On a **cloud/VPS** network
> (Google Cloud, DigitalOcean, OVH, Hetzner, Vultr …) up to **10** co-tenants are queued and linked
> automatically — counted the same way by the frontier and the KB, with the reverse index's own total
> so a truncated list never hides a big shared host; above that **every** domain goes to
> approval (harness: a `proposal.json` item — auto-approved in `/cti`'s default auto mode, the
> analyst's via `case_approve` under `--review`; loop: an *APPROVAL REQUIRED* gap and
> `/approve-cohost`) and nothing is collected or linked until approved. Approval is **per domain**
> (a shared-platform tenant such as `kit.pages.dev` counts on its own, never the whole platform) and
> is the evidence: exactly the approved sites are seeded, linked, and may bind the cluster with the
> case host past both the shared-hosting bound and the clustering cap of 8 domains per indicator;
> automatically linked sites keep that cap. Every unapproved site on the box stays a held lead,
> never automatic. Every held origin-sweep lead lists all its domains. Without the CDN range
> cache an address is `undetermined` and never collected.
> Caps and the edge/ambiguous/parking lists live in
> `intel_engine/WebPivot/references/origin_history.json`; the assessment renders a *Historical
> Origin IPs* table (with tenancy overlap for shared boxes), the house report a *Historical origin
> hosting* table, and `/origin-history <case>` prints the dated history on demand.

## Archive IOC harvest

> **Archive IOC harvest runs by default too.** For domain/URL targets the Acquire phase also runs
> `wayback_harvest.py <domain> --indicators` (add `--urlscan` when `URLSCAN_API_KEY` is set),
> harvesting **emails, phones, crypto wallets, tracking/verification IDs, SaaS-operator IDs, and
> socials from the *entire* Wayback history** — not just the live page — with first-seen/last-seen
> per selector. It writes case-schema `indicators[]` to `<case>/raw/harvest.indicators.json`, which
> merge into the case and flow into the **auto-saved IOC bundle** at Deliver. This is the step that
> recovers selectors a network later scrubbed — across the whole snapshot corpus, not just the live page.
> Passive by construction — only web.archive.org (+ urlscan.io if keyed), never the target.

## Deep-pipeline handoff steps

> 1. Write each host's already-collected pivot JSON to `$SKILL_DIR/intel_engine/cases/<CASE-ID>/raw/<host>.json`
>    and the host list to an absolute `<CASE-ID>-seeds.txt`, both **anchored at the engine root**
>    (`ROOT=$SKILL_DIR/intel_engine`) — never a CWD-relative path.
> 2. `intel.py pipeline open <CASE-ID> <abs-seeds.txt> --no-collect` — `--no-collect` skips the live
>    fetch and runs the *rest of the existing pipeline* over the raw you just wrote: ingest →
>    prior-overlap (`/recall`) → risk (`/risk`) → shared cluster seeds → `clusters.json` →
>    `case_graph.json` → ICD-203 `assessment.md`. Every step is a KB/local read: zero egress, zero
>    metered calls.
> 3. In a full `/cti` (not `--quick`), run `intel.py enrich <CASE-ID>` next. It reads stored
>    raw pivots, performs matching third-party identity/OSINT lookups, checkpoints results
>    in `cases/<CASE-ID>/enrichment/` (including `index.json`), and prints recorded credit
>    units per leg. `--free-only`/`no_spend` leave metered leads OPEN for a later full run;
>    passive posture forbids direct target contact, not third-party metered lookups. This
>    phase has third-party egress and can spend credits, unlike the reuse-mode handoff.

## Persisted case location

> **The persisted case lands at `$SKILL_DIR/intel_engine/cases/<CASE-ID>/` — `raw/`, `shared.txt`,
> `clusters.json`, `case_graph.json`, `assessment.md` — NOT the current working directory**, and it
> is a COMPLETE case that `intel.py pipeline status <CASE-ID>` accepts (not the partial dir a hand-rolled
> op sequence would leave). `<CASE-ID>` is the same id as the report filenames (mint
> `CASE-YYYYMMDD-NN` when none is given). Its cluster/risk/assessment fold back into the auto-saved
> report. Tier 3 (stateless), or a person/username/phone target with no host seeds → the handoff is
> **skipped silently** and the tier noted; broad collection + report are unaffected.

## Self-contained & self-resolving

> **Self-contained & self-resolving.** `/backend` resolves to **SELF** (in-repo) — no external
> setup. The bundled installer (`scripts/install.{sh,ps1}`) provisions the deep layer; or by hand: `uv venv && uv pip install -r requirements.txt` (harness SDK/MCP + IntelGraph
> renderers; the collector + KB + deterministic pipeline are stdlib and need none). An explicit
> `$INTEL_HOME` still overrides for a shared external KB. Full architecture, the op map, and the
> evidence-envelope schema: [`connectors/intel-backend.md`](../connectors/intel-backend.md).
