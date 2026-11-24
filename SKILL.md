---
name: cti-expert
description: "Cyber threat intelligence and OSINT analysis toolkit. Runs structured investigations and delivers analyst-grade intelligence products with sourced, trust-scored findings. Use for OSINT and CTI cases, digital-footprint and exposure review, domain/subdomain/DNS/certificate recon, web-infrastructure pivoting (favicon hashes, tracker IDs, TLS certs, phishing-kit fingerprinting, campaign clustering), username/email/phone enumeration, breach and infostealer-log triage, image forensics, geolocation, crypto-wallet and IBAN/bank-account tracing, darknet search, M365/Azure and SaaS tenant recon, China/Sinophone recon (ICP filings, PRC corporate registries, Baidu/FOFA/Quake/ZoomEye), vulnerability and ransomware lookup, threat modeling, PII redaction, and structured reporting. Commands include /case, /sweep, /query, /webpivot, /username, /phone, /email-deep, /breach-deep, /icp, /cn-corp, /iban, /stealer-log, /exposure, /threat-model, /report, /brief, /redact, /apikeys."
version: "2.12"
author: "Hieu Ngo - chongluadao.vn"
---

# CTI Expert

Cyber threat intelligence and open-source intelligence skill. Turns Claude into a trained CTI/OSINT analyst. Generates precision search queries, interprets public data, builds case timelines, and delivers structured intelligence products — keyless by default; optional API keys add depth.

> **Runs anywhere.** Works in **Claude Code** (Desktop & CLI) and in **OpenAI Codex / ChatGPT** and other `AGENTS.md`-aware agents — see [`AGENTS.md`](AGENTS.md) for the cross-agent runtime contract. Throughout this file, **`$SKILL_DIR`** = the directory containing this `SKILL.md` (Claude Code: `~/.claude/skills/cti-expert`; Codex/manual clone: the repo you are working in). Resolve it by locating `SKILL.md` — never hard-assume `~/.claude`. Detect the OS once (Windows/macOS/Linux) and prefer **uv** for all Python — see §Tool Auto-Install Policy.

Collection method: `agent-browser` when available (JavaScript-heavy sites, infinite-scroll, screenshot evidence), with automatic fallback to web search / web fetch / direct URL fetch. Tool limitations are logged as collection gaps — never as case blockers.

---

## 1. Quick Start

```bash
# Full autonomous case — runs every applicable technique
/case target.com

# Guided flow for first-time investigators
/flow person

# Summary of what's been found so far
/brief
```

Append `--yolo` to any command to skip all interactive prompts and confirmations. The analyst makes every decision autonomously.

---

## 2. AEAD Case Lifecycle

Every investigation follows four phases:

| Phase | What Happens |
|-------|-------------|
| **Acquire** | Collect raw data — `/sweep`, `/query`, `/username`, `/phone`, `/email-deep`, `/breach-deep`, `/subdomain`, `/webpivot` + `/icp` (domain/URL targets), `/dork-sweep` · `/docleak` · `/github-osint`/`/secrets`, `/cn-corp` · `/iban` · `/hash-id` on discovery |
| **Enrich** | **Recursive pivot loop** — the [pivot orchestration engine](engine/pivot-orchestration.md) tracks candidate identifiers hop-by-hop; `/cti` executes each matching enrichment leg and re-enters **verified owner-linked** yields as seeds. Registrant email→`/email-deep` (not a second `/breach-deep` or `/intelx` on the same selector), username→`/username`, name→`/dork-sweep`+`/docleak`, apex→`intelx phonebook`+`/secrets`+`/github-osint` when keyed and allowed. The deterministic pipeline covers infrastructure; the slash-command agent runs the remaining identity/exposure legs and closes each frontier lead with evidence. Never treat a generated query or shared infrastructure as an operator link. Acquire↔Enrich iterate until the applicable frontier is addressed. |
| **Assess** | Score and verify — `/exposure`, `/threat-model`, `/validate`, `/coverage`, `/verify-finding`. Judgments carry **likelihood terms**, coverage gets the **5W1H pass**, attributions get an **ACH matrix** ([`handbook/analytic-standards.md`](handbook/analytic-standards.md)). **If the case has not converged** (frontier still open after the pivot loop + deterministic pipeline) and posture is active, `/case` **auto-escalates to the `/harness` deepening loop** — keyless-first (the CLI's own model), egress hard-gated on hostile infra; `--no-harness` opts out |
| **Deliver** | Package output — `/report`, `/brief`, `/render`, `/workspace save` — **first ASKS whether to import more evidence from manual investigation** (merged into the report JSON before anything is built), **always auto-saves the base data bundle (.md + .json + .csv + IOC bundle: .stix.json/.txt/.csv/.jsonl), then ASKS which presentation report to render — (a) PDF · (b) DOCX · (c) HTML · (d) all** (both prompts skipped under `--yolo`/guided-auto, which default to HTML). When `CHONGLUADAO_API_KEY` is set, the IOC bundle also attaches CLD's **STIX + MISP indicator feed** as companion artifacts (`cld_api.py feed stix2\|misp --raw` → loadable bundle, not merged into the case graph). **Deep-layer persist (automatic, ZERO extra egress):** when `/backend` is live, `/case` **reuses the pivots it already collected** — never re-fetches — to persist the versioned case at `$SKILL_DIR/intel_engine/cases/<CASE-ID>/` and correlate it cross-case; see the auto-chain note below. See [`connectors/chongluadao-api.md`](connectors/chongluadao-api.md) |

Run `/progress` at any point to see which phase you're in and what's pending.

> **Intake before Acquire (`/cti` driver).** `intel.py cti <target>` scopes the case **before any
> collection** (Quarry included): at a terminal it asks the **target class** and **purpose** (the
> `case_scope` fields — classes from `WebPivot/references/intake.json`) and persists the answers to
> `cases/<case>/scope.json`; a case that already has a stated scope is not re-asked. Scripted runs
> (no TTY, `--yes`, `INTEL_NO_PROMPT`, or nested inside a harness phase) never block on input:
> pass `--class <class>` / `--purpose <purpose>`, otherwise the run proceeds on the default
> (`unknown` / `triage`) and prints `[scope] DEFAULTED …`. The summary JSON carries `target_class`.

> **`/case` and web-infra pivoting.** For a **domain or URL** target, `/case` includes
> web-infrastructure pivoting (`/webpivot`) in the Acquire phase. It runs **keyless by default**
> (crt.sh + passive DNS + anonymous urlscan) and **upgrades automatically when premium keys are
> set** via `/apikeys` (Shodan/Censys/FOFA/Hunter.how/DNSLytics/SecurityTrails/urlscan-PRO/WhoisXML). With keys
> the pipeline also: reads the **urlscan Pro hostname lifecycle** (pre-registration NS/A eras on the
> timeline, verdict rows in Appendix B), runs the **MO-neighbour pivot** on the estate's non-CDN origin
> (co-tenants WHOIS-verified; only a registrant join-key ever seeds, same-MO personas render as a
> rung-10 *Related personas* table — `--mask-personas` to aggregate), **measures entitlement**
> (`meta.capability.plans`, per-case `capability_plans.json`; Censys' search is its own probe), and
> fires SecurityTrails DNS-history + DSL reverse-WHOIS, DNSLytics reverse-IP (co-tenancy-filtered),
> a once-per-case Censys cert search, Shodan cert/JARM search and IntelX (loop: `--full` only). Every
> metered leg is `--free-only`/`no_spend`-gated; IntelX selectors, WhoisXML/SecurityTrails reverse-WHOIS terms,
> MO-neighbour origins, DNSLytics reverse-IP and the Censys cert search are bought once per CASE (on-disk memo),
> while per-host legs (urlscan lifecycle, SecurityTrails subdomains/history, Shodan search) stay per host under
> per-case caps. Because
> `/webpivot` can fetch the target directly, for hostile infrastructure it prefers passive capture
> (urlscan/Wayback) — see [`techniques/web-pivot.md`](techniques/web-pivot.md). It is **not** run for
> username/phone/person targets.
>
> **Historical origin-IP sweep (automatic, offline join).** Every A/AAAA record any source ever saw
> for a collected host or subdomain is merged into one dated `origin_history` block, classified
> (CDN / WAF edge, parking, bogon, ambiguous, origin), and each **origin** and **ambiguous** IP is
> collected as an IPPivot seed. Rails: an address last seen **before the current registration**
> is the previous owner's (lead, never collected); the **current co-tenants** of a
> `historical`/`undated` origin or of an `ambiguous` network are held as dated leads, never seeds or
> KB edges; a recent origin's co-tenants pass the usual shared-hosting guard and stay
> neighbour-rung. On a **cloud/VPS** network
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
> never automatic. Without the CDN range cache an address is `undetermined` and never collected.
> Sources, classes, caps and report tables: [`handbook/case-pipeline-detail.md`](handbook/case-pipeline-detail.md#historical-origin-ip-sweep).
>
> **⭐ ChongLuaDao is the first-party premium upgrade.** With `CHONGLUADAO_API_KEY` set
> (`/apikeys set chongluadao <KEY>`), Acquire/Enrich fold CLD's own datasets into `/scam-check`,
> `/threat-check`, `/phone`, `/breach-deep`, `/email-deep`, `/vuln-check` and `/impersonate`, and
> `/cld <target>` is the direct entry point. Your client connects **only to ChongLuaDao, never
> to the target** (provable from `scripts/cld/cld_api.py`); for URL/AI/IP checks CLD does any
> target fetch server-side — the safe first-touch verdict on a live scam funnel before a direct
> pivot. Full catalog + AEAD placement: [`connectors/chongluadao-api.md`](connectors/chongluadao-api.md).
>
> **Archive IOC harvest runs by default too.** For domain/URL targets the Acquire phase also runs
> `wayback_harvest.py <domain> --indicators`, harvesting selectors from the whole Wayback history
> into `<case>/raw/harvest.indicators.json` and on into the auto-saved IOC bundle.
> Passive by construction — only web.archive.org (+ urlscan.io if keyed), never the target.
> Detail: [`handbook/case-pipeline-detail.md`](handbook/case-pipeline-detail.md#archive-ioc-harvest).
>
> **The five v2.6 commands are in the pipeline too — no flags.** `/icp` runs for every
> domain/URL/org target (and an IP's resolved hostname); `/cn-corp`, `/iban` and `/hash-id`
> fire the moment a company name/USCC, payment detail, or hash appears — and all three feed
> their yields **back into the recursive pivot loop** as new seeds, so an ICP licence serial or
> a reused bank account expands the graph like any other node. `/redact` is the exception: it
> is **opt-in** (`--redact`), because a redacted report is a weaker artifact and that should
> always be a deliberate choice. Full trigger table: §Technique Activation Matrix.
> Narrow with `--no-cn`.

> **Two layers, one skill: broad collector → deep pipeline.** cti-expert is the **broad
> collector** — the wide net of Acquire/Enrich commands (`/webpivot`, `/sweep`, `/subdomain`,
> `/icp`, `/username`, `/email-deep`, `/breach-deep`, …) that pull artifacts from anywhere. The
> **`intel_engine` engine is now vendored in-repo under `intel_engine/`** (`intel_engine/harness/`,
> `intel_engine/tools/`, `intel_engine/WebPivot/`, `intel_engine/IntelGraph|IntelReport|BinaryPivot|IntelAnalysis/`)
> and supplies the **pipeline chains + deeper pivoting logic**: a persistent knowledge base (`intel_engine/knowledge/`), versioned cases
> (`cases/`), cross-case correlation, calibrated assessment, and rendering.
>
> **The chain (automatic for `/case`, and it NEVER re-fetches):** broad collection (cti-expert)
> already ran `pivot_extract` per host during Acquire. When `/backend` resolves to Tier 1/2 **and**
> the run produced ≥1 host seed (domain/URL/IP), `/case` hands what it already collected to the
> deterministic pipeline in **reuse mode** (`--no-collect`) — one command, a complete case dir, and
> nothing touches the target again:
>
> The three handoff steps are in [`handbook/case-pipeline-detail.md`](handbook/case-pipeline-detail.md#deep-pipeline-handoff-steps):
> write the collected pivots, run `intel.py pipeline open <CASE-ID> <abs-seeds.txt> --no-collect`
> (zero egress, zero metered calls), then in a full `/cti` run `intel.py enrich <CASE-ID>`
> (third-party egress, may spend credits). Write each host's already-collected pivot JSON to
> `$SKILL_DIR/intel_engine/cases/<CASE-ID>/raw/<host>.json` and the host list to an absolute
> `<CASE-ID>-seeds.txt`, both **anchored at the engine root** (`ROOT=$SKILL_DIR/intel_engine`) —
> never a CWD-relative path.
>
> **The persisted case lands at `$SKILL_DIR/intel_engine/cases/<CASE-ID>/` — NOT the current working
> directory** — as a complete case `intel.py pipeline status <CASE-ID>` accepts, with the same
> `<CASE-ID>` as the report filenames. Tier 3, or a target with no host seeds, skips the handoff
> silently and notes the tier. Detail: [`handbook/case-pipeline-detail.md`](handbook/case-pipeline-detail.md#persisted-case-location).
>
> **A collecting run never starts without the analyst's go-ahead.** `/case`'s handoff stays
> `--no-collect`, and `/cti`'s default engine — the cross-type harness loop (`intel.py cti
> <target>`) — collects live. So **confirm before launching it**: target, case id, rounds,
> spend posture. `intel.py pipeline open` without `--no-collect` re-fetches every seed directly
> (`collect_many` on `https://<host>`; the egress gate at `collect_core.py:169` only fires when
> `hostile` is set, which the `open` path never sets). A blind auto-collect would therefore be a
> **second live round** against infra `/case` may have just classified hostile/no-touch.
> Collect only for a **fresh** case with no prior collection, after setting the egress posture
> (`/scope`, `/cti-proxy`, or `--passive`). `--passive` always takes the pipeline path (no chase
> loop, no live contact), never the harness.
>
> **Quarry, when enabled, runs before any vendor spend.** A configured Quarry
> (`QUARRY_MCP_URL` + `QUARRY_API_KEY`, `QUARRY_ENABLED=on|off|ask`) holds the vendor answers this
> skill would otherwise pay for again. `ask` (the default) asks once per case and remembers the
> answer; `--quarry` / `--no-quarry` override it. The driver reuses a finished scan for free, or
> starts one and **waits for it with no time limit** — hours or days on a large estate, resuming if interrupted —
> before the harness loop or pipeline collects. A no-spend or no-contact case reuses only.
> Imported rows go through the rung table: owner links become edges, co-tenancy and kit matches
> become facts only. Ask the user before the first scan of a case. Every bridge session lists
> Quarry's MCP tools first and re-lists on `tools/list_changed`; `intel.py quarry tools` reloads the
> list on demand (read-only) and flags any tool the bridge calls that Quarry no longer exposes.
>
> **`/harness` deepening AUTO-ESCALATES on non-convergence** (`--no-harness` opts out). After the
> `--no-collect` pipeline, if the case has **not converged** — `intel.py convergence <case>`
> reports status ≠ `converged` (`cold` = no free leads left = exhausted), or `intel.py frontier
> <case>` still lists open leads
> **and** posture is active (not `--passive`, infra not classified hostile/no-touch) — `/case` runs
> the harness Collect→Correlate→Assess loop to close the gap. Egress stays safe **by construction**:
> the harness's own `audit.py` PreToolUse gate turns `hostile=True` into a **hard denial** of
> outbound collection ([`harness/README.md`](intel_engine/harness/README.md)), so an escalation can
> never re-touch no-touch infra — on hostile infra it deepens correlation/assessment only.
> **Model — the CLI's own agent:** run interactively in Claude Code, the IntelHarness skill
> front-end drives the same pipeline on your subscription with **no separate LLM key**; it falls
> back to `HARNESS_BACKEND=local` (Ollama/vLLM/LM Studio, keyless) or an API key only for unattended
> SDK runs. No reasoning backend reachable **and** non-interactive → the escalation is **skipped and
> noted as a collection gap**, never a blocker. A converged case, `--passive`, or hostile-only infra
> → no escalation and the deterministic result stands.
>
> **Self-contained & self-resolving.** `/backend` resolves to **SELF** (in-repo) — no external
> setup, and an explicit `$INTEL_HOME` overrides it for a shared external KB. Install steps and
> pointers: [`handbook/case-pipeline-detail.md`](handbook/case-pipeline-detail.md#self-contained--self-resolving);
> architecture and op map: [`connectors/intel-backend.md`](connectors/intel-backend.md).

---

## 2.5. Pivot Priority & False-Positive Control (CRITICAL)

Two failure modes ruin a cluster: asserting a link that isn't there, and missing one that is.
This section governs both. Apply it in Enrich, before anything reaches a report.

### Pivot priority ladder

Work **down** this ladder. Never assert same-operator on a lower rung when a higher rung is
available or contradicts it. Tag every asserted link in the report with the rung it rests on.

| Rung | Indicator | Strength |
|---|---|---|
| 1 | Registrant email / phone / org — **including historic WHOIS** | decisive |
| 2 | One domain carrying **two identities across its own WHOIS history** | decisive — proves an alias |
| 3 | Site-verification token (Google Search Console, etc.) | decisive — proves account control |
| 4 | Shared TLS certificate / SAN cross-cover | strong |
| 5 | Nameserver delegation to a host the operator **runs themselves** | strong — proves zone control |
| 6 | APK signing certificate | strong |
| 7 | Distinctive favicon / analytics / tracker / backend tenant ID | moderate — verify below |
| 8 | Co-tenancy on a **dedicated** host (few tenants) | moderate |
| 9 | Site template / framework / kit | **weak — kit-level, never operator-level** |
| 10 | Co-tenancy on **shared/reseller** hosting; managed-provider nameservers | information, not a link |

**Reverse-WHOIS is the highest-yield pivot here.** Always `mode=preview` first — the count is
free. A term returning hundreds is shared boilerplate; do not purchase it.

### Mandatory false-positive control

Before any indicator becomes a cluster edge, run `/reference check <value>`. If it returns
UNKNOWN, **decide and record it** with `/reference add` so the next case inherits the judgement.

Six traps, all of which have produced real false clusters:

| Trap | Why it fools you | Test |
|---|---|---|
| **Commodity site kit** | A template sold to hundreds of unrelated fraud operators | Search the template path in urlscan/FOFA — a large population means kit-level |
| **Privacy-proxy contacts** | The registrar's boilerplate phone/email, shared by every customer of that service | Reverse-WHOIS it; a spread of unrelated domains means noise |
| **Shared/reseller hosting IP** | A 20+-tenant cPanel box links nothing | Count tenants before clustering |
| **Managed-provider nameservers** | Cloudflare/GoDaddy/Gandi/Wix NS are shared by millions | Self-hosted NS is rung 5; provider NS is rung 10 |
| **Org-name collision** | A registrant org string that also matches a real, unrelated company | Reverse-WHOIS the org; inspect what comes back before attributing |
| **Shared analytics / tag container** | Often one web developer reusing a container across unrelated clients | **Check domain creation dates** — a decade-old business sharing a tag with a new fraud domain is a third party |

> **Never put an unvalidated indicator into a report that recommends abuse reporting.** Naming an
> uninvolved business is the most damaging error this skill can produce. When a cluster rests on a
> single rung-7-or-below indicator, label it *candidate, single-indicator* — not a cluster member.

### Reusing recalled knowledge — the five-question gate

Anything the KB or `/recall` hands back is a **prior claim**, not a fresh finding. Before it
shapes a pivot, a cluster or a sentence in a report, answer all five — and say which one failed
when you drop it:

| Question | Check | Fails when |
|---|---|---|
| **Knowledge** — what exactly is claimed? | the fact/edge itself (`/kb --entity`) and the case **abstract** recall leads with | you only have a case id or a vague "seen before" |
| **Evidence** — on what? | `source`/`collector`, `evidence_refs`, observation count (`seen … ×N`), the `cases` that recorded it | no evidence ref, or a single sighting by an extractor-tier source |
| **Validity** — still true, and true *when it mattered*? | `valid from..until`; `/kb --as-of <incident day>` for the state on that day; a `[superseded]` value is history only | the window ended before the incident, or the fact is superseded |
| **Authority** — who says so, and does anyone disagree? | tier analyst > registry > vendor > extractor; a `[DISPUTED vs …]` flag or the assessment's **Conflicting Evidence** table | an unresolved dispute — resolve it before relying on either value |
| **Utility** — does it bear on *this* case's premise? | the case intake (`case_scope`) claim | relevant to the old case only — note it, don't import it |

A recalled link that fails Validity or Authority is reported as context ("seen in CASE-… in 2025,
since superseded / disputed"), never as a current same-operator link (RULE 5).

### Attribution rails — collecting ≠ attributing (RULE 5)

Provider-level / same-MO evidence (shared kit, IP co-tenancy, exchange-wallet flow) is ingested as
`add_fact` only, never `operator_lead`, never an edge. The harness **cross-type loop** MAY collect
such hosts (source `kit:` / `cotenant:` / `cpty:`) — typed nodes, `propose`, Plan phase with
read-only `PLAN_TOOLS`, auto free/urlscan pivots with ≤ N=25 hits, otherwise a digest-bound
`proposal.json` gated by `audit.gate` (auto-approved by the loop in `/cti`'s default auto mode,
gated tools excepted; `--review`: `harness approve`, `case_approve`, TTY) — but they never
cluster, never attribute, and render as **kit siblings** / **neighbours** with a rung caveat
(`Assessment.kit_siblings` / `neighbours` / `mentions`). Owner-link classes only
(WHOIS registrant email/phone, exact cert, analytics GA/GTM/gtag/FB/TikTok/Metrica, telegram
bot-token, discord webhook, non-exchange wallet) may enter `cluster`. Rung table:
`intel_engine/tools/kb/references/rungs.json`. Dispatcher ops `propose` and `corpus-search`
(`corpus_search` MCP tool) feed the loop without elevating kit/neighbour hits. The identity /
estate routes (`pgp.lookup`, `corp.registry`, `telegram.resolve`, `revimg.links`,
`takedown.watch`, `container.registry`, `masked.hint` — free, auto; `telegram.phone`,
`google.account`, `corp.opencorporates` — always a proposal item, offered only when the session /
GHunt / token exists) return LEADS only: PGP UIDs, registry officers (homonym candidates),
Telegram ids, reverse-image hits, registry labels and takedown successors are kit/neighbour facts;
officer names, ids and hint verdicts never become pivot nodes. `commands/cti.md` has the table.

**Person-profile mode** (scope `subject_type: person`; default `infrastructure` = off): case
enrichment adds `vn_corp --by-phone` (+84) / `--by-person` (confirmed names only, homonym gate
kept), spoofability of the subject's domains and offline handle hints; the analyst fills
`subject_profile` / `client_seeds` / `engagement` via `evidence_import` and runs
`exposure_score model=executive` — ratings are analyst judgement, never auto-scored.

### Claim discipline — what a hit can say (RULE 5)

Collection results carry their source's own semantics; the report may not widen them. Four rails:

1. **Leak / stealer-log search hits = "selector appears in the leak corpus" — nothing more.** A hit
   count, a `by_bucket` tally or a `read_these` list says no machine was infected and no account was
   compromised. Only a search with `status: clean` makes an absence a negative; `partial (…)`
   means missing records are unknown, not absent.
2. **Infection / compromise claims need an opened record.** Open the item (`/intelx item
   <storageid> --bucket <bucket>`, T1 `intelx_search` mode=`item`) and cite its storageid, bucket
   and what the redacted preview shows. No opened item → the claim is not written.
3. **Platform account linkage ≠ legal owner or person.** A connected Instagram account, a page
   role, a "managed by" label or a search typeahead tie two *accounts*; they do not name who owns
   the page or the business. Owner/person claims need an owner-class source (registry, WHOIS
   registrant, the subject's own signed statement) and stay `candidate` until then.
4. **Metrics transcribed from a table keep the table's own semantics.** Count vs value vs scope
   (e.g. "orders" vs "total transaction value over all transactions") are separate cells — never
   merge them into one sentence ("N orders worth X") unless the source itself states that
   relation. Quote each metric with its own label, unit and period.



### Binary downloads and ANY.RUN sandbox submissions (CRITICAL)

When `/cti` discovers an `app:apk` or `app:desktop_installer` URL, the pipeline downloads it to
`cases/<case>/bin/<sha256>.<extension>` and runs BinaryPivot static analysis. It writes the result
under `cases/<case>/bin/analysis/<sha256>.json`, explicitly ingested into the KB without adding a
file-host row to the web estate, even without an ANY.RUN key. `--no-collect` skips this step;
a hostile/no-direct-contact posture blocks the direct fetch. Failed, truncated or non-binary
downloads are neither ingested nor submitted to the sandbox.

Binary hashes and extracted identifiers attach to the file in the KB. Only a matching
already-collected **self-hosted** web origin receives owner-specific identifier edges; a shared
CDN/download host remains a provenance fact, never an operator cluster join. Consequence: when an
APK is served off-site (a CDN, a file-locker), its signing cert / backend links live on the
`file_hash` node, and `shared_indicators` (domain-sourced only) will not surface them — read the
`file_hash` entity directly to corroborate two apps by a common cert or backend.

**A configured ANYRUN_API_KEY authorizes automatic submission of complete downloaded binaries in
spending runs.** `--free-only`, `scope.json` `no_spend`, and the loop's default free-only mode suppress
uploads; `loop --full` permits them. A case-local `anyrun/submissions.json` records attempts and
task UUIDs by SHA-256; an ambiguous POST result is not retried on resume. This is outbound and
irreversible: the operator may see a public task and rotate its infrastructure. Leave the key unset
or use a no-spend run when that disclosure is unacceptable.

`/anyrun` remains **lookup-only**. Direct `anyrun_submit` (T1) / `bp_anyrun.py submit` calls still
require a per-submission risk briefing and analyst confirmation. The automatic pipeline is the
explicit key-configured exception: it calls the same `bp_anyrun.submit(confirm=True)` after static
analysis and spend/egress checks. The sandbox client's remaining gates apply unchanged:

1. **Private by default, public refused.** Privacy defaults to `owner`; `public` is refused even
   with `confirm` unless `allow_public` is separately authorised — per call, or as the analyst's
   standing `ANYRUN_ALLOW_PUBLIC=1` in the gitignored `.env`. With that set, a plan that *cannot*
   go private (`denied`) is downgraded to a public task **explicitly** — the result carries
   `public_task`, `downgraded_from`, `public_authorized_by` — never silently, and never when the
   plan can go private. Auto-delete defaults to a week.
2. **Free plan fails closed.** Pre-flight, before any POST, the engine checks the key's own
   account record: `/user` → `limits.private` (observed live; `0` in any window = **denied**,
   and the analyst attestation below cannot override that positive evidence; `-1`/positive =
   entitled), else a prior non-public task in the account's history. Neither → `refused` +
   `plan_evidence`, unless the analyst explicitly attests to a paid plan
   (`allow_unverified_plan=true` / `--i-have-a-paid-plan`) — never set it on your own.
3. **Post-submit read-back.** The task record carries no privacy while the sandbox is running
   (observed live: a `status: "in progress"` stub for ~2 min), so after the POST the engine polls
   the report — bounded to `sandbox timeout + 60 s`, max 240 s — and, once finished, reads the
   privacy ANY.RUN actually applied. A forbidden mode is withdrawn (task deleted) and the result
   says `exposed: true`. If the task outlives the wait, the result says `privacy_verified: null`
   with a `verify_command`; **run it** — `bp_anyrun.py verify-privacy <uuid>` / `anyrun_submit`
   with `verify_task=true, target=<uuid>` — to finish the check and the withdrawal. Either way
   this is *detected*, not *prevented*: deletion does not un-publish what the feed already
   showed, so treat the infrastructure as tipped.

Direct MCP `anyrun_submit` still requires `HARNESS_ALLOW_SUBMIT=1`; the pipeline does not use that
tool and instead calls `bp_anyrun.submit()` after its own key, spend, file, and egress checks.
`tests/test_no_sample_submission.py` protects the manual confirmation gate;
`tests/test_binary_auto.py` covers the automatic path. Neither route bypasses private-plan proof
or the post-submit privacy check. Uploads are **outbound and irreversible**:

- A public task is **world-readable**: the file, its hash, screenshots and full network log.
- **Operators watch for their own samples.** The standard response is to rotate the backend,
  revoke the signing key and re-skin the front — destroying the infrastructure the case is built
  on, often days before a takedown or referral can land.
- **It cannot be recalled.** Deleting a task does not un-publish what was already seen.
- A URL detonation **fetches the live target** from published sandbox egress: the operator learns
  it was sandboxed, and a "clean" verdict may be the decoy served to datacenter IPs.

For a manual submission, try static `analyze_artifact` and an existing detonation of the hash
(`anyrun_lookup`, VirusTotal, MalwareBazaar, Triage, Koodous) first. The pipeline always submits
the downloaded FILE rather than the live URL and names it by hash (never a case ID or client).
`--submit` (urlscan/Wayback) is a separate action with its own approval policy.

### A permuted email is a hypothesis, never a finding (CRITICAL)

When a case yields a **real person's name** or a **username**, and you already hold a domain that
matters to the case, run **`/email-permute`**. An operator's mailbox is almost never published, but
it is usually *derivable* — mail hosts use a small set of local-part conventions, and the operator's
own domain is the highest-yield thing to permute against.

That value comes with a matching hazard, so this rule is absolute:

- **Permute against the case's own domains.** Name × the operator's domain is a narrow, high-prior
  question. Name × `gmail.com` is volume with no prior behind it — `--free` exists, is capped, and
  should be a deliberate choice, not a reflex.
- **Never ingest a candidate into the KB, cite one in a report, or contact one.** A fabricated
  address that reaches `kb_ingest` becomes a shared indicator, and a shared indicator merges two
  operator clusters. A permutator wired straight into correlation does not enrich a case — it
  silently names an innocent party. This is the same failure RULE 5 exists to prevent.
- **Candidates are not seeds.** They never enter the spider-map frontier. Only an address in the
  tool's `promote` list — corroborated by *independent* evidence (Gravatar registration, breach
  corpus, a GitHub commit, a page/DOM hit, a dork) — may be treated as a real email seed, and that
  promotion is an analyst decision.
- **Never validate over SMTP.** `RCPT TO` probing connects to the *target's* mail server, which the
  egress posture exists to prevent on a hostile case; and a catch-all domain answers `250` for
  every address ever tried, so it manufactures confidence instead of measuring it. Use `--verify`,
  which gates on MX (RFC 7505 null MX included) and checks Gravatar — both keyless, neither
  touching the target.

State the status in the turn. *"12 candidates, 0 corroborated"* is an honest result; presenting
those 12 as discovered addresses is not.

### Dead seed? Do not stop

Zero pivots, a parked page, or NXDOMAIN is not an answer. Run **`/fallback <domain>`** — crt.sh,
the full Wayback timeline, archive.today, and the local KB. A parked apex frequently has live
subdomains: enumerate CT and the Wayback CDX host histogram before writing a seed off. Report an
empty result as empty; a collector that returned nothing is a finding, not something to omit.

### Social-media seed intake — Facebook / Instagram / TikTok / LinkedIn

When the seed is a social URL, share link or handle, run this chain **before** any web-infra pivot:

1. **`/sharelink <url>`** — resolve share/short links and unwrap login walls; take the
   `platform_ids` block (page/profile/owner id, story_fbid, shortcode, @user, sec_user_id). A URL the
   analyst pasted from a login wall is parsed with `--no-follow` (nothing contacted).
2. **`/meta-transparency <page-or-handle>`** (Facebook / Instagram) — Page id, Ad Library About
   tab (creation date, name-change dates, admin countries, confirmed owning organisation, linked
   Instagram), IG public profile, Wayback name/bio/location history. Read each field's `status`:
   `login_required` / `blocked` / `rate_limited` are **collection gaps**, never negatives. TikTok /
   LinkedIn have no transparency collector — go straight to step 3.
3. **`/username <handle>`** and **`/email-permute <name|handle>`** on every handle and display
   name discovered (`handles[]`) — hypotheses until confirmed.
4. **Leak fan-out** — the confirmed account usernames, business emails and phones go through
   `/enrich <case> --leak-only` (`case_enrich`) like any other confirmed selector.
5. **Ask early for logged-in screenshots.** Relay the tool's `capture_checklist` to the analyst in
   round 1 — Page transparency → *See all*, Ad Library Page → *About*, Instagram → *About this
   account*, profile *About* tabs — taken in their own research account, with URL bar and clock
   visible, then imported with `evidence_import`. **Never ask for cookies, session tokens,
   passwords or HAR exports**, and never run a collector with them.

**Account linkage ≠ owner identity.** A linked Instagram, a confirmed owning organisation, an admin
country, a shared ad disclaimer or a sharer id ties *accounts* together; who runs them needs an
owner-class source (see Claim discipline rule 3) and stays `candidate` until then.

### Egress control — proxy / rotation

On a hostile case your **egress IP is a selector too** — a direct fetch of scam
infrastructure exposes your real address to the operator, and repeated lookups
from one IP get you rate-limited or fingerprinted. The `/cti-proxy` layer routes
every **HTTP(S)** request the collectors make (keyless crt.sh, Wayback/CDX,
urlscan, the CLD connector, WHOIS, analytics reverses, `/apikeys test`) through a
configured proxy — or a **rotation pool** with automatic failover — so collection
egresses from an IP you choose, and successive calls can egress from different
ones. It also tunnels the collector's raw-socket TLS cert probe (`/cert-pivot`
leaf fingerprint) via CONNECT, **failing closed** rather than dialling direct.

> **Raw-socket TLS probes are handled too — nothing dials the target directly
> behind a proxy.** The cert-SHA probes (`wp_pssl.py`, `wp_recon.py`) and JARM
> (`jarm.py`) all take their socket from `cti_proxy.proxied_connection`: under an
> HTTP pool it is **CONNECT-tunnelled and fails closed** (never a direct dial);
> under a SOCKS pool the in-process socket hook carries it (installed at import via
> `wp_common`, and `jarm.py`'s own bootstrap) **when PySocks is present in that
> interpreter** — if it is not (e.g. the `intel.py` pipeline runs tools under
> `$INTEL_PY`), the hook is absent and these probes **fail closed instead of
> leaking**, so install `pysocks` there; with no proxy it dials direct. As a
> policy choice the `/webpivot` analyze path additionally **skips JARM under an
> HTTP pool** (ten tunnelled handshakes are slow) and runs it under SOCKS / no
> proxy — that gate honors the env/pool proxy, not just an explicit `--proxy`.

```bash
uv run scripts/proxy/proxy.py add http://user:pass@host:3128 --label res-1
uv run scripts/proxy/proxy.py add 1.2.3.4:8080        # bare host:port -> http://
uv run scripts/proxy/proxy.py rotation round-robin    # | random | sticky | off
uv run scripts/proxy/proxy.py test                    # confirm each proxy's egress IP
uv run scripts/proxy/proxy.py status                  # pool + policy + toggles
uv run scripts/proxy/proxy.py disable                 # back to the real IP
```

- It is **opt-in and additive** — with no proxy configured the skill runs exactly
  as before, from your real IP. A pool, once added, is enabled by default.
- **No-leak default:** with a pool set, a failed pool is **not** silently retried
  direct — turn that on deliberately with `allow-direct on`.
- **Precedence:** env `CTI_PROXY` / `CTI_PROXIES` (and standard `HTTPS_PROXY`)
  override the stored pool for a one-off session; the store lives in
  `scripts/proxy/proxies.json` (gitignored, chmod-600 — it may hold credentials).
- **Coverage:** the broad collectors (`scripts/…`) get full in-process rotation +
  failover; the deep pipeline (`/backend`, `/pipeline`, `/harness`) inherits the
  egress for every tool it spawns (one proxy per run). For an ad-hoc tool call or
  the MCP server, export first: `eval "$(python3 scripts/proxy/proxy.py use)"`.
- **Formats:** `add` accepts a full URL, a bare `host:port`, a provider
  `host:port:user:pass` export, a `user:pass@host:port` authority, or a pasted
  `http_proxy="…"` line. HTTP/HTTPS get the full rotation + failover + `no_proxy`
  behavior; `socks5://`/`socks5h://` auto-install PySocks on `add` but rotate only
  per run — no in-process failover, and `no_proxy` is not enforced (the global
  socket hook routes everything).
- Full reference: `/cti-proxy` (`commands/cti-proxy.md`).

---

## 3. Command Reference

> **How to read this table — check the marker before you announce a command.**
>
> | Marker | Meaning | What you may say |
> |---|---|---|
> | **T2:** / **T1:** shown | Backed by a real CLI op and/or MCP tool. | Call it, then report what it returned. |
> | **[model]** | No code behind it, and none is needed — it names a way for *you* to work (a summary style, a checklist, a KB read-back). | Do the thing. Never claim a tool ran. |
> | **[unimplemented]** | The tradecraft is documented but nothing executes it yet. | Say so, then follow the linked technique by hand. Do NOT narrate it as a tool call. |
>
> A command with no marker and no **T2:**/**T1:** line has not been triaged yet — treat it as
> **[unimplemented]**. Announcing a tool call that cannot happen is the failure this table exists
> to prevent: the output looks identical to real collection and is not.

### 3.0 Entry point & registered commands

**`/cti <target>` is the single entry to this skill.** It routes any target type — domain, IP,
email, username, phone, wallet, hash, APK, Telegram handle, filename or string — through recall
→ the **cross-type harness loop** (default engine: typed pivots, a read-only Plan phase, and
**auto mode** — every paid / oversized pivot auto-approved and run round after round, except
`engage_account` / `webamon_scan` / `misp_publish` / `misp_push`; `--review` = per-round analyst
approval; the analyst's typed seeds collect keyed, found hosts free-only) → assess.
`--pipeline`/`--quick`, or no available LLM backend, falls back to the
deterministic pipeline. Plain English works identically ("analyze example.com and pivot the
infrastructure"); the command form just removes ambiguity.

**`/case <target>` is an alias of `/cti <target>`** — the same full pipeline run; `/cti` is the canonical entry (and the only form that works from a cold prompt). Prefer `/cti`.

Nine commands are **registered with Claude Code** by `bash scripts/register.sh` and work from a
cold prompt in any project. The same run calls `scripts/register_agents.py`, which registers them
with every other detected agent (omp, pi, OpenCode, Gemini CLI, Qwen Code, Factory droid,
Windsurf) and installs `/cti` as the `cti` agent skill for Cursor and Copilot CLI (`/cti`), Codex
(`$cti`) and the ChatGPT desktop app (`@cti`):

| Command | Does | Equivalent T2 op | Equivalent T1 tool |
|---|---|---|---|
| **`/cti <target>`** | **entry point — routes by target type**; AUTO mode by default (paid pivots auto-approved, `approved_by: auto` in `proposal.json` + ledger; gated: `engage_account`, `webamon_scan`, `misp_publish`, `misp_push`); `--review` = per-round approval; `--quarry` = wait for Quarry first | *(whole chain)* | *(whole chain)* |
| `/cti-recall <seed>` | seen before? **run first, always** | `recall` | `domain_verdict`, `which_cases` |
| `/cti-case <ID> <seeds>` | full deterministic pipeline | `pipeline open` | *(none — CLI only)* |
| `/cti-pivot <url\|ip>` | collect one target | `pivot-extract` | `pivot_extract` |
| `/cti-cluster <domain>` | correlate & expand | `kb`, `cert-overlap` | `kb_cluster`, `cert_overlap` |
| `/cti-check <indicator>` | false-positive control | `reference check` | `reference_check`, `reference_add` |
| `/cti-report <ID>` | render graph + PDF/DOCX | `graph`, `report` | `render_diagram`, `render_report` |
| `/cti-status` | backend / MCP / credits health | `backend.py status` | `api_usage` |
| `/cti-proxy [op]` | egress proxy / rotation pool for **all** outbound calls; `status [--probe]` shows the effective pool and allow_direct with their sources (env / .env / proxies.json, credentials masked) and probes each exit; `/cti` refuses with `egress-unavailable` when the pool is dead and direct is off; vendor API hosts go direct when every exit refuses or is dead (targets never do) | *(none — CLI only)* | *(none — CLI only)* |

> **Every other `/command` in §3 is a convention read from this file, not a registered command.**
> Once the skill is loaded they are unambiguous instructions; typed at a cold prompt they do
> nothing. When in doubt use `/cti` and describe the goal.

**Three layers, one operation.** The same capability is reachable three ways and the names differ
by layer — T0 uses `kebab-case` after a slash, T2 uses `kebab-case` ops, T1 uses `snake_case`
tools. The table above is the canonical mapping; when you add a capability, add a row here in the
same commit or the layers drift apart again.

Capabilities that are *not* registered commands still carry their layer mapping inline in the §3
tables. The engine's WebPivot/BinaryPivot collectors add these: `/capabilities` (T2 `capabilities`,
T1 `capability_check`), `/impersonate` (T2 `impersonate`, T1 `impersonation_hunt`), `/search-pivot`
(T2 `search-pivot`, T1 `search_pivot`), `/censys` (T2 `censys`, T1 `censys`), `/intelx`
(T2 `intelx`, T1 `intelx_search`) and `/anyrun` (T2 `anyrun`, T1 `anyrun_lookup`).

---

Commands grouped by AEAD phase.

### Command index

One line per command, grouped by AEAD phase. **Before running a command, read its row in
[`handbook/command-reference.md`](handbook/command-reference.md)** — the row holds the flags, the
backing **T2:** op / **T1:** tool or marker, the rails and an example.

**Acquire** — full rows: [`handbook/command-reference.md#acquire`](handbook/command-reference.md#acquire)

| Command | Purpose |
|---|---|
| `/case [target]` | Full pipeline — runs every applicable technique |
| `/sweep [target]` | Multi-vector recon on any target type |
| `/query [subject]` | Builds 12–15 advanced search operator queries |
| `/username [handle] [--offline]` | Enumerate handle across 3000+ platforms |
| `/google-account [email\|gaia-id]` | Google-account leads through an installed GHunt |
| `/telegram [phone\|@user\|t.me link]` | Telegram from the analyst's research account |
| `/reverse-image [url\|file]` | Where else does this picture appear? |
| `/phone [number]` | Carrier, line type, reputation, public associations |
| `/vn-corp [mst\|company]` | Keyless Vietnamese business registry |
| `/email-deep [email]` | Accounts, breach history, infrastructure |
| `/subdomain [domain]` | CT logs, brute-force, passive enumeration |
| `/breach-deep [email]` | Multi-source breach lookup |
| `/traffic [domain]` | Traffic estimation, ranking, audience data |
| `/visitors [domain]` | Full visitor intelligence: tech, geo, sources, analytics |
| `/techstack [domain]` | Technology fingerprint (CMS, analytics, CDN, server) |
| `/competitors [domain]` | Competitor & related site discovery |
| `/secrets [target]` | Exposed credentials in repos and paste sites |
| `/grayhatwarfare [mode] [selector]` | GrayHatWarfare: buckets, shortener and git corpora |
| `/github-osint [target]` | GitHub user/org/repo recon; committer-identity harvest |
| `/cld [target]` | ChongLuaDao first-party premium connector |
| `/threat-check [target]` | IP/domain/URL/hash threat intelligence |
| `/scam-check [domain]` | Phishing/scam/malicious domain check |
| `/webpivot [url]` | Web-infra pivoting — extract page artifacts |
| *(automatic — no flag)* | Four layers run on every collection |
| `/capabilities` | Which optional API keys are configured |
| `/impersonate [domain]` | Hunt lookalike / typosquat domains of a seed |
| `/search-pivot [indicator]` | Multi-engine search-engine pivot |
| `/censys [mode] [value]` | Censys Platform — the server-side view |
| `/intelx [selector]` | Intelligence X — search ONE strong selector |
| `/osint-industries [type] [selector]` | OSINT Industries account existence for ONE selector |
| `/anyrun [indicator]` | ANY.RUN TI Lookup — READ-ONLY |
| `/webamon [domain\|url]` | Webamon scan corpus and kit fingerprints |
| `/cert-pivot [domain]` | Cert-fingerprint pivot — hosts serving the same cert |
| `/sensitive-paths [list]` | Classify a Wayback/URL list for exposed paths |
| `/email-hygiene [email]` | Grade an email domain 0–100 + A–F |
| `/vuln-check [query]` | CVE/vulnerability lookup (CIRCL + NVD) |
| `/ransomware-check [org]` | Check if org is a ransomware victim |
| `/stealer-log [folder]` | Triage an infostealer-log folder |
| `/gdoc [url]` | Extract metadata/owner from Google document |
| `/msftrecon [domain]` | M365/Azure tenant recon |
| `/icp [domain\|serial]` | ICP filing → registered PRC entity, licence number |
| `/cn-corp [name\|USCC]` | PRC corporate registry chain |
| `/iban [value]` | Validate and decompose a bank account selector |
| `/hash-id [hash]` | Identify a hash's algorithm before lookup |
| `/appliance-scan [domain\|ip]` | Passive edge/VPN appliance scan |
| `/saas-map [domain]` | Map SaaS tenancy + identity fabric |
| `/suppliers <CASE> --subject <apex[,apex]>` | The subject's supplier map from stored raws |
| `/sharelink [url]` | Extract sharer identity from a share link |
| `/meta-transparency [fb-page\|@ig-handle]` | Keyless Meta account transparency |
| `/binary [file\|url\|dir]` | Static IOC extraction from a scam/fraud binary |
| `/container-registry [namespace\|image]` | Public container-registry OSINT |
| `/dork-sweep [target] [--telegram\|--docs\|--filetype\|--all] [--after DATE] [--clean]` | Dork sweep: Telegram ecosystem, doc-hosts, filetype families |
| `/docleak [target] [--platform list] [--severity high]` | 18-platform document leak hunt with severity classification |
| `/dns-history [domain]` | Historical DNS record changes via passive DNS |
| `/cert-history [domain]` | Certificate-transparency timeline with per-source status |
| `/proton-check [email]` | Proton Mail account age via its PGP key |
| `/pgp-lookup [email\|fingerprint\|keyid]` | Keyless keyserver pivot |
| `/wifi [ssid]` | WiFi SSID geolocation via Wigle.net |
| `/wifi --bssid [mac]` | Exact AP lookup by MAC address |
| `/takedown-watch [domain…\|--case ID]` | Was the name held / suspended / deleted? |
| `/register [name]` | Add a subject to the case workspace |
| `/snapshots [url]` | List/fetch archived Wayback snapshots |
| `/archive-harvest [domain]` | Sweep a domain's whole Wayback history for indicators |
| `/fallback [domain]` | Dead-seed recovery |

**Enrich** — full rows: [`handbook/command-reference.md#enrich`](handbook/command-reference.md#enrich)

| Command | Purpose |
|---|---|
| `/branch [data]` | Expand a discovered identifier laterally |
| `/pivot-suggest` | Rank "what to pivot on next" from findings |
| `/email-permute [name\|handle]` | Derive email candidates from a name or username |
| `/rank-relations` | Score + rank same-operator relations across analyzed pages |
| `/crypto-balance [addr]` | On-chain balance + lifetime flow for a wallet |
| `/masked-hint [hints]` | Test masked recovery hints against the case's selectors |
| `/sellers [pub-id…]` | AdSense publisher id → the legal payee |
| `/app-developer [package\|app-id]` | App-store developer account behind an app |
| `/timeline [subject]` | Assemble dated event sequence |
| `/crossref` | Detect shared identifiers across subjects |
| `/link-subjects [A] [B]` | Define a connection between two subjects |
| `/show-connections` | Display all logged connections |
| `/show-trail [subject]` | Show the evidence chain for a subject |
| `/watch [subject]` | Add subject to active tracking list |
| `/record-finding` | Log a finding with source and confidence |
| `/show-findings` | List all recorded findings |
| `/graph` | Full ASCII subject relationship map |
| `/pathfind [A] [B]` | Discover connection path between subjects |
| `/diff [url]` | Diff archived versions of a URL |

**Assess** — full rows: [`handbook/command-reference.md#assess`](handbook/command-reference.md#assess)

| Command | Purpose |
|---|---|
| `/exposure [target]` | Composite exposure score (0–100) |
| `/threat-model` | Build threat model from findings |
| `/signatures` | Surface recurring behavioral patterns |
| `/validate` | Quality audit — score 0–100 |
| `/coverage` | Coverage matrix with identified gaps |
| `/verify-finding [id]` | Re-check a specific finding's sources |
| `/subject [name]` | View or create subject record |
| `/lookup [name]` | Retrieve a registered subject |
| `/modify [name]` | Update a subject record |
| `/archive-subject [name]` | Remove subject from active tracking |
| `/find [query]` | Search across all subjects |
| `/blind-spots` | Prioritized investigation gap analysis |
| `/source-check` | Batch source URL accessibility check |
| `/drift [subject]` | Temporal risk score tracking |
| `/clarify [finding]` | Plain-language finding explanation |

**Deliver** — full rows: [`handbook/command-reference.md#deliver`](handbook/command-reference.md#deliver)

| Command | Purpose |
|---|---|
| `/report` | Full report — base bundle, then presentation prompt |
| `/report html` | Interactive self-contained HTML report (primary deliverable) |
| `/report brief` | Single-page executive brief |
| `/report json` | Raw data as JSON |
| `/report csv` | Spreadsheet-compatible export |
| `/report docx` | Word document in the PDF house style |
| `/report legal` | Evidence-formatted for legal proceedings (adds DOCX/PDF) |
| `/report journalist` | Source-citation-heavy format |
| `/brief` | Plain-language summary (non-technical) |
| `/render entities` | ASCII subject relationship diagram |
| `/render timeline` | Chronological event chart |
| `/render risk` | Exposure heatmap |
| `/render network` | Network topology of connections |
| `/stats` | Counts and coverage statistics |
| `/workspace save [name]` | Persist case state |
| `/workspace open [name]` | Resume a saved case |
| `/workspace list` | Show saved cases |
| `/workspace diff [a] [b]` | Diff two saved workspaces |
| `/render threat-path` | ASCII attack path flow diagram |
| `/render attack-surface` | ASCII attack surface exposure map |
| `/report ioc` | Export IOCs as STIX 2.1 or flat list |
| `/redact [file]` | Shareable variant of a report (opt-in) |

**UX & Navigation** — full rows: [`handbook/command-reference.md#ux--navigation`](handbook/command-reference.md#ux--navigation)

| Command | Purpose |
|---|---|
| `/flow [type]` | Guided step-by-step case workflow |
| `/template list` | Browse pre-built case templates |
| `/template run [name]` | Run a pre-built template |
| `/novice` | Toggle simplified, low-jargon mode |
| `/terms` | OSINT term glossary |
| `/progress` | Current case phase and coverage |
| `/opsec` | OPSEC checklist for current task |
| `/onboard` | Interactive first-time onboarding guide |
| `/quality` | Investigation quality composite score |

**Configure** — full rows: [`handbook/command-reference.md#configure`](handbook/command-reference.md#configure)

| Command | Purpose |
|---|---|
| `/apikeys` | Manage premium/pro API keys |
| `/backend` | Detect/report the optional persistent-intelligence backend |
| `/kb [query]` | Query the shared knowledge base |
| `/recall [seed]` | "Have I seen this before?" |
| `/kb-forget [case]` | Remove one case's contribution from the KB |
| `/risk [case]` | Score a case's hosts for red flags |
| `/evidence import <case> <findings.json>` | Import the analyst's graded findings |
| `/report-sections [load\|sources\|lint] [case]` | The analyst report block: load, sources, lint |
| `/reverse-whois [email\|name]` | Reverse-WHOIS a registrant identity |
| `/cert-overlap [d1 d2 …]` | KB-aware TLS/SAN same-operator verdict |
| `/reference [check\|add\|list]` | Curated false-positive control ledger |
| `/pipeline [open\|status] <case> <domains-file>` | The deterministic chain (no LLM key) |
| `/harness [open\|continue\|status]` | The agent-driven whole-case orchestration (IntelHarness) |
| `/close <case> --outcome <o>` | Close a case with a disposition; no expansion until reopen |
| `/action-log <case> --notice <file>` | Record a drafted notice as sent, or its result |
| `/notice <case>` | Draft registrar/host/CDN/platform/bank/referral notices (nothing sent) |
| `/watch [add\|list\|run\|rm]` | Watch-list over CT / lookalike / takedown / drift monitors (leads only) |
| `/graph --render` | IntelGraph publication-quality render of a case graph |
| `/report pdf` | IntelReport pandoc render → PDF + DOCX |
| `/clusters [case]` | Partition a case into same-operator clusters |
| `/frontier [case]` | Next free apex seeds, deferred pivots, open leads |
| `/enrich [case]` | Resume machine-executable enrichment from stored raw pivots |
| `/loop [case]` | Collect → assess repeatedly until the case converges |
| `/scope [case]` | Case intake: no-touch class, ownership, egress gate |
| `/liveness [domain]` | Is it actually alive? |
| `/pssl [domain\|cert]` | Passive SSL — historical cert → IP direction |
| `/origin-history [case] [--host H]` | Every address each collected host ever resolved to |
| `/approve-cohost [case] [ip] [domain…\|--all]` | Approve named co-tenants of an origin IP (analyst-run) |
| `/paths [url]` | The URL path as a clustering indicator |
| `/kit-rules [update\|status]` | Import the public IOK kit rules into the local cache (never automatic) |
| `/serp [domain]` | The advertising layer — Google Ads Transparency |
| `/docmeta [url\|file]` | Document/image metadata |
| `/screenshot [url]` | Rendered full-page PNG as hashed visual evidence |
| `/exhaust [case]` | Which collection layers actually RAN |
| `/misp-export [case]` | Build a MISP event from the case's pivots |
| `/misp [search\|push\|publish]` | MISP search, stage, publish — separate decisions |
| `/pivot-extract <.eml>` | pivot_extract on a victim's saved email |
| `/victims [case]` | Infer the access vector from the victim set |
| `/case-timeline [case]` | IntelGraph infrastructure-lifecycle timeline |
| `/tool-calls [case]` | Audit what the model actually called |
| `/login-detect [url]` | Find the login form, password field, registration page |
| `/engage [url]` | GATED — synthetic-persona account in the members area |

---

## 4. Subject & Connection Model

Reference: `engine/case-schema.json`, `engine/subject-registry.md`

### Subject Types

| Type | Emoji | Examples |
|------|-------|---------|
| Person | 👤 | Full name, alias |
| Username | @ | Social handle |
| Email | 📧 | Address, domain |
| Domain | 🌐 | Site, subdomain |
| IP Address | 🖥 | IPv4, IPv6 |
| Organization | 🏢 | Company, group |
| Phone | 📱 | E.164 format |
| Location | 📍 | GPS, address |
| Asset | 📦 | Document, image |
| Event | 📅 | Dated occurrence |
| Device | 🖥️ | IoT device, server, workstation |
| Image | 🖼️ | Photograph, screenshot |
| Crypto Address | 💰 | Bitcoin, Ethereum wallet |
| Bank Account | 🏦 | IBAN, local account no., BIC |
| ICP Filing | 📋 | PRC licence serial (one registrant, many sites) |
| Custom | 🏷️ | User-defined entity type |

### Connection Types

```
owns         — domain, email, or asset ownership
uses         — platform account or tool usage
works_at     — employment or affiliation
linked_to    — general association
alias        — same identity, different handle
communicated_with — observed contact
```

### Finding Trust Scores

| Score | Label | Meaning |
|-------|-------|---------|
| 5 | PRIMARY | Authoritative or official source |
| 4 | DERIVED | Confirmed by 2+ independent sources |
| 3 | CONFIRMED | Single reliable source, verified |
| 2 | ANECDOTAL | Reported but unverified |
| 1 | CONTESTED | Conflicting data exists |

### Source Reliability Scale

Complements numeric trust scores with source-level grading. Trust score rates finding content; source reliability rates the source itself.

| Grade | Label | Typical Sources |
|-------|-------|-----------------|
| A | Completely Reliable | Official registries, government records |
| B | Usually Reliable | Established outlets, corporate sources |
| C | Fairly Reliable | Known blogs, industry publications |
| D | Not Usually Reliable | Anonymous forums, unverified claims |
| E | Unreliable | Known disinformation, fabricated content |
| F | Cannot Be Judged | Insufficient information to assess |

### Confidence Levels

| Level | Label | Use When |
|-------|-------|---------|
| VERIFIED | Direct observation, primary source | |
| STRONG | Multiple corroborating sources | |
| MODERATE | Single reliable source | |
| WEAK | Circumstantial or inferred | |
| TENTATIVE | Analyst deduction only | |
| CHALLENGED | Contradicted by other findings | |

### Likelihood Language (judgments, not findings)

The three scales above grade **evidence**. An analytic **judgment** built on that evidence —
an attribution, a motive, a forecast — carries a probability-anchored likelihood term instead.
Without an anchor, "MODERATE" routinely means a 30-point-different thing to writer and reader.

| Term | Band | | Term | Band |
|------|------|---|------|------|
| Almost no chance | 1–5% | | Likely / probable | 55–80% |
| Very unlikely | 5–20% | | Very likely | 80–95% |
| Unlikely | 20–45% | | Almost certain | 95–99% |
| Roughly even chance | 45–55% | | | |

**Likelihood and confidence are orthogonal — report both:**
> The operator is **very likely** based in Guangdong (**moderate confidence** — single
> registry record, unverified).

Never 0% or 100%. One term per judgment. Never attach a likelihood term to a directly
observed fact. `findings[].confidence` in the report JSON stays an integer describing
**evidence quality** — likelihood lives in the narrative.

**Attribution claims additionally require an ACH matrix** (competing hypotheses, scored by
inconsistency, runner-up named). Full rules — likelihood, the 5W1H coverage overlay, ACH and the
pre-assessment bias checks: [`handbook/analytic-standards.md`](handbook/analytic-standards.md).
Activity modelling (Diamond events / activity threads / activity groups, Pyramid-of-Pain pivot
priority, ATT&CK mapping limits): [`handbook/intrusion-modeling.md`](handbook/intrusion-modeling.md).
Capturing, preserving and verifying online evidence (chain of custody, what to record per item):
[`handbook/collection-preservation.md`](handbook/collection-preservation.md).
Claim ladders that keep *same infrastructure / same account / same operator / named person*
apart live in the owning technique (`username-osint.md`, `darknet-investigation.md`,
`blockchain-investigation.md`, `fx-dns-cert-history.md`); every research source behind them is
registered in [`docs/research-sources.md`](docs/research-sources.md).

### Map Rendering (ASCII Mandatory)

**ALL visualization commands produce ASCII box-drawing art by default.** This includes `/graph`, `/render entities`, `/render network`, `/render timeline`, `/render risk`, `/pathfind`, and `/show-connections`. Mermaid available only with explicit `--mermaid` flag.

**Why ASCII-first:** Universal terminal compatibility, renders correctly in .md and .docx exports, no external renderer dependency.

```
┌─────────────────────────────┐   owns   ┌───────────────────────────┐
│ 👤 John Doe          [3/5] │══════════▶│ 🌐 example.com     [4/5] │
└─────────────────────────────┘           └───────────────────────────┘
         │ works_at                       │ hosted_on
         ▼                                ▼
┌─────────────────────────────┐  ┌───────────────────────────┐
│ 🏢 Acme Corp         [4/5] │  │ 🖥 203.0.113.10    [4/5] │
└─────────────────────────────┘  └───────────────────────────┘
```

**Connection arrows:**  `═══▶` owns · `───▶` confirmed · `···▶` inferred · `←─▶` bidirectional · `─·─▶` alias · `╌╌▶` works_at
**Box styles:**  `┌──┐` confirmed · `┌ ─ ┐` unverified · `╔══╗` target
**Badge:**  `[n/5]` trust score · emoji prefix = entity type

---

## 5. Finding Framework

Reference: `engine/finding-framework.md`, `engine/conflict-resolver.md`

Every finding logged via `/record-finding` captures:

```
Source URL / method
Collection method (browser | search | fetch | manual)
Trust score (1–5)
Confidence level (VERIFIED → CHALLENGED)
Timestamp
Linked subjects
```

**Conflict detection** (`engine/conflict-resolver.md`): When two findings about the same subject contradict each other, the system flags a CONTESTED state. Both findings are preserved. Resolution options: accept one, mark both TENTATIVE, or log the conflict as its own finding.

**Deviation detection** (`analysis/deviation-detector.md`): Automatically flags behavioral anomalies — account creation gaps, platform presence inconsistencies, metadata mismatches.

**Weight engine** (`analysis/weight-engine.md`): Aggregates trust scores across findings to compute subject-level confidence.

---

## 6. Technique Catalog

Reference directory: `techniques/`

| File | Covers |
|------|--------|
| `fx-metadata-parsing.md` | EXIF, email headers, document metadata analysis |
| `fx-image-verification.md` | Image authenticity and provenance workflow |
| `fx-breach-discovery.md` | Breach database methods and paste site search |
| `fx-geolocation.md` | GPS extraction, W3W, Plus Codes, MGRS, Street View |
| `fx-social-topology.md` | Social graph construction and topology; **relative discovery** (same surname in follows/friends, confirming post/comment, confirmed / probable / possible grading; relatives stay leads) |
| `people-records-global.md` | Public people / civil / electoral / corporate / court records by region (UK, US, EU, SEA incl. Thailand, Vietnam, Philippines; FamilySearch, grave indexes) and how each corroborates birth year/place, address history and relatives; legal & data-minimisation notes |
| `fx-email-header-analysis.md` | Header analysis, SPF/DKIM, SMTP routing |
| `fx-document-forensics.md` | Document forensics and metadata extraction |
| `fx-http-fingerprint.md` | HTTP fingerprinting and server signature analysis |
| `fx-leak-monitoring.md` | Leak and breach monitoring, paste site search |
<!-- dork-integration:phase-05 start -->
| `fx-dork-sweep.md` | Google/Bing dork sweeps — Telegram ecosystem, doc-hosts, filetype families + 4-tier free fallback cascade (WebSearch → Bing → DDG → agent-browser) + Tier 5 SerpApi (metered, failed queries only) |
| `fx-document-leak-hunt.md` | 18-platform document leak discovery with severity classification, paywall handling, auto-snapshot |
<!-- dork-integration:phase-05 end -->
| `username-osint.md` | 3000+ platform enumeration with pivot extraction; §7 identity linkage standard — claim ladder L1 string → L2 controller → L3 person → L4 named identity, handle rarity, stylometry/graph/account-trafficking limits |
| `phone-osint.md` | Carrier lookup, VoIP detection, spam databases, FreeCNAM CallerID, WhoCalld, USPhoneBook reverse lookup |
| `email-osint.md` | Full email investigation: accounts, breaches, infra, Proton API, PGP keys, permutation, manual reference tools |
| `fx-dns-cert-history.md` | Historical DNS records (passive DNS, A/NS/MX changes), CT certificate timeline (crt.sh + backup chain, per-source status, completeness line), pivot hits as "Related hosts (unverified)" + origin checks; §2.6 passive-DNS maliciousness checks with confounders, §2.7 temporal pivot rule (co-resolution links only on overlapping windows) |
| `threat-intel.md` | AbuseIPDB, GreyNoise, OTX, VirusTotal, **URLScan.io**, **CIRCL CVE**, **NVD API**, **ransomware.live** |
| `web-traffic-analysis.md` | SimilarWeb/Semrush estimation, audience data |
| `secret-scanning.md` | Credential/secret detection in repos and pastes |
| `github-osint.md` | GitHub user/org/repo profiling, code search, commit metadata, forks, collaboration networks |
| `domain-advanced.md` | Subfinder, Amass, CT log enumeration; NXDOMAIN/DGA triage (lead generator); botnet/C2 estate reconstruction from independent vantage points |
| `social-media-platforms.md` | Twitter/X Snowflake IDs, Discord, Strava, BlueSky, ShareTrace share link analysis |
| `advanced-geolocation-techniques.md` | Overpass Turbo, road sign analysis, reflected text |
| `web-dns-forensics.md` | Zone transfers, Tor lookups, GitHub, Telegram, WHOIS, Xeuledoc Google doc intel |
| `fx-visitor-intelligence.md` | Visitor stats, tech stack, geo, traffic sources, analytics/AdSense/advertising ID cross-domain linking, competitors |
| `wifi-ssid-osint.md` | WiFi SSID/BSSID geolocation via Wigle.net, encryption analysis, travel patterns |
| `scam-check.md` | Phishing/scam domain verification and detection |
| `cloud-audit.md` | Cloud infrastructure security (AWS/GCP/Azure): IAM, network, storage, compute, logging, secrets |
| `microsoft-tenant-recon.md` | M365/Azure tenant enumeration — federation, tenant ID, Azure AD config, MDI detection |
| `china-recon.md` | China/Sinophone layer — ICP filing → PRC entity + licence-serial sibling pivot, GSXT/信用中国/TianYanCha/QCC/Aiqicha registry chain, USCC validation, Quake/ZoomEye/FOFA cyberspace engines, Baidu dorking, CJK pinyin + Traditional variant generation, CN social platforms, access-reality gaps |
| `fiat-payment-osint.md` | Bank accounts as selectors — IBAN mod-97 validation + BBAN decomposition, BIC, VN/SEA non-IBAN rails (VietQR/NAPAS BIN), account-reuse pivot, mule-pattern signals; EMVCo / VietQR parser (CRC-verified) → typed `bank_account` selector `bank:<cc>:<bank-id>:<account>`, kit rung, `which_cases` across cases |
| `drainer-investigation.md` | Wallet-drainer heuristic over the page + captured JS — connect library, approval-harvest calls (setApprovalForAll / Permit2 / eth_sign), legitimate-app markers → `web3-site` / suspected drainer pattern (untested heuristic); drainer contracts are kit rung, never payee wallets (`artifacts.web3`, `drainer_markers.json`) |
| `fx-edge-appliance-recon.md` | Edge/VPN appliance fingerprint → CISA KEV/CVE catalog (Citrix/F5/Cisco/Ivanti/Forti/PAN/Exchange) + exposed-service port-risk matrix + passive patch-lag inference (scan-index uptime → "no reboot since", announced build → lag after advisory), passive-first |
| `fx-saas-identity-recon.md` | SaaS tenancy + identity-fabric mapping — DNS-TXT tenancy tokens, IdP fingerprinting (Okta/Auth0/OneLogin/Ping/Keycloak/ADFS/Entra), unauthenticated API/GraphQL/OpenAPI-spec discovery |
| `fx-supplier-exposure.md` | Supplier map from collected DNS/mail/cert/document evidence — TXT verification tokens, SPF includes, MX, NS, cert issuer, document metadata and CNAME chains (`artifacts.cnames`, from `wp_recon.detect_cnames` on the collected host; guessed `www`/`sso`/`mail`/`status` under an apex only on organisation cases, `scope.json` `subject_type=org` — those queries reach the target's authoritative DNS) — via `wp_suppliers.py` → `cases/<id>/suppliers.json` (`references/suppliers.json`) + per-supplier third-party risk: public breaches, KEVs in supplier products, stealer infections among supplier staff carrying the subject. A supplier is a relationship of the subject, never an operator link |
| `dependency-audit.md` | Supply chain security: CVE audit, framework-specific vulns, typosquatting, CI/CD security |
| `disk-forensics.md` | Digital evidence analysis: image integrity, Sleuth Kit, file carving, artifact recovery, timeline |
| `incident-triage.md` | Security incident response: NIST 800-61 methodology, containment, evidence preservation, IOC extraction |
| `owasp-audit.md` | OWASP Top 10 (2021) source code audit with grep patterns and CWE references |
| `prompt-injection-audit.md` | AI/LLM security: prompt injection classes, agent/MCP security, permission boundary audit |
| `stealer-log-analysis.md` | Infostealer-log triage: family fingerprinting (RedLine/Vidar/StealC/Lumma/META/traffer), victim-vs-operator profiling, cross-log actor correlation, IOC + attribution extraction (`uv run` parser, raw artifacts shown) |
| `agent-browser.md` | Interactive browser collection & evidence capture via vercel-labs/agent-browser (CDP, accessibility-tree `@eN` snapshots, screenshots; primary interactive collector, complementary to Scrapling) |
| `media-vision-analysis.md` | Image/A-V *content* analysis — vision OCR + sign/landmark/logo/face read (`multix gemini`, Gemini) and FFmpeg keyframe/audio preprocessing → transcription; extracted text/GPS/entities re-enter the pivot loop (standalone `npx` multix + `ffmpeg`, no AgentKit/sibling-skill dep) |
| `phishing-domain-survival.md` | Registration/DNS strategy profiling — maliciously-registered vs **compromised** classification + takedown-survival outlook from WHOIS/DNS (`scripts/phish_domain_survival.py`, offline, zero-dep); eCrime 2026 "Built to Last?" |
| `clickfix-clipboard-hijack.md` | ClickFix / PasteJacking clipboard-hijack detection — clipboard-write + lure + OS-command co-occurrence, decodes PowerShell `-EncodedCommand` → C2 IOCs (`scripts/clickfix_detect.py`, offline, zero-dep); eCrime 2026 "PasteJacked" |
| `visibility-aware-html.md` | Visibility-aware HTML analysis — hidden credential forms / off-origin links / off-screen brand text a naive parser misses (`scripts/html_visibility_analysis.py`, offline, zero-dep); eCrime 2026 "Visibility-Aware HTML Analysis" |
| `apk-permission-scope.md` | APK permission-scope risk scoring — dangerous-permission combos (accessibility+overlay+SMS) = on-device-fraud capability; combination is the signal, capability≠guilt (`scripts/apk_permission_scope.py`, offline, zero-dep); eCrime 2026 "The 'Allow' Reflex" |
| `kit-template-attribution.md` | Phishing kit/template structural fingerprint + similarity → same-kit lineage; commodity-template match graded as noise, never auto-merged (`scripts/kit_template_fingerprint.py`, offline, zero-dep); eCrime 2026 tree-structured attribution; named kit signatures (`kit_signatures.json`, ships unseeded) → `artifacts.kit_matches`, kit-rung facts |
| `renderer-confirmation.md` | Renderer-level confirmation of ClickFix + visibility — feeds runtime clipboard writes / computed-hidden elements into the static detectors and reconciles (`scripts/render_confirm.py`; renderer optional, degrades to a note); eCrime 2026 PasteJacked + Visibility-Aware HTML |
| `phishtrace-dynamic-features.md` | Runtime-trace phishing characterization — redirects / exfil endpoints / cloaking; exfil hosts are IOCs not attribution; thin trace on a flagged page = cloaked, never benign (`scripts/phishtrace_features.py`, offline, zero-dep); eCrime 2026 "PhishTrace" |

---

## 7. Workflow Guides

Reference directory: `workflows/`

| Guide | Intended User | File |
|-------|--------------|------|
| Journalist Source Verification | Journalists verifying claims | `wf-journalist.md` |
| HR Screening | HR professionals running background checks | `wf-hr-screening.md` |
| Cyber Threat Intelligence | Security analysts tracking adversaries | `wf-threat-analyst.md` |
| Emerging-Threat Response | CTI analysts answering a CVE, advisory, campaign, actor or supply-chain trigger for a defended organisation: triage, exposure, Threat Advisory, Threat Assessment, hunt package, acknowledgments, +7/+30-day checkpoints | `wf-emerging-threat.md` |
| Private Investigator | Licensed PIs running person cases | `wf-private-investigator.md` |

Activate via `/flow [type]` — interactive guided prompts walk through each step.

> **Emerging-threat trigger** (CVE, vendor advisory, campaign, actor profile): run the response per `workflows/wf-emerging-threat.md` — Admiralty-graded intake, Axis 1 → provisional tier, five-dimension exposure (passive vs consumer-owned), Axis 1 × Axis 2 tier (`/exposure --model tier --case`), Advisory then house-report Assessment, `cases/<id>/distribution.jsonl` acknowledgments, +7/+30-day re-runs.

> **Does the consumer even log this?** Emerging-threat detection exposure starts here: `intel_engine/IntelAnalysis/references/telemetry_baselines.json` maps each telemetry need to its audit subcategory, the Windows default, the Yamato / Microsoft / ASD baseline settings and the log-size floor (adapted from Yamato Security's EventLog-Baseline-Guide, MIT, pinned). The consumer — never cti-expert — runs Hayabusa / Takajō (Windows logs), Suzaku (cloud logs) and Senrigan (CloudTrail) on their own data with the rules in `hunt_rules_yamato.json`; a reported match keeps the rule's DRL `author` field (`workflows/wf-emerging-threat.md` §2, §3.4).

> **Hunt handoff** (the consumer holds telemetry): `intel_engine/IntelAnalysis/references/hunt_packages.json` is a **link-only** index of 67 published hunting queries (ES|QL/EQL/KQL/Sigma/SPL from the MIT-licensed Packt companion repo, pinned to one commit), grouped by ATT&CK tactic — each with an ABLE hypothesis, CAR-style telemetry, prerequisites, method and false-positive notes. Pick by ATT&CK id → tactic → the consumer's telemetry; every query is validated in the consumer's environment with baselines from their own data; cti-expert never runs them. Includes the Time-Terrain-Behavior diversity score and its velocity extension for machine-speed activity. Procedure: `workflows/wf-threat-analyst.md` Phase 5, "Hunt package library". A second link-only index, `intel_engine/IntelAnalysis/references/hunt_rules_yamato.json` (generated by `IntelAnalysis/scripts/build_yamato_index.py`), maps 389 ATT&CK techniques to Yamato Security's Sigma rules — hayabusa-rules for Windows event logs, suzaku-rules for AWS/Azure/M365/Google Workspace (DRL 1.1: keep each rule's author on any shared rule or reported match) — and 187 Senrigan hunts (AGPL-3.0: 139 CloudTrail, 30 Suzaku-timeline, 18 VPC Flow Log); every document of a Sigma correlation file (correlation rule and its base rules) is indexed and is a valid `hunt_package_ref`; titles and metadata only, no detection logic. The consumer runs Hayabusa/Takajō, Suzaku or Senrigan on their own logs; cti-expert links them and never bundles or runs them.

---

## 8. Output Formats

Reference: `output/reports/`, `connectors/`

### Conversational domain table — show this in chat on every collection turn (CRITICAL)

Whenever a collection command (`/cti`, `/case`, `/sweep`, `/webpivot`, `/subdomain`, or the
pipeline) returns one or more domains, the reply's **first** element — before any prose — is a
markdown table summarizing each domain, so the operator sees the yield at a glance **in the
conversation**. The §8 file exports are the durable record; this table is the live view and is
never skipped, even for a single domain.

| Domain | Resolves | Top pivots | Risk | Cluster / peers | Seen before |
|---|---|---|---|---|---|
| `site-a.example` | ✓ | `favicon:123456789` · `G-XXXXXXXXXX` | NRD, BPH | 3 peers | CASE-0001 (Operator A) |
| `site-b.example` | ✓ | `registrant@example.com` | — | 3 peers | new |

Columns: **Resolves** ✓/✗ (collector got a host); **Top pivots** the 1–3 highest-rung indicators
(§2.5 ladder) as `kind:value`; **Risk** the `risk_signals` flags (NRD / BPH / money-trail, or `—`);
**Cluster / peers** shared-indicator peer count from the KB; **Seen before** the prior case +
operator from `/recall`, or `new`. Keep to these columns — detail goes in the prose below. One row
per domain; for a large sweep show the top 20 by risk and note how many rows were omitted.

### Actor threat-profile report

A case can be delivered as an **actor threat profile**: put `actor_profile` (one object — name,
aliases, attribution {assessment, likelihood term, confidence, dissent}, activity timeline, intent,
capability, victimology, persona/OPSEC, `tempo_summary` / `tempo_ref`), `claim_confidence`,
`pivot_opportunities`, `playbook` (one row per ATT&CK tactic), `hunt_hypotheses` (HH-nn, priority
telemetry, behavioural signals, optional `hunt_package_ref` into `hunt_packages.json` or
`hunt_rules_yamato.json` — a Sigma rule id, including a correlation's base rules, or a Senrigan CloudTrail / timeline / VPC-flow hunt id) and
`telemetry_priorities` in the `report` block (schema: `evidence_import.json`). The house report
renders one **Actor Profile** chapter after Findings (with a derived ATT&CK coverage table that
points to `attack_mapping` MAP-nn rows); REPORT.json, HTML and DOCX carry it in the same order.
Attribution always prints its ICD-203 likelihood term and confidence, and every dissent line is
shown. The Threat Score is read only from `cases/<id>/actor_scores.json` (`/exposure --model
actor --case`) — a lead, never attribution (RULE 5). Lint: attribution without likelihood or
confidence, intent without evidence, a High claim without sources, a hunt hypothesis without
telemetry or signals, a playbook ATT&CK id without evidence, a Critical key finding at P4, a
`hunt_package_ref` that is not an id in the hunt indexes (`hunt_packages.json`,
`hunt_rules_yamato.json`; any index missing: one "refs not checked" warning), a `tempo_ref` that is not a case-relative
`<stem>_events.json` ledger from `case_timeline --tempo` (optionally `#operator_tempo`) or whose
ledger lacks an `operator_tempo` read, and a non-empty `tempo_summary` while that read is
`insufficient` — QA warnings only, never import rejections.
Key findings accept the Severity Tier Matrix **P4** ("track only — no deadline"); roadmap stays
P1–P3. Schema and a synthetic example: `handbook/report-template.md`.
`telemetry_priorities` rows may carry `baseline_ref`, a key into `telemetry_baselines.json` `settings`
(the Windows audit setting that produces the source). Lint warns when a ref does not resolve; a
missing map gives one warning, never a failure. A resolved ref is printed after the row's Why as
"— Windows audit setting: <name> (<event IDs>)" in every output, and REPORT.json carries it as
`baseline_setting`; rows without a resolvable ref render unchanged.

### Deliver contract (CRITICAL)

**MUST read [`handbook/report-export.md`](handbook/report-export.md) before the Deliver phase of any
`/report`, `/brief` or `/case` run** — it holds every step, the generator commands, the report-JSON
schema, the report formats, the visual outputs and the connectors. In order:

1. **Import prompt (Step 0).** First ask, via `AskUserQuestion`, whether to import more evidence
   collected by manual investigation (findings, subjects, indicators, selectors, timeline events,
   sources, screenshots, notes) and merge it into the report JSON before anything is built.
2. **Base bundle (Step A) — always saved, no prompt:** `CTI-REPORT-[CASE-ID]-[YYYY-MM-DD]` `.md` +
   `.json` + `.csv`, plus the IOC / selector bundle `IOC-[CASE-ID]-[YYYY-MM-DD].{stix.json,txt,csv,jsonl}`.
3. **Presentation prompt (Step B).** Then ask which report to render — (a) PDF · (b) DOCX · (c) HTML ·
   (d) All — and build it on top of the base bundle; when HTML is among them, confirm the export and
   its Blueprint mode first (Step C). Explicit `/report html|docx|pdf|json|csv|ioc` skips this prompt.
4. **`--yolo` / guided-auto / non-interactive:** skip all three prompts and render **HTML** (Blueprint
   in Auto) on top of the base bundle. **`/report legal`** defaults to **All** (PDF + DOCX + HTML).
5. **Pipeline cases (`/cti` · `/case` · `/harness`):** build the report JSON with
   `scripts/build_report_data.py` from the case directory — never by hand. A hand-built JSON is only
   for a report with no case dir.
6. Every artifact carries the CTI Expert attribution credit, the Markdown and JSON pass the dash
   normalizer, and every saved file is confirmed to the user.

---

## 9. Skill Tiers & Customization

Reference: `experience/skill-tiers.md`, `experience/layered-detail.md`

### Tiers

| Tier | Command | What Changes |
|------|---------|-------------|
| **Novice** | `/novice` | Jargon removed, steps explained, glossary auto-linked |
| **Practitioner** | (default) | Standard output, moderate detail |
| **Specialist** | `/novice off` | Full technical detail, raw findings, internal signals |

Switch tiers at any point — output adapts immediately.

### Guided Flows

`experience/guided-flows/` contains step-by-step interactive flows:

- `person-investigation.md` — Full guided person case
- `domain-reconnaissance.md` — Guided domain sweep
- `email-investigation.md` — Guided email tracing
- `rapid-case.md` — 10-minute abbreviated sweep

Activate: `/flow person` · `/flow domain` · `/flow email` · `/flow quick`

### Case Templates

`experience/case-templates/` contains pre-built starting configurations:

- `due-diligence.md` — Corporate partner vetting
- `security-audit.md` — Organization exposure audit
- `background-check.md` — Individual background research

Activate: `/template run [name]`

---

## 10. Ethics & Boundaries

This skill operates strictly within publicly available information.

### Permitted

- Journalists verifying facts about public figures or institutions
- Security professionals auditing their own organization's exposure
- Individuals reviewing their own digital footprint
- Corporate due diligence on business partners
- Academic research and educational demonstrations

### Prohibited

- Stalking, harassment, or doxing of any individual
- Accessing accounts or systems without authorization
- Social engineering or deception campaigns
- Any activity violating applicable law

Ethical reminders are issued automatically when the investigation approaches sensitive territory. Public data is not a license to cause harm.

---

## 11. Autonomous Mode (--yolo)

Append `--yolo` to any command or activate at session start.

**What changes:**
- No clarifying questions — analyst infers context and proceeds
- No confirmation prompts — scope expands automatically on new discoveries
- Guided flows skip Q&A — reasonable defaults applied
- Both `/report` and `/brief` generated without asking — the presentation-format prompt and the HTML export confirmation are skipped; defaults to **HTML** (Blueprint in Auto mode) on top of the always-saved base data bundle (.md + .json + .csv + IOC .stix.json/.txt/.csv/.jsonl)

**What stays the same:**
- Ethics and legal boundaries — always enforced
- Trust scores on every finding
- Source citations on every claim
- `/validate` and `/coverage` run before final delivery

Activate per-command: `/case target.com --yolo`
Activate for session: `/cti-expert --yolo`

---

## 12. Architecture Reference

cti-expert is **one skill, two layers**: the **broad collector** (cti-expert's own `scripts/`,
`techniques/`, `handbook/`, report generators and docs) and the **vendored `intel_engine/`
deep layer** (pipeline chains, case state, harness loop and the MCP tools).

- [`handbook/architecture-reference.md`](handbook/architecture-reference.md) — the annotated
  directory tree; read it to find where a capability lives.
- [`STRUCTURE.md`](STRUCTURE.md) — the two-layer layout and the anti-drift rules.
- [`connectors/intel-backend.md`](connectors/intel-backend.md) — backend tiers and the op map.

---

## Technique Activation Matrix

**MUST read [`handbook/technique-activation.md`](handbook/technique-activation.md) before the Acquire phase of any `/case` or `/cti` run.**
It holds the per-target-type matrix of techniques that fire without being asked, the five v2.6 commands (`/icp`, `/cn-corp`, `/iban`, `/hash-id`, `/redact`),
the recursive pivot orchestration defaults, and the leak / GitHub / dork / M365 auto-fire rules.

---


## Tool Priority & Fallback

**Primary interactive collector: [`agent-browser`](https://github.com/vercel-labs/agent-browser)** (vercel-labs) — a fast native-Rust CDP browser that returns accessibility-tree snapshots (`@eN` element refs) + screenshots; **no API key** for core automation; cross-platform; also an MCP server. Full how-to + per-command usage in [`techniques/agent-browser.md`](techniques/agent-browser.md). It is **complementary to Scrapling, not in conflict** (different ecosystems — Rust binary via npm/brew/cargo vs Python via pip — each manages its own browser): use **agent-browser to *interact with and witness* a page** (logins, clicks, screenshots, JS render) and **Scrapling to *fetch and parse* pages programmatically**.

1. Check `agent-browser` first (`agent-browser --version`; load its guide via `agent-browser skills get core`; install per the auto-install policy if missing)
2. Use `agent-browser` for: screenshot evidence, logins/interactive UI, JS-rendered/SPA pages, complex multi-step browser flows
3. Use Scrapling DynamicFetcher for: JS-heavy sites, SPA content, auto-escalation from static (programmatic)
4. Use Scrapling StealthyFetcher for: anti-bot bypass, Cloudflare-protected targets
5. Use Scrapling Fetcher for: fast static page collection, HTML parsing (~2ms)
6. Fall back to web search → web fetch → direct curl — no investigation blockers
7. Tag each finding with collection method: `[browser]` · `[scrapling-dynamic]` · `[scrapling-stealth]` · `[scrapling-static]` · `[vision]` · `[vision-local]` · `[media]` · `[search]` · `[fetch]` · `[manual]` · `[whois-lib]` · `[whois-cli]` · `[whois-api]`

### Media Evidence Analysis — vision (multix/Gemini) + video (FFmpeg)

Screenshots, photos, scanned documents, and audio/video are **nodes, not dead ends** — analyze the *content*, don't just fingerprint the file. These tools are **native to this skill** (no AgentKit / sibling-skill dependency, so a bare clone works): the vision layer is the standalone [`multix`](https://github.com/mrgoonie/multix-cli) CLI run via `npx`, the media layer is `ffmpeg`/`imagemagick`, provisioned by the Tool Auto-Install Policy. **Keyless by default:** with no `GEMINI_API_KEY`, OCR/sign-read/transcription fall back to the host agent's own multimodal read + `tesseract` OCR + local Whisper (`whisper-ctranslate2`) — a key only upgrades quality/scene-reading. Full workflow: [`techniques/media-vision-analysis.md`](techniques/media-vision-analysis.md). A missing key/binary logs a collection gap, never blocks.

- **Images / screenshots / documents → vision** (`multix gemini`, Gemini; reads `GEMINI_API_KEY` from env or the skill's `$SKILL_DIR/.env`). Read text a parser can't (OCR a Telegram-bio screenshot), read signage / landmarks / reflected text for geolocation, describe logos and faces for correlation, or pull structured fields:
  - `npx --yes --prefer-online --package=@mrgoonie/multix@latest -- multix gemini analyze --files EVIDENCE.png --prompt "OCR all text; describe location cues, signage, landmarks, logos, faces" --format markdown --output vision.md`
  - `npx --yes --prefer-online --package=@mrgoonie/multix@latest -- multix gemini extract --files EVIDENCE.png --prompt "Extract handles, emails, phones, wallet/IBAN, org names as JSON" --format json --output vision.json`
- **Video / audio → preprocess with FFmpeg, then vision.** Extract keyframes and the audio track first, then analyze/transcribe them:
  - Keyframes → `ffmpeg -i clip.mp4 -vf "fps=1/5" frame_%03d.png`, then feed each frame to `multix gemini analyze`
  - Audio → `ffmpeg -i clip.mp4 -vn -c:a copy audio.m4a`, then `... multix gemini transcribe --files audio.m4a --prompt "Transcript with timestamps" --format markdown --output transcript.md`
- **Feedback into the pivot loop.** OCR'd handles/emails/phones, extracted GPS/landmarks, transcribed names, and read logos become new seeds and re-enter the Enrich loop ("Recursive pivot orchestration" in [`handbook/technique-activation.md`](handbook/technique-activation.md)). Face matches stay **held pending corroboration**.
- **Tags:** mark such findings `[vision]` (multix) and `[media]` (ffmpeg/imagemagick preprocessing).
- **No Gemini key? Keyless fallback (own models).** OCR + sign/landmark/logo/face read → the **host agent's own vision** (read the image in-session — Claude Code/Codex are multimodal) plus `tesseract` for dense OCR; A/V transcription → **local Whisper** (`whisper-ctranslate2`, offline) after the same `ffmpeg` audio extraction. A `GEMINI_API_KEY` only upgrades quality. Tag these findings `[vision-local]`.

---

## Tool Auto-Install Policy

**Before running any CLI tool, detect the OS, check whether the tool exists, and if not, install it automatically and silently using the method correct for that OS.** This ensures zero-friction investigation on Windows, macOS, and Linux alike — the analyst never stalls on a missing dependency and never runs a Linux-only command on Windows.

> **Full cross-platform reference:** [`scripts/platform-setup.md`](scripts/platform-setup.md) — OS detection, `$PY`/shell conventions, package managers, the complete per-tool × per-OS install matrix, and known gotchas. Consult it whenever this summary is not enough. **Read §8 of [`scripts/platform-setup.md`](scripts/platform-setup.md#8-the-skills-install-procedure-step-by-step) before the first install of a session** — it holds the step-by-step procedure (platform detection, uv bootstrap, the auto-install protocol and the per-category install dispatch).

### Behavior Rules

- **uv first (anything Python):** prefer uv — `uv tool install` for CLIs, `uv pip install` for libraries, `uv run` for scripts. It behaves identically on every OS, so reach for it before per-OS pip/pipx. Fall back to `<$PY> -m pip` / `pipx` only when uv cannot be installed.
- **Detect before install (system binaries):** dispatch by the OS detected in Step 0 — never run `apt` on Windows or `winget` on Linux.
- **Silent install:** do not ask permission — install and proceed. Tool installation is a normal part of the investigation workflow.
- **Go tools:** require Go installed. If `go` is missing, install it via the OS package manager (`winget install GoLang.Go` / `brew install go` / `sudo apt install -y golang`), or note the gap and fall back to the next tool in the cascade.
- **Linux privileges:** system installs need `sudo` unless running as root.
- **Windows specifics:** `winget` may prompt UAC; a freshly installed tool may not be on PATH until the shell is reopened (probe its install dir or restart the shell before declaring failure). The DOCX generator self-heals UTF-8 output and pandoc location — see `platform-setup.md` §6.
- **Git-based install:** for tools without a PyPI package (msftrecon, blackbird, sharetrace), clone the repo and install its `requirements.txt` with `<$PY> -m pip install -r requirements.txt`.
- **Fallback on install failure:** if installation fails, log a collection gap and skip to the next tool in the cascade — never block the investigation.
