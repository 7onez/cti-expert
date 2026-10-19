---
name: cti
description: "THE ENTRY POINT for cti-expert. Investigate any target — domain, IP, email, username, phone, wallet, hash or APK. Routes to the right chain automatically. Usage: /cti <target> [--deep|--quick|--passive]"
argument-hint: "<target> [--deep|--quick|--passive]"
---

# /cti — cti-expert entry point

**Load the `cti-expert` skill now**, then investigate: `$ARGUMENTS`

This is the single entry to the whole toolkit. Everything else (`/cti-recall`, `/cti-case`,
`/cti-pivot`, `/cti-cluster`, `/cti-check`, `/cti-report`, `/cti-status`) is a shortcut to one
step of what this command does end-to-end.

## Step 0 — ALWAYS FIRST: have we seen this before?

Run `recall` on the target before spending a single API credit. A known seed carries prior case
context and possibly an existing operator attribution — re-investigating it wastes credits and
risks contradicting a published assessment.

- **T1:** `mcp__intel__domain_verdict` + `mcp__intel__which_cases`
- **T2:** `python3 scripts/backend/intel.py recall <seed>`

If it is already attributed, **report that and stop** unless the user asks to extend the case.

## Step 1 — Match the target and auto-run its route

Classify `$ARGUMENTS` before invoking a tool. In a full `/cti`, run **every applicable
matching leg below without a second invocation or an opt-in prompt**; a seed is not complete
after its first successful lookup. For each result, classify newly discovered identifiers
and repeat Step 2c. `--quick` is the explicit one-pass exception (see Flags). Deduplicate
by `(tool, normalized selector)` and use the case memo where available. Do not send a name,
brand, favicon, JARM or certificate fingerprint to a file-hash/IoC endpoint.
Use SKILL.md §Technique Activation Matrix for the rest of the target-matched techniques
(e.g. `/icp` for domains, MSFTRecon only on M365 DNS, `/cn-corp` on a company/USCC,
`/iban` on payment details, and `/hash-id` on discovered hashes). A checkmark means
**eligible when its input/precondition exists**, not permission to send every source
an unrelated selector. This is agent-orchestrated after `pipeline open`, not a claim
that `pipeline open` alone runs the identity/OSINT commands.

| Target looks like | Automatically run (in addition to recall and applicable Step 2c legs) |
|---|---|
| domain / URL | Step 2 pipeline (already runs host-matched CLD Feeds + Shield when keyed), then convergence and Step 2c; do not run `cld route` again on that host |
| person / organization name | `/query` + `/dork-sweep` and `/docleak` on the name; `/cn-corp` for a surfaced company/USCC, `/icp` on an identified domain, `/github-osint` only for a verified developer handle/account; keyed `cld ransomware <org>` and `cld internal-leaks <org>` for a real organization, not privacy/proxy boilerplate |
| bare IP | `pivot_extract` in IPPivot mode (ASN, co-tenancy, ports, passive DNS); keyed `cld route <IP>`; treat co-tenants as leads, not owner links |
| email | `email-deep <email> --case <case-dir>` (one IntelX search + reverse-WHOIS preview, bounded purchase); keyed `cld route <email>` for Feeds burner + Shield email IoC; `github-osint` only when a developer link exists; dork sweep on the address and its domain |
| username / operator handle | `username <handle>`; keyed `cld actor-usernames <handle>` only for an operator handle, never a brand social account; pivot on exposed emails; dork sweep |
| phone number | `phone <number>` + dork sweep; keyed `cld route <number>` (Feeds phone + Shield IoC); reverse-WHOIS preview only when it is a verified registrant contact, not a number scraped from page text |
| crypto wallet / IBAN | chain tracing in **and out** for wallets (outbound can identify cash-out); `/iban` validation for IBAN; IntelX on a strong selector when keyed; never route an unsupported selector to CLD |
| file hash / APK / EXE | `/hash-id` first for any hash; `analyze_artifact` for local files; keyed `cld ioc hash <hash>` only for a confirmed **file hash**, never an ambiguous 64-hex cert fingerprint or a credential hash; never submit a sample to a public sandbox without the required confirmation |
| Telegram handle / `t.me` URL | keyed `cld route t.me/<handle>` (Shield Telegram posts), not the domain route on `t.me` |
| Facebook / Instagram / TikTok / LinkedIn URL, share link or handle | **Social intake (SKILL.md §2.5 "Social-media seed intake") — not the domain route on the platform host.** `sharelink <url>` (unwraps login walls → `platform_ids`; `--no-follow` for a pasted wall URL) → `meta-transparency <page-or-@handle> --case <case>` for Facebook/Instagram (tri-state fields + Wayback name/bio history) → `username` / `email-permute` on every discovered handle and display name → leak fan-out on the confirmed account usernames, business emails and phones (Step 2a) → relay the tool's `capture_checklist` to the analyst in round 1 (logged-in screenshots of Page transparency → See all, Ad Library Page → About, IG → About this account). **Never request cookies, session tokens, passwords or HAR files.** Account linkage (linked IG, owning organisation, admin countries, sharer id) ≠ owner identity |
| CVE / `.onion` | keyed `cld route <selector>` (matching vulnerability / onion lookup); do not treat a CVE as a file hash |

`cld route` itself selects matching Feeds and Shield endpoints; never fire every vendor endpoint
for every target. If the key is absent, a leg is unavailable; if `--passive` or case scope forbids
it, skip with that reason. Keep no-spend separate from egress posture; `--free-only` and
`scope.json` `no_spend` prohibit metered calls even when they contact only a third-party corpus.
Ambiguous input: state the reading chosen and proceed, asking only when two readings require
materially different work.

## Step 2 — Run the cross-type harness loop (default engine), don't hand-run collectors

For any seed type (domain, URL, email, phone, IP, hash, wallet, Telegram handle, filename or
string), run the `cti` driver. It recalls, then runs the **cross-type harness loop**:
- typed pivots on every selector type;
- a read-only Plan phase that ranks and adds pivots;
- free work (and urlscan Pro, quota-backed) within 25 hits runs on its own;
- every metered, oversized or unknown-size pivot waits in `cases/<CASE-ID>/proposal.json` for
  the analyst's approval.

Your typed seeds collect with the keyed layers. Every host the loop finds collects free-only,
and its keyed enrichment is an `enrich.host` proposal item.

```bash
python3 scripts/backend/intel.py cti <target> [--case <CASE-ID>] [--depth N] [--deep] [--free-only]
python3 scripts/backend/intel.py harness approve <CASE-ID> --only <ids> [--reject <ids>]   # unlisted = deferred
python3 scripts/backend/intel.py harness continue <CASE-ID>
```

**Confirm before launching.** A harness run collects live, runs LLM phases for tens of minutes,
and spends on your typed seeds. State the target, the case id, the rounds and the spend posture,
and start it only after the analyst agrees (project rule: confirm before harness/pivot runs).

**Ask the analyst** before approving: show the proposal table (`harness approve <CASE-ID> --show`
or `case_approve` without `confirm`), and approve only the ids they name. Unlisted items are
deferred, not dropped; only `--reject` drops one for good. The MCP `cti` tool starts the harness
run in the background and returns the case id and log path; check it with
`harness status <CASE-ID>`.

**Fallback — the deterministic pipeline** (no LLM), used for `--pipeline`, `--quick`, `--passive`
(no live contact, no chase loop), inside a harness run (never nested), or automatically when no
harness backend answers before anything was collected:

```bash
python3 scripts/backend/intel.py pipeline open <CASE-ID> <seeds-file>
```
Discovered APK/installer links are downloaded into `cases/<CASE-ID>/bin/`; static JSON is stored
under `bin/analysis/<sha256>.json` and ingested into the KB without adding a web-host row.

Binary identifiers belong to the file; a shared download host is not a same-operator link.

A configured `ANYRUN_API_KEY` also submits the saved file on a spending run; `--free-only`,
case `no_spend`, hostile posture, or the default free-only `loop` suppress submissions.
A public-only ANY.RUN plan is refused unless `ANYRUN_ALLOW_PUBLIC=1` is explicitly set;
public tasks expose the sample worldwide and cannot be recalled.


Hand-running a collector is a fallback, not the default. If you do it, **say so in the write-up**
— evidence archiving, the versioned assessment and the convergence check will not have run.

## Step 2a — Leak coverage on confirmed selectors (MANDATORY, round 1)

Leak/stealer checks are not a follow-up the analyst has to ask for. The harness runs them
itself right after round-1 collection, **before** the cross-type step, so metered
co-tenant/frontier pivots can never starve them; the pipeline runs them inside `enrich`.
They cover every **confirmed** selector: analyst seeds, owner-rung nodes, WHOIS registrant
email/phone of seed and first-hop hosts, owned seed domains, and social-intake account
usernames. Kit- and neighbour-rung selectors (co-tenants, shared-kit hosts, exchange
counterparties) are **never** leak-checked.

| Selector | ChongLuaDao | IntelX | Hudson Rock | deep_profile |
|---|---|---|---|---|
| email | `exposure --type email` | via deep_profile | via deep_profile (`search-by-login/emails`) | email/breach chain |
| username / handle | `exposure --type username` | n/a (soft selector) | `search-by-login/usernames` | n/a |
| phone | `route` (checkphone + IoC) | `search --logs-only` | n/a (no phone endpoint) | n/a |
| owned domain | `exposure --type domain` | `search --logs-only` | `search-by-domain` | n/a |

```bash
python3 scripts/backend/intel.py enrich <CASE-ID> --leak-only [--free-only]   # rerun / resume; idempotent
```

The spend gate still applies: `--free-only` or `scope.json` `no_spend` runs only the keyless
CLD leg, and each metered vendor is written as `not_consulted` with the hold reason. Missing
keys read `not_consulted` with the key name, never as clean. Results land in
`cases/<CASE-ID>/enrichment/leak_coverage.json` (one row per selector × vendor:
`hit` / `clean` / `not_consulted` + reason), in the assessment's "Leak / stealer coverage"
table, in the `cti` JSON line (`leak_coverage`) and as KB `leak_exposure` facts. They are
exposure evidence, never an attribution edge.

## Step 2b — persist the versioned case, then deepen if it hasn't converged

`/case` is an alias of `/cti`. If a separate broad collector **already** produced the
case's raw pivots, persist them with zero extra egress (do not also run the live Step 2):

```bash
python3 scripts/backend/intel.py pipeline open <CASE-ID> <seeds> --no-collect
```

`--no-collect` also defers identity lookups: follow it with
`python3 scripts/backend/intel.py enrich <CASE-ID>`. Use `--free-only` for no-spend
cases; metered leads stay OPEN for a later keyed/full run. `--passive` governs
direct target contact, not third-party credit spend. Then check convergence —
`intel.py convergence <CASE-ID>` and `intel.py frontier <CASE-ID>`. If it has
**not converged** and posture is active (not `--passive`, infra not classified
hostile), **auto-escalate to the `/harness` deepening loop** — keyless-first
(it uses the CLI's own model on your subscription; no separate LLM key),
egress **hard-gated** on hostile infra; `--no-harness` opts out. `intel.py harness doctor
[--backend claude|codex|omp|openai|deepseek|kimi|local]` reports which backend that escalation
would actually run on (probes auth) before it does; `HARNESS_BACKEND` pins one. Full contract:
SKILL.md §2 (AEAD deep-layer note) and the technique-activation / auto-fire matrices for the
`/webpivot`·`/icp`·`/iban`·`/hash-id` auto-fires that also run in a full `/cti` (= `/case`) run.

## Step 2c — Auto-pivot enrichment: leaks · breach · OSINT · dorks (NOT optional)

The deterministic pipeline (Step 2) covers host infrastructure and the collector's CLD
domain/registrant-email legs, **not** the entire identity/exposure surface. A full `/cti`
run remains open until the applicable legs have fired on the seed and each verified,
owner-linked identifier discovered later. "Not queried" is not "not found."

Classify and deduplicate each identifier before following it; only corroborated owner links
become new case seeds. Shared hosting, brand mentions, search hits and email permutations
remain hypotheses, not recursive estate pivots:

| Discovered | Auto-fire (in addition to Step 1; skip duplicate `(tool, selector)` calls) |
|---|---|
| **registrant email** | `/email-deep <email> --case <case-dir>` (Hudson Rock, ZoneCruncher, one IntelX search, OSINT Industries account existence, reverse-WHOIS preview/purchase when bounded). The collector already queried CLD email IoC for this registrant when keyed; do not send a second CLD lookup. No second `/breach-deep`, `/intelx` or `/osint-industries` on that email. `/github-osint` only after a developer link; `/dork-sweep` on email and domain |
| **username / dev handle** | `/username` + `/dork-sweep`; `/email-deep` on exposed verified email; keyed `cld actor-usernames <handle>` for operator handles only |
| **person name** | `/dork-sweep` + `/docleak` (queries to execute, not evidence by themselves); `/github-osint` only after a handle surfaces; `/email-permute` against case-owned domains (hypotheses only) |
| **registrant phone** | `/phone` + reverse-WHOIS preview + `/dork-sweep`; keyed `cld route <phone>`; keyed and spend allowed: `/osint-industries phone <E164> --case <id>` (caller-ID names, registered platforms — historic corroboration, never the number's current holders). Page-text phone is not automatically a registrant |
| **apex / URL** | collector already sent CLD Feeds + host-matched Shield when keyed; no second domain route. Run `/intelx phonebook <apex>` if keyed and spend allowed, `/github-osint` + `/secrets` and `/dork-sweep <apex>`; execute/review generated searches rather than count query strings as findings |
| **registrant organization** | keyed `cld ransomware <org>` **and** `cld internal-leaks <org>` when not privacy/proxy/registrar boilerplate; host search in the collector is not an org search |
| **Telegram handle** | keyed `cld route t.me/<handle>`; never route `t.me` as the operator domain |
| **GitHub account / repo link** | `github <account-or-repo>` for public committer identities; search/secret legs on the account where applicable; re-enter corroborated email/handle results |
| **wallet / IBAN / file hash** | `/intelx search <wallet-or-IBAN>` if keyed; `/iban` for IBAN; `/hash-id` before hash lookup, then keyed `cld ioc hash <hash>` for a confirmed file hash only |

Rules that keep this cheap and correct:
- **`/intelx` takes a STRONG selector only** — email / domain (`*.apex`) / URL / IP / phone / wallet / IBAN. **Never** a brand or person name (refused locally, and a soft term still costs a unit).
- **Reverse-WHOIS is the highest-yield estate pivot** — preview the count before any purchase and **cross-check email vs name**: a name returning unrelated domains is a name collision, not one operator (§2.5). Confirm on the email/phone triple before clustering.
- **Bulk-guard footgun:** `ingest-rwhois` (`--max-domains`, default 25) and `export-graph` (`--max-indicator-degree`, default 25) **silently drop** a legitimate large single-operator estate as "reseller noise." When rung-1 (email+name+phone) already confirms one operator, **raise the threshold above the estate size** (e.g. `--max-domains 60`) or the edge is lost.
- **Posture:** on hostile infra prefer passive corpora (IntelX/Wayback/urlscan); `/intelx` and dorks do **not** touch the target. `--passive` propagates. Never submit the case's own sample to a public sandbox (§2.5).
- **Metered discipline:** `email-deep` may send keyed Hudson Rock, ZoneCruncher, IntelX, OSINT Industries (1 credit) and purchase bounded reverse-WHOIS results; IntelX phonebook and `/osint-industries` on a phone/username also consume vendor credits. `--free-only`, `scope.json` `no_spend`, or `--quick` hold those legs. **ChongLuaDao is unlimited** (no per-call credit / quota) — its legs run under `--free-only` and `no_spend` like a free source; the usage ledger still logs each request but never caps. State what was actually sent and spent.
- **Run and account for every matching lead.** `pipeline open` and each `loop` round run structured leads and checkpoint responses under `cases/<case>/enrichment/` with a readable `index.json`: email-deep, phone OSINT, keyed CLD phone/Telegram/operator org/handle, IntelX phonebook, linked GitHub accounts. Missing keys and `--free-only`/`no_spend` leave metered legs OPEN for `intel.py enrich <case>` or `loop --full`; `--passive` restricts direct target contact, not third-party spend. Empty completed lookups close as `empty`; transient failures stay OPEN. On `--no-collect`, invoke `intel.py enrich <case>` explicitly. **Agent work remains:** `dork-sweep` and `/secrets` emit queries only, and an apex is not a GitHub login. Execute/review those OPEN frontier leads, fold verified results into the assessment, and only then use `intel.py enrichment-done <case> --key <key> --reason ran|empty|unavailable|skipped`. Never mark a generated query as `ran`; report remaining leads and actual credit usage.

## Step 3 — Dead seed? Do not stop

Zero pivots, a parked page or NXDOMAIN is not an answer. Run `fallback_probe` (crt.sh, full
Wayback timeline, archive.today, local KB). A parked apex very often has live subdomains —
enumerate CT and the Wayback CDX host histogram before writing the seed off.

## Step 4 — Apply §2.5 before asserting anything

Read SKILL.md §2.5 (Pivot Priority & False-Positive Control) and obey it:

- Work **down** the priority ladder. Never assert same-operator on a low rung when a higher rung
  is available or contradicts it.
- Run `reference_check` on every indicator before it becomes a cluster edge. Record new verdicts
  with `reference_add`.
- Tag every asserted link with the rung it rests on.
- A cluster resting on a single weak indicator is **"candidate, single-indicator"** — not a member.

## Step 5 — The `cti` driver (one call, machine-readable)

Everything above is the AGENT-orchestrated `/cti`. The engine also ships a driver that sequences
the same cold-start path in one call, useful from a script, a cron, or a sub-agent that needs a
resumable, parseable result:

```bash
python3 scripts/backend/intel.py cti <target> [--case ID] [--quick|--deep|--passive] [--free-only] [--extend] [--quarry|--no-quarry] [--pipeline] [--depth N]
```

It runs `recall`, then stops if the target is already confirmed-attributed (unless `--extend`).
When Quarry is enabled for the case it next waits for the Quarry scan before anything else spends
the same vendor accounts. `QUARRY_ENABLED=ask` (the default) asks once and remembers the answer;
`--quarry` / `--no-quarry` override it. A scan Quarry already finished is reused free. A new scan
waits with no time limit (hours or days; network faults retry, and a rerun resumes the same job), so
launch the driver without a shell timeout (backgrounded, or the MCP `cti` tool, which backgrounds
itself on every path whenever Quarry is on for the case). A no-spend or no-contact case reuses only, never starts one. A failed or
cancelled scan, a rejected key, an error, or an unanswered ask returns `status: awaiting-quarry` and
does not collect — the job is checkpointed, and the next run resumes it. Collection starts only after a
`completed` or `reused` import. Then:
- **Default:** the **cross-type harness loop** runs for `--depth` rounds (3; 6 with `--deep`).
  `--free-only` maps to `--no-spend`. It stops at `awaiting-approval` when paid pivots need the
  analyst; `next` is then `["approve","report"]`.
- **`--pipeline` / `--quick` / `--passive`, inside a harness run, or no harness backend** (nothing
  collected): collect (`pipeline open`
  for a domain/URL; otherwise the type-matched op — `email-deep`/`phone`/`pivot-extract`/`hash-id`/
  `crypto-balance`/`search-pivot`) → `enrich` → a read of `frontier`/`convergence` → `loop` when
  the case has not converged and posture allows.
- Called from inside a harness phase, it always uses the pipeline (no recursion).

The LAST line of stdout is one JSON object:
`{"case":…, "status":…, "converged":…, "open_leads":[…], "next":[…], "engine"?:"harness"}`.
`next` always ends with `"report"`.

`--quick`/`--passive` here match their meaning above (one pass; no loop). **`--deep` is NOT the
multi-agent fan-out** described below — this driver has no sub-agents — it maps onto the `loop`
step's own `--full` (metered engines) and `--deep-archive` flags and a deeper `--depth`, i.e. the
deterministic engine spends more per round instead of spawning more agents.

Two related fixes that make this driver (and `/cti` itself) trustworthy to script against:
`intel.py convergence <CASE-ID>` (no subcommand) now defaults to `status`, matching how it is
documented everywhere above; and `intel.py api-usage --case <CASE-ID>` now finds every ledger row
for that case, including the ones logged by a subprocess the pipeline spawned (WHOIS/FOFA/urlscan/
etc. clients), not only the top-level collector's own rows.


## Flags

- `--quick` — recall + one type-matched collection pass; for a domain pass `pipeline open --no-enrich` so the identity/exposure frontier remains OPEN. Do not close deferred leads as `ran` or `skipped`; a later full `/cti` resumes via `intel.py enrich <case>`.
- `--deep` — **parallel sub-agent fan-out** (see below): expand every discovered identifier as a
  new seed, one sub-agent per seed, until the frontier is exhausted
- `--passive` — no live contact with the target; work from Wayback/urlscan captures only.
  **Use this for any hostile target.**
- `--no-harness` — skip the Step 2b non-convergence auto-escalation to the `/harness` deepening loop

## Deep mode — parallel sub-agent fan-out (`--deep`)

`--deep` turns one investigation into a fleet. You (the orchestrator) do the first pass, then
spawn a **sub-agent per discovered seed** with the Agent tool so pivots run in parallel instead of
one-at-a-time. This is how `/cti --deep` does *powerful* OSINT — breadth-first collection, then a
wave of deep pivots, converged back into a single case.

1. **Seed pass (you run it).** Do Steps 0–2 on the target: `recall`, then the collection pass, then
   ingest. From the ingested pivots, build the **frontier** — every newly discovered identifier
   worth its own pivot: domains, IPs, emails, usernames, phones, wallets, GA/GTM/pixel IDs,
   file/APK hashes, Telegram handles.
2. **Prune before you spawn.** Run `recall` + `reference_check` on each frontier seed. **Never**
   spawn a sub-agent for a seed that is already attributed in the KB or already ruled shared-noise
   — that wastes credits and risks contradicting a published assessment. Dedup the frontier.
3. **Fan out — one sub-agent per surviving seed.** Launch them in parallel with the Agent tool
   (multiple Agent calls in a single message so they run concurrently). Each sub-agent's brief:
   > Load the `cti-expert` skill. Investigate `<seed>` with **`/cti <seed> --quick`** (quick, not
   > deep — the orchestrator owns recursion). Write pivot JSON into the **same** case dir
   > `$INTEL_HOME/cases/<CASE-ID>/`. Return only: new identifiers found, each with its Admiralty
   > rating and the §2.5 rung it rests on. Do not cluster or assess — that is the orchestrator's job.
   - **Concurrency cap:** ≤ 6 sub-agents in flight at once; queue the rest.
   - **Depth cap:** default frontier depth **2 hops** from the original seed. A seed a sub-agent
     discovers goes into the *next* round's frontier, not an unbounded recursion.
   - **`--deep --passive`** propagates: every sub-agent runs `--quick --passive`.
4. **Converge + cluster + enrich (you run it).** Ingest every sub-agent's pivot JSON, then run cluster →
   risk over the **merged** set to partition it into distinct operator clusters. Sub-agents ran
   `--quick` (infra only, **no** enrichment), so the orchestrator owns **Step 2c** here: run the
   leak/breach/OSINT/dork legs **once** over the **deduped** identifier frontier (skip any seed
   already attributed in the KB or ruled shared-noise) so `/breach-deep`·`/intelx`·`/dork-sweep`·
   `/github-osint` aren't fired redundantly per sub-agent. Apply SKILL.md
   §2.5 across the whole frontier — an edge is only real on the rung it rests on. Repeat rounds 1–4
   until a round adds no new un-attributed seed (frontier exhausted) or the depth cap is hit.
4b. **Assess in parallel — one sub-agent per cluster (Assess-phase fan-out).** Collection is
   already parallel (Step 3 sub-agents + the mechanical `collect_many` threads); the assessment is
   the other slow, serial part. When convergence yields **2+ distinct clusters**, don't judge them
   one-at-a-time — spawn one **assessment sub-agent per cluster** (same ≤ 6 concurrency cap), each
   scoped to its cluster's members + shared indicators:
   > Load the `cti-expert` skill. Assess ONLY this cluster: run the ICD-203 / ACH pass over these
   > domains + shared indicators, apply §2.5 rung discipline, and return a structured verdict —
   > operator hypothesis, confidence (likelihood term), risk flags, and the single strongest and
   > weakest edge. Do not collect, and do not reason about other clusters.
   Then **you synthesise** — this stays central, because a per-cluster agent cannot see the whole
   board: merge the verdicts, resolve cross-cluster links, dedup shared operators, and write the
   case assessment. One cluster only → assess inline; the fan-out overhead isn't worth it.
5. **Report what the fleet could not reach.** List seeds you pruned, sub-agents that returned
   empty, and any seed left unexpanded because of the depth/concurrency cap.

Single-seed cases with no frontier: skip the fan-out and run enrichment inline — the sub-agent
overhead is not worth it. Fan-out earns its cost at 3+ live seeds.

## Output

Report findings with two-axis confidence (Admiralty per finding, ICD-203 per judgment), state
empty results as empty, and list what you did **not** cover. Write case artifacts to
`$INTEL_HOME/cases/<CASE-ID>/` — never to a `cases/` directory at the repo root.

**Leak coverage is part of every final answer.** For each confirmed selector, state which leak
vendors (ChongLuaDao, IntelX, Hudson Rock, deep_profile) were consulted — with the result — and
which were not, and why (missing key, `free_only`/`no_spend` hold, n/a for the type, retryable
error). Read it from `enrichment/leak_coverage.json`; if that file is absent the fan-out never
ran — say so and run `intel.py enrich <CASE-ID> --leak-only`, never report "no leaks".

**Deliver — build the report bundle deterministically (do NOT hand-author the report JSON).** Once
the case has an `assessment.md`, turn it into the presentation bundle via the converter, then the
generators (see SKILL.md §8 for the full flow and the format prompt):
```bash
uv run "$SKILL_DIR/scripts/build_report_data.py" "$INTEL_HOME/cases/<CASE-ID>" -o "CTI-REPORT-<CASE-ID>-<DATE>.json"
```
This emits the exact flat schema the generators consume — operator/registrant subjects with
selectors, the full domain estate as network indicators, findings/timeline/connections, and the
§2.5 exclusion set in `ioc_exclude` (so no excluded CDN/shared IP, registrar, or nameserver leaves
as an IOC). Merge any analyst-supplied evidence onto that JSON before rendering. **Before the HTML
export, confirm it (SKILL.md §8 Step C):** run `python3 "$SKILL_DIR/scripts/cti_archify.py" <REPORT.json>
--plan`, state the path plus what Auto (compact apex-level fold) and Force (`CTI_ARCHIFY=force`, the widest
25-node grid) would embed, and let the analyst pick Auto / Force / `CTI_ARCHIFY=0` / skip; then quote the
generator's `Blueprint (Archify):` line back. `--yolo` skips the prompt (Auto).

**Deliver — the editorial PDF/DOCX is deterministic too.** The polished house report (cover, sections
I–XI, Methodology with both confidence scales and the ICD-203 × Admiralty confidence scatter, relationship
graph + entity relationship map, attribution inference chain, temporal view + registration heatmap +
domain × shared-indicator matrix, a captured landing page per estate host inline in the cluster section,
per-domain dossiers, Appendices A–E incl. glossary — the format of the reference reports) is composed
from the case dir, not hand-written and not harness-only:
```bash
python3 "$SKILL_DIR/scripts/backend/intel.py" house-report <CASE-ID>      # → cases/<CASE-ID>/report/CTI-REPORT-<CASE-ID>-<date>.{pdf,docx,house.md} + figures
#   flags: --no-screenshots (fully offline) · --no-archive-fallback · --max-screenshots N · --screenshot-timeout S
```
Its only egress is the landing-page step: hosts without a screenshot on disk are rendered in headless
Chromium through the research-egress proxy policy (proxied, or direct only if the store allows it;
blocked → stated in the report, never forced). A page that will not render, or renders near-empty, falls
back to the newest public web-scan screenshot, then a rendered web-archive snapshot — captioned as such,
dated by the archive, linked in Appendix B, and labelled a previous owner's page when it predates the
current registration (drop-catch evidence, not the operator's landing page). Negative archive lookups are
cached 7 days. Note the Assess phase may run the `/harness` deepening loop first when the frontier has
not converged (`--no-harness` opts out); the Deliver prompts come after it.
It reads `assessment.json` when present (engine schema — `harness/schemas.py:Assessment`; the harness
and `loop` write it, an analyst can author it, and `case-store snapshot --assessment <json>` copies it to
the head) and **degrades without it**: the body is then composed from `assessment.md` alone and the
inference-chain figure is skipped. It also reads `assessment.md`
for the analyst narrative, `whois/`, `raw/`, `clusters.json`, `shared.txt`, `scope.json` and the
operator/reference ledgers. Internal tool, vendor and path names are scrubbed to public source
classes on the way in (house Rule 12); the impersonated brand's genuine domain never becomes an
indicator. Run it after the JSON/HTML/IOC bundle above — both come from the same case dir.

**Shareable exports — mask uninvolved third parties (§2.5).** Before rendering a report to a
shareable format (PDF/DOCX/HTML) or an IOC bundle, **mask the PII of any party you confirmed is
NOT involved** — e.g. a name-collision innocent's email/phone (`ntp***@example.com`) — because a
skim reader or an IOC scraper strips the exculpatory framing. Keep the **full** value only in the
internal case files (`assessment.md`, `knowledge/reference.jsonl`) so the false-positive rejection
stays auditable. The operator's own IOCs are the finding — keep those. Mask by hand for a couple of
values, or run `scripts/redact.py` for a full pass (opt-in `--redact`).

**Protect an analyst-authored `assessment.md`.** If you hand-write the authoritative assessment,
title it with a heading the loop does **not** claim (e.g. `# Analyst Assessment (ICD-203) — …`, not
`# Cluster Intelligence Assessment — …`) so `case_state.may_overwrite_assessment` treats it as
precious; the loop render then diverts to `loop_assessment.md`. Snapshot it under the case's
`assessments/` store as belt-and-suspenders.
