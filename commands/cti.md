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

## Step 1 — Route by target type

| Target looks like | Do this |
|---|---|
| domain / URL | full pipeline (Step 2) |
| bare IP | `pivot_extract` in IPPivot mode — ASN, co-tenancy, ports, passive DNS |
| email | reverse-WHOIS (**preview first**), breach/stealer triage, cross-platform OSINT |
| username | enumerate platforms, then pivot on anything the profiles expose |
| phone | carrier + reputation + messaging-app presence, then reverse-WHOIS the number |
| crypto wallet | chain tracing in **and out**; outbound identifies the cash-out venue |
| file hash / APK / EXE | `mcp__intel__analyze_artifact` (BinaryPivot) |

Ambiguous input: say which reading you chose and why, then proceed. Don't stop to ask unless two
readings would produce materially different work.

## Step 2 — Run the pipeline, don't hand-run collectors

For a domain or URL, use the deterministic chain. It sequences collect → ingest → prior-overlap →
risk → cluster → assess, and it records provenance that hand-running does not:

```bash
python3 scripts/backend/intel.py pipeline open <CASE-ID> <seeds-file>
```

Hand-running a collector is a fallback, not the default. If you do it, **say so in the write-up**
— evidence archiving, the versioned assessment and the convergence check will not have run.

## Step 2b — persist the versioned case, then deepen if it hasn't converged

`/case` is an **alias of `/cti`**, so `/cti` runs the *same* full pipeline — including the
deep layer. When `/backend` is live (Tier 1/2) and the run produced ≥1 host seed, persist a
**versioned** case with **zero extra egress** by reusing the pivots already collected (do **not**
re-fetch):

```bash
python3 scripts/backend/intel.py pipeline open <CASE-ID> <seeds> --no-collect
```

That runs ingest → recall → risk → clusters → `case_graph.json` → ICD-203 `assessment.md` over
`cases/<CASE-ID>/raw/`. Then check convergence — `intel.py convergence <CASE-ID>` (status ≠
`converged`, or `intel.py frontier <CASE-ID>` still lists open leads). If it has **not converged**
and posture is active (not `--passive`, infra not classified hostile), **auto-escalate to the
`/harness` deepening loop** — keyless-first (it uses the CLI's own model on your subscription; no
separate LLM key), egress **hard-gated** on hostile infra, `--no-harness` opts out. Full contract:
SKILL.md §2 (AEAD deep-layer note) and the technique-activation / auto-fire matrices for the
`/webpivot`·`/icp`·`/iban`·`/hash-id` auto-fires that also run in a full `/cti` (= `/case`) run.

## Step 2c — Auto-pivot enrichment: leaks · breach · OSINT · dorks (NOT optional)

The deterministic pipeline (Step 2) is **infra-only** — WHOIS/DNS/cert/IP/webpivot. It does **not**
cover the identity/exposure surface. A `/cti` run is **not complete** until the enrichment layer has
fired on the seed **and on every identifier the loop discovers** (email, username, person name,
phone, wallet, GitHub handle, org). Do not report "nothing further found" from a run that never ran
these — that is absence of collection, not absence of evidence (§2.5 *Dead seed*).

Fire by identifier type, then feed every hit **back into the recursive pivot loop** as a new seed:

| Discovered | Auto-fire (leaks / breach / OSINT / dork) |
|---|---|
| **email** | `/breach-deep` + `/email-deep` (LeakCheck·HudsonRock·CLD) → `/intelx <email>` (breach dumps, **infostealer logs**, pastes, darknet — logs-first pass is ~50% keyless) → `/github-osint` (commit attribution) → `/dork-sweep --telegram --docs` on the address and `@domain` |
| **username** | `/username` (3000+ platforms) → social-platform recon → `/intelx` on any email the profiles expose → `/github-osint` if a GitHub profile/hit exists (`github_harvest`: `.patch` From: e-mails, first 2 + last 2 commits per repo, org about-profile + members + top contributors, former logins from no-reply addresses) → `/dork-sweep --telegram --docs` |
| **person name** | `/dork-sweep --docs` + `/docleak` (author/uploader fields) → `/github-osint` only after a likely handle/commit-email surfaces → `/email-permute` **against the case's own domains** (hypothesis only — never a finding, never ingested; §2.5) |
| **phone** | `/phone` (carrier + reputation + **infostealer exposure** + VN scam reports) → `/intelx <phone>` → `/dork-sweep` |
| **domain / org** | `/intelx --phonebook <apex>` (every email/subdomain/URL IntelX has seen) → `/secrets` + `/github-osint` (org, primary domain, discovered repos) → `/dork-sweep --filetype --docs` + `/docleak` on domain + org → `wayback_harvest --indicators` (Acquire already runs this) |
| **wallet / IBAN / hash** | `/intelx <selector>` → `/iban`·`/hash-id` (auto per §Auto-fire matrix); credential-material hashes route to `/breach-deep`, never a public sandbox |

Rules that keep this cheap and correct:
- **`/intelx` takes a STRONG selector only** — email / domain (`*.apex`) / URL / IP / phone / wallet / IBAN. **Never** a brand or person name (refused locally, and a soft term still costs a unit).
- **Reverse-WHOIS is the highest-yield estate pivot** — always `--reverse-mode preview` first (count is free), and **cross-check email vs name**: a name that returns unrelated domains is a **name-collision**, not one operator (§2.5). Confirm on the email/phone triple before clustering.
- **Bulk-guard footgun:** `ingest-rwhois` (`--max-domains`, default 25) and `export-graph` (`--max-indicator-degree`, default 25) **silently drop** a legitimate large single-operator estate as "reseller noise." When rung-1 (email+name+phone) already confirms one operator, **raise the threshold above the estate size** (e.g. `--max-domains 60`) or the edge is lost.
- **Posture:** on hostile infra prefer passive corpora (IntelX/Wayback/urlscan); `/intelx` and dorks do **not** touch the target. `--passive` propagates. Never submit the case's own sample to a public sandbox (§2.5).
- **Metered discipline:** `/breach-deep`, `/intelx` (beyond the keyless logs-first pass) and reverse-WHOIS purchase spend credits — state what you spent. `--quick` skips this expansion; a full `/cti` (= `/case`) runs it.
- **Enforced, and closable (no infinite loop).** `intel.py frontier <case>` emits these as **OPEN enrichment leads** (per registrant email + per apex — `/intelx`·`/breach-deep`·`/dork-sweep`·`/github-osint`); `frontier`/`status` print the open count. Treat them as a **/cti completeness checklist**: the case isn't done while actionable leads remain. **Close every leg with a reason** so it can't re-open forever — `intel.py enrichment-done <case> --key <key> --reason ran|empty|unavailable|skipped`: `ran`/`empty` after running (empty is a collection gap, not a failure), `unavailable` when a key is missing, `skipped` when `--passive`/scope blocks it. Closed-as-gap legs move to `enrichment_gaps` (auditable, not re-chased). **This is a checklist, not the engine stop-condition** — `intel.py loop`/`convergence` converge on new hosts/indicators and never block on enrichment leads, so the harness auto-escalation stays bounded. Never mark a leg `ran` that you did not run.

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

## Flags

- `--quick` — recall + one collection pass; **no** cluster expansion and **no** Step 2c leak/breach/OSINT/dork enrichment (infra triage only)
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
python3 "$SKILL_DIR/scripts/backend/intel.py" house-report <CASE-ID>      # → cases/<CASE-ID>/report/CTI-REPORT-<CASE-ID>-<date>.{pdf,docx,md} + figures
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
