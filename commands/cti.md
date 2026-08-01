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

- `--quick` — recall + one collection pass, no cluster expansion
- `--deep` — **parallel sub-agent fan-out** (see below): expand every discovered identifier as a
  new seed, one sub-agent per seed, until the frontier is exhausted
- `--passive` — no live contact with the target; work from Wayback/urlscan captures only.
  **Use this for any hostile target.**

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
4. **Converge + cluster (you run it).** Ingest every sub-agent's pivot JSON, then run cluster →
   risk over the **merged** set to partition it into distinct operator clusters. Apply SKILL.md
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
