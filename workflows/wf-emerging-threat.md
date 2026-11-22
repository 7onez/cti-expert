# WF-Emerging-Threat: Emerging-Threat Response Procedure

How cti-expert answers an external trigger that may matter to a defended organisation: a
vulnerability or vendor advisory, a campaign or malware report, an actor profile, a peer or
supply-chain incident, a sector-targeting shift or a geopolitical event. The output is an early
**Threat Advisory**, a full **Threat Assessment**, a **hunt package**, and a dated record of who
was told and who acknowledged.

**Source.** The five-phase spine, its step numbering (1.1–5.4), the five exposure dimensions and
the cross-cutting principles are adapted from the emerging-threat SOP in
`[PK Packt ACTIH companion repo, 2026, chapter-01/CTI SOP Emerging Threat Response.md]`
([pinned](https://github.com/PacktPublishing/Advanced-Cyber-Threat-Intelligence-and-Hunting/blob/0f76fbc2ff505e6fcb2585b1b3d0b08ce271b1e4/chapter-01/CTI%20SOP%20Emerging%20Threat%20Response.md),
MIT, © 2026 Packt). The text below is rewritten for cti-expert. Anything marked
**(adaptation)** is ours: tool mappings, Admiralty grading, the response log, the report mapping
and the checkpoint re-runs.

**Related files.** Case workflow and hunt phase:
[`wf-threat-analyst.md`](wf-threat-analyst.md). Judgement language, ACH and bias checks:
[`handbook/analytic-standards.md`](../handbook/analytic-standards.md). Diamond events, Pyramid
of Pain and ATT&CK mapping: [`handbook/intrusion-modeling.md`](../handbook/intrusion-modeling.md).
Capture and custody: [`handbook/collection-preservation.md`](../handbook/collection-preservation.md).
The two severity axes and the tier grid:
[`handbook/severity-tiers.md`](../handbook/severity-tiers.md) (not repeated here). Report-block
keys: [`handbook/report-template.md`](../handbook/report-template.md).

---

## When to use it, and when not to

| | |
|---|---|
| **Trigger** | `/cti` gets a vulnerability id, a vendor advisory, a campaign or malware report, an actor name or profile, or a peer, supply-chain or sector alert, **and** there is a defended organisation (the consumer) whose exposure is in question `[PK …, CTI SOP Emerging Threat Response.md, "Trigger Types"]` |
| **Inputs** | The trigger artefact (URL or document); the consumer's apex domain(s) and sector; a named consumer contact for each asset, control and relational domain (for the dispatched queries in 2.4) |
| **Output** | `cases/<id>/` holding the Advisory, the Assessment (house report), the hunt records, `distribution.jsonl` and the custody `export` lines |
| **Not this workflow** | A declared incident goes to the consumer's IR procedure. Routine tracking goes to `/watch`. Bulk IOC ingestion goes to the consumer's detection pipeline. Infrastructure attribution with no defended consumer goes to [`wf-threat-analyst.md`](wf-threat-analyst.md) `[PK …, "Scope"]` |
| **Abstain** | When there is no consumer to tell. When the trigger cannot be authenticated (1.2) and no corroboration exists. When the consumer gives no asset or control access and the passive view cannot answer any exposure dimension. In that last case, issue the Advisory only and say that the exposure picture is not possible |

**Who owns what (adaptation).** cti-expert sees the internet-facing estate, public corpora,
breach and stealer data and its own case knowledge base. It does **not** see the consumer's CMDB,
EDR, SIEM, scanner, IAM or contracts. Each step below says what cti-expert runs and what the
consumer does. Steps marked **consumer-owned** cannot be done from here. Record them as dispatched
or answered, never as done by us.

---

## Phase 1 — Intake & Initial Triage

**1.1 One owning analyst.** One analyst owns the item at least through Phase 4. A hand-off is a
`handoff` line in the response log (§ Response log) `[PK …, 1.1]`.
*cti-expert:* open the case with `/cti <trigger>` and run `/recall` first, because a known
advisory, actor or IOC may already have a case. Write the intake with `/scope <case>`: the
purpose is `emerging-threat response for <consumer>` and the claim is the trigger.

**1.2 Source credibility and authenticity** `[PK …, 1.2]`.
- **Grade the source with Admiralty (adaptation).** Source reliability A–F
  ([`engine/finding-framework.md`](../engine/finding-framework.md) "Source Reliability Scale")
  and information credibility 1–6, recorded on the trigger finding at `/evidence import`. Upstream
  ranks sources by vendor tier. We map that onto Admiralty:

  | Source | Typical grade | Action |
  |---|---|---|
  | The product vendor's own advisory; a national CERT; a research team with a long, checkable record | **A** or **B** | Act on it alone: open the case and draft the Advisory |
  | A known industry publication or a mid-size research blog | **C** | Start work and corroborate in parallel. Do not wait for corroboration before starting |
  | An unknown blog, a social post, a forum or a paste | **D** or **F** | A **lead**, not intelligence. Corroborate before any consumer action |
  | Anonymous and uncorroborated | **E** or **F** | Discard unless corroborated |

- **One A-graded report is enough to START and to issue a provisional Advisory. It is never
  enough on its own to attribute or to close (adaptation).** An actor named in the report goes
  into the `actors` section as the vendor's claim (`confirmed: false`) until it passes the rung
  table and ACH ([`analytic-standards.md`](../handbook/analytic-standards.md) §3; SKILL.md
  "Attribution rails — collecting ≠ attributing (RULE 5)"). Closing needs the Phase 5 evidence.
- **Authenticate the artefact.** For a vulnerability, run `/vuln-check <id>` (CIRCL + NVD) to
  confirm the record exists and is published. Fetch the advisory from the vendor's own domain,
  not a re-post. For a report, confirm that the named publisher really published it. Use
  `/snapshots <url>` for the first-seen date, which exposes recycled material. Preserve the
  artefact with `capture_evidence verify=true` (or `/screenshot`) per
  [`collection-preservation.md`](../handbook/collection-preservation.md) §6, then cite its
  `capture_sha256`.
- **Confounders.** A re-post of an older advisory carrying a fresh date. Two "independent"
  reports that both copy one original (that is one source, not two: B3 in analytic-standards
  §4). A vendor that downplays exploitation of its own product. A researcher who overstates it.

**1.3 One-paragraph internal summary.** Plain language, for the case only, not a deliverable
`[PK …, 1.3]`. For a vulnerability: what it is, prerequisites, impact and exploitability. For a
campaign: the actor as claimed, victimology, TTPs and infrastructure. For an actor: capability,
intent and history. For a peer or supply-chain event: what is confirmed and what is speculated.
*cti-expert:* store the paragraph as the `triage` line's `summary` and as KQ-01's working answer
(`key_questions`).

**1.4 Provisional severity, intrinsic properties only** `[PK …, 1.4]`. Rate **Axis 1 (threat
severity)** of [`severity-tiers.md`](../handbook/severity-tiers.md) from the threat alone and
record the provisional tier as that file defines it for Phase 1 (P1 Flash / P2 Priority /
P3 Standard / P4 Informational).
- **Actor triggers (adaptation):** score the actor with `/exposure --model actor`. Its
  `threat_score` (0–1) and `band` map to Axis 1 per `severity-tiers.md`. Adding
  `--set exposure_level=<level>` also returns the tier once Axis 2 is known (2.6). The score is
  an analyst judgement and a lead, never attribution or a same-operator edge, and an intent
  rating needs a cited source.
- **Confounders:** a CVSS number is not Axis 1, because exploit availability and patch state
  matter as much as impact. A loud media cycle raises the need for an Advisory (1.6), not the
  severity.

**1.5 Record in the tracking system** `[PK …, 1.5]`. *cti-expert (adaptation):* the case
directory **is** the tracking entry. Append a `triage` line to `cases/<id>/distribution.jsonl`
with the case id, UTC time, owner, source URL, Admiralty grade, the summary and the provisional
tier. Import the trigger as a graded finding with `/evidence import` so that it reaches the
report.

**1.6 Is an Advisory warranted?** Usually when the provisional tier is P1 or P2, or when
leadership will be asked about the trigger whatever its tier `[PK …, 1.6]`. Record the decision
and the reason on the `triage` line (`advisory: yes|no`).

**1.7 Issue the Threat Advisory** (outline in § Deliverables). Distribution is narrow: security
leadership, SOC leadership and the platform owners of the affected technology. It states what is
known, the provisional tier, the next steps with times, and that a Threat Assessment will follow
`[PK …, 1.7]`. *cti-expert:* write it and record a custody `export` line plus one `sent` line per
recipient (§ Response log). *Consumer-owned:* reading it and acknowledging it.

---

## Phase 2 — Exposure Assessment

Five dimensions `[PK …, Phase 2]`. The trigger type decides which ones dominate. The table
says what cti-expert can see passively and what only the consumer can answer **(adaptation)**.

| Dimension | Dominant for | cti-expert sees passively | Consumer-owned |
|---|---|---|---|
| **Technical**: do we run it? | vulnerability, malware | `/subdomain <apex>` for edge hostnames; `/appliance-scan <host> --case <id>` for product, version (TENTATIVE unless the analyst confirms it), patch lag after a verified advisory (`--advisory ID:YYYY-MM-DD:fixed`) and "no reboot since"; `/censys` when keyed; credentials for the affected service URL in stealer logs (`/intelx "*.<apex>"`, `/email-deep`, `/stealer-log --subject-emails`) | CMDB and asset inventory, vulnerability scanner and cloud console counts, **internal** deployments (invisible from outside) |
| **Targeting**: are we in the target set? | actor, campaign, sector shift, geopolitics | The consumer's sector and region from the case intake; `/exposure --model organisation` (`actors` domain); keyed `cld ransomware <org>` and leak claims (`leak_claims`); `/impersonate <apex>` for lookalikes aimed at the brand; `/recall` and `kb_crossref` for earlier cases with the same indicators | The organisation's own view of its markets, its subsidiaries and planned M&A |
| **Tradecraft**: do our controls cover the TTPs? | campaign, malware | The ATT&CK mapping and scenarios (Phase 3); the public posture that bears on the TTPs: `/email-hygiene` (spoofability for phishing TTPs), `/msftrecon` (federation and identity surface) | Control coverage per technique: EDR policy, MFA coverage, segmentation |
| **Relational**: are we tied to victims? | peer incident, supply chain | `/suppliers <case> --subject <apex>` (TXT tokens, SPF, MX, NS, CNAME, certificate issuer) and its per-supplier breach, KEV and stealer checks ([`techniques/fx-supplier-exposure.md`](../techniques/fx-supplier-exposure.md)); `corp_registry` (MCP) for group structure | Contracts, data flows, remote-access paths of vendors, peering and interconnect |
| **Detection**: would we see it? | always | Nothing directly. cti-expert writes the hunt and the telemetry requirement (CAR triples), and points each Windows source at its audit setting in `telemetry_baselines.json` (below) | Log sources, retention, SIEM coverage. This dimension is wholly consumer-owned |

A supplier, a co-tenant or a shared provider is a **relationship of the subject**, never an
operator link. Passive absence is not evidence of non-exposure: `/appliance-scan` sees only what
internet scanners indexed. Record a passive null as `negative_checks` with its scope, and keep
the dimension open until the consumer answers.

**Does the consumer even log this? (adaptation)** Before asking whether a TTP would be seen, ask
whether the log that would show it exists. For Windows event logging,
[`intel_engine/IntelAnalysis/references/telemetry_baselines.json`](../intel_engine/IntelAnalysis/references/telemetry_baselines.json)
maps each telemetry need (process creation with command line, logons, scheduled tasks, PowerShell
script blocks, service installs, Defender, optional Sysmon) to its audit subcategory, the Windows
default, what each compared baseline (Yamato Security, Microsoft client and server, ASD) sets, and
the log-size floor. It is adapted from Yamato Security's EventLog-Baseline-Guide (MIT), pinned to one
commit, with the guide's usable/unusable Sigma-rule counts per baseline. Send the relevant keys to
the detection owner as a dispatched query (2.4), cite them as `baseline_ref` on the
`telemetry_priorities` rows, and keep the Detection dimension open until the owner answers. A
setting being recommended is not evidence that the consumer has it. *Consumer-owned:* checking
the actual audit policy and log sizes on their hosts.

**2.1 Define the exposure scope precisely** `[PK …, 2.1]`. Turn the trigger into queryable
identifiers: product and version range, build or edition, configuration preconditions (for
example "portal enabled, version below 7.3.1"), not labels like "VPN". For TTPs: observable
behaviours and control questions. For relationships: named vendors and paths. Call out the
**high-risk preconditions**: internet-facing, identity-adjacent, multi-tenant, management-plane.
*cti-expert:* write each identifier as a KQ row and an `open_questions` row (OQ-nn: decision at
stake, source needed, time window).

**2.2 Determine exposure by the fastest accurate path** `[PK …, 2.2]`. *cti-expert:* run the
passive column of the table. *Consumer-owned:* every query against internal systems. cti-expert
has no self-service access to them unless the consumer grants it in writing. Record such a grant
in `scope.json`.

**2.3 Identify domains and owners** `[PK …, 2.3]`: asset domains (technical), control domains
(tradecraft and detection) and relational domains (vendor management, procurement, M&A). Map the
scope to the right owners rather than sending to everyone. *Consumer-owned:* the owner map.
*cti-expert:* keeps the map's case copy as `roles` rows. The `role` field takes its fixed values,
for example `supplier` for a vendor; put the owner's team in `basis`.

**2.4 Execute exposure queries** `[PK …, 2.4]`. Passive queries run from here, and each result
is a finding. Dispatched queries go to the owners as a short template: identifier, the question,
a "by when", and how to answer. Log each one as a `query` line in the response log.

**2.5 Collect and consolidate** `[PK …, 2.5]`:
- **Affected scope**, as an order of magnitude: assets, uncovered TTPs or relevant vendors.
  Precision is not needed yet.
- **Concentration** matters more than the total. Two exposed gateways in front of identity are
  worse than fifty lab hosts.
- **Silent domains** stay visible as open `open_questions` rows. They are a gap, never a zero.
- *cti-expert (adaptation):* write a `counting_rules` row for each count. For example "3
  stealer-log records naming the portal URL" `does_not_mean` "3 compromised accounts".

**2.6 Contextual severity, the final tier** `[PK …, 2.6]`. Combine the dimensions into one
**Axis 2 (exposure level)** and read the tier as Axis 1 × Axis 2 in
[`severity-tiers.md`](../handbook/severity-tiers.md):
`/exposure --model tier --case <id> --set item=<trigger id> --set severity=<Axis 1>
--set exposure=<Axis 2> --set rationale="…"`. The rationale names the dimension that drove
Axis 2. With `--case` the tier goes into `cases/<id>/tier_log.json` (the first assignment logs
trigger `initial`). That file, not the response log, is the tier history.

**2.7 Confidence with its rationale** `[PK …, 2.7]`: high, medium or low, plus why. Name which
domains answered, which dimensions rest on passive data only, and which are open. Use the
likelihood/confidence split of analytic-standards §1. Confidence is part of the deliverable.

**2.8 Gate: proceed, deprioritise or close** `[PK …, 2.8]`. Proceed to Phase 3, drop to
passive tracking (`/watch`), or close with the reason. Closing at the gate still needs Phase 1
authentication and an exposure answer, never a single report saying "not affected". Append a
`gate` line.

---

## Phase 3 — Deep-Dive Analysis

**3.1 Deep threat analysis**, the bulk of the effort `[PK …, 3.1]`.
- **Understand the trigger fully.** For a vulnerability: mechanism, path, prerequisites,
  attacker capability, patch behaviour, bypass potential. For a campaign: the kill chain, tooling,
  infrastructure patterns and how they changed. For an actor: capability, intent, tempo, and the
  attribution confidence including dissent. For an incident: confirmed versus speculated, dwell
  time, objectives.
- **Translate it to the consumer's environment**, and **build plausible scenarios**, not worst
  cases. *cti-expert:* `scenarios` rows (SC-nn, feasibility × impact, the controls in the way).
- **Map to detection and prevention coverage.** Say per scenario what the consumer would see,
  where, and what it would miss. Detection exposure is an **output** of the scenarios, not an
  input. *cti-expert:* `attack_mapping` rows (MAP-nn) using the procedure first, then the technique
  id from the live ATT&CK site, with status `observed` / `attempted` / `inferred` and its limits
  ([`intrusion-modeling.md`](../handbook/intrusion-modeling.md) §7). A technique the vendor saw
  elsewhere is `inferred` for this consumer.
- **Tempo and exploitation status.** In-the-wild reporting, public PoC, observed target selection.
  *cti-expert:* `/vuln-check` (and the ChongLuaDao CVE/KEV feed when keyed); vendor IOCs through
  `/threat-check`, `/anyrun` (read-only) and `/misp search`. Each IOC is a lead with a freshness
  date.
- **Actor and capability attribution.** Which actors use the vulnerability class or share the
  tooling, and with what confidence. *cti-expert:* an `actors` row per claim, carrying its grade
  and `confirmed: false` until ACH supports it, and the attribution block of
  [`wf-threat-analyst.md`](wf-threat-analyst.md) Phase 4. A shared IOC between the advisory and
  an old case is a lead for `kb_crossref`, not an edge.
- **Abstain** from naming an actor when the only basis is the trigger's own claim. Report it as
  "attributed by <publisher> (grade)".

**3.2 Peer & ISAC engagement** `[PK …, 3.2]`. *Consumer-owned:* trust-group chatter and direct
peer contact. *cti-expert (adaptation):* `/misp search <ioc>` is read-only and shows whether the
instance already knows the indicator. Sharing back follows `/misp-export` (offline), then
`/misp push`, then `/misp publish`, each gated on the analyst's explicit confirmation.

**3.3 Detection development support** `[PK …, 3.3]`. Validate logic against real tradecraft and
durable behaviour, not a published PoC string or infrastructure the attacker will rotate (the top
of the Pyramid of Pain, intrusion-modeling §6). Anchor coverage to ATT&CK. *Consumer-owned:*
building and deploying the rules.

**3.4 Hunt package development** `[PK …, 3.4]`. *cti-expert:* one hunt record per hypothesis
from [`wf-threat-analyst.md`](wf-threat-analyst.md) Phase 5: ABLE hypothesis, abstract analytic,
time / terrain / behaviour scope (5.2), CAR data-model triples, the telemetry gap, and the time
box. Every record starts as `WRITTEN-NOT-RUN`. *Consumer-owned:* running it and returning the
result. "Nothing found" is reportable only from a run whose gap statement says the behaviour
would have been visible. Before a hypothesis is handed over, check its telemetry against
`telemetry_baselines.json`. When the consumer lacks the setting, the hypothesis is untestable until
they enable it: state that as the gap, never as a null.

**Running the hunt on the consumer's own logs (adaptation, consumer-owned).** The consumer runs
Yamato Security's open-source tools against their own data: Hayabusa and Takajō on Windows event
logs, Suzaku on cloud logs, and Senrigan on AWS CloudTrail. They use the Sigma rules listed for
each hypothesis in the hunt library's Yamato rule index (`hunt_rules_yamato.json`, link-only, pinned).
**cti-expert never runs these tools.** They are AGPL-3.0, so nothing of them is bundled or copied
here (we only name them). The logs are the consumer's and stay with the consumer, outside
the passive estate cti-expert sees. The returned result is recorded on the hunt record like any
other consumer return. The rules themselves are under the Detection Rule License (DRL) 1.1. When a
match is reported back, in the hunt record, the Assessment or a `sent` line, it must keep the
matching rule's `author` field and show it next to the match.

**3.5 Working-level coordination throughout** `[PK …, 3.5]`. The SOC, detection and hunt teams
get draft scenarios, mappings and hunt records as they form. They should not wait for the
Assessment. *cti-expert:* each early hand-over is a `sent` line marked `draft: true`, so the audit
shows when each team first had the material.

---

## Phase 4 — Stakeholder Notification & Final Threat Assessment

**4.1 Draft the Threat Assessment** (outline in § Deliverables) `[PK …, 4.1]`: executive summary,
timeline, technical summary, exposure picture, recommended actions, detection guidance, IOCs (say
so explicitly when there are none), and confidence and sources per major claim.

**4.2 Distribute through one channel** `[PK …, 4.2]`. *cti-expert:* one artefact, the house
report PDF from `intel.py house-report <case>`. Its sha256 is recorded with a custody `export`
line. Corrections are a new version, never an edited file.

**4.3 Notify recipients by trigger** `[PK …, 4.3]`. Select from vulnerability management, SOC
and detection engineering, IR and threat hunting (the hunt package as a formal hand-off),
infrastructure and platform owners, NOC, vendor management (supply chain) and the CISO. Only the
teams the trigger concerns. One `sent` line per team.

**4.4 Acknowledgment from every recipient team** `[PK …, 4.4]`. Any explicit receipt counts. An
unacknowledged team is chased and the chase is logged. *Consumer-owned:* acknowledging.

**4.5 Log distribution and acknowledgments** `[PK …, 4.5]`. *cti-expert:* `ack` lines in the
response log. Before calling Phase 4 done, check that every `sent` line has an `ack` or a
logged `chase`.

---

## Phase 5 — Tracking & Follow-Up

Before 4.2 is sent, take a baseline: `intel.py drift <case> --snapshot` (`case_drift`), so that
the checkpoints compare against the state at issue **(adaptation)**.

**5.1 +7-day checkpoint** `[PK …, 5.1]`.

| Question | cti-expert re-runs (adaptation) | Consumer-owned |
|---|---|---|
| Has exploitation status moved? | `/vuln-check <id>`; `/threat-check`, `/misp search` on the IOCs | Peer and ISAC chatter |
| Has the exposed surface changed? | `/appliance-scan <hosts> --case <id>` (version and patch lag; still TENTATIVE without confirmation); `intel.py drift <case>` (origin, nameserver or certificate moves) | Patch and mitigation percentage from the scanner or CMDB |
| Is attacker infrastructure still up? | `/takedown-watch --case <id>` on the advisory's domains (held, deleted, moved) | Blocks deployed |
| Did hunts run? | Update each hunt record's execution status from the consumer's return | Running the hunts |
| Are detections live? | Record the reported state | Deployment, tuning and signal |

Append a `checkpoint` line. Re-tier at once if a re-tier trigger fired: run `--model tier --case`
again with `--set trigger=<id>` (`exploitation_confirmed`, `new_exposure`,
`mitigation_threshold`, `actor_adopts`, `sector_shift`, `attribution_downgrade`,
`actor_rescored`; meanings in `severity-tiers.md`) and a rationale.

**5.2 +30-day checkpoint** `[PK …, 5.2]`. Re-run the 5.1 set. Then either close or roll the item
into standing tracking (`/watch`). Re-tier when exploitation has emerged, or when mitigation
reached its threshold. A tier never goes to zero: the lowest cell is still tracked
(`severity-tiers.md`). Record the re-tier in `tier_log.json` as in 5.1, then append a `close`
line.

**5.3 Lessons learned** `[PK …, 5.3]`: gaps in this procedure, gaps in the owner map (slow,
missing or wrong domains, read from the open `query` lines), and missed response deadlines from
the tier's deadline in `severity-tiers.md`. *cti-expert:* write them as the `close` line's
`lessons` and, when they concern the skill, as a change proposal. No case values go into tracked
files (CLAUDE.md RULE 1).

**5.4 Archive in the knowledge base** `[PK …, 5.4]`. The Advisory, the exposure findings, the
hunt records and the Assessment stay together in `cases/<id>/`. Run `kb_ingest` so a later
trigger's `/recall` finds them. Write the case abstract at close.

---

## Deliverables (adaptation)

### Threat Advisory: short, early, provisional

One page, issued within the provisional tier's clock. Render it with `/report brief`, or as a
short markdown file through `/report pdf`.

| # | Section | Content | Case source |
|---|---|---|---|
| 1 | Header | Case id, version, UTC time, TLP, owner, "PROVISIONAL" | `triage` line |
| 2 | What happened | The 1.3 summary in ≤ 80 words | KQ-01 |
| 3 | Source and grade | Publisher, Admiralty grade, authenticity check done | trigger finding |
| 4 | Provisional tier | Axis 1 and the provisional tier, with one reason | `triage` line |
| 5 | What we know about exposure so far | Passive results only, labelled as such | `key_findings` |
| 6 | Asks now | Interim mitigations from the vendor, owner by name | `roadmap` P1 |
| 7 | Next | "A Threat Assessment follows by <date> with the exposure picture, detection guidance and hunt package" | — |

### Threat Assessment: full, final tier

Built deterministically with `intel.py house-report <case>` from the case and the report block
imported with `/evidence import` (keys validated by `/report-sections lint`).

| Assessment part `[PK …, 4.1]` | House report placement | Report-block key or source |
|---|---|---|
| Executive summary | I. Executive Summary, "Key findings" | `key_findings` (severity; priority = the tier when P1–P3, none for P4); `risk_assessment` when `/exposure --model organisation` ran |
| Timeline | Incident Timeline | `incident_timeline` (Tnnn, proves / not_proven): advisory date, first exploitation report, our exposure dates |
| Technical summary | Findings | Graded findings; `threat_events` (event, dates, why it raises risk, Admiralty grade) |
| Actor and attribution status | Threat card map | `actors` (claim, grade, `confirmed: false` for a publisher's claim) |
| Exposure picture | Key Questions, Counting Rules, Open Questions | `key_questions` per dimension; `counting_rules`; `open_questions` for silent domains; `negative_checks` for passive nulls |
| Scenarios | Scenarios | `scenarios` (SC-nn) |
| Recommended actions | Recommendations | `roadmap`: P1 this week / P2 this month / P3 ongoing, one owner each |
| Detection guidance | ATT&CK Mapping, plus an appendix | `attack_mapping` (MAP-nn) plus the hunt records |
| IOCs | IOC export | `/report ioc` with freshness dates; "none published" stated when empty |
| Confidence and sources | Methodology and Sources | Admiralty per finding, likelihood term per judgement, bias checks B1–B10 |

### Hunt package

The Phase 5 hunt records of [`wf-threat-analyst.md`](wf-threat-analyst.md), one per hypothesis,
with the telemetry requirement written as CAR triples, the gap stated, and each Windows source
tied to its `telemetry_baselines.json` setting. The Yamato rule index entries the consumer should
run (3.4) go with each record. They are handed to IR
and threat hunting with their own `sent` line (4.3).

---

## Response log: `cases/<id>/distribution.jsonl` (adaptation)

**Decision: a separate, manually kept JSONL file in the case. The custody log is used only for
the deliverable file itself.** Reasons:
- `evidence/custody.jsonl` records events on **evidence items** (`capture`, `verify`, `copy`,
  `export`, `transfer`, `cite`). `wp_custody.py` refuses any other action, and each line names an
  item path and a digest. A recipient's acknowledgment or a dispatched query has no item and no
  digest. Recording them there would need new actions in code and would mix response admin into
  the evidence chain. Tier changes already have their own log, `tier_log.json` (2.6).
- The issued PDF **is** an item. So the hand-over of the artefact goes to custody as one `export`
  line: `python3 intel_engine/WebPivot/tools/wp_capture.py --custody export --case <case> --item
  <path to the PDF> --digest <sha256> --note "Threat Assessment v1 issued" --collector <who>`.
  Every `distribution.jsonl` line about that artefact carries the same `sha256`, which ties the
  two logs together.
- A plain file needs no new tool (Rule 3) and survives in the case store (RULE 2).

**Convention.** Append-only, one JSON object per line, UTC ISO times. Never edit a line: an
acknowledgment is a new `ack` line, not a change to the `sent` line.

| Field | Meaning |
|---|---|
| `utc` | When the event happened |
| `event` | `triage` · `query` · `gate` · `handoff` · `sent` · `ack` · `chase` · `checkpoint` · `close` |
| `actor` | Who recorded it (the owning analyst) |
| `team` | Recipient or queried team (for `query` / `sent` / `ack` / `chase`) |
| `deliverable`, `version`, `sha256` | For `sent` / `ack`: `advisory` / `assessment` / `hunt`, its version, the artefact's sha256 |
| `channel` | How it went (email, ticket, chat) |
| `draft` | `true` for 3.5 working-level hand-overs |
| `axis1`, `tier` | For `triage` only: Axis 1 and the provisional tier (contextual tiers live in `tier_log.json`) |
| `note` | Free text: summary, gate reason, ack wording, lessons |

---

## Cross-cutting principles (in our words) `[PK …, "Appendix: Cross-Cutting Principles"]`

1. **We inform, the consumer acts.** cti-expert is the authority on the threat. Patching,
   detection, hunting and vendor talks belong to the consumer's teams. Never report a consumer
   action as done until the owner says it is.
2. **One artefact, one channel, one owner per deliverable.** Under pressure, scattered messages
   are how things get missed. Version, never patch.
3. **Awareness must be provable.** Every recipient acknowledges, and the log shows it. Action
   stays with the recipient.
4. **Tier first from the threat, then from exposure.** Exposure assessment is the gate. Only the
   contextual tier drives consumer action.
5. **Everything dated, versioned and kept in the case.** The response log is the spine of the
   response.
6. **What we learn compounds.** Ingest the case so the next trigger's `/recall` starts from it
   (adaptation: the knowledge base is cti-expert's own).
7. **(adaptation)** A score, a tier or a vendor's attribution is a judgement or a lead, never a
   same-operator edge. Passive absence is never "not exposed".

---

## Worked example (synthetic)

All names, ids, dates and hosts are invented. **ExampleGate VPN** is a fictional product, and
**EXAMPLE-2026-0001** a made-up vulnerability id. The consumer is the owner of `example.com`.
The case is CASE-0001.

**Phase 1.** On 2026-10-12 the fictional vendor publishes advisory EXAMPLE-2026-0001 on its own
site: a path-handling flaw in the ExampleGate VPN web portal that lets an unauthenticated user
read session files, fixed in 7.3.1. The advisory says "limited exploitation observed" and
attributes it to an actor it calls SAMPLE PANDA. A blog repeats the story a day later and adds a
claim of mass scanning.
- 1.1: the analyst opens CASE-0001 with `/cti EXAMPLE-2026-0001`. `/recall` returns no prior
  case.
- 1.2: the vendor page is the vendor's own statement about its product: **A2**. The blog cites
  no data of its own: **D3**, a lead. The vendor page is captured with `verify=true` and its
  `capture_sha256` cited. `/snapshots` shows the page first appeared on 2026-10-12, so it is not
  recycled.
- 1.4: unauthenticated, little prerequisite, exploited, patch under 72 hours old: Axis 1 =
  Critical. The provisional tier is recorded per `severity-tiers.md`.
- 1.6–1.7: Advisory **yes**. It goes out the same day to the CISO, SOC lead and network platform
  owner: three `sent` lines, one custody `export` line. All three `ack` lines are in by
  2026-10-13.

**Phase 2.**
- Technical: `/subdomain example.com` lists `gw.example.com` and `vpn-dr.example.com`.
  `/appliance-scan gw.example.com --advisory EXAMPLE-2026-0001:2026-10-12:7.3.1 --case CASE-0001`
  (assuming the product is in the fingerprint reference; if it is not, the stored banner and
  page title are the only passive signal) reads 7.2.4 from a CPE: **TENTATIVE** pre-fix, indexed
  uptime with no reboot since 2026-08-30. `vpn-dr` shows a banner without a version.
- Stealer data: `/intelx "*.example.com"` returns 3 stealer-log records naming
  `https://gw.example.com/portal`. Counting rule: 3 records `does_not_mean` 3 compromised
  accounts.
- Relational: `/suppliers CASE-0001 --subject example.com` lists a managed-service provider at
  `msp.example.org`. Whether it reaches the consumer through ExampleGate is a vendor-management
  question.
- Queries dispatched (`query` lines): network (CMDB), IT lab, vendor management. Network answers
  with 2 production appliances, versions 7.2.4 and 7.2.6, plus appliance logs kept 14 days and not
  in the SIEM. Vendor management confirms the MSP uses its own access path, not ExampleGate. The
  lab never answers and stays an open question.
- Axis 2 = **Significant**: small count, but internet-facing and in front of identity. Detection is
  poor. `/exposure --model tier --case CASE-0001 --set item=EXAMPLE-2026-0001
  --set severity=Critical --set exposure=Significant --set rationale="…"` reads **P1** from the
  grid and logs it as `initial` in `tier_log.json`.
- Confidence **medium**: two of three domains answered, and the version is confirmed by the owner
  but not seen by us. Gate: **proceed**.

**Phase 3.** SC-01: session-file read on `gw` → a reused session → VPN access as a user →
internal remote desktop. SC-02: a stealer-log password plus a reused session. MAP-01: Exploit
Public-Facing Application, `inferred` here (seen by the vendor elsewhere). The vendor's IOCs,
`192.0.2.44`, `198.51.100.7` and `update-check.example.org`, go through `/threat-check` and
`/misp search`. All are leads with a date of 2026-10-12. The `actors` row reads "SAMPLE PANDA,
per vendor (A2), confirmed: false". Hunt H-01 (ABLE): A any · B portal requests carrying
traversal sequences followed by a session from a new network · L both appliances · E appliance
HTTP access log (url, src_ip, session_id). Status `WRITTEN-NOT-RUN`. Gap: 14-day retention, so
the hunt cannot see before 2026-09-30, and the logs are not in the SIEM. Follow-on hunt H-02
(remote-desktop hosts behind the VPN) needs Windows process creation with command line
(`baseline_ref: process_creation_cmdline`). The owner reports that auditing is off at the Windows
default, so H-02 cannot be tested until it is enabled. That is recorded as the gap, not as a null.

**Phase 4.** `intel.py house-report CASE-0001` builds Assessment v1 on 2026-10-14. One custody
`export` line is written. `sent` lines go to vulnerability management, the SOC, IR and hunt (with
H-01), the network platform owner and the CISO. IR acknowledges a day late after one logged
`chase`. Baseline: `intel.py drift CASE-0001 --snapshot`.

**Phase 5.**
- +7 (2026-10-21): `/appliance-scan` now reads 7.3.1 on `gw` (still TENTATIVE until the owner
  confirms it, which they do). `vpn-dr` is unchanged. `/vuln-check` notes a public PoC, so Axis 1
  stays Critical. `/takedown-watch --case CASE-0001` shows `update-check.example.org` on
  `clientHold`. The consumer ran H-01: 0 hits over 2026-10-07 to 2026-10-21. It is reported as
  "no hits within the retained 14 days", not as "no compromise".
- +30 (2026-11-13): both appliances patched and confirmed, the detection is live and validated.
  Re-tier with `--set trigger=mitigation_threshold`: Axis 2 drops to Limited, and Critical ×
  Limited reads P2 from the grid. The item rolls into `/watch`, not closed, because the lab never
  answered.
  Lessons: the lab had no owner in the map, and appliance logs need to reach the SIEM. Then
  `kb_ingest` and the case abstract.
