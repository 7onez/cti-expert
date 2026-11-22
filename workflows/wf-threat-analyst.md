# WF-Threat-Analyst: Threat Intelligence Case Workflow

Analyst-centric workflow for building threat intelligence from open-source discovery.

---

## Phase Overview

| Phase | Goal | Output |
|-------|------|--------|
| 1. Tasking | Define intelligence requirement | IR card |
| 2. Collection | Gather raw indicators and actor data | Raw findings log |
| 3. Processing | Structure, tag, and score findings | Findings table |
| 4. Analysis | Model activity, attribute, assess | Analysis memo |
| 5. Hunt *(when a consumer holds telemetry)* | Test the behaviour in the consumer's data; hand off detections | Hunt record + detection handoff |
| 6. Dissemination | Produce actionable output | Threat brief (F6) |

---

## Phase 1 — Tasking

**Define the Intelligence Requirement (IR):**

| Field | Content |
|-------|---------|
| Question | Specific, answerable (e.g., "What initial access TTPs target FS sector Q2 2026?") |
| Priority | CRITICAL / HIGH / MEDIUM / LOW |
| Consumer | Who receives the output (SOC, CISO, response team) |
| Deadline | Hard date |
| Success criteria | What constitutes a complete answer |

---

## Phase 2 — Collection

**Discovery paths by indicator type:**

| Indicator type | Discovery paths |
|----------------|----------------|
| IP address | Shodan, Censys, AbuseIPDB, passive DNS, BGP data |
| Domain | WHOIS history, DNS records, certificate transparency, VirusTotal |
| File hash | VirusTotal, MalwareBazaar, Hybrid Analysis, Any.run |
| Email | Header analysis, breach exposure, domain ownership |
| Handle / alias | Username sweep across platforms, forum indexing |
| Infrastructure cluster | SSL cert pivot, registrant pivot; ASN / registrar / shared-IP pivots yield service-provider **leads**, not edges ([`intrusion-modeling.md`](../handbook/intrusion-modeling.md) §2) |

**Collection rules:**
- Log every query: tool, query string, timestamp, result count
- Archive all source pages before closing
- Mark null results explicitly, with where you looked — a null is evidence only when the source
  would have shown the item (Heuer: "not looked" ≠ "looked, none"; analytic-standards §3)
- Capture, preserve and verify every item a finding rests on per
  [`handbook/collection-preservation.md`](../handbook/collection-preservation.md) (risk check, hashed capture, custody record)

---

## Phase 3 — Processing

**For each raw indicator collected:**

| Step | Action |
|------|--------|
| 3.1 | Assign finding ID (`FND-NNN`) |
| 3.2 | Tag type: IP / domain / hash / credential / behavioral / identity |
| 3.3 | Score weight: CRITICAL / HIGH / MEDIUM / LOW |
| 3.4 | Rate confidence: 0–100 |
| 3.5 | Link to subject (`SUB-NNN`) — create subject if new |
| 3.6 | Note first-seen / last-seen dates |
| 3.7 | Check false-positive risk (known-good lists) |

**IOC quality gate:**

| Score | Action |
|-------|--------|
| 85–100 | Operationalize: block, detect, alert |
| 65–84 | Monitor: watchlist, hunting query |
| 40–64 | Context only: do not block on this alone |
| < 40 | Discard or archive pending corroboration |

---

## Phase 4 — Analysis

Model first, then judge. Modelling lives in
[`handbook/intrusion-modeling.md`](../handbook/intrusion-modeling.md); judging lives in
[`handbook/analytic-standards.md`](../handbook/analytic-standards.md).

| Task | Method |
|------|--------|
| Model events | Diamond event per observation, confidence **per feature**; empty vertices become gaps (intrusion-modeling §1–2) |
| Chain and group | Activity thread per adversary–victim pair; activity group only under a **stated grouping function** (intrusion-modeling §4–5) |
| Prioritise pivots | Pyramid of Pain: track artefact- and behaviour-level pivots, use IPs/domains for immediate action (intrusion-modeling §6) |
| Map TTPs | Procedure first, then technique; IDs from the live ATT&CK site; status observed / attempted / inferred (intrusion-modeling §7) |
| Attribute actor | ACH, Heuer's eight steps, linchpin check (analytic-standards §3) — the rung table caps what any shared indicator can prove |
| Assess likelihood | Likelihood term + separate confidence (analytic-standards §1) — not a bare percentage |
| Find gaps | 5W1H overlay (analytic-standards §2); list what is unknown; do not speculate past findings |
| Pre-release bias checks | B1–B10 (analytic-standards §4) — this replaces a free-form premortem |

**Attribution documentation (required):**
```
Question:            [what is being attributed, to what level: infrastructure / operator / person]
Activity group:      [AG id + grouping function, or "none formed"]
Leading hypothesis:  [name or "unknown"]  — [likelihood term] ([confidence] — [why])
Runner-up:           [hypothesis + why it was not rejected]
Supporting findings: [FND-IDs — diagnostic rows only]
Counter-indicators:  [list or "none"]
Linchpins:           [items/assumptions the judgment depends on]
Milestones:          [observations that would change the ranking]
Intelligence gaps:   [list, incl. bias checks that could not be run]
```

---

## Phase 5 — Hunt

**Trigger.** The consumer (SOC, IR team, client) holds host, network or application telemetry
and the analysis produced a behaviour worth testing — or the requirement asks "is this activity
in our environment?". cti-expert has no access to the consumer's telemetry by default: it
*writes* hunts and records what was actually run. Skip this phase for pure infrastructure
attribution with no defending consumer.

**Sources.** MITRE TTP-based hunting `[MITRE TTP-Based Hunting, Daszczyszak et al., MTR180158,
2020]`; PEAK `[PEAK, Bianco & Fetterman, Splunk SURGe 2023]`. Both build on behaviour rather than
brittle IOCs — the top of the Pyramid of Pain
([`intrusion-modeling.md`](../handbook/intrusion-modeling.md) §6).

### 5.1 Choose the hunt type (PEAK)

| Type | Use when | Core move |
|---|---|---|
| **Hypothesis-driven** | Analysis yields a specific behaviour to test | Form a testable supposition; confirm or refute with data |
| **Baseline** (exploratory data analysis) | New data source or environment; precursor to the others | Data dictionary → distributions → outliers (stack counting / least frequency) → known-benign list |
| **Model-assisted (M-ATH)** | Enough data to model known-good or known-bad | ML model, then human review of what deviates or aligns |

Each runs **Prepare → Execute → Act**, with **Knowledge** (business context, CTI, past hunts,
this hunt's findings) feeding every phase; steps may be skipped or reordered.

### 5.2 Prepare — scope the hunt (MITRE + PEAK)

1. **Hypothesis in ABLE form** (PEAK): **A**ctor (optional) · **B**ehaviour (one or two
   techniques, not a whole kill chain) · **L**ocation (where in the estate) · **E**vidence (data
   source and what the behaviour would look like there). Refine until it can be proven or
   disproven.
2. **Abstract analytic on behavioural invariants** (MITRE): describe the behaviour so that it
   survives a change of tool — e.g. "a scheduled task executes a file that arrived over SMB",
   not a tool hash.
3. **Scope the analysis space** (MITRE): **time** (a known activity window, or a bounded
   look-back — often set by retention), **terrain** (only where the defender has authority:
   crown jewels, choke points, the defenders' own sensors), **behaviour** (TTPs that separate
   cleanly from local benign activity first). Actor knowledge may **prioritise** TTPs but should
   not **deselect** others — actors adapt and more than one may be present.
4. **Data requirements** (MITRE): collection requirements (which sources, sensors, fields) and
   modelling requirements (a data model mapping object:action to fields — e.g. process create →
   parent, command line, user). Continuous activity data beats alert-only sensors for hunting.
5. **Set a time box** (PEAK): a maximum hunt duration agreed in advance.

#### MITRE CAR: analytics and data-model reference

`[MITRE Cyber Analytics Repository, car.mitre.org]`. CAR is a library of analytics mapped to
ATT&CK, plus the data model the analytics are written against. Use it for steps 2 and 4.

- **Data model.** CAR describes telemetry as **(object, action, field)**, for example
  `process / create / parent_exe` or `flow / start / dest_port`. The objects include process, file,
  flow, registry, module, user_session and authentication. State the data requirement in these
  terms, then map each triple to the consumer's real source and field name. A triple that the
  sensor does not populate is a gap for 5.3, not a field to assume.
- **Analytic structure.** Each CAR analytic has a hypothesis, an information domain (host,
  network, process), ATT&CK coverage with a coverage level, the data-model triples it reads,
  pseudocode, optional tool implementations (Splunk, EQL, Sigma and others) and a unit test that
  triggers it. Reuse the hypothesis and pseudocode as the abstract analytic. Record the CAR ID on
  the hunt record's `Analytic` line.
- **Validate every analytic for this environment.** A CAR analytic, or any of its
  implementations, is a starting point and not a tested detection here. Before you report its
  result: map its triples to fields the consumer's sensors actually emit; run its unit test, or
  an equivalent benign trigger, and confirm that it fires; then baseline it against local benign
  activity and record the expected false positives. Until all three are done, report the
  analytic as `WRITTEN-NOT-RUN` or *untestable*.
- **Coverage is not detection.** CAR covers a minority of ATT&CK techniques: 94 of 588 techniques
  and sub-techniques in its coverage table dated 2024-01-08. Its coverage
  comparison counts analytics per technique, which says nothing about whether this estate can
  see the behaviour. A technique with no CAR analytic still needs an analytic. A technique with
  several still needs the 5.3 gap check.

#### Hunt package library (upstream queries, link-only)

`[PK Packt ACTIH companion repo, 2026, chapters 4–18 query files]`. The index
[`intel_engine/IntelAnalysis/references/hunt_packages.json`](../intel_engine/IntelAnalysis/references/hunt_packages.json)
has one entry per upstream query file, grouped by ATT&CK tactic. Each entry gives an ATT&CK id,
an ABLE one-liner, CAR-style telemetry (`process/create`, `dns/query`, `http/request`,
`cloudtrail/api`…), the platform and language (ES|QL, EQL, KQL, SPL, Sigma), prerequisites,
the method, false-positive notes and a link pinned to a commit. No query text is copied, so
open the link to read the query. (adaptation)

- **Trigger.** A 5.2 hypothesis exists and you need an analytic to start from.
- **Pick.** Filter by the hypothesis's ATT&CK ids first, then by `tactic`. Keep only entries
  whose `telemetry` and `platform` match what the consumer actually collects (step 4). If the
  language differs, port the logic and do not run it as written. If nothing matches, write the
  analytic yourself from CAR.
- **Validate (the CAR rule above applies unchanged).** Map every field to the consumer's
  schema, trigger the query once with benign activity, then baseline it. Build every baseline,
  lookup and enrich policy listed under `prerequisites` from the consumer's own data, over a
  window believed clean. Never reuse upstream example thresholds or baseline values. Until then
  the hunt record says `WRITTEN-NOT-RUN`. Put the entry `id` and `upstream_url` on the
  `Analytic` line.
- **Abstain** when a prerequisite is missing, for example sign-in logs without session ids,
  S3 data events switched off, no directory-listing events or no peer-group tags. Report the
  hunt as *untestable* with that gap and do not run a weaker version silently.
- **Time-Terrain-Behavior (TTB), as a method note.** For each entity, count the distinct
  **time** contexts it acts in (business hours, evening, night, weekend and so on), the
  distinct **terrain** it shows up in (endpoint, IDS, proxy, DNS, authentication, cloud), and
  the distinct **behaviour** categories it produces. Multiply the three counts, so an entity
  that is broad on all three axes rises to the top. The **velocity extension** adds the
  entity's rate of moving between time contexts, divided by its peer-group median, to the time
  term. This surfaces machine-speed or agentic activity that covers few contexts in a very
  short window. Caveats: compare entities only **within a peer group** (workstation, domain
  controller, build server), because servers and admin hosts are broad by role. The peer
  medians must come from the consumer's own clean window. Bucket boundaries are local choices.
  A high score is a triage lead to break down per bucket, never a detection or attribution.
- **C2 rarity patterns, as hypotheses to test rather than verdicts.**
  (1) A DNS domain resolved by very few hosts but heavily, outside browsers.
  (2) A user agent that is rare across the fleet but noisy from one source.
  (3) A URI path reused across several unrelated destination domains.
  Suppress generic paths (favicon, health checks, analytics beacons) before reading (3). On the
  passive web side, `url_paths` is the analogue of (3): it treats a shared URL path as a
  campaign identifier across disposable hosts, without consumer telemetry. A path match from
  either side is a lead for Phase 4. It is not a same-operator edge.
- **Output.** One hunt record per hypothesis (5.4). Hits go back to Phase 4 as Diamond events.

**Yamato Security detection index (link-only).** `[YS Yamato Security hayabusa-rules, suzaku-rules
and senrigan, 2026]`. The index
[`intel_engine/IntelAnalysis/references/hunt_rules_yamato.json`](../intel_engine/IntelAnalysis/references/hunt_rules_yamato.json)
is keyed by ATT&CK technique and covers 389 techniques. For each technique it gives, per rule
repo, the rule count, up to `per_technique_refs` rule refs (critical and high first; 1,634 refs
in all) and, when there are more, every directory that holds the rest. A rule ref carries the
Sigma rule id, title, level, logsource, author, path and a link pinned to a commit. Every Sigma
document with an id is indexed: 4,734 hayabusa-rules ids and 1,001 suzaku-rules ids. A
correlation file holds the correlation rule and its base rules. Each of them is indexed on its
own: its id is in `sources.<repo>.rule_ids`, and when it carries an ATT&CK tag it is a ref
marked `kind: correlation` or `kind: base`, with the file's path and link (hayabusa-rules: 3
correlation and 3 base documents; suzaku-rules: 7 and 9). A correlation does not inherit its
base rules' ATT&CK tags. The index also lists 187 Senrigan hunts (`senrigan_hunts`) with their
ATT&CK ids and telemetry. There are 139 CloudTrail hunts and 30 Suzaku-timeline hunts, each
tagged `cloudtrail/<eventSource>`. There are 18 VPC Flow Log hunts (`senrigan-vpcflow-…`), each
tagged `vpcflow/<column>` for the columns it requires. Rules without an ATT&CK tag are only
counted, per logsource, under `sources.<repo>.untagged`. `counts` at the top of the file holds
these totals. No rule logic, hunt SQL or prompt text is copied, so open the link to read the
rule. The generator `intel_engine/IntelAnalysis/scripts/build_yamato_index.py` rebuilds the
index from local clones; do not edit it by hand.

- **Pick.** Look up `techniques.<ATT&CK id>` for each id in the 5.2 hypothesis. If a
  sub-technique has nothing, try its parent. Choose the repo that matches the consumer's
  logs: `hayabusa-rules` for Windows event logs, `suzaku-rules` for AWS, Azure, Microsoft 365
  and Google Workspace logs, and `senrigan` hunts for CloudTrail. Then keep only rules whose
  `logsource` the consumer actually collects (step 4). The listed refs are a sample. When
  `count` is larger than the list, open the `dirs` (link = the source's `tree_url` + dir) and
  pick from there. An untagged rule can still fit a hypothesis by logsource; find it under its
  directory. Put the rule id (or Senrigan hunt id) in `hunt_package_ref`, and put the id and
  link on the hunt record's `Analytic` line. Any indexed rule id is a valid
  `hunt_package_ref`; the report lint resolves it against `sources.<repo>.rule_ids`.
- **Run on the consumer's own data, with their own tools.** The consumer runs
  [Hayabusa](https://github.com/Yamato-Security/hayabusa) with hayabusa-rules on their Windows
  event logs (.evtx), and can post-process the results with
  [Takajō](https://github.com/Yamato-Security/takajo). They run
  [Suzaku](https://github.com/Yamato-Security/suzaku) with suzaku-rules on their cloud logs
  (AWS CloudTrail, Azure, Microsoft 365, Google Workspace), or run
  [Senrigan](https://github.com/Yamato-Security/senrigan) on their CloudTrail. We link these
  tools and never bundle them, for two reasons. First, they are AGPL-3.0, and copying their code
  or text would put this skill under that licence. Second, every rule and hunt needs the
  consumer's own logs, which this skill never holds. The CAR rule above still applies: map,
  trigger once, baseline, and report `WRITTEN-NOT-RUN` until all three are done.
- **Attribution when a match is reported (DRL 1.1).** The rules are under the Detection Rule
  License 1.1. When the consumer shares a rule or reports a match, keep the rule's `author`
  exactly as the rule gives it, together with the rule title, id and pinned link. Senrigan
  hunts are AGPL-3.0: name and link the hunt, and never paste its SQL or prompt into a report.
- **Abstain** when the consumer cannot run the tool or lacks the logsource. Report the hunt as
  *untestable* with that gap; a rule existing for a technique is not coverage (see 5.3).

### 5.3 Execute — gap first, then hunt

1. **Needed vs available telemetry** (MITRE): confirm each required source is **present**,
   **valid** (no configuration gaps or tampering — check event counts over time; compare host
   and network views) and **continuous across the terrain**. Write the gap: which behaviours
   are invisible, where, and for which time window.
2. **Mitigate or accept** the gap: enable logging or deploy a sensor (weigh OPSEC and mission
   impact), substitute another source at lower confidence, or narrow the hypothesis. Watch the
   seams: links from covered to uncovered terrain, events either side of a missing window.
3. **Implement, test, tune** the analytic against the data model; widen or narrow time and
   terrain when results are empty or swamped. Prefer chains of connected hits over single hits.
4. **Evaluate hits.** Benign causes to rule out (MITRE): administrators, developers,
   misconfiguration, **the hunt team's own activity**, another defending team, and — rarely —
   an insider (escalate per policy, not here).
5. **Escalate** likely-malicious findings to IR immediately (PEAK); record them as a timeline
   and host list.

### 5.4 Act — record and hand off (PEAK)

Preserve the hunt, document findings (hypothesis confirmed / refuted / **untestable**, data
gaps, misconfigurations, escalations), create detections, add new topics to the backlog, and
communicate. A hunt that finds nothing is still a success *if you are satisfied you would have
found the behaviour had it been present* — which requires the gap statement above.

**Hunt record (required, one per hypothesis):**
```
Hypothesis (ABLE):     A: [actor or "any"]  B: [behaviour]  L: [terrain]  E: [source + expected signal]
ATT&CK:                [technique names, live IDs; procedure sentence]
Telemetry / schema:    [source, index/sourcetype or table, required fields, retention, time range]
Gap (needed − avail):  [invisible behaviours, terrain and time windows; "none" only if checked]
Analytic:              [query text or pseudo-logic + data model it targets]
Execution status:      WRITTEN-NOT-RUN | RUN by [who] on [date] over [range] | BLOCKED: [why]
Result:                [hits n; disposition each: malicious / benign-explained / open]
Known-benign:          [explained outliers to suppress]
Detection handoff:     level = report | dashboard | analytic-in-code | signature/rule;
                       logic; expected FP sources; owner; review date
```

**Rules.**
- Never report "no evidence found" for a hunt that was only **written**, or that ran against data
  missing a required field — report *untestable* with the gap (Heuer: "not looked" is not "looked,
  none"; analytic-standards §3).
- Choose the **highest** detection-output level you can maintain — rules over code over
  dashboards over reports (PEAK hierarchy of detection outputs); a report-level output is
  acceptable when benign volume needs human review.
- Hunt hits feed back into Phase 4 as new Diamond events; a hit is not attribution.
- Never fabricate query output, hit counts or field names the consumer has not confirmed.

---

## Phase 6 — Dissemination

**Select output format by consumer:**

| Consumer | Format | See |
|----------|--------|-----|
| SOC / IR team | F6 threat-brief | [`output/reports/format-catalog.md`](../output/reports/format-catalog.md) |
| CISO | F1 leadership-brief | |
| Analyst archive | F2 full-analysis | |
| Sharing community | STIX 2.1 export | [`output/reports/export-specs.md`](../output/reports/export-specs.md) |

**Pre-release checklist:**
- [ ] No active source or method revealed
- [ ] Attribution stated as a likelihood term + confidence, runner-up and linchpins named
- [ ] Bias checks B1–B10 recorded (PASS / FIXED / gap)
- [ ] Every hunt carries its execution status and telemetry gap; no unrun hunt reported as "nothing found"
- [ ] Victim identifiers removed (unless necessary)
- [ ] IOCs marked with freshness date (stale IOCs noted)
- [ ] All claims traceable to a finding ID

---

## Analyst Bias Controls

The checklist is [`analytic-standards.md`](../handbook/analytic-standards.md) §4 (B1–B10,
from Heuer `[B05 Heuer 1999, Ch 5, Ch 9–13]`); run it before release and record PASS / FIXED per
check. Quick map from the common names to those checks:

| Bias | Mitigation |
|------|-----------|
| Confirmation bias | ACH step 5: rank by inconsistencies, not by supporting rows; drop non-diagnostic rows (§3) |
| Attribution creep | 2+ **independent** owner-link indicators per same-operator claim (B3; rung table); persona ≠ owner ≠ person (intrusion-modeling §2) |
| Over-confidence | Confidence rises only with new diagnostic evidence, not more data (B9); linchpin cap (§3) |
| Availability bias | Probability from counts and base rates, not from how easily a similar case comes to mind (B7) |
| Anchoring on a prior verdict | Score from this case's matrix before reading `/recall` or vendor labels (B6) |
| Vividness, consistency, causal, scenario, hindsight | B1, B3–B5, B8, B10 |
