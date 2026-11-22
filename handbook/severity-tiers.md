# Severity Tiers

The operator reference for turning one intelligence trigger into a response tier, **P1–P4**.
Adapted from the CTI Severity Tier Matrix in
[PK Packt ACTIH companion repo, 2026, chapter-01/CTI Severity Tier Matrix.md] (MIT),
[pinned](https://github.com/PacktPublishing/Advanced-Cyber-Threat-Intelligence-and-Hunting/blob/0f76fbc2ff505e6fcb2585b1b3d0b08ce271b1e4/chapter-01/CTI%20Severity%20Tier%20Matrix.md).
The arithmetic and a worked example are in `analysis/weight-engine.md` §10. Actor scoring is in §9.

A tier is a **response priority**, set by analyst judgement. It is not attribution evidence, not a
same-operator edge, and not a probability.

---

## Procedure

**Trigger.** Any intelligence item that may need a response. That includes:

- a vulnerability or malware report;
- a campaign write-up;
- an incident at a peer;
- a supplier or dependency compromise;
- a geopolitical event;
- an actor profile or a re-score of one (use `--model actor`, see below).

**Inputs.** The item itself and what you know about your own estate: inventory, controls,
detection coverage and relationships.

**Steps.**

1. **Rate Axis 1, threat severity.** Use the pattern table for the trigger type, and judge the
   threat on its own, without looking at your environment. This is the provisional severity.
   When a trigger fits two rows, take the row its strongest confirmed fact supports, not the row
   its worst rumour suggests.
2. **Rate Axis 2, exposure.** Walk the five dimensions below. Take the level that the
   **dominant** dimension for this trigger type supports, and say in the rationale which
   dimension drove it.
3. **Read the cell** from the grid:
   `exposure_score.py --model tier --set severity=<S> --set exposure=<E> --set rationale="..."`.
4. **Record it** when it belongs to a case: add `--case <id> --set item=<short id>`. This writes
   `cases/<id>/tier_log.json`.
5. **Re-tier** whenever a trigger in the re-tiering table fires. Pass `--set trigger=<id>` and a
   rationale saying what changed. The log keeps every change.

**Output.** `{model: "tier", severity, exposure, tier, cell{row, column, value}, deadline,
report_priority, tier_name, rationale, notes?}`.

**Confounders.**

- **Loud is not severe.** Media volume and vendor marketing push severity up. Rate the threat from
  its facts: impact, prerequisites, exploit status and fix status.
- **Missing inventory reads as None.** Exposure of None needs positive evidence, such as an asset
  search that came back empty. Without that evidence the level is unknown, not None.
- **Severity and exposure are separate questions.** Do not lower severity because "we are not
  affected". Express that through exposure.

**Abstain** (record "not tiered" and why) when you cannot rate both axes. Typical cases are an
unverified single-source report, or an inventory owner who has not answered yet. A guessed axis
produces a wrong tier that looks authoritative. Set a provisional severity in the tracking record
instead, and tier once exposure is known.

---

## Axis 1: threat severity, by trigger type

Rated from the threat itself, before looking at your environment. The facets considered are:

- **Vulnerabilities and malware:** what it gives the attacker, what it needs first, whether
  exploit code or real use exists, and whether a fix exists and how old it is.
- **Campaigns:** skill, scale, tempo, how often it succeeds against organisations like yours, and
  how well its infrastructure survives takedown.
- **Peer incidents:** how bad the underlying compromise was, how skilled the attacker looked, and
  how quickly it caused harm.
- **Supply chain:** how badly the supplier was compromised, how widely the affected component is
  used, and what access the attacker gained through it.
- **Geopolitical events:** how strongly similar events have been followed by cyber activity
  before, which actors are likely to move, and the timing.

| Level | Vulnerability / malware | Campaign | Peer incident | Supply chain | Geopolitical |
|---|---|---|---|---|---|
| **Critical** | direct compromise (remote code execution, authentication bypass) with little or nothing needed first; exploit code public or real-world use seen; no fix, or a fix under 72 hours old | skilled, active, often succeeding, aimed at a wide target set that includes your sector, with no public detection advice yet | confirmed compromise at a directly comparable peer by a skilled attacker within the last 30 days | confirmed compromise of a widely used supplier or component, where the attacker could push code or updates downstream | an event that has reliably been followed by destructive or disruptive activity against your country or sector, with actors already mobilising |
| **High** | privilege escalation, sensitive-data exposure or a strong lateral-movement aid; exploit code or credible reports of use; a fix exists but is not widely applied | capable and active with techniques relevant to you; targets sectors next to yours; detection advice starting to appear | confirmed compromise at a sector peer, attribution unclear or the attacker moderately skilled | a supplier with meaningful but bounded reach, or a widely used dependency | an event that has often been followed by espionage or nuisance activity against your region |
| **Medium** | real impact but held back by preconditions (local access, a specific configuration, a chain of flaws); exploit code may exist; no real-world use seen | less skilled, well-known techniques with broad public detection, not aimed at your sector | confirmed incident at an organisation outside your sector, of limited relevance | a supplier with limited reach, or impact that is well contained | an event with only a loose historical link to cyber activity |
| **Low** | limited impact, theoretical or very hard to use, unusual configurations only; no exploit code | unskilled, well-detected commodity activity with no relevance to your sector | a distant or weakly relevant incident, kept for tracking | minimal reach, contained impact, or a supplier you do not use | an event with no visible link to cyber activity, kept for awareness |

The geopolitical column is an adaptation: upstream lists the geopolitical facets but gives no
per-level pattern.

**From an actor score.** When the trigger is an actor profile or re-score, Axis 1 is the actor's
band from `--model actor`:

| Actor band | Axis 1 |
|---|---|
| Critical | Critical |
| High | High |
| Medium | Medium |
| Low | Low |
| Negligible | Low, with a note. The grid never closes, so the result is at worst a tracked P4. |

`exposure_score.py --model actor ... --set exposure_level=<E>` returns the tier directly.

---

## Axis 2: exposure

Rate each dimension that applies to the trigger, then take one level overall.

| Dimension | Question |
|---|---|
| **Technical** | do we run the affected technology, how much of it, and in which critical domains? |
| **Targeting** | are we inside the sector, region or organisation type the threat goes after? |
| **Tradecraft** | do our controls cover the techniques involved, or do they land on a gap? |
| **Relational** | are we tied to victims through a vendor, shared infrastructure, peering or partnership? |
| **Detection** | would we see this activity class if it were happening here? |

| Level | Technical | Targeting | Tradecraft | Relational | Detection |
|---|---|---|---|---|---|
| **Extensive** | a large share of the estate, and it sits in critical domains (identity, internet-facing edge, core production) | we are squarely in the observed or stated target set | the techniques land on real control gaps, with nothing compensating | we depend directly on the compromised supplier, or share infrastructure with confirmed victims | we would not see it |
| **Significant** | a meaningful number of assets, **or** any presence in a critical domain whatever the count | we are next to the targeted population, with partial overlap | controls cover part of it; detection exists but is incomplete or untested | we depend on the supplier indirectly, or peer with affected parties | partial, low-confidence visibility |
| **Limited** | a handful of assets outside critical domains, or critical assets behind strong compensating controls | outside the target set, with only faint adjacency | controls cover all but edge cases | a distant, immaterial connection | we would probably see it |
| **None** | no affected assets, or affected assets fully isolated or mitigated | outside the target set, with no adjacency | controls fully cover it | no dependency, peering or shared infrastructure | full visibility of the activity class |

"Negligible" is accepted as another name for None.

---

## The grid

| Severity \ Exposure | None | Limited | Significant | Extensive |
|---|---|---|---|---|
| **Critical** | P3 | P2 | **P1** | **P1** |
| **High** | P4 | P3 | P2 | **P1** |
| **Medium** | P4 | P3 | P3 | P2 |
| **Low** | P4 | P4 | P4 | P3 |

- **Exposure pulls harder upward than downward.** A top-severity threat with no current exposure
  still gets P3, because exposure can appear through a new deployment, a missed asset or a
  supplier change. A low-severity threat stays at P3 at most, however exposed you are, because
  its impact is capped.
- **P1 needs both axes.** It needs severity of at least High and exposure of at least
  Significant. P1 is impossible below High severity. The tool refuses to load a grid that breaks
  this rule.
- **Nothing closes automatically.** Low × None is P4: tracked, not ignored.

## Tiers and the house report

| Tier | Name | Deadline | `key_findings` priority | `roadmap` priority | Typical response |
|---|---|---|---|---|---|
| P1 | Flash | 7 days | P1 | P1 | advisory the same day to leadership and owners, hunt package, daily tracking |
| P2 | Priority | 30 days | P2 | P2 | planned response within the month; advisory normally issued |
| P3 | Standard | 90 days | P3 | P3 | handled in normal work, reviewed for re-tiering |
| P4 | Informational | none: track only | P4 | never | recorded in the tier log, not closed |

The P1–P3 deadlines are the same as the house report's `risk_assessment.priorities`. A finding
from a P1–P3 tier carries the same label in `key_findings.priority` and in `roadmap`. A P4
finding carries `P4` in `key_findings`, which renders as "P4 (track only — no deadline)". It
never becomes a roadmap row, because `roadmap.priority` accepts P1–P3 only. The report flags a
Critical finding at P4, so re-check both axes before keeping that combination.

## Re-tiering

| Trigger id | Re-rate | When |
|---|---|---|
| `exploitation_confirmed` | severity up | in-the-wild exploitation or live campaign use is confirmed |
| `new_exposure` | exposure up | missed inventory, a new deployment, a newly found vendor tie, a control gap |
| `mitigation_threshold` | exposure down | patched, detections live and validated, controls tightened, vendor fixed |
| `actor_adopts` | severity up | an actor of concern takes up the technique or vulnerability, whatever the patch state |
| `sector_shift` | severity up | an actor or campaign moves its targeting into our sector |
| `attribution_downgrade` | severity down | the attacker is reassessed as less capable |
| `actor_rescored` | severity, either way | (adaptation) the actor's Threat Score crossed a band boundary at a re-score |

Each change appends one entry to the item's `log` in `cases/<id>/tier_log.json`:

```json
{"utc": "YYYY-MM-DDTHH:MM:SSZ",
 "old": {"severity": "Critical", "exposure": "Significant", "tier": "P1"},
 "new": {"severity": "Critical", "exposure": "Limited", "tier": "P2"},
 "trigger": "mitigation_threshold",
 "rationale": "what changed, with the evidence"}
```

The first assignment is logged with `old: null` and `trigger: "initial"`. A change of cell without
a known trigger id and a rationale is refused.

```bash
exposure_score.py --model tier --set severity=High --set exposure=Extensive --set rationale="..."
exposure_score.py --model tier --case CASE-0001 --set item=<id> --set severity=... --set exposure=... \
  --set trigger=new_exposure --set rationale="..."
exposure_score.py --model tier --list
```

The grid, rules, tiers, exposure dimensions and triggers live in
`scripts/osint/references/severity_tiers.json`.
