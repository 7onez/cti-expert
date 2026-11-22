# Weight Engine

Produces a normalized composite score (0–100) for subject exposure using a weighted sum of indicator subscores. Uses min-max normalization to bring raw indicator values onto a common scale.

---

## Formula

```
COMPOSITE = Σ ( normalize(raw_i) × weight_i )

WHERE:
  raw_i    = raw indicator value (scale varies by indicator)
  normalize = min-max: (raw - min) / (max - min) → [0.0, 1.0]
  weight_i = indicator weight (all weights sum to 1.0)
  COMPOSITE = 0–100 (multiply final sum by 100)
```

---

## 1. Indicator Weight Table

### Security Group (total weight: 0.46)

| Indicator | Raw Scale | Min | Max | Weight |
|---|---|---|---|---|
| Breach count score | 0–100 | 0 | 100 | 0.17 |
| Credential reuse score | 0–100 | 0 | 100 | 0.13 |
| Account security score | 0–100 | 0 | 100 | 0.16 |

### Privacy Group (total weight: 0.16)

| Indicator | Raw Scale | Min | Max | Weight |
|---|---|---|---|---|
| Personal info exposure | 0–100 | 0 | 100 | 0.09 |
| Metadata leakage score | 0–100 | 0 | 100 | 0.07 |

### Reputation Group (total weight: 0.19)

| Indicator | Raw Scale | Min | Max | Weight |
|---|---|---|---|---|
| Content liability score | 0–100 | 0 | 100 | 0.11 |
| Persona consistency score | 0–100 | 0 | 100 | 0.08 |

### Legal Group (total weight: 0.12)

| Indicator | Raw Scale | Min | Max | Weight |
|---|---|---|---|---|
| Legal finding score | 0–100 | 0 | 100 | 0.08 |
| Compliance violation score | 0–100 | 0 | 100 | 0.04 |

### Infrastructure Group (total weight: 0.11)

| Indicator | Raw Scale | Min | Max | Weight |
|---|---|---|---|---|
| Threat intelligence score | 0–100 | 0 | 100 | 0.11 |

### Surface Group (total weight: 0.06)

| Indicator | Raw Scale | Min | Max | Weight |
|---|---|---|---|---|
| Platform breadth score | 0–100 | 0 | 100 | 0.06 |

**Weight sum verification:** 0.17+0.13+0.16+0.09+0.07+0.11+0.08+0.08+0.04+0.11+0.06 = **1.00**

---

## 2. Normalization

Min-max normalization maps each raw score to [0.0, 1.0]:

```python
def minmax_normalize(raw, min_val=0, max_val=100):
    if max_val == min_val:
        return 0.0
    return (raw - min_val) / (max_val - min_val)
```

For indicators already on a 0–100 scale, normalization is a no-op. For indicators on other scales (e.g., raw breach count 0–20), use domain-appropriate min/max:

| Indicator | Raw Input | Min | Max | Notes |
|---|---|---|---|---|
| Breach count | integer count | 0 | 10 | Cap at 10; higher → same as 10 |
| AbuseIPDB confidence | 0–100 | 0 | 100 | Direct percentage |
| OTX pulse count | integer count | 0 | 20 | Cap at 20 |
| VirusTotal detections | engine count | 0 | 90 | Total engines ≈ 90 |
| Platform count | integer count | 0 | 100 | Cap at 100 |

---

## 3. Per-Indicator Scoring

### Per-Indicator Additive Components

| Indicator | Condition | Points Added |
|---|---|---|
| **Breach count** | 1 breach | +22; 2–3 → +40; 4+ → +60 |
| | Recent breach ≤12mo | +18 |
| | Password exposed | +20; sensitive fields → +12 |
| **Credential reuse** | Reuse per platform | +10 each (cap 50) |
| | Weak pattern reuse | +25; no MFA → +10 |
| **Account security** | Impossible travel event | +18 each (cap 40) |
| | Suspicious login pattern | +25; session signal → +20 |
| **Content liability** | Harassment detected | +30; misinformation → +25 |
| | Mass deletion signal | +15; threat actor link → +35 |
| **Threat intelligence** | AbuseIPDB 25–74% | +20; ≥75% → +40 |
| | GreyNoise malicious | +40; OTX pulses ≥3 → +28 |
| | VirusTotal ≥10 engines | +40; 3–9 → +22; 1–2 → +10 |
| | Confirmed C2/botnet | +45 |

---

## 4. Context Multipliers

Applied after weighted sum, before final cap at 100:

| Condition | Multiplier | Applies To |
|---|---|---|
| Finding age ≤ 30 days | ×1.25 | Any indicator |
| Finding age > 730 days | ×0.80 | Any indicator |
| Verified public figure | ×1.20 | Full composite |
| Confirmed active compromise | ×1.35 | Full composite |
| Anonymous/pseudonymous subject | ×0.90 | Full composite |

```python
def apply_multipliers(base_score, subject, context):
    m = 1.0
    if context.most_recent_finding_age_days <= 30: m *= 1.25
    elif context.most_recent_finding_age_days > 730: m *= 0.80
    if subject.type == "verified_public_figure":  m *= 1.20
    if context.active_compromise_confirmed:        m *= 1.35
    elif subject.type == "pseudonymous":           m *= 0.90
    return min(100, base_score * m)
```

---

## 5. Weighted Sum Assembly

```python
WEIGHTS = {
    "breach":       0.17,
    "credentials":  0.13,
    "account":      0.16,
    "info":         0.09,
    "metadata":     0.07,
    "content":      0.11,
    "persona":      0.08,
    "legal":        0.08,
    "compliance":   0.04,
    "threat_intel": 0.11,
    "surface":      0.06
}

def weighted_composite(subject):
    scores = {
        "breach":       breach_count_score(subject),
        "credentials":  credential_reuse_score(subject),
        "account":      account_security_score(subject),
        "info":         personal_info_score(subject),
        "metadata":     metadata_leakage_score(subject),
        "content":      content_liability_score(subject),
        "persona":      persona_consistency_score(subject),
        "legal":        legal_finding_score(subject),
        "compliance":   compliance_violation_score(subject),
        "threat_intel": threat_intel_score(subject),
        "surface":      platform_breadth_score(subject)
    }

    raw = sum(
        minmax_normalize(scores[k]) * WEIGHTS[k]
        for k in scores
    ) * 100

    return apply_multipliers(raw, subject, context)
```

---

## 6. Score Bands

| Score | Grade | Action |
|---|---|---|
| 0–15 | A | Routine monitoring only |
| 16–30 | B | Quarterly review |
| 31–45 | C | Bi-monthly analyst review |
| 46–65 | D | Active case, weekly review |
| 66–80 | F1 | Priority escalation |
| 81–90 | F2 | Critical — daily monitoring |
| 91–100 | F3 | Emergency — immediate response |

---

## 7. Executive Model (deductive, `--model executive`)

A second, separate model for a **protected person** (an executive, a public figure, a client
under a protective-intelligence engagement). It answers "how much of this person can an
adversary assemble?" with an analyst rating per criterion, and runs the opposite way from §1–§6:
the subject **starts at 100 and loses points**, so **higher = safer**. Never put an executive score
and a composite score in the same column of a report.

```
SCORE     = 100 − Σ deduction_i                 (over the RATED criteria only)
deduction = max_i × rating_i / 3                rating ∈ {0,1,2,3}
  0 = no exposure found   1 = minor   2 = significant   3 = severe / fully exposed
```

| # | Criterion | Max deduction | Rate on (examples) |
|---|---|---|---|
| C1 | Digital account footprint | 15 | discoverable, linkable accounts and handles |
| C2 | PII exposure | 20 | national ID, date of birth, personal phone / e-mail, tax or registry numbers |
| C3 | Family / close-relation exposure | 15 | spouse, children, relatives, close associates identifiable and exposed |
| C4 | Physical address & habits | 15 | home address, routine locations, travel patterns, geotagged media |
| C5 | Corporate assets & financial exposure | 10 | company roles, shareholdings, registered assets, payment identifiers |
| C6 | Political / reputation | 10 | affiliation, controversy, adverse media, litigation |
| C7 | Breach records & stealer logs | 10 | subject identifiers in breach corpora or infostealer logs |
| C8 | Account & infrastructure security | 5 | spoofable mail domains (`email_hygiene.py` spoofability), no MFA evidence, exposed admin surfaces |

The maxima sum to 100, so rating every criterion 3 reaches 0.

| Score | Band |
|---|---|
| ≥ 80 | LOW |
| 60–79 | MODERATE |
| 40–59 | HIGH |
| < 40 | CRITICAL |

**Worked example.** C1=2, C2=3, C3=1, C4=0, C5=2, C6=1, C7=3, C8=3 →
deductions 10 + 20 + 5 + 0 + 6.67 + 3.33 + 10 + 5 = 60 → **40 (HIGH)**, coverage 8/8.

**Coverage, not silence.** An unrated criterion is *unknown*, not *clean*. The tool lists it in
`missing`, reports `coverage` as `rated/8`, and adds `score_floor` / `band_floor` — the score if
every unrated criterion proved fully exposed. A subject rated on 3/8 criteria with score 71.67
(MODERATE) and floor 16.67 (CRITICAL) has not been assessed as moderate; the report says so.

Each rating SHOULD carry a rationale (`cN_rationale`) naming the evidence that drove it, so the
score can be re-derived and challenged. Criteria, maxima and bands live in
`scripts/osint/references/exposure_executive.json`.

```bash
exposure_score.py --model executive --set c1=2 --set c2=3 --set c2_rationale="ID number in a leak"
exposure_score.py --model executive ratings.json   # {"c1": 2, "c2": {"rating": 3, "rationale": "..."}}
exposure_score.py --model executive --list
```

---

## 8. Organisation Model (risk by domain, `--model organisation`)

This is a third, separate model for an **organisation** under a cyber-risk assessment. It answers
"where is this organisation most exposed, and how badly would it hurt?" one risk domain at a time.
It is **analyst judgement on a fixed scale**:

- Every rating is set by the analyst from the evidence. The tool never derives a rating from
  collected data.
- The score is **not a probability** of compromise. It ranks domains for remediation.

Higher = riskier, on a 0–10 scale. An organisation score cannot go in the same column as a
composite score (0–100, §1–§6) or an executive score (100 = safe, §7).

```
DOMAIN SCORE = score_matrix[exploitability][harm]     exploitability, harm ∈ {0,1,2,3}
               default matrix = (e × h) / 9 × 10, rounded half-up to one decimal
OVERALL      = mean of the RATED domain scores        (unrated domains excluded)
```

| id | Domain | Rate on (examples) |
|---|---|---|
| `affiliates` | Affiliate, member and partner compromise | member or affiliate organisations whose exposure opens a path in |
| `impersonation` | Impersonation and fraud industry | lookalike domains, fake profiles and apps, fraud kits using the brand |
| `edge` | Network edge and remote access | internet-facing VPN, RDP, mail, admin panels, edge appliances with public exploits |
| `insider` | Insider and channel abuse | staff or contractor misuse, abuse of support / sales / partner channels |
| `personnel` | Key personnel and leadership | executives whose exposure enables targeting or pretexting (§7 per person) |
| `actors` | State actors and criminal markets | documented interest of state actors, ransomware crews, access brokers |
| `credentials` | Staff credentials | staff identifiers in breach corpora and infostealer logs, credential reuse |
| `suppliers` | Suppliers and partners | vendors inferable from DNS, mail and documents, and their compromises |
| `mail_dns` | Certificates, email and domains | SPF / DMARC / DKIM, spoofability, dangling records, certificate hygiene |
| `code_docs` | Code, apps and documents | public repositories, secrets in code, mobile apps, document metadata |

**Rubric.** Rate each domain on the rubric below.

- **Exploitability** asks how an adversary could use the issue. It covers three things:
  - reachability from the internet;
  - the tooling available;
  - in-the-wild use.
- **Harm** asks what it would cost the organisation. It covers four things:
  - data;
  - operations;
  - partners;
  - reputation.

| Level | Exploitability | Harm |
|---|---|---|
| 0 | not reachable from the internet, or no known way to use it | no meaningful effect on data, operations, partners or reputation |
| 1 | reachable only with prior access or an insider position; no public tooling; no known in-the-wild use | limited: low-sensitivity data, brief local disruption, minor reputational noise |
| 2 | reachable from the internet with effort; public tooling or a published technique; sporadic in-the-wild use | significant: personal or business data exposed, service disruption, partners affected, media attention |
| 3 | directly reachable from the internet; commodity tooling; active in-the-wild use against similar targets | severe: large-scale or sensitive data loss, prolonged outage, partner or member compromise, lasting reputational damage |

Default score matrix (rows = exploitability, columns = harm):

| e \ h | 0 | 1 | 2 | 3 |
|---|---|---|---|---|
| 0 | 0.0 | 0.0 | 0.0 | 0.0 |
| 1 | 0.0 | 1.1 | 2.2 | 3.3 |
| 2 | 0.0 | 2.2 | 4.4 | 6.7 |
| 3 | 0.0 | 3.3 | 6.7 | 10.0 |

Bands and remediation priorities:

| Score | Level |
|---|---|
| ≥ 8.0 | Critical |
| ≥ 6.0 | High |
| ≥ 4.0 | Medium |
| < 4.0 | Low |

| Priority | Fix within |
|---|---|
| P1 | 7 days |
| P2 | 30 days |
| P3 | 90 days |

A band edge is inclusive: 8.0 is Critical, but 7.9 is High.

**Rationale and issue.** Each domain can carry two notes:

- `<d>_rationale` names the evidence behind the rating.
- `<d>_issue` gives the one-line main issue printed in the report.

A domain rated at **harm 3 must carry a rationale**. Without one, the tool refuses to score.

**Errors.** The tool also refuses to score in these cases:

- it does not know a domain id;
- a domain has only one of its two axes rated;
- a rating falls outside 0–3;
- no domain is rated at all.

**Coverage, not silence.** An unrated domain is *unknown*, not *low risk*. Unrated domains are
handled like this:

- They are excluded from the mean.
- They are listed under `coverage.unrated`.
- When fewer than half the domains are rated, `coverage.warning` says so.

Never compare two organisations rated on different domain coverage. The `coverage.note` in every
result says this.

**Worked example (synthetic).** *Example Org*, three domains rated:

| Domain | e | h | Score | Level | Rationale |
|---|---|---|---|---|---|
| `edge` | 3 | 3 | 10.0 | Critical | remote-access gateway at vpn.example.com runs a version with a public exploit |
| `credentials` | 2 | 2 | 4.4 | Medium | staff addresses @example.com in two stealer-log corpora |
| `mail_dns` | 2 | 1 | 2.2 | Low | DMARC p=none on example.com |

The overall score is (10.0 + 4.4 + 2.2) / 3 = 5.53, which rounds to **5.5 (Medium)**. Coverage is
3/10, so the result carries a warning: seven domains are unknown, and the 5.5 describes only the
three that were assessed. The analyst assigns remediation priorities in the report; a Critical
`edge` finding like this one would normally be P1 (7 days).

**Output** is the organisation risk object that the house report renders as `risk_assessment`:

```json
{"model": "organisation",
 "domains": [{"id": "edge", "name": "Network edge and remote access", "exploitability": 3,
              "harm": 3, "score": 10.0, "level": "Critical", "main_issue": "...", "rationale": "..."}],
 "overall": {"score": 5.5, "level": "Medium", "method": "mean of rated domains",
             "note": "analyst judgement on a fixed 0-10 scale, not a probability"},
 "coverage": {"rated": 3, "total": 10, "unrated": ["affiliates", "..."], "note": "...", "warning": "..."},
 "bands": {"Critical": 8.0, "High": 6.0, "Medium": 4.0, "Low": 0.0},
 "priorities": {"P1": "7 days", "P2": "30 days", "P3": "90 days"}}
```

With `--case <id>`, the tool also writes this object to `cases/<id>/exposure_organisation.json`.
The following all live in `scripts/osint/references/exposure_organisation.json`, so a new domain
there becomes ratable and counts towards `coverage.total`:

- domains;
- the rubric;
- the score matrix;
- bands;
- priorities;
- the harm level that requires a rationale;
- the coverage-warning ratio.

```bash
exposure_score.py --model organisation --set edge=3x3 --set edge_rationale="public exploit for the VPN"
exposure_score.py --model organisation ratings.json --case CASE-0001
    # {"edge": {"exploitability": 3, "harm": 3, "rationale": "...", "issue": "..."}, "mail_dns": "2x1"}
exposure_score.py --model organisation --ratings '{"credentials": "2x2"}'
exposure_score.py --model organisation --list
```

---

## 9. Actor Model (Threat Score, `--model actor`)

A fourth, separate model. It answers "how much of a threat is **this actor** to **this
organisation**?" Adapted from the Threat Actor Scoring Model in
[PK Packt ACTIH companion repo, 2026, chapter-01/Threat Actor Scoring Model.md] (MIT),
[pinned](https://github.com/PacktPublishing/Advanced-Cyber-Threat-Intelligence-and-Hunting/blob/0f76fbc2ff505e6fcb2585b1b3d0b08ce271b1e4/chapter-01/Threat%20Actor%20Scoring%20Model.md).

**Rails.** The Threat Score is an analyst judgement and a lead:

- It is never attribution and never a same-operator edge. It does not go into the KB as a link.
- It is **specific to one organisation**: `sectoral_reach` and `org_exposure` describe that
  organisation. Never compare actor scores across organisations, or across runs with different
  `org_exposure` ratings. Every result carries this in `note`.
- It is not a probability. Higher = more threatening, on 0.00–1.00.

**Trigger.** Score an actor when you create its profile (`handbook/aam-actor-modeling.md`), when a
significant update lands, at the band's review cadence, and on any out-of-cycle trigger (new
attribution work, the actor named in a peer incident in our sector, a geopolitical shift between
its sponsor and our country, or a major change on our side such as an acquisition or a new
platform).

**Inputs.** The actor name, plus four analyst ratings from 0.0 to 1.0 in steps of 0.25. Any other
value is refused.

| id | Dimension | Question |
|---|---|---|
| `intent` | Intent | does the actor want to hit this organisation, its sector or its geography? |
| `capability` | Capability | could it carry out an operation against us if it chose to? |
| `sectoral_reach` | Opportunity: sectoral reach | does it operate against organisations like ours, in general? |
| `org_exposure` | Opportunity: organisational exposure | given our current environment, can it actually reach us? |

The scale anchors for each step are printed by `--model actor --list`.

**Steps.**

```
OPPORTUNITY  = 0.6 × sectoral_reach + 0.4 × org_exposure
THREAT SCORE = 0.5 × intent + 0.25 × capability + 0.25 × opportunity
Intent floor rule: intent = 0.0  →  THREAT SCORE = 0.0, whatever the other ratings
```

Both values are rounded half-up to two decimals. The band is read from the **rounded** score, so a
reader can check the band against the published number.

| Threat Score | Band | Review cadence | Operating posture (summary) |
|---|---|---|---|
| ≥ 0.85 | Critical | monthly | dedicated profile, standing hunts, detection tested against its tooling, leadership briefed each quarter |
| ≥ 0.60 | High | quarterly | periodic hunts, its tooling in detection-engineering planning, yearly top-threat briefing |
| ≥ 0.35 | Medium | quarterly | covered by ordinary detection work, opportunistic hunting only |
| ≥ 0.10 | Low | out-of-cycle only | profile kept, reporting read at intake, general controls only |
| < 0.10 | Negligible | out-of-cycle only | catalogue only; the written rationale is the artifact |

A band edge is inclusive: 0.85 is Critical and 0.849 is High. `review_due` is `as_of` (default
today, UTC) plus the cadence. It is `null` for Low and Negligible, which have no fixed cadence.

**Rationale and evidence.** The tool refuses to score in these cases:

- A dimension has no `<dim>_rationale`.
- `intent` is 0.75 or higher and neither `intent_evidence` nor `intent_rationale` cites evidence,
  meaning a URL or a case reference (`CASE-…`, `cases/…`). An intent judgement without cited
  evidence is a guess.
- The result is Negligible and there is no overall `rationale=`. A later analyst must be able to
  see why the actor sits this low. This matters most when the Intent floor rule set the score,
  because a capable actor at 0.00 looks like a mistake.

**Output.**

```json
{"model": "actor", "actor": "...", "dimensions": {"intent": 0.75, "capability": 0.5,
 "sectoral_reach": 0.75, "org_exposure": 0.5}, "opportunity": 0.65, "threat_score": 0.66,
 "band": "High", "posture": ["..."], "review_cadence": "quarterly", "review_due": "YYYY-MM-DD",
 "as_of": "YYYY-MM-DD", "floor_applied": false, "rationales": {"intent": "...", "overall": "..."},
 "evidence": {"intent": "..."}, "note": "...", "tier": {"...": "only with exposure_level"}}
```

**Persistence (`--case`).** With `--case <id>` the result is stored in
`cases/<id>/actor_scores.json`, keyed by actor name. A re-score keeps the new result and appends
`{utc, old, new, shift, reason}` to that actor's `history`. Pass `reason=` to say what changed.
Most actors move by no more than 0.10 in a quarter. A shift above 0.10 with no reason is stored
with a `warning` and printed (upstream score-stability guidance).

**Tier.** Add `exposure_level=None|Limited|Significant|Extensive` to get the Severity Tier Matrix
tier (§10) as `tier`. The band is Axis 1. Negligible has no Axis 1 row and maps to Low, with a
note.

**Confounders.**

- **Capability is the easiest dimension to see, so it tends to dominate the discussion.** It
  carries only a quarter of the score. Do not raise intent because an actor is impressive.
- **Victimology bias.** Published victim lists over-represent sectors that disclose. An absence
  of reported victims in our sector is weak evidence of low intent.
- **`org_exposure` moves with our own changes**, such as a new deployment or new detections. A
  shift there is not a change in the actor.

**Abstain** (do not score; record why in the actor profile) when you cannot rate intent from any
cited source, or when the actor's identity itself is unsettled (a cluster that may be two actors).
A score on a guessed intent is worse than no score.

**Worked example A: an Intent-floored capable actor (synthetic).** *Example Org* (CASE-0001) is
a regional freight company. It rates *EXAMPLE-SPIDER*:

| Dimension | Rating | Rationale |
|---|---|---|
| intent | 0.0 | its reported targeting is retail payment systems on another continent; nothing touches freight or our region |
| capability | 0.75 | bespoke loaders and steady infrastructure rotation across two years of reporting |
| sectoral_reach | 0.25 | one reported intrusion at a parcel-tracking supplier, outside our region |
| org_exposure | 0.5 | we run the same remote-support product it has abused; detection covers part of its chain |

Opportunity = 0.6 × 0.25 + 0.4 × 0.5 = **0.35**. The weighted sum would be 0.1875 + 0.0875 =
0.275 (Low), but intent is 0.0, so the Intent floor rule applies: **0.00, Negligible**. The tool
requires the overall rationale, for example "capable, partly reachable, no interest in freight or
our region; re-score if its targeting moves". The actor stays in the catalogue with no active
work.

**Worked example B: a high-intent, mid-capability actor (synthetic).** For the same company,
*SAMPLE PANDA*:

| Dimension | Rating | Rationale |
|---|---|---|
| intent | 0.75 | three freight operators in our region phished this year (evidence: CASE-0001 note, https://intel.example.com/report-0042) |
| capability | 0.5 | commodity remote-access tool, some custom scripting, slow to rotate infrastructure |
| sectoral_reach | 0.75 | direct peers on the same dispatch software |
| org_exposure | 0.5 | dispatch servers are internet-facing, and multi-factor sign-in is only partly rolled out |

Opportunity = 0.45 + 0.20 = **0.65**. Threat Score = 0.375 + 0.125 + 0.1625 = 0.6625, which rounds
to **0.66, High**. That means a quarterly review (`review_due` = `as_of` + 90 days) and periodic
hunts. With `exposure_level=Limited`, the tier is High × Limited = **P3**. Intent carries most of
the score here: the same actor rated for a company outside freight would land much lower.

```bash
exposure_score.py --model actor --ratings '{"actor": "SAMPLE PANDA", "intent": {"rating": 0.75,
  "rationale": "...", "evidence": "CASE-0001"}, "capability": {"rating": 0.5, "rationale": "..."},
  "sectoral_reach": {"rating": 0.75, "rationale": "..."}, "org_exposure": {"rating": 0.5,
  "rationale": "..."}}' --set exposure_level=Limited --case CASE-0001
exposure_score.py --model actor ratings.json --set reason="new phishing wave against peers" --case CASE-0001
exposure_score.py --model actor --list
```

Weights, steps, bands, postures, cadences, the evidence pattern and the drift threshold live in
`scripts/osint/references/exposure_actor.json`.

---

## 10. Severity Tier Matrix (`--model tier`)

This turns one intelligence trigger into a response tier, **P1–P4**, from two analyst-rated axes.
Adapted from the CTI Severity Tier Matrix in
[PK Packt ACTIH companion repo, 2026, chapter-01/CTI Severity Tier Matrix.md] (MIT),
[pinned](https://github.com/PacktPublishing/Advanced-Cyber-Threat-Intelligence-and-Hunting/blob/0f76fbc2ff505e6fcb2585b1b3d0b08ce271b1e4/chapter-01/CTI%20Severity%20Tier%20Matrix.md).
The two axes are:

- **Axis 1, threat severity**: Critical, High, Medium or Low. It is rated from the threat itself,
  before looking at our environment.
- **Axis 2, exposure**: None, Limited, Significant or Extensive. It combines five dimensions:
  technical, targeting, tradecraft, relational and detection.

The per-trigger severity patterns and the exposure dimension guides are in
`handbook/severity-tiers.md`, which is the operator-facing procedure.

| Severity \ Exposure | None | Limited | Significant | Extensive |
|---|---|---|---|---|
| Critical | P3 | P2 | **P1** | **P1** |
| High | P4 | P3 | P2 | **P1** |
| Medium | P4 | P3 | P3 | P2 |
| Low | P4 | P4 | P4 | P3 |

**Design rules** (checked when the grid loads; a re-weighted grid that breaks one is refused):

- **P1 needs both axes.** It needs severity of at least High and exposure of at least Significant.
  P1 is impossible below High severity.
- **Nothing closes automatically.** Every cell is a tier. Low × None is P4: tracked, not dropped.

| Tier | Name | Deadline | `key_findings` priority | `roadmap` priority |
|---|---|---|---|---|
| P1 | Flash | 7 days | P1 | P1 |
| P2 | Priority | 30 days | P2 | P2 |
| P3 | Standard | 90 days | P3 | P3 |
| P4 | Informational | none: track only | P4 | never |

**Reconciliation with the house report.** P1–P3 deadlines are the same as
`risk_assessment.priorities` (§8: P1 7 days, P2 30 days, P3 90 days). A finding from a P1–P3
tier carries that tier as `key_findings.priority` and `roadmap.priority`. A P4 finding carries
`P4` in `key_findings`, rendered "P4 (track only — no deadline)", and never becomes a roadmap
row, because `roadmap.priority` accepts P1–P3 only. A Critical finding at P4 is flagged by the
report; check the axes before keeping it. The item stays in the tier log either way.

**Actor input.** An actor's band (§9) is Axis 1. Negligible maps to Low, with a note.

**Re-tiering.** A tier is not fixed. With `--case <id> --set item=<what is tiered>`, the tool
keeps `cases/<id>/tier_log.json`:

- The first assignment logs trigger `initial`.
- Any later change of cell must name a trigger id and a `rationale`. It appends
  `{utc, old, new, trigger, rationale}`, where `old` and `new` are `{severity, exposure, tier}`.

| Trigger id | Axis | Direction | When |
|---|---|---|---|
| `exploitation_confirmed` | severity | up | in-the-wild exploitation or live campaign use is confirmed |
| `new_exposure` | exposure | up | missed inventory, a new deployment, a newly found vendor tie, a control gap |
| `mitigation_threshold` | exposure | down | patched, detections live and validated, controls tightened, vendor fixed |
| `actor_adopts` | severity | up | an actor of concern takes up the technique or vulnerability, whatever the patch state |
| `sector_shift` | severity | up | an actor or campaign moves its targeting into our sector |
| `attribution_downgrade` | severity | down | the attacker is reassessed as less capable |
| `actor_rescored` | severity | either | (adaptation) the actor's Threat Score crossed a band boundary |

**Worked example: a vulnerability trigger walked through the grid (synthetic).** An advisory
describes an unauthenticated remote code execution flaw in *ExampleGate*, an invented
remote-access appliance. A public proof of concept is out, and the vendor fix is two days old.

- **Axis 1.** Direct compromise, no prerequisites, public exploit code, a fix under 72 hours old:
  this matches the Critical vulnerability pattern.
- **Axis 2.** Example Org runs two ExampleGate units at vpn.example.com (192.0.2.10 and
  192.0.2.11).
  - Technical: few assets, but both are internet-facing and give access to identity systems.
  - Detection: partial. Gateway logs reach the SIEM, but nothing alerts on the exploit's request
    pattern.
  - Exposure: **Significant**.
- **Cell.** Critical × Significant = **P1** (7 days).

A week later one unit is patched, the other is taken offline, and a validated detection is live.
Exposure drops to Limited, so the tier becomes Critical × Limited = **P2**. The log records
`trigger=mitigation_threshold` and the rationale.

```bash
exposure_score.py --model tier --set severity=Critical --set exposure=Significant \
  --set rationale="both units internet-facing, no exploit detection" --set item=examplegate-rce --case CASE-0001
exposure_score.py --model tier --set severity=Critical --set exposure=Limited --set item=examplegate-rce \
  --set trigger=mitigation_threshold --set rationale="one unit patched, one offline, detection validated" --case CASE-0001
exposure_score.py --model tier --list
```

The grid, rules, tiers, deadlines, exposure dimensions and re-tier triggers live in
`scripts/osint/references/severity_tiers.json`.

---

## Cross-References

- `analysis/exposure-model.md` — dimension-level exposure scoring that uses this engine
- `analysis/drift-monitor.md` — score change tracking over time
- `engine/workspace-state.md` — persists computed scores per subject
