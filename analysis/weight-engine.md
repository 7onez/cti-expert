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

## Cross-References

- `analysis/exposure-model.md` — dimension-level exposure scoring that uses this engine
- `analysis/drift-monitor.md` — score change tracking over time
- `engine/workspace-state.md` — persists computed scores per subject
