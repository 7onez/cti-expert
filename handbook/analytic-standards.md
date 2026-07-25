# Analytic Standards — likelihood language, 5W1H coverage, competing hypotheses

The skill already grades **evidence** (trust score 1–5, source reliability A–F, confidence
VERIFIED→CHALLENGED). This file governs the layer above: how **judgments** are expressed, how
coverage is judged *substantively* rather than by technique count, and how rival explanations
are tested before one is asserted.

Reference lineage: ICD 203 analytic standards, Heuer's *Psychology of Intelligence Analysis*
and *Structured Analytic Techniques*, UNODC *Criminal Intelligence Manual for Analysts*.

---

## 1. Likelihood language (probability-anchored)

**Problem this solves.** `CONFIDENCE: MODERATE` is an ordinal word with no numeric anchor.
Writer and reader routinely differ by 30 percentage points on what it means, and the report
gives them no way to notice.

Every **analytic judgment** — not every finding — must carry one of these terms. Use the term,
optionally with the band; never a bare percentage, which implies false precision.

| Term | Band | Use when |
|------|------|----------|
| **Almost no chance** / Remote | 1–5% | Contradicted by strong evidence, but not physically impossible |
| **Very unlikely** / Highly improbable | 5–20% | Evidence points clearly the other way |
| **Unlikely** / Improbable | 20–45% | Weight of evidence against, alternatives better supported |
| **Roughly even chance** | 45–55% | Genuinely balanced — say so rather than picking a side |
| **Likely** / Probable | 55–80% | Weight of evidence supports it; alternatives remain live |
| **Very likely** / Highly probable | 80–95% | Strong, corroborated support; alternatives weak |
| **Almost certain** | 95–99% | Multiple independent primary sources agree; no credible alternative |

### Rules

1. **Never state 0% or 100%.** OSINT cannot establish either.
2. **One term per judgment.** "Likely to very likely" is hedging; pick the band your evidence
   supports.
3. **Separate likelihood from confidence.** They are orthogonal:
   *"The operator is **very likely** based in Guangdong (**moderate confidence** — single
   registry record, unverified)."* Likelihood = how probable the claim is. Confidence = how
   good the evidence base is. High likelihood on weak evidence is a legitimate — and important
   — state to report.
4. **Anchor to evidence, not to feel.** If you cannot name what would move the estimate up or
   down a band, the judgment is not yet analysis.
5. **Findings keep trust scores; judgments take likelihood terms.** Do not put a likelihood
   term on a directly observed fact — an observation is not a probability.

### Mapping to the existing scales

| Evidence state | Typical judgment ceiling |
|---|---|
| Trust 5, two+ independent primary sources | up to *almost certain* |
| Trust 4 (DERIVED, 2+ independent) | up to *very likely* |
| Trust 3 (single reliable, verified) | up to *likely* |
| Trust 2 (ANECDOTAL) | *roughly even* at best |
| Trust 1 (CONTESTED) | state the conflict; no single judgment |

---

## 2. 5W1H coverage overlay

**Problem this solves.** `/coverage` and `/blind-spots` score against a *technique* matrix —
so a case where every technique ran scores "complete" even with no **Why** and no **How**. A
technique matrix measures effort; 5W1H measures whether the case answers anything.

Apply as a second pass after the technique matrix, at Assess.

| Dimension | The case must answer | Typical gap symptom |
|---|---|---|
| **Who** | Primary and secondary actors; network nodes; who funds/hosts/supports | A pile of selectors with no named or characterised operator |
| **What** | The specific activity; capabilities and TTPs; what is exploited | "Suspicious domain" with no stated mechanism of harm |
| **When** | Start/end, full event sequence, timing patterns | Findings with no dates; no `/timeline` |
| **Where** | Physical (coords/address/jurisdiction) **and** digital (IP/platform/host); applicable jurisdictions | Infrastructure mapped, jurisdiction never stated — so nothing is actionable |
| **Why** | Motive category (financial/political/ideological/personal); why *this* target, timing, method | **Most commonly missing.** Technically complete cases that never state intent |
| **How** | Execution sequence, tooling, evasion | IOCs without a modus operandi — no basis for detection or prediction |

**Scoring.** Per dimension: `ANSWERED` (evidence-backed) · `PARTIAL` (indicated, not
established) · `UNANSWERED` · `N/A` (justify explicitly). A case with **Why** or **How**
unanswered is not Deliver-ready regardless of technique coverage — report it as a stated
intelligence gap rather than letting the reader assume it was considered.

**Where the answers usually come from:** Who → `/subject` `/username` `/crossref` ·
What → `/threat-check` `/scam-check` `/exposure` · When → `/timeline` `/dns-history`
`/cert-history` `/snapshots` · Where → `/sweep` DNS/geo, registry jurisdiction, `/icp`
`/cn-corp` · Why → monetisation path (`/crypto-balance`, `/iban`), victim profile, targeting
pattern · How → `/webpivot` kit fingerprint, `/sensitive-paths`, `/appliance-scan`.

---

## 3. Analysis of Competing Hypotheses (ACH)

**Problem this solves.** `engine/conflict-resolver.md` reconciles two contradictory *findings*.
It does not test two rival *explanations* of the same evidence. Without ACH, `/threat-model`
tends to elaborate the first plausible story — the classic satisficing failure.

Required whenever an **attribution** claim is going into a report, or whenever two analysts
could read the same evidence differently.

### Procedure

1. **Enumerate hypotheses first, before weighing.** Aim for 3+, mutually exclusive where
   possible. Always include the mundane one and a deception hypothesis.
2. **List the evidence** — one row per item, including significant *absences*.
3. **Score each item against each hypothesis** — not "does it fit" but
   **"how consistent is it, and would I expect to see this if the hypothesis were true?"**
   `C` consistent · `I` inconsistent · `N` neutral/uninformative.
4. **Refute, do not confirm.** The surviving hypothesis is the one with the fewest `I`s.
   Evidence consistent with *every* hypothesis has **no diagnostic value** — mark it `N` and
   stop citing it as support.
5. **Report the runner-up** and state what evidence would change the ranking.

### Template

```
Question: who operates payment-portal.top ?

H1  Independent VN-based operator
H2  Reseller of a commercial phishing kit
H3  Node in a known CN-operated network
H4  Deliberate false-flag imitating H3

Evidence                                            H1  H2  H3  H4   Diagnostic?
E1 ICP filing -> Shenzhen entity                     I   N   C   C    yes
E2 Kit code identical to 40 other sites              I   C   C   C    weak
E3 Vietnamese-language UI, native idiom              C   C   C   C    NO -> mark N
E4 Telegram operator handle posts in Mandarin        I   N   C   I    yes
E5 Receiving IBAN issued in LT, not VN               I   N   C   C    yes
E6 No CN-language artifacts in kit source            C   C   I   C    yes

Inconsistencies:  H1=4   H2=0*   H3=1   H4=1
* H2 explains the artifacts but not the ICP filing (E1 = N, not support)

Assessment: H3 is LIKELY (55-80%) — ICP filing, operator language and beneficiary
jurisdiction align; E6 is the one inconsistency, adequately explained by kit localisation.
H4 cannot be excluded and is the runner-up.
Would change the ranking: registrant identity from a second independent registry;
operator-language evidence predating the campaign; a second unrelated ICP filing.
```

### Rules

- **Absence of evidence is evidence** when a hypothesis predicts something you should see.
  Record `I` for a confident absence — and distinguish it from "not yet collected".
- **Never drop a hypothesis for being uncomfortable or unfashionable.** Drop it on `I` count.
- **Deception is a standing hypothesis** in adversary work. Actors know they are watched and
  plant artifacts; a signal that is trivially easy to fake carries less diagnostic weight.
- Under `--yolo`, ACH still runs for attribution claims — it is analysis, not a prompt.

---

## 4. Report integration

- Executive summary and every judgment: a **likelihood term** (§1).
- `/coverage` and `/blind-spots`: technique matrix **plus** the 5W1H table (§2).
- `/threat-model`: an ACH matrix for each attribution claim, with the runner-up named (§3).
- `intelligence_gaps[]`: every `UNANSWERED` 5W1H dimension, plus the evidence named in
  "would change the ranking".
- Keep likelihood **out** of `findings[].confidence` — that field stays an integer 0–100
  describing evidence quality, per the report JSON contract.

---

## Cross-references

- [`engine/finding-framework.md`](../engine/finding-framework.md) — trust scores, evidence chains
- [`engine/conflict-resolver.md`](../engine/conflict-resolver.md) — contradictory findings (distinct from ACH)
- [`validation/coverage-matrix.md`](../validation/coverage-matrix.md) — technique matrix + 5W1H pass
- [`validation/quality-scoring.md`](../validation/quality-scoring.md) — quality composite
- [`output/reports/citation-guide.md`](../output/reports/citation-guide.md) — sourcing standards
