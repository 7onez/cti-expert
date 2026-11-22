# Analytic Standards — likelihood language, 5W1H coverage, competing hypotheses

The skill already grades **evidence** (trust score 1–5, source reliability A–F, confidence
VERIFIED→CHALLENGED). This file governs the layer above: how **judgments** are expressed, how
coverage is judged *substantively* rather than by technique count, and how rival explanations
are tested before one is asserted.

Reference lineage: ICD 203 analytic standards, Heuer's *Psychology of Intelligence Analysis*
`[B05 Heuer, CIA CSI 1999]` and *Structured Analytic Techniques*, UNODC *Criminal Intelligence
Manual for Analysts*. Activity modelling (Diamond events/threads/groups, Pyramid of Pain, ATT&CK
mapping) lives in [`intrusion-modeling.md`](intrusion-modeling.md); this file judges what those
models produce.

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
tends to elaborate the first plausible story — what Heuer calls *satisficing*: accepting the
first explanation that seems good enough instead of the best of the alternatives
`[B05 Heuer 1999, Ch 4, Ch 8]`.

Required whenever an **attribution** claim is going into a report, or whenever two analysts
could read the same evidence differently. Also required when a Diamond activity group is about
to be labelled as one operator ([`intrusion-modeling.md`](intrusion-modeling.md) §4).

### Procedure — Heuer's eight steps `[B05 Heuer 1999, Ch 8]`

1. **Identify the hypotheses — generate before you evaluate.** Aim for 3–7, mutually exclusive
   where possible (over seven: group some for the first cut). Always include the mundane one
   (kit customer, shared hosting, compromised third party) and a deception hypothesis.
   Distinguish **disproved** (positive evidence against it) from **unproven** (no evidence
   yet): only a disproved hypothesis may be dropped. Deception in particular is not rejected for
   lack of evidence of deception — only after a systematic search for it has come back empty.
2. **List evidence *and arguments*.** Include your own **assumptions and logical deductions**
   (about the actor's goals, how a kit is sold, what a registrar does) as rows tagged `A` —
   Heuer's point is that unlisted assumptions are what usually drive the final judgment. For
   each hypothesis ask *"if this were true, what should I expect to see — or not see?"* and
   record significant **absences**, noting why each is absent: it did not happen · it is not
   normally observable · it is being concealed · nobody looked. Only the first two may be scored.
3. **Build the matrix and judge diagnosticity — work across rows.** Take one item at a time and
   rate it against every hypothesis: `C` consistent · `I` inconsistent · `N` neutral /
   not applicable (`II` = strongly inconsistent). The question per cell is *"if this hypothesis
   were true, how likely is it I would see this item?"* — not "does it fit". Optionally annotate
   each row with its importance and with **how easily it could be faked or planted** (see the
   deception rule below).
4. **Refine the matrix.** Reword, split or merge hypotheses (two hypotheses no evidence can
   separate become one). Add any factor that is influencing you but is not yet a row. Move rows
   with **no diagnostic value** off the matrix into a *considered, non-diagnostic* list that
   stays in the case file as the record of what was weighed.
5. **Draw tentative conclusions — work down columns, try to refute.** Look at the `I`s, not the
   `C`s: a long list of consistent evidence proves little, a single solid inconsistency can
   sink a hypothesis. The `I` count is a **rough ranking only** — weigh how strong each
   inconsistency is. The matrix records your reasoning; it does not decide for you. If the
   matrix ranking disagrees with your judgment, a factor is missing from it — add the row.
6. **Sensitivity analysis on linchpin evidence.** See *Linchpin check* below.
7. **Report all hypotheses**, with the relative likelihood of each (§1 terms), not just the
   winner; say why each rejected one was rejected.
8. **Set milestones for future observation** — observable events that, if they happen, would
   shift the ranking. Writing them now stops later rationalisation ("that doesn't really change
   anything"). Each milestone names the selector and the cti-expert check that would see it
   (adaptation: `/takedown-watch`, `/drift`, `/dns-history`, `/kb --as-of`).

### Diagnosticity rule

An item is **diagnostic** only when its expected probability differs across hypotheses —
Heuer's analogy is a fever: it shows the patient is ill but not which illness
`[B05 Heuer 1999, Ch 4, Ch 8]`. Operating rules (adaptation):

- A row rated identically across every hypothesis (`C C C C` or `N N N N`) is non-diagnostic:
  remove it per step 4 and **stop citing it as support** anywhere in the report.
- The headline judgment must rest on at least one diagnostic row that is not an assumption. If
  every row that separates the leader from the runner-up is an `A` row, report *roughly even
  chance* between them and name the assumption as the gap.
- "Fits the story" is not a rating. Typical cti-expert rows that look supportive but are usually
  non-diagnostic between operator hypotheses: page language, kit/template match, provider ASN,
  managed nameservers, CDN, registrar choice — each is equally expected under the "kit customer"
  and "same operator" hypotheses (cf. the rung table in `SKILL.md`, rungs 9–10).

### Linchpin check (step 6)

A **linchpin** is an item or assumption whose re-rating would change which hypothesis leads.
Find them by asking, for each diagnostic row: *if this item were wrong, misleading or read
differently, would the leader change?* Then, for every linchpin `[B05 Heuer 1999, Ch 8]`:

1. **Re-check it against the original source**, not a summary of it (adaptation: the raw
   WHOIS / RDAP record, the capture under `cases/<id>/evidence/`, not the assessment line
   that cites it).
2. **Consider deception**: from the adversary's seat, what motive, opportunity and means were
   there to plant it, and at what cost? A registrant string, a page language or a Telegram
   handle is cheap to fake; a registrant e-mail reused across years of WHOIS history is not.
3. **State the dependency in the report**: *"This judgment depends on E1 being the operator's
   filing rather than a reseller's."*
4. **Cap the term when a linchpin is fragile** (adaptation): a linchpin that is single-source,
   unverified, or easy to fake holds the judgment to the §1 ceiling of that one item's trust
   score, however many consistent rows surround it.

**Abstain** — write *insufficient evidence to discriminate* and list the missing items as
`intelligence_gaps[]` — when no diagnostic row survives step 4, or when every linchpin fails
the re-check.

### Template

```
Question: who operates payment-portal.example ?

H1  Independent VN-based operator
H2  Customer of a commercial phishing kit, operator unknown
H3  Node in a known CN-operated network (CASE-0001 activity group)
H4  Deliberate false-flag imitating H3

Evidence / argument                                  H1  H2  H3  H4   Fakeable?
E1 ICP filing -> Shenzhen entity                     I   N   C   C    medium
E2 Kit code identical to 40 other sites              C   C   C   C    -> non-diagnostic
E3 Vietnamese-language UI, native idiom              C   C   C   C    -> non-diagnostic
E4 Telegram operator handle posts in Mandarin        I   N   C   I    easy
E5 Receiving IBAN issued in LT, not VN               I   N   C   C    hard
E6 No CN-language artifacts in kit source            C   C   I   C    n/a (absence: looked, none)
A1 ICP filings are made by the operator, not a hosting reseller (assumption)
                                                     -   -   C   C

Considered, non-diagnostic (step 4): E2, E3
Inconsistencies:  H1=4   H2=0*   H3=1   H4=1
* H2 is unrefuted but also unsupported: its N's are absence of a link, not support.

Linchpins (step 6): E1 + A1 together, E5.
  If A1 fails (reseller filing), E1 becomes N for H1/H3 and H3 vs H2 is roughly even.
  E5 re-checked against the raw payment capture: holds.
Assessment: H3 is LIKELY (55-80%) — ICP filing, operator language and beneficiary
jurisdiction align; E6 is the one inconsistency, explained by kit localisation.
H4 cannot be excluded and is the runner-up; H2 remains unproven, not disproved.
Depends on: A1.
Milestones (step 8): a second, unrelated ICP filing for the same serial (/cn-corp);
registrant identity from a second independent registry; operator-language evidence
predating the campaign (/snapshots); the IBAN reappearing in an unrelated kit (H2 up).
```

### Rules

- **Absence of evidence is evidence** when a hypothesis predicts something you should see *and*
  you looked where it would be. Record `I` for a confident absence; leave "not yet collected"
  out of the matrix and list it as a gap.
- **Never drop a hypothesis for being uncomfortable or unfashionable.** Drop it only when
  disproved (step 1), not because it is unproven or has a high `I` count from weak rows.
- **Deception is a standing hypothesis** in adversary work. Actors know they are watched and
  plant artifacts; a signal that is trivially easy to fake carries less diagnostic weight.
- Under `--yolo`, ACH still runs for attribution claims — it is analysis, not a prompt.

---

## 4. Bias checks before finalising an assessment

Heuer's position is that these biases are not cured by knowing about them; they are reduced by
procedure `[B05 Heuer 1999, Ch 9]`. Run each check below against the draft assessment **after**
ACH and **before** the likelihood terms go into the report. Record each as `PASS`, or `FIXED:`
plus what changed. A check that cannot be run (missing data) becomes an `intelligence_gaps[]`
entry, not a pass. The check wording is adaptation; the bias each targets is Heuer's.

| # | Bias (source) | Check the agent runs | If it fails |
|---|---|---|---|
| B1 | **Vividness** — concrete, first-hand, anecdotal items outweigh abstract or statistical ones (Ch 10) | For each linchpin: is it a vivid single item (a screenshot, one chat message, one "the same kit as last time") while an aggregate exists (urlscan/FOFA population for the kit, reverse-WHOIS count, `/reference check` verdict)? | Rate by the aggregate; demote the anecdote to context |
| B2 | **Absence of evidence** — gaps are "out of sight, out of mind" (Ch 10) | List the variables relevant to the question with **no** data (5W1H §2 helps). For each: is the absence normal for this kind of target, or itself an indicator (e.g. no WHOIS history at all, no archive captures)? | Add the gaps; lower confidence, not just likelihood |
| B3 | **Oversensitivity to consistency / small samples** — consistent evidence can be redundant or drawn from a tiny sample (Ch 10) | Count **independent** sources, not rows: ten domains on one kit, five mirrors of one WHOIS record, or three vendors repeating one report are one observation. Ask how representative the sample is | If representativeness is unknown, confidence stays low however consistent the rows look |
| B4 | **Uncertain accuracy & discredited evidence** — "best guess" treats a probable item as certain; impressions persist after their evidence is withdrawn (Ch 10) | (a) Chained inferences multiply: a step that rests on a probable item rests on its uncertainty too. (b) If any finding was retracted this case (e.g. `/reference check` → BENIGN), re-run the matrix **without it** and check the conclusion it first suggested still stands on its own | Re-derive the judgment from the remaining rows |
| B5 | **Causal over-attribution** — preference for causal and centrally-directed explanations; big effects assumed to need big causes; behaviour put down to the actor's disposition rather than circumstance (Ch 11) | Write the non-coordinated reading: coincidence, independent kit customers, a provider default, a reseller, an opportunist reusing a leaked panel. Does a large victim count or polished kit get read as "sophisticated organised group" without evidence of shared control? | Add the non-coordinated hypothesis to ACH; it must be refuted, not ignored |
| B6 | **Anchoring** — the first estimate drags later ones (Ch 12) | Form the estimate from this case's matrix **before** reading the prior verdict (`/recall`, `domain_verdict`, a vendor label, the previous analyst's grade); then compare. If new diagnostic evidence arrived but the term did not move, justify why | Re-score from the matrix; record the prior as context only (five-question gate in `SKILL.md`) |
| B7 | **Availability & base rates** — probability judged by how easily cases come to mind; base rates ignored unless causal (Ch 12) | "This looks like the network from last week" is availability. Ask the base-rate question: of comparable hosts carrying this feature, how many are the same operator? Use KB counts, kit population, provider tenancy | Replace recall with the count; if no count exists, say so |
| B8 | **Scenario arithmetic** — narrative detail raises felt probability while each added step lowers real probability; the weakest link caps the chain (Ch 12) | For a multi-step story (registered → kit → payment → laundering), name the least-supported step. The scenario's term cannot exceed that step's | Lower the term; list the weak step as a gap |
| B9 | **More information ≠ more accuracy** — extra data raises confidence faster than accuracy (Ch 5) | Since the last estimate, did confidence rise because new **diagnostic** rows arrived, or because more rows of any kind arrived? | Return confidence to what the diagnostic rows support |
| B10 | **Hindsight** — once an outcome is known, prior uncertainty is hard to reconstruct (Ch 13) | When reviewing a closed or reopened case, or grading a past judgment: *"If the opposite outcome had occurred, would I have been surprised?"* Judge the past call on what was knowable then (`/kb --as-of <date>`) | Grade the old judgment against its own evidence; do not rewrite history |

**Abstain** from a single headline judgment when B3 or B8 leaves the leading hypothesis resting
on one non-independent observation: report the competing hypotheses side by side with
*roughly even chance* and the gap that would separate them.

---


## 5. Report integration

- Executive summary and every judgment: a **likelihood term** (§1).
- `/coverage` and `/blind-spots`: technique matrix **plus** the 5W1H table (§2).
- `/threat-model`: an ACH matrix for each attribution claim, with the runner-up named, the
  linchpins and their dependency sentence, and the step-8 milestones (§3).
- Assessment QA: the §4 check list (B1–B10) with `PASS` / `FIXED:` per row; failed or unrunnable
  checks feed `intelligence_gaps[]`.
- `/threat-model` (active-actor cases only): optionally add an **AAM actor-state overlay** after
  the ACH matrix — the four OODA faces + a next-move posture via Mirror/Twin/Opposite/Lever —
  [`handbook/aam-actor-modeling.md`](aam-actor-modeling.md). ACH attributes the past; AAM anticipates
  the next move. Skip for closed retrospective cases.
- `intelligence_gaps[]`: every `UNANSWERED` 5W1H dimension, the evidence named in the step-8
  milestones, and every bias check that could not be run.
- Keep likelihood **out** of `findings[].confidence` — that field stays an integer 0–100
  describing evidence quality, per the report JSON contract.

---

## Cross-references

- [`engine/finding-framework.md`](../engine/finding-framework.md) — trust scores, evidence chains
- [`engine/conflict-resolver.md`](../engine/conflict-resolver.md) — contradictory findings (distinct from ACH)
- [`validation/coverage-matrix.md`](../validation/coverage-matrix.md) — technique matrix + 5W1H pass
- [`validation/quality-scoring.md`](../validation/quality-scoring.md) — quality composite
- [`output/reports/citation-guide.md`](../output/reports/citation-guide.md) — sourcing standards
- [`handbook/aam-actor-modeling.md`](aam-actor-modeling.md) — AAM actor-state overlay (next-move posture; distinct from ACH attribution)
- [`handbook/intrusion-modeling.md`](intrusion-modeling.md) — Diamond events, activity threads and groups, Pyramid of Pain pivot priority, ATT&CK mapping limits
- [`handbook/collection-preservation.md`](collection-preservation.md) — how evidence is collected, preserved and verified (source / item / content) before it enters ACH
- [`workflows/wf-threat-analyst.md`](../workflows/wf-threat-analyst.md) — where ACH, the bias checks and the hunt phase sit in the case workflow
