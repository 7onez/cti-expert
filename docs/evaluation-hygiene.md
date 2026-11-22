# Evaluation Hygiene — measuring heuristics, classifiers and LLM-in-the-loop CTI

Operating procedure for **any claim that something works**: a new extractor, a scoring
heuristic (e.g. `scripts/phish_domain_survival.py`), a noise filter, an LLM step that extracts
TTPs or proposes an attribution, and any classifier-like sentence in a report ("X% of flagged
domains are malicious").

- **Trigger:** you add or retune a heuristic/threshold/denylist; you add an eval fixture; you
  write a precision/accuracy/"N of M" figure into an assessment; you put an LLM judgement in the
  loop of a case.
- **Inputs:** the rule or prompt under test, the fixtures or case records it is measured on, the
  dates each was captured and when the rule was frozen, and the label source.
- **Output:** an **evaluation card** (§4) attached to the PR or to the report finding. No card →
  the claim is stated as an untested heuristic, never as a measured rate.
- **Abstain when:** there is no held-out data, no stated base rate, or no baseline. Say
  "not evaluated" rather than quoting a number.

Sources: [P18 Arp et al., USENIX Sec 2022] (ten pitfalls of ML in security),
[P19 Alam et al., NeurIPS 2024 D&B] (CTIBench) and, as an experimental design idea only,
[P20 Cheng et al., arXiv 2026] (CTI2TTP, §2). Everything marked **(adaptation)** is our
operating rule, not a claim made by the source.

---

## 0. How this repo actually evaluates

| Layer | Where | What a pass means |
|-------|-------|-------------------|
| Golden-set fixtures | `intel_engine/tools/eval/cases/<name>/{input.html, expected.json}` run by `run_eval.py` through the real `pivot_extract.py --no-enrich --no-whois` | the extractor still emits every `expect_pivots` / `expect_artifacts` spec and none of the `forbid_pivots` / `forbid_artifacts` specs |
| Frontier goldens | `cases/frontier_golden/CASE-*.json` (`test_frontier_golden`) | `frontier()` output is byte-identical after a refactor |
| Unit modules | `unit_mods` list in `run_eval.py`; `tests/test_*.py` (e.g. `test_phish_domain_survival.py`) | pure functions behave as specified on hand-built inputs |
| Metered-spend guard | ledger length check in `run_eval.py` | the gate reached no paid API |

The golden set is a **regression gate**: it proves a decision we already made still holds. It is
**not** a performance estimate. Fixtures are chosen cases (a QR funnel, a parking page, a
webfont-phone false positive), so a green run says nothing about precision or recall in the wild.
Never cite "all fixtures pass" as evidence that a heuristic is accurate (adaptation of the
lab-only and sampling-bias pitfalls, [P18 Arp et al., USENIX Sec 2022] §2.1, §2.4).

---

## 1. The ten pitfalls → rules for cti-expert

Source names and definitions are [P18 Arp et al., USENIX Sec 2022] §2. The rules under each are
**(adaptation)** unless they restate an Arp recommendation. Prevalence figures in Arp describe
their 30-paper sample, not CTI tooling; do not quote them as rates.

### P1 — Sampling bias
*Arp:* the data does not represent the true distribution of the problem; mixing incompatible
sources is a common cause; discuss dataset limits openly.
- **Eval rule:** state the population a fixture set stands for ("phishing kits on fresh
  registrations", not "phishing"). Benign and malicious examples must come from the **same
  collection path** (e.g. both from newly observed domains in one window), never benign = a
  top-sites list and malicious = a feed.
- **Report rule:** a rate is reported with its population and window ("among 120 domains
  collected in CASE-0001 between 2026-10-01 and 2026-10-14").
- **Confounder:** survivorship — only domains that `domain_liveness` judged live, or only pages
  `pivot_extract` could render, were kept (Arp lists survivorship under selective snooping,
  Table 8).

### P2 — Label inaccuracy
*Arp:* ground-truth labels are noisy or unstable; verify labels (e.g. inspect FPs or a random
sample); labels can shift over time; **uncertain instances must not be removed from test data**.
- **Eval rule:** record the label source per fixture (`analyst-confirmed`, `feed:<name>`,
  `takedown-observed`). A reputation-feed hit is a label of *"reported"*, not of
  *"maliciously registered"* — feeds list compromised sites too. Manually verify a random sample
  of each label source before using it. Keep `unknown` as its own bucket and report its size.
- **Report rule:** "confirmed malicious" needs independent corroboration (see the calibration
  check in `validation/quality-scoring.md`); a feed listing alone stays "reported as malicious by
  <feed>".
- **Abstain when** labels for the class you are measuring come only from the heuristic's own
  output (circular).

### P3 — Data snooping (test, temporal, selective)
*Arp:* the model is built with information not available in practice. **Test snooping**: the test
set was used before final evaluation (feature finding, tuning). **Temporal snooping**: time
dependencies ignored, so samples are judged with features from the future. **Selective
snooping**: data cleansed with information not available in practice (Arp Table 8).
- **Eval rule — temporal split:** every fixture records `captured_utc`; every heuristic records
  the commit at which its weights/thresholds were **frozen**. A fixture captured or inspected
  while the rule was being written or tuned is **development data and cannot validate that
  rule**. Validation fixtures are captured after the freeze and were never looked at during
  tuning.
- **Eval rule — feature time:** features must be "as of observation". Do not score a domain's
  age, registrar or status with WHOIS pulled after a takedown (a later `clientHold`, a
  re-registration by a new owner) and call it what the analyst could have seen.
- **Eval rule — selective:** never filter the test set by the outcome ("only keep domains that
  ended up suspended"); never drop hard cases because they were ambiguous.
- **Report rule:** a figure measured on the same cases that were used to build the rule is
  labelled "in-sample, optimistic".

### P4 — Spurious correlations
*Arp:* artifacts unrelated to the task separate the classes and the model learns them (their
Android example: the store URL became a top benign feature, i.e. the classifier learned the app's
origin, not maliciousness); define the objective first and use explanations to check what
drives decisions.
- **Eval rule:** inspect the contributing signals on true and false positives. Our scorers already
  emit per-signal weights and reasons, so use them. Run an ablation: remove one feature (TLD,
  registrar, privacy) and re-score. If performance hardly moves without the "real" features, the
  set is separated by an artifact.
- **Typical CTI artifacts:** one kit family dominating the malicious fixtures; the collection
  source's own fingerprint (a feed only lists certain TLDs, so TLD predicts "in feed"); a shared
  CDN, parking or registrar default that every example happens to carry. These are the same
  base-rate traps the KB already treats as noise (prevalence caps, `reference_check`), so they are
  leads, not same-operator edges.

### P5 — Biased parameter selection
*Arp:* thresholds or hyperparameters were tuned on the test set; use a separate validation set.
- **Eval rule:** thresholds such as the `purpose_score >= 35` cut-off in
  `phish_domain_survival.py` are tuned on a dev split only. Changing a threshold after looking at
  holdout results turns the holdout into dev data. Capture a new holdout.
- **Report rule:** never present "the best of N settings" without saying N.

### P6 — Inappropriate baseline
*Arp:* no or weak baselines; include simple, well-understood and non-learning methods (in their
intrusion-detection case a boxplot rule on one feature beat a complex ensemble at low FPR).
- **Eval rule:** every new heuristic is compared, on the same holdout, against at least
  (a) the simplest single-feature rule (e.g. "age < 30 days"), (b) the incumbent tool
  (`phish_domain_survival.py` class, existing denylist), and (c) the trivial rule (flag all /
  flag none). If it does not beat (a) on the measure that matters, do not ship it.

### P7 — Inappropriate performance measures
*Arp:* single numbers like accuracy hide TP/FP; ROC can look excellent on imbalanced data while
precision is poor; prefer precision/recall (PR curves) for rare-event detection; MCC when class
prevalence in the dataset is inflated; consider curves only up to tractable FPRs.
- **Eval rule:** report the confusion counts (TP, FP, FN, TN, abstained), precision and recall of
  the class you act on, and MCC if the fixture mix is balanced artificially. Never report
  accuracy alone.
- **Report rule:** the measure must match the action. If a flag triggers an abuse report, the
  number that matters is precision (wrongful reports); if it triggers more collection, recall
  matters more.

### P8 — Base rate fallacy
*Arp:* ignoring class imbalance when interpreting results. Their illustration: 99% TPR at 1% FPR
with a 1:100 class ratio means about 100 false positives for every 99 true positives.
- **Report rule (mandatory):** any sentence of the form "X% of flagged domains are malicious" or
  "the detector is N% accurate" must state the base rate of the population it runs on and the
  expected FP **count** at that base rate ("at roughly 1 malicious in 100 new registrations, a 2%
  FPR means about 2 benign flags for every true one"). If the base rate is unknown, say so and do
  not give a precision figure.
- **Eval rule:** fixture sets are usually balanced or malicious-heavy. Precision measured on them
  does not carry over to a live stream. Re-weight to a stated prior or say it does not apply.

### P9 — Lab-only evaluation
*Arp:* evaluated only in controlled settings; account for temporal and spatial dynamics and
practical constraints; deploy where possible.
- **Eval rule:** the golden set is offline by design (HTML-derived only, see §0). Any claim about
  network-derived signals (favicon hash, TLS, passive DNS, WHOIS) needs a separate live check on a
  recent window. Report drift between the offline estimate and the live run.
- **Report rule:** state whether a figure came from frozen fixtures, a closed set of
  analyst-picked cases, or an open stream.

### P10 — Inappropriate threat model
*Arp:* the system's own attack surface (poisoning, evasion) is not considered; assume an adaptive
adversary.
- **Eval rule:** for each heuristic, list the cheap evasions (age a domain before use; abuse a
  compromised long-lived host; use an established registrar; avoid dynamic DNS) and include at
  least one adversarial fixture per evasion. The expected outcome is `indeterminate` or
  `likely_compromised`, never a confident `maliciously_registered`.
- **Poisoning surface:** the reference denylists (`reference_add` verdict `benign`), operator
  registry and KB are training data for future cases. A bad `benign` entry silently hides a real
  indicator, and a bad attribution propagates through `/recall`. Changes to them are reviewed like
  code.

### Pre-merge checklist (copy into the PR)
```
[ ] population + window stated                         (P1)
[ ] label source per fixture; unknowns kept & counted  (P2)
[ ] rule frozen at <commit>; holdout captured after it, never inspected while tuning  (P3, P5)
[ ] features as-of-observation; no outcome-based filtering  (P3)
[ ] ablation / per-signal inspection done              (P4)
[ ] baselines: single-feature, incumbent, trivial      (P6)
[ ] confusion counts + precision/recall (+MCC)         (P7)
[ ] base rate + expected FP count at that rate         (P8)
[ ] offline vs live stated; live drift checked         (P9)
[ ] evasion fixtures + poisoning surface listed        (P10)
```

---

## 2. Judging LLM-in-the-loop CTI (CTIBench)

### What CTIBench measures
[P19 Alam et al., NeurIPS 2024 D&B] defines five task families, each with its own metric:

| Task | Input → output | Metric (as stated) |
|------|----------------|--------------------|
| **CTI-MCQ** | multiple-choice questions on standards, ATT&CK, CWE, CAPEC (GPT-generated, human-validated) | accuracy |
| **CTI-RCM** | CVE description → CWE ("root cause mapping"), 2024 NVD sample | accuracy |
| **CTI-VSP** | CVE description → CVSS v3 base vector; score derived deterministically by a library | mean absolute deviation |
| **CTI-ATE** | threat description → MITRE ATT&CK technique IDs (techniques only, no sub-techniques) | F1 (text says Micro-F1; Table 1 header says Macro-F1) |
| **CTI-TAA** | vendor report with actor and campaign names replaced by a placeholder → threat actor | correct / plausible / incorrect, with aliases resolved by a graph search over alias and related-group links |

Findings worth carrying over, each specific to their models and datasets: on CTI-MCQ the larger
models' **errors were correlated**; in their RCM and VSP analysis, accuracy rose with description
length up to a point and then fell; VSP predictions **over-estimated severity** more often than
under-estimated, and the models struggled with PR, S, C and I; TAA scored better on reports from
before the models' knowledge cutoff, which the authors read as memorisation playing a role. Their
stated limits: a **limited subset of CTI tasks**, **English-only**, and the risk that LLMs
generate convincing false intelligence.

### Rules for this repo (adaptation unless noted)
1. **A benchmark score is not investigative accuracy.** CTIBench items are single, clean
   documents with a known answer and a closed answer space. Case work is multi-source, noisy,
   adversarial, open-world, and often has no answer. Never cite a CTIBench (or similar) number as
   the reliability of a cti-expert run or a report.
2. **Keep task-specific evals separate.** Extraction (ATE-like), taxonomy mapping (RCM-like),
   scoring (VSP-like) and attribution (TAA-like) each get their own fixtures and metric. Never
   average them into one "LLM quality" figure. CTIBench itself reports per-task metrics.
3. **Evidence span is required.** Every extracted TTP, CWE, wallet or attribution must cite the
   span it came from (fixture file plus quoted text or offset). Scoring treats a correct label
   with no valid span as *unsupported*, and a span that does not contain the claimed behaviour as
   *wrong*. CTIBench prompts ask for a justification but score only the final line. We score the
   span.
4. **Abstention is a scored outcome.** CTI-TAA has no abstain class, and its "plausible" bucket
   credits a related but different actor. Under our attribution rails a plausible-but-different
   actor is a **misattribution**. Score attribution as `correct` / `correct_abstain` (evidence
   insufficient and the model said so) / `wrong_abstain` (evidence sufficient) / `wrong`, and
   weight `wrong` well above `wrong_abstain`. Keep "same infrastructure", "same operator" and
   "named person" as separate answer levels.
5. **Control for memorisation.** Mask names (CTIBench's placeholder method), use post-cutoff or
   fully synthetic material, and when evaluating the harness mask KB recall and operator-registry
   labels so the model cannot simply look the answer up.
6. **Agreement is not corroboration.** Two LLM passes or two models agreeing are not independent
   sources, given the correlated errors CTIBench observed. The skeptic panel and any "LLM
   consensus" count as one source.
7. **Let code do the arithmetic.** As in CTI-VSP, the model emits a structured object (vector,
   IDs, spans) and deterministic code derives scores, so model arithmetic errors are kept out of
   the measurement.

### Experimental: diverge-then-converge extraction (CTI2TTP)
[P20 Cheng et al., arXiv 2026] (arXiv 2605.25836v2) is a **2026 preprint** with no peer-reviewed
version cited here, and it has not been independently validated. Both of its evaluation sets
were built or re-annotated by the same authors (a new 150-report benchmark and a corrected TRAM).
Treat it as a design idea for an extraction step, not as a proven method. Its macro-F1 figures
describe its datasets and backbones, never a cti-expert run (rule 1).

*What the paper describes (§3, Fig. 2):*
- **Diverge, for recall.** An LLM splits a report into atomic behaviours and keeps tool names,
  commands and paths verbatim. For each behaviour it then proposes up to *k* distinct ATT&CK
  parent techniques in one generation, instead of resampling near-duplicates.
- **Span localisation, the bridge.** A deterministic lexical matcher (token overlap, down-weighting
  of common terms, an n-gram bonus) picks the sentence window that best supports each behaviour.
  Proposal and verification see only that window, not the whole report.
- **Converge, for precision.** A verifier receives the behaviour, its span and the official ATT&CK
  definition of each candidate. It judges support from the span alone, without outside knowledge,
  and returns a 0–1 score. Candidates under a threshold are dropped. In the authors' ablation,
  removing verification cost the most precision, and removing span localisation hurt precision and
  recall alike.
- *Stated limits:* English vendor reports only; techniques the taxonomy itself blurs stay
  ambiguous; higher cost than one-pass prompting; no live-SOC measurement.

*How it maps to our rules (adaptation):*
- **Rule 3 (evidence span required).** CTI2TTP enforces the span before a label exists, while we
  score the span afterwards. The two fit together. A pipeline built this way must emit the span it
  verified against, and our scorer still checks that span independently: the pipeline choosing a
  span is not evidence that the span is right.
- **Definition check.** Add a second span test next to "the span contains the claimed behaviour":
  does the span match the technique's official definition, not just a shared keyword? A
  keyword-only match is scored *wrong*, like a span that lacks the behaviour.
- **Fixture idea 1 (`ate_span_required`).** The synthetic report already has the right shape: two
  behaviours with locatable spans (cron entry → T1053, screen capture → T1113), plus a forbidden
  T1059 that a broad diverge step could plausibly propose and a definition check should reject.
  Score diverge-stage recall, converge-stage precision and final per-ID F1 as separate numbers
  (rule 2).
- **Threshold.** The paper's default τ and its "operating regimes" are its own calibration on its
  own data. Never import them. Tune our threshold on a dev split and freeze it (P3, P5).
- **Rule 6.** A verifier from the same model family as the proposer is not an independent source.
  Its acceptance is not corroboration.

### Implemented fixtures (`intel_engine/tools/eval/judgement_cases/`, local-only)
These extend the golden set beyond `pivot_extract`. They run offline in the unit phase as
`test_judgement_fixtures` (`run_eval.py --unit test_judgement_fixtures`). No LLM is called; each
claim fixture ships recorded synthetic predictions, at least one that must pass and at least one
that must fail for a named reason. All data is synthetic.

1. **`ate_span_required`.** Synthetic report: the loader on `cdn-update.example` adds a cron
   entry, captures the screen every 60 s and posts to `203.0.113.45`. Expect T1053 and T1113, each
   with a span quoted from the input that contains the behaviour. T1059 is forbidden. Scored by
   per-ID F1 over supported claims only (sub-techniques cut to the technique, as in CTI-ATE).
   No valid span = `unsupported_span`; a span without the behaviour = `wrong_span`.
2. **`taa_masked_abstain`.** Actor masked as `[PlaceHolder]`; the only overlap with the synthetic
   KB operator is a commodity kit and the shared host `198.51.100.7`. Only `correct_abstain`
   passes. Naming the KB operator or a related one is `wrong`, and any operator or person claim
   breaks the `same_infrastructure` ceiling.
3. **`shared_infra_not_operator`.** `shop-a.example`, `shop-b.example` and `shop-c.example` on
   CDN address `192.0.2.80` with the same parking favicon, run through the real ingest and
   cluster partition into a throwaway KB. Expect no shared indicator, no multi-domain component,
   and a `shared-hosting co-tenancy` lead. Two control mutations (CDN classification removed;
   a distinctive shared favicon) must be caught as `cluster_formed`.
4. **`temporal_holdout_registration`.** Fixtures carry `captured_utc` and `split`; rules carry
   `frozen_at` and an optional `dev_manifest`. A rule fails if any holdout predates `frozen_at`,
   has no capture time, or is in its dev manifest.
5. **`cvss_vector_only`.** The model returns a CVSS v3.1 vector for a synthetic advisory; code
   computes the base score [R07 FIRST, CVSS v3.1 Specification §7, App. A]. A model-stated
   numeric score fails as `model_arithmetic`, even when it is right.

Scoring a real harness prediction:
`python3 intel_engine/tools/eval/claim_scorer.py <fixture_dir> <prediction.json>` (exit 0 pass,
1 fail; JSON with reason codes and metrics). The prediction is
`{"abstain": bool, "claims": [{"kind", "label", "level", "span": {"quote", "start", "end"}}]}`.
The `expected.json` keys, as read by the scorer (full table in `intel_engine/tools/eval/README.md`):
```jsonc
{
  "description": "masked attribution must abstain on commodity overlap",
  "task": "taa", "input": "input.txt",
  "captured_utc": "2026-11-14T00:00:00Z", "split": "holdout",
  "expect_outcome": "correct_abstain",          // correct | correct_abstain | wrong_abstain | wrong
  "require_span": true,                          // every claim must quote input text
  "forbid_entities": [{"kind": "operator"}, {"kind": "named_person"}],
  "expect_level_max": "same_infrastructure",     // lead < same_infrastructure < same_operator < named_person
  "recorded_predictions": [{"file": "predictions/pass_abstain.json", "pass": true}]
}
```
Outcome costs are ordinal and our own choice (adaptation): correct 0, correct_abstain 0,
wrong_abstain 1, wrong 5. A passing fixture is a regression result on synthetic material; rule 1
above still applies.

---

## 3. Worked example — a "malicious-registration" heuristic

Hypothetical rule **H-NEWREG**: flag a domain `maliciously_registered` if it is under 14 days old
**and** (its NS is on dynamic DNS **or** its label embeds a brand). All domains, dates and counts
below are synthetic and illustrative. They are not from any source.

### Incorrect evaluation
The author writes H-NEWREG on 2026-10-10. Malicious set: 50 domains from a phishing feed
(`login-examplebank-verify.example`, …). Benign set: 50 domains from a popular-sites list. The
author tweaks the age cut-off (7 → 10 → 14 days) until all 100 are classified correctly, adds the
100 as fixtures captured on 2026-10-12, and writes in a report: *"H-NEWREG is 100% accurate; 95% of
domains it flags are malicious."*

| Pitfall | What went wrong |
|---------|-----------------|
| P1 | Benign = popular sites, all years old, so age alone separates the sets. |
| P2 | The feed lists compromised legitimate sites too. Those are counted as "maliciously registered" or quietly dropped. |
| P3 | The 100 fixtures were inspected while tuning (test snooping). Their WHOIS was pulled after several had been suspended (temporal). |
| P4 | The feed only covers a few TLDs, so the TLD predicts "in feed". |
| P5 | The cut-off was chosen on the very set it is scored on. |
| P6 | No comparison with "age < 14 d" alone or with `phish_domain_survival.py`. |
| P7 | Accuracy on a 50/50 set. |
| P8 | No base rate. Among new registrations, benign is the large majority. |
| P9 | Offline features only. No live window. |
| P10 | Aged domains and compromised hosts, the two obvious evasions, are absent. |

### Correct evaluation
1. **Objective and population.** "Among newly observed domains in phishing cases, separate
   purpose-registered from compromised and benign." There are three classes plus `unknown`.
   Abstention (`indeterminate`) is an allowed output.
2. **Freeze first.** Dev set: domains first observed 2026-09-01 to 2026-09-30, used for tuning.
   Freeze the rule at a commit. Holdout: domains first observed 2026-10-15 to 2026-10-31,
   collected by the same path and not opened until the freeze. Features are taken from WHOIS/DNS
   snapshots at first observation.
3. **Labels.** Analyst-confirmed classes. Compromised sites (unrelated legitimate content,
   long-lived MX) get their own label. A random sample of feed labels is verified by hand.
   Unknowns stay in the holdout and are counted.
4. **Baselines on the holdout:** age < 14 d alone; `phish_domain_survival.py`
   `registration_class`; flag-none.
5. **Measures.** A per-class confusion matrix with an abstain column; precision and recall for
   `maliciously_registered`; MCC; abstention rate.
6. **Ablation.** Drop the brand-in-label feature, then the dynamic-DNS feature, and re-score.
   Read the per-signal reasons on every FP.
7. **Adversarial fixtures.** An aged domain (e.g. 400 days old, first used yesterday) and a
   compromised long-lived site hosting a kit path. Expect `indeterminate` or `likely_compromised`.
8. **Base-rate statement.** Illustrative: if a live stream had 10,000 new registrations with about
   100 purpose-registered phishing domains, a rule with 90% recall and a 2% FPR would raise 90
   true and about 198 false flags. Precision would be about 31%, not the 95% seen on a balanced
   set.
9. **Live window.** Re-run on a fresh week and report the drift from the holdout figures.
10. **Regression guard.** Freeze each confirmed FP as a negative case. Those are unit cases for
    `tests/test_phish_domain_survival.py`-style scorers, or `forbid_*` fixtures where the signal is
    HTML-derived.

**Correct report wording:** *"On a held-out set of 140 domains first observed 2026-10-15 to
2026-10-31 in CASE-0001 (31 purpose-registered, 12 compromised, 89 benign, 8 unknown), H-NEWREG
flagged 30, of which 24 were purpose-registered (recall 24/31). It did not beat the age-only
baseline on precision. In a stream where about 1 in 100 new domains is purpose-registered, expect
about 2 false flags per true one. H-NEWREG is a triage prior and does not justify an abuse report
or a same-operator link on its own."*

---

## 4. Evaluation card (attach to the PR or to the finding)

```
claim:            <what the heuristic/LLM step decides>
population:       <collection path + time window>           # P1
labels:           <source per class; verified sample size; unknown count>   # P2
frozen_at:        <commit>; dev window <..>; holdout window <..>            # P3/P5
baselines:        <single-feature / incumbent / trivial — results>          # P6
metrics:          TP FP FN TN ABSTAIN; precision; recall; MCC               # P7
base_rate:        <stated prior or "unknown → no precision claim">          # P8
setting:          offline fixtures | closed analyst set | live window (+drift)  # P9
evasions tested:  <list>; poisoning surface: <list>                         # P10
llm (if any):     task family; span validity rate; abstention scoring; memorisation control
verdict:          ship | ship as triage-only | do not ship | not evaluated
```

## Cross-references
- `handbook/analytic-standards.md` — likelihood language (no bare percentages), ACH.
- `techniques/phishing-domain-survival.md` / `scripts/phish_domain_survival.py` — the incumbent
  registration scorer used as the baseline in §3.
- `intel_engine/tools/eval/README.md` (local-only, gitignored) — fixture layout and
  `expected.json` schema.
- `validation/quality-scoring.md` — confidence-calibration scoring of reports.
