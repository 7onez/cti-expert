# Intelligence Summary (INTSUM) Report Template

When the user issues `/intel-report`, generate a markdown file following this exact structure. Populate sections from conversation findings. Mark sections as "No data collected" if empty.

---

```markdown
# OSINT Intelligence Summary (INTSUM)

**Classification:** OPEN SOURCE — PUBLIC DATA ONLY
**Report Date:** [YYYY-MM-DD]
**Analyst:** Claude (AI-Assisted OSINT)
**Subject:** [Primary target of investigation]
**Report ID:** INTSUM-[YYYYMMDD]-[short-subject-slug]

### Document Control
| Author | Version | Created | Modified | Hours | Client |
|--------|---------|---------|----------|-------|--------|
| [analyst name] | [1.2] | [2026-01-01] | [2026-01-05] | [14] | [Example Client Ltd] |

---

## 1. Executive Summary

[2–4 sentence overview of the investigation scope, key findings, and overall assessment. This should be readable by someone who reads nothing else.]

---

## 2. Key Questions

[The questions the requester needs answered, and how far this report answers each. One row per question; never drop an unanswered one.]

| ID | Question | Status | Answer | Confidence | Refs |
|----|----------|--------|--------|------------|------|
| KQ-01 | [Who operates example.com?] | [answered / partial / open] | [one-line answer or "not established"] | [high / moderate / low] | [FND-001, T001] |

---

## 2a. Subject Identity Card

[One table per entity. Fields in this fixed order, each omitted when there is no row: Name, Alias, Date of birth, Birthplace, E-mail, Phone, Address, Company, Account, Relative, Other. Every row carries its basis, source and status; a value the client supplied is tagged `[client-provided]` — it is a seed, not an independent finding (RULE 5: not a knowledge-base edge).]

#### [Subject A]
| Field | Value | Status | Basis | Source | Admiralty |
|-------|-------|--------|-------|--------|-----------|
| Name | [Jane Example] | [confirmed / probable / possible] | [company registry filing] | [registry URL] | [B2] |
| E-mail | [operator@example.com [client-provided]] | [probable] | [registrant record] | [WHOIS capture URL] | [B3] |

---

## 3. Subject Profile

| Field | Value | Confidence |
|-------|-------|------------|
| **Name / Identifier** | [value] | [🟢/🟡/🔴] |
| **Type** | [person / organization / domain / etc.] | — |
| **Known Aliases** | [usernames, alternate names] | [confidence per alias] |
| **Location** | [city, country if known] | [🟢/🟡/🔴] |
| **Affiliation** | [employer, org] | [🟢/🟡/🔴] |
| **Online Presence** | [list of confirmed platforms WITH FULL URLs] | [🟢/🟡/🔴] |
| **First Seen Online** | [earliest dated reference] | [🟢/🟡/🔴] |

---

## 4. Key Findings

### Finding 1: [Descriptive Title]
- **Confidence:** [🟢 HIGH / 🟡 MEDIUM / 🔴 LOW]
- **Confirmation:** [confirmed / strong indirect / attempted, unproven / unverified]
- **Summary:** [What was found]
- **Evidence:** [Specific URLs, search queries, or data points]
- **Not proven:** [What this finding does NOT establish — e.g. "shows a login attempt, not a successful login"]
- **Analyst Note:** [Interpretation or significance]

### Finding 2: [Descriptive Title]
[repeat structure]

### Finding N: [Descriptive Title]
[repeat structure]

---

## 5. Entity Relationship Map

[Text-based representation of discovered connections between entities]

```
[Primary Subject]
├── email: subject@example.com
│   └── linked to: GitHub account "username"
│       └── real name visible: "John Doe"
├── username: "cooluser99"
│   ├── Twitter/X: active, 2.3k followers
│   ├── Reddit: active in r/technology, r/cybersecurity
│   └── GitHub: 47 repos, employed at TechCorp (bio)
├── domain: example.com
│   ├── registered: 2019-03-15
│   ├── registrant: privacy-protected
│   └── hosted at: 203.0.113.50 (AWS us-east-1)
└── organization: TechCorp Inc.
    ├── founded: 2017
    └── CEO: Jane Smith
```

---

## 6. Timeline

| Date | Event | Source | Confidence |
|------|-------|--------|------------|
| [YYYY-MM-DD] | [Event description] | [URL or source] | [🟢/🟡/🔴] |
| [YYYY-MM-DD] | [Event description] | [URL or source] | [🟢/🟡/🔴] |

---

## 7. Source List

**CRITICAL: Every source MUST include its full URL. Text-only references (e.g., "LinkedIn John Doe" without a URL) are PROHIBITED. See `output/reports/citation-guide.md` for the mandatory URL policy.**

All sources consulted during this investigation:

| # | Source | URL (MANDATORY) | Date Accessed | Notes |
|---|--------|-----------------|---------------|-------|
| 1 | [Source name] | [Full URL — e.g., https://linkedin.com/in/john-doe] | [date] | [relevance] |
| 2 | [Source name] | [Full URL — e.g., https://github.com/username] | [date] | [relevance] |

---

## 8. Analyst Caveats & Methodology Notes

- This report is based exclusively on publicly available information gathered via web search.
- Correlation between accounts is inferred from shared identifiers (usernames, emails, bios) and is not guaranteed to represent the same individual.
- Confidence ratings reflect the analyst's assessment at time of writing and may change with additional information.
- No private data was accessed. No accounts were created or logged into. No social engineering was employed.
- [Any investigation-specific caveats]

---

## 8a. Client-provided Details

[What the client supplied at intake. These seeded collection and are not independent corroboration. A value marked sensitive prints as "provided by client — withheld" unless the report was built with `--show-sensitive`.]

| Type | Value | Note | Sensitive |
|------|-------|------|-----------|
| [phone] | [provided by client — withheld] | [number the subject used to contact staff] | [yes] |

---

## 9. Counting Rules

[What every headline number counts — and what it does not mean. A count of tokens, credentials, bytes, log lines or attack chains is never a count of accounts, victims or hosts; duplicates are counted once; attempted and confirmed outcomes are never added together.]

| Metric | Counts | Does not mean |
|--------|--------|---------------|
| [exposed_tokens] | [distinct session tokens in the dump, deduplicated] | [number of compromised accounts] |

---

## 10. Roles

[Analyst judgement for this report only (RULE 5): a role is not a knowledge-base edge and never names an operator on a single signal.]

| Entity | Role | Basis | Confidence | Admiralty |
|--------|------|-------|------------|-----------|
| [operator@example.com] | [operator / supplier / publisher / intruder / facilitator / victim / unknown] | [registrant e-mail on 3 domains] | [moderate] | [B2] |

---

## 11. Incident Timeline

| ID | When (UTC) | Event | Proves | Not proven | Evidence | Kind |
|----|------------|-------|--------|------------|----------|------|
| T001 | [2026-01-01T00:00:00Z] | [example.com registered] | [domain existed from this date] | [who registered it] | [WHOIS capture URL] | [technical / context] |

---

## 12. ATT&CK Mapping

| MAP | Technique ID | Technique | Tactic | Chain | Status | Evidence | Limits |
|-----|--------------|-----------|--------|-------|--------|----------|--------|
| MAP-01 | [T1078] | [Valid Accounts] | [Initial Access] | [chain A] | [observed / attempted / inferred] | [T001, FND-002] | [no log of a successful session] |

---

## 13. Scenarios

| ID | Title | Feasibility | Impact | Narrative | Controls |
|----|-------|-------------|--------|-----------|----------|
| SC-01 | [Credential reuse against the portal] | [high / moderate / low] | [very high / high / moderate / low] | [how it would unfold] | [MFA; token revocation] |

---

## 14. Recommendations

### P1 — this week
| Action | Owner | Done when |
|--------|-------|-----------|
| [Revoke the exposed tokens] | [IT security] | [revocation confirmed in the IdP log] |

### P2 — this month
[same table]

### P3 — ongoing
[same table]

---

## 15. Open Questions

[What we wanted to find but couldn't — each tied to the decision it blocks and the sources that would close it.]

| OQ | Question | Decision at stake | Sources needed | Window | Owner |
|----|----------|-------------------|----------------|--------|-------|
| OQ-01 | [Was the token used after the leak?] | [whether to notify customers] | [IdP sign-in logs] | [2026-01-01 – 2026-01-31] | [SOC] |

---

## Appendix — QA Warnings

[Consistency checks over the report block (`report_sections.lint`): one identifier on two entities, an alias/relative without basis or source, a row without a source, near-duplicate handles, a client seed contradicting a confirmed row. Resolve or explain each before release.]

- [identifier on two entities: … ]

---

## Appendix A — Sources Checked

[Every source/tool queried for this case, INCLUDING zero-hit results — a zero row is a negative result at collection time, not proof of absence.]

| Source | Selector | Calls | Hits | Status | First (UTC) | Last (UTC) |
|--------|----------|-------|------|--------|-------------|------------|
| [web-scan index] | [example.com] | [1] | [0] | [zero] | [2026-01-01T00:00:00Z] | [2026-01-01T00:00:00Z] |
| [passive DNS] | [example.com] | [1] | [n/r] | [n/r — ran, result count not recorded] | [2026-01-01T00:00:00Z] | [2026-01-01T00:00:00Z] |

---

*Generated by Free OSINT Expert Skill v1.0 — AI-Assisted Open Source Intelligence*
```

---

## Report JSON fields (generators)

`build_report_data.py` emits these keys into the flat report JSON (REPORT.json) from the analyst
`report` block that `evidence_import` stores (`{"findings": [...], "report": {...}}`, read by
`intel_engine/tools/report_sections.py`). `generate-cti-html.py`, `generate-cti-docx.py` and
`generate-cti-docx-hybrid.py` render each section only when its list is non-empty, in the order of
the template above. Every key is optional; every row is a JSON object.

| Key | Row fields |
|-----|-----------|
| `key_questions` | `id` KQ-nn, `question`, `status` answered\|partial\|open, `answer`, `confidence` high\|moderate\|low, `refs[]` |
| `open_questions` | `id` OQ-nn, `question`, `decision_at_stake`, `sources_needed[]`, `window_start`, `window_end`, `owner` |
| `roles` | `entity`, `role` operator\|supplier\|publisher\|intruder\|facilitator\|victim\|unknown, `basis`, `confidence`, `admiralty` |
| `scenarios` | `id` SC-nn, `title`, `feasibility` high\|moderate\|low, `impact` very_high\|high\|moderate\|low, `narrative`, `controls[]` |
| `roadmap` | `priority` P1\|P2\|P3, `action`, `owner`, `done_when` |
| `incident_timeline` | `id` Tnnn, `when` ISO-8601, `event`, `proves`, `not_proven`, `evidence[]`, `kind` technical\|context |
| `attack_mapping` | `id` MAP-nn, `technique_id` (T1078 / T1078.004), `technique`, `tactic`, `chain`, `status` observed\|attempted\|inferred, `evidence`, `limits` |
| `counting_rules` | `metric`, `counts`, `does_not_mean` |
| `sources_checked` | `source`, `kind` tool\|api, `source_class` (public wording — the rendered Source column), `selector`, `calls`, `hits` int\|"unknown", `status` hit\|zero\|error\|skipped\|unknown, `errors`, `skipped`, `first`, `last`, `reason` (from the case tool-call + api-usage ledgers; zero-hit rows kept; `unknown` = ran but result count not recorded, rendered "n/r — ran, result count not recorded", never as hit or zero) |
| `metrics` | `metric`, `value`, `unit` (what one counted item is: token, credential, account …), `values[]` (the counted items, for the duplicate check), `status` confirmed\|attempted\|mixed, `components[]` ({`label`, `value`, `status`}) |
| `metric_warnings` | list of strings from `validate_metrics` (see below) |
| `subject_profile` | `entity`, `field` name\|alias\|dob\|birthplace\|email\|phone\|address\|company\|account\|relative\|other, `value`, `basis`, `source`, `admiralty`?, `status` confirmed\|probable\|possible; `client_provided` (bool) is added by the builder when the value matches a client seed |
| `client_seeds` | `type`, `value`, `note`?, `sensitive` (bool). A sensitive value — and any identity row carrying it — is written as "provided by client — withheld" unless `build_report_data.py --show-sensitive`; `sensitive_shown` records which |
| `engagement` | OBJECT `{author, version, created, modified, hours, client?}` → cover analyst (`case.analyst` = author) and the Document Control front matter |
| `qa_warnings` | list of strings from `report_sections.lint(sections, findings)` (sensitive client values scrubbed unless `--show-sensitive`) |
| `findings[].confirmation` | confirmed\|strong_indirect\|attempted_unproven\|unverified (copied from the evidence import) |
| `findings[].not_proven` | what the finding does not establish |
| `risk_assessment` | OBJECT `{model, domains[], overall, coverage, bands, priorities, import_record}` — the organisation risk object (report block, else `cases/<case>/exposure_organisation.json`); only these keys are carried. Rendered "Overall Risk" (score sentence + domain table, highest score first) and "Rating Scales" (bands + P1/P2/P3 deadlines) |
| `key_findings` | `n`, `finding`, `severity`, `priority` P1\|P2\|P3\|P4, `priority_label` — rendered in `n` order; `priority_label` is "P1 (7 days)" with the deadline from `risk_assessment.priorities`, or "P4 (track only — no deadline)" for the Severity Tier Matrix track-only tier |
| `affiliate_exposure` | `org`, `country`, `infected_hosts`, `latest_infection`, `stealer_family`, `portal` — COUNTS ONLY: any other field is dropped by the builder and again by the generators (`counts_only`), so a credential or cookie never reaches the JSON, the HTML data or the DOCX |
| `leak_claims` | `actor`, `venue`, `date`, `claim`, `proven` (bool), `evidence[]`; unproven rows print **Unconfirmed** |
| `leak_claims_tally` | `{claims: N, proven: K}` — K counts only rows whose `proven` is literally true; the generators print "Of N dark-web/Telegram claims naming the subject, K are proven" from the rows, and `validate_metrics` warns when a hand-edited tally disagrees with them |
| `threat_events` | `event`, `start`, `end`?, `location`, `why_it_raises_risk`, `local_legal_notes`, `grade` — by start date |
| `usernames_to_reserve` | `platform`, `handle`, `status` available\|taken_by_other\|reserved |
| `negative_checks` | `check`, `scope`, `result` (default "no record"), `date` — rendered "Checked — Nothing Found" with the zero-hit `sources_checked` rows |
| `email_services` | `email`, `service`, `evidence[]`, `date`. The address is written "(withheld)@domain" (also inside `qa_warnings`) unless `build_report_data.py --show-sensitive`; the generators re-apply this to a hand-authored file |
| `actor_profile` | OBJECT — the actor threat-profile object as imported (see "House report sections — actor threat profile"), plus `threat_score` {`actor`, `threat_score`, `band`, `posture`, `source`} when `cases/<case>/actor_scores.json` holds the actor |
| `claim_confidence` | `claim`, `confidence` High\|Medium\|Low\|Low_to_Medium (rendered "Low to Medium"), `rationale`, `sources[]` |
| `pivot_opportunities` | `seed_artifact`, `pivot_question`, `defensive_use` |
| `playbook` | `tactic`, `behaviours[]`, `attack_ids[]`, `evidence[]` — in ATT&CK tactic order |
| `attack_coverage` | DERIVED: `technique_id`, `tactics[]`, `playbook` (bool), `hunts[]` (HH ids), `mappings[]` ("MAP-nn (status)" from `attack_mapping`) — every technique the playbook or a hunt hypothesis names, in tactic order |
| `hunt_hypotheses` | `id` HH-nn, `hypothesis`, `priority_telemetry[]`, `behavioural_signals[]`, `attack_ids[]`, `hunt_package_ref`? |
| `telemetry_priorities` | `source`, `why`, `baseline_ref`? — in the analyst's priority order |
| `report_figures` | `{card_maps: {person\|threats\|suppliers: png}, exposure_charts: {fig_exposure_year\|fig_exposure_country\|fig_exposure_family: png}, exposure_source}` — absolute paths. The builder draws them into `cases/<case>/report/report-data/` (card maps via `house_report_charts.build_card_maps`, card text through `house_report.scrub` — the Rule 12 vendor/tool-name scrub + masking — exactly as in the house report; charts via `house_report_exposure_charts`); with `--no-figures`, or when drawing fails, it records the house report's `report/card_map_*.png` / `fig_exposure_*.png` (the person map only when no sensitive client seed could be on it). The HTML inlines each PNG as a data URI and drops this key from its embedded data; the DOCX embeds each with its caption |

Order in the generators (house-report order): Key Questions, subject card map, Overall Risk, Key
Findings — Severity and Priority (HTML overview / DOCX executive summary); Counting Rules, Rating Scales; threat card map,
Affiliate Exposure (+ charts), Dark-web and Telegram Claims, Services Registered by E-mail, Events That
Raise the Threat; Actor Profile (one chapter: Executive Line, Source Basis and Confidence, Actor
Overview, Intent, Capability, Victimology, Persona & OPSEC, Tempo, Infrastructure and Defensive Pivots,
Operational Playbook, ATT&CK Coverage, Hunt Hypotheses, Priority Telemetry); Roles, supplier card map,
Incident Timeline …; Recommendations, Usernames to Reserve; QA Warnings, Sources Checked, Checked —
Nothing Found. Each renders only when present.

Backward compatibility: `intelligence_gaps` (flat strings) is still emitted — when `open_questions`
exist, one string per OQ row leads the list; `recommendations` (flat strings) is derived from
`roadmap` when present.

**Anti-inflation check.** `validate_metrics(data)` (`scripts/cti_report_sections.py`, re-exported by
`build_report_data.py`; rules in `scripts/references/report_metrics.json`) warns — to stderr and
into `metric_warnings`, never changing a number — when a label implies accounts / victims / hosts /
records but the unit is tokens / credentials / bytes / attack chains (unless a counting rule with a
`does_not_mean` covers that metric), when `values[]` holds duplicates or two metrics count the same
value, and when attempted and confirmed outcomes are summed. The generators run it on a
hand-authored JSON that lacks `metric_warnings` and print the warnings in Counting Rules.

## House report sections — organisation risk, threat and person (report block)

These `report` block keys are accepted by `evidence_import` (schema: `references/evidence_import.json`
`report_sections`), merged by `report_sections.load` (latest import wins per merge key) and rendered by
the house report (`house_report_sections.py`). `build_report_data.py` carries them into REPORT.json too
(see Report JSON fields), so the HTML and DOCX generators render them as well. An
absent key renders nothing.

| Key | Row fields | Where it renders |
|-----|-----------|------------------|
| `risk_assessment` | OBJECT, the organisation risk object: `domains[]` (`id`, `name`, `exploitability` 0–3, `harm` 0–3, `score` 0–10, `level` Critical\|High\|Medium\|Low, `main_issue`, `rationale`), `overall` {`score`, `level`, `method`}, `coverage` {`rated`, `total`, `unrated[]`, `warning`?}, `bands` {level: inclusive lower bound}, `priorities` {P1: "7 days", …}. When no import carries it, `cases/<case>/exposure_organisation.json` (from `exposure_score.py --model organisation --case`) is read | Executive Summary "Overall risk": "<level> (<score>/10), mean of N of M rated domains" plus a domain · score · level · main issue table, highest score first. Methodology "Rating scales": bands and P1/P2/P3 deadlines |
| `key_findings` | `n` (number), `finding`, `severity` Critical\|High\|Medium\|Low\|Info, `priority` P1\|P2\|P3\|P4 (P4 only here; `roadmap` stays P1–P3) | Executive Summary "Key findings", in `n` order, with the priority deadline from `risk_assessment.priorities`; P4 prints "P4 (track only — no deadline)" |
| `affiliate_exposure` | `org`, `country`, `infected_hosts` (number), `latest_infection` ISO date, `stealer_family` (string or list), `portal` | Findings "Affiliate exposure — infected computers". Counts only: no credential or cookie is ever printed. Charts by year of infection, country and stealer family when the data exists (from these rows, otherwise from the case's stealer-triage `STEALER-ANALYSIS-*.json`) |
| `leak_claims` | `actor`, `venue`, `date` ISO, `claim`, `proven` (bool), `evidence[]` | Findings "Dark-web and Telegram claims": "Of N dark-web/Telegram claims naming the subject, K are proven"; every unproven row is labelled **Unconfirmed** |
| `threat_events` | `event`, `start` ISO, `end` ISO?, `location`, `why_it_raises_risk`, `local_legal_notes`, `grade` (Admiralty) | Findings "Events that raise the threat", by start date |
| `email_services` | `email`, `service`, `evidence[]`, `date` ISO | Findings "Services registered by e-mail". The address is shown as "(withheld)@domain" unless `--show-sensitive`, and is withheld from the QA warnings too |
| `usernames_to_reserve` | `platform`, `handle`, `status` available\|taken_by_other\|reserved | Recommendations "Usernames to reserve", as a defensive recommendation |
| `negative_checks` | `check`, `scope`, `result` (default "no record"), `date` ISO | Appendix "Sources checked" → "Checked — nothing found", together with the zero-hit ledger sources |
| `relationships` | `from`, `to`, `relation`, `description`?, `group`?, `side` left\|right\|full, `grade`?, `confirmed` (bool, default true), `dates`?, `cc` (2-letter)?, `icon`? | Card maps (person / organisation). An unconfirmed card is drawn dashed |
| `actors` | `name`, `type` (the panel title), `claim`?, `grade`?, `confirmed` (bool, default true), `cc`?, `date`?, `icon`? | Threat card map. An unconfirmed claim is drawn dashed |

Lint (`report_sections.lint`, shown in the QA warnings appendix): a Critical or High key finding
without a priority; a Critical key finding at P4 (the Severity Tier Matrix never gives Critical that
tier — a severity / exposure / priority mismatch); an overall risk score that is not the mean of its
domain scores; a threat event that ended before the report date (stale); a leak claim marked proven
with no evidence.

## House report sections — actor threat profile (report block)

An actor threat-profile deliverable, structure adapted from [PK Packt ACTIH companion repo, 2026,
chapter-03 threat-profile deliverable] (MIT). The house report renders one "# Actor Profile" chapter
after Findings when `actor_profile` or any of the row sections below is present; every sub-section
with no data is omitted. Vocabulary (ATT&CK tactic order, ICD-203 likelihood terms, confidence words,
the actor-score file) lives in `references/report_sections.json` `actor_profile`. An actor profile,
its threat score and its tier are analyst judgement and leads — never attribution in the KB and
never a same-operator edge (RULE 5).

| Key | Row fields | Where it renders |
|-----|-----------|------------------|
| `actor_profile` | ONE object: `name` (required), `executive_line`, `aliases[]` {`name`, `source`}, `attribution` {`assessment`, `likelihood` (ICD-203 term), `confidence`, `dissent[]`}, `activity_timeline[]` {`when`, `event`, `sources[]`}, `intent` {`motivations[]`, `evidence[]`}, `capability` {`summary`, `evidence[]`}, `victimology` {`sectors[]`, `geographies[]`, `data_targeted[]`}, `persona_opsec[]`, `tempo_summary`, `tempo_ref` (pointer to the case timeline's tempo analysis), `threat_score_ref` (key into `cases/<case>/actor_scores.json`; default `name`) | Executive line + threat-score line (an analyst lead, from the actor-score file only); Overview: Aliases, Attribution — always "<assessment> — *<likelihood>*, **<confidence> confidence**" (an absent term is printed as "not stated") and every dissent line —, Activity timeline (by `when`); Intent; Capability; Victimology; Persona & OPSEC; Tempo |
| `claim_confidence` | `claim`, `confidence` High\|Medium\|Low\|Low to Medium, `rationale`, `sources[]` | "Source basis and confidence" |
| `pivot_opportunities` | `seed_artifact`, `pivot_question`, `defensive_use` | "Infrastructure and defensive pivots" — a hit is a lead, not a same-operator link |
| `playbook` | `tactic`, `behaviours[]`, `attack_ids[]`, `evidence[]` | "Operational playbook", in ATT&CK tactic order (unknown tactics last) |
| `hunt_hypotheses` | `id` HH-nn, `hypothesis`, `priority_telemetry[]`, `behavioural_signals[]`, `attack_ids[]`, `hunt_package_ref`? (a key into the hunt-package index, carried as a string) | "Hunt hypotheses", by id |
| `telemetry_priorities` | `source`, `why`, `baseline_ref`? (a key into the `settings` of `intel_engine/IntelAnalysis/references/telemetry_baselines.json` — the Windows audit setting that produces the source, carried as a string) | "Priority telemetry", numbered in the analyst's order |

"ATT&CK coverage" is derived, not imported: every technique id the playbook or a hunt hypothesis
names, with its tactic(s), whether the playbook carries it, the HH ids that hunt it, and the
incident `attack_mapping` rows (MAP-nn) that evidence the same technique. `attack_mapping` keeps its
own per-technique, per-status incident table in "Infrastructure and lifecycle"; the playbook is the
actor-level, per-tactic behaviour view, so neither duplicates the other.

Lint: an attribution without an ICD-203 likelihood term or a confidence; an intent with no evidence; a
High `claim_confidence` row without sources; a hunt hypothesis without priority telemetry or
behavioural signals; a playbook row with an ATT&CK id but no evidence; a `hunt_package_ref` that is
not an `id` in `intel_engine/IntelAnalysis/references/hunt_packages.json` (index missing or unreadable:
one "hunt package index unavailable — refs not checked" warning); a `tempo_ref` that is not the case's
timeline ledger (`<stem>_events.json`, e.g. `timeline_events.json` or `timeline_events.json#operator_tempo`,
case-relative), whose file is absent or has no `operator_tempo` read; a non-empty `tempo_summary` while
that read's status is `insufficient`; a `baseline_ref` that is not a `settings` key in
`intel_engine/IntelAnalysis/references/telemetry_baselines.json` (map missing or unreadable: one
"telemetry baseline map unavailable — refs not checked" warning). All are QA warnings, never import
rejections.

**Priority telemetry and `baseline_ref`.** Name the log source in `source` and why the hunt needs it in
`why`. When the source is Windows event logging, set `baseline_ref` to the matching setting key in
`telemetry_baselines.json` (for example `process_creation_cmdline`, `logon`, `scheduled_task_audit`,
`powershell_script_block`). That map, adapted from Yamato Security's EventLog-Baseline-Guide (MIT),
gives the audit subcategory, the Windows default, what each compared baseline (Yamato Security,
Microsoft client/server, ASD) sets, and the guide's log-size floor. It answers the consumer's first
question, "do we even log this?"; it is a configuration pointer, not evidence that the consumer logs
it. A `baseline_ref` that resolves is printed after the row's Why as "— Windows audit setting: <name>
(<event IDs>)" in every output, and REPORT.json carries it as `baseline_setting` next to `baseline_ref`;
a row with no ref, or one that does not resolve, prints as before.

Synthetic example (invented actor; example.com only):

```json
{"report": {
  "actor_profile": {
    "name": "SAMPLE PANDA",
    "executive_line": "SAMPLE PANDA runs short credential-phishing waves against example logistics portals.",
    "aliases": [{"name": "Group-0001", "source": "https://example.com/reports/group-0001"}],
    "attribution": {"assessment": "One operator runs every wave in this case", "likelihood": "likely",
                    "confidence": "moderate",
                    "dissent": ["A resold phishing kit could explain the overlap."]},
    "activity_timeline": [{"when": "2025-11", "event": "First observed wave",
                           "sources": ["https://example.com/wave-1"]}],
    "intent": {"motivations": ["financial gain"], "evidence": ["https://example.com/payout-panel"]},
    "capability": {"summary": "Commodity kit, hand-tuned lures, fast domain rotation.",
                   "evidence": ["https://example.com/kit"]},
    "victimology": {"sectors": ["logistics"], "geographies": ["EU"], "data_targeted": ["portal credentials"]},
    "persona_opsec": ["Registers through privacy proxies."],
    "tempo_summary": "Registrations cluster on weekdays.",
    "tempo_ref": "timeline_events.json#operator_tempo"},
  "claim_confidence": [{"claim": "The waves share one operator", "confidence": "Medium",
                        "rationale": "Shared registrant and kit build", "sources": ["https://example.com/overlap"]}],
  "pivot_opportunities": [{"seed_artifact": "Kit favicon hash", "pivot_question": "Which other hosts serve it?",
                           "defensive_use": "Pre-emptive blocklist"}],
  "playbook": [{"tactic": "Initial Access", "behaviours": ["Links to look-alike portals"],
                "attack_ids": ["T1566.002"], "evidence": ["https://example.com/lure"]}],
  "hunt_hypotheses": [{"id": "HH-01", "hypothesis": "Look-alike portal visits follow a phishing e-mail",
                       "priority_telemetry": ["proxy logs", "mail gateway"],
                       "behavioural_signals": ["first visit to a days-old domain after a mail click"],
                       "attack_ids": ["T1566.002"]}],
  "telemetry_priorities": [{"source": "Web proxy logs", "why": "Lure clicks"},
                           {"source": "Windows process creation with command line",
                            "why": "Lure attachment spawning a script host", "baseline_ref": "process_creation_cmdline"}]}}
```
