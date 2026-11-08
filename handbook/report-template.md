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
