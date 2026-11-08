# Signature Catalog

Reference library of observable signatures used during case analysis. Organized by detection domain.

---

## Categories

| Category | Scope |
|---|---|
| TEMPORAL_SIGNATURES | Activity timing, cadence, and scheduling regularities |
| BEHAVIORAL_SIGNATURES | Handle construction, platform presence, and account lifecycle markers |
| NETWORK_SIGNATURES | Connection structure, follower quality, and coordination indicators |
| LINGUISTIC_SIGNATURES | Writing style, vocabulary, and content fingerprinting |
| AGENTIC_SIGNATURES | Autonomous / multi-agent attack tooling in captured attacker telemetry or server logs |

---

## TEMPORAL_SIGNATURES

### T-01: Precision Posting Interval
Automated scheduling often produces machine-precise intervals.

| Variance Window | Interpretation |
|---|---|
| ≤ 3 minutes | High automation probability |
| 3–15 minutes | Possible scheduler |
| > 15 minutes | Likely manual |

Regex to detect clock-hour posting:
```regex
^(0[0-9]|[01][0-9]|2[0-3]):00:\d{2}$
```

### T-02: Off-Timezone Clustering
Posts clustered outside claimed timezone's waking hours (23:00–06:00 local).

```python
def timezone_mismatch_score(post_times, claimed_tz):
    local_times = [convert_to_tz(t, claimed_tz) for t in post_times]
    off_hours = [t for t in local_times if t.hour in range(23, 6)]
    return len(off_hours) / len(local_times)
# Score > 0.40 → significant mismatch
```

### T-03: Coordinated Multi-Account Timing
Multiple accounts posting within a tight window on a recurring basis.

```
WHEN accounts_posting_within(5_minutes) >= 3
AND common_hashtag_or_content
AND recurrence >= 4_times_in_30d
THEN classify = COORDINATED_CAMPAIGN
```

### T-04: Dormancy-Burst Cycle
Long silence followed by dense activity, then silence again.

```
WHEN gap_days > 45
AND burst_posts_in_3d > 20
AND subsequent_gap > 30_days
THEN classify = DORMANCY_BURST_CYCLE
```

---

## BEHAVIORAL_SIGNATURES

### B-01: Handle Obfuscation Variants

| Substitution Class | Characters | Example |
|---|---|---|
| Numeral-alpha swap | 0→o, 1→l/i, 3→e, 4→a, 5→s, 7→t | `j4ck5on` |
| Symbol injection | @ → a, $ → s, ! → i | `c@rter` |
| Separator insertion | _, ., - | `john.doe` vs `johndoe` |
| Prefix/suffix | real, the, official, 1, 2 | `realjohndoe` |

Detection regex (leet numerals):
```regex
[a-z]*[013457@$!][a-z0-9@$!]*
```

### B-02: Disposable Email Fingerprints

Common patterns:
```regex
# Random prefix (bot-generated)
^[a-z]{6,12}[0-9]{3,6}@

# Known disposable TLDs
@(mailinator|guerrillamail|10minutemail|tempmail|throwam|yopmail)\.

# Plus-aliasing (privacy-aware)
\+[a-z0-9]{3,}@
```

### B-03: Account Age Disparity
Subject claims long-standing presence but account creation timestamp is recent.

```
WHEN subject.states_active_since = "2015"
AND account.created_at > 2022-01-01
THEN flag = CLAIMED_HISTORY_MISMATCH
```

### B-04: Platform Selectivity

Flag when subject avoids all high-verification platforms (LinkedIn, verified accounts) despite professional claims. Presence only on email-only or no-auth platforms indicates deliberate identity compartmentalization.

### B-05: Catch-All Email Domain
```
# Probe: send to random@targetdomain.com
# Delivery without bounce = catch-all enabled
# Implication: any address at domain is valid; enumeration useless
```

---

## NETWORK_SIGNATURES

### N-01: Follower Quality Score

Score each follower: +2 per quality signal (profile complete, >10 posts, account age >90d, following/follower ratio <5, engagement rate >1%). Max 10 per follower. Aggregate average: score < 0.30 → low-quality base (purchased or bot).

```python
# score / (len(followers) * 10)  → 0.0–1.0; threshold 0.30
```

### N-02: Coordinated Mutual Cluster
```
WHEN account_set_A follows account_set_B AND vice versa
AND all_accounts_created_within(30_days)
AND follower_quality_score < 0.35
THEN classify = INAUTHENTIC_MUTUAL_CLUSTER
```

### N-03: Hub-Spoke Coordination
One central account followed by dozens of low-quality amplifier accounts that repost exclusively from the hub.

```regex
# Repost-only bio pattern
(bot|auto|mirror|feed|relay|posts from @)
```

---

## LINGUISTIC_SIGNATURES

### L-01: Phrase Reuse Across Accounts

Build 4-gram fingerprints per account. Compute Jaccard coefficient across combined post corpora. Jaccard > 0.35 → strong authorship link.

### L-02: Capitalization and Punctuation Habits

Machine-distinctive personal style markers (regex examples):
- Oxford comma: `,\s+and\s+\w+\.$`
- Habitual ellipsis: `\w\.\.\.` (no trailing space)
- Double punctuation: `\w[!?]{2,}`

### L-03: Non-Native Language Markers

| Construction | Probable L1 |
|---|---|
| "I am agree" | Russian / Slavic |
| "very much thank" | CJK |
| "since X years" | Romance language |

### L-04: Copy-Paste Bot Content

```
WHEN jaccard(post_A, post_B) > 0.95
AND accounts_unrelated AND time_delta < 30_minutes
THEN classify = CONTENT_SYNDICATION_BOT
```

---

## AGENTIC_SIGNATURES

Shapes left by autonomous or multi-agent attack tooling — an LLM planner dispatching tool-calling workers — in captured attacker telemetry, honeypot logs, or the access logs of a seized/cooperating server. Evaluated by `scripts/osint/signature_scan.py` (raw `requests` / `payloads` / `log_lines` / `credential_events`, or precomputed `agt_*` scalars — see `--list`); thresholds live in `scripts/osint/references/agentic_signatures.json`, and that file wins over the numbers quoted here if they ever diverge.

**RULE 5 — applies to every AGT signature:** detecting an agent framework identifies TOOLING (kit rung), never the human operator or sponsor. A fired AGT signature is a FACT/LEAD about the traffic: never a KB edge (`add_edge`), never `operator_lead`, never a name on a single signal. Two estates hit by the same agent framework share a *tool*, exactly as two sites built from one phishing kit share a kit.

Feed **document-level** requests (strip static assets): one human page load fetches dozens of sub-resources in a sub-second burst and will otherwise trip AGT-01/02.

### AGT-01: Sub-second Machine Cadence
- **Observable:** median inter-request interval across one source/session.
- **Threshold:** median ≤ 1000 ms over ≥ 50 requests.
- **False positives:** CI test suites, uptime monitors, load tests, vulnerability scanners, browser sub-resource fetches (feed document-level requests only).
- **RULE 5:** tooling (kit rung), never the operator.

### AGT-02: Planner/Worker Burst Rhythm
- **Observable:** runs of ≥ 5 requests at < 1000 ms spacing (worker tool calls) separated by 1.5–60 s pauses (planner inference latency) — a stop-think-fan-out rhythm rather than a constant scanner rate.
- **Threshold:** ≥ 3 such bursts.
- **False positives:** crawlers with politeness back-off, batch jobs with per-batch sleeps, humans opening many tabs at once.
- **RULE 5:** tooling (kit rung), never the operator.

### AGT-03: Parallel Fan-out Across Hosts
- **Observable:** one request shape (method + path template, ids collapsed) sent to many distinct hosts inside a short window.
- **Threshold:** ≥ 10 distinct hosts within 10 s.
- **False positives:** internet-wide scanners (research or commercial), CDN health checks, legitimate fleet automation (config management, monitoring).
- **RULE 5:** tooling (kit rung), never the operator.

### AGT-04: Systematic Enumeration Ordering
- **Observable:** consecutive distinct targets (host+path) visited in sorted order or with a +1 numeric id step.
- **Threshold:** ≥ 85 % of consecutive pairs ordered over ≥ 20 distinct targets (random order sits near 50 %).
- **False positives:** sitemap-driven crawlers, backup/sync tools, paginated API clients, directory brute-forcers driven by sorted wordlists (also tooling, not necessarily agentic).
- **RULE 5:** tooling (kit rung), never the operator.

### AGT-05: Library / Headless User-agent Mix
- **Observable:** default HTTP-library UAs (`python-httpx`, `aiohttp`, `Go-http-client`, `node-fetch` …) — what a framework sends when nobody sets one — mixed in one session with headless browsers (`HeadlessChrome`, Playwright, Puppeteer) or self-declared agent fetchers.
- **Threshold:** library share ≥ 50 %, or library and headless/declared-agent each ≥ 5 %.
- **False positives:** CI/CD and integration tests, internal scripts, SDK clients, self-declared AI crawlers that are honouring robots.txt (declared-agent alone never fires).
- **RULE 5:** tooling (kit rung), never the operator.

### AGT-06: Retry-with-Variation After 4xx
- **Observable:** a 4xx (401/403/404/422/429) followed within 10 s by a request to the same host + path template whose raw path, query, method or body has CHANGED — an agent reasoning about the error and mutating the payload, unlike a plain retry.
- **Threshold:** ≥ 3 varied retries.
- **False positives:** fuzzers and WAF-bypass scanners (tooling, not necessarily agentic), API clients with fallback endpoints, humans correcting a typo in a URL.
- **RULE 5:** tooling (kit rung), never the operator.

### AGT-07: LLM Prose Artefacts in Traffic
- **Observable:** assistant-style prose in payloads, form fields, code comments, UAs or log lines — refusals, "Certainly! Here is the updated payload", `<thinking>` tags, markdown code fences, leaked system-prompt text.
- **Threshold:** ≥ 1 matching string (raise to ≥ 3 for noisy corpora).
- **False positives:** chatbot features on the logged site itself, developers pasting assistant output into tickets/comments, spam generated by LLMs (content tooling, not an attack agent).
- **RULE 5:** tooling (kit rung), never the operator.

### AGT-08: Tool-call JSON / Prompt Leakage
- **Observable:** tool-call / function-call fragments in logs or payloads — `"tool_calls":`, `"function_call":`, `"role":"tool"`, `"arguments":"{…`, `<function_calls>`, `mcp__…` tool names, ReAct `Thought: … Action:` lines.
- **Threshold:** ≥ 1 matching string.
- **False positives:** the logged server legitimately proxies an LLM API, developer tooling or observability pipelines that log agent traces.
- **RULE 5:** tooling (kit rung), never the operator.

### AGT-09: Fresh-harvest Credential Spraying
- **Observable:** a secret first seen exposed in a public source (paste, public repo commit, leaked env file) is tried against login/API endpoints shortly after. Pass `credential_events` with a FINGERPRINT (hash) of the secret, never the secret itself.
- **Threshold:** first attempt ≤ 60 min after exposure.
- **False positives:** secret-scanning services validating leaked keys (GitHub/provider partner programmes), the owner rotating and testing the key, red-team engagements.
- **RULE 5:** tooling (kit rung), never the operator.

```
WHEN AGT-01 AND (AGT-03 OR AGT-06)
AND (AGT-05 OR AGT-07 OR AGT-08)
THEN classify = AUTONOMOUS_AGENT_TOOLING   # kit rung — names a tool, never a person
```

---

## Confidence Reference

| Signature | Confidence | Key Booster |
|---|---|---|
| T-01 precision interval | 78% | Multi-week consistency |
| T-03 coordinated timing | 85% | Recurrence count |
| B-01 leet handle | 72% | Cross-platform confirm |
| B-02 disposable email | 90% | Domain in known-bad list |
| N-01 follower quality | 80% | Sample size |
| L-01 phrase overlap | 82% | Higher Jaccard |
| AGT-03 parallel fan-out | 75% | Co-fires with AGT-06 retry variation |
| AGT-08 tool-call leakage | 90% | Not the logged server's own LLM traffic |

---

## Cross-References

- `analysis/deviation-detector.md` — BEHAVIORAL_SHIFT triggers reference B-04
- `analysis/cross-reference-engine.md` — L-01 and L-02 feed content matching
- `techniques/username-enumeration.md` — B-01 variant generation
- `scripts/osint/signature_scan.py` + `scripts/osint/references/agentic_signatures.json` — AGT-01..AGT-09 evaluator and tunables
