# Intrusion Modelling — Diamond events, activity groups, Pyramid of Pain, ATT&CK mapping

cti-expert already collects hosts, certificates, registrants, kits and wallets, and partitions them
into clusters. This file gives that material an analytic structure: what a single observed
**event** is, how events chain into an **activity thread**, how threads and events are grouped
into an **activity group** under a stated grouping function, which pivots are worth the effort
(**Pyramid of Pain**), and how to map behaviour to **ATT&CK** without overclaiming.

Judging the result — likelihood terms, ACH, bias checks — stays in
[`analytic-standards.md`](analytic-standards.md). Same-operator evidence strength stays in the
rung table (`SKILL.md` → *Pivot priority ladder*). This file never raises a rung.

Sources: `[P01 Caltagirone, Pendergast & Betz 2013]` (Diamond Model), `[P03 Strom et al. 2018,
rev. 2020]` (ATT&CK Design and Philosophy), `[Bianco 2013, rev. 2014]` (Pyramid of Pain blog
post). Text tagged with a source restates it; *(adaptation)* marks how cti-expert applies it.

---

## 1. The Diamond event

> **Axiom 1** — for every intrusion event there exists an adversary taking a step towards an
> intended goal by using a capability over infrastructure against a victim to produce a result.
> `[P01 §4]`

| Part | Source definition `[P01 §4]` | cti-expert material *(adaptation)* |
|---|---|---|
| **Adversary** (core) | Actor responsible; usually empty at discovery. Split **operator** (who runs the intrusion) from **customer** (who benefits) — they may differ | Registrant identity, Telegram/handle personas, payment beneficiary — each a *claim about* the adversary, never the vertex itself (§2) |
| **Capability** (core) | Tools and techniques, from manual to automated; C2 is a sub-feature of capability | Kit / template fingerprint, APK, panel, payment flow, `analyze_artifact` output |
| **Infrastructure** (core) | Structures used to deliver capability, keep control, effect results | Hosts, IPs, domains, certs, nameservers, mailboxes, bot tokens — `raw/<host>.json` |
| **Victim** (core) | Target; separate **persona** (people/orgs/industry) from **assets** (accounts, hosts, addresses) | Impersonated brand, targeted customer base, `victim_profile` |
| Meta-features | Timestamp (start/end), phase, result, direction, methodology, resources; extensible (data source, author, detection method) | First/last seen, WHOIS/cert dates, collector name, capture hash |
| **Confidence** | Every core and meta-feature carries its **own** confidence value; the model leaves the scale to the implementation | Per-feature evidence-quality grade (trust 1–5 / Admiralty), never one score for the whole event |

Operating rules:

- **Empty features are gaps, not failures** `[P01 §4]`. After writing an event, every empty
  vertex is a named pivot target or an `intelligence_gaps[]` entry.
- **Confidence is per feature.** "Infrastructure: `portal-verify.example`, confidence high
  (observed); adversary: persona `kit_admin_0001`, confidence low (self-asserted handle)" is one
  event. Do not average them *(adaptation)*.
- **Timestamps decay knowledge.** The source notes that confidence in a feature should fall with
  time because adversaries change `[P01 §4.5.1]`; check validity windows (`/kb --as-of`) before
  reusing an old event.
- **Resources** (Axiom 5: every event needs external resources — funds, accounts, domains,
  hosting, knowledge) `[P01 §4.5.6]` are the cleanest gap generator: for each event ask *how did
  the adversary obtain each resource it needed?* — registrar account, payment method,
  certificate, phone number for the bot. Each unanswered one is a pivot candidate.

## 2. Personas, owners and providers — keeping the vertices honest

The Diamond separates roles that OSINT routinely collapses:

- **Type 1 infrastructure** — fully controlled or owned by the adversary. **Type 2** —
  controlled by a witting or unwitting **intermediary** (compromised hosts, staging servers,
  hijacked mailboxes); it is what the victim sees as "the adversary" and it exists to obscure
  origin. **Service providers** — ISPs, registrars, web-mail and hosting providers that keep
  Type 1 and Type 2 infrastructure available, wittingly or not `[P01 §4.3]`.
- A victim asset in one event can become (Type 2) infrastructure in the next — "the apparent
  target of activity may not necessarily be the victim" `[P01 §4.4]`.
- Registration details used for infrastructure-to-adversary pivots are often false, but a false
  identity **reused consistently** is itself a trackable persona `[P01 §7.1.3, n. 13]`.
- Operator and customer may be different entities `[P01 §4.1]`.

The source states these as feature definitions, not as one numbered axiom. cti-expert turns them
into one standing rule *(adaptation)*:

> **Persona ≠ infrastructure owner ≠ named person.** A registrant string, handle or e-mail is a
> **persona** attached to the adversary vertex. Whoever *controls* a host is a separate question
> (Type 1 vs Type 2), and whoever *operates or benefits* is a third. A link at one level is never
> promoted to the next without its own evidence — the same ladder `SKILL.md` keeps as
> *same infrastructure / same account / same operator / named person*.

Consequences in this skill:

| Observation | Diamond reading | cti-expert handling |
|---|---|---|
| Phishing page on a legitimate business's subdomain | Type 2 infrastructure; the business is a victim asset, not the adversary | `victim_profile`; never name the owner as operator |
| Shared cPanel IP with many tenants, managed NS, CDN, registrar | Service provider | `add_fact` only — a **lead**, never a cluster edge (rung 10) |
| Same privacy-proxy contact on many domains | Service provider artefact | Noise; `/reference check` |
| Same self-asserted registrant e-mail across years of WHOIS | Consistent persona (may still be false) | Owner-link class, rung 1 — joins infrastructure; naming a real person needs separate identity evidence |
| Same kit on many sites | Shared capability | Kit sibling; capability-level, not adversary-level (rung 9) |

## 3. Analytic pivoting — every pivot is a hypothesis test

"Pivoting is the analytic technique of extracting a data element and exploiting that element, in
conjunction with data sources, to discover other related elements" — and it is fundamentally
hypothesis testing `[P01 §7]`. The diamond's edges show what *can* be discovered, not what *will*
be: "success is not guaranteed" `[P01 §7, n. 11]`.

Centred approaches `[P01 §7.1]` and where they live here *(adaptation)*:

| Approach | Starting vertex | cti-expert route |
|---|---|---|
| Infrastructure-centred | Domain / IP / cert / registrant | `/webpivot`, passive DNS, CT, reverse-WHOIS — the default |
| Capability-centred | Kit, APK, panel, script | `analyze_artifact`, kit fingerprint, `url_paths` |
| Victim-centred | Targeted brand or user base | `impersonation_hunt`, `victim_profile` |
| Social-political-centred | Expected adversary–victim relationship | Targeting pattern and motive (5W1H **Why**); the source warns correlation is not causation |
| Technology-centred | Misuse of a technology (e.g. DNS anomalies) | Bulk-registration and DGA-style patterns in `techniques/` |
| Adversary-centred | Direct monitoring of the actor | Generally out of scope for passive OSINT |

Rule *(adaptation)*: write the hypothesis before the pivot ("if `portal-verify.example` shares
an operator with `secure-login.example`, reverse-WHOIS on the registrant should return both") and
record the result as confirming, refuting or non-diagnostic.

## 4. Activity threads and the activity-attack graph

An **activity thread** is a directed, phase-ordered graph of events against **one
adversary–victim pair**; arcs are causal ("this happened because of, and after, that") `[P01 §8]`.
Each arc is labelled with:

- analytic **confidence** in the causal link;
- **AND** (necessary) or **OR** (one of several possible paths);
- **actual** (evidenced) or **hypothesised**;
- the information or resource the earlier event **provides** to the later one.

Axiom 4: every malicious activity has two or more phases executed in succession `[P01 §4.5.2]`.
Any phase model may be used; the source does not claim a universal phase set. Threads can be
linked horizontally across victims when one event serves several.

Why it matters here *(adaptation)*:

- **Hypothesis vs fact.** The source names "the lack of differentiation between hypothesis and
  fact" as one of the most dangerous analytic failings `[P01 §8.2]`. Every hypothesised event
  stays dashed until evidence makes it actual.
- **Gaps by phase.** An empty phase between two evidenced phases is a gap; the resources
  meta-feature says what must have filled it. Simpler explanations — fewer extra hypothesised
  events to satisfy the required resources — are preferred `[P01 §8.2]`.
- **Adversary process.** Features extracted from several events (e.g. register → certificate →
  lure → credential POST) form a process that can be matched against other threads regardless of
  the specific infrastructure — useful when hosts are disposable `[P01 §8.1]`.
- **Activity-attack graph** `[P01 §8.3]`: overlay what the adversary *did* (thread) on what it
  *could* do (attack graph) to show preferred paths and likely next moves. In cti-expert this is
  the bridge to the AAM next-move overlay ([`aam-actor-modeling.md`](aam-actor-modeling.md)).

## 5. Activity groups — state the grouping function

An **activity group** is a set of events and threads associated by **similarity** of features or
processes and weighted by confidence — correlated, not causally linked `[P01 §9]`. The source's
six steps: **analytic problem → feature selection → creation → growth → analysis →
redefinition**. Formally a creation function `AGC(problem, feature vector, events) → groups`, and
it may legitimately produce **zero** groups `[P01 §9.3]`.

What the source requires and what we take from it:

1. **The problem comes first.** A feature vector built to group by likely adversary does not
   necessarily group by malware author or by victim exposure `[P01 §9.1]`. State which question
   the grouping answers.
2. **Name the feature vector and weights** `[P01 §9.2]`. Processes are valid features and resist
   infrastructure churn.
3. **Growth includes abstention.** A new event joins the most similar group *or none*, if
   confidence is below threshold `[P01 §9.4]`.
4. **Overfitting and error propagation.** The source's main warning: weak feature vectors pull in
   unrelated events, and in intrusion analysis this shows up where two activities overlap
   features such as **a public capability or shared hosting space**; each wrong member then
   attracts more wrong members `[P01 §9, n. 21; §9.6]`. Groups must be re-examined and
   re-clustered when contrary evidence appears.
5. **Activity group families** gather groups by common, usually non-technical, features (shared
   funding or tasking) `[P01 §9.7]` — e.g. several kit operators paid out through one laundering
   service. A family is not a single operator.

Mapping to cti-expert *(adaptation)*:

| Diamond term | cti-expert artefact | Grouping function in force |
|---|---|---|
| Event | One host collection (`raw/<host>.json`) plus its dated facts | — |
| Activity thread | `/case-timeline` ordering of one campaign against one victim brand | Causal, phase-ordered |
| Activity group | A component in `clusters.json` / `/clusters` | Connected components over **strong shared owner-link edges** (registrant e-mail/phone, exact cert, analytics IDs, bot tokens, webhooks, non-exchange wallets) |
| Excluded features | Co-tenancy, managed NS, CDN, kit match, privacy proxy | Held as facts/leads — the overfitting causes `[P01 n. 21]` names |
| Redefinition | `/reference add` a benign verdict, `case_reopen`, re-run clusters | Error correction |

Write every reported group with this block:

```
Activity group: AG-1 (CASE-0001)
Analytic problem: which hosts are likely run by the same operator?
Feature vector: registrant e-mail (w=1.0), exact TLS cert (w=0.8), GA/GTM ID (w=0.6)
Creation function: clusters.json connected components over owner-link edges, outliers allowed
Excluded on purpose: shared IP 198.51.100.24 (provider), kit template (capability)
Members / outliers: 2 hosts / 1 kit sibling outside the group
Confidence per membership: see event table
Redefine if: an owner-link is found to be a privacy proxy or a reused agency container
```

A group is **not** an attribution. Labelling a group as one operator, or naming who it is, goes
through ACH ([`analytic-standards.md`](analytic-standards.md) §3).

## 6. Pyramid of Pain — which pivots are worth tracking

Bianco ranks indicator types by how much it costs the adversary when defenders deny them —
bottom to top: **hash values → IP addresses → domain names → network/host artifacts → tools →
TTPs** `[Bianco 2013, rev. 2014]`. Hashes are exact but change with any bit; IPs change with
little effort; domains need registering and paying for, so slightly more; artifacts force the
adversary to reconfigure; denying tools forces research, development and retraining; denying
TTPs forces them to learn new behaviour. Fuzzy hashes sit nearer the tools level because they
tolerate change. His operating question for any report: for every paragraph, *"is there
anything here I can use to detect the adversary's activity, and where does this fall on the
pyramid?"*

The pyramid is **ordinal, not a score**, and it measures **durability / cost to change**, not
same-operator strength. Those are separate axes *(adaptation)*:

| Level `[Bianco]` | cti-expert pivot artefacts *(placement is adaptation)* | Durability for tracking | Attribution strength (rung table) |
|---|---|---|---|
| Hash values | File/APK/sample SHA-256, screenshot hash | Lowest — one rebuild breaks it | Exact sample match only |
| IP addresses | Origin IPs, A records | Low — cheap to move; shared hosting common | Rung 8–10, co-tenancy |
| Domain names | Apexes, subdomains, lookalikes | Low–moderate | Not a link by itself |
| Network / host artifacts | URL path patterns, distinctive headers, favicon of an operator-made asset, JARM, analytics / tag IDs, bot tokens, panel endpoints | Moderate — operator must reconfigure | Rung 3–7 depending on class |
| Tools | Kit / panel codebase, APK signing cert, fuzzy hash, YARA-style kit signature | High — must replace or rebuild | Kit = rung 9 (shared capability); signing cert = rung 6 |
| TTPs | Registration cadence, hosting choice pattern, lure and cash-out process (adversary process, §4) | Highest | Weakest alone — shared across many actors `[P03 §2]` |

How to use it *(adaptation)*:

- **Prioritise pivots up the pyramid** for *tracking over time*: a URL-path pattern or panel
  artefact survives a host rotation that kills every IP and domain pivot (`url_paths`).
- **Use the base for immediate action** (blocking, takedown) and expect it to go stale; mark
  IOC freshness.
- **Never let durability stand in for attribution.** TTPs are hardest to change and the least
  unique; a durable kit artefact is a capability, not an operator.
- A report that lists only bottom-level IOCs has not answered **How** (5W1H): add at least one
  artefact- or behaviour-level observation or state that none was observable.

## 7. ATT&CK mapping — behaviour-backed and procedure-aware

From the design paper `[P03]`:

- **Tactic** = the adversary's tactical *why*; **technique** = *how* (sometimes *what* is gained);
  **sub-technique** = a more specific how; **procedure** = the specific implementation actually
  used, which can span several techniques and include specific tools `[P03 §3.3–3.4.1]`.
- ATT&CK is **empirical**: it documents behaviour seen in the wild (reported, reported
  non-public, under-reported, unreported categories) `[P03 §4.1.2, §4.3.1.4]`. It is not a
  checklist; 100% coverage — of techniques or of every procedure of one technique — is
  unrealistic, and anyone mapping should be able to explain which procedures they actually cover
  `[P03 §2.1]`.
- **Do not attribute on techniques alone**: many groups use the same techniques; attribution
  involves all parts of the Diamond `[P03 §2]`.
- **Do not assume a technique** that was not stated or could have happened another way (the
  paper's example: HTTP C2 does not imply port 80). One behaviour may map to several techniques
  `[P03 §4.3.5]`.
- Techniques performed automatically by software belong to the software, not the group
  `[P03 §4.3.5]`. Use original sources, not secondary reporting `[P03 §4.3.5]`.

Mapping rules *(adaptation)*:

1. Map from an **observed procedure** in the case evidence. Write the procedure sentence first,
   then the technique. Status per the report contract (`handbook/report-template.md` §12):
   `observed` · `attempted` · `inferred` — `inferred` needs the reasoning and stays out of
   detection handoff.
2. **Consult the live ATT&CK site for IDs and names** every time. The knowledge base is
   versioned; techniques are added, re-parented and deprecated `[P03 §3.9]`. The 2020 paper also
   describes pre-access behaviour as a separate PRE-ATT&CK scope — check where such behaviour sits
   in the current matrix rather than relying on that.
3. Most of this skill's evidence is pre-compromise infrastructure and lure behaviour seen from
   outside. Map only what that vantage shows; leave post-compromise tactics empty rather than
   inferring them from a kit's existence.
4. A technique heatmap measures what was **mapped**, not what the adversary did; say so beside
   any coverage figure.

## 8. Worked example — synthetic phishing activity thread (CASE-0001)

All names, addresses and handles are synthetic.

**Seed:** a credential-phishing page impersonating `bank.example`, reported at
`secure-login.example`.

**Events** (confidence per feature: H high · M moderate · L low):

| Ev | Phase | Infrastructure | Capability | Adversary | Victim | Evidence | Status |
|---|---|---|---|---|---|---|---|
| E1 | Resource acquisition | `secure-login.example` registered 2026-03-02 (H) | — | registrant `ops@mailbox.example` (M, self-asserted) | — | RDAP + historic WHOIS | actual |
| E2 | Resource acquisition | `portal-verify.example` registered 2026-03-04 (H) | — | same registrant e-mail (M) | — | reverse-WHOIS preview, 2 results | actual |
| E3 | Staging | both on 198.51.100.24 (H); 40+ other tenants | — | — | — | passive DNS, tenant count | actual |
| E4 | Weaponisation | — | kit "LoginKit-X" template, path `/auth/verify.php` (H) | — | brand assets of `bank.example` (H) | DOM capture, urlscan population ≈ 300 sites | actual |
| E5 | Delivery | lure link to `secure-login.example` | SMS lure (M) | — | customers of `bank.example` (persona, M) | one victim report | actual, single-source |
| E6 | Actions on objective | credentials POSTed to `api.portal-verify.example` (H) | Telegram bot exfil, token `0000000000:AA_fake` (H) | bot owner handle `@kit_admin_0001` (L) | victim credentials | DOM/JS capture | actual |
| E7 | Monetisation | — | — | — | — | — | **hypothesised** — no payment evidence |

**Thread arcs:** E1 →AND→ E5 (provides the lure domain, H) · E4 →AND→ E5 (provides the page,
H) · E5 →AND→ E6 (provides credentials, M — single victim report) · E2 →AND→ E6 (provides the
exfil endpoint, H) · E6 →OR→ E7 (hypothesised; resources needed: cash-out account, mule or
exchange — all unknown).

**Activity group:** AG-1 = {E1, E2, E6} by registrant e-mail and the shared bot token (owner-link
classes). E3's shared IP is **excluded** (service provider, 40+ tenants). E4's kit links
`secure-login.example` to ~300 kit siblings — **excluded** (public capability); those are leads
listed as kit siblings, never members. Writing the group block of §5 with these exclusions is the
check that the source's overfitting warning was applied.

**Pyramid triage of the pivots:**

| Pivot | Level | Next action |
|---|---|---|
| 198.51.100.24 | IP | Block now; do not track (provider, shared) |
| `secure-login.example`, `portal-verify.example` | Domain | Takedown request; watch with `/takedown-watch` for relocation |
| `/auth/verify.php` + POST to `api.<apex>` pattern | Network artifact | `url_paths` across urlscan — survives host rotation |
| Bot token `0000000000:AA_fake` | Network artifact (owner-link) | Strongest join key found; pivot for other kits posting to the same bot |
| LoginKit-X | Tool | Kit-level detection signature for defenders; not an attribution feature |
| Register-pair → same-day TLS → SMS lure → bot exfil | TTP / process | Process match against other threads in the KB |

**ATT&CK (names to verify on the live site before use):** phishing via a link — `observed`
(E5, single source); acquisition of domains — `observed` (E1, E2); phishing for credentials via a
web form — `observed` (E6). Nothing post-compromise is mapped: not visible from this vantage.

**Judgment boundary.** Same infrastructure: E1/E2/E6 — evidenced. Same operator: AG-1 is a
candidate; labelling it one operator needs ACH with H1 *one operator*, H2 *two kit customers
sharing a bot reseller*, H3 *compromised/borrowed bot token*. Named person: **insufficient** —
`@kit_admin_0001` is a self-asserted persona with low confidence and the registrant e-mail is
unverified. Milestones: a second registrant e-mail on the same bot token (H2 up); the token
appearing in unrelated kits (H3 up); payment details for E7.

## 9. When to abstain

- **No event** without at least one evidenced core feature; a list of IOCs with no capability,
  victim or timestamp is a collection, not an event.
- **No group** when the only shared features are provider, kit or ATT&CK-technique level —
  report "no activity group under the owner-link function" (n = 0 is a valid result `[P01 §9.3]`).
- **No ATT&CK ID** without an observed or explicitly reasoned procedure.
- **No operator or person** from the Diamond alone — that is ACH plus identity evidence.

## 10. Operator tempo — when the operator acts *(adaptation)*

The Diamond's meta-features include a timestamp; across many events those timestamps can show a
working rhythm. The companion repo's actor-profile deliverable reads an actor's operational tempo
as a business-hours window and notes "two distinct activity rhythms" — a day-job window and a
second, after-hours line of activity — and turns that into monitoring windows
`[PK Packt ACTIH companion repo, 2026, chapter-03 threat-profile deliverable]`
([pinned](https://github.com/PacktPublishing/Advanced-Cyber-Threat-Intelligence-and-Hunting/tree/0f76fbc2ff505e6fcb2585b1b3d0b08ce271b1e4/chapter-03)).
cti-expert adapts the idea as a passive, deterministic read with an event filter, an abstention
floor and a confounder list: `case_timeline` with `tempo=true` (CLI `--tempo`), tunables in
`intel_engine/IntelGraph/references/operator_tempo.json`. *(adaptation)*

**Trigger.** A case holds a body of timestamps a human plausibly chose — git author times from
`github_harvest`, post or message times, manual panel actions from an authorised engagement,
manually ordered certificates, hand-placed registrations — and the question is one of: when to
monitor, whether a claimed location fits, or whether one "operator" keeps two clocks.

**Inputs.** The case's pivot_extract JSON (registrations, certificates), `github_harvest` output
(`repos[].commits_sampled[]`) and any JSON carrying `operator_events: [{when, kind, source, host,
url}]` with `kind` in the reference's `operator_kinds` (`post`, `message`, `panel_action`,
`login_event`, `manual_registration`, `commit_author`).

**Steps.**

1. **Select operator-chosen timestamps only.** Drop, with a recorded reason: certificates from
   automated issuers (ACME, Let's Encrypt, managed or AutoSSL), CT and passive-DNS observation
   windows, Wayback captures and spans, urlscan submissions, registrar-side WHOIS updates, page
   self-declared dates, our own collection time, bot committers, stamps at exactly 00:00:00
   (date-only precision — the hour is unknown, not midnight) and same-session bursts (events of
   one kind on one host within 10 minutes count once — one decision).
2. **Count.** Build an hour-of-day × weekday histogram in UTC.
3. **Abstain below the floor.** Fewer than 30 events, or fewer than 10 distinct days → status
   `insufficient`, no offsets reported.
4. **Scan offsets.** For every candidate UTC offset (−12 to +14, half- and quarter-hour zones
   included) score the share of events in the local working window (default Mon–Fri
   09:00–18:00) and in the after-hours window 23:00–06:00. Rank by working share; the offsets
   within 5 points of the best form the reported *consistent ranges*: contiguous runs of the
   qualifying **signed** offsets, not a numeric minimum-to-maximum envelope. Offsets a day apart
   share clock hours (for example UTC−12 and UTC+12) but not the local weekday, so they merge only
   when both qualify and their weekday scores agree; otherwise each keeps its own range and the
   other is reported as a calendar-day alias. The range holding the best-scoring offset is listed
   first; the rest follow as "also consistent". A non-qualifying alias is never printed. Thus
   02–06 UTC activity every day yields "UTC+7 to UTC+12" (also consistent: UTC−12, a calendar-day
   alias of UTC+12), and 40 Saturday-UTC events give UTC−12 to UTC−11, never UTC+12 or UTC+13.
   Best share under 50 % → `no_clear_window` (round-the-clock or irregular activity; no timezone lead).
5. **Look for a second rhythm.** Hours only: weekday and weekend are an attribute of each band
   (its non-workday share), never a band of their own, so a weekend event inside the primary
   hours is the same rhythm, not residue. For each candidate offset as primary, take the events
   outside its working *hours* on any day and find the working-window-wide band of hours holding
   most of them, among bands that start at least one window width (9 h) from the primary band's
   start — the two bands never overlap. Flag **two rhythms** when that band holds ≥ 60 % of those
   events and primary band plus second band cover at least max(10, 20 % of events) more than the
   best single window-wide band of hours (`two_rhythm_min_coverage_gain`).
   The second band's residue share must also exceed the uniform-clock baseline
   width / (24 − width), or 60 % for a 9-hour band: fitting two arbitrary windows onto uniform
   round-the-clock activity is not evidence of two rhythms.
   One band worked seven days a week is one rhythm. Give both readings: the primary zone's evenings and weekends, or a
   second zone's working day. In a bimodal set the best single offset is a blend that straddles
   both bands; the finding then leads with the pair, not the blend.

**Output.** In the timeline ledger as `operator_tempo`: status (`lead` | `no_clear_window` |
`insufficient`), histogram, top offsets with working / after-hours / non-workday shares,
consistent range, the two-rhythm block, exclusions by reason, declared author offsets from git
`.patch` `Date:` headers (the committer machine's TZ setting — a separate, easily changed lead),
confounders and the rail. It never feeds correlations, clustering, `operator_lead` or KB edges.

**Confounders (printed with every read).** Automation and schedulers (cron, CI, scheduled posts,
renewals — T-01 precision intervals are the tell); shift work and outsourcing; deliberate offsets
or VPN (a VPN moves location, not the clock); DST (a set spanning a change splits across adjacent
offsets); a mixed team; timestamps a platform sets from server, queue or rounded time; a regional
work week other than Mon–Fri; collection sampling (first/last commits, recent posts).

**Wording.** "Activity concentrates in a window consistent with UTC+N business hours — lead."
Quote the share, the event count, the day count and the consistent range. Never "the operator is
based in …", never a country from an offset alone (one offset spans many countries), and never a
same-operator claim because two estates share an offset — that is a common property of a time
zone, not an artifact.

**Keep consistent with posting-time analysis.** The after-hours window is the same 23:00–06:00
local definition used by `analysis/signature-catalog.md` **T-02 Off-Timezone Clustering**. Use
T-02 when the question is "does this account's posting fit its *claimed* zone?"; use the tempo
read when no zone is claimed and the question is "which zones would make this a working day?".
Both are leads; a T-02 mismatch and a tempo range that excludes the claimed zone are one
observation seen twice, not two independent signals.

**When to abstain.** Below the floor; when most kept events come from one source that a platform
stamps (server-time posts); when the kept set is dominated by one kind that could be scheduled
(T-01 fires on it); when the case spans a DST change and the consistent range straddles it —
report the range, not a single offset.

**Worked example (synthetic).** CASE-0002, actor label EXAMPLE-SPIDER, estate on
`portal.example.com` and `pay.example.org`. Inputs: 64 commit author times from one
`github_harvest` run, 11 channel post times supplied as `operator_events`, 3 manually ordered
certificates and 4 registrations. Dropped: 41 certificates from an ACME issuer, 96 Wayback
captures, 7 registrar WHOIS updates, 2 registrations stamped 00:00:00, 6 commits by a dependency
bot and 9 commits collapsed into same-session bursts. Kept: 68 events across 23 days.
Best offset UTC+2 holds 63 % of events in local Mon–Fri 09:00–18:00; UTC+1 and UTC+3 sit within 5
points, so the consistent range is UTC+1 to UTC+3. Of the 25 events outside those working hours
(on any day), 19 (76 %) fall in 17:00–02:00 UTC — 10 h from the primary band's 07:00 UTC start,
so the bands do not overlap — and the two bands hold 19 events more than the best single 9-hour
band of hours, against a floor of 13.6 (20 % of 68) — so two rhythms are flagged: either local
19:00–04:00 work in the primary zone, or a working day at UTC−8. The two `.patch` headers that
carry a declared offset both read `+0200`.

> *Finding (lead):* Activity concentrates in a window consistent with UTC+2 business hours (63 %
> of 68 operator-chosen events across 23 days; consistent range UTC+1 to UTC+3). A second rhythm
> (19 events, 17:00–02:00 UTC) fits either late-evening work in the same zone or UTC−8 business
> hours. Confounders: shift work, a mixed team, scheduled commits, DST. Not attribution; no KB
> edge; the bot and the ACME certificates were excluded.

Milestones that would move it: post times from a second platform landing in the same range
(supports); the second-rhythm events tracing to one CI account (automation, collapses the second
rhythm); a declared `.patch` offset that disagrees with the histogram (deliberate offset or
travel — record, do not resolve).

---

## Cross-references

- [`handbook/analytic-standards.md`](analytic-standards.md) — likelihood terms, ACH (Heuer's eight steps), bias checks
- [`workflows/wf-threat-analyst.md`](../workflows/wf-threat-analyst.md) — case phases, hunt phase and detection handoff
- [`handbook/aam-actor-modeling.md`](aam-actor-modeling.md) — next-move overlay built on the activity-attack graph
- [`handbook/report-template.md`](report-template.md) §12 — ATT&CK mapping table contract
- [`analysis/signature-catalog.md`](../analysis/signature-catalog.md) T-01, T-02 — scheduler precision and off-timezone posting; same after-hours window as §10
- `SKILL.md` → *Pivot priority ladder*, *Attribution rails* — rung table and owner-link classes
