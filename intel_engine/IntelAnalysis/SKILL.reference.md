---
name: IntelAnalysis
description: The analyst / judgment layer for OSINT — correlation, attribution, confidence calibration, and next-pivot decisions over the knowledge base. Does NOT collect; it reasons over facts collectors (WebPivot etc.) already gathered. USE WHEN correlate findings, attribute infrastructure, who is behind this, same operator/actor/owner, build the case, assess confidence, weigh evidence, cluster analysis, what to pivot on next, connect the dots, generate hypothesis, prove or disprove, NRD, bulletproof hosting, money trail, reused wallet, scam red flags, case timeline, registration/expiry dates, renewal pattern, same expiry, which IP hosted it when, hosting window, co-tenancy overlap, certificate issuance batch, registrant era, was this contemporaneous, campaign start and end, cite the evidence, archived link, urlscan link, stealer/infostealer log, leak corpus, breach dump, whose machine is this, operator's machine, credentials for the panel, admin panel URL from a log, IntelX hit, does this leak prove same operator.
---

> **OPSEC — this skill is portable/shared. Never write case data into it.** No real operator
> names, emails, domains, IPs, wallets, tracking IDs, hashes, or case IDs in this file, its
> workflows, tool code, or test fixtures. Investigation data lives only in the git-ignored
> `cases/` / `knowledge/` / `MEMORY/`. In examples use placeholders (`example.com`,
> `G-XXXXXXXXXX`, `CASE-0001`). See the repo-root `CLAUDE.md` for the full rule.

# IntelAnalysis — the analyst's brain

## 🎯 The GOAL — answer *who*, at the strongest level the evidence actually supports

**The purpose of the whole pipeline is to unmask the operator behind the infrastructure.**
Clustering is not the product; it is the step that assembles enough of one estate for an identity
to become visible. Every assessment must therefore answer, explicitly:

1. **Is it one operator?** — the cluster and the attribution-grade artifacts binding it.
2. **Who is that operator?** — the strongest honest rung on the ladder: a *named actor* → a
   *persona* (registrant / advertiser legal entity / dev account) → an *unnamed but characterised*
   operator (jurisdiction, language, hosting habits, working hours, kit provenance, payment rails).
3. **What would name them?** — if the answer to (2) is short of a name, the identity gap is a
   finding in its own right: state the single pivot most likely to close it and its cost.

"Unattributed" is an acceptable answer; **silence is not**. An assessment that lists clusters and
never states who — or why who is unknown — has not met the goal.

🚫 **And the goal never buys a shortcut.** The pressure to produce a name is exactly what
manufactures false attribution, so the rails in §2–§4 tighten rather than relax here: base-rate
the artifact, keep same-kit / same-operator / same-actor apart, treat every registrant identity as
a **persona** until an independent non-self-declared source corroborates it, and try to *break*
the identity hypothesis before publishing it. A wrong name burns a real person and is worse than
no name at all.

This is the **reasoning layer**, not a collector. Collectors (WebPivot, future
`osint-ip`/`osint-ioc`) gather attributed facts into `knowledge/`. IntelAnalysis reads
that store and applies **investigative judgment**: which facts matter, what they prove,
how confident to be, and what to chase next. It writes assessments; it does not fetch.

**Deterministic-first still holds.** Correlation math (dedup, shared-indicator detection,
clustering) is code — call `tools/kb/query.py` and `WebPivot/tools/graph_build.py`. Use
model reasoning only for the parts code can't do: weighing evidence, resolving conflicts,
forming and falsifying hypotheses, and deciding the next move. Run this skill on the
strongest model (Opus / Fable); the collectors run cheap.

## Running the tools — paths & working directory (read first)

Run every command below from the `intelligence_assist` **project root** (where `knowledge/`,
`cases/`, and `tools/` live). `tools/kb/query.py` and the KB store are project-root-relative —
they are not inside this skill folder, so `cd` to the project root first (`cd "$ROOT"`).

## Inputs / outputs

- **Reads:** the knowledge base.
  ```bash
  python3 tools/kb/query.py --kb knowledge --stats
  python3 tools/kb/query.py --kb knowledge --shared --min 2      # cluster seeds (start here)
  python3 tools/kb/query.py --kb knowledge --cluster <domain>    # peers of a domain
  python3 tools/kb/query.py --kb knowledge --entity <value>      # one entity, facts + edges + provenance
  ```
- **Writes (output contract — every assessment is persisted, not just spoken):**
  1. A cited assessment file at a **fixed path**: `cases/<case>/assessment.md`,
     following the §7 schema exactly (BLUF → Cluster table → Timeline → Attribution → Gaps &
     alternatives → Next steps), with every row cited to a time + source + online link (§7). Writing the assessment only into the chat is not "done" — save the file, then
     summarize it in the reply. Re-running an assessment overwrites the same path.

     > **`assessment.md` is YOURS; the machines write `loop_assessment.md`.** Both front-ends
     > re-render an assessment to that path — `tools/intel.py` every convergence round, and the
     > SDK path via `harness/render.py`. Each now overwrites **only output it recognises as its
     > own** (`tools/case_state.may_overwrite_assessment`) and diverts to `loop_assessment.md`
     > otherwise, so your file is safe. The one thing that breaks it: opening your assessment
     > with a renderer's own signature — `# Cluster Intelligence Assessment — `,
     > `# Intelligence Assessment — `, or a bare `# Assessment` followed by `**BLUF —**`. Use any
     > other heading (e.g. `# Assessment — <case>`) and you are fine.
  2. The **timeline of the case** — `IntelGraph/scripts/case_timeline.py` (or the `case_timeline`
     MCP tool) over `cases/<case>/out/*.json` → `cases/<case>/timeline{_hires.png,.svg,.md,
     _events.json}`. The ledger is the assessment's evidence table: every dated fact with its
     source and an **online** link (§1.5, §7). Run it before you write the cluster, not after —
     it is what tells you whether a shared indicator was shared *at the same time*.
  3. When your judgment changes a rating, the **updated confidence back into the store** (so the
     next run inherits it), keeping provenance.
  4. Optional but recommended: **invoke the `IntelGraph` skill** on the `case_graph.json` and drop
     the rendered `network.html` beside the report in `cases/<case>/`.

## Method

```
Triage facts → Time-order them (lifecycle, hosting windows, expiry) → Correlate into clusters
   → Attribute (same-kit vs same-operator vs same-actor) → Calibrate confidence
   → NAME THE OPERATOR at the strongest honest rung (actor → persona → characterised-but-unnamed)
   → Form & falsify hypotheses → Prioritise the pivots that would close the IDENTITY gap
   → Write the assessment
   → Capture what it taught (register the operator + any new tell) so the next case starts ahead
```

**Before you start, load your priors + check what you already know.**
- Read `knowledge/analyst_profile.md` (your standing brief — thresholds, tells, house style; see
  `Workflows/AnalystProfile.md` to set it up and to feed in past reports with `ingest_report.py`).
- `intel.py open` prints a **prior-knowledge overlap** block after ingest — which seeds already
  connect to previously-seen domains and to any confirmed operator in `knowledge/operators.jsonl`.
  A `⚠ CONFIRMED-OPERATOR MATCH` means this isn't a new investigation, it's an extension of a closed
  one. Look up any domain with `python3 tools/kb/operator_registry.py find <domain>`.
- It also prints **scam red-flags** per seed (NRD / bulletproof-hosting / money-trail — see below and
  `references/RiskIndicators.md`). Run `python3 tools/kb/risk_signals.py --case <case>` anytime.

**Generate hypotheses, then break them.** `python3 tools/kb/hypothesize.py --kb knowledge --min 2`
turns the KB into falsifiable operator hypotheses — each with the disconfirming check and the open
questions to answer. It clusters ONLY on attribution-grade identity artifacts (same-operator ≠
same-kit) and drops proxy/high-fan-out noise. Full loop: `Workflows/Hypothesis.md`.

**When you finish, close the loop (`Workflows/Learn.md`).** Record the operator you assessed to the
registry and append any reusable tell to the "Captured (in-case)" blocks below — this is the
difference between a KB that grows and one that just accumulates.

---

## 0. Opening a case — first moves  ▢ TUNE  (in-case notes)

**Collect broad BEFORE you theorize.** The opening pass is deliberately maximal — get the
widest concrete footprint first, because the domain that looks central often isn't.

1. **Bulk-collect the whole set; don't narrow early.** Run WebPivot artifact extraction +
   WHOIS (current **and** history) + a page capture across *every* seed domain at once.
   Gather more than you think you need — correlation comes after collection, not during.
2. **Start from the seed / initial domain** — the one closest to the case origin (the tip
   that opened the case). Read it first, but do **not** assume it's the hub; the real broker
   is often a sibling (betweenness centrality tells you which, later).
3. **Read the naming pattern by eye** before tooling — brand families, TLD rotation,
   transliteration tells — to pre-guess sub-groups.
4. **Anchor on the registrant email / identity.** The email that registered the domains is
   the most concrete glue — build the spine from WHOIS (recover it from *history* when the
   current record is privacy-masked), then hang artifacts off that spine.
5. **Prioritise artifacts that are UNIQUE to the site or its paid services**, most-concrete first:
   registrant email/name → owner-account tokens (GA4/GTM, SEO/ads UUIDs, ahrefs/GSC/Bing) →
   **origin IP** (true backend, *not* the shared CDN/hosting edge — see §1) → on-page DOM
   artifacts the operator uses to get paid/contacted (phone, Zalo/Messenger, email, distinctive
   page schema/template), any comments that are unique to the build, and finally the favicon hash (stronger if it's a niche/custom kit). also check for a reused crypto wallet address (e.g. BTC, ETH, USDT) — if it's reused across sites, it's a strong same-operator artifact. Some typo of the website name in the domain name is also a medium signal of same-operator.
6. **Acquire by hostility.** Passive-first (Wayback / urlscan / crt.sh) for clearly adversarial
   targets; live fetch from a safe egress for low-risk ones. Judge per target, not one rule.

Executable recipe: `Workflows/OpenCase.md`.

## 1. Artifact triage ladder  ▢ TUNE WITH YOUR EXPERIENCE

Not all shared artifacts are equal. Rank every shared indicator before you reason about it.
Seeded from cases so far — **edit the tiers as you learn**:

| Tier | Weight | Artifacts | Why |
|---|---|---|---|
| **Money-trail** | high | **reused crypto wallet** (btc/eth/usdt/tron), payment-processor/merchant id, registrant/on-page **phone**, contact **email**, IBAN/SWIFT | how the operator gets *paid* and *contacted* — the crucial category for loss/LE/takedown. A reused wallet = the same payee (attribution-grade). Now KB edges: `uses_wallet`, `shows_email`. See `references/RiskIndicators.md` |
| **Attribution-grade** | high | registrant email/name, GA4/GTM property, ahrefs/GSC verification token, favicon hash on a *niche/custom* kit, reused crypto wallet | private, owner-controlled — a stranger can't share these by accident |
| **Corroborating** | medium | Messenger/contact handle, phone, distinctive template/DOM-skeleton hash, self-hosted third-party host | meaningful with ≥1 attribution-grade artifact; weak alone |
| **Noise** | low / drop | Cloudflare name servers, generic registrar (GoDaddy/Porkbun), shared CDN host, common favicon (WordPress default), `googletagmanager.com` | shared by millions; near-zero attribution value — keep for completeness, never assert on |

**Infrastructure red-flags (raise the scam prior, not attribution):** `risk_signals.py` scores each
host for **NRD** (newly-registered — young + shared kit = one batch/operator), **bulletproof/abuse-
tolerant hosting** (registrar/NS/host match — a lead, verify origin IP vs CDN first), and the
**money-trail** above. A young unbranded site with a wallet + a Telegram/WhatsApp handle is the
archetypal payment funnel — `escalate`. Tunable lists: `references/risk_indicators.json`.

**Tells learned in-case (keep adding yours):**
- **Sequential GA/UA account numbers** = one operator batch-provisioned them in a sitting.
  A tight block like `UA-100000001` … `UA-100000009` across sibling sites is strong same-operator.
- **Shared WordPress theme** (e.g. `flatsome`) = weak-medium same-kit; **identical inline-CSS
  block or DOM-skeleton hash** across sites = stronger (same build, not just same theme).
- **Reverse-WHOIS count is a filter:** a registrant tied to a handful of thematically-coherent
  domains = attribution-grade; one tied to hundreds/thousands of unrelated domains = a shared
  reseller/agency = NOISE. Enforced by `tools/kb/ingest_reverse_whois.py --max-domains`. Reverse by
  **email**, **name**, or **phone** (`--email/--name/--phone`; `reverse_whois` MCP `kind=phone`) —
  all **preview the count first** and refuse to purchase/link a > `--max-domains` set without an
  explicit override (a registrant *phone* is especially prone to registrar-bulk noise, e.g. Dynadot).
- **Registrar/proxy contacts** (`abuse@`, `admin@onamae.com`, `registrar@inet.vn`, Domains-By-Proxy)
  and placeholder registrants ("domain expired", "Domain Admin C/O ID#…") are never the owner.
- **Origin IP ≠ hosting/CDN IP.** A shared *origin/backend* IP — a real server both
  sites resolve to, or an origin leaked from behind Cloudflare — is **attribution-grade infra**.
  A shared *edge/CDN/shared-host* IP (Cloudflare `104.21.x` / `172.67.x`, shared cPanel host) is
  **NOISE** — millions share it. Always resolve which kind before treating a shared IP as a link.
  *Enforced:* `WebPivot/tools/cdn_ranges.py` fetches published CDN/cloud ranges (Cloudflare,
  Fastly, AWS CloudFront, Google, BunnyCDN) and classifies each IP; `graph_build.py` drops
  CDN IPs and tags the rest `origin_candidate`. Run `cdn_ranges.py --update` to refresh ranges.
  Gap: CDNs with no public list (Akamai, Imperva) need ASN classification — see the tool's
  `NO_PUBLIC_LIST`.

▢ **Your rules:** _how you treat a GA4 ID that appears on 200 domains (link farm vs shared SEO agency); when a favicon is "niche" vs "off-the-shelf"; TLD-rotation patterns you've seen; Vietnamese-market registrar tells (Mat Bao, PA Vietnam, iNET)…_

**Captured (in-case — edit freely):**
- **Sequential handle aliases = one person.** `alias1@ / alias5@ / alias20@example.com` is one identity, not three. Normalize `name+<n>@` families to a single actor before counting.
- **A thematically-coherent registrant is attribution-grade even under privacy.** A single registrant name recurring across a thematically-coherent brand family (e.g. one seller's product-line domains) holds even when *current* WHOIS is a privacy proxy — recover it from WHOIS **history** (pre-privacy record), don't stop at the masked current record.
- **Mis-parsed / ad-network indicators are noise — drop, never assert.** `g-recaptcha` captured as a GA4 `G-` id (parser artifact); an AdSense `pub-…` or GA id shared across 80–100+ thematically-unrelated shops = a shared ad/SEO network, not one owner. (Same class as the reverse-WHOIS >200-domain reseller filter.)
- **Build fingerprints beat theme names.** A shared `wp_theme:<name>` is weak same-kit; an identical **HTML-comment hash / inline-CSS hash / DOM-skeleton** across sites is strong same-build — and reaches domains outside the seed list (a single HTML-comment fingerprint can span dozens of sites beyond the seed list).
- **Same WHOIS registration/expiry date = one batch, one actor.** Exact-same creation date (and the matching expiry, since expiry = created + term) across thematically-coherent domains means they were registered in one sitting by the same person — same class as sequential GA/UA numbers. Corroborating→same-operator; strongest with same registrar + a small coherent set, down-weight a huge set or a registrar bulk-promo default. In-case pattern: two thematically-related domains sharing one creation date (a 2nd signal beyond a shared phone); two brand-family domains sharing another creation date (bridging two sub-families). *Enforced:* `graph_build.py` models `regdate:<YYYY-MM-DD>` as a hub (day precision).
- **Privacy-word matching does NOT catch role placeholders — they need their own exact list.** The privacy filter screens registrant names for privacy-signalling *words* ("privacy", "redacted", "withheld"). A generic ROLE placeholder such as `Domain Admin` contains none of them, so it survived and became a **high-confidence `registered_by → person` edge**, merging every unrelated domain whose registrar emitted the same string. The doctrine above ("placeholder registrants are never the owner") was already written here — the *code* didn't enforce it. Watch for this class of gap generally: a documented rule with no test is not an enforced rule. *Enforced now:* `_is_role_placeholder()` in `ingest_webpivot.py` (exact match on a normalised form — never substring, or legitimate orgs like "Admin Solutions GmbH" get eaten), the same guard in `clean_kb.py` for pre-existing edges, and `tests/test_indicator_classification.py` covering both directions.
- **The population count IS the finding — count before you cluster.** For any shared tenant-style indicator (affiliate/partner marker, analytics or verification token, co-tenancy IP, developer footer credit), the number of *other* hosts carrying it decides its tier, and often decides it against you. A count of ~1 asserts nothing cross-domain, however "attribution-grade" the indicator type is. A count of 30 thematically-scattered co-tenants doesn't weaken the IP pivot, it **kills** it — and that negative is worth recording, because it stops the next analyst re-deriving it.
- **When vendor docs don't state an indicator's scope, establish it empirically.** Docs frequently won't say whether a verification/tenant token is per-account or per-domain — which is the difference between a decisive cross-domain link and no link at all. Settle it with a collision test: harvest a corpus of `(apex, token)` pairs and look for one token on two unrelated apexes. Two distinct apexes sharing an identical token proves account-level issuance. Don't assume the strong reading.
- **A zero is only a zero if a control query proves the collector was working.** Two separate false negatives nearly landed in one case: a credential read from the wrong path made every reverse-WHOIS call return "no key" (renders identically to "no pivot exists"), and empty SERP keys produced a page of authentic-looking zero rows. **Validate every consequential zero against a control term with a known non-zero answer**, and label blocked sources BLOCKED, never EMPTY. An unvalidated zero is a fabricated finding.

### Base-rate a CONFIGURATION before you call it a fingerprint  ▢ TUNE

The bullet above counts *tenant* indicators. This one covers the class that fools analysts more
often, because it feels technical enough to be evidence: an **infrastructure configuration** —
a non-standard port, a protocol on an odd port, a service/banner combination, a software version
string, a control panel, a TLS-stack/JARM hash, a naming scheme across a set of domains.

**The rule: never promote a configuration pattern to an operator fingerprint until you have
counted how many hosts on the internet share it.** It is one query. Skipping it is the standard
way a *hosting-provider default* gets written up as tradecraft — providers image thousands of
VPSes identically, so "unusual" and "rare" are not the same thing. An admin port that looks
distinctive on one box can be the provider's stock image on 3,000.

**Count it twice — the two counts answer different questions:**

| Count | Question it answers |
|---|---|
| **Globally** (`port="…"`, `protocol="…"`, banner, JARM) | is this a world-wide default? |
| **Scoped to the host's own ASN / provider** | is this *that provider's* image default? |

Both must be small. A pattern can be genuinely rare globally and still be universal inside the
one provider your target rents from — which kills it just as dead, because every neighbour has it
by accident of billing, not by choice of operator. Also sanity-check the denominator: a count that
is a small *share* of a huge ASN can still be far too many hosts to mean anything.

**The same count means opposite things depending on who you think you are chasing. State your
actor hypothesis before you interpret it:**

| Actor model | How they treat host config | So a shared config means | Prior |
|---|---|---|---|
| **APT / espionage / mercenary spyware** | rents commodity VPS, leaves provider defaults alone; the tradecraft investment goes into the **payload**, not the hosting | **probably a false positive.** These operators are small — a handful of hosts. A config shared with hundreds or thousands is the provider, not the actor. Only a *tiny* (single- to low-double-digit) and thematically-coherent population is a real link | assume noise until the count is small |
| **Scam compound / mass-fraud / kit-as-a-service** | **mass-deploys** — one golden image, one panel, one port set, one naming scheme, rolled out across the whole estate as an operational necessity | **plausibly the operator.** A large population is expected here and does not by itself refute the link. But volume alone still isn't proof | a high count is *permissible* — test coherence, don't just count |

For the mass-deploy case the count stops being the decider and **coherence** takes over: do the
members share naming semantics, registrar, registration/expiry rhythm, certificate issuance
batching, content kit or victim theme? A coherent 300 is an estate. An incoherent 300 is a
provider's customer list. Never let "they mass-apply config" become a licence to skip the check —
it changes the threshold, not the requirement.

**Record the negative.** "Configuration X appears on N hosts, dominated by provider P, therefore
rejected as a pivot" belongs in the assessment. It is what stops the next analyst — or you, in six
weeks — re-deriving the same dead end and spending metered credits reversing it.

*Counting it:* FOFA is usually the cheapest census (`port="…" && protocol="…"`, then repeat with
`&& asn="…"`); Censys `search` answers the same question but is Starter+ and returns 403 on the
free plan, so don't budget credits for it (see `WebPivot/tools/wp_censys.py`). Fetch the total
match count with `size=1` — you want the denominator, not the rows.

## 1.5 Temporal analysis — lifecycle, hosting windows & expiry consistency  ▢ TUNE

**Every artifact has a time, and a link that is not contemporaneous is not a link.** The triage
ladder above tells you how *private* an artifact is; this section tells you whether the two sides
actually held it **at the same time**. Two domains on one IP in windows that never overlap is a
recycled address. A tracker id on site A in 2023 and site B in 2026 is a resold kit. Run the
timeline before you write the cluster — the tool is `IntelGraph/scripts/case_timeline.py`
(`case_timeline` MCP tool); the executable recipe is `Workflows/Timeline.md`.

**The rule that governs the rest of this section:** for every shared indicator, write down the
window it was observed in **on each host**, then state the overlap. "Shared" without an overlap is
a hypothesis about the past, not an observation.

### The five clocks of a domain

| Clock | Source | What it dates |
|---|---|---|
| **Registration** | RDAP / WHOIS `created`, `expires`, `updated` | when the name was bought, until when it is paid for, when the record last changed |
| **Registrant era** | WHOIS **history** | which persona held it between which dates — handovers, privacy switches |
| **Hosting** | passive DNS `time_first`/`time_last`, urlscan scans, live DNS | which IP served it, and between which dates |
| **Certificate** | CT logs (`not_before`/`not_after`), live TLS | when the hostname was provisioned, and by which issuance run |
| **Content** | Wayback captures, page self-declared dates | when it was parked / live / re-skinned, and when the payment artifact appeared |

The clocks disagree, and the disagreement is informative: a **cert (or a first Wayback capture)
that predates the site going live** is pre-staging; content that changes with no registration or
hosting change is a re-skin by the same operator; hosting that changes with no content change is
a migration. Say which clock you are citing — "registered 2024-05" and "first seen 2024-11" are
different claims and only one of them is a birth date.

### Expiry consistency — the billing tell

Registration dates are *set by the operator once*. **Renewals are a repeated, voluntary payment**,
which is why the expiry/renewal pattern is often a better owner signal than the creation date:

- **Same expiry date reached from DIFFERENT creation dates = one payer.** Someone deliberately
  aligned the renewals (or bought the set in one basket on one card). This is a second, independent
  signal. **Same expiry because the domains share a creation date and term is the registration
  cohort restated — do not count it twice**; that is one fact wearing two hats.
- **Renewal in lockstep.** `updated` bumping and `expires` jumping by one term on the same day
  across a set = one auto-renew batch on one payment instrument. Watch this across *years*: a set
  that renews together twice is far stronger than a set that renews together once.
- **Abandonment cohorts date the END of the campaign.** Domains whose expiry passes unrenewed
  within days of each other = one payer stopped paying. This is as attributive as a registration
  batch, and it tells a takedown/LE audience when the operation actually wound down. A **single**
  domain in a dead cluster still being renewed is the interesting one — someone is still paying.
- **Term length is a budget decision.** An unusual term (5y/10y) shared across a set, or a
  deliberate prepaid renewal right after a takedown of a sibling, are both operator choices.
- **The discounts.** A registrar bulk promo, a default 1-year term, and registrar-forced renewal
  windows manufacture coincidences. Before asserting: are the registrars the same (weaker — the
  registrar may explain it) or different (stronger — only the owner explains it)? Is the cohort
  small and thematically coherent, or does the same date cover thousands of that registrar's book?
- **`updated` cohorts have the same trap in reverse.** Same-day WHOIS updates across **different**
  registrars is an operator action (an NS move, a privacy toggle across the fleet). Across **one**
  registrar it is more likely a registrar-side event — DNSSEC rollout, system migration, bulk
  privacy change. Discount it.

### Hosting windows — co-tenancy is an overlap claim

- **A shared IP means nothing until the windows overlap.** State the overlap interval and its
  length. Sequential tenancy (A leaves, B arrives) is the normal behaviour of recycled hosting
  address space and is *not* evidence of a common operator.
- **Synchronised migration beats static co-tenancy.** Several domains moving from IP1 to IP2
  inside the same short window is one admin moving a fleet — a stronger, harder-to-fake signal
  than sitting on the same box, because shared hosting puts strangers on one box every day.
- The §1 CDN rule still applies *on top of* this: an overlap on a Cloudflare/CDN edge or a shared
  cPanel host is noise however perfect the overlap. Classify the IP first, then check the window.
- **Passive DNS coverage is uneven.** `time_first` is when the *sensor* first saw it, never when
  the record was created; a gap may be a sensor gap. Corroborate a window with a second source
  (urlscan scan of that day, a Wayback capture, a cert) before you build on it.

### Certificate rhythm

- **Certs issued within minutes/hours of each other across hosts = one provisioning run** on one
  machine (an ACME batch). Corroborating, and strong when the issuer and the profile match — but a
  shared CA with 90-day auto-renewal syncs *unrelated* sites too, so check that the issuance
  window is tight, not merely the same day.
- **A cert whose SANs cover several case domains is attribution-grade AND dates the link
  precisely** — those names were on one host at that moment.
- **The first CT entry is the best public birth date for a hostname**, usually earlier than the
  first web capture, and it exposes staging subdomains that never got crawled.
- **A cert chain that stops renewing dates the host going dark** — often the cleanest end-date
  you will get for infrastructure that was never archived.

### Sequence-of-events reasoning

Order is evidence. Two readings worth building the narrative around:

- **Successor infrastructure.** A domain registered days after a seizure, takedown, ban or
  enforcement action against a sibling is a continuity move — date both events and put them in
  one sentence.
- **Falsification by impossibility.** If a claimed link requires an artifact to exist before the
  thing that produced it — a token minted after the domain lapsed, a wallet first transacting
  after the site went dark, a persona era that ended before the artifact appeared — the link is
  dead regardless of how private the artifact is. This is the cheapest disconfirmation you have
  (§4): check the dates before spending a credit.

### Recency — never write a stale fact in the present tense

A dated observation supports a present-tense sentence only while it is fresh (the thresholds live
in `IntelGraph/references/evidence_sources.json` → `staleness`, default 30 days). Past that,
write "as of `<date>`". "Hosted at `<ip>`" from a two-year-old passive-DNS record is a false
statement about today, and it is the single easiest way to put a wrong IP in a takedown request.

**Captured (in-case — edit freely):**
- **Date the artifact, not just the host.** When a shared artifact is recovered from an archive
  rather than the live page, its observation date is the **capture** date. A cluster built from
  one live page and one 2019 snapshot is a cluster across seven years — say so, or don't assert.
- **A registration-batch claim needs the registrar count, not just the date.** Same-day creation
  at one registrar is one plausible bulk purchase; same-day creation across *different* registrars
  is a deliberate distribution and a much stronger operator signal.

## 1.6 Victim profiling — when the hostname isn't the operator's  ▢ TUNE

**If the operator is serving from a name they do not own, the victims are evidence.** Hijacked
subdomains, compromised CMS installs and dangling records all mean the operator had to *obtain*
each hostname. The victim set is therefore a sample of their **capability**, and profiling it
answers a question infrastructure analysis cannot:

> To get these hostnames, what did the operator have to be able to do — and did they do it
> themselves, or buy it?

Run this whenever a seed's apex is a legitimate business whose own records are intact. Tool:
`tools/kb/victim_profile.py` (`victim_profile` MCP tool); recipe: `Workflows/VictimProfile.md`.

### Profile the victim, not just the attacker

For every victim apex, record what the **legitimate** side looks like: DNS operator (the account
that had to be written into), registrar, hosting ASN, control panel, CMS, MX provider, country /
TLD, business sector, domain age, and *when* the hijacked label first appeared. Then read the
distribution across victims — the shape names the vector:

| Victim set shape | Access vector it supports | What to chase next |
|---|---|---|
| Nearly all at **one provider** (not a hyperscaler) | That provider is breached, or an insider | The provider's own incident response |
| One **control panel** across **many** providers | Panel exploit / default credentials | The panel's **version banner** — a version-locked set is near proof |
| One **CMS or plugin** across many providers | CMS/plugin vulnerability | The plugin version; compare against the sector base rate |
| A small **DNS operator / agency** + one country or sector | A reseller, web agency or IT contractor was compromised | Who administers all of them |
| **Nothing technical in common** | **Stolen or purchased credentials** | Infostealer corpora; onset clustering |

### Dispersion is a finding

A victim set with no shared platform reads like a failed analysis — "no pattern". It is the
opposite. **A credential list has no technical common factor**, because it was assembled by
infostealer malware across whatever machines happened to be infected, or sold as an
access-broker lot. Dispersion across providers, countries, panels and sectors *is* the signature.
State it positively: *"the absence of a shared platform across N providers in M countries is
itself the evidence — this is a credential supply, not an exploit."*

### Base rates before you believe a concentration

A dimension whose dominant value is the world's default tells you nothing. **cPanel** on most
shared hosting and **WordPress** on ~40% of the web will both look "concentrated" in any victim
set you assemble, related or not. Before reporting a concentration, ask what share you would
expect from a random draw of small-business domains. Promote it only with a shared **version** or
a specific vulnerable component; otherwise label it a base-rate artifact. A concentration on a
*minority* platform (Plesk, DirectAdmin, CyberPanel, a regional host) is worth far more than the
same percentage on the default.

### Demographics — country and sector say whether the list was SELECTED

The platform dimensions tell you *how* they got in. **Country and sector tell you whether the
victim list was chosen or merely inherited** — and that is a different question with a different
answer. Read the two together:

| | **Providers concentrated** | **Providers dispersed** |
|---|---|---|
| **Country concentrated** | a **regional host / national reseller** was compromised — notify it directly, it is the shortest path to victims you have not found | a **region-selected list**, or a lure that needs one language — check whether the impersonated brand is national |
| **Country dispersed** | *(rare — re-check your provider grouping)* | **indiscriminate dump** — worked through in whatever order it arrived |

A **sector** concentration cutting across countries points somewhere else again: vertical software
(a sector-specific CMS or booking platform) or a list bought by industry.

**Get the country from the victim, not from their server.** Source order is WHOIS **registrant
country** first (where the business is — the thing we actually want), then the **ccTLD** when it
is a real country code. **Hosting country must never be counted.** Small businesses host abroad
constantly, so hosting measures where the victim's *provider* is: a Cloudflare-fronted victim set
reads as American, and a set of foreign SMBs on one British reseller reads as British. Keep it as a
displayed hint only.

Two more traps. A two-letter TLD is **not** automatically a country — `.io`, `.co`, `.me`, `.ai`
and friends are sold globally, and counting them invents clusters. And a country reached by WHOIS
(`SLOVAKIA`) and by ccTLD (`SK`) must be **normalised to one value**, or a single country splits
in half and the concentration disappears.

**Sector will often be thin, and that is fine — say so.** We derive it from the domain name and
the WHOIS registrant organisation, because we will not fetch the victim's own homepage. When it
resolves for under half the set, report *"coverage too low to read"* rather than treating a
2-of-13 sample as a pattern.

**Look for regional sub-clusters even when the overall verdict is dispersion.** A country + small
provider grouping can hide inside a set that is dispersed overall, and it is often the most
actionable thing in the case: it names one provider who can find the victims you have not.

Country also has a purely operational use: it names the **national CERT/CSIRT** to notify.

### Onset timing separates a dump from a drip

Date each hijack (first CT issuance for the label is usually the tightest bound; the added DNS
record is rarely dateable). Compressed onset across many victims = **one bulk credential dump
being worked through**. A steady spread over months = **ongoing access**, a drip-fed broker
relationship, or a re-usable exploit. Same victim set, different remediation urgency.

### Why this changes the recommendation

Get the vector wrong and the advice is wrong. A panel exploit is fixed by a vendor patch; a
provider breach by that provider; a **credential supply is fixed only by per-victim resets** — and
until those happen, taking down the page accomplishes close to nothing, because the operator
moves to the next name on the list. **Say which of these you are recommending, and why the victim
shape supports it.**

**Two discipline notes.** (1) The victims are **not the target** — never scan or probe them.
Everything here comes from public DNS and records you already hold; the panel is identified from
the subdomains a panel creates in its *own customer's* zone. (2) A domain the operator
**registered themselves** has no victim; counting it inflates provider diversity and corrupts
every concentration. Exclude it explicitly — the tool cannot tell, only you can.

▢ **Your thresholds:** _how many victims you need before you'll call a shape; which platforms you
treat as base-rate noise in your region; whether you fold victim-side findings into the operator
assessment or report them separately to the hosting providers._

## 1.65 Path-routed estates — when the hostname is packaging  ▢ TUNE

**If every host in a set looks disposable but every page looks branded, stop clustering on hosts.**

A mature kit operator knows what we pivot on. Their counter is to make the hostname carry no
information: numeric or random labels on cheap TLDs, a fresh certificate each, registered in small
batches, rotated on a schedule. What they *cannot* make disposable is their own routing — so the
brand a victim sees is selected by the **URL path**:

    host-a/<kit-x>/     host-b/<kit-x>/     host-c/<kit-y>/

### Recognising it

Any two of these mean you are probably looking at one estate, not several cases:

- hostnames that carry **no semantics** (digits, random strings) while the *pages* impersonate
  named brands — the meaning moved out of the name and into the path;
- the **same path directory on hosts that share nothing else** — no registrant, no certificate, no
  favicon, no ASN;
- **one host serving several unrelated brands** at different paths (the mirror image, and equally
  diagnostic — one back end, many storefronts);
- host-level artifacts that are all *unique per host* while the page-level artifacts (DOM skeleton,
  CSS, bundle hashes) are **identical**.

### What it changes

1. **The unit of investigation is `host + path`, not host.** Two paths on one host can be two
   different kits with different victims, targets and takedown routes. Collapsing them to the host
   averages away the distinction.
2. **The kit directory is your best collection pivot**, because it is the artifact that survives
   the rotation. Hunt it in the indexes that store full URLs — urlscan `page.url`, an `inurl:`
   dork, FOFA, a Wayback CDX sweep across *any* host. That is how you find the next host **before**
   it is reported.
3. **Count hosts, not sightings.** One kit seen 40 times on one host is one host. The finding is
   *N distinct hosts*, and N is what you report.

### The limit — say it out loud

🚫 **A shared kit directory is SAME-KIT evidence, not same-operator.** Two resellers of one
purchased kit have the same directory names, exactly as two tenants of a white-label platform share
its artifacts (§2). It is a strong lead and a legitimate pivot; it becomes attribution only when an
**independent artifact class agrees** — registrant, hosting window, tracker, wallet, or the
back-office evidence from §1.7.

🚫 **And base-rate it first (§1 *Base-rate a CONFIGURATION*).** `/login`, `/assets`, `/api/v1`,
`/wp-admin` are on every site alive. The tooling denylists them and emits nothing, but the
discipline is yours: before you treat a path as a fingerprint, ask how many unrelated sites use
that exact word. If the answer is "millions", it is a convention, not a campaign.

Tools: `wp_paths.py analyze` / `patterns` (`url_paths` MCP tool) — and the raw capture
(`wp_capture.py`, automatic with `--case`) is what lets you compare two hosts' actual DOM/JS/CSS
bytes rather than two summaries of them.

## 1.67 Paid traffic — the advertiser is a payer, and the page may be lying to you  ▢ TUNE

**If the operator buys ads, two things become available that no other layer gives you: an identity
that was verified against documents, and a reason to distrust the page you just collected.**

### The page you collected may be the decoy

A kit that pays for clicks can gate on the arrival. Present the campaign's `utm` set and a `gclid`
and it serves the scam; arrive without them — directly, from a crawler, from Google's own reviewer
on an unexpected referrer — and it serves something harmless. **The collection does not fail. It
succeeds on the wrong page**, and every artifact in the result — favicon, DOM skeleton, wallets,
contacts — describes the decoy. This is the one failure mode in this skill where a *clean* result is
the alarming one.

Suspect it when the seed came from an **advertisement, a victim's browser history, a stealer log or
a takedown report** (all of which carry the click parameters), when the page is **implausibly thin
for a domain that is paying for traffic** (nobody buys clicks to a parked page), or when the page's
own code contradicts what it renders — an `AW-` conversion id, an analytics container or a funnel
route table sitting behind a "coming soon" screen.

Read the probe's verdict literally:

| Verdict | What it licenses you to say |
|---|---|
| `divergent` | **Click-keyed cloaking observed.** Re-collect from `unlock_url` and treat the earlier artifacts as void. The evasion itself is a finding — serving reviewers one page and victims another is deliberate, and it speaks to intent, not identity. |
| `identical` | No click-keyed cloaking **on this URL, today**. It does not exclude cloaking keyed on geography, ASN, device, time or a server-validated click id — say which you tested. |
| `dynamic` | An ordinary live page. Not a finding. |
| `inconclusive_unstable` | The page differs between two *identical* requests, so nothing can be attributed to the click. Re-probe from a stable path or compare captured evidence bundles. **Never write this up as evasion.** |
| `inconclusive` | A view could not be fetched, **or an anti-bot wall answered instead of the page** (`challenge_detected`). Neither view is what a victim sees, so nothing can be compared — and the wall is the *host's* defence, never the operator's evasion. Re-probe through a proxy. Silence is not exoneration. |

### The advertiser is the strongest identity artifact here

To spend money on Google the operator passed **identity verification**, and the Ads Transparency
Center publishes the result — an `advertiser_id`, the legal name the ads are *funded by*, and the
domains that account pointed at. Two consequences worth stating in an assessment:

1. **It is a same-PAYER link, not a same-template one.** Money is harder to share than code. A
   shared advertiser account outranks a shared favicon or a shared kit directory, because a second
   operator cannot copy it off the first — they would have to be inside the billing.
2. **It outlives the infrastructure.** Registrations, certificates and hosts rotate weekly; the ad
   account does not, because re-verifying one is slow and the budget lives in the old one. When the
   domain-level trail goes cold, this is often the only line still running.

The *funded by* name is the under-used half: it is a name checked against documents, so it is the
string to run through the corporate registry of the stated country and through reverse-WHOIS — one
of the few places a real-world identity and the infrastructure can be made to meet.

### The limits — say them out loud

🚫 **An agency-shaped advertiser is not an operator.** A media buyer or affiliate network advertises
for many unrelated clients from one account. When the account points at many distinct domains, what
you have proven is that **one buyer bought traffic for all of them** — which may be a vendor, not a
principal. The tooling drops those to leads at
`serpapi.json → clustering_policy.agency_domain_threshold`; the judgement is still yours, and the
tell is whether the domains form a coherent campaign (§2) or an unrelated portfolio.

🚫 **A click id is never a pivot.** `gclid` / `fbclid` / `msclkid` are unique per click. They prove
the visit was **paid traffic** and nothing about who.

🚫 **`utm_source=google` is not a fingerprint** — base-rate it (§1). An operator-chosen
`utm_campaign` is same-CAMPAIGN evidence, in the same class as a shared kit directory (§1.65).

🚫 **Two domains bidding on the same keyword are competitors.** Co-appearance in a sponsored block
is target-selection evidence about the brand being abused, never a link between the bidders.

🚫 **A keyless run never queried the archive.** "No advertiser found" then means *nobody asked*.
Check `meta.capability` before writing a negative.

### What the archive reliably gives you, and what it does not

Opening a creative reliably returns **`ad_funded_by`** — the legal entity, not the display name —
and the **markets the ad ran in, each with its own last-shown date**. Use both: the entity name is
the registry query, and the market list tells you who was being targeted and until when, which is
dated evidence you can put on a timeline (§1.5).

It does **not** reliably return the ad's destination URL — Google's archive commonly stores a text
ad as a rendered image with no link — so do not build a plan around recovering the operator's own
`utm` set that way. When you need the real parameters, take them from a URL you already hold: a
takedown report, a victim's browser history, a stealer log (§1.7). The probe works without them.

The live sponsored-block lookup is **best-effort**; Google withholds it from automated clients often
enough that an empty result carries no information. Never write "nobody is advertising against this
brand" from it.

Tools: `wp_serp.py advertiser` / `creatives` / `cloak` / `serp` (`serp_ads` MCP tool), and
`pivot_extract --serp --serp-region <market>` — the archive is queried **per region**, so a campaign
aimed at one country returns nothing from the default.

## 1.7 Leak-corpus analysis — read the logs, skim the dumps  ▢ TUNE

Every other layer tells you what the operator **published**. The leak corpus (IntelX) tells you what
**leaked out from behind it** — and one bucket in it is different in kind from all the others.

### The two corpora are not the same evidence

| | **Public breach dump** | **Infostealer log** |
|---|---|---|
| What one hit is | one site's user table — an address in a row | **one machine at one moment** |
| What it proves | this address existed somewhere, some year | this **host** held these credentials on this **date** |
| Freshness | recycled through combolists for years | dated to the infection |
| What it reveals | nothing the address didn't already say | the **URL/user/password triple with session context**, cookies, autofill, and the machine's own identity |
| Analytic use | **a date, and only a date** | **admin/panel URLs the public site never links** — and sometimes the operator's own box |

So the order of work is fixed: **read the logs item by item; skim the dumps for the date and move
on.** Inverting it is the classic way to spend an afternoon on a combolist and never open the one
record that mattered. The tooling enforces this at the *retrieval* layer — `wp_intelx.search()`
queries `leaks.logs` in its own pass before the general one, because IntelX returns a bounded page
and the recycled rows will otherwise fill it (see WebPivot § *Intelligence X*).

### Pivot the DOMAIN, not just the contacts

A stealer log is indexed by **the URL the malware captured**. That makes the case domain a
first-class selector: searching it returns *the machines that held credentials for it*. Three
distinct products, in ascending order of value:

1. **Victim machines** — customers phished by the site. Feeds §1.6 (dispersion, onset, demographics).
2. **Non-public URLs** — `/admin`, `/panel`, the CMS path, a staging host. These are collection
   targets the live site never links, and they date the build.
3. **The operator's own machine.** Operators get infected too. A log whose host holds *the campaign's
   panel credentials plus the registrar / CMS / hosting / exchange logins behind it* is **direct
   attribution**, not exposure — the strongest single artifact this toolkit can surface.

Search the **seed apex first**, then the operator's email, then discovered siblings. Recipe:
`Workflows/StealerLog.md`.

### Whose machine is this? — the only question that matters on a log item

Judge each item; never judge the corpus. A machine is a **victim** when it holds credentials *for*
the campaign's front-end alongside ordinary consumer accounts, and the geography/language matches
the campaign's target market. It is the **operator's** when it holds the *back* of the operation —
the admin panel, the registrar or hosting account the domains were bought through, the CMS login,
a bulk-mail or SMS console, the exchange or payment account the money lands in — and typically the
builder-side residue too: FTP/SFTP entries for the case hosts, a second unrelated scam's panel,
and geography that matches the operator hypothesis rather than the victim market. Two or three of
those together, on one host, is the finding.

**Three failure modes to reject explicitly.**

- 🚫 **Co-membership is never a link.** "Both selectors appear in the log corpus" is a statement
  about millions of infected machines. `clustering_policy.never_cluster_on` includes `leaks.logs`
  and it fails closed for exactly this reason. The **item** is evidence; the **corpus** is not.
- 🚫 **A victim's machine is not the operator's.** A log holding a credential *for* the scam site
  is the most common shape by far, and it is a victim artifact. Requiring the *back office* — not
  the front end — is what separates the two.
- 🚫 **Absence is only a finding if the logs pass ran.** A keyless run built the query and executed
  nothing; a budget-capped run may have dropped the pass. Check `logs_pass` / `logs_coverage`
  before writing "does not appear in any stealer log", and say which selectors were covered.

### Handling — these are real victim credentials

Cite the item's **metadata** (systemid, bucket, date, the host or URL that matched). **Never paste a
password, cookie, token or session artifact into a case file, an assessment or a chat.** If a
credential's *existence* is the finding, say that it exists and where it was seen — that is the
whole evidentiary content. Victim identities go to the provider or to law enforcement, not into the
operator assessment.

▢ **Your thresholds:** _how many back-office artifacts on one host before you'll call it the
operator's machine; whether you report victim-side findings separately; how stale a log can be
before you stop treating its URLs as live collection targets._

## 2. Correlation & the same-* distinction  ▢ TUNE

Three claims of increasing strength — never conflate them:

- **Same kit** — reused code/template/favicon. Says nothing about who runs it (kits are sold/shared).
- **Same operator** — shared *private* IDs/infra (GA4 property, verification token, registrant, wallet). One controller.
- **Same actor/person** — a named identity ties them (registrant name, reused email, phone).
  **This tier names a *persona*, not a human.** A registrant identity is an unverified
  assertion by whoever filled the form; nominee, borrowed and wholly synthetic identities are
  routine. Write it as "registered under the persona *X*", never "X owns it" — see the
  persona doctrine below before you put a name in an assessment.

**Corroboration rule (seeded):** assert *same-operator* only with **≥2 independent
attribution-grade artifacts**, or 1 attribution-grade + a named identity. One shared
generic artifact is a *lead*, not a finding. **Independent is not enough — they must also be
contemporaneous** (§1.5): two artifacts whose presence windows never overlap on the two hosts
support "the same kit/account passed through both", not "one operator ran both at once".

▢ **Your thresholds:** _when you'll assert on a single artifact (which ones earn that trust); how you down-weight artifacts that co-occur because of a shared SEO/agency tool rather than a shared owner._

**Captured (in-case — edit freely):**
- **A shared phone / Zalo / Messenger handle is corroborating, never attribution.** Do NOT merge two clusters on a phone alone. Keep them separate until a registrant, verification token, or GA/GTM property confirms. (This is why an ID-card cluster bound only by a shared Zalo number should be assessed a *separate* operator, not folded into the main ring, until a registrant or token confirms.)
- **Resolve a theme-only cluster with a registrant lookup before asserting same-operator.** When sites bind only by a shared generic theme, run WHOIS registrant-name before deciding — that can reclassify a theme-only cluster from "likely unrelated" to a known operator's.
- **A named-identity bridge on ONE node can merge two artifact families.** A single page carrying one family's registrant email *and* another family's ahrefs token is enough to assert the two families are one operator — a single node that holds two families' private artifacts is attribution-grade glue.
- **Intra-domain continuity is a different claim from cross-domain clustering — don't apply the ladder to it.** A contact detail (phone, postal address) persisting across a full rebuild of ONE domain — new theme, new business model, new plugin stack — proves *continuity of control of that domain*, i.e. it rules out "the domain changed hands". That is a genuinely useful finding, and the same-operator tier ladder does **not** govern it, because no second domain is involved. Say which question you are answering.
- **For "is this a real business?", an official register outranks any infra inference.** An infra-derived fraud prior (privacy-proxied WHOIS + abandoned site + affiliate monetisation + a fraud-prone sector) is a *prior*, not a finding, and a national company register plus the sector's licence registry can refute it outright as A1 ground truth. Two corollaries: (1) prefer the government API over aggregator sites — aggregators are commonly WAF-blocked and merely resell the same record; (2) a licence serial often encodes its **cohort year** — compare that against the trading window you observed, because a licence issued *after* the activity is a real open question, and the honest move is to log it as unresolved rather than to assert a violation.
- **A shared street address needs a tenant count before it means anything, in either direction.** Enumerate every entity registered there. A domiciliation/virtual-office provider (look for the registry's domiciliation activity codes among the tenants) makes the address worthless. But even *genuine* multi-tenant premises with a handful of unrelated occupants is too shared to cluster on — so when several entities do belong together, make the link rest on the **shared registered officer**, which is a registry fact, not on the address they happen to share.
- **Every persona is fake until proven otherwise — a registrant identity is an ASSERTION, not a fact.**
  Names, emails, phones and addresses in WHOIS are self-declared and unvalidated by any registry.
  Serious operators register under **nominees** (a real but uninvolved person — a relative, an
  employee, a bought passport scan) or **synthetic** identities. So the persona is evidence of
  *who filled the form*, which is a **clustering key**, and is NOT evidence of *who runs the
  operation*. Both uses are legitimate; conflating them is the error.
  - **Do use it to cluster.** A persona's value is that the operator reused it — that is exactly
    what makes it a pivot. Reverse-WHOIS it hard, take every domain it touches.
  - **Do not use it to attribute.** Never promote persona → principal without an
    *independent, non-self-declared* corroborator: an indictment or court filing, a registry/
    company record, a breach or leak record, a payment or KYC artifact, or an operational
    mistake (the persona reused on a personal/legitimate asset predating the operation).
  - **Personas rotate on a schedule; treat era boundaries as findings.** A brand family
    registered under persona A in one period and persona B in a later period usually marks a
    handover, a new registrar/proxy regime, or an OPSEC reset — not two unrelated groups. Date
    the eras and say which one each domain belongs to.
  - **A persona appearing on thematically-innocent assets is a lead, not a contradiction.** When
    a name also sits on unrelated ordinary domains (`Operator A` on a small business site), the
    likeliest readings are identity theft, a nominee's own real domains, or a plain name
    collision. Log all three; do not silently pick the incriminating one.
  - **Common names collide — a name is a weaker key than an email.** Require a second signal
    (same registrar, same registrant city/address, same era, coherent brand family) before
    treating a name-only overlap as one persona.
  - **Write-up rule:** "registered under the persona `Operator A` (`operator-a@example.com`)",
    with a standing caveat that the persona may be a nominee or synthetic. If the real
    principals are known from a filing, state them separately and cite the filing — never
    merge the two into one sentence.
- **Reverse the NAME as well as the email, and reverse every transliteration variant.** Personas
  from non-Latin-script regions get transliterated inconsistently at different registrars, and
  each spelling indexes as a *different* registrant string — so each returns a different domain
  set. Reverse the email, the name, and every plausible romanisation/case/spacing variant, then
  union the results. In-case, a *name* selector returned ~6× the email selector's domains and was
  the only one that crossed from one brand family into a second, operationally-distinct brand —
  the whole cross-brand link would have been missed on the email alone.
- **A live email-verification token on a contentless site = retained sending capability.** A domain reset to a blank template but still publishing a bulk-mail provider's domain-verification record is provisioned as an authenticated *sending* identity with nothing to send about. That is not itself abuse, but it is the configuration a lapsed domain gets abused through — flag it for monitoring rather than filing it as noise.

## 3. Confidence calibration  ▢ TUNE

Blend source reliability × corroboration × recency into a 0–1 score. Starting model:

- base by tier (attribution-grade 0.9 / corroborating 0.6 / noise 0.3),
- **+** raise when ≥2 independent artifacts agree, **−** lower for stale data or single-source,
- **+** raise for a demonstrated **overlap in time** (§1.5); **−** lower hard when the windows
  don't overlap or when one side is dated only by a years-old archive capture,
- keep the *provenance* — a claim's score is only as good as its `evidence_ref`, and an
  `evidence_ref` with no observation date can't be aged.

▢ **Your calibration:** _the priors you actually trust per source (FOFA latest-index blind spots, urlscan freshness, WhoisXML history gaps), and how much a Vietnamese-registrar early record outweighs later privacy._

**Log every confidence call so the labels stay honest — `tools/kb/calibration.py`.** When you
assert a cluster/attribution, record it; when reality settles it, resolve it. `score` then tells
you whether your HIGHs actually land (Brier score + a per-label reliability table: are your
"high" calls confirmed ~85% of the time, or are you OVERconfident?). The judgement layer is an
*aid* — this is how you learn how much to trust it.
```bash
python3 tools/kb/calibration.py record --case <case> --claim "X,Y = one operator (reused GA4)" --confidence high
python3 tools/kb/calibration.py resolve --id <id> --outcome confirmed   # …later
python3 tools/kb/calibration.py score
```

## 4. Hypothesis loop  ▢ TUNE

For each cluster, state the hypothesis, then **actively try to break it**:

1. **Hypothesis:** "Domains X, Y, Z are one operator."
2. **Disconfirm:** look for the artifact that *shouldn't* be shared if true — a different
   registrant, a conflicting GA property, an IP in a different ASN. Absence of
   disconfirming evidence ≠ proof; note what you couldn't check.
3. **Next pivot:** pick the lead most likely to confirm *or* refute cheaply (see §5).

▢ **Your heuristics:** _the "what would I check next" instincts — the tells that make you
suspicious of a coincidence; when a clean story is too clean._

## 5. Pivot prioritisation  ▢ TUNE

Rank open leads by **expected yield ÷ cost** (cost = API credits, time, attribution risk):

- prefer passive + free (crt.sh, Wayback, existing KB) before paid (FOFA/WhoisXML credits),
- prefer artifacts that *split* the hypothesis (confirm or kill it) over ones that merely add volume,
- a reverse lookup on a *named identity* (e.g. reverse-WHOIS on a leaked registrant) usually
  outranks another favicon sweep.

▢ **Your priorities:** _the order you'd actually run things given a credit budget._

**Know when to STOP — `tools/kb/convergence.py`.** Pivoting has no natural finish line, so
define one: snapshot the case each round and stop when the last N rounds add no new hosts and
no new (noise-filtered) indicators. That's the signal to stop chasing the tail and write the
assessment.
```bash
python3 tools/kb/convergence.py snapshot <case>          # after each pivot round
python3 tools/kb/convergence.py status <case> --stale 2  # CONVERGED vs EXPANDING (+ budget)
```

> **Shared-infrastructure is filtered automatically — `tools/kb/noise_filters.py`.** A managed
> nameserver (Cloudflare/NameSilo), a parking favicon, a registrar/privacy abuse email, or a
> malformed GA4 (`g-recaptcha`) links unrelated domains without implying common ownership.
> `--shared` and the ingester now drop these at the source, so a `--shared` cluster is a real
> lead, not infra noise.
>
> **When something slips through, edit the JSON — never the Python.** The matching *logic* is in
> the modules; the *values* are two data files you can extend mid-case:
>
> - `tools/kb/references/noise_filters.json` — shared **infrastructure**: managed-DNS suffixes,
>   parking favicons/hosts, shared apexes, SaaS tenant suffixes, privacy-proxy and placeholder
>   phones, phone-length bounds.
> - `tools/kb/references/registrant_noise.json` — shared **registrant identity**: org suffixes,
>   WHOIS-label junk, role-name placeholders (`Domain Admin`), privacy markers, proxy email
>   domains/tokens, empty-hash artifacts, and the report-ingest noise domains.
>
> Both are read by the ingester, `clean_kb`, `hypothesize` and `ingest_report` — one edit, every
> consumer. Each group's `_comment` states whether it matches exactly or as a substring; that
> distinction is load-bearing (an exact rule keeps `Admin Solutions GmbH` while dropping
> `Domain Admin`). **Over-filtering is the costlier direction** — it silently destroys real
> attribution, so add providers freely and anything operator-shaped never.
>
> If a module ever prints `[refs] WARNING`, its data file is unreadable and it is running on a
> stub list — stop and fix the file, because a filter that returns False everywhere manufactures
> clusters. `python3 tests/test_references.py` proves the files load.

## 6. Conflict handling

The store keeps disagreements (WHOIS vs RDAP, two registrants across history). **Surface
the conflict in the assessment**; don't silently pick one. A conflict is often the signal
(e.g. a pre-privacy record naming the real owner vs the later proxy).

## 7. Assessment write-up standard  ▢ TUNE

- **BLUF** — the finding in one sentence, with a confidence word (assessed / likely / possible).
- **Cluster** — domains + the shared artifacts that bind them (a table, each row cited).
- **Timeline** — the case's lifecycle: registration cohorts, registrant eras, hosting windows,
  certificate batches, the campaign's start and (if it lapsed) its end. Say which links are
  contemporaneous and which are not (§1.5). Embed the `case_timeline.py` figure and attach its
  evidence ledger.
- **Attribution** — same-kit / same-operator / same-actor, and the evidence for the level claimed.
- **Operator — the section the case exists for.** Say who runs it at the strongest honest rung:
  a named actor, a persona (registrant / advertiser legal entity / dev account — labelled as a
  persona, with the nominee-or-synthetic caveat), or an unnamed operator *characterised* by
  jurisdiction, language, hosting habits, working hours, kit provenance and payment rails. If no
  rung is reachable, write **"unattributed"** and why — never omit the section. Then the
  **identity gap**: the single pivot most likely to produce a name, and what it costs.
- **Gaps & alternatives** — what you couldn't verify, and the competing explanation you ruled out.
- **Next steps** — the prioritised open pivots, identity-closing ones first.

### Evidence citation standard (non-negotiable)

Every asserted fact carries four things — **what · when (UTC) · source · a link that resolves for
someone who has never seen our disk**:

| When (UTC) | Host / indicator | Claim | Source (Admiralty) | Evidence link |
|---|---|---|---|---|
| 2026-01-02 → 2026-04-01 | `site-a.example` | hosted at `198.51.100.10` | passive DNS (B2) | https://bgp.he.net/ip/198.51.100.10 |

- **Online links only.** Wayback snapshot (`web.archive.org/web/<ts>/<url>`), archive.today,
  urlscan result (`urlscan.io/result/<uuid>/`), crt.sh cert id, RDAP record, BGP, a block
  explorer. A `cases/<case>/out/*.json` path is **collection provenance, never the citation** —
  it may appear in an internal appendix, but a reader must be able to re-check without it.
- **Prefer the frozen copy over the search.** A snapshot shows what you saw; a live search result
  changes under the reader and can quietly turn your finding into a hallucination.
- **No public copy yet? Create one before you assert** — `pivot_extract --archive-missing`
  (Wayback Save Page Now) or a urlscan submission — then cite what you created. Archive first,
  assert second: hostile infrastructure disappears exactly when the report lands.
- **Timestamp the observation, not the write-up.** "Observed 2026-03-04" beats "as of this
  report", and it is what lets the next analyst age the claim (§3, §1.5 recency).
- **A claim with no link is labelled as inference**, in its own row, graded as such — never
  smuggled in beside sourced rows.
- Link templates + per-source Admiralty defaults live in
  `IntelGraph/references/evidence_sources.json`; `case_timeline.py --markdown` emits this table
  for you from the case's collected JSON.

▢ **Your format:** _house style, client-facing vs internal, how you phrase confidence for a legal/takedown audience._

---

## Worked example (illustrative — replace with your own as the KB grows)

`--shared` over the store yields: an ahrefs token on 4 domains, a GA4 property
`G-XXXXXXXXXX` + GTM + favicon on one brand family, a Messenger handle bridging two
sibling domains, and a leaked registrant name on a third domain. Triaged: those are all
attribution-grade except the Cloudflare NS (noise). Corroboration: ≥2 attribution-grade
artifacts across the set **and** a named identity → **assessed same-operator, one named
actor.** Next pivot (§5): reverse-WHOIS on the leaked registrant name (named identity >
another favicon sweep).
