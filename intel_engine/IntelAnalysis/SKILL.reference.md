---
name: IntelAnalysis
description: The analyst / judgment layer for OSINT — correlation, attribution, confidence calibration, and next-pivot decisions over the knowledge base. Does NOT collect; it reasons over facts that collectors (WebPivot, etc.) already gathered. USE WHEN correlate findings, attribute infrastructure, who is behind this, same operator, same actor, build the case, assess confidence, weigh evidence, cluster analysis, what should I pivot on next, is this the same owner, investigation judgment, connect the dots, threat attribution, generate hypothesis, prove or disprove, newly registered domain, NRD, bulletproof hosting, money trail, trace the money, reused wallet, scam red flags, my investigation style, feed past reports.
---

> **OPSEC — this skill is portable/shared. Never write case data into it.** No real operator
> names, emails, domains, IPs, wallets, tracking IDs, hashes, or case IDs in this file, its
> workflows, tool code, or test fixtures. Investigation data lives only in the git-ignored
> `cases/` / `knowledge/` / `MEMORY/`. In examples use placeholders (`example.com`,
> `G-XXXXXXXXXX`, `CASE-0001`). See the repo-root `CLAUDE.md` for the full rule.

# IntelAnalysis — the analyst's brain

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

Run every command below from the `intel_engine` **project root** (where `knowledge/`,
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
  1. A cited assessment file at a **fixed path**: `knowledge/reports/<case>/assessment.md`,
     following the §7 schema exactly (BLUF → Cluster table → Attribution → Gaps & alternatives →
     Next steps). Writing the assessment only into the chat is not "done" — save the file, then
     summarize it in the reply. Re-running an assessment overwrites the same path.
  2. When your judgment changes a rating, the **updated confidence back into the store** (so the
     next run inherits it), keeping provenance.
  3. Optional but recommended: **invoke the `IntelGraph` skill** on the `case_graph.json` and drop
     the rendered `network.html` beside the report in `knowledge/reports/<case>/`.

## Method

```
Triage facts → Correlate into clusters → Attribute (same-kit vs same-operator vs same-actor)
   → Calibrate confidence → Form & falsify hypotheses → Prioritise next pivots → Write the assessment
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

## 2. Correlation & the same-* distinction  ▢ TUNE

Three claims of increasing strength — never conflate them:

- **Same kit** — reused code/template/favicon. Says nothing about who runs it (kits are sold/shared).
- **Same operator** — shared *private* IDs/infra (GA4 property, verification token, registrant, wallet). One controller.
- **Same actor/person** — a named identity ties them (registrant name, reused email, phone).

**Corroboration rule (seeded):** assert *same-operator* only with **≥2 independent
attribution-grade artifacts**, or 1 attribution-grade + a named identity. One shared
generic artifact is a *lead*, not a finding.

▢ **Your thresholds:** _when you'll assert on a single artifact (which ones earn that trust); how you down-weight artifacts that co-occur because of a shared SEO/agency tool rather than a shared owner._

**Captured (in-case — edit freely):**
- **A shared phone / Zalo / Messenger handle is corroborating, never attribution.** Do NOT merge two clusters on a phone alone. Keep them separate until a registrant, verification token, or GA/GTM property confirms. (This is why an ID-card cluster bound only by a shared Zalo number should be assessed a *separate* operator, not folded into the main ring, until a registrant or token confirms.)
- **Resolve a theme-only cluster with a registrant lookup before asserting same-operator.** When sites bind only by a shared generic theme, run WHOIS registrant-name before deciding — that can reclassify a theme-only cluster from "likely unrelated" to a known operator's.
- **A named-identity bridge on ONE node can merge two artifact families.** A single page carrying one family's registrant email *and* another family's ahrefs token is enough to assert the two families are one operator — a single node that holds two families' private artifacts is attribution-grade glue.
- **Intra-domain continuity is a different claim from cross-domain clustering — don't apply the ladder to it.** A contact detail (phone, postal address) persisting across a full rebuild of ONE domain — new theme, new business model, new plugin stack — proves *continuity of control of that domain*, i.e. it rules out "the domain changed hands". That is a genuinely useful finding, and the same-operator tier ladder does **not** govern it, because no second domain is involved. Say which question you are answering.
- **For "is this a real business?", an official register outranks any infra inference.** An infra-derived fraud prior (privacy-proxied WHOIS + abandoned site + affiliate monetisation + a fraud-prone sector) is a *prior*, not a finding, and a national company register plus the sector's licence registry can refute it outright as A1 ground truth. Two corollaries: (1) prefer the government API over aggregator sites — aggregators are commonly WAF-blocked and merely resell the same record; (2) a licence serial often encodes its **cohort year** — compare that against the trading window you observed, because a licence issued *after* the activity is a real open question, and the honest move is to log it as unresolved rather than to assert a violation.
- **A shared street address needs a tenant count before it means anything, in either direction.** Enumerate every entity registered there. A domiciliation/virtual-office provider (look for the registry's domiciliation activity codes among the tenants) makes the address worthless. But even *genuine* multi-tenant premises with a handful of unrelated occupants is too shared to cluster on — so when several entities do belong together, make the link rest on the **shared registered officer**, which is a registry fact, not on the address they happen to share.
- **A live email-verification token on a contentless site = retained sending capability.** A domain reset to a blank template but still publishing a bulk-mail provider's domain-verification record is provisioned as an authenticated *sending* identity with nothing to send about. That is not itself abuse, but it is the configuration a lapsed domain gets abused through — flag it for monitoring rather than filing it as noise.

## 3. Confidence calibration  ▢ TUNE

Blend source reliability × corroboration × recency into a 0–1 score. Starting model:

- base by tier (attribution-grade 0.9 / corroborating 0.6 / noise 0.3),
- **+** raise when ≥2 independent artifacts agree, **−** lower for stale data or single-source,
- keep the *provenance* — a claim's score is only as good as its `evidence_ref`.

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
> lead, not infra noise. If a new managed-DNS/parking provider slips through, add it to that file.

## 6. Conflict handling

The store keeps disagreements (WHOIS vs RDAP, two registrants across history). **Surface
the conflict in the assessment**; don't silently pick one. A conflict is often the signal
(e.g. a pre-privacy record naming the real owner vs the later proxy).

## 7. Assessment write-up standard  ▢ TUNE

- **BLUF** — the finding in one sentence, with a confidence word (assessed / likely / possible).
- **Cluster** — domains + the shared artifacts that bind them (a table, each row cited).
- **Attribution** — same-kit / same-operator / same-actor, and the evidence for the level claimed.
- **Gaps & alternatives** — what you couldn't verify, and the competing explanation you ruled out.
- **Next steps** — the prioritised open pivots.

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
