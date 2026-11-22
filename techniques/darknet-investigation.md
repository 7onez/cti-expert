# Darknet Investigation Module

> **Module ID:** DARKNET-001
> **Version:** 1.1.0
> **Phase:** 5 - Enhancement Modules
> **Classification:** Dark Web Search, Leak Monitoring & Ransomware Tracking

---

## 1. Overview

Darknet investigation OSINT locates threat actor activity, ransomware victim claims, data leaks, and illicit marketplace intelligence from Tor hidden services and dark web indexes. Use when a target organization, individual, or keyword needs to be monitored across dark web forums, marketplaces, and ransomware group leak sites.

**Key use cases:** Ransomware victim identification, credential and data leak discovery, threat actor attribution, dark web marketplace monitoring, incident response triage, and compliance/due diligence screening.

**Note:** Full access to `.onion` sites requires Tor Browser or a local Tor SOCKS5 proxy (port 9050 by default). Several tools in this module provide **clearnet access** to dark web intelligence without requiring Tor — these are noted explicitly.

---

## 2. Tool Inventory

### Search & Discovery

#### Ahmia.fi
**URL:** https://ahmia.fi/
**Tor access:** http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/

Search engine for Tor hidden services. Accessible via clearnet — no Tor required for basic keyword searching. Filters out child sexual abuse material (CSAM) from its index.

- **Usage:** Enter keyword in search bar → returns `.onion` URLs with page title and snippet
- **Clearnet:** Yes — full search available without Tor
- **Best for:** Initial keyword sweep across indexed `.onion` content

#### onionsearch (CLI)
**Install:** `pip3 install onionsearch`
**Repo:** https://github.com/megadose/onionsearch

CLI tool that queries multiple `.onion` search engines simultaneously and aggregates results. Requires a running Tor proxy (SOCKS5 on 127.0.0.1:9050).

- **Searches across:** Ahmia, Torch, DarkSearch, Haystack, and others
- **Usage:** `onionsearch "target keyword" --len 10`
- **Clearnet:** No — requires Tor proxy

#### DarknetLive
**URL:** https://darknetlive.com/onions/
**Forums section:** https://darknetlive.com/forums/

Curated, actively maintained directory of verified `.onion` services. Lists marketplaces, forums, and service sites with activity status. More reliable than stale link lists.

- **Usage:** Browse by category or use browser Ctrl+F to search for specific service names
- **Clearnet:** Yes — no Tor required for the directory
- **Best for:** Identifying which platforms a target may be active on

### Ransomware & Extortion Monitoring

#### ransomwatch
**URL:** https://ransomwatch.telemetry.ltd/
**API:** https://api.ransomwatch.telemetry.ltd/

Transparent ransomware group claim tracker. Monitors leak sites for new victim posts and exposes data via a public API. Supplements ransomware.live (already in cti-expert).

- **Usage:** Browse by group, or use the API to query by keyword
- **Clearnet:** Yes — fully clearnet accessible
- **Best for:** Confirming whether a target organization appears as a ransomware victim

#### DDoSecrets (Distributed Denial of Secrets)
**URL:** https://ddosecrets.com/

Repository of leaked datasets published by hacktivist groups. Hosts publicly released data from breaches, government leaks, and corporate exposures.

- **Usage:** Browse Special:AllPages or search for organization/country
- **Clearnet:** Yes
- **Best for:** Hacktivist leak discovery; documents published after exfiltration

### Scanning & Analysis

#### OnionScan
**Repo:** https://github.com/s-rah/onionscan

Open-source scanner for analyzing `.onion` services for security misconfigurations that may deanonymize the operator (Apache server leaks, Bitcoin addresses, email addresses, linked clearnet infrastructure).

- **Usage:** `onionscan http://example.onion` — produces JSON report of linkage risks
- **Clearnet:** No — requires Tor; scans `.onion` targets directly
- **Best for:** Attribution work — identifying clearnet infrastructure linked to a dark web operator

### Additional Reference Resources

- **Torch** — One of the oldest Tor search engines; large index but low result quality. Onion-only access.
- **Hunchly Dark Web Tracker** — Commercial tool for automated dark web page capture and monitoring. Useful for long-term tracking campaigns (reference for capabilities comparison).

---

## 3. Investigation Workflow

```
Step 1: Clearnet intelligence — no Tor needed
  └─ Ahmia.fi: keyword search across indexed onion sites
       https://ahmia.fi/search/?q={keyword}
  └─ ransomwatch: check if target appears as ransomware victim
       https://ransomwatch.telemetry.ltd/
  └─ DDoSecrets: check for hacktivist leak datasets involving target
       https://ddosecrets.com/wiki/Special:AllPages
  └─ DarknetLive: identify relevant marketplaces/forums by category
       https://darknetlive.com/onions/

Step 2: Expanded keyword search via Tor (requires Tor Browser or proxy)
  └─ onionsearch CLI: query multiple search engines simultaneously
       onionsearch "target organization" --len 10
  └─ Direct .onion access for specific marketplace/forum pages
  └─ Ahmia .onion for search within Tor network

Step 3: Ransomware victim verification
  └─ ransomwatch API: query by domain or organization name
       curl "https://api.ransomwatch.telemetry.ltd/victims" | jq ...
  └─ ransomware.live (existing cti-expert tool): cross-reference
  └─ Note timestamp of first claim appearance (important for IR timelines)

Step 4: Leak site monitoring
  └─ DDoSecrets: search for datasets referencing the target
  └─ Paste site sweeps (Pastebin, Ghostbin, PrivateBin): Google dork
       site:pastebin.com "{organization}" password OR dump OR leak

Step 5: Attribution analysis (Advanced — requires Tor + OnionScan)
  └─ OnionScan target .onion service for OPSEC failures:
       - Apache server headers leaking clearnet hostname
       - Linked Bitcoin addresses (cross-reference blockchain explorers)
       - Email addresses embedded in page source
       - Linked clearnet domains or CDN origins
  └─ PGP key cross-reference: same FULL fingerprint on two aliases? Then demand a fresh,
       venue-bound signature before calling it the same key-holder (§5 Vendor/Alias Linkage)
  └─ Writing style / handle cross-reference with clearnet profiles — leads only; stylometry
       needs an explicit candidate set, enough text, and an abstention outcome (§5)
  └─ Size/volume/"top vendor" claims → §5 Marketplace & Forum Measurement first

Step 6: Documentation (critical for legal and compliance)
  └─ Screenshot all findings with timestamp visible
  └─ archive.org does NOT index .onion — save pages locally via:
       wget --no-check-certificate -p -k http://example.onion/page
  └─ Maintain chain of custody record if findings are for legal proceedings
  └─ Log: date/time, URL, tool used, investigator identity, hash of saved file
```

---

## 4. CLI Commands & Expected Output

### Ahmia Clearnet Search
```bash
# Keyword search via clearnet — no Tor required
# Replace spaces with + in query
curl -s "https://ahmia.fi/search/?q=target+organization" \
  | python3 -c "
import sys, re
html = sys.stdin.read()
# Extract result URLs and titles
urls = re.findall(r'href=\"(http[s]?://[^\"]+\.onion[^\"]*?)\"', html)
for u in urls[:20]:
    print(u)
"
```

**Expected output:**
```
http://exampleabcdef.onion/forum/thread/12345
http://darkmarketxyz.onion/vendor/target-name
http://leaksite123.onion/post/organization-dump
```

### ransomwatch API Query
```bash
# Query ransomwatch for victims matching a keyword (clearnet, no auth)
curl -s "https://api.ransomwatch.telemetry.ltd/victims" \
  | jq '.[] | select(.post_title | test("keyword"; "i")) | {
      group: .group_name,
      victim: .post_title,
      date: .discovered,
      url: .post_url
    }'
```

**Expected output:**
```json
{
  "group": "lockbit",
  "victim": "Target Organization Inc",
  "date": "2024-03-15T14:22:00",
  "url": "http://lockbit3abcdef.onion/post/12345"
}
```

### ransomware.live Cross-Reference (existing cti-expert tool)
```bash
# Supplement with ransomware.live API
curl -s "https://api.ransomware.live/victims" \
  | jq '.[] | select(.post_title | test("keyword"; "i")) | {
      group: .group_name,
      victim: .post_title,
      date: .discovered
    }'
```

### onionsearch CLI (requires Tor proxy on 127.0.0.1:9050)
```bash
# Install
pip3 install onionsearch

# Basic search across all supported engines
onionsearch "target keyword" --len 10

# Search with specific engines only
onionsearch "target keyword" --engine ahmia --engine torch --len 20

# Output to file
onionsearch "target keyword" --len 50 > darkweb_results.txt
```

**Expected output:**
```
Searching for: target keyword
[*] Ahmia      - Found 7 results
[*] Torch      - Found 12 results
[*] DarkSearch - Found 3 results

Results:
http://examplexxx.onion/page/1 - Title: ...
http://forumyyy.onion/thread/99 - Title: ...
...
```

### OnionScan Attribution Scan
```bash
# Install Go, then:
go install github.com/s-rah/onionscan@latest

# Scan target onion service for OPSEC failures
# Requires Tor proxy running on 127.0.0.1:9050
onionscan --torProxyAddress 127.0.0.1:9050 \
          --depth 2 \
          http://targetservice.onion \
          2>/dev/null | python3 -m json.tool

# Key fields to review in output:
# - "linkedSites"       : clearnet domains referenced
# - "emailAddresses"    : operator contact leaks
# - "bitcoinAddresses"  : wallet addresses for blockchain pivot
# - "pgpKeys"           : PGP fingerprints for identity cross-reference
# - "serverVersion"     : software version (fingerprinting)
```

### Paste Site Dork (Clearnet)
```bash
# Construct Google dork queries for paste site leak monitoring
# Run these in browser — no CLI
echo 'Google dorks for paste site monitoring:'
echo ''
echo 'site:pastebin.com "{organization}" password OR dump OR leak'
echo 'site:pastebin.com "{domain.com}" credentials'
echo 'site:ghostbin.com "{organization}"'
echo 'site:rentry.co "{organization}" dump'
echo '"{organization}" filetype:txt password database dump'
```

---

## 5. Analysis & Interpretation Guidance

### Dark Web Signal Assessment

```
Ransomware claim credibility:
  HIGH:   Organization name matches exactly, sample data published, known active group
  MEDIUM: Name match only, no sample data, smaller/less active group
  LOW:    Partial name match, group has history of false claims (e.g., KelvinSecurity)

Leak freshness indicators:
  - First seen date on ransomwatch vs. organization's known breach date
  - Is the data already publicly circulating? (check BreachDirectory, DeHashed)
  - Countdown timer present: extortion still in negotiation phase

Forum post credibility:
  - Account age: older accounts with post history > newly registered
  - Vouches or trusted vendor badges: WEAK — vouches are often incentivised or
    appraiser-driven (see §5 Review & Appraisal Evidence); never proof of volume or legitimacy
  - PGP-signed posts: signed content is harder to fabricate — but only a signature that
    verifies, made by a key whose history you checked, counts (§5 Vendor/Alias Linkage)
```

### Marketplace & Forum Measurement

Source: longitudinal market scraping and feedback-as-sales-proxy method
[P08 Soska & Christin, USENIX Sec 2015]; crawler/parser split and site-reported fields
[P09 Nunes et al., IEEE ISI 2016].

**Trigger:** any statement about a market's, forum's or vendor's size, sales, activity,
"active since", popularity, "top vendor" status or trend — or before treating two venues
as two confirmations of one fact.

**Inputs:** saved captures (raw HTML + hash), crawl start/end UTC per venue, pages
attempted / fetched / failed, logged-in or anonymous state, parser version.

```
1. DATE EVERY OBSERVATION
   observation = {venue, page_type: listing|vendor|feedback|thread|post,
                  crawl_start_utc, crawl_end_utc, pages_attempted, pages_fetched,
                  pages_failed, session_state, parser_version, capture_sha256}
   - Keep raw captures and parsed rows separate; re-parse old captures when the site
     layout changes. P08 decoupled scraping from parsing for exactly this reason.
   - A full crawl of a large market can take days; record the window, not one timestamp.
   - Record GAPS explicitly: outages, session expiry, anti-scraping lockouts, pages
     never reached. P08 reports some markets at ~70% uptime or lower, and one market
     where a single scrape typically captured under half of the feedback present.

2. TREAT ONE CRAWL AS A LOWER BOUND
   - Feedback is rarely deleted (it is the vendor's reputation), so later crawls fill
     in earlier periods; the most recent window is always the least complete.
   - Estimate coverage by mark–recapture across two crawls (P08):
       M = feedback in crawl 1;  n = feedback dated ≤ t1 seen in crawl 2;
       m = items present in both;  F̂ = n·M / m
     (P08 extends this to many crawls with the Schnabel estimator.)
   - If m is small or the crawls overlap in time, report the observed count as a
     lower bound only — do not publish F̂ (adaptation).

3. NAME THE UNIT — never mix them in one number
   listing ≠ product ≠ alias (handle, venue) ≠ vendor (person or crew) ≠ order
   ≠ unit sold ≠ feedback item ≠ review ≠ vouch copy
   - P08 counts a seller per (marketplace, vendor-name) pair, so a seller on three
     markets is counted three times unless aliases are linked.
   - Listing counts are a poor proxy for sales: in P08's data a few listings carried a
     large share of sales and sales-per-listing swung widely during growth.

4. WHAT FEEDBACK CAN AND CANNOT ESTIMATE
   CAN (only where the venue makes feedback MANDATORY per order):
     - a LOWER BOUND on orders: deduplicated feedback items
     - a lower-bound value: each feedback paired with the listing price observed
       nearest in time, assuming one unit per feedback (P08's conservative assumption)
     - an UPPER BOUND on transaction time: the feedback timestamp; precision varies
       by venue (day vs. month)
   CANNOT:
     - volume on venues where feedback is optional (P08 left such markets out of
       volume estimates for this reason) → write "volume not estimable"
     - quantity per order, off-market or direct deals, refunds/scams after feedback
     - legitimacy or product quality (see Review & Appraisal Evidence)
     - site-displayed counters ("7000 sold", ratings): the venue's own claim, not a
       measurement — record as claim (adaptation; P09 parses "items sold" as a field)
   Dedup: the same feedback seen in N crawls counts once — key on body text, vendor,
   listing title and approximate date (P08).
   Holding prices: out-of-stock listings parked at absurd prices to keep their reviews.
   Drop price observations far from the listing's median before pairing (P08 used
   median-relative cut-offs; use the idea, not their exact constants).

5. SOURCE INDEPENDENCE
   Two venues showing the same fact are ONE source when any of these hold:
     - scraped mirror / clone (identical post IDs, timestamps, byte-identical text)
     - aggregator or vendor directory republishing listings (P08 notes a directory
       it used was likely manually curated → lead, not confirmation)
     - the same alias cross-posting its own advert to both (P09 observed vendors
       advertising market products on forums)
   Trace to the ORIGIN post, cite that, and list mirrors as "also seen at" (adaptation).

6. VALIDATE WHEN YOU CAN
   P08 had two authors build independent analyses and compared them, then spot-checked
   against court records and a leaked vendor page. Equivalent here (adaptation):
   re-derive any headline number by a second method or analyst before publishing.
```

**Output:** `Observed ≥N <unit> for <alias> on <venue>, <first crawl>–<last crawl> UTC,
<k> crawls, coverage <estimate | unknown>; feedback <mandatory | optional>; value
<lower bound | not estimable>.`

**Confounders:** vendor "vacation" mode (P08 counts a seller active at T only if listings
are seen before and after T), relisting under new IDs, crypto price swings when
converting to fiat, partial crawls masquerading as decline, a takedown cutting the
series mid-trend.

**Abstain:** no crawl time → "undated, not usable for timelines"; optional feedback →
"volume not estimable"; single crawl → "lower bound only"; venue not crawled in the
window → "no observation", never "absent".

**Ethics/OPSEC:** P08 rate-limited crawls so the measurement did not affect the subject.
Logged-in crawling needs an account, which the Absolute rules below forbid without
explicit authorisation — prefer existing captures and third-party datasets.

### Review & Appraisal Evidence

Source: [P10 Li & Liao, NDSS 2024]; feedback-proxy caveats [P08 Soska & Christin, USENIX Sec 2015].

**Trigger:** a review, vouch, rating, "successful transactions" count, trusted badge or
appraisal is about to support a claim of volume, reliability, or that a product works.

P10 describes the **appraisal system**: vendors hand free samples ("vouch copies") to
selected appraisers in exchange for detailed reviews; selection uses VIP status, post
count, reputation score, membership length, or staff rank. P10 documents fake reviews by
appraisers who are friends of (or paid by) the vendor, vendors posting appraisals from
their own sockpuppet accounts, fake appraiser groups bumping threads with "100% LEGIT"
replies, vendor-supplied review templates, and negative reviews posted to extort a
vouch copy.

```
1. Classify each review: purchase feedback | appraisal/vouch | unknown.
   Markers of appraisal: mentions "vouch copy"/"review copy", free sample, a review
   template, membership in an official reviewer group.
2. Exclude vouch copies from any sales/order count — a free sample is not a sale.
3. Check reviewer independence: account age vs. vendor's, post history outside this
   vendor, registration bursts, near-duplicate wording across reviewers, mentions in
   the venue's scam-report section (P10's route to suspect appraisers).
4. Extract technical artifacts (hashes, detection counts, file names, languages,
   tested targets) as CLAIMS to verify — P10 found appraisal reviews carried CTI
   artifacts far more often than listings or ordinary reviews in its dataset.
5. Record: review_type, incentive (vouch_copy | purchase | unknown),
   independence (passed | failed | unchecked).
```

**Weight:** reviews are WEAK evidence of volume or legitimacy, even when numerous and
positive. They can be useful evidence of *what the product claims to do*.

**Confounders/abstain:** P10's detector is English-only and tuned for precision, so a
review lacking vouch keywords may still be incentivised — when the type is unclear, treat
it as `incentive: unknown` and do not cite it for legitimacy.

### Threat-Warning Extraction

Source: crawler → parser → relevance classifier → warnings pipeline [P09 Nunes et al., IEEE ISI 2016].

**Trigger:** a listing or forum thread offers or discusses an exploit, access, malware,
data, or service relevant to the client, a product, a CVE, or a sector.

P09 crawled markets and forums, parsed product fields (title, description, vendor,
reviews, items sold, CVE, ratings) and forum fields (topic/post content, author, status,
reputation), then used an expert-labelled classifier to separate hacking-related items
from drugs/other goods (only ~13% of products in their markets were hacking-related).
Their motivating case is an exploit for a patched-but-unexploited vulnerability listed
for sale weeks before public reports of exploitation.

```
WARNING RECORD
  warning_id            CASE-0001-W-001
  observed_utc          first time WE saw it (crawl window) — a lower bound on age
  claimed_date          date the post/listing states, if any (claim)
  source                venue, URL/onion path, capture_sha256, origin vs mirror
  actor_alias           (handle, venue) — an alias, never a person
  actor_role            vendor | buyer/requester | reseller | broker | admin | appraiser | unknown
  claimed_capability    one-line summary of what is CLAIMED (quote short phrases)
  capability_type       exploit | "0day" claim | access | malware | data | service
  target                product+version | CVE | sector | named org — and specificity
  terms                 price, escrow, exclusivity, sample offered
  corroboration_status  claim-only | seller-artifact | independently-corroborated
                        | verified | contradicted
  corroboration_refs    what moved it up the ladder (advisory, sandbox, exploitation report)
  triage_method         manual | classifier <name/version> + human review
  confidence / likelihood  per handbook/analytic-standards.md
  recheck_by            date to re-crawl (listing removed? price changed?)
```

Rules (adaptation unless noted):
- `claimed_capability` and verified capability are different fields. A "0day" label,
  a demo video or a screenshot is a seller artifact, not verification.
- Underground listings include rip-offs: a claim with no corroboration ships as
  `claim-only`, worded "advertised as", never "has".
- A classifier is a triage filter. In P09's leave-one-market-out test, the best product
  model recalled ~92% at ~82% precision (their data) — so expect misses and false hits;
  a human reviews before a warning goes to a client.
- Spelling variants are common (P09 used character n-grams to cope); search keyword
  variants, not just the canonical product name.
- P09 linked users across venues by username; under this module's standard that is
  name similarity only (weak) — see Vendor/Alias Linkage.
- **Abstain:** no specific target or capability → log as landscape context, not a warning.

### Attribution Techniques

Keep the claim ladder separate (see Vendor/Alias Linkage): same handle string ≠ same key
material ≠ same key-holder ≠ same operator/crew ≠ named person.

```
Handle cross-referencing (LEAD only):
  - Dark web handle appears on clearnet hacker forums (XSS, Exploit.in)?
  - Same handle registered on GitHub, Twitter, Telegram?
  - Reverse image search avatar/profile photo
  - Name similarity is WEAK: handles are copied by fans, impostors and successors.
    P08 merged only case-only variants and filtered generic name parts;
    "Sally" vs "Sally!" stayed unlinked without a common PGP key.

PGP key pivoting:
  - Extract PGP key from dark web post: grep -A50 "BEGIN PGP"
  - Compare FULL fingerprints (40/64 hex), never short key IDs (adaptation: short IDs collide)
  - Query key servers: https://keys.openpgp.org/search?q={fingerprint}
  - Same key on dark web and a clearnet identity = LEAD toward deanonymisation, not
    proof: a public key can be copied by anyone, keyserver User IDs are self-asserted
    (keys.openpgp.org verifies only that the e-mail owner consented), and a private
    key can be shared or stolen. Escalate only with a verifying signature and checked
    key history (Vendor/Alias Linkage below).

Writing style analysis (stylometry) — WEAK, rank-only, abstention mandatory
  [P12 Narayanan et al., IEEE S&P 2012]:
  - Requires an EXPLICIT CANDIDATE SET. Stylometry ranks the unknown text against the
    authors you supply; it always returns a "closest" candidate even when the true
    author is not in the set. Document how the set was built and include
    "none of these / insufficient" as a valid result.
  - Requires SUFFICIENT TEXT, in several samples: in P12's 100,000-blog experiment
    accuracy was poor with fewer than ~7–10 training posts per author and kept improving
    up to ~40; a single anonymous post was right ~7.5% of the time (their data, top-1).
  - Even at best it ranks: P12 got the right author first in ~20% of trials and in the
    top 20 in ~35%; confidence-based abstention raised top-1 precision above 80% by
    giving up about half the answers. Use an abstention threshold; most texts should
    end as "no attribution".
  - Same domain/genre only: P12 found cross-context (blog-to-blog) matching weaker
    (~12%) and did NOT test cross-domain (e.g. forum post vs. e-mail); deliberate
    obfuscation defeats it.
  - Strip signatures, quoted text, templates and copied boilerplate first — vendor
    listing text and review templates are frequently shared (P10), which manufactures
    false matches (adaptation).
  - Output: ranked candidates + confidence, as a lead to prioritise OTHER evidence
    (P12: it narrows candidates; combine with another source). Never the sole basis
    for a link, and never for a named person.
  - Tools: JGAAP (Java Graphical Authorship Attribution Program) — same conditions apply.
  - Timezone clustering, regional slang, recurring typos: searchable LEADS; shared by
    many people, easy to imitate.

Bitcoin address pivoting:
  - Extract wallet addresses from OnionScan output or page source
  - Query blockchain explorer: https://www.blockchain.com/explorer
  - Cluster addresses via wallet heuristics (common-input ownership) — see
    techniques/blockchain-investigation.md for the heuristic's limits
  - Check exchange deposit addresses for KYC linkage
```

### Vendor/Alias Linkage Standard

Source: alias definition and conservative linking heuristics, migration after closures
[P08 Soska & Christin, USENIX Sec 2015]; stylometry limits [P12 Narayanan et al., IEEE S&P 2012];
sockpuppet appraisers [P10 Li & Liao, NDSS 2024]. Hypothesis scoring per
`handbook/analytic-standards.md` (ACH).

**Trigger:** two or more aliases on different venues (or the same venue) may be one seller;
or a known alias disappears when a market closes and similar names appear elsewhere.

**Definitions:** an **alias** is a unique (vendor nickname, marketplace) pair (P08).
Claim ladder (adaptation):

| Rung | Claim | Minimum evidence |
|---|---|---|
| L0 | Same handle string | Text match only — weak |
| L1 | Same key material displayed | Identical FULL fingerprint on both aliases |
| L2 | Same key-holder | L1 + a fresh signature, bound to the new venue and date, verifying under that key; key history checked |
| L3 | Same operator / crew | L2 or several independent strong links (key, wallet reuse, shipping/ops details) + no better competing hypothesis |
| L4 | Named person | Off-darknet identity evidence; never from one shared signal |

```
PGP checks (strong but not absolute):
  1. Full fingerprint equality — P08 linked accounts that CLAIM the same PGP key;
     displaying a public key proves nothing about who holds the private key.
  2. Fresh signature — a signed message posted on the NEW alias whose content names
     that venue/alias and a date or challenge phrase after the old alias went quiet.
     Re-posted old signed messages are replays and do not count.
  3. Key creation date — must precede the old alias's first observation if the key is
     claimed as the vendor's long-standing key. A key created after a closure is a
     NEW key: it needs a cross-signature by the old key (or a message signed by the old
     key endorsing it) before any link.
  4. Signed-message history — earlier signatures on the old venue verify with the same
     key; subkeys, expiry and revocation status are consistent; no revocation notice.
  Risks to name in the report: private key shared within a crew, stolen (compromised
  device, seized or leaked backups), or sold with the "brand"; impostors trading on a
  known name after a closure (adaptation).

Other link signals:
  - Name similarity / directory listings: weak (above).
  - Identical product photos or listing text: weak–moderate (copyable from archives).
  - Wallet reuse: route to blockchain-investigation.md; same-wallet ≠ same person.
  - Sockpuppets can be confirmed by the venue (P10: an admin IP check); you rarely can.
  - Stylometry: rank-only lead, rules above.

Hypothesis record (one per proposed link):
  link_id, aliases[], rung_claimed (L0–L4), evidence_for[], evidence_against[],
  competing: H_same (same key-holder) | H_imp (impostor copying public data)
           | H_shared (crew shares key/brand) | H_sold (account/brand transferred)
           | H_none (unrelated, coincidental name)
  result: linked at rung Lx | NO LINK SUPPORTED | INSUFFICIENT
  likelihood + confidence, assumptions, what would change the call
```

"No link supported" is a first-class outcome — record it so the next analyst does not
re-merge the aliases from name similarity.

**Migration hypothesis template (after a market closure):**

```
closure_event       venue, date_utc, type: seizure | voluntary shutdown | suspected exit scam
                    (P08 tags closures in these three classes), evidence for the type
old_alias           (handle, venue), first/last observed, key fingerprint(s), product mix
window              search window after closure (state it; no universal value)
venues_crawled      list + crawl dates — absence elsewhere is limited to these
candidates[]        (handle, venue), first observed, key fp, key created, signed msgs,
                    product/shipping overlap, announcement source (origin vs mirror)
per candidate       rung reached, competing hypotheses, likelihood, confidence
status              migrated (L2+) | probable successor | impostor suspected
                    | no successor found in crawled venues | insufficient
```

Context, not rules: P08 observed sellers listing on several markets and "moving" after
takedowns, multi-market aliases becoming common only after the Fall 2013 closures, and
market composition settling about 2–3 months after a takedown or scam — in their
2011–2015 data. Use these to frame hypotheses, not as expected timelines.

**Abstain:** only L0 evidence, or the new venue was never crawled → INSUFFICIENT.

### Worked Example — `example_vendor` After a Market Closure (synthetic)

```
Facts (all synthetic; days relative to closure D0):
  Market A   suspected exit scam at D0 (escrow withdrawals frozen, site gone)
  example_vendor@MarketA   observed D-400..D-2 in 9 crawls; key FPR-EXAMPLE-0001
                           (created D-420); 6 signed announcements D-300..D-10 verify
  example_vendor@MarketB   first observed D+5; displays FPR-EXAMPLE-0001
  Example_Vendor_Official@MarketC   first observed D+9; displays FPR-EXAMPLE-0002
                           (created D+8), photos identical to archived Market A listings
  Forum F thread D+6 announces "moving to B and C"; site G shows the same thread

Step 1 — Measurement
  Market A feedback mandatory; 1,240 unique feedback after dedup. Last two crawls:
  M=1,100, n=1,180, m=1,050 → F̂ ≈ 1,236 ≈ observed → coverage good for that window.
  → "≥1,240 orders (feedback items) D-400..D-2; one unit assumed per feedback."
  Market B feedback optional → "volume not estimable".
  Site G: same post IDs and timestamps as Forum F → scraped mirror → ONE source.

Step 2 — Reviews
  Market B shows 14 "vouch" reviews D+6..D+7; all mention review copies; 11 reviewer
  accounts registered D+5..D+6 → appraisal type, independence FAILED → excluded from
  volume and legitimacy.

Step 3 — Linkage B
  L1: full fingerprint matches.  L2: D+6 message on Market B, naming Market B and the
  Forum F challenge phrase, verifies under FPR-EXAMPLE-0001; key creation D-420 predates
  Market A first sighting; old signed history verifies.
  Competing: H_shared (crew key) and H_sold not excluded; H_imp needs the private key
  → inconsistent with the fresh signature.
  → Linked at L2: very likely the same key-holder (moderate confidence: single key,
    no independent wallet or ops link). L3/L4 NOT claimed.

Step 4 — Linkage C
  Name similar (L0); key created D+8, no cross-signature by FPR-EXAMPLE-0001; photos
  copyable from archives.  H_imp best fits; H_same inconsistent with the new key.
  → NO LINK SUPPORTED; impostor suspected. Recorded so it is not re-merged.

Step 5 — Stylometry check
  Candidate set {A, B, C aliases}; texts are templated listing copy, < 10 posts each
  → ABSTAIN (insufficient text, shared boilerplate).

Step 6 — Warning record
  Market B listing D+7 "access to a hosting panel at a *.example provider" →
  CASE-0001-W-001, actor_role vendor, corroboration claim-only, no named target org
  → landscape note, not a client warning.

Conclusion (as reported):
  "example_vendor on Market B is very likely controlled by the holder of the key used by
  example_vendor on Market A (moderate confidence). Whether that holder is one person
  or a crew is undetermined. Example_Vendor_Official on Market C shows no supported link
  and is assessed as a likely impostor. No individual is identified. Market B sales
  cannot be estimated from its optional feedback."
```

### OPSEC Assessment for Investigators

```
Risk levels by activity:
  LOW RISK (no Tor needed):
    - Ahmia.fi clearnet search
    - ransomwatch API queries
    - DDoSecrets browsing
    - DarknetLive directory browsing

  MEDIUM RISK (use Tor Browser, isolated VM):
    - Visiting .onion marketplaces or forums
    - onionsearch queries routed through Tor
    - Browsing ransomware group leak sites directly

  HIGH RISK (use Tails OS or Whonix, air-gapped preferred):
    - Creating accounts on dark web forums
    - Interacting with threat actors
    - Downloading files from .onion sites
    - OnionScan probing (active enumeration; may alert operators)

Absolute rules:
  - NEVER access .onion sites from personal or corporate networks without Tor
  - NEVER create accounts on dark web forums for investigation purposes
  - NEVER download executables from dark web sources to connected systems
  - NEVER screenshot content that contains your hostname, username, or IP
```

### Evidence Collection Standards

```
For incident response and legal proceedings:
  1. Hash files immediately after capture (SHA-256)
     sha256sum screenshot.png > screenshot.png.sha256

  2. Record metadata: date, time (UTC), URL, tool, investigator ID

  3. Dark web pages disappear rapidly — capture immediately:
     - Full-page screenshot (browser: Ctrl+Shift+S in Firefox)
     - Local wget mirror (for static pages)
     - Video screen capture for dynamic/JS-heavy pages

  4. Chain of custody: inside a case, `capture_evidence` / `capture_screenshot` append to the
     implemented log `cases/<case>/evidence/custody.jsonl` (utc, action, actor, item, sha256,
     note, prev-hash chain); manual hand-offs via `wp_capture.py --custody transfer|export|cite`.
     Outside the tooling, keep the same fields by hand:
     [UTC timestamp] | [URL] | [Tool] | [Investigator] | [File hash]
     2024-03-15T14:22:00Z | http://exampleonionaddr.onion/post | browser | analyst1 | sha256:abc...
     Standard: handbook/collection-preservation.md §6.
```

---

## 6. Confidence Ratings

| Finding Type | Confidence | Notes |
|---|---|---|
| Ransomwatch victim claim | MEDIUM | Claim present; data may be fabricated or recycled |
| DDoSecrets leak dataset | HIGH | Published, verifiable data exists |
| Ahmia search result | MEDIUM | Index may be stale; .onion may be offline |
| OnionScan linked domain | HIGH | Technical evidence of server misconfiguration |
| Handle / name match alone | LOW | Copied by impostors and successors; corroborate before any link |
| Handle cross-reference + independent corroboration | MEDIUM | Corroboration must not be a mirror of the same post |
| PGP public key displayed on two aliases (full fingerprint) | MEDIUM | Public keys are copyable; shows the CLAIM of one key |
| Fresh venue-bound signature under the same key, history checked | HIGH (same key-holder) | Not same person: keys can be shared, stolen or sold |
| PGP key → clearnet identity via keyserver UID | LOW–MEDIUM | UIDs are self-asserted; needs independent identity evidence |
| Bitcoin address cluster | MEDIUM | Heuristics-based; not definitive without exchange KYC |
| Writing style attribution | LOW | Rank within an explicit candidate set, enough text, abstention allowed [P12]; never sole basis |
| Feedback-derived order count (mandatory feedback, deduped) | MEDIUM | Lower bound only; not estimable where feedback is optional [P08] |
| Site-displayed sales counter / rating | LOW | The venue's own claim |
| Review, vouch or appraisal | LOW | Often incentivised or appraiser-driven [P10]; not volume or legitimacy |
| Threat-warning claim (claim-only) | LOW | Advertised capability ≠ verified capability [P09] |

---

## 7. Limitations

1. **Tor required for most active investigation** — Clearnet tools (Ahmia, ransomwatch, DDoSecrets) cover initial sweep; deeper work requires Tor Browser or proxy
2. **Ahmia index staleness** — Crawled `.onion` sites may be offline; index lags by days to weeks
3. **AIS spoofing analog** — Dark web operators frequently rotate `.onion` addresses; cached URLs may be dead
4. **ransomwatch false positives** — Some ransomware groups exaggerate or fabricate victim lists for reputational pressure; always verify with organization
5. **Jurisdiction variability** — Accessing certain dark web content (weapons, CSAM, controlled substances) is illegal regardless of investigative intent in many jurisdictions; know your legal authority
6. **OnionScan maintenance** — Repository has not received major updates; some checks may be unreliable against modern `.onion` v3 addresses
7. **Evidence admissibility** — Screenshots of dark web content may face chain-of-custody challenges in legal proceedings; engage legal counsel early
8. **Measurement coverage** — Crawls of unreliable markets are partial; counts are lower bounds, the most recent window is the least complete, and venues not crawled yield "no observation", not "absent" [P08]
9. **Stylometry is closed-set** — It ranks supplied candidates and cannot tell you the author is outside the set unless you use an abstention threshold; short or templated text makes it unusable [P12]

---

## 8. Command Reference

| Command | Purpose | Input |
|---|---|---|
| `/darknet-search [keyword]` | Search dark web indexes for keyword | Organization name, domain, or term |
| `/ransomware-check [org]` | Check ransomware victim claims | Organization name or domain |
| `/onion-scan [url]` | Scan .onion service for OPSEC leaks | `.onion` URL |

---

*Darknet Investigation Module v1.1.0*
*Part of Free OSINT Expert Skill - Phase 5*
*For authorized investigation and educational purposes only*
