# Username OSINT Module

> **Module ID:** USR-OSINT-001
> **Version:** 1.1.0
> **Phase:** 5 - Enhancement Modules
> **Classification:** Cross-Platform Username Enumeration & Profile Correlation

---

## 1. Overview

Username OSINT discovers accounts across platforms using a single handle. Use when a target's username or alias is known and cross-platform presence needs mapping. Combines automated scanning with manual verification to build a digital footprint.

**Key use cases:** Alias tracking, platform correlation, activity timeline reconstruction, alt-account discovery.

---

## 2. Tool Inventory

### Primary — Maigret (3000+ sites)
```bash
pip3 install maigret
# or
pipx install maigret
```

### Secondary — Sherlock (400+ sites)
```bash
pipx install sherlock-project
# or
pip3 install sherlock-project
```

### Tertiary — Blackbird (600+ sites, async)
```bash
pip3 install blackbird-osint
```

### Web Fallback — WhatsMyName
- URL: https://whatsmyname.app
- Repo: https://github.com/WebBreacher/WhatsMyName
- No install required; browser-based or API-accessible

---

## 3. Investigation Workflow

```
Step 1: Normalize target username
  └─ Strip spaces, special chars; note common variants (underscores, dots, numbers)

Step 2: Run Maigret (widest coverage)
  └─ Use --top-sites 500 for speed vs. --all-sites for coverage

Step 3: Run Sherlock in parallel (different site list)
  └─ Cross-references sites Maigret may miss

Step 4: Run Blackbird for social-focused sites
  └─ Better at newer platforms (TikTok, Clubhouse, etc.)

Step 5: Manual spot-check top hits
  └─ Confirm profile photo, bio, posting style matches target

Step 6: Document and correlate findings
  └─ Grade each link on the claim ladder (§7.1): string match, same controller,
     same person, named identity are separate claims with separate evidence
```

---

## 4. CLI Commands & Expected Output

### Maigret
```bash
# Top 500 sites, JSON output
maigret <username> --top-sites 500 --json maigret_results.json

# All sites (slower, ~3000)
maigret <username> --all-sites --folderoutput ./results/

# With proxy (Tor)
maigret <username> --top-sites 500 --tor
```

**Expected output:**
```
[+] Checking username "johndoe" on 500 sites
[+] Twitter: https://twitter.com/johndoe
[+] GitHub: https://github.com/johndoe
[-] Facebook: Not found
[*] Reddit: Claimed (unverified)
...
[*] Found 47 accounts. Report saved: johndoe.json
```

### Sherlock
```bash
# Standard scan with JSON output
sherlock <username> --output sherlock_results.txt --print-found

# Multiple usernames
sherlock user1 user2 user3 --print-found

# Skip NSFW sites
sherlock <username> --nsfw
```

**Expected output:**
```
[*] Checking username "johndoe" on: Twitter
[+] Twitter: https://twitter.com/johndoe
[+] Instagram: https://www.instagram.com/johndoe/
[*] GitHub: https://www.github.com/johndoe
```

### Blackbird
```bash
# Basic scan
blackbird -u <username>

# Export JSON
blackbird -u <username> --json

# Email-based search
blackbird -e user@example.com
```

---

## 5. Fallback Cascade

```
Maigret unavailable?
  └─> Use Sherlock (pip3 install sherlock-project)

Sherlock unavailable?
  └─> Use WhatsMyName web UI at whatsmyname.app

No CLI tools?
  └─> Manual Google dorking:
        inurl:<username> site:twitter.com
        inurl:<username> site:instagram.com
        "<username>" profile -site:google.com

API rate-limited?
  └─> Add --timeout 10 --retries 2 flags
  └─> Use --tor for Maigret to rotate exit nodes
```

---

## 6. Output Interpretation

### Claim Status Meanings
```
[+] Found/Claimed   → Account confirmed active with content
[*] Available       → Username not taken on that platform
[-] Not Found       → No account OR profile is private/deleted
[!] Error           → Timeout, captcha, or platform change
```

### False Positive Handling
```
Common false positives:
  - 404 pages that still return HTTP 200
  - Deleted accounts with cached profile URLs
  - Username squatting (empty accounts)

Verification steps:
  1. Open URL manually — check for profile photo, bio, posts
  2. Confirm content matches target's known interests/language
  3. Check join date vs. known target activity timeline
  4. Cross-match profile photo via reverse image search (TinEye/Google)
  5. Look for cross-links (e.g., Instagram bio linking to known Twitter)
```

### Cross-Platform Correlation
```
Correlation signals (each is support for a §7.1 rung, never proof on its own):
  - Platform-authored cross-links, ideally bidirectional (A's bio → B and B's bio → A)
  - Same profile photo across platforms — only if reverse search finds no earlier
    source; a copied or stock photo is an impersonation/bulk-account tell, not a link
  - Same bio text / phrasing — trivially copied; weigh like a photo
  - Matching post timestamps (activity overlap) — check timezone, not just overlap
  - Cross-posted content or reposts — reposts are also what fans and clones do
  - Same follower/following relationships — community overlap produces false
    matches; apply §7.4 before citing
  - Geotags in same locations
```

---

## 7. Identity Linkage Standards

Operating rules for turning enumeration hits into identity claims. Sources: username
uniqueness and linkage [P14 Perito et al., PETS 2011]; stylometric author identification
[P12 Narayanan et al., IEEE S&P 2012]; graph-topology de-anonymisation [P13 Narayanan &
Shmatikov, IEEE S&P 2009]; bulk fraudulent account markets [P11 Thomas et al., USENIX Sec
2013]; competing hypotheses [B05 Heuer, Psychology of Intelligence Analysis, CIA CSI 1999].
Every numeric result below is quoted with its paper and dataset; none is a threshold for
your case. Likelihood terms and ACH format follow `handbook/analytic-standards.md`.

### 7.1 Claim Ladder

Four separate claims. Climb one rung at a time; each rung needs its own evidence and gets its
own confidence. A lower rung never implies a higher one.

| Rung | Claim | Evidence that can carry it | Does NOT carry it | Abstain wording |
|---|---|---|---|---|
| **L1 String** | The same (or near-variant) handle exists on platforms X, Y, Z | Manually verified hit (§6), archived capture, persistent platform ID recorded | Tool-only hit; "available"/error status | "Handle not confirmed on X" |
| **L2 Same controller** | Accounts X, Y, Z are operated by one party | Platform-authored cross-links (bidirectional strongest); same verified email/phone on both; OAuth/linked-account listing; account self-statement; shared persistent ID | Handle match alone, however rare (§7.2); shared photo/bio; contact overlap alone (§7.4); stylometry alone (§7.3) | "Common control not established" |
| **L3 Same person** | That party is one individual, continuously, across the time window of interest | L2 plus continuity: no transfer tells (§7.5) inside the window, consistent timezone/language/behaviour, stylometry as support only | Account age or early history when a control change cannot be excluded; team/role/shared accounts | "Controller continuity not established for <window>" |
| **L4 Named identity** | The individual is legal person N | L3 plus an independent record binding the account to N: self-disclosure on a real-name surface the account controls, official/court record, platform/legal process | Name-shaped handle (P14 found most Google-profile usernames in its sample contained part of the owner's name — that is a lead to *test*, not a binding); people-search aggregators; a commit name | "Real identity not established" |

Rails: a person-level claim (L3/L4) in a report requires an ACH matrix (§7.6 template); never
name a third party on L1 evidence; a near-variant handle (edit distance > 0) starts at L1 only
after the variant is graded in §7.2.

### 7.2 Handle Rarity Check

**Source boundary.** [P14 Perito et al., PETS 2011] estimate a username's probability with a
character-level Markov chain (5-grams, trained on ~10M eBay + Google usernames) and convert it
to *information surprisal* `I(u) = −log2 P(u)`; a handle is unique in a population of W users
when `I(u) > log2 W`. They extend this to "username couples" (Psame) for non-identical handles,
weighting by how much information the shared part carries and how likely the edit is. In their
data string length correlated strongly with the Markov estimate (Pearson 0.801), and linked
pairs had a smaller edit distance than random pairs (mean 4.2 vs 12 in their Google-profile
sample). Limits they state: ground truth came from users who chose to list linked accounts
(likely less privacy-minded); privacy-sensitive services (dating, medical) were not tested;
users who pick unrelated names defeat the method; "an almost perfect username match does not
always indicate that the two usernames belong to the same person". We do **not** run their
model; the grading below is an (adaptation). Steps 1–2 are automated, string-only, in
`pivot_suggest.py :: handle_rarity` (data: `scripts/references/handle_rarity.json`), which caps
the priority of username-reuse/variant pivots by grade; step 3 and the confounders stay manual.
Brand/platform handles with generic parts (`binance_support`), public-figure-name handles and
mostly keyboard-walk handles (`qwertyuiop`) grade GENERIC — the impersonation handles common in
scam cases. That lowers pivot priority, not identity confidence; deliberate copying of a
distinctive handle still needs the population check (step 3).

**Trigger:** before any handle match is given weight in a linkage, crossref score, or report.
**Inputs:** the handle(s), the platforms, U-01 leet-normalised form (`analysis/pattern-library.md`).

1. Normalise (case, separators, leet) and split into tokens: dictionary words, given/family
   names, digits, random-looking runs.
2. Grade (adaptation):
   - **GENERIC** — dictionary word, common first/last name, name+name, name+2–4 digits (P14
     observed trailing digits often look like birth years — treat as a lead, not a DOB),
     platform-default patterns (`user12345`), very short handles. **No linkage weight.**
   - **MODERATE** — compound of common tokens with an unusual join or suffix. Lead only.
   - **RARE** — long, multiple uncommon tokens or high-variety character-class transitions,
     no common-name skeleton. Strong *lead* for L2; still not L2.
3. Population proxy (adaptation): count exact-match hits across unrelated contexts (different
   languages, regions, interests). Many unrelated owners ⇒ downgrade, whatever step 2 said.
4. Variants: grade the **shared** part, not the full string; a variant whose shared part is
   GENERIC carries nothing (P14's `alice`/`malice` vs `vonneumann`/`jvonneumann` point).

**Output:** grade + one-line reason, e.g. `RARE — two uncommon tokens, 1 exact hit set, all same niche`.
Never write a probability for a specific handle ("1-in-a-billion", "99% same person") — P14's
numbers are population estimates from one training corpus.

**Confounders:** rarity does nothing against *deliberate* copying (impersonation, squatting,
fan or parody accounts — a rare handle is the one worth copying); bulk-account generators
produce long, odd-looking handles from templates (§7.5); platform-suggested names; recycled
handles (§9 item 2); transliteration of non-Latin names (P14 restricted to a–z).
**Abstain** when GENERIC, when step 3 shows multiple owners, or when an actor has motive to
imitate the persona — report "handle match carries no linkage weight".

### 7.3 Stylometry (Supporting Signal Only)

**Source boundary.** [P12 Narayanan et al., IEEE S&P 2012] ranked 100,000 blog authors using
topic-independent features (word/char length, vocabulary richness, letter/digit/punctuation
frequencies, 293 function words, syntactic-category pairs), after stripping signatures,
markup and duplicated posts. On their corpus (mean ~305 words/post): with 3 test posts the
correct blog ranked first in ~20% of trials and top-20 in ~35%; one post gave ~7.5%; accuracy
was poor with fewer than ~7–10 known samples per author. Confidence came from the **gap
statistic** (best vs second-best match distance) and from two classifiers agreeing; refusing
to answer below a threshold raised precision from ~20% to >80% at half the recall.
Cross-context (two blogs, same author) was weaker (~12% top-1). They did **not** test
cross-domain text (blog vs e-mail), deliberate obfuscation, or small-author forensic settings.
Short chat posts, translated or machine-translated text and AI-written or AI-edited text are
outside anything P12 validated.

**Trigger:** two pseudonymous text bodies need a behavioural link *after* L2 evidence was sought.
**Preconditions (all, else abstain):** an enumerated candidate set (closed list of known
authors); enough text per candidate and in the questioned set, split into several samples;
comparable genre, register and language; text written by the account holder (not quoted,
templated, translated or generated).

1. Strip signatures, quotes, boilerplate, templates, code, URLs.
2. Compare on topic-independent features only; topic words make the match about subject, not author.
3. Rank candidates; record the gap between rank 1 and rank 2 and whether a second method agrees.
4. Allow `⊥` — "none of the candidates" — as a first-class outcome.

**Output:** `consistent with candidate X (gap: large/small, methods agree: y/n)` ·
`not distinguishable among X, Y` · `none of the candidates` · `not assessable (precondition N failed)`.
**Weight:** support for L3 only; never establishes L2 or L4 and never stands alone in ACH.
**Confounders:** shared community idiom, ghostwriters and team accounts, copy-editing tools,
deliberate style change, the true author missing from the candidate set (a ranker always
returns *someone* — P12's narrowing to a shortlist is not identification).

### 7.4 Graph Linkage (Contacts, Follows, Co-membership)

**Source boundary.** [P13 Narayanan & Shmatikov, IEEE S&P 2009] re-identify nodes across two
social graphs from topology alone: a few **seed** mappings, then **propagation** scoring each
candidate by mapped-neighbour overlap, with degree normalisation (high-degree nodes otherwise
win), an **eccentricity** test (the best score must stand out from the second best) and a
**reverse match** (the mapping must also hold with the graphs swapped). On Twitter vs Flickr,
weighted by centrality: 30.8% correct, 12.1% wrong, 57% not identified. Of the wrong mappings,
41% landed on a node one hop from the true one and 55% on a node reporting the same location —
overlap pulls matches toward friends and look-alikes. Too few seeds and propagation dies; early
mappings were less accurate. Their ground truth itself was built from username/name matches
scored by length and name rarity.

**Trigger:** "account B follows/knows the same people as account A" is offered as linkage.
**Inputs:** contact sets of A and B; the candidate pool (A's closest contacts are candidates too).

1. Drop hubs (celebrities, official accounts, the community's big names) — degree normalisation (adaptation).
2. Score overlap for B **and** for A's closest contacts; B must stand out clearly (eccentricity, adaptation).
3. Reverse check: starting from B's contacts, does A come out top?
4. Require one independent non-graph item (L2 evidence) before asserting common control.

**Output:** `graph-consistent, corroborated by <item>` or `graph overlap only — lead`.
**False-match risk:** partners, co-workers, team members and sock puppets run *by someone else*
in the same circle all show high overlap; dense niche communities make overlap uninformative
(score `N` in ACH). **Abstain** when the pool was not enumerated or B does not stand out from
A's neighbours. **Privacy:** contact lists expose third parties; record counts and the minimum
named contacts needed, never publish full lists. Anomaly heuristics for coordinated clusters
live in `techniques/fx-social-topology.md`.

### 7.5 Account Trafficking Confounder

**Source boundary.** [P11 Thomas et al., USENIX Sec 2013] bought 120,019 Twitter accounts from
27 merchants over ten months (2012–13). In that market accounts were cheap and delivered in
bulk (about $0.02–0.10 each), e-mail-confirmed with fraudulent webmail addresses, registered
from diverse IPs with CAPTCHAs solved; **"pre-aged"** stock was a selling point (one merchant's
accounts had a median age of 323 days); 10% of purchased accounts were logged into again after
sale (median 3 days) and 6% were resold. Merchants were detectable by **naming patterns**
(character-class sequences, name and screenname built from the same tokens, `WendyHunt5`-style),
signup-flow events, user-agent uniformity and form timing — and several merchants shared
patterns (common registration software or resale between merchants). Phone-verified accounts
cost more on other services. Figures are Twitter-only and dated; use them as mechanism, not rate.

**Consequence:** an account's age, creation date and early history describe whoever held it
*then*. Purchase, resale, compromise and handover break history-based attribution.

**Trigger:** any L3 argument that uses account age or past activity; any set of accounts that
look template-made.
**Tells (adaptation):**
- Creation bursts: sibling accounts created within hours/days, similar handle templates.
- Template naming: first+last+digits with an identical character-class shape across a set;
  display name and handle built from the same tokens.
- Dormancy then repurposing: a long silent gap, then new language, topic, timezone or audience.
- Profile rewrite on reactivation: handle rename (persistent ID unchanged — see
  `techniques/social-media-platforms.md` §2.3), new bio/photo, mass deletion of old posts.
- Followers that do not fit the content; stock or stolen photos; mass-webmail recovery e-mail.

**Steps:** build the account timeline; cut it into **control epochs** at every tell; attribute
inside an epoch only; treat each epoch as a separate controller until continuity evidence spans
the boundary. **Abstain** from carrying any conclusion across an epoch boundary you cannot date
or bridge — report "controller after <date> undetermined".

### 7.6 Worked Example (synthetic)

CASE-0001. Handle `quillfox_exmpl` on forum A (`forum.example`), code host B (`code.example`),
social C (`social.example`). Question: who controls each account, and who is the person?

```
L1  Verified on A, B, C (manual review, captures stored).                     ESTABLISHED
    Rarity (§7.2): RARE — two uncommon tokens + unusual suffix; exact hits only
    on these 3 accounts, all in the same niche.                               lead, not L2
L2  B <-> C: B profile links to C, C bio links to B (bidirectional,
    platform-authored).                                     very likely same controller
    A <-> B/C: A's 2019-2020 posts link to B's repositories; B and C never
    mention A (one-directional).                            tested below (ACH)
L3  A timeline: created 2019, active 2019-01..2021-01 in B's tool niche;
    dormant 2021-01..2024-03; reactivated 2024-03 in another language,
    unrelated topic, bio and photo replaced.                -> two control epochs (§7.5)
    C follows 6 of A's forum contacts, all inside a ~200-member niche
    community (§7.4: overlap uninformative).
    Stylometry (§7.3): A = one-line forum posts, B = commit messages
    -> genre mismatch, short text                           NOT ASSESSABLE
L4  B commit e-mail quillfox@mail.example — a mailbox, not a legal identity;
    no real-name surface found.                             INSUFFICIENT — abstain
```

```
Question: is forum account A (current epoch) controlled by the party behind B/C?

H1  Same party throughout
H2  Same party until 2021; control changed (sold, compromised, handed over)
H3  Never the same party (independent choice of the handle)
H4  Created to imitate the B/C persona

Evidence                                                  H1  H2  H3  H4  Diagnostic?
E1 Identical handle on A, B, C                             C   C   C   C   NO -> N
E2 Handle graded RARE, no other owners found               C   C   I   C   vs H3 only
E3 A's 2019-20 posts link to B repos, same niche           C   C   I   C   vs H3 only
E4 3-year dormancy, then language/topic/profile change     I   C   N   N   yes
E5 B/C never link back to A                                N   N   C   C   weak
E6 Contact overlap inside a dense niche community          N   N   N   N   NO
E7 Stylometry not assessable (absence)                     N   N   N   N   NO

Inconsistencies:  H1=1   H2=0   H3=2   H4=0

Assessment:
  A, 2019-2021 epoch: LIKELY same controller as B/C (55-80%), moderate confidence —
    rare handle plus A's own links; B/C never reciprocate, so H4 stays open.
  A, 2024- epoch: NO DETERMINATION. H2 and H4 tie at zero inconsistencies; H1 is
    unlikely (E4). Do not carry B/C attribution onto current A activity.
  Person (L3 across all accounts) and named identity (L4): insufficient — abstain.
Runner-up: H4 for the 2019-2021 epoch.
Would change the ranking: B or C acknowledging A; A's current epoch reusing B's
verified e-mail or signing key; platform ownership records via legal process.
```

---

## 8. Confidence Ratings

Rate the claim the evidence supports (§7.1 rung), not "the target".

| Finding Type | Confidence | Claim it supports | Verification Method |
|---|---|---|---|
| Username found on major platform | HIGH | L1 only | Manual profile review |
| Username found on niche site | MEDIUM | L1 only | Cross-check photo/bio |
| Maigret-only result (no manual check) | LOW | none until verified | Always verify manually |
| RARE handle on several platforms (§7.2) | LEAD | toward L2 | Seek L2 evidence |
| GENERIC handle on several platforms | NONE | nothing | — |
| Bidirectional platform-authored cross-link | HIGH | L2 | Capture both profiles |
| Cross-platform photo match | MEDIUM | L2 support | Reverse search: no earlier source |
| Same bio text match | MEDIUM | L2 support | Direct comparison; check for copying |
| Contact/follow overlap | LOW | L2 support | §7.4 eccentricity + reverse check |
| Stylometric consistency | LOW | L3 support | §7.3 preconditions met |
| Activity timeline overlap | MEDIUM | L3 support | Timezone/language check; §7.5 epochs |
| Deleted/suspended account evidence | MEDIUM | L1 (historical) | Archive.org, cached pages |

---

## 9. Limitations

1. **Private accounts** — Many platforms hide content; existence detectable but not content
2. **Username recycling** — Platforms reassign inactive usernames; old hits may be wrong person
3. **Rate limiting** — Aggressive scanning triggers CAPTCHAs or IP bans; use delays
4. **Site list drift** — Maigret/Sherlock site databases go stale as platforms change APIs
5. **Common usernames** — "johndoe", "admin", "user123" produce massive false positive noise
6. **Regional platforms** — VK, Weibo, Naver poorly covered by Western tools; check manually
7. **Tor dependency** — --tor flag requires Tor service running locally (`systemctl start tor`)
8. **Account trafficking** — bought, aged, resold or compromised accounts carry someone else's history (§7.5)
9. **Untested text types** — stylometry is not validated on short posts, translated or AI-written text (§7.3)

---

## 10. Command Reference

| Command | Purpose | Input |
|---|---|---|
| `/username [handle]` | Full cross-platform username scan | Username string |
| `/username-variants [handle]` | Generate and scan common variants | Base username |
| `/username-report [handle]` | Compile correlation report | Username string |

---

*Username OSINT Module v1.1.0*
*Part of Free OSINT Expert Skill - Phase 5*
*For authorized investigation and educational purposes only*
