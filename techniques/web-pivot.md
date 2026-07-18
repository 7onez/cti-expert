# Web Infrastructure Pivoting — `/webpivot`

Turn a single web page into a set of **pivot points** — the artifacts in its
HTML/DOM/headers that link it to other sites, infrastructure, and actors — and the
exact queries to run them. Built for authorized OSINT, anti-fraud/anti-scam, phishing
takedown, brand protection, and threat-infrastructure investigation.

Integrated from the **WebPivot** toolkit by **[Zeroska](https://github.com/Zeroska)**, adapted for cti-expert. Tools live in `$SKILL_DIR/scripts/webpivot/`
(`$SKILL_DIR` = the dir containing this skill's `SKILL.md`; Claude Code:
`~/.claude/skills/cti-expert`). The core is **stdlib-only** — run everything with `uv`.

## When this fires

- "analyze this site / page / HTML / DOM", "what can I pivot on here"
- "find related / sibling domains", "who else runs this", "same operator?"
- "is this a phishing kit / scam cluster", "cluster these URLs / campaign"
- "reverse this GA / GTM / AdSense / pixel ID", "favicon hash for pivoting"
- "trace this scam site's infrastructure / wallet"

## The `/webpivot` command surface

| Invocation | Runs | Purpose |
|---|---|---|
| `/webpivot <url>` | `pivot_extract.py <url> --leads` | ranked pivots for one page (add `-o` to save to the case) |
| `/webpivot <url> --render` | `pivot_extract.py --render` | render a JS-heavy SPA first (needs playwright) |
| `/webpivot <url> --crawl [N]` | `pivot_extract.py --crawl N` | walk same-site nav/tabs and merge artifacts |
| `/webpivot <domain> --history` | `wayback_ga.py <domain> --timeline` | scrubbed GA/AdSense IDs across Wayback (Bellingcat) |
| `/webpivot <domain> --whois` | `whois_enrich.py <domain>` | current + historic + reverse WHOIS (needs key) |
| `/webpivot --graph <case>` | `graph_build.py <case>/raw/*.json` | cluster many pages into one link graph |
| `/webpivot --rank <case>` | `rank_relations.py <case>/raw/*.json` | score + rank same-operator relations (noise-filtered) |
| `/webpivot <domain> --cert` | `cert_pivot.py <domain>` | pivot the TLS cert fingerprint → other hosts + SAN siblings |
| `/webpivot --suggest <case>` | `pivot_suggest.py <case>/findings.json` | ranked "what to pivot on next" from findings |
| `/webpivot --wallets <case>` | `crypto_balance.py <addr…>` | on-chain balance/flow for discovered wallets |
| `/webpivot --paths <list>` | `sensitive_paths.py --file <index>` | classify Wayback/URL list for sensitive paths |

All map to the tools documented below; `$SKILL_DIR` = `~/.claude/skills/cti-expert`.
`/rank-relations`, `/cert-pivot`, `/pivot-suggest`, `/crypto-balance`, `/email-hygiene`,
and `/sensitive-paths` are top-level aliases for the same tools.

## Authorization first (read before touching live infrastructure)

1. **Scope & basis.** You must have a legitimate basis: your own assets, a written
   engagement, published abuse/threat-intel work, or infrastructure targeting you or
   your constituents. When unsure, stop and confirm.
2. **Attribution risk.** `pivot_extract.py` fetches the target **directly** — the target
   sees your IP and User-Agent. For adversarial infra, either use **non-attributable
   egress** (research VPS / VPN, or `--proxy` / `--proxy-range`) **or stay passive**: pull
   the DOM from **urlscan.io / Wayback / a prior scan** and feed the saved HTML to the
   harness. Passive is the default for hostile targets.
3. **Passive OSINT only.** Reads publicly served content and public reverse-lookup
   indexes. Not for intrusion, credential access, exploitation, DoS, or evading access
   controls — and no bypassing paywalls/logins/CAPTCHAs.
4. **Minimize.** Personal data (emails, phones, handles) is incidental to infrastructure
   pivoting — retain minimally, don't redistribute, handle per your data-protection duties.
   Cluster **infrastructure/operators**, don't dox individuals.

## The tools (`uv run`, zero required deps)

Runner (any OS): `uv run "$SKILL_DIR/scripts/webpivot/<tool>.py" <args>`. The core runs on
the Python 3 stdlib; optional accelerators are `requests` (fetch) and `playwright`
(`--render` post-JS DOM). The Shodan-style favicon `mmh3` hash uses a bundled pure-Python
MurmurHash3 — no `mmh3` package needed.

### 1. `pivot_extract.py` — the extraction engine

```bash
WP="$SKILL_DIR/scripts/webpivot"
# Analyze a live page → full artifact + ranked-pivot JSON, saved to the case
uv run "$WP/pivot_extract.py" https://suspicious-site.example --pretty -o "<case>/raw/suspicious-site.example.json"
# Just the ranked pivot leads (markdown, high→low confidence)
uv run "$WP/pivot_extract.py" https://suspicious-site.example --leads
# Render a JS-heavy SPA before extraction (needs playwright + chromium)
uv run "$WP/pivot_extract.py" https://spa.example --render --leads
# Offline: analyze saved HTML, or pipe from stdin / another scraper
uv run "$WP/pivot_extract.py" saved_page.html --pretty
curl -s https://x.example | uv run "$WP/pivot_extract.py" -
```

- **`--crawl [MAXPAGES]` / `--crawl-depth N`** — also follow the site's nav/tabs/panels on
  the **same registrable domain** and merge every page's artifacts into one result.
  `meta.crawled` lists pages fetched. Works with `--render`.
- **`--rotate-ua` / `--ua "<s>"` / `--proxy URL` / `--proxy-range SPEC`** — stay low-profile
  while crawling. Rotation applies to target-site fetches; third-party enrichment
  (crt.sh/urlscan/FOFA/WhoisXML) stays on a direct path. No proxy flag → direct connection.
- **Redirect & affiliate analysis** — records the full redirect chain
  (`meta.redirect_chain`) + final host, and extracts affiliate/referral/campaign codes
  (`affid`, `ref`, `partner`, `utm_*`, base64 auto-decoded) as MEDIUM pivots with
  source-search queries → find **where the promoter advertises the link**.
- **`--save-dom PATH` / `--submit`** — store the collected DOM and actively archive the URL
  (Wayback Save-Page-Now + urlscan.io scan; urlscan needs `URLSCAN_API_KEY`).
- **`--whois-reverse`** — reverse-WHOIS by registrant **email and name**, current + historic
  (a shared registrant name can cluster sites that share no technical artifact).

**What it extracts** (full table → [`handbook/pivot-artifacts.md`](../handbook/pivot-artifacts.md)):
favicon mmh3/md5/sha256, analytics & ad IDs (GA4 `G-`, `GTM-`, AdSense `pub-`, FB Pixel,
Yandex, Hotjar, Matomo, Sentry DSN…), crypto wallets (BTC/ETH/XMR/TRON/LTC), emails, social
handles, third-party hosts, inline-script SHA-256, form actions + input names (phishing-kit
tell), HTML comments, DOM-skeleton hash (template reuse), tech fingerprints, cookie names,
server headers, and **SaaS / no-code operator tokens** (GoHighLevel `msgsndr` location ID,
backend Google Sheet ID, Make/Zapier/Apps-Script webhooks, TrustedForm lead-cert) —
attribution-grade for hosted-builder funnels, fully present only in the `--render` DOM.

**What it emits:** a `pivots` array ranked high→low confidence, each with copy-paste queries
for the right engine and the **correct hash algorithm per engine** — Shodan/FOFA/ZoomEye =
**mmh3**, Censys = **MD5**, Netlas = **SHA-256** (all three emitted from one favicon).

### 2. `wayback_ga.py` — historical analytics (Bellingcat method)

Walks a domain's *entire Wayback history* and extracts every GA/GTM/AdSense/verification ID
ever present — catching shared IDs a network later scrubbed. Passive (only touches
web.archive.org). Reuses `pivot_extract`'s extractors.

```bash
uv run "$WP/wayback_ga.py" suspect.example --max 15 --timeline
uv run "$WP/wayback_ga.py" -f domains.txt --pretty > "<case>/history.json"
```

### 3. `whois_enrich.py` — registration pivots (needs `WHOISXML_API_KEY`)

Current WHOIS, WHOIS **history** (every registrant email/name ever seen — catches
pre-privacy records), and **reverse WHOIS** by registrant email or name. Registrant
email/name are top-tier same-operator artifacts. No key → every call is a no-op.

```bash
uv run "$WP/whois_enrich.py" suspect.example                  # current + history
uv run "$WP/whois_enrich.py" --reverse-email owner@x.com      # owner's other domains
uv run "$WP/whois_enrich.py" --reverse-name "Some Org" --search-type historic
```

### 4. `graph_build.py` — clustered case graph

Merges many `pivot_extract` JSONs into one normalized, **clustered** graph: typed nodes
(domains + shared artifacts as hub nodes), evidence-graded edges, connected components,
**Louvain communities**, and **betweenness centrality** — all zero-dependency. Two domains
that share an artifact both connect to its hub; that convergence is "same operator/kit" at
a glance. Requires each input JSON to carry `meta.host` (real-URL analysis sets it).

**Ranked relations are folded in by default:** `graph_build` calls `rank_relations` (§6) in the
same pass, so the output also carries a `relations` array (scored, noise-filtered same-operator
pairs), a `clusters` array, and explicit **`sibling` edges** weighted by `relation_strength`
(operator-class when `same_operator_likely`). Disable with `--no-rank`; widen with
`--rank-include-weak`.

```bash
uv run "$WP/graph_build.py" "<case>"/raw/*.json --operator "name" -o "<case>/case_graph.json"
```

Feed `case_graph.json` to the **interactive HTML report** (see
[`output/visuals/render-engine.md`](../output/visuals/render-engine.md)) or summarize it as a
Mermaid infra graph (see [`output/visuals/diagram-patterns.md`](../output/visuals/diagram-patterns.md)).

### 5. `cdn_ranges.py` — CDN/origin classifier

Classifies an IP as **CDN/cloud edge (noise)** vs **candidate origin (attribution-grade)** by
CIDR membership against published provider ranges (cache shipped co-located; `--update` to
refresh). A shared *origin* IP across two sites is a strong link; a shared *CDN* IP is not.

```bash
uv run "$WP/cdn_ranges.py" --classify 104.21.61.155 8.8.8.8
uv run "$WP/cdn_ranges.py" --update      # refresh the published-ranges cache
```

### 6. `rank_relations.py` — relation-strength ranking + noise denylist

Mechanizes **step 4 (Corroborate)** below: instead of eyeballing "do these share ≥2
artifacts?", it scores every pair of analyzed hosts by the **weighted sum of the
artifacts they share**, drops ubiquitous CDN/analytics/font infrastructure via an
editable denylist **first**, then ranks the survivors into same-operator clusters.
Pure post-processing — feed it the per-page JSON `pivot_extract` already saved.

```bash
uv run "$WP/rank_relations.py" "<case>"/raw/*.json --pretty -o "<case>/relations.json"
uv run "$WP/rank_relations.py" "<case>"/raw/*.json --md             # ranked table, high→low
uv run "$WP/rank_relations.py" "<case>"/raw/*.json --min-strength 8 # strong links only
```

**Signal weights** — a relation's `relation_strength` is the sum of its DISTINCT matched signals:

| Weight | Signals (why) |
|---|---|
| **5** | `registrant_email` · `wallet` · `tracking_id` · `verification` — operator-grade / exact private ID |
| **4** | `favicon` · `shared_cert` · `same_origin_ip` — kit or infra (origin IPs only; CDN edge IPs dropped) |
| **3** | `registrant_name` · `social` · `redirect_chain` · `dom_skeleton` |
| **2** | `same_ip` (unknown class) · `wp_theme` · `nameserver` · `reg_batch` · `email` |
| **1** | `page_link` |

**Assessment:** `same_operator_likely` (≥2 signals incl. one ≥4, **or** strength ≥8) ·
`related_probable` (strength ≥4) · else `weak_lead` (hidden unless `--include-weak`).
`clusters` = connected components over non-weak edges. The denylist
([`scripts/webpivot/data/pivot-noise-denylist.txt`](../scripts/webpivot/data/pivot-noise-denylist.txt))
is plain-text and editable; bypass entirely with `CTI_PIVOT_NOISE_DISABLE=1`.

### 7. `cert_pivot.py` — TLS cert-fingerprint pivoting

`/cert-history` time-lines a domain's **own** certs; this pivots the **fingerprint** to
find **other hosts serving the same cert** — a strong same-operator signal — and mines a
cert's **SAN list** for sibling domains. Keyless it live-fetches the leaf cert (stdlib
`ssl`, computes SHA-1/SHA-256), queries crt.sh, and emits copy-paste queries + deep-links
for Shodan/Censys/FOFA. With keys it runs the pivots live.

```bash
uv run "$WP/cert_pivot.py" suspicious-site.top --pretty
uv run "$WP/cert_pivot.py" suspicious-site.top -o "<case>/raw/cert.suspicious-site.top.json"
uv run "$WP/cert_pivot.py" --sha256 <hex>            # pivot an explicit fingerprint
```

| Key | Auto-fires | Query |
|---|---|---|
| `SHODAN_API_KEY` | leaf cert | `ssl.cert.fingerprint:<sha256>` (SHA-1 alt) → hosts |
| `CENSYS_API_ID`+`CENSYS_API_SECRET` | leaf cert | `services.tls.certificates.leaf_data.fingerprint_sha256="<sha256>"` → hosts |

### 8. `pivot_suggest.py` — ranked "what to pivot on next"

Reads a case's findings and emits **ranked pivot suggestions** so `/branch` and `/crossref`
act on concrete correlations, not guesswork. Deterministic, offline: username variants
(leet `4→a`, incremental numbering, separator, exact cross-platform reuse), email↔name
mismatch (possible alias), temporal-sync clusters (≥2 platforms in one window), and
domain TLD/stem clusters. Fuzzy match = Levenshtein for short strings, trigram Jaccard for long.

```bash
uv run "$WP/pivot_suggest.py" "<case>/findings.json" --pretty
uv run "$WP/pivot_suggest.py" --usernames "d4rkc4t,darkcat,dark_cat"   # ad-hoc, no file
uv run "$WP/pivot_suggest.py" --xref "john.doe" "johndoe"              # similarity 0–100
```

See [`analysis/auto-branch-rules.md`](../analysis/auto-branch-rules.md) for how the rules map
to the IBR/CBR branch rules and priority matrix.

### 9. `crypto_balance.py` — wallet balance / lifetime-flow enrichment

Turns a discovered wallet into on-chain intel: current balance, lifetime received/sent, tx
count, valued at spot (CoinGecko). Keyless-first public explorers (BTC→blockstream,
LTC→litecoinspace, ETH→Blockscout, TRON→Tronscan, ADA→Koios, DOT→Subscan); `BLOCKCHAIR_API_KEY`
unlocks full flows on more chains.

```bash
uv run "$WP/crypto_balance.py" 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa --pretty
uv run "$WP/crypto_balance.py" 0xABC…  --coin eth
```
See [`techniques/blockchain-investigation.md`](blockchain-investigation.md).

### 10. `email_hygiene.py` · `sensitive_paths.py`

- **`email_hygiene.py`** — deterministic 0–100 + A–F grade per email domain (disposable −60,
  no-MX −30, free −15, role local-part −10; MX via keyless DNS-over-HTTPS). A throwaway/no-MX
  sender domain on a "professional" target is itself a finding. See
  [`techniques/email-osint.md`](email-osint.md).
- **`sensitive_paths.py`** — pure classifier over a Wayback/CDX/URL list → severity-tagged
  hits (CRITICAL/HIGH/MEDIUM/LOW) + per-year timeline. Pairs with `/dork-sweep` and
  waymore/katana output to surface exposed `.git`, `.env`, backups, configs over time.

```bash
uv run "$WP/email_hygiene.py" admin@site.top ceo@site.top --pretty
waymore -i example.com -mode U | uv run "$WP/sensitive_paths.py" --stdin --severity HIGH
```

## Method (default flow)

1. **Acquire** — fetch (or `--render` for SPAs; or feed saved HTML / a urlscan DOM). Prefer
   passive capture for hostile targets.
2. **Extract** — run `pivot_extract.py`; get structured artifacts + ranked pivots.
3. **Pivot** — run the emitted queries against the engines in
   [`handbook/pivot-services.md`](../handbook/pivot-services.md). Start with HIGH-confidence
   artifacts (favicon hash, shared tracker IDs) — they most reliably reveal same-operator infra.
4. **Corroborate** — a single shared artifact is a **lead, not proof**. Confirm a cluster with
   **≥2 independent artifacts** (e.g. same favicon **and** same GA4 ID) before asserting common
   ownership. Distinguish "same kit" (reused code/template) from "same operator" (shared private
   IDs/infra) — different claims.
5. **Record** — persist per-host artifact JSON into the case workspace (see
   [`engine/workspace-manager.md`](../engine/workspace-manager.md)); build the graph; capture the
   exact artifact value + confirming query so every asserted link is reproducible.

## Workflow routing

| Request | Do |
|---|---|
| Analyze one page, get all pivots | `pivot_extract.py <url> --leads` (then `-o` to save) |
| I have an artifact (favicon/tracker/wallet) — where does it pivot? | look it up in `handbook/pivot-services.md`, run the reverse-lookup |
| Cluster many pages into campaigns / find sibling sites | extract each → `graph_build.py raw/*.json` → read communities |
| Find sites via shared/scrubbed analytics IDs over time | `wayback_ga.py <domain> --timeline` (Bellingcat) |
| Build a clustered, interactive link graph | `graph_build.py` → interactive HTML report |

## Premium tier — keys auto-upgrade the pivot (optional)

cti-expert is keyless-first; premium keys are **strictly additive**. Manage them with
**`/apikeys`** (see [`handbook/api-keys.md`](../handbook/api-keys.md)) — keys resolve
**environment first**, then the skill-root `.env` (`$SKILL_DIR/.env`, `chmod 600`, gitignored;
override with `CTI_API_KEYS_ENV`).

With keys present, `pivot_extract.py`'s `enrich_live` automatically escalates from the keyless
baseline (crt.sh + HackerTarget passive DNS + anonymous urlscan on the domain) to premium
reverse-lookups, attaching each hit to the pivot as `live_results` (shown in `--leads`):

| Key | Auto-fires on | Live result |
|---|---|---|
| `SHODAN_API_KEY` | favicon hash | `http.favicon.hash:<mmh3>` → hosts |
| `CENSYS_API_KEY` (+`CENSYS_ORG_ID`) | favicon hash | favicon **MD5** → hosts |
| `FOFA_KEY` (+`FOFA_EMAIL`) | favicon / tracker / live IP | `icon_hash` / `body` / `ip` reverse |
| `DNSLYTICS_API_KEY` | GA `UA-` / AdSense `ca-pub-` | sibling domains sharing the account |
| `SECURITYTRAILS_API_KEY` | domain | passive-DNS subdomains |
| `URLSCAN_API_KEY` | tracker / verification | authenticated DOM content search |
| `WHOISXML_API_KEY` | `--whois-reverse` | current + historic + reverse WHOIS |

Each premium enricher is **key-gated** (no key → skipped) and **exception-guarded** (a bad
endpoint/quota → an error line, never a crash). **No keys → keyless mode, byte-for-byte
unchanged.** Never commit the `.env`.

## Notes on artifact reliability (2025–2026)

- **GA `UA-` IDs are historical** (Universal Analytics shut down Jul 2023). Live artifacts are
  GA4 `G-` and `GTM-`.
- **crt.sh is frequently overloaded** — keep Certspotter / Censys as CT fallbacks.
- **Validin** is the current standout free/low-cost infra-pivot engine (DNS + certs + favicon +
  response-body hashes in one graph).
- **Chainabuse** (absorbed Bitcoinabuse) is the primary free crypto-scam DB with a public API.

## See also

- [`handbook/pivot-artifacts.md`](../handbook/pivot-artifacts.md) — what to extract + confidence + where each pivots
- [`handbook/pivot-services.md`](../handbook/pivot-services.md) — reverse-lookup engines, hash algo per engine, API/key notes
- [`techniques/scam-check.md`](scam-check.md), [`techniques/threat-intel.md`](threat-intel.md), [`techniques/blockchain-investigation.md`](blockchain-investigation.md), [`techniques/whois-universal.md`](whois-universal.md) — adjacent tradecraft
