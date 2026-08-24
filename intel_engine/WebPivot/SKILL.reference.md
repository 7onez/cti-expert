---
name: WebPivot
description: Website content & DOM analysis for OSINT and cybercrime investigation, aimed at UNMASKING THE OPERATOR behind the infrastructure — extracts pivot artifacts (favicon hash, tracking/analytics IDs, crypto wallets, emails, phones, Telegram, Google Doc/Sheet/Form IDs, ETag, WHOIS registrant, third-party infra, DOM fingerprints) and emits ready-to-run queries (Shodan, FOFA, crt.sh, urlscan). USE WHEN unmask the operator, who is the threat actor behind this, identify the operator/owner, attribute this infrastructure, find the person behind the site, analyze website/HTML/DOM, pivot artifact, favicon hash, tracking/analytics ID, GA GTM pixel, reverse analytics, telegram channel, google sheet/form, whois registrant, cluster sites, phishing kit, scam site, who owns this site, related domains, impersonation domain, typosquat, lookalike domain, TLD sweep, homoglyph, hunt lookalikes, search a selector in leaks, breach data, stealer/infostealer logs, darknet, IntelX, phonebook, find emails for a domain, has this email leaked, historical WHOIS, google ads, who advertises this domain, ads transparency, advertiser id, malvertising, cloaking, cloaked landing page, the site looks empty, utm, gclid, decoy page, SerpApi, SERP ads.
---

> **OPSEC — this skill is portable/shared. Never write case data into it.** No real operator
> names, emails, domains, IPs, wallets, tracking IDs, hashes, or case IDs in this file, its
> workflows, tool code, or test fixtures. Investigation data lives only in the git-ignored
> `cases/` / `knowledge/` / `MEMORY/`. In examples use placeholders (`example.com`,
> `G-XXXXXXXXXX`, `CASE-0001`). See the repo-root `CLAUDE.md` for the full rule.

## API keys — and the keyless disclosure rule (read before reporting any "nothing found")

**Optional API keys enable live pivoting** (`URLSCAN_API_KEY`, `FOFA_KEY`/`FOFA_EMAIL`,
`WHOISXML_API_KEY`, `PDNS_USERNAME`/`PDNS_PASSWORD`, `CENSYS_PAT`, `INTELX_KEY`, `SERPAPI_KEY`, and for IPPivot `IPINFO_TOKEN` / `SHODAN_KEY`) —
read from the environment first, then from the first `chmod 600` `.env` found: the invocation
directory, the repo root, then a skill-local `.env`. **No keys → keyless mode: every tool still
runs, nothing errors.** Full setup, what each key + urlscan-Pro unlocks, passive-DNS, and the
standalone `whois_enrich.py` tool are in **`references/Setup.md`**.

> 🔑 **RULE — say so when the run was keyless or partial.** Keyless is supported, but it is not the
> same investigation. A keyless run **extracts** every artifact and **cannot reverse** most of them:
> with no FOFA/urlscan credential the favicon-hash and tracker reverses never execute, so *"no
> sibling domains"* is a fact about the credentials, **not** about the operator. Before you present
> any negative or thin result:
>
> ```bash
> python3 "$WP/tools/wp_capabilities.py"          # which keys exist · what each absence costs
> ```
>
> 1. **Tell the user** the run's mode (`keyless` / `partial` / `free-only`), **which indexes went
>    unqueried**, and that absence of siblings is therefore not evidence of absence.
> 2. **Carry it into the deliverable** — every run already writes `meta.capability` into its JSON
>    (mode, missing keys, the lost evidence classes, and a ready-to-paste limitation statement);
>    put that statement in the assessment's collection-limitations note and cap confidence
>    accordingly. `--leads` prints it at the top; `pivot_extract` prints the banner on stderr.
> 3. **Say what would fix it** — name the one key that would most change the answer (the tool ranks
>    the absences by impact) rather than reporting a dead end.
>
> The MCP tool is `capability_check`. This applies to `--free-only` runs too: keys may exist but be
> forbidden to spend, which is analytically keyless for the metered indexes.

---

# WebPivot Skill

## Running the tools — paths & working directory (read first)

Two roots; keep them straight or commands fail:

- **Skill scripts** live in this skill folder. Call them by **absolute path** so the current
  directory never matters: `~/.claude/skills/WebPivot/tools/pivot_extract.py`. Inside the
  `intelligence_assist` repo, the repo-relative form `WebPivot/tools/pivot_extract.py` also works.
  *(Bare `tools/pivot_extract.py` only works if you already `cd`'d into `WebPivot/` — don't rely on it.)*
- **Case data + KB tools** live at the `intelligence_assist` **project root** — `cases/`,
  `knowledge/`, and `tools/kb/`. Run those commands from the project root.

Set this up once per case, then every example below resolves:

```bash
cd ~/.claude/skills/WebPivot/../..     # or: cd <intelligence_assist repo root>
ROOT="$PWD"; WP="$ROOT/WebPivot"       # WP = skill scripts, ROOT = case data + KB
CASE="$ROOT/cases/<case-name>"; mkdir -p "$CASE/raw" "$CASE/whois"
set -a; [ -f "$ROOT/.env" ] && source "$ROOT/.env"; set +a   # FOFA / URLSCAN / WHOISXML keys
```

## One-command case pipeline (the stable path)

For a whole domain list, prefer the orchestrator over running each tool by hand — it always
persists to the case and the KB the same way, so a case is reproducible:

```bash
python3 tools/intel.py open <case> domains.txt        # extract → ingest → --shared
python3 tools/intel.py open <case> domains.txt --render --operator "name"   # + case_graph.json + network.html
python3 tools/intel.py status <case>                  # audit what a case has persisted
```

It writes `cases/<case>/raw/<host>.json` (one per host, overwrites on re-run), ingests into
`knowledge/`, and saves the cluster seeds to `cases/<case>/shared.txt`. The per-tool commands
below are for single pages or when you need a step in isolation.

## 🎯 The GOAL — unmask the OPERATOR, not the infrastructure

Mechanically, this skill turns a page into **pivot points** — the artifacts in its HTML/DOM/TLS/
WHOIS that link it to other sites, infrastructure and actors — plus the exact queries to run them.
But that is the *method*. **The objective of every run is the human behind the estate: who built
it, who is paid by it, who is contactable through it, and under what identity they registered it.**

A run that ends with a tidy list of hashes, tokens and sibling domains and says nothing about
**who** has produced *collection*, not a *result*. The deliverable is an identity statement:
a named or narrowed operator with its evidence and confidence — or an explicit **identity gap**
naming the one pivot that would close it. Never a silent stop at "here are the artifacts".

Read every capability below with one question in front of it: *does this artifact carry a person,
or only a machine?* Two ranks, and never confuse them:

- **Infrastructure-scoped** — favicon mmh3, JARM, TLS fingerprint, ASN/origin IP, kit path, DOM
  skeleton, SPA route signature, JS bundle hash. These **expand the estate** (which hosts are the
  same thing) and are how you find more surface to read. **They identify nobody.**
- **Identity-bearing** — what a person had to *register, pay for, sign, be contacted on, or forget
  to strip*. This is what the run is actually hunting:
  - **registrant** name / email / phone / address — current **and** historical, then reverse-WHOIS
    every one of them (and every transliteration of a name)
  - **owner-account tokens nobody else can mint** — GA4/GTM/UA, GSC/Bing verification, ahrefs,
    the `ads.txt` `pub-` AdSense account, Apple team id
  - **the ad account** (`wp_serp`) — a Google-**verified, paying** advertiser id and the legal
    entity it is *funded by*: an identity WHOIS privacy cannot mask and a re-skin cannot change
  - **document / image metadata** (`wp_docmeta`) — `/Author`, XMP `DocumentID`, EXIF `Artist`/GPS
    on the files the site *hosts*: exported once from the operator's own machine, never re-exported
  - **source maps & build env** (asset layer) — `dev_username`, `dev_project`, `dev_path`,
    `build_env:*`: the developer's home directory and project name, compiled in by accident
  - **contact rails** — Telegram / Zalo / Messenger / WhatsApp handles, phones, support mailboxes,
    chat-SaaS tenant ids: how the victim reaches the operator is how you reach them
  - **money** — wallet addresses, payee accounts, affiliate/referral ids
  - **leak corpus** (`wp_intelx`) — stealer logs, where the machine holding the panel credentials
    is sometimes the operator's own box (`IntelAnalysis` §1.7)
  - **the file the site serves** — hand off to `BinaryPivot` (APK signing cert, keystore CN,
    Firebase tenant): the build identity survives every front-end re-skin

Sequencing follows from that: run the estate-expanding pivots to obtain **more pages to read**,
then mine every newly-found host for identity-bearing artifacts. Expansion is not the finish
line — it is more surface on which the operator may have slipped.

> 🚫 **The rails do not loosen because the goal is a name.** An identity claim carries the same
> burden as any other finding: base-rate the artifact before believing it, keep **same-kit /
> same-operator / same-actor** distinct, and treat a registrant identity as a **persona** — an
> unverified assertion by whoever filled the form, routinely a nominee or a synthetic. What you
> earn is *"registered under the persona X"*; *"X owns it"* requires an independent,
> non-self-declared corroborator (`IntelAnalysis` §2). On a compromised host the WHOIS, favicon,
> cert and analytics belong to the **victim** — only the injected kit is the operator's (§0
> intake). And a keyless run's silence is a fact about the credentials, not about the operator.
> A wrong name is worse than no name: it burns a real person.

> ⚠️ **Authorization first.** Read `EthicalFramework.md` before targeting live infrastructure. Fetching a hostile site touches it directly — use non-attributable egress (research VPS / VPN) and prefer passive sources (urlscan, Wayback, crt.sh) over direct fetches when the target is adversarial.

## The harness

`tools/pivot_extract.py` is the AI-controllable engine. **Zero required dependencies** — the core runs on the Python 3 stdlib, and the Shodan-style favicon `mmh3` hash is computed with a bundled pure-Python MurmurHash3. Optional accelerators: `requests` (fetch), `playwright` (rendered post-JS DOM via `--render`).

```bash
# Analyze a live page → full artifact + pivot JSON, SAVED to the case (the deliverable, not stdout)
python3 "$WP/tools/pivot_extract.py" https://suspicious-site.example --pretty -o "$CASE/raw/suspicious-site.example.json"

# Just the ranked pivot leads (markdown, high→low confidence) — a quick view
python3 "$WP/tools/pivot_extract.py" https://suspicious-site.example --leads

# Render JS-heavy SPA before extraction (needs: pip install playwright && playwright install chromium)
python3 "$WP/tools/pivot_extract.py" https://spa.example --render --leads

# Offline: analyze saved HTML, or pipe from stdin / another scraper
python3 "$WP/tools/pivot_extract.py" saved_page.html --pretty
curl -s https://x.example | python3 "$WP/tools/pivot_extract.py" -
```

## Capabilities — flags & when (full detail: `references/Capabilities.md`)

`pivot_extract.py` auto-detects its input and already does everything below — this index is the
routing map, so **open `references/Capabilities.md` for the depth on any row** (the tool's behaviour
is unchanged whether or not you read it). **Exhaust both pivot modes.**

| Capability | Flag / trigger | What it gives you |
|---|---|---|
| **Capability check (run it first)** | `tools/wp_capabilities.py` · `capability_check` MCP tool · auto-banner on every run | which keys are configured and, for each absent one, **the evidence class that is unavailable** + the free path that substitutes. Recorded in `meta.capability` and printed at the top of `--leads`. **Read it before reporting any "nothing found"** — see the keyless disclosure rule above |
| **domainPivot** | URL / host / HTML (default) | favicon mmh3, trackers, wallets, emails, WHOIS, TLS, CT, 3rd-party, SaaS tokens |
| **IPPivot** | a **bare IP** as input | passive IP recon: IPinfo ASN, FOFA `ip=`, Shodan, `dig` PTR/MX/NS/TXT; a shared CDN IP → `ip:information`, not a pivot |
| **IP identity — country · ASN · abuse · privacy flags** | (auto on the DOMAIN path too) · `tools/wp_ippivot.py` · `ip_info` MCP tool | **where an address is and whose it is**, for every IP a case surfaces — the live A record, an origin candidate from pDNS/pSSL, an SPF sender. Answers three things nothing else here does cleanly: whether the address is a PIVOT AT ALL (a shared CDN edge is other people's tenants; a small hosting ASN is real co-tenancy), the JURISDICTION and **abuse contact** a takedown actually goes to (a property of the ADDRESS — a privacy-masked WHOIS gives you nothing), and WHAT KIND of address it is: `hosting` on a scam server is ordinary, but `vpn`/`proxy`/`tor` on an address an operator connected FROM is a different statement — the flags stay separate, never collapsed to one boolean. Runs KEYLESS (rate-limited, still country + org); `IPINFO_TOKEN` adds the structured ASN block, abuse contact and privacy flags. **Memoised per process** — a case re-resolves the same CDN pair on every host and IPinfo bills per lookup. Skipped under `--free-only` |
| **Misconfig triage — internal-IP leak + anonymous FTP** | (auto in IPPivot from the FOFA `banner`) · `wp_recon.scan_misconfig` · `references/misconfig_signals.json` → the `ip:misconfig` pivot | reads the tell that a box is **operator-run and sloppy**, not hardened/CDN infrastructure — PASSIVELY, from an index that already holds the banner (no packet sent). Two signals. (1) **Internal-IP leak**: an RFC1918 / loopback / link-local address surfacing in a public result's `ip`/`host`/**banner** (a redirect `Location`, a self-signed cert SAN, a config echo) means the box is **dual-homed and exposing its internal topology** — pivot the leaked host/redirect for the real origin or the internal service map, and a CDN edge never does this. (2) **Anonymous FTP**: a `230` anon-login banner is a HIGH-value triage lead — the kit itself, uploaded **victim logs**, builder configs, sometimes the operator's own files. 🚫 **This layer FLAGS only; it never auto-connects.** Actually opening the box's FTP is ACTIVE + attributable (it tells the operator they are watched) and victim data carries handling/legal implications — a human decides that step. Base-rate safe: the row's own public IP is never a leak, and CGNAT (`100.64/10`) is off by default. IPPivot **fuses FOFA + Shodan + Censys** for the port/service/co-tenant view this reads over, so combining the three widens the historical window on the artifact |
| **ImpersonationHunt** | `<domain> --hunt-impersonation` | hunt lookalikes of a seed: typosquat perms + TLD sweep + crt.sh keyword hunt, existence-checked by live DNS → `impersonation:candidate` pivots + a monitoring watchlist. FREE (crt.sh+DNS); `--hunt-fofa`/`--hunt-urlscan` opt-in. Never live-fetches the lookalike infra |
| **SearchPivot** (multi-engine) | `tools/search_pivot.py "<indicator>" [--engines google,yandex,duckduckgo]` · `search_pivot` MCP tool | general-web complement to FOFA/PublicWWW for ANY indicator (domain, slogan, tracking ID, wallet, handle): emits ready-to-open, URL-encoded dork queries across Google/Yandex/DuckDuckGo/Bing/Brave. Does NOT scrape — **fire the queries with Claude Code's WebSearch + WebFetch (the readable duckduckgo html URL)**, extract candidate hosts, feed the NEW ones back into `pivot_extract`. FREE, no keys |
| **Asset layer — JS bundles + source maps** | (auto) · off with `--no-assets` · `--assets-max N` | **the fix for SPA/white-label kits, where the shell HTML is empty and every extractor above finds nothing.** Fetches the page's OWN JS (config/env names + hashed builds first, libraries skipped) and re-runs all extractors over the bundle source → off-apex `api_endpoint` / `websocket_endpoint` (the backend the front was compiled against — every front rotates, the backend doesn't), `build_env:<KEY>` tenant/brand tokens inlined by the bundler, `js_bundle_sha256` (survives a favicon/DOM re-skin). Follows `sourceMappingURL` → `.js.map` for `dev_username` / `dev_project` / `dev_path` — the operator's own build machine. FREE |
| **SPA route table** | (auto, from the bundles already fetched) | the app's OWN router declares every path it serves — Vue/React/Angular route literals + Next.js `sortedPages`/`__NEXT_DATA__`. **Zero extra requests, no path brute-forcing.** → `spa_route_signature` (sha256 over the sorted route set = same compiled app, survives a re-skin), `spa_route:admin` (the operator panel the public funnel never links to) and `spa_route:funnel` (deposit/withdraw/KYC/referral — the scam's mechanics, read without walking the funnel). Routes are **leads only; the tool never fetches them** |
| **Well-known / policy files** | (auto) · off with `--no-well-known` | fixed list of published standards: `robots.txt`, `sitemap.xml`, `ads.txt`, `app-ads.txt`, `security.txt`, `humans.txt`, `apple-app-site-association` → `adstxt_publisher` (an owner-registered AdSense `pub-` account — **Tier A**, same class as a GSC/GA4 token), `apple_team_id` + `ios_bundle_id`, `security_contact`, `robots_disallow` leads. FREE. **A fixed standards list, never a wordlist — this does not brute-force paths** |
| **Document / image metadata** | (auto) · off with `--no-docmeta` · `--docmeta-max N` · standalone: `tools/wp_docmeta.py <url\|path>` · `doc_metadata` MCP tool | **reads the files the site HOSTS, not the page.** A page is re-skinned in minutes; nobody re-exports the PDF licence when the brand changes. Downloads linked PDFs (the "licence"/"certificate"/"prospectus") and the site's own images, then parses `/Info` + XMP + EXIF → `doc_author` (a real name or OS account from `/Author`, EXIF `Artist`, `XPAuthor` — **not copyable by a stranger**), `doc_xmp_docid` (**XMP DocumentID is minted per SOURCE document — the same id on two domains is literally the same file**), `doc_copyright`, `doc_gps` (coordinates from an unstripped photo), `doc_camera`, `doc_producer`/`doc_software` (the shop that made it → same-**KIT** until corroborated), `media_sha256`. FREE/keyless, but it **costs extra requests to the target**. Values naming a common tool or a default account (Word, Photoshop, Canva, "Windows User") are recorded as context and **never clustered on** — tune in `references/docmeta.json`. ⚠️ **An empty result is NORMAL** (most CMS/CDN pipelines strip EXIF): never report it as deliberate sanitising |
| Multi-page crawl | `--crawl [N] --crawl-depth D` | follow same-site nav/tabs, fold every page's artifacts into one result |
| Rotate UA / proxy | `--rotate-ua` · `--ua` · `--proxy` · `--proxy-range` | low-profile fetch; per-request UA + proxy pool (auto during crawl) |
| Redirect & affiliate codes | (auto) | records `meta.redirect_chain` + affid/ref/utm codes (base64-decoded) as pivots |
| Reverse WHOIS (name+email) | `--whois-reverse` | current + historic reverse-WHOIS siblings (name links sites sharing no tech artifact) |
| Passive recovery | (auto) · `--no-fallback` | dead/blocked target → urlscan DOM → Wayback → still records the host + passive intel |
| Cloudflare solve | `--solve-cf` (+ `--flaresolverr`) | detects managed challenge; FlareSolverr/Playwright *collect* it (a UA swap won't) |
| Create archive | `--archive-missing` | Save-Page-Now snapshot when none exists yet |
| Save DOM + archive | `--save-dom` · `--submit` | store raw/post-JS DOM; push to Wayback + urlscan for a permanent capture |
| Historical analytics | `tools/wayback_ga.py` | every GA/GTM/verification ID across full Wayback history (Bellingcat) |
| Live TLS cert | (auto, https) | SANs, `tls_cert:co_san` cross-apex link, `tls_cert:fingerprint_sha256` |
| **Censys Platform** ⚠️ **100 credits/MONTH** | (auto with `CENSYS_PAT`) · off with `--no-censys` · `tools/wp_censys.py` · `censys` MCP tool | the **server-side** view FOFA/urlscan don't give. Every pivot gets a **CenQL query + a click-to-run `platform.censys.io` URL** built **offline, keyless, free**. With a key it also runs the three **lookup** endpoints — the only ones a **FREE Censys plan** can call: `cert <sha256>` → the certificate's own `names` (every hostname on that exact leaf cert — the cert stating its own coverage, not crt.sh's fuzzy overlap), `host <ip>` → ASN/WHOIS org + DNS names + ports + cert fingerprints (folded into IPPivot), `webproperty <host>` → cert/favicon/body-hash/software/threat labels (folded into domain enrichment). **`search` is Starter+** — on Free it degrades to `skipped` **plus the UI link that runs the same query**. **SPEND IT SPARINGLY — see the credit rule below.** Setup: `references/Setup.md` |
| **Passive SSL (CIRCL)** — historical **cert -> IP** | (auto with `PDNS_USERNAME`/`PDNS_PASSWORD`) · off with `--no-pssl` · `tools/wp_pssl.py` · `passive_ssl` MCP tool | the **origin-recovery** direction, and the half this toolkit was missing. Everything else reads the cert a host presents NOW (live handshake) or the names a CA logged AT ISSUANCE (crt.sh, Censys). This answers *which IP addresses have been observed serving this exact leaf certificate, over time* — so when an operator later hid behind Cloudflare, the box they served the same cert on first is still recoverable. **Pairs with passive DNS**: pDNS = historical name->IP, pSSL = historical cert->IP, and an address returned by BOTH is the strongest origin lead the pair produces (`origin_corroborated`). Uses the SAME free CIRCL account as pDNS and is sha1-keyed (Censys is sha256), so the sha1 is taken from the DER bytes the TLS probe already read — no extra connection to the target. 🚫 **BASE-RATE CONTROLLED, and this one matters more than anywhere else**: a shared CDN/hosting certificate is served by *thousands* of unrelated addresses (a Cloudflare edge cert measured at **915**), so past `max_ips_per_cert` — or on a CDN subject — the cert is INFRASTRUCTURE and `clusterable` is false. ⚠️ Coverage is Europe-weighted: an empty answer for a VN/CN/small-ISP address means the corpus never saw it — **absence of RECORD**, never "this address served no certificate" |
| **Intelligence X** — leaks / stealer logs / pastes / darknet / historical WHOIS | queries **auto** on every pivot (keyless) · `--intelx` runs them live · `tools/wp_intelx.py` · `intelx_search` MCP tool | the only layer that reaches a corpus **outside the live internet**. Every email / phone / domain / IP / BTC pivot gets its **IntelX selector + a click-to-run `intelx.io` URL**, built **offline, keyless, free**; a domain also gets the **phonebook** link. With `INTELX_KEY` + `--intelx` it runs them: leak/stealer-log/paste/darknet/WHOIS-snapshot sightings per selector, and **phonebook(domain) → every email address, subdomain and URL** IntelX has seen under the apex (a *collection input*, not just evidence — feed the emails and subdomains straight back into `pivot_extract`). **STRONG SELECTORS ONLY** — a brand or person name is refused. The **domain and the email are pivoted first** (a stealer log is indexed by the URL it captured, so the case domain names the machines that held credentials for it), and the **stealer logs are QUERIED in their own pass before the general one** so a bounded page can't fill with recycled combolist rows — a stealer log is one machine at one moment (panel URLs, and sometimes the **operator's own box**), a breach dump is an address and a year. Neither is clusterable on its own; only `whois`/`pastes`/darknet hits may support a same-operator edge. Keyless = **~50% capability** — see below |
| **Advertising — Google Ads Transparency + the cloaking probe** | `--serp` / `--serp-region` (metered) · `--ad-params` · `--cloak-probe` / `--no-cloak-probe` (FREE, auto on ad evidence) · `tools/wp_serp.py` · `serp_ads` MCP tool | reads what the operator **BOUGHT**, not what they provisioned. `ads:advertiser_id` is a Google-**VERIFIED, paying** account — an identity WHOIS privacy cannot hide and a re-skin cannot change — plus the `ads:advertiser` legal name it is *funded by* (run it through a corporate registry / reverse-WHOIS), and the **reverse**: every other domain that account advertised (**same-PAYER**, HIGH; downgraded to leads when the account is agency-shaped). Opening a creative adds `ad_funded_by` (the verified legal entity) + the dated per-region markets. `ads:campaignid` / `adgroupid` / `creative` are object ids inside ONE ad account. **The cloaking probe is free and needs no key**: many fraud landing pages serve the real scam ONLY to arrivals carrying the right `utm`/`gclid` and show everyone else a decoy — the probe fetches the page as a plain visitor, as a paid ad click and as a control, and on `divergent` the run **re-points at the click view** and collects the real page. 🚫 A click id is never a pivot; `dynamic`/`inconclusive_unstable` are never cloaking. Keyless **~55%** |
| CORS backend probe | (auto, primary page) | foreign-Origin GET+preflight → `cors_allowed_origin` backend/sibling hosts the HTML never names |
| Mail intel | (auto, `dig`) | MX provider / `m365_tenant` / custom `mail_server`, SPF `include`/sender-IP, DMARC contacts |
| CT / SSL search | (auto) | crt.sh + Shodan CTL merged, resilient, wildcard-aware, SAN siblings |
| Hosting-IP classify | (auto) | `cdn_ranges` → CDN edge = noise, only the origin-candidate IP is reversed |
| App-download artifacts | (auto) | APK/`.exe`/installer URLs + signing-cert → first query is the **BinaryPivot** command |
| QR decode | (auto for generator URLs) · `--decode-qr` | wallet / Telegram / WhatsApp / affiliate link hidden in a QR image |
| **Reporting (the deliverable)** | `--report` · `--master` · `--misp` · `--screenshot` | ICD-203 assessment, evidence ledger, IOC bundle → `Workflows/Reporting.md` |
| Case graph | `tools/graph_build.py` | merge JSONs → clustered graph (components / Louvain / centrality) → `Workflows/NetworkGraph.md` |

Chain the modes: a domain's live IP → IPPivot; an IPPivot co-hosted domain → domainPivot. A shared
managed provider / CDN edge / registrar is context, **not** a same-operator pivot. A WebPivot run
ends with a readable ICD-203 assessment — **never** raw JSON.

### ⚠️ Censys credits — 100 a MONTH, no rollover, shared by every case

Censys is the **tightest quota in the toolkit** and the quota is **per account**: overspending in
one case removes Censys from every later case until the 1st. A lookup is **1 credit**, a search is
**5** — and **running the emitted CenQL in the web UI costs the same 5**, so the UI link is not a
free escape hatch. Twenty searches empty the month.

- **Default to the free, keyless path.** Every pivot already carries its CenQL + UI link at zero
  cost. Hand those to the analyst instead of spending a search yourself.
- **Spend on the artifact that decides the question**, not as blanket enrichment. Ranked by value
  per credit: `cert <sha256>` (1 credit → every hostname on that leaf cert) → `host <ip>` →
  `webproperty <host>` → `search` (5 credits, and Starter+ only anyway).
- **Check the balance before a batch:** `python3 "$WP/tools/wp_censys.py" budget` (offline, free) or
  the `censys` MCP tool with `mode='budget'`.
- The guard enforces this: spends are tracked against `MEMORY/api_usage.jsonl`, capped per month
  **and** per run, with a reserve that keeps the cheap 1-credit lookups affordable. Over budget →
  `skipped` with the balance and the UI link, never a mid-case 402. Tune thresholds in
  `references/censys_queries.json` → `credit_budget` (or `CENSYS_MONTHLY_CREDITS` /
  `CENSYS_MAX_CREDITS_PER_RUN` for one run).
- **Report Censys spend** alongside the Anthropic cost — they are separate ledgers.

### ⭐ The URL PATH is a campaign identifier — and raw capture is the evidence

**The technique.** Every other pivot in this skill hangs off the **hostname** — favicon, TLS,
registrant, nameserver, JARM. A kit operator who has noticed that inverts the model: they buy a
pool of disposable hosts (numeric labels, cheap TLDs, rotated weekly, a fresh certificate each) and
select which branded template a victim sees by the **URL path**:

```
host-a.example/<kit-x>/     host-b.example/<kit-x>/     host-c.example/<kit-y>/
```

Nothing at host level connects those. Collect path-blind and you file **three unrelated one-domain
cases**. Keep the path and the same three rows collapse into *one operator, two kits, three hosts* —
and the kit directory becomes a pivot you can hunt with, which finds the **next** host before it is
reported anywhere. The path outlives the host, because the path is the product and the host is
packaging.

```bash
python3 "$WP/tools/wp_paths.py" analyze "https://host.example/kit-x/step2/9f3a1c"
python3 "$WP/tools/wp_paths.py" patterns "cases/<case>/raw/*.json"   # which kits recur, on how many hosts
python3 "$WP/tools/wp_capture.py" "https://host.example/kit-x/" --case <case>
python3 "$WP/tools/wp_capture.py" cases/<case>/evidence/captures/<host>/<kit>/<ts>   # verify
```

- **Every run keeps the path.** `meta.url_path`, `meta.path_template`, `meta.kit`, `meta.locale`,
  `meta.location` (`host+path` — on a path-routed estate *that* is the unit of investigation, not
  the host). The path is read from the **final** URL, after redirects, because a kit entry link
  routinely lands you somewhere short and redirects into the template directory.
- **`path:kit` is the artifact that survives host rotation** — the template directory, the one
  string the operator cannot randomise without rebuilding their own routing. It ships reverse
  queries for the indexes that store a full URL: `urlscan page.url:`, an `inurl:` dork, FOFA,
  PublicWWW, and a Wayback CDX sweep across *any* host.
- **`path:template` normalises the variable parts** — session ids, build hashes, dates and locales
  become `{hex}` / `{uuid}` / `{date}` / `{locale}`, so a kit that hands every victim a unique URL
  still collapses to one countable template. The concrete locale is kept separately: which market a
  template was localised for is **target-selection evidence**, not noise.
- 🚫 **Base-rate controlled, or this layer would fuse the internet.** `/login`, `/assets`, `/api/v1`,
  `/wp-admin`, a `.js` file — all denylisted in `references/url_paths.json`, and a path with no
  distinctive segment emits **nothing at all**. That is the correct result for an ordinary site,
  not a failure. Add a segment there the moment a run produces a cluster joined only by a path.
- 🚫 **A shared kit directory is SAME-KIT, not same-operator** — two resellers of one kit have the
  same directory names, exactly like two tenants of a white-label platform. It is a strong
  *collection* lead; the operator claim needs a second, independent artifact class. The KB edge is
  `serves_kit` at **medium**, never `same_operator`.
- **`patterns` is where the finding lives**: one kit on **N distinct hosts**, and the mirror image —
  **`multi_kit_hosts`**, one back end serving several brands. Both halves of the same technique.

**Raw capture — the DOM, every JS and every CSS, hashed.** Everything else here is *derived*: a
hash, a fingerprint, an extracted wallet — assertions about a page that will be gone in days, after
which nobody can re-check them, including us. So a run with `--case` **captures by default**:

```
cases/<case>/evidence/captures/<host>/<kit>/<UTC>/
    dom.html            manifest.json     ← per-file sha256 + capture_sha256
    assets/             third_party/
```

- **Cite the `capture_sha256`, not the directory** — it is computed over the sorted per-file
  digests, so any later edit, addition or removal changes it. `wp_capture.py <dir>` re-hashes and
  tells you whether the bundle still matches its manifest.
- **CSS is captured here and nowhere else.** A shared theme is same-kit evidence, and until now the
  stylesheet was the one artifact class WebPivot never retained.
- **Captures are timestamped and never overwritten.** Re-collecting next week is a *new*
  observation — the **diff between two captures is how you date a re-skin**.
- **Budgeted, and it says so.** Same-site assets (the operator's own code) get the generous
  allowance, third-party CDN libs a small one. Anything dropped is listed in `skipped_for_budget`
  and the manifest is stamped `INCOMPLETE` — **read that before treating a bundle as the whole
  page.** Tune in `references/capture.json`; `--no-capture` / `--no-capture-third-party` to narrow.

### ⭐ The ADVERTISING layer — who PAID for the traffic, and what the page shows *them*

Every other pivot here reads something the operator **provisioned**. This one reads what they
**bought**, and that changes two things.

**1. A Google advertiser is a verified, paying identity.** Google will not take the money without
identity verification, and the **Ads Transparency Center publishes the result**: a stable
`advertiser_id`, the legal name the ads are *"funded by"*, and every creative that account ran with
the domain each one pointed at. So a domain whose WHOIS is behind privacy and whose host is a week
old can still carry a KYC'd identity — and it **survives domain rotation**, because nobody
re-verifies a fresh ad account for each throwaway host. Reverse the `advertiser_id` and you get the
operator's other landing domains, often before they are reported anywhere.

**2. A page that buys traffic frequently only shows its real self to that traffic.** The kit gates
on the arrival: present a `gclid` and the campaign's `utm` set and it serves the scam; arrive
without them — directly, from a crawler, from Google's own reviewer — and it serves a **decoy**. The
run does not fail, which is the danger: it *succeeds on the wrong page*, and "no scam content found"
gets written down as a finding.

```bash
python3 "$WP/tools/wp_serp.py" advertiser scam-site.example --region VN --details 1
python3 "$WP/tools/wp_serp.py" creatives AR00000000000000000001     # reverse → their other domains
python3 "$WP/tools/wp_serp.py" cloak "https://scam-site.example/" --ad-params 'utm_campaign=vn_q3&gclid=E1'
python3 "$WP/tools/wp_serp.py" serp "brand keyword" --gl vn         # who is buying it now (best-effort)
python3 "$WP/tools/wp_serp.py" budget                               # searches left this month
# in the pipeline:
python3 "$WP/tools/pivot_extract.py" "https://scam-site.example/" --case <case> --serp --serp-region VN
```

- **The cloaking probe is FREE and runs automatically** whenever there is advertising evidence (an
  `AW-` conversion id, an `ads.txt`, ad parameters on the URL) — three requests to the target, no
  API credit. It fetches the page **as a plain visitor**, **as a paid ad click** (parameters + a
  Google `Referer` + cross-site fetch metadata), and **as a plain visitor again, as a control**.
  On `divergent` the run **switches to the click view and collects that instead**, and says so.
  Force with `--cloak-probe`, disable with `--no-cloak-probe`.
- 🚫 **An anti-bot wall is not a page.** If either view comes back as a Cloudflare/DataDome/CAPTCHA
  interstitial the verdict is `inconclusive` — two challenge pages differ from each other by design
  (nonces, padding), and scoring them would report the *bot wall* as the operator's evasion, on
  exactly the hostile infrastructure where that finding would be believed hardest. Re-probe through
  a residential `--proxy`, or `--solve-cf` and pass the resulting URL to `wp_serp.py cloak`. Markers
  are tunable in `references/serpapi.json → challenge_markers`.
- 🚫 **A length difference alone is never cloaking.** Bytes change for nonces, padding and inlined
  tokens; the question is whether the *visible text* changed. Length only corroborates a difference
  that the title, host, status or text-similarity check already found.
- 🚫 **`dynamic` and `inconclusive_unstable` are NOT cloaking.** Every live page differs a little
  between two fetches (session ids, CSRF tokens, rotating banners). The control fetch is the
  falsification step: if the plain view also differs from *itself*, the verdict is
  `inconclusive_unstable` and **nothing is attributed to the click**. Reporting an unstable CMS as
  deliberate evasion is an accusation, and this layer refuses to make it on one observation.
- **`--details 1` opens a creative and names the payer precisely**: `ad_funded_by` is the **legal
  entity** Google verified (`<Brand> B.V.` rather than `<Brand>`), and the response carries the
  **per-region markets** the ad ran in with a last-shown date each — dated target-selection
  evidence, and the answer to which `--serp-region` to query next. ⚠️ The creative's **destination
  link is a bonus, not a plan**: Google's archive commonly stores a text ad as a rendered image with
  no URL, and the tool says so (`no_link_note`) rather than looking broken. When a link *is*
  returned, its `utm` set is the operator's own cloaking key — feed it back with `--ad-params`.
  Otherwise the reliable sources for real ad parameters are a URL you already hold (report, victim's
  browser history, stealer log) or the probe's synthetic profile.
- **`ads:advertiser_id` is same-PAYER evidence at HIGH** — money is harder to share than code. The
  KB edge is `advertised_by` and every co-advertised domain hangs off the same indicator, so they
  cluster automatically. 🚫 **Unless the account is agency-shaped**: past
  `clustering_policy.agency_domain_threshold` distinct target domains it is a media buyer or
  affiliate network *buying traffic for others*, the confidence drops to a lead, and the ingest
  keeps its clients as **facts, not edges**. Same discipline as a white-label platform artifact.
- **`ads:advertiser` (the funded-by name) is worth as much as the id** and is easy to under-use: it
  is a name Google **verified against documents**, so it is the string to run through a corporate
  registry and through reverse-WHOIS — where a real-world identity and the infrastructure meet.
- **`ads:campaignid` / `adgroupid` / `creative`** are ValueTrack object ids allocated *inside one ad
  account*, so the same value under the same parameter name on another domain means **one account
  paid for both**. Medium — they are short integers.
- 🚫 **A click id is never a pivot.** `gclid` / `fbclid` / `msclkid` values are unique per click; they
  prove the visit was **paid traffic** (`ads:paid_arrival`, informational) and nothing more.
  `utm_*` values stay owned by the `affiliate:*` pivots — this layer does not duplicate them.
- 🚫 **Two domains bidding on the same keyword are competitors**, never an operator link. And the
  `serp` mode is **best-effort**: Google serves the sponsored block inconsistently to automated
  clients (live testing saw it absent even for high-commercial-intent queries), so an empty result
  sets `ads_block_present: false` and is a fact about the *response* — never the finding "nobody
  advertises against this brand". The Ads Transparency archive is the reliable path.
- **Metered, capped, and honest keyless.** One SerpApi search per call, capped per run and per month
  from the same ledger (`references/serpapi.json → search_budget`), skipped under `--free-only`.
  With no `SERPAPI_KEY` the layer runs at **~55%**: the cloaking probe in full, every parameter
  classified, and the free `adstransparency.google.com` address for the domain and for any
  advertiser id — but the archive is **never queried**, so *"no advertiser found" means "never
  asked"* and must not be reported as a finding.

### Intelligence X — the leak / paste / darknet selector layer (**keyless ≈ 50% of it**)

Every other engine here indexes the **live internet**. IntelX indexes what has **leaked out of it**:
breach dumps, infostealer logs, pastes, darknet mirrors, historical WHOIS snapshots, plus its own
crawl. That is where an operator's *contact* selectors surface — a registrant email in a market
listing, a support phone in a forum post, a payout wallet in a paste, usually next to their own
advertising copy.

```bash
python3 "$WP/tools/wp_intelx.py" query <selector>            # OFFLINE: classify + build the UI URLs
python3 "$WP/tools/wp_intelx.py" search example.com          # logs pass + general pass (2 units)
python3 "$WP/tools/wp_intelx.py" search example.com --logs-only   # 1 unit — the high-yield question
python3 "$WP/tools/wp_intelx.py" search registrant@example.com    # the operator's own selector
python3 "$WP/tools/wp_intelx.py" phonebook example.com --target emails   # PAID endpoint
python3 "$WP/tools/wp_intelx.py" budget                      # OFFLINE: this month's spend
python3 "$WP/tools/pivot_extract.py" <url> --intelx           # run it inside a collection
```

- **Strong selectors only.** Email, domain (`*.apex` allowed), URL, IP/CIDR, phone, Bitcoin,
  MAC/UUID/IBAN/credit-card. A **brand or person name is a soft term** — IntelX refuses it and the
  attempt still costs a unit, so the classifier rejects it locally first. For keyword work use FOFA
  `body=` / PublicWWW / `search_pivot`.
- ⭐ **Pivot the DOMAIN and the EMAIL first — in that order.** A stealer-log record is indexed by the
  **URL the malware captured**, so the case domain is a first-class selector, not an afterthought:
  searching it returns *the machines that held credentials for that domain* — the campaign's victims,
  the **admin/panel URLs the public site never links**, and, when the operator signed into their own
  panel from an infected box, **the operator's own machine**. Nothing else in this toolkit reaches
  that. The email comes next: it is the selector that carries **identity** across corpora. Contact
  artifacts (phone, wallet) follow. Order lives in `references/intelx.json → search_plan.selector_priority`,
  and the **seed host is searched ahead of any discovered sibling**.
- ⭐ **Query the logs FIRST — this is a retrieval rule, not a display preference.** IntelX returns a
  **bounded page**. On a long-exposed selector the recycled public-breach rows fill it and the one
  infostealer record is **truncated away before any sort can reach it**. So `search()` runs a
  bucket-scoped **`leaks.logs` pass first**, then the general pass, and merges (`search_plan`;
  1 unit each — and when only one unit is left, **the logs pass is the one that runs**). The result
  carries **`logs_pass`**: with it true, an empty `read_these` is a *real negative*; without it,
  it means nothing. Use `--logs-only` on a tight allowance, `--no-logs-first` to go back to one
  general search.
- **`phonebook(domain)` is the highest-value call** for web casework, and PAID-only: one apex →
  every email, subdomain and URL IntelX has seen under it. Treat the results as **new collection
  targets**, then corroborate before they attribute anything.
- 🚫 **A leak hit is NOT a same-operator link.** Two addresses in one combolist share a **victim
  population**, not an owner — that is the textbook false cluster for this corpus. Only
  `whois` / `pastes` / `darknet.*` hits may support an operator edge (policy:
  `references/intelx.json → clustering_policy`, enforced by `clusterable()` on every record, and it
  **fails closed**).
- ⭐ **Stealer logs ≫ breach dumps — read the logs, skim the dumps.** A breach dump is one site's
  user table: an address and a year, recycled through dozens of combolists. **Skim it for the DATE
  and move on.** An infostealer log is *one machine at one moment* — the URL/user/password triple
  with its session context — so it dates the compromise to a **host**, exposes **admin/panel URLs
  the public site never links** (straight into the victim / access-vector layer), and — the
  case-making part — **operators get infected too**: a log holding the campaign's own panel or
  registrar/CMS/exchange logins is **direct attribution**, not exposure. Log hits come back as
  **`read_these`** — items to open one at a time and ask *whose machine is this: a victim of this
  campaign, or the operator?* Corpus co-membership is still not an edge; the item is where the
  evidence lives. Handle as real victim credentials — **cite metadata, never paste secrets into the
  case file**. Judging an item is the analyst's call: **`IntelAnalysis` §1.7 +
  `Workflows/StealerLog.md`**.
- **Metered**, capped per run and per month from the same ledger as everything else
  (`references/intelx.json → search_budget`, or `INTELX_MAX_SEARCHES_PER_RUN` /
  `INTELX_MONTHLY_SEARCHES` for one run). `--free-only` suppresses it entirely.
- 🔑 **Without `INTELX_KEY` the layer runs at ~50%** — it still classifies every selector and hands
  you a working `intelx.io` / `phonebook.cz` URL for each, but **executes nothing**. So a run with
  no IntelX section has **not** established that the operator is absent from any leak, paste or
  darknet listing. Say that before presenting the result; `meta.capability` carries the sentence.

## ⭐ After the first collection: EXHAUST the seed — `wp_exhaust.py` / `collection_gaps`

The first `pivot_extract` on a seed is a **triage**, not a worked seed. The layers that open a
*different search space* — IntelX's leak/stealer-log corpus, the advertising + cloaking probe,
passive SSL, the lookalike hunt, document metadata — are all behind opt-in flags, and opt-in flags
do not get typed once the first result looks interesting. Measured across this repo's stored
collections: **`intelx` had run on exactly one of them.**

The damage is not a thin case, it is a case that cannot tell how thin it is. Correlation over a
triage-depth collection is scrupulous about every artifact it has and silent about the search it
never ran, so *"no further links found"* reads as a finding when it is a statement about which
flags were passed — the same error the keyless capability banner exists to prevent, one level up.

```bash
python3 "$WP/tools/wp_exhaust.py" CASE-0001                 # every host: exhausted or triage
python3 "$WP/tools/wp_exhaust.py" CASE-0001 site.example    # one host, with the commands to run
```

Every collection now ends with this check: on a triage verdict it prints the layers that never
ran, cheapest first, each with the flag that closes it. Read it as a work list, in this order:

1. **the free gaps** — capture, archive timeline, URL path, document metadata, the lookalike hunt,
   a screenshot, and the **cloaking probe** (`--cloak-probe` needs no key);
2. **the free-account gaps** — passive DNS and passive SSL (one CIRCL login covers both);
3. **the metered ones as a decision** — `--intelx` first, because the leak corpus is the one
   search space the live internet cannot substitute for.

A seed is `exhausted` only when every layer in `seed_policy.required_layers` has run. **If it is
still `triage` when the assessment is written, say so in the assessment** — and never report a
layer that did not run as a negative finding. Tune the checklist in
`references/exhaustion.json`; add a layer there when you add a collector, or it will never appear
in the gap list.

## §0 Intake — scope before you collect, and TEST the claim (run this first)

A target rarely arrives alone; it arrives with a belief attached — *"this scam site"*, *"their
C2"*, *"the domain impersonating us"*. **Establish the scope before the first request, and treat
the belief as a hypothesis this run tests, never as a premise it inherits.** Full runbook:
**`Workflows/Intake.md`**; the classes, questions, posture and verdict vocabulary are tunable data
in **`references/intake.json`**.

**Ask** (one grouped prompt, ≤4 at a time — not an interrogation). The two that carry the scoping
are **target class** and **purpose**:

| Ask | It changes |
|---|---|
| **What do you believe this is?** — confirmed scam · suspected scam · threat-actor infra · victim host · legitimacy check · unknown | fetch posture, opsec, which layers run, **whose artifacts these are** |
| **What is that based on?** — complaint · takedown/seizure · vendor report · an ad you were served · a log · a hunch | whether the class is asserted or hypothesised, and what its verdict is judged against |
| **What is the run for?** — triage · cluster expansion · attribution · takedown package · own-exposure check | depth; whether capture/ingest/assessment are mandatory; which skill runs next |
| **Brand or entity involved — and which side is this host?** | seeds `--hunt-impersonation`; forces the **direction** check |
| **How did it reach you?** — ad · message · file download · redirect chain · another case | turns on `--serp` + `--cloak-probe`, or hands the file to **BinaryPivot** |
| **A date that matters? Constraints?** — may we touch it · may we spend credits · case id | archive anchor; passive-only vs direct fetch; `--free-only`; where it persists |
| **What would tell you this is *not* what you think?** | the disconfirming checks this run must report on, and the stop condition |

**Never blocks.** Context already given → don't re-ask, echo the inferred scope in one line and
start. Nothing given, or the caller is `intel.py` / the orchestrator / MCP / a batch (nobody to
ask) → proceed as **`unknown`**: passive-first, liveness + archive timeline first (they usually
resolve the class), and **state that assumption in the deliverable**.

**Record the answers so the automated path gets them too.** Once you have them, write them to the
case with the **`case_scope`** MCP tool (`case_scope(case=…, target_class=…, purpose=…, claim=…,
basis=…, brand=…, how=…, window=…, falsifier=…)`). It persists to `cases/<case>/scope.json`, and
every harness phase — collect, correlate, verify, assess — renders that record into its prompt on
this round and every resume. A no-touch class set there becomes a **hard gate denial** of outbound
collection, not a suggestion. Read it back with `case_scope(case=…)`; `python3
harness/case_scope.py questions` prints the same question set the harness expects.

**Two classes change behaviour the most:**

- **`threat_actor_infra` → never fetch from analyst egress.** A direct request tells the operator
  they are being examined and from where; target-side allowlists mean one probe can burn the
  collection. Third-party scanners and stored captures only.
- **`victim_host` → the ownership boundary.** On a compromised host the WHOIS, favicon, certificate
  and analytics are the **victim's**. Only the injected kit path, its assets and its endpoints are
  the operator's. Cluster on the rest and unrelated victims fuse into one imaginary estate.

**Test the claim** — run these however confident the requester was, and especially when very:
liveness *by reading the page* (parking / suspended / default / soft-404 all return 200) · archive
timeline anchored on the incident date · impersonation **direction** (is the seed the imposter, or
the brand's real site?) · base-rate every artifact before it becomes an edge · decide whose asset
each artifact is.

**Answer it explicitly**, one line near the top of the deliverable:

> Stated premise: `<class>` (source: `<basis>`). Collection verdict: **supported · partially
> supported · not supported · contradicted · inconclusive** — `<one line of why>`.

`not supported` = found nothing either way — and on a keyless/free-only/passive/blocked run that is
a fact about the **collection**, so pair it with the capability disclosure. `inconclusive` = the
target was never observed; the claim was not tested. **`contradicted` is the most valuable result
an intake produces — lead with it.** Never raise confidence because the requester was certain,
never skip a disconfirming check because the class was stated as confirmed, and never write the
stated class into the KB or an assessment as a collected finding. If the collection establishes a
different class than the one stated, **stop, say so, restate the posture**, and continue under it.

## Workflow Routing

| Request | Workflow |
|---|---|
| **A target arrives (with or without context) — scope it and test the claim** | **`Workflows/Intake.md`** (run first) |
| Analyze one page, get all pivots | `Workflows/AnalyzePage.md` |
| I have an artifact (favicon/tracker/wallet), where does it pivot? | `Workflows/PivotFromArtifact.md` |
| Cluster many pages into campaigns / find sibling sites | `Workflows/CampaignClustering.md` |
| Find sites via shared/scrubbed analytics IDs over time (Bellingcat) | `Workflows/HistoricalAnalytics.md` |
| Build a clustered, interactive link graph to tell the story | `Workflows/NetworkGraph.md` |
| **"Output full report for that cluster"** (whole-case ICD-203 rollup, not one host) | `Workflows/Reporting.md` |
| Write per-host report / evidence ledger / IOC bundle, or monitor a brand's new certs | `Workflows/Reporting.md` |
| Analyze a **list/batch** of domains, or fan out agents for scale/verification | `Workflows/ParallelBatch.md` |
| The site pushes an APK / .exe installer — analyze the file for IOCs | **BinaryPivot skill** (`analyze_artifact.py`) |

## Trigger Patterns

- "analyze this site / page / HTML / DOM", "what can I pivot on here"
- "find related / sibling domains", "who else runs this", "same operator?"
- "is this a phishing kit / scam cluster", "cluster these URLs"
- "reverse this GA / GTM / AdSense / pixel ID", "favicon hash for pivoting"
- "trace this scam site's infrastructure / wallet"
- **"output full report for that cluster"** / "cluster report" / "campaign report" → whole-case ICD-203 rollup (`Workflows/Reporting.md`), not a single-domain report
- "this site pushes an APK / .exe download" → detect it here, then hand the file to the **BinaryPivot** skill

## Method (default flow)

0. **Intake — scope it and test the claim (§0 above, `Workflows/Intake.md`).** Establish target class + purpose before the first request; they decide the fetch posture, which layers run, and **whose artifacts the page's are**. Never blocks: no context → `unknown`, passive-first, and say so. The requester's stated class sets the posture, never the finding.
1. **Acquire** — fetch (or `--render` for SPAs; or feed saved HTML / a urlscan DOM). Prefer passive capture for hostile targets.
1b. **Always check the web archive** — on *every* target, even one that loads live. Pull the Wayback CDX timeline (`http://web.archive.org/cdx/search/cdx?url=<host>*&output=json&collapse=digest`) and read the status codes: a parked/dead site today may have hosted a live scam funnel in an earlier snapshot (mine that archived DOM for real artifacts), and a `created` WHOIS date inside the capture history means a prior owner. Never conclude "parked / nothing to pivot on" from the live page alone. Then run `wayback_ga.py` for the full analytics history. See `Workflows/AnalyzePage.md` step 2c.
2. **Extract** — run `pivot_extract.py`; get structured artifacts + ranked pivots.
3. **Pivot** — run the emitted queries against the services in `references/PivotServices.md`. Work the **`references/PivotMatrix.md`** checklist: harvest *every* dimension on *every* seed and rank attribution by its same-owner strength tiers (Tier A owner-verified tokens — GSC `verifications`, own GA4/GTM, TLS leaf-fingerprint — before Tier D falsifiable WHOIS). Don't pivot opportunistically off whichever artifact you happened to notice.
4. **Corroborate** — a single shared artifact is a lead, not proof. Confirm a cluster with ≥2 independent artifacts (e.g. same favicon **and** same GA4 ID) before asserting common ownership.
5. **Record** — capture artifact values + the confirming pivots for the graph (**invoke the `IntelGraph` skill** for a relationship diagram).
6. **Correlate (hand off)** — for anything past a single host — a cluster, a "same operator?" question, an attribution call — **invoke the `IntelAnalysis` skill**. It reads the KB you just ingested and runs the judgment layer (triage → cluster → attribute → calibrate confidence → next pivot). A WebPivot run that stops at raw pivots is collection without judgment; the analysis is a separate skill and does not start unless you invoke it.

## Output contract — every run lands in the case (do not skip)

A WebPivot run is only "done" when its result is **persisted into the case**, not when it
prints to the terminal. Stdout is a preview; the case files are the deliverable. For every
page analyzed, produce all three, in order:

1. **Raw pivot JSON** → `cases/<case>/raw/<host>.json` — always use `-o "$CASE/raw/<host>.json"`.
   Never let the JSON exist only in stdout.
2. **Ingested into the knowledge base** → run once the raw files exist, from the project root:
   ```bash
   python3 tools/kb/ingest_webpivot.py --kb knowledge "$CASE"/raw/*.json
   ```
   This is what makes IntelAnalysis able to reason over the run. A run that isn't ingested
   is invisible to correlation — **so once the seeds are ingested, invoke the `IntelAnalysis`
   skill to correlate and attribute** (step 6 of the flow above). Don't end at raw pivots.
3. **Confirmed** with `query.py --shared` so the cluster seeds are recorded, not just implied:
   ```bash
   python3 tools/kb/query.py --kb knowledge --shared --min 2
   ```
4. **Reported** as a human-readable **ICD-203 assessment** — the analyst deliverable, not raw JSON.
   `intel.py open` writes `cases/<case>/assessment.md` for you; otherwise render it explicitly:
   ```bash
   python3 WebPivot/tools/evidence_report.py cases/<case>/raw/*.json --case <case> \
       --analyst <you> -o cases/<case>/assessment.md
   ```
   Present the BLUF + Key Judgments to the user (table / verdict / estimative wording) — do NOT
   end a run by pasting raw pivot JSON. For a single page, `pivot_extract.py … --report`.
   Ledger / IOC-bundle / monitoring options: `Workflows/Reporting.md`.

   Every assessment now **auto-opens with a standardized Domain Summary table** rendered by
   `tools/domain_table.py` (called from `evidence_report.py`): one fixed grid of
   **Domain | Status | Registered | Expires | Registrar | Nameservers | Registrant | IP · ASN |
   Attribution | Analyst context** — so WHOIS + registration dates + attribution are in *every*
   output for the analyst to judge, not buried in JSON. Status/IP come from the pivot capture,
   WHOIS from WhoisXML (cached under `cases/<case>/whois/`), ASN keyless from ip-api, attribution
   from `knowledge/operators.jsonl`. The **Analyst context** column is populated from an optional
   `cases/<case>/notes.json` sidecar (`{"domain": "your judgement note", …}`) — use it to record
   the reasoning the automated columns can't. Render it standalone for an ad-hoc set:
   ```bash
   python3 tools/domain_table.py cases/<case>/raw/*.json --case <case> --kb knowledge
   python3 tools/domain_table.py --domains a.com,b.com --kb knowledge   # live-probe domains w/o raw JSON
   ```

Fixed filename rule: **one file per host**, named exactly `<host>.json` (the bare hostname,
no scheme, no trailing slash) so re-runs overwrite instead of duplicating. Same host analyzed
twice = same file. This is what keeps a case reproducible: re-running the whole `domains.txt`
yields the identical set of `raw/*.json`, and ingest is idempotent, so the KB converges to the
same state every time.

*(Artifact-reliability notes — UA/GA4, crt.sh overload, Validin, Chainabuse — moved to
`references/Capabilities.md` § Notes on artifact reliability.)*

---

## Tuning the tool without editing code — `references/*.json`

Every denylist, provider registry and permutation table the collector matches against is **data,
not code**. When a run produces a bad link or misses one, the fix is usually a one-line edit to a
JSON file — no Python, no redeploy. Each file opens with a `_comment` explaining what it is for
and which direction is the safe one to be wrong in; every group has its own `_comment`.

| File | Edit it when |
|---|---|
| `references/intake.json` | The scoping step (§0) asks a question that changes nothing — delete it, an intake nobody answers is worse than none — or a **target class needs a different posture** (`fetch_posture`, `run`, `clustering_rule`), a new disconfirming check should be mandatory (`claim_verification.mandatory_checks`), or an answer should switch a layer on (`scope_switches`). `policy` holds the never-block rules |
| `references/registrant_noise.json` | a WHOIS privacy proxy / registrar role mailbox got treated as a registrant, or a reverse-WHOIS burned credits on boilerplate |
| `references/third_party_noise.json` | an analytics/CDN endpoint scraped from a JS bundle was reported as the operator's backend, or a managed MX/NS showed up as operator infra |
| `references/generic_labels.json` | a generic subdomain (`api.`, `cdn.`) or a library filename (`jquery.min.js`) created a false same-operator link |
| `references/impersonation.json` | `--hunt-impersonation` is missing the TLDs or affixes a ring actually uses — **this is the per-campaign tuning knob** |
| `references/mail_providers.json` | an MX / SPF include / DMARC `rua` host came back unclassified |
| `references/pivot_tables.json` | a SaaS token's confidence is wrong (a vendor started sharing tenant ids → set it to `null`), or a new affiliate param appeared |
| `references/asn_registry.json` | an ASN's `noise` / `kind` call is wrong. Grows automatically — `wp_ippivot` banks each new ASN it meets |
| `references/censys_queries.json` | Censys renamed a CenQL field, changed a credit price, you upgraded plan, or an artifact kind should (or should not) get a Censys query — `pivot_kind_map` is the single place that decides. **`credit_budget` is the spend guard**: raise `monthly_credits` after buying credits, `max_credits_per_run` for a batch that genuinely needs it |
| `references/url_paths.json` | A path segment produced a bad cluster — add it to **`generic_segments`**, the base-rate control that decides what is never a kit. Also: `variable_patterns` (an operator is randomising a segment you keep clustering on), `locale_segments`, `asset_extensions` (a filename is being read as a kit), `kit_thresholds.min_hosts_for_pattern` (how many hosts before a repeated kit is called a pattern) |
| `references/capture.json` | A capture is truncating what you need — raise `budgets` (`same_site_total_bytes`, `max_assets`, `max_asset_bytes`). Also `capture_kinds` to start capturing images/fonts, and `layout` to change where bundles land |
| `references/pssl.json` | A passive-SSL result produced a bad cluster or missed one. **`clustering_policy` is the safety rail, not a preference**: `max_ips_per_cert` (above it a certificate is a CDN/shared-hosting cert and can never be an operator edge), `shared_subject_markers` (CDN wildcard CNs, rejected however few IPs carry them), `max_certs_per_ip`, `min_ips_for_edge`. `request_budget` bounds politeness (CIRCL is rate-limited, not credit-metered); `reporting` holds the exact wording that keeps an empty answer readable as absence of record |
| `references/intelx.json` | IntelX added a bucket you need graded, an artifact kind should (or should not) get an IntelX selector (`pivot_kind_map`), a real-world value is being misclassified (`selector_types`), or — most important — a bucket is on the wrong side of **`clustering_policy`**: `cluster_on` may support an operator edge, `never_cluster_on` (every breach corpus and stealer log) may not. **`search_plan`** owns the retrieval order: `first_pass_buckets` (the stealer logs, queried before anything else so the breach corpora can't fill the page), `general_pass` (set false on a tight allowance to buy log coverage on twice as many selectors), and `selector_priority` (domain and email first). **`search_budget` is the spend guard** |
| `references/serpapi.json` | An advertising artifact produced a bad link or a missed one. **`generic_values`** is the base-rate control (`utm_campaign=google` must never be a fingerprint); **`clustering_policy.agency_domain_threshold`** decides when an advertiser is a media buyer rather than an operator; **`ad_parameters`** adds a click id / ValueTrack macro the tool does not know yet; **`cloaking_probe`** tunes how different two views must be before it is called cloaking (raise `min_similarity` if a busy CMS keeps reading as divergent); **`probe_params` / `probe_headers`** are what the probe sends to look like a paid click; **`search_budget`** is the spend guard |
| `references/api_keys.json` | a new optional key exists, a provider changed what a tier includes, or the keyless banner overstates/understates what an absent key costs — this is what `wp_capabilities.py` prints and what `meta.capability` records |
| `references/cdn_ranges.json` | **never by hand** — generated cache; rerun `python3 tools/cdn_ranges.py --refresh` |

Two rules that keep this safe:

- **Over-filtering is the costlier direction.** A value added to a denylist silently destroys real
  attribution. Adding a *provider* is cheap; adding anything that could be an operator's own asset
  is not. The exact-vs-substring semantics of each group are stated in its `_comment` — read it.
- **A broken file degrades loudly, never silently.** If a JSON is missing or malformed, the module
  falls back to a minimal embedded list and prints a `[refs] WARNING` to stderr. Never ignore that
  warning: a filter running on the stub is a filter that manufactures false clusters.

`python3 tests/test_references.py` (also run by `tools/eval/run_eval.py`) proves every file parses,
is documented, and is actually being loaded rather than silently falling back.
