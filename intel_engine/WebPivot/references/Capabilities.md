# WebPivot — Capabilities (full detail)

The SKILL.md body carries a one-line **capability index**; this file is the depth behind each row.
Open it when you're actually using a given capability. Nothing here changes behaviour — the engine
(`pivot_extract.py` + siblings) does all of this regardless; this is the reference for *how* and
*when*. All example paths assume `WP` / `CASE` set up per SKILL.md's "Running the tools" section.

## Keyless mode — what it costs, and why it must be stated (`tools/wp_capabilities.py`)

Every tool here runs with **zero API keys**. That is a design contract, not a fallback. The risk it
creates is one of interpretation, and it is the reason this module exists:

> WebPivot always **EXTRACTS** every artifact. What a key buys is the ability to **REVERSE** one.

A keyless run therefore produces a full artifact list and a **short pivot result** — the same shape
a keyed run produces when the operator genuinely has no siblings. Nothing in the output
distinguishes them unless the run says so. That is how "no related infrastructure" ends up in an
assessment when the truth was "the index that would have found it was never queried".

```bash
python3 "$WP/tools/wp_capabilities.py"              # per key: present/absent, what's lost, the free path
python3 "$WP/tools/wp_capabilities.py" --json       # == meta.capability
python3 "$WP/tools/wp_capabilities.py" --free-only  # keys present but forbidden to spend
```

Disclosure happens in three places automatically, so it cannot be forgotten:

| Where | What it carries |
|---|---|
| **stderr banner** at the top of every `pivot_extract` run | the absent keys ranked by impact, the evidence class each removes, the free substitute. **Silent when fully keyed** — so the block never becomes noise to scroll past |
| **`meta.capability`** in the result JSON | `mode` (`keyless` / `partial` / `free-only` / `keyed`), `keys_present`, `keys_missing`, `reduced[]` (each lost evidence class), `keyless_baseline`, and a ready-to-paste `statement`. It travels with the evidence, so a reader months later sees the run's coverage without re-deriving it |
| **`--leads` header** | the same statement where the analyst is actually looking |

**The four modes.** `keyless` (no credential at all) · `partial` (some absent) · `free-only`
(credentials exist but `--free-only` forbade spending them — analytically keyless for every metered
index, which is exactly what the convergence loop runs) · `keyed` (everything present; no banner).

**Impact ranking.** `critical` absences (FOFA, urlscan) remove a *primary reverse-lookup index* —
with one missing, **absence of siblings is not evidence of absence** and confidence must be capped
accordingly. `high` (Censys, WhoisXML) removes a distinct evidence class. `medium`/`low` reduce
detail only and roll up to one banner line. What each key costs is DATA in
`references/api_keys.json` — edit that file when a provider changes, never the code.

**Reporting.** Name the mode, the unqueried indexes, and the single key that would most change the
answer. "Nothing found, and here is why that may mean nothing" is an analytic product; "nothing
found" alone is not.

## Two pivot modes — domainPivot & IPPivot (exhaust both)

`pivot_extract.py` auto-detects its input, so ONE engine covers both halves of the infrastructure:

- **domainPivot** — a URL / hostname / HTML file → the page-content flow (favicon, trackers,
  wallets, WHOIS, TLS, FOFA `body=`/subdomain, …).
- **IPPivot** — a **bare IP** (`1.2.3.4`, `[2001:db8::1]`) → a **passive** IP-recon flow
  (`tools/wp_ippivot.py`). Never touches the target: everything is an index read or a
  recursive-resolver query.

```bash
python3 "$WP/tools/pivot_extract.py" 203.0.113.7 --leads          # passive IP recon
python3 "$WP/tools/pivot_extract.py" 203.0.113.7 --pretty -o "$CASE/raw/203.0.113.7.json"
```
Per IP it pulls: **IPinfo.io** (ASN, org, PTR hostname, geo, hosting flags, abuse contact);
**classify_ip** (CDN/cloud edge vs origin candidate); **FOFA `ip="…"`** (open ports, service
banners, co-hosted domains); **Shodan host** (only if `SHODAN_KEY` set); **dig/nslookup** for
**PTR, MX, NS, TXT** (mail servers, mail domains, SPF/DMARC). It emits the same `pivots` schema
(so `--report`/`--master`/`--misp` and KB ingest all work unchanged):
- **origin-candidate IP** → a HIGH `ip` pivot; its co-hosted domains (FOFA reverse) are
  same-operator leads. Plus `ip:ports`, `ip:asn`, `ip:ptr` (distinctive reverse-DNS),
  `ip:mx` (self-hosted mail — not a managed provider).
- **noise provider** (shared CDN/cloud edge, or an ASN flagged in
  `references/asn_registry.json`) → **NOT** a same-operator pivot: recorded as `ip:information`,
  and the provider's ASN + abuse contact is banked to `asn_registry.json` for later enrichment /
  takedown routing. The registry stores **generic provider facts only** — never a target IP or case.

Chain the two modes: a domain run's live IP → feed that IP back through IPPivot; an IPPivot
co-hosted domain → feed it back through domainPivot. Optional keys: `IPINFO_TOKEN` (richer IPinfo:
structured ASN + abuse), `SHODAN_KEY` (host ports/services). All optional — the flow degrades
gracefully to keyless IPinfo + FOFA + system `dig`.

## ImpersonationHunt — hunt lookalikes of a seed — `--hunt-impersonation`

When a domain isn't just a target but a **brand being impersonated**, the highest-yield move is
often NOT analyzing the one page — it's finding every **typo / TLD-swap / keyword lookalike** an
operator registered around it. `--hunt-impersonation` turns a bare seed domain into that hunt
(`tools/wp_impersonate.py`). Like IPPivot it is **standalone and never live-fetches** the lookalike
infra — so your IP never touches the attacker's clones.

```bash
python3 "$WP/tools/pivot_extract.py" brandname.example --hunt-impersonation --leads
python3 "$WP/tools/pivot_extract.py" brandname.example --hunt-impersonation --pretty \
        -o "$CASE/raw/brandname.example.impersonation.json"
python3 "$WP/tools/wp_impersonate.py" brandname.example --generate-only --pretty   # just the candidate list, offline
```

Three moves, in yield order:
1. **Typosquat permutations** of the brand label — omission, adjacent-QWERTY-key insertion/
   replacement, transposition, character repetition, ASCII **homoglyph** (`o→0`, `l→1`, `rn→m`),
   hyphenation/de-hyphenation, and **combosquat** affixes (`brand-login`, `secure-brand`, `brandvn`).
2. **TLD sweep** — the exact brand label across a curated scam-heavy TLD list
   (`.com/.net/.io/.vip/.top/.xyz/.cc/.online/.sbs/.cfd/.icu`, common ccTLDs `.vn/.id/.ph/.br/.ng`,
   multi-part `com.vn`/`co.uk`, …).
3. **Keyword hunt** — every domain whose **name contains the brand label**, from **certificate
   transparency** (`crt.sh` identity `%label%` LIKE search — this catches lookalikes you'd never
   think to generate, e.g. `label` + random string). A too-short/generic label (< 4 chars) skips
   the LIKE sweep to avoid a noise flood; typos + TLD sweep still run.

Every generated candidate is then **existence-checked with concurrent live DNS**, so the output
separates **confirmed lookalikes** (resolve now and/or seen in CT — each an `impersonation:candidate`
pivot whose first query is `pivot_extract.py https://<lookalike>` so you can compare its pivots to
the seed and prove same-operator) from an **`impersonation:watchlist`** roll-up of unregistered
candidates to monitor (NRDs of a brand appear over time). Same `pivots` schema → `--report` /
`--master` / `--misp` and KB ingest all work unchanged, so lookalikes cluster with the rest of the
case's web infrastructure.

**Cost:** free by default — **crt.sh + DNS spend zero credits**. Add `--hunt-fofa` (FOFA
`cert="label"`) and/or `--hunt-urlscan` (`page.domain:*label*`) for the metered keyword sweeps;
both are recorded to the `api_usage` ledger. `--hunt-max N` caps generated candidates (default 600,
ordered typo → combosquat → TLD-sweep so a cap keeps the closest lookalikes).

> **WHOIS/registrant keyword hunting** — to find lookalikes tied by *who registered them* (not just
> the name), take the seed's WHOIS **registrant email/name/phone** and reverse it with the
> `reverse_whois` tool (or `pivot_extract.py … --whois-reverse`). That complements the name-based
> hunt here.

## Multi-page crawl — `--crawl`

By default the tool analyzes a single page. Add `--crawl [MAXPAGES]` to also follow the site's
**navigation / tabs / panels** (links inside `<nav>`/`<header>`/`<aside>` and menu/tab/panel/sidebar
elements), staying on the seed's **registrable domain**, and merge every page's artifacts into one
result. `--crawl-depth` sets how many link-hops deep to walk. The pages actually fetched are listed
in `meta.crawled`.
```bash
# walk up to 15 pages, 2 hops deep, and fold all their pivot artifacts together
python3 "$WP/tools/pivot_extract.py" https://target.example --crawl 15 --crawl-depth 2 --leads
```
Crawl is same-site only (never leaves the registrable domain), bounded by the page cap, and a
per-page fetch error is skipped, not fatal. It works with `--render` too (post-JS DOM per page).

## Change the User-Agent + route through a proxy — stay low-profile while crawling

- `--rotate-ua` rotates the User-Agent per request from a built-in browser pool (auto-enabled
  during `--crawl` so a multi-page walk isn't one identical fingerprint). `--ua "<string>"` pins
  one fixed UA and disables rotation.
- `--proxy URL` routes requests through a single proxy (`http://user:pass@host:port`,
  `socks5://host:port`). `--proxy-range SPEC` gives an **optional** pool that rotates per request —
  SPEC is a comma list, a file (one proxy per line), and/or a final-octet IP range like
  `10.0.0.1-10.0.0.9:8080`. Bare `host:port` tokens get an `http://` scheme. **No proxy flag →
  direct connection, unchanged.** Proxy/UA rotation apply to the target-site fetches (seed, crawl,
  favicon); third-party enrichment APIs (crt.sh/urlscan/FOFA/WhoisXML) stay on a direct path.
```bash
python3 "$WP/tools/pivot_extract.py" https://target.example --crawl --rotate-ua \
    --proxy-range 10.0.0.1-10.0.0.9:8080          # rotating UA + rotating proxy pool
python3 "$WP/tools/pivot_extract.py" https://target.example --proxy http://user:pass@host:3128
```

## Redirect & affiliate-link analysis (tracker/shortlinks)

The tool follows redirects, records the full **redirect chain** (`meta.redirect_chain`) and final
destination host, and extracts any **affiliate / referral / campaign codes** from the URL query
strings (`affid`, `ref`, `partner`, `8c`, `utm_*`, …) — base64 values are auto-decoded (e.g.
`affid=MTA2MDEzMQ==` → `1060131`). Each code becomes a MEDIUM pivot with source-search queries: run
the code in PublicWWW / urlscan / Google to find **where the promoter advertises the link** (social,
Telegram, other sites) — usually the more interesting entity than the broker. Shown inline in `--leads`.

## Registrant-name reverse WHOIS (run historic!) — `--whois-reverse`

The tool runs reverse-WHOIS by registrant **name** (not just email), in **both current and historic**
modes, and attaches the sibling domains to the `whois:registrant_name` pivot's `live_results`. A
shared registrant name can cluster sites that share *no* technical artifact — historic mode has
linked sibling brands that a current-only lookup returned as a single unrelated domain.

## Low-profile fetch + boilerplate filtering

Requests carry a full browser header profile (not just User-Agent), so basic Cloudflare/LiteSpeed
bot filters don't reset the fetch. Platform-default artifacts from hosted builders
(Wix/Squarespace/Shopify favicon hashes, `facebook.com/wix`-style handles, `*.wixpress.com` emails
and Sentry DSNs) are filtered out so they never create false same-operator clusters.

## Dead / blocked targets recover passively (not a silent miss)

If the live fetch fails (NXDOMAIN, firewalled, Cloudflare block), the tool falls back to the most
recent **urlscan stored DOM** then a **Wayback** snapshot, and — even when nothing is recoverable —
still records the intended host with its passive intel (urlscan related domains/IPs) so the target
is a persisted fact, not dropped. `recovered_via` in `meta` records the source. `--no-fallback`
disables this.

## Cloudflare-walled targets — detect + escalate (`--solve-cf`)

Many scam/leak sites sit behind Cloudflare's **managed challenge / Turnstile** (HTTP 403/503 JS
interstitial). The tool *detects* this (`meta.cloudflare`) instead of reporting a generic error,
because the fix is different from a normal block: **a User-Agent swap does NOT beat a managed
challenge** — it needs a browser that runs the challenge JS. Escalation ladder, weakest→strongest
(all already in the tool): full browser headers (always on) → `--rotate-ua` → **residential/rotating
`--proxy` / `--proxy-range`** (CF blocks datacenter IPs hardest — this is usually the deciding
factor) → `--render` (Playwright executes the JS) → **`--solve-cf`**, which on a detected challenge
tries a **FlareSolverr** instance (`--flaresolverr URL` or `$FLARESOLVERR_URL`; run
`docker run ghcr.io/flaresolverr/flaresolverr`) and then a Playwright render. FlareSolverr drives a
real headless browser and returns the solved HTML + cookies — the proper way to *collect* a
CF-walled page; we never forge a `cf_clearance` token. ⚠️ **Authorized OSINT only**
(`EthicalFramework.md`) — use non-attributable egress. Note the `--solve-cf` render path needs
Playwright in the running interpreter (use the WebPivot `.venv`).

## Not archived yet? Create a snapshot to pivot on (`--archive-missing`)

If the target has no Wayback snapshot, this submits it to **Save-Page-Now** so a permanent
third-party capture exists for this and future runs, then analyzes the fresh snapshot if nothing
else was recoverable (`archives.wayback.submitted` records the URL). Caveat: SPN's crawler is itself
blocked by a hard CF wall (you'll see a 520), so pair it with `--solve-cf` or a proxy on CF-hardened
targets.

## Collect + archive in one pass — `--save-dom` and `--submit`

Store the raw DOM you collected, and actively push the URL to the Wayback Machine *and* urlscan.io
so there's a permanent third-party capture and a fresh scan to mine later:
```bash
python3 "$WP/tools/pivot_extract.py" https://target.example --render \
    -o "$CASE/raw/target.example.json" \
    --save-dom "$CASE/dom/target.example.html" \    # store the collected DOM (add --render for post-JS)
    --submit                                         # Wayback Save-Page-Now + urlscan scan (needs URLSCAN_API_KEY)
```
`--save-dom` writes whatever was fetched (use `--render` to store the post-JS DOM — client-side
content like inline form scripts only appears there). `--submit` attaches `archives.wayback.snapshot`
and `archives.urlscan.result` to the JSON. A Wayback read-timeout does **not** mean the capture
failed — Save-Page-Now usually completes server-side.

## Historical analytics (Bellingcat method) — `tools/wayback_ga.py`

Walks a domain's *entire Wayback history* and extracts every GA/GTM/AdSense/verification ID ever
present — catching shared IDs that a network later scrubbed. Passive (only touches web.archive.org).
```bash
python3 "$WP/tools/wayback_ga.py" suspect.example --max 15 --timeline
python3 "$WP/tools/wayback_ga.py" -f domains.txt --pretty > "$CASE/history.json"
```

## Live TLS certificate — SANs, co-SAN cross-apex link, cert fingerprint

When the seed is fetched live over https (never for archived/offline input), the tool reads the
**served certificate** directly (443 handshake, stdlib `ssl` — no new dependency) and records its
**SAN list, issuer, serial, validity, and SHA-256 fingerprint** as `artifacts.tls_cert`. A
hostname-mismatched / expired / self-signed cert doesn't abort — it falls back to an unverified read
and still yields the fingerprint + DER-scanned SANs (those failures are themselves signals). Two
HIGH-confidence pivots come out of it:
- **`tls_cert:co_san`** — SANs whose **registrable domain differs from the seed's** (one cert
  covering `brand-a.com` *and* `brand-b.net`). This is often a cleaner same-operator link than the
  hosting IP. Same-site subdomains are excluded (they're just this domain's own hosts). Emits
  crt.sh / Censys / urlscan queries per co-apex.
- **`tls_cert:fingerprint_sha256`** — the cert fingerprint → Censys (`cert.fingerprint_sha256=`),
  Validin, and crt.sh to find **every host serving the exact same certificate**. With a
  `CENSYS_PAT` the tool also runs the Censys **certificate lookup** on it and attaches the result
  as `live_results.censys_cert` (see below).

## Censys Platform — the server-side view (`CENSYS_PAT`, `--no-censys`, `tools/wp_censys.py`)

FOFA and urlscan index what a page *looks like*. Censys indexes what the **server presents**, and it
is the one engine here whose free tier is shaped so that the *lookups*, not the search, are where
the value sits.

**Every pivot gets a Censys query with no key at all.** The CenQL builder is offline and free, so
each pivot's `queries` list carries the Censys query plus a **click-to-run `platform.censys.io` URL**
— which matters because a free Censys account *can* search in the web UI (1 page of 100 results,
5 credits) even though it cannot search via the API. Which artifact kinds get a query is decided by
`pivot_kind_map` in `references/censys_queries.json`; kinds Censys does not index (wallets, Telegram
handles, phone numbers) correctly get **nothing**, rather than a query that can never match.

⚠️ **CenQL, not Legacy Search.** Censys retired the old query language. `services.tls.certificates
.leaf_data.fingerprint_sha256:` does not error on the Platform — it returns **zero hits**, which
reads to an analyst as "no related infrastructure". Everything WebPivot emits is namespaced under
`host.` / `web.` / `cert.`, and `tools/eval/test_censys.py` fails the build if that ever regresses.

**With a `CENSYS_PAT`, three lookups run automatically. All three work on a FREE plan:**

| Lookup | Wired into | Why it's worth a credit |
|---|---|---|
| **certificate** by leaf SHA-256 | the `tls_cert:fingerprint_sha256` pivot → `live_results.censys_cert`; also every cert fingerprint IPPivot sees on an origin IP | returns the certificate's own **`names`** — every hostname on that exact leaf cert. crt.sh gives fuzzy *name overlap*; this is the cert **stating its own coverage**, so a multi-apex list is near-decisive cross-brand same-operator evidence |
| **host** by IP | IPPivot, alongside IPinfo/FOFA/Shodan → `artifacts.ip_intel.censys` | ASN + WHOIS org, **forward and reverse DNS names** (co-hosted hostnames FOFA and Shodan often miss), open ports, per-service banners, and the cert fingerprints the IP serves — each of which becomes its own HIGH `tls_cert:fingerprint_sha256` pivot |
| **web property** by `hostname:port` | domain enrichment → `live_results.censys` on the `domain` pivot | the cert, favicon hashes, body hash, software stack, labels and threat tags Censys holds **for the hostname the victim typed** — the server's own record, independent of what the site chose to serve us just now |

**`search` is Starter and above.** `POST /v3/global/search/query` answers **403 on a free plan**. It
degrades to `{"skipped": "...", "ui_url": ...}` carrying the identical CenQL as a UI link — that is
a degradation, not a failure, and should be reported as "run this link", never as an error.

**Credits — spend deliberately, this is the tightest quota here.** 1 per lookup, 5 per search, 8
with regex; a free account gets **100 per month that do not roll over**, and the quota is **per
account**, so an overspend in one case removes Censys from every later case until the 1st. Two
traps worth naming:

- **the UI link is not free.** Running the emitted CenQL in the web console costs the same 5
  credits as the API search. It is the free plan's only way to *search*, not a free way to search.
- **blanket enrichment is the failure mode.** A 200-domain batch doing one lookup each is two
  months of credits. Spend on the artifact that decides the question — value per credit runs
  `cert <sha256>` (1 credit → every hostname on that leaf cert) → `host <ip>` →
  `webproperty <host>` → `search`.

So the spend is **budgeted, not just logged**. `wp_censys` sums this month's Censys credits from
`MEMORY/api_usage.jsonl` (across every case) and refuses to exceed `credit_budget` in
`references/censys_queries.json`: `monthly_credits` (100), `max_credits_per_run` (20 — blast radius
for one batch), `reserve_for_lookups` (10 — a 5-credit search may not consume the last credits and
strand the cheap cert lookup), `warn_at_remaining` (30 — below this every call prints the balance).
Over budget → `{"skipped": reason, "budget": {...}, "ui_url": …}`, the same degradation shape as a
plan 403, never a mid-case 402. Override per run with `CENSYS_MONTHLY_CREDITS` /
`CENSYS_MAX_CREDITS_PER_RUN`; check the balance offline with `wp_censys.py budget` (or the `censys`
MCP tool, `mode='budget'`).

Censys is also **skipped under `--free-only`**, disabled by `--no-censys`, logged to
`MEMORY/api_usage.jsonl`, and memoised per process so one run never pays twice for the same IP.
The query builder is unaffected by all of these — it costs nothing.

**With no `CENSYS_PAT` at all** the three lookups simply do not run. `wp_censys.py` says so
explicitly rather than printing an error: what is unavailable, what is still available keyless (the
CenQL + UI link for every artifact), what the UI search costs, and how to create a free token. An
absent Censys section in a case file is a missing credential, never a finding about the target.

*JARM caveat:* Censys records JARM but only makes it **searchable** with the Adversary Investigation
module, so on Free/Starter/Core that query returns nothing — Shodan `ssl.jarm:` is the free path.
The `jarm:hash` pivot therefore emits the Censys form without a UI link.

Standalone / MCP:
```bash
python3 WebPivot/tools/wp_censys.py cert <sha256>              # the cert's full hostname list
python3 WebPivot/tools/wp_censys.py host 203.0.113.10
python3 WebPivot/tools/wp_censys.py webproperty site-a.example # defaults to :443
python3 WebPivot/tools/wp_censys.py search 'web.hostname="site-a.example"'   # Starter+
python3 WebPivot/tools/wp_censys.py query favicon_hash <md5>   # OFFLINE, no key, no credits
python3 WebPivot/tools/wp_censys.py budget                     # OFFLINE: this month's balance
```
Setup + how to create the free key: `references/Setup.md`. MCP tool: `censys` (mode = cert | host |
webproperty | search | query | budget).

## CORS policy — the backends/siblings the server admits it trusts

When the seed is fetched live over http(s) (never for archived/offline input, and only on the
primary page — not on crawled sub-pages), the tool actively probes the origin's cross-origin policy:
it sends a **foreign `Origin`** on both a GET (a "simple" request) and an **OPTIONS preflight**, then
reads what the server echoes in `Access-Control-Allow-Origin` (ACAO) and friends. This routes through
the normal `fetch()` path, so a `--proxy` is honored (unlike the raw-socket TLS probe, it never leaks
the analyst's IP). The full request/response of the exchange is kept under `artifacts.http`
(`request_headers` sent + every `response_headers` received + `status`), and the parsed verdict under
`artifacts.cors`. Three outcomes matter, and only the first is a host pivot:
- **Literal origin** (e.g. `Access-Control-Allow-Origin: https://api.backend.example`) → each named
  host becomes a **`cors_allowed_origin`** pivot. This is the point of the probe: it reveals
  **backend/API/staging/sibling origins the app trusts that never appear in the page HTML**. A named
  host on a **different registrable domain** than the seed is `medium` confidence (a cross-brand
  operator link → crt.sh `%.host` / urlscan `domain:host` / reverse-IP); a host under the seed's own
  apex is `low` (it still *confirms* a live backend subdomain worth resolving).
- **Reflect-any + credentials** (ACAO echoes back whatever `Origin` we send **and**
  `Access-Control-Allow-Credentials: true`) → a **`cors_misconfig`** lead. It names no host, but
  confirms a live, credential-bearing API; feed it candidate Origins to enumerate more trusted hosts.
- **`*` (wildcard)** → a public asset host, recorded but **not** treated as an operator pivot.
Corroborate a `cors_allowed_origin` link with a second artifact (favicon / cert / tracker) before
asserting common ownership — a shared backend can also just be a shared SaaS vendor.

## Mail server / provider — `dig MX` before you spend time on recon

On a live domain (never archived/offline; one query per case — skipped on crawled sub-pages) the
tool resolves the domain's **MX records** via `dig` (nslookup fallback) and classifies the mail
infrastructure into `artifacts.mail`. It's a recursive-resolver query — **passive, no target contact,
no API cost** — but it answers three investigation-shaping questions up front:
- **Which managed provider?** — Google Workspace (`aspmx.l.google.com`), Microsoft 365
  (`*.mail.protection.outlook.com`), Proofpoint, Mimecast, Zoho, Yandex, Proton, Cloudflare Email,
  Amazon WorkMail/SES, Fastmail, Namecheap Private Email, GoDaddy, Tencent/Alibaba/NetEase, forwarders
  (ImprovMX / ForwardEmail), … A managed provider is **attribution context, not a host pivot** (millions
  of tenants share `aspmx.l.google.com`).
- **Microsoft 365 is the exception → `m365_tenant` pivot.** An M365 MX host
  `<routing>.mail.protection.outlook.com` **encodes the organization's own tenant domain** (dashes
  stand in for dots), so `github-com.mail.protection.outlook.com` reveals the tenant behind the site —
  and other domains on the same tenant. Emitted `medium`.
- **Custom / self-hosted MX → `mail_server` pivot.** An exchange matching no known provider is real
  operator mail infra. On the seed's own apex it's self-hosted (`low`; the mail box's IP + other
  domains it serves are pivots); on a **different** apex it's third-party/shared mail infra (`medium`;
  other domains pointing their MX here — reverse-MX — can be a same-operator link).
- **No MX at all** — the domain isn't configured to receive mail: a common **throwaway / parked-scam**
  tell (they only need to serve a page, not run a mailbox). Surfaced in `--leads` (`📭 Mail: no MX`).

The same pass also reads the domain's **SPF** (apex TXT) and **DMARC** (`_dmarc.<domain>` TXT) into
`artifacts.mail.spf` / `.dmarc` — the other half of a domain's mail posture, and a rich seam of pivots:
- **SPF custom `include:`** — an authorized-sender domain matching no major ESP is the operator's own
  or a bespoke mailer → **`spf_include`** pivot (major ESPs like `_spf.google.com` / `spf.protection.outlook.com`
  are suppressed as context). **SPF `ip4:`/`ip6:`** single hosts are the actual sending servers →
  **`mail_sender_ip`** pivots (reverse-IP / FOFA `ip=`); a whole netblock is skipped as an ESP range.
- **DMARC `rua`/`ruf`** reporting addresses NOT at a monitoring vendor (dmarcian, Postmark, Valimail…)
  are **operator-controlled** mailboxes → **`dmarc_contact`** pivots (a strong attribution + reverse-WHOIS
  seam; e.g. `dmarc@<their-own-domain>`). The DMARC **policy** (`p=none/quarantine/reject`) is surfaced,
  and a domain with SPF but **no DMARC** is flagged as spoofable.
The provider / tenant / custom-MX / SPF / DMARC verdict shows as a banner in `--leads`; pivots rank inline.

## CT / SSL search — two indexes merged, resilient, wildcard-aware

Live enrichment runs a certificate-transparency search on the base domain via `ct_search()`, which
queries **both crt.sh and Shodan's keyless CTL mirror** (`ctl.shodan.io/api/v1/domain/<d>` +
`/hostnames`) concurrently and unions the results. crt.sh queries **both** `%.<domain>` (subdomains)
**and** the apex `identity`, and — because crt.sh's `?q=` endpoint frequently returns nginx **502s**
— falls back to the more stable `?identity=` form (`_crtsh_fetch`); when crt.sh is down entirely,
Shodan CTL still returns the subdomains + certs, so a CT lookup no longer silently fails. Shodan's
`/hostnames` endpoint enumerates every logged hostname directly and each cert's `san_dns_names`
exposes **SAN-sibling domains** (a different registrable domain on the same cert = strong same-owner
link). The result carries, per logged certificate, the **issuer + validity window + serial**, and
flags any **wildcard cert** (`*.<domain>`) separately (`wildcards` field) — one wildcard cert can
cover many sibling hosts, so it's a broad-scope-reuse signal worth pivoting. Shown inline in
`--leads` (cert timeline + wildcard note). A per-domain Let's Encrypt cert with only `apex`+`www`
SANs (common on Hostinger/shared auto-SSL) is **not** a shared-operator pivot — read the issuer +
SAN scope before treating a cert as a link.

## Hosting IP is noise, not a pivot — `cdn_ranges` is wired in

During live enrichment each resolved IP is classified against `tools/cdn_ranges.py`
(Cloudflare/Fastly/CloudFront/Google/Bunny ranges). A shared **CDN/cloud edge** IP is flagged as
noise and the FOFA IP-reverse is **skipped** for it (reversing a Cloudflare IP returns thousands of
unrelated tenants); only an **origin-candidate** IP gets reversed. Classification is attached to the
domain pivot's `live_results.dns.ip_classification`. If the range cache is missing the step degrades
gracefully (old behaviour). Refresh ranges with `python3 WebPivot/tools/cdn_ranges.py --update`.

## Asset layer — JS bundles, source maps, policy files (`--no-assets` / `--no-well-known`)

**The problem it solves:** on a modern SPA / white-label kit the shell HTML is nearly empty. Every
extractor in this document is pointed at the HTML document, so on exactly the kits that matter most
they find nothing. The operator's real configuration lives in `/assets/index-<hash>.js` or a
`config.js`, and the developer's own machine paths survive in the `.js.map`.

**1. JS bundles** (default ON). Resolves the page's `<script src>` list, keeps only the seed's own
registrable domain, skips known third-party libraries, and priority-orders the rest — config/env
names first, then content-hashed build artifacts, then entry points — capped at `--assets-max`
(default 6) and a 2 MB total budget. Each bundle is fetched exactly once; its **sha256 is a re-skin
resistant kit fingerprint** (a rebrand changes the favicon and the DOM, not the compiled bundle).
Every existing extractor (trackers, SaaS tokens, crypto, Telegram, socials, emails) is then re-run
over the bundle source and merged into the normal artifact dicts, with provenance kept under
`artifacts.assets.js_derived`. **Phone extraction is deliberately excluded** — minified JS is dense
with numeric literals and would return pure garbage; crypto survives only because every candidate is
checksum-validated.

**2. Backend / API endpoints.** `baseURL` / `apiUrl` / `axios.create` assignments, `wss://` sockets,
`/graphql` endpoints, and hostnames whose leftmost label reads as a backend tier (`api`, `gateway`,
`svc`, `trade`, …). Split into **off-apex** `api_endpoint` (HIGH — in a white-label kit the backend
is shared by every front and is the strongest same-operator link the front end can give you) vs
`api_endpoint:same_site` (LOW — infrastructure context, not a cross-site pivot). Analytics/CDN/SaaS
endpoints are filtered out, and a backend on a hosted-platform apex is rejected by the one noise
policy (`noise_filters.is_noise_indicator`) so a shared BaaS never becomes a same-operator edge —
the same same-KIT-not-same-OPERATOR trap as a shared nameserver.

**3. Build-time env vars.** `VUE_APP_*` / `REACT_APP_*` / `NEXT_PUBLIC_*` / `VITE_*` values inlined
by the bundler become `build_env:<KEY>` pivots. A brand/tenant-shaped key is HIGH: it is the
white-label platform naming its own customer. **Read it carefully — the same KEY with the same VALUE
is the same tenant; the same KEY with a DIFFERENT value is the same PLATFORM, not the same
operator.** Empty and boolean values are dropped.

**4. Source maps.** Follows `sourceMappingURL` (including inline `data:` maps) to the `.js.map` and
parses `sources[]` for `dev_username` (the build machine's home directory — CI/runner accounts like
`builder`, `jenkins`, `ubuntu` are rejected), `dev_project` (the internal, often un-rebranded name of
the kit), and `dev_path`. `node_modules` entries are dependency noise and never contribute a project
root. When the map ships `sourcesContent`, the **original un-minified source — with the operator's
own comments, often in their native language — is recoverable from that one file.** These artifacts
survive every front-end re-skin and are among the strongest passive attribution signals available.

**5. SPA route table — passive path discovery.** A single-page app ships its *entire* routing
table inside the bundle: Vue Router, React Router and Angular all compile to object literals
carrying `path:"/…"`, and Next.js emits a `sortedPages` manifest (plus `__NEXT_DATA__` in the HTML).
Because the bundle was already fetched for the steps above, **recovering the app's full URL
inventory costs ZERO additional requests to the target** — no wordlist, no 404 storm, nothing for
the operator to notice. This is the passive answer to "what paths exist here", and it is strictly
better than brute-forcing: a router table lists the routes that actually exist, including ones no
wordlist would guess.

- `spa_route_signature` — sha256 over the **sorted** route set (order-independent, so a bundler
  reshuffling declaration order between builds can't change it; needs ≥3 routes to be meaningful).
  An identical route inventory on another domain means the same compiled application, which
  survives a cosmetic re-skin. Like any kit fingerprint this is same-**KIT**; corroborate with an
  owner-tied artifact before calling it same-**OPERATOR**.
- `spa_route:admin` (LOW) — `/admin`, `/console`, `/backoffice`, `/staff`… the operator surface the
  public funnel never links to.
- `spa_route:funnel` (LOW) — `/deposit`, `/withdraw`, `/kyc`, `/invite/:code`, `/commission`… reads
  out what the application *does to a victim* without walking the funnel.
- `spa_route_name` (LOW) — named routes are the developer's own vocabulary; an unusual name reused
  under another brand points at the same codebase.

Angular declares routes without a leading slash and is normalized, so the same app yields the same
signature across frameworks. SVG icon path data (`{path:"M0 0L10 10z"}` in icon libraries) is the
single biggest false-positive source and is explicitly rejected, along with bundled asset paths,
the root route, and catch-alls. **The tool never fetches a discovered route** — visiting an admin
path found this way is an analyst decision and a separate authorization question; the emitted
queries point at the Wayback archive first. In the KB, the signature is a `same_route_table` edge
while individual admin/funnel routes are recorded as facts only, because `/admin` is universal and
would false-cluster the entire internet.

> **Note — unquoted HTML attributes.** Production builds minify the HTML and drop attribute quotes
> (`<script src=/static/js/app.6c9e4bdf.js>`). The extractor's attribute regexes accept both forms;
> a quote-mandatory pattern silently finds no scripts at all on exactly these built-SPA kits.

**6. Well-known / policy files** (default ON; `--no-well-known`). A **fixed list of published
standards** — `robots.txt`, `sitemap.xml`, `ads.txt`, `app-ads.txt`, `.well-known/security.txt`,
`humans.txt`, `.well-known/apple-app-site-association`. **This is not a wordlist and it never grows
at runtime — nothing here brute-forces paths.** An HTML body is rejected for all of them so a SPA
catch-all route that 200s every path can't manufacture phantom policy files. Yields:

| Artifact | Pivot | Why it matters |
|---|---|---|
| `ads.txt` / `app-ads.txt` | `adstxt_publisher` | An AdSense/AdManager `pub-…` id is an **owner-registered** monetization account — a stranger cannot declare yours. **Tier A**, same strength class as a GSC verification token or an own GA4 property. Reverse it for every property that operator monetizes |
| `apple-app-site-association` | `apple_team_id`, `ios_bundle_id` | The iOS twin of `assetlinks.json`. A Team ID is one paid, identity-verified Apple account signing every app the operator ships |
| `security.txt` | `security_contact` | Operator-controlled mailbox → reverse-WHOIS it |
| `robots.txt` | `robots_disallow` (LOW) | Admin/staging/panel paths the operator chose to hide — check the **archive** before touching one live |
| `sitemap.xml` | (artifact) | Full funnel URL inventory; a better crawl frontier than scraping `<a>` tags |

**Footprint / OPSEC.** Fetching the page's own JS is *less* anomalous than not fetching it — a real
browser retrieves every one of those files. The seven policy GETs are the genuine extra footprint,
on standard crawler-expected paths. All of it is FREE and keyless (never touched by `--free-only`),
routes through `fetch()` so `--proxy` is honoured, and is gated to a **live, non-archived primary
page** — never an offline/Wayback source, never re-run per crawled sub-page. `artifacts.assets.
coverage` records what was attempted vs found, so "nothing here" stays distinguishable from "we
didn't look."

## What it extracts

(see `references/PivotArtifacts.md`): favicon mmh3/md5/sha256, analytics & ad IDs (GA4 `G-`, `GTM-`,
AdSense `pub-`, FB Pixel, Yandex, Hotjar, Matomo, Sentry DSN, …), crypto wallets (BTC/ETH/XMR/TRON/LTC),
**app-download artifacts** (direct `.apk`/`.aab`/`.ipa` URLs + the backend host serving them, **desktop
"trading terminal" installers** — `.exe`/`.msi`/`.dmg`/`.pkg`/`.appimage`/`.deb` — Android package ids,
iOS app ids, smart-app-banner meta, `intent://` deep links, and the APK **signing-cert SHA-256** +
package from `/.well-known/assetlinks.json`). Each detected file emits an `app:apk` /
`app:desktop_installer` pivot whose first query is the exact **BinaryPivot** command to statically
extract the file's own IOCs (signing cert, embedded C2/backend hosts, wallets) — those become shared
indicators that cluster the app with the web infra, emails, social handles, third-party hosts,
inline-script SHA-256, form actions + input names (phishing-kit tell), HTML comments, DOM-skeleton
hash (template reuse), tech fingerprints, cookie names, server headers, the **full HTTP
request/response headers and an active CORS probe** (`artifacts.http` + `artifacts.cors` — see the
CORS section above; trusted backend/sibling origins the HTML never names), the **mail provider + MX
records** (`artifacts.mail` — Google Workspace / M365 tenant / custom self-hosted MX / no-MX, via
`dig`), **SaaS / no-code operator tokens** (GoHighLevel `msgsndr` location ID, backend Google Sheet
ID, Make/Zapier/Apps-Script automation webhooks, TrustedForm lead-cert) — attribution-grade for
hosted-builder funnels, and only fully present in the `--render` DOM.

## QR codes — the money is often hidden in the QR (`qr:*` pivots)

Scam funnels put the deposit wallet, a Telegram invite, or a WhatsApp/affiliate link inside a QR
image instead of in text, so it dodges keyword extraction. `pivot_extract.py` handles this two ways:
- **Zero-dep, always on:** when the page renders the QR through a generator *service*
  (`api.qrserver.com/...?data=`, Google Charts `chart.googleapis.com/...&chl=`, QuickChart, tec-it, …)
  the payload sits in the image URL query string — the tool URL-decodes it directly, no image
  processing needed.
- **`--decode-qr` (optional):** fetches candidate `<img>`/inline `data:` images and decodes them from
  pixels via `pyzbar`+Pillow or OpenCV if installed. Without a decoder lib, a detected QR is **still
  surfaced** as a `qr:undecoded_image` lead (never silently dropped). A canvas-drawn QR has no `<img>`
  to read statically — capture it with `--render --screenshot` and decode the screenshot.

Decoded payloads are classified into pivots — `qr:crypto:<coin>` (HIGH, the payout wallet, also fed
to the KB as `qr_wallet_*` so a reused deposit address clusters operators), `qr:telegram` (HIGH),
`qr:whatsapp`, and `qr:url` (a URL in a QR is usually a redirector/affiliate link — the `qr:url`
pivot's first query resolves the redirect to the real destination). **URL redirects are first-class**:
the tool already records the seed's full `meta.redirect_chain` + affiliate/referral codes, and every
URL-bearing pivot keeps the **full, unshortened URL** so you can resolve it.

## What it emits

A `pivots` array, ranked high→low confidence, each with copy-paste queries for the right engine (with
the correct hash algorithm per engine — Shodan/FOFA=mmh3, Censys=MD5, Netlas=SHA-256), plus
redirect-chain / affiliate-code pivots for tracker links, live-TLS-cert pivots (`tls_cert:co_san`
cross-apex + `tls_cert:fingerprint_sha256`), CORS-trusted-origin pivots (`cors_allowed_origin`
backend/sibling hosts + a `cors_misconfig` flag), mail-infra pivots (`mail_server` custom/self-hosted
MX + `m365_tenant`, via `dig MX`), and reverse-WHOIS (email + name, current + historic) under
`--whois-reverse`.

## Case graph — `tools/graph_build.py`

Merges many `pivot_extract` JSONs into one normalized, **clustered** graph model: typed nodes
(domains + shared artifacts as hub nodes), evidence-graded edges, plus connected components,
**Louvain communities**, and **betweenness centrality** — all zero-dependency. Feeds the interactive
renderer.
```bash
python3 "$WP/tools/graph_build.py" "$CASE"/raw/*.json --operator "name" --operator-links a.com,b.com -o "$CASE/case_graph.json"
# then render (IntelGraph skill): python3 ~/.claude/skills/IntelGraph/scripts/render_network.py "$CASE/case_graph.json" "$CASE/network.html" --title "..."
```
See `Workflows/NetworkGraph.md` for the full extract → build → render pipeline and how to read it.

## Notes on artifact reliability (2025-2026)

- **GA `UA-` IDs are historical** (Universal Analytics shut down Jul 2023). Live analytics artifacts are GA4 `G-` and `GTM-`.
- **crt.sh is frequently overloaded** — `ct_search` auto-covers it with the keyless **Shodan CTL** mirror (`ctl.shodan.io`); Certspotter / Censys remain further CT fallbacks.
- **Validin** is the current standout free/low-cost infra-pivot engine (DNS + certs + favicon + response-body hashes in one graph).
- **Chainabuse** (absorbed Bitcoinabuse) is the primary free crypto-scam reporting DB with a real public API.
