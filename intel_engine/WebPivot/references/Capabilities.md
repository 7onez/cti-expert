# WebPivot — Capabilities (full detail)

The SKILL.md body carries a one-line **capability index**; this file is the depth behind each row.
Open it when you're actually using a given capability. Nothing here changes behaviour — the engine
(`pivot_extract.py` + siblings) does all of this regardless; this is the reference for *how* and
*when*. All example paths assume `WP` / `CASE` set up per SKILL.md's "Running the tools" section.

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
- **`tls_cert:fingerprint_sha256`** — the cert fingerprint → Censys
  (`services.tls.certificates.leaf_data.fingerprint_sha256`), Validin, and crt.sh to find **every
  host serving the exact same certificate**.

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
