# Pivot Services — reverse-lookup engines (verified 2025-2026)

Grouped by artifact. `API` = scriptable; note key requirements. Flags mark
services that recently changed — verify before relying.

## 1. Favicon hash
| Service | Query field | Hash algo | Cost | API |
|---|---|---|---|---|
| **Shodan** | `http.favicon.hash:<int>` | **mmh3** | Paid (favicon filter needs membership) | REST + py lib, key |
| **FOFA** | `icon_hash="<int>"` | **mmh3** | Freemium (heavy paid gating) | REST, key |
| **ZoomEye** (zoomeye.ai) | `iconhash:"<mmh3>"` | **mmh3** | Freemium credits | REST, key |
| **Quake** (360, quake.360.net) | `favicon:"<mmh3>"` | **mmh3** | Freemium credits | REST, key — independent CN index |
| **Censys** (Platform API) | `web.endpoints.http.favicons.hash_md5=<md5>` | **MD5** | Free plan = **no search API** (UI only, 5 credits/query); Starter+ for the API | REST, PAT ⚠️ **CenQL, not Legacy Search** — the old `services.http.response.favicons.md5_hash` no longer runs |
| **Netlas** | `http.favicon.hash_sha256` | **SHA-256** | Freemium + 14-day trial | REST, key |
| **Validin** | favicon in host-response graph | body hashes | Free community + free API | REST, free key |

Helper tools that build cross-engine queries: `favihunter`, `favihash`, osint.sh favicon tool.

## 2. Tracking / analytics / ad IDs
| Service | Input | Cost | API |
|---|---|---|---|
| **DNSlytics** reverse-adsense / reverse-analytics | UA/G/pub ID | Freemium | REST, key |
| **HackerTarget** reverse-analytics-search | GA/AdSense ID | Free (rate-limited) + paid | REST |
| **AnalyzeID** | GA, AdSense, Amazon-affiliate, email, IP | Free web | no official API |
| **SpyOnWeb** (spyonweb.net) | GA/AdSense/IP/NS | Free | ⚠️ churned owners, thinner results |
| **osint.sh** /analytics /adsense | GA/AdSense ID | Free web | API sponsors-only |
| **PublicWWW** | any source string incl. `fbq('init','id')`, `pub-…` | Freemium (paid export) | REST, key |
| **BuiltWith** Relationships | GA/AdSense/pixel | Mostly paid | REST, key |
| **hunt.io** | tracker IDs as threat-graph pivots | Paid | HuntSQL, key |
| **urlscan.io** | search DOM for the ID | Free tier + paid | REST, free key |

⚠️ GA `UA-` shut down Jul 2023 — historical only. Live: `G-` (GA4), `GTM-`. FB Pixel has no dedicated reverse service → use PublicWWW / urlscan.

## 3. Source-code / HTML string search
| Service | Query | Cost | API |
|---|---|---|---|
| **FOFA** — served-HTML body | `body="<literal string>"` | Freemium | REST, key |
| **PublicWWW** — literal HTML/JS/CSS string | the string | Freemium | REST, key |
| **NerdyData** — source + company data | the string | Paid (trial) | REST, key |
| **Intelligence X** (intelx.io) — code/tracker selectors, bundles AnalyzeID GA/AdSense tabs | the string | Freemium | REST, key |

**FOFA `body=` is the HTML-search pivot** — when IntelAnalysis flags a high-value keyword/phrase
(a slogan, brand string, distinctive class/template literal), reverse it with `body="<phrase>"`
(combine with `&&`, e.g. `body="a" && body="b"`) to find every host serving that HTML. It often
beats PublicWWW on freshly-registered domains FOFA has crawled but PublicWWW hasn't indexed.
`pivot_extract` auto-emits a FOFA `body=` query for every HTML-string artifact (verification /
tracker / description / footer / SaaS id) and takes analyst keywords via `--fofa-keyword "<phrase>"`
(repeatable) — searched live when a `FOFA_KEY` is set.

**Unique subdomain label** (e.g. `svc-a.site-a.example`) — a distinctive, non-generic leftmost label is
an operator naming convention. Reverse it across other apexes: FOFA `host="<label>."`, crt.sh
`<label>.%`, Shodan `ssl.cert.subject.CN:"<label>"` / `hostname:"<label>"`, Censys
`host.dns.names:"<label>"` (tokenised `:`, **not** `=` — the value is a label, not a whole
hostname). `pivot_extract` emits this as a `subdomain` pivot automatically.

## 4. Certificate Transparency
| Service | Query | Cost | API |
|---|---|---|---|
| **crt.sh** | `%.domain`, cert hash | Free | JSON `?output=json`, no key ⚠️ often overloaded/down |
| **Shodan CTL** ⭐ | domain | Free | **keyless mirror of the crt.sh DB — steadier when crt.sh 502s** |
| **Certspotter** (SSLMate) | domain | Free tier + paid | REST, free key (low quota) |
| **Censys** ⭐ | `cert.fingerprint_sha256=<sha256>` (search, Starter+) — **or the certificate LOOKUP, which works on the FREE plan and returns the cert's own `names` list** | Free (1 credit/lookup, 100/month) | Platform API, PAT · `wp_censys.py cert <sha256>` |
| **Cloudflare Merkle Town / Azul** | dashboard | Free | limited |

**Shodan CTL (keyless, no Shodan account needed)** — a second CT index that reads the same
crt.sh database from a steadier host, so it covers crt.sh's frequent outages. Two endpoints:
```
https://ctl.shodan.io/api/v1/domain/<domain>            # cert objects: subject_cn, issuer_cn,
                                                         #   not_before/after (unix epoch), san_dns_names
https://ctl.shodan.io/api/v1/domain/<domain>/hostnames  # flat JSON array of every hostname → subdomains
```
Use it to **enumerate a target's subdomains** and to read each cert's `san_dns_names` — a cert
whose SAN list covers a *different registrable domain* is a strong same-operator link. `pivot_extract`
now queries crt.sh **and** Shodan CTL concurrently and unions them (`ct_search`), so a run survives
either source being down and gets fuller subdomain coverage; `tools/fallback_probe.py` does the same
on cold seeds.

### 4b. Cert-fingerprint pivots — find OTHER hosts serving the SAME cert

CT enumeration (above) lists a domain's own certs. **Cert-fingerprint pivoting** goes the
other direction: take one leaf cert's fingerprint and find every host that presents it — a
strong same-operator signal — and mine the cert's **SAN list** for sibling domains.
Automated by [`cert_pivot.py`](../../../scripts/webpivot/cert_pivot.py) (`intel.py cert-pivot`).

| Engine | Query field | Hash algo | Notes |
|---|---|---|---|
| **Shodan** | `ssl.cert.fingerprint:<hash>` | **SHA-256** (SHA-1 alt) | key → live hosts; web link keyless |
| **Censys** | `services.tls.certificates.leaf_data.fingerprint_sha256="<hex>"` | **SHA-256** | `CENSYS_API_ID`+`_API_SECRET` |
| **FOFA** | `cert="<sha256>"` | **SHA-256** | base64-wrapped web query |
| **crt.sh** | `?id=<n>` / `?serial=<hex>` / `?q=<sha256>` | — | keyless; SANs = sibling domains |

The leaf-cert fingerprint is computed **keyless** from a live TLS handshake (stdlib `ssl`);
no key is needed to obtain it or to build the clickable pivot links — keys only run the
searches server-side.

## 5. Passive DNS / shared IP / shared infra
| Service | Cost | API |
|---|---|---|
| **IPinfo.io** — ASN, org, PTR hostname, geo, hosting/privacy flags, abuse contact | Free tier (richer with token) | REST, `IPINFO_TOKEN` |
| **FOFA** `ip="<ip>"` — open ports, service banners, co-hosted domains (passive) | Freemium | REST, `FOFA_KEY` |
| **Shodan** host — ports, services, hostnames | Paid (host API needs key) | REST, `SHODAN_KEY` |
| **Validin** — DNS + certs + favicon + response-body hashes, one graph | **Free community + free API** | REST, free key ⭐ standout |
| **SecurityTrails** — passive DNS, subdomains, reverse-IP, WHOIS history | Freemium (50/mo) | REST, key |
| **DNSlytics** — reverse-IP, shared hosting, DNS history | Freemium | REST, key |
| **ViewDNS** reverseip | Free web + paid API | REST, key for API |
| **Netlas** — DNS + host responses | Freemium | REST, key |
| **Silent Push** — infra pivots, live scans, attack clustering | Mostly paid + community | REST, key |
| **HackerTarget** — reverse IP / DNS | Free (limited) + paid | REST |

**IPPivot noise control** — WebPivot's `wp_ippivot.py` classifies each IP as an *origin candidate*
(reverse-IP co-tenants = same-operator leads) or *noise* (shared CDN/cloud edge / bulk hosting,
where reverse-IP returns unrelated tenants). Noise providers are skipped as pivots but their ASN +
abuse contact is banked to `references/asn_registry.json` (generic provider facts only) for later
enrichment and takedown routing. A bare IP into `pivot_extract.py` runs this passive flow
(IPinfo + FOFA `ip=` + Shodan + `dig` MX/NS/TXT/PTR) — never a packet to the target.

## 6. URL/page scan & historical DOM
| Service | Cost | API |
|---|---|---|
| **urlscan.io** — full DOM, resources, screenshots, IPs, cookies, searchable corpus | Free + paid | REST, free key |
| **Wayback / CDX** — historical snapshots + capture index | Free | CDX API, no key |
| **VirusTotal** — detections, relations, historical resolutions | Freemium (500/day) | REST v3, key |
| **URLhaus / ThreatFox** (abuse.ch) — malware URL listings | Free | REST ⚠️ auth-key now required (2024+) |
| **PhishTank** — verified-phish status | Free | API ⚠️ registration/feed access restricted |
| **OpenPhish** — phishing feed | Free community + paid | feed |

## 7. Crypto-address pivoting
| Service | Cost | API |
|---|---|---|
| **Chainabuse** (absorbed Bitcoinabuse) — community scam reports | Free | Public API v1.2, free key |
| **Block explorers** — etherscan/blockchain.com/blockstream/tronscan/bscscan | Free | REST, free-tier key |
| **Breadcrumbs** — visual wallet-clustering | Freemium | REST, key |
| **Arkham Intelligence** — entity attribution/clustering | Free web + paid | limited API |
| **Chainalysis / TRM / Elliptic** — pro clustering, sanctions | Enterprise | gated |
| **OFAC SDN crypto list** — sanctioned-address match | Free | data download |

## 8. China: ICP filings, PRC registries, CN cyberspace indexes

Full tradecraft in [`techniques/china-recon.md`](../../../techniques/china-recon.md). Reverse-pivot
the **licence serial** (not the province prefix) to find sibling sites under one filing.

| Service | Input → output | Cost | API |
|---|---|---|---|
| **beian.miit.gov.cn** | domain → filing entity, licence, approval date | Free | none — CAPTCHA, Chinese-only ⚠️ authoritative |
| **ICP_Query** / beian mirrors (chinaz, aizhan) | domain → cached filing | Free | scriptable; mirrors go stale → trust 2 until MIIT-confirmed |
| **PublicWWW / NerdyData** | `"ICP备<serial>号"` → sibling domains | Freemium | REST, key |
| **FOFA / Quake / ZoomEye** | `body="ICP备<serial>"` → hosts | Freemium | REST, key |
| **ENScan_GO** | company 中文全名 → ICP filings, domains, apps, mini-programs | Free tool | CLI; needs aggregator cookies |
| **GSXT** (gsxt.gov.cn) | USCC / 中文全名 → registration, legal rep, capital, status | Free | none — slider CAPTCHA ⚠️ ground truth |
| **信用中国** (creditchina.gov.cn) | company → penalties, 失信 blacklist | Free | limited |
| **TianYanCha / QCC / Aiqicha** | company → shareholders, officers, branches, related firms | Freemium | ⚠️ **IP-blocked outside mainland**; needs CN egress + +86 account |
| **Cninfo** (cninfo.com.cn) | listed company → official filings | Free | listed companies only |
| **Sayari / Datenna** | company → cross-border UBO, sanctions | Enterprise | REST, key |

## Scriptable-API cheat sheet
- **No key:** crt.sh, Wayback CDX, Cloudflare Merkle Town, ViewDNS (web), Cninfo, 信用中国.
- **Free-tier key:** Shodan, FOFA, **Quake**, ZoomEye, **Censys** (⚠️ free = **lookup endpoints only**, 100 credits/month; search is Starter+ — see `Setup.md`), Netlas, **Validin**, SecurityTrails, DNSlytics, VirusTotal, urlscan.io, Certspotter, PublicWWW, Intelx, Chainabuse, block explorers, abuse.ch.
- **Free but not scriptable (CAPTCHA / manual):** beian.miit.gov.cn, GSXT.
- **Geo-gated:** TianYanCha, QCC, Aiqicha — CN egress required; log a collection gap otherwise.
- **Paid/enterprise:** BuiltWith, NerdyData, hunt.io, Silent Push, Chainalysis/TRM/Elliptic.
- **No official API (scrape/manual):** AnalyzeID, osint.sh, SpyOnWeb.

Store your keys in a `chmod 600` `.env` at the repo root, or export them (never commit). See
`references/Setup.md`.

---

> **Canonical copy.** Single source of truth for pivot services; the repo-root
> `handbook/pivot-services.md` is a pointer to it. Merged 2026-08-27 from two copies that had
> drifted apart. The root copy still taught the **retired** Censys query
> `services.http.response.favicons.md5_hash`; §1 above carries the CenQL replacement. Kept from
> the root copy and NOT present upstream: Quake, §4b cert-fingerprint pivots, §8 China registries.
