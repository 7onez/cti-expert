# Pivot Services — reverse-lookup engines (verified 2025–2026)

> Reference from the **WebPivot** toolkit by [Zeroska](https://github.com/Zeroska), integrated into cti-expert.

Reverse-lookup engines for the artifacts in [`handbook/pivot-artifacts.md`](pivot-artifacts.md),
used by [`techniques/web-pivot.md`](../techniques/web-pivot.md). `API` = scriptable; note key
requirements. ⚠️ marks services that recently changed — verify before relying.

## 1. Favicon hash
| Service | Query field | Hash algo | Cost | API |
|---|---|---|---|---|
| **Shodan** | `http.favicon.hash:<int>` | **mmh3** | Paid (favicon filter needs membership) | REST + py lib, key |
| **FOFA** | `icon_hash="<int>"` | **mmh3** | Freemium (heavy paid gating) | REST, key |
| **ZoomEye** (zoomeye.ai) | `iconhash:"<mmh3>"` | **mmh3** | Freemium credits | REST, key |
| **Quake** (360, quake.360.net) | `favicon:"<mmh3>"` | **mmh3** | Freemium credits | REST, key — independent CN index |
| **Hunter.how** (hunter.how) | `favicon_hash="<mmh3>"` | **mmh3** | Freemium quota | REST, key — independent CN index |
| **Censys** (Platform API) | `services.http.response.favicons.md5_hash` | **MD5** | Freemium | REST, key ⚠️ classic Search API retired |
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
| Service | Cost | API |
|---|---|---|
| **PublicWWW** — literal HTML/JS/CSS string | Freemium | REST, key |
| **NerdyData** — source + company data | Paid (trial) | REST, key |
| **Intelligence X** (intelx.io) — code/tracker selectors, bundles AnalyzeID GA/AdSense tabs | Freemium | REST, key |
| **Hunter.how** — live-asset source via `web.body="<string>"` / `header.*` | Freemium | REST, key |

## 4. Certificate Transparency
| Service | Query | Cost | API |
|---|---|---|---|
| **crt.sh** | `%.domain`, cert hash | Free | JSON `?output=json`, no key ⚠️ often overloaded/down |
| **Certspotter** (SSLMate) | domain | Free tier + paid | REST, free key (low quota) |
| **Censys** | cert fields | Freemium | Platform API, key |
| **Cloudflare Merkle Town / Azul** | dashboard | Free | limited |
| **crt.name** (aggregated index) | `apex=<eTLD+1>` | Free | `/v1/search`, no token, 100/IP/day — **text one-per-line by default; add `&format=json`**; **fallback below crt.sh only** |
| **agniops** (aggregated index) | `domain=<apex>` | Free | `/v1/search`, no token — **text one-per-line**; same posture as crt.name — **fallback below crt.sh only** |

> **CT is free/keyless.** crt.sh needs no key (just often overloaded); **CertSpotter**'s key is an
> *optional* reliability + rate-limit upgrade and a crt.sh fallback — its free tier also works keyless
> at a low rate. CT lookups never require payment.

> **crt.name / agniops are fallbacks, not peers of crt.sh.** Both are **aggregated** subdomain
> indexes (crt.name = CT logs **plus** Common Crawl, ICANN CZDS, ProjectDiscovery Chaos, HaGeZi;
> agniops = feeds of undisclosed provenance), so a name they return is **not CT-log-attributable evidence** the way a
> crt.sh row is. Rank them *below* crt.sh, tag results `source:crt.name(aggregated)` /
> `source:agniops(aggregated)`, and validate before any such name enters a report.
> **OPSEC:** querying either discloses the target apex to an unknown third-party operator — crt.sh and
> CertSpotter are established CT operators; these are not.
> **Auto-wiring:** `wp_recon.ct_search()` calls both — but **only as a fallback** when crt.sh *and*
> Shodan CTL return no subdomains, and their names land in a **separate** `aggregated_subdomains` /
> `aggregated_sources` channel, never merged into the CT-attributable `subdomains`. crt.name's remote
> `/mcp` endpoint stays deliberately **not** wired in — an unvetted remote MCP server is exactly the
> supply-chain / prompt-injection surface `../techniques/prompt-injection-audit.md` warns against.

### 4b. Cert-fingerprint pivots — find OTHER hosts serving the SAME cert

CT enumeration (above) lists a domain's own certs. **Cert-fingerprint pivoting** goes the
other direction: take one leaf cert's fingerprint and find every host that presents it — a
strong same-operator signal — and mine the cert's **SAN list** for sibling domains.
Automated by [`cert_pivot.py`](../scripts/webpivot/cert_pivot.py) (`/webpivot --cert`).

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
| **Validin** — DNS + certs + favicon + response-body hashes, one graph | **Free community + free API** | REST, free key ⭐ standout |
| **SecurityTrails** — passive DNS, subdomains, reverse-IP, WHOIS history | Freemium (50/mo) | REST, key |
| **DNSlytics** — reverse-IP, shared hosting, DNS history | Freemium | REST, key |
| **ViewDNS** reverseip | Free web + paid API | REST, key for API |
| **Netlas** — DNS + host responses | Freemium | REST, key |
| **Silent Push** — infra pivots, live scans, attack clustering | Mostly paid + community | REST, key |
| **HackerTarget** — reverse IP / DNS | Free (limited) + paid | REST |
| **Hunter.how** — domain/ip/cert/favicon/body asset search, CN-dense | Freemium | REST, key |

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

Full tradecraft in [`techniques/china-recon.md`](../techniques/china-recon.md). Reverse-pivot the
**licence serial** (not the province prefix) to find sibling sites under one filing.

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
- **Free-tier key:** Shodan, FOFA, **Quake**, ZoomEye, **Hunter.how**, Censys, Netlas, **Validin**, SecurityTrails, DNSlytics, VirusTotal, urlscan.io, Certspotter, PublicWWW, Intelx, Chainabuse, block explorers, abuse.ch.
- **Free but not scriptable (CAPTCHA / manual):** beian.miit.gov.cn, GSXT.
- **Geo-gated:** TianYanCha, QCC, Aiqicha — CN egress required; log a collection gap otherwise.
- **Paid/enterprise:** BuiltWith, NerdyData, hunt.io, Silent Push, Chainalysis/TRM/Elliptic.
- **No official API (scrape/manual):** AnalyzeID, osint.sh, SpyOnWeb.

Manage keys with **`/apikeys`** (see [`handbook/api-keys.md`](api-keys.md)): stored in the
skill-root `.env` (`$SKILL_DIR/.env`, `chmod 600`, gitignored) with **environment-variable
override**. `pivot_extract`'s live enrichment auto-uses Shodan / Censys / FOFA / DNSLytics /
SecurityTrails / urlscan-PRO / WhoisXML when their key is present — never commit the `.env`.
