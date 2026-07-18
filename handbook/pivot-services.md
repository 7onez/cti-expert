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

## 4. Certificate Transparency
| Service | Query | Cost | API |
|---|---|---|---|
| **crt.sh** | `%.domain`, cert hash | Free | JSON `?output=json`, no key ⚠️ often overloaded/down |
| **Certspotter** (SSLMate) | domain | Free tier + paid | REST, free key (low quota) |
| **Censys** | cert fields | Freemium | Platform API, key |
| **Cloudflare Merkle Town / Azul** | dashboard | Free | limited |

> **CT is free/keyless.** crt.sh needs no key (just often overloaded); **CertSpotter**'s key is an
> *optional* reliability + rate-limit upgrade and a crt.sh fallback — its free tier also works keyless
> at a low rate. CT lookups never require payment.

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

## Scriptable-API cheat sheet
- **No key:** crt.sh, Wayback CDX, Cloudflare Merkle Town, ViewDNS (web).
- **Free-tier key:** Shodan, FOFA, ZoomEye, Censys, Netlas, **Validin**, SecurityTrails, DNSlytics, VirusTotal, urlscan.io, Certspotter, PublicWWW, Intelx, Chainabuse, block explorers, abuse.ch.
- **Paid/enterprise:** BuiltWith, NerdyData, hunt.io, Silent Push, Chainalysis/TRM/Elliptic.
- **No official API (scrape/manual):** AnalyzeID, osint.sh, SpyOnWeb.

Manage keys with **`/apikeys`** (see [`handbook/api-keys.md`](api-keys.md)): stored in the
skill-root `.env` (`$SKILL_DIR/.env`, `chmod 600`, gitignored) with **environment-variable
override**. `pivot_extract`'s live enrichment auto-uses Shodan / Censys / FOFA / DNSLytics /
SecurityTrails / urlscan-PRO / WhoisXML when their key is present — never commit the `.env`.
