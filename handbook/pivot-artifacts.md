# Pivot Artifacts — what to extract and where it points

> Reference from the **WebPivot** toolkit by [Zeroska](https://github.com/Zeroska), integrated into cti-expert.

A *pivot artifact* is any value in a page's HTML/DOM/headers that is likely to be
**reused** on other properties by the same operator. Reuse is the whole game: find the
artifact, search for everyone else who shares it. Extracted by
[`techniques/web-pivot.md`](../techniques/web-pivot.md) (`pivot_extract.py`).

Confidence = how strongly a shared value implies **same operator**.

| Artifact | Where it lives | Confidence | Pivots to | Harness field |
|---|---|---|---|---|
| **Favicon mmh3 hash** | `/favicon.ico`, `<link rel=icon>` | **High** | Shodan `http.favicon.hash`, FOFA `icon_hash`, ZoomEye `iconhash`, Censys (MD5), Netlas (SHA-256) | `favicon.shodan_mmh3/md5/sha256` |
| **GA4 measurement ID `G-`** | inline gtag/GTM JS | **High** | PublicWWW, urlscan, DNSlytics reverse-analytics, NerdyData | `trackers.google_analytics_ga4` |
| **GTM container `GTM-`** | GTM snippet | **High** | PublicWWW, urlscan | `trackers.google_tag_manager` |
| **AdSense `pub-` / `ca-pub-`** | AdSense JS | **High** | DNSlytics reverse-adsense, AnalyzeID, osint.sh/adsense, PublicWWW | `trackers.google_adsense` |
| **ICP licence `苏ICP备…号`** | page footer, `<meta>` | **High** (serial) | PublicWWW / NerdyData `"ICP备…"`, FOFA `body=`, Quake/ZoomEye body search, ENScan_GO; `-N` suffixes = sibling sites under one filing | `cn.icp_license` |
| **MPS public-security filing `…公安备…号`** | page footer | Medium-High | source search; corroborates the ICP registrant | `cn.mps_filing` |
| **Facebook Pixel ID** | `fbq('init','…')` | Medium-High | PublicWWW, urlscan (no dedicated reverse svc) | `trackers.facebook_pixel` |
| **GA `UA-` (legacy)** | old analytics.js | Medium | Historical only (UA shut down 2023) — SpyOnWeb, DNSlytics history | `trackers.google_analytics_ua` |
| **Yandex / Hotjar / Matomo / Mixpanel / Sentry DSN / Clarity / Intercom / Crisp / Segment** | vendor JS | Medium-High | PublicWWW / NerdyData source search; Sentry DSN reveals internal host | `trackers.*` |
| **SaaS / no-code operator tokens** (GoHighLevel `msgsndr`, backend Google Sheet ID, Make/Zapier/Apps-Script webhooks, TrustedForm) | inline/rendered JS, form scripts | **High** (private) | source search (PublicWWW/urlscan); the automation backend clusters funnels | `saas_ids.*` |
| **Crypto wallet (BTC/ETH/XMR/TRON/LTC)** | body text, JS, `href` | Medium | block explorers, Chainabuse, Arkham/Breadcrumbs clustering, PublicWWW | `crypto.*` |
| **Contact / registrant email** | mailto, body, JSON-LD | Medium | reverse-WHOIS (ViewDNS/WhoisXML), Epieos, hunter.io, urlscan | `emails` |
| **Social handles** | outbound links | Medium | platform search, cross-account correlation | `socials.*` |
| **Third-party / non-CDN hosts** | script src, hrefs | Low-Medium | crt.sh, SecurityTrails, DNSlytics, Validin | `third_party_hosts` |
| **Inline-script SHA-256** | `<script>` bodies | Medium | match identical inline scripts across scans (kit code) | `inline_script_sha256` |
| **Form action + input names** | `<form>` | Medium | phishing-kit fingerprint; PublicWWW for reused field-name sets | `forms[].action / .inputs` |
| **HTML comments** | `<!-- -->` | Low-Medium | kit author strings, build tools, dev leaks, template IDs | `html_comments` |
| **DOM skeleton hash** | tag structure | Medium | template reuse — compare skeleton hashes across pages | `dom_skeleton_sha1` |
| **Tech fingerprint** | headers + markers | Low | CMS/framework/jQuery version → narrows the population | `tech_fingerprint` |
| **Cookie names** | `Set-Cookie`, JS | Low-Medium | session/tracking cookie name-sets can fingerprint a kit/platform | `cookie_names` |
| **Server / X-Powered-By / CSP** | response headers | Low | infra + CSP `report-uri` / allowed hosts leak related domains | `server_headers` |

## Pivot logic

1. **Rank by confidence.** Favicon hash and shared analytics/ad IDs (and private SaaS tokens)
   are the strongest same-operator signals. Start there.
2. **A shared artifact is a lead, not proof.** Trackers can be copied, favicons reused by
   templates. Require **≥2 independent artifacts** overlapping before asserting a cluster.
3. **Compose queries.** Combine artifacts on one engine when possible
   (e.g. urlscan `page.url:* AND "G-XXXX"`; Shodan `http.favicon.hash:123 http.html:"pub-456"`).
4. **Passive before active.** Resolve via urlscan/Wayback/crt.sh before touching the live host,
   especially for adversarial infrastructure.
5. **Right hash per engine.** Shodan/FOFA/ZoomEye/Quake use **mmh3**, Censys uses **MD5**, Netlas
   uses **SHA-256** — the harness emits all three from one favicon.
6. **ICP: pivot on the serial, never the province.** `苏ICP备12345678号-3` → cluster on
   `12345678` (one registrant, HIGH). The `苏` prefix is a whole province; the `-3` is one site
   within the filing — enumerate siblings by walking the suffix. See
   [`techniques/china-recon.md`](../techniques/china-recon.md) §1.2.
