# Pivot Artifacts — what to extract and where it points

A *pivot artifact* is any value in a page's HTML/DOM/headers that is likely to be
**reused** on other properties by the same operator. Reuse is the whole game:
find the artifact, search for everyone else who shares it.

Confidence = how strongly a shared value implies **same operator**.

| Artifact | Where it lives | Confidence | Pivots to | Extracted by harness |
|---|---|---|---|---|
| **Favicon mmh3 hash** | `/favicon.ico`, `<link rel=icon>` | **High** | Shodan `http.favicon.hash`, FOFA `icon_hash`, ZoomEye `iconhash`, Censys (MD5), Netlas (SHA-256) | ✅ `favicon.shodan_mmh3/md5/sha256` |
| **GA4 measurement ID `G-`** | inline gtag/GTM JS | **High** | PublicWWW, urlscan, DNSlytics reverse-analytics, NerdyData | ✅ `trackers.google_analytics_ga4` |
| **GTM container `GTM-`** | GTM snippet | **High** | PublicWWW, urlscan | ✅ `trackers.google_tag_manager` |
| **AdSense `pub-` / `ca-pub-`** | AdSense JS | **High** | DNSlytics reverse-adsense, AnalyzeID, osint.sh/adsense, PublicWWW | ✅ `trackers.google_adsense` |
| **Facebook Pixel ID** | `fbq('init','…')` | Medium-High | PublicWWW, urlscan (no dedicated reverse svc) | ✅ `trackers.facebook_pixel` |
| **GA `UA-` (legacy)** | old analytics.js | Medium | Historical only (UA shut down 2023) — SpyOnWeb, DNSlytics history | ✅ `trackers.google_analytics_ua` |
| **Yandex Metrika / Hotjar / Matomo / Mixpanel / Sentry DSN / Clarity / Intercom / Crisp / Segment** | vendor JS | Medium-High | PublicWWW / NerdyData source search; Sentry DSN reveals internal host | ✅ `trackers.*` |
| **Crypto wallet (BTC/ETH/XMR/TRON/LTC)** | body text, JS, `href` | Medium | blockchain explorers, Chainabuse, Arkham/Breadcrumbs clustering, PublicWWW | ✅ `crypto.*` |
| **Contact / registrant email** | mailto, body, JSON-LD | Medium | reverse-WHOIS (ViewDNS/WhoisXML), Epieos, hunter.io, urlscan | ✅ `emails` |
| **Contact phone** | `tel:` href, footer/body text | Medium | PublicWWW/urlscan source search, reverse-WHOIS (phone), WhatsApp/Telegram/Zalo | ✅ `phones` |
| **Telegram channel / group-invite** | `t.me/…`, `tg://` links | Medium-High | PublicWWW, urlscan, search; invite links (`t.me/+…`) are operator-run groups | ✅ `telegram[]` |
| **Google Doc / Sheet / Form / Drive / Slides ID** | `docs.google.com/…`, `forms.gle`, `drive.google.com/…` | **High** | PublicWWW, urlscan, NerdyData — operator-owned backend; often publicly readable | ✅ `saas_ids.google_*` |
| **Footer postal address** | `<footer>` text | Medium | PublicWWW/urlscan/Google verbatim source search — a distinctive registered address is copied across an operator's sites | ✅ `footer.addresses` |
| **Footer copyright / company** | `<footer>` text | Low-Medium | source search a distinctive company string | ✅ `footer.copyright` |
| **Page description** | `<meta description>` / `og:description` | Low | PublicWWW/NerdyData verbatim search → template/operator reuse | ✅ `description` |
| **ETag** | response header | Low | strong ETag on the same asset path elsewhere → shared origin/kit (corroborate) | ✅ `etag` / `server_headers.etag` |
| **Registrant phone / address** | WHOIS (current + history) | Medium | reverse-WHOIS by phone/address (WhoisXML/ViewDNS) — ties sites sharing no technical artifact | ✅ `whois.*` + `whois:registrant_phone/address` pivots |
| **Social handles** | outbound links | Medium | platform search, cross-account correlation | ✅ `socials.*` |
| **Third-party / non-CDN hosts** | script src, hrefs | Low-Medium | crt.sh, SecurityTrails, DNSlytics, Validin | ✅ `third_party_hosts` |
| **Inline-script SHA-256** | `<script>` bodies | Medium | match identical inline scripts across scans (kit code) | ✅ `inline_script_sha256` |
| **Form action + input names** | `<form>` | Medium | phishing-kit fingerprint; PublicWWW for reused field-name sets | ✅ `forms[].action / .inputs` |
| **HTML comments** | `<!-- -->` | Low-Medium | kit author strings, build tools, dev leaks, template IDs | ✅ `html_comments` |
| **DOM skeleton hash** | tag structure | Medium | template reuse — compare skeleton hashes across pages | ✅ `dom_skeleton_sha1` |
| **Tech fingerprint** | headers + markers | Low | CMS/framework/jQuery version → narrows the population | ✅ `tech_fingerprint` |
| **Cookie names** | `Set-Cookie`, JS | Low-Medium | session/tracking cookie name-sets can fingerprint a kit/platform | ✅ `cookie_names` |
| **Server / X-Powered-By / CSP** | response headers | Low | infra + CSP `report-uri` / allowed hosts leak related domains | ✅ `server_headers` |

## Pivot logic

1. **Rank by confidence.** Favicon hash and shared analytics/ad IDs are the strongest
   same-operator signals. Start there.
2. **A shared artifact is a lead, not proof.** Trackers can be copied, favicons reused
   by templates. Require **≥2 independent artifacts** overlapping before asserting a cluster.
3. **Compose queries.** Combine artifacts on one engine when possible
   (e.g. urlscan `page.url:* AND "G-XXXX"`; Shodan `http.favicon.hash:123 http.html:"pub-456"`).
4. **Passive before active.** Resolve via urlscan/Wayback/crt.sh before touching the live host,
   especially for adversarial infrastructure.
5. **Right hash per engine.** Shodan/FOFA/ZoomEye use **mmh3**, Censys uses **MD5**,
   Netlas uses **SHA-256** — the harness emits all three from one favicon.
