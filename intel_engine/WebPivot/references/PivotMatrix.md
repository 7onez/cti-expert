# Pivot Matrix — run *every* dimension on *every* seed

The failure mode this file prevents: **opportunistic pivoting** — noticing a GTM tag on one
site, a favicon on another, and missing the owner-verified token that was sitting in the same
DOM the whole time. Attribution is only as strong as your *strongest* shared artifact, so you
must harvest all of them, every time, and then rank.

One command produces the whole matrix for a host:

```bash
python3 WebPivot/tools/pivot_extract.py <domain> --render --leads -o "$CASE/raw/<host>.json"
python3 WebPivot/tools/wayback_ga.py <domain>          # historical tokens (scrubbed GA/GSC live in old snapshots)
```

`--render` matters: hosted-builder / SPA funnels inject tokens **client-side**, so a raw fetch
misses the GSC/GA/theme that only appear after JS runs.

---

## The strength hierarchy (rank attribution by this, NOT by WHOIS)

Lead every same-operator judgment with the **highest tier present**, and treat everything below
it as corroboration. The single most common report weakness is anchoring identity on Tier D
(WHOIS) when a Tier A artifact is already in hand.

| Tier | Meaning | Why it's that strong |
|---|---|---|
| **A — Dispositive** | owner **proved control** / account-level / cryptographic | can't be faked by copying a page |
| **B — Strong** | rarely coincidental, but copyable in principle | a clone can inherit it → wants a 2nd signal |
| **C — Corroborating** | meaningful only **time-bound** or with a 2nd signal | infra sharing ≠ ownership |
| **D — Falsifiable** | self-asserted | anchor of last resort |

---

## Tier A — Dispositive (start here)

| Pivot | WebPivot field | Search / verify on | Caveat |
|---|---|---|---|
| **Google site-verification token** (GSC) | `verifications.*` (🔑 node) | PublicWWW, urlscan, source search of the `<meta name="google-site-verification">` value | The owner proved DNS/HTML control to Google → **near-dispositive same-owner** across every domain carrying the token. This is the pivot most reports bury in a table. |
| **GA4 / GTM / AdSense — the operator's OWN container** | `trackers.google_analytics_ga4` · `google_tag_manager` · `google_adsense` | PublicWWW, urlscan, DNSlytics reverse-analytics, NerdyData | **Verify it isn't cloned** from the impersonated brand — a copied site copies the victim's snippet too. Confirm with a 2nd converging pivot (e.g. TLS) before treating the container as operator-owned. |
| **Google Doc / Sheet / Form / Drive ID** | `saas_ids.google_*` | PublicWWW, urlscan, NerdyData | Operator-owned backend, often publicly readable → can expose the operator directly. |
| **Identical TLS leaf-cert fingerprint** | `whois.tls` / `tls_cert:*` pivots | Censys `cert.fingerprint_sha256=` / Shodan by exact leaf SHA-256 (not just crt.sh name overlap); on a FREE Censys plan use the certificate LOOKUP (`wp_censys.py cert <sha256>`) — it returns the cert's own full `names` list with no search entitlement | crt.sh *overlap* is fuzzy; the exact fingerprint finds every host serving the **same** cert. Enumerate **every SAN** and pivot each — multi-brand SANs are cross-brand glue. |
| **APK signing-cert SHA-256** | *(BinaryPivot `analyze_artifact.py`)* | cluster app ↔ web infra in the same KB | Strongest same-operator pivot for the app half of the funnel — survives full re-skin. |

---

## Tier B — Strong (need a 2nd signal to call ownership)

| Pivot | WebPivot field | Search on | Caveat |
|---|---|---|---|
| **Favicon hash** (mmh3/md5/sha256) | `favicon.shodan_mmh3 / md5 / sha256` | Shodan `http.favicon.hash`, FOFA `icon_hash`, ZoomEye `iconhash`, Censys `web.endpoints.http.favicons.hash_md5` (md5), Netlas (sha256) | High-yield but **noisy**: templates/CDNs share icons across unrelated sites (a favicon-only cluster can be many operators). Disambiguate by **compositing** favicon **+** `dom_skeleton_sha1` **+** an inline-script hash. Suppress benign hashes via `tools/kb/reference.py`. |
| **Custom theme slug** | `wp_themes[]` (🎨 node) | PublicWWW `/wp-content/themes/<slug>`, urlscan | A bespoke theme name reused across domains is an operator build fingerprint. Generic themes (astra, hello-elementor) are noise. |
| **DOM skeleton hash** | `dom_skeleton_sha1` | compare across scans | Catches the "same login-panel template" you can *see* but couldn't prove — hash it and cluster. |
| **JARM TLS-stack fingerprint** | `jarm.jarm` | Shodan `ssl.jarm:`, Censys `host.services.jarm.fingerprint` (⚠️ Adversary Investigation module only), ZoomEye `jarm=` | Fingerprints the server's TLS stack+config → survives **domain rotation & re-branding** (ideal vs self-rotating scam-app infra). But stock stacks (nginx/CF defaults) share a JARM → **pair with a 2nd artifact**, never cluster on JARM alone. Active probe, suppressed under `--proxy`. |
| **Inline-script SHA-256** | `inline_script_sha256` | match identical inline scripts across scans | Kit code; distinctive custom JS is a strong same-kit signal. |
| **Form action + input-name set** | `forms[].action / .inputs` | PublicWWW for the reused field-name set | Phishing/brokerage-kit fingerprint. |
| **Distinctive footer address / company string** | `footer.addresses` · `footer.copyright` | PublicWWW / urlscan / Google verbatim | A registered virtual-office address copied across sites is a real link — but **shared virtual offices** are used by many unrelated firms; corroborate. |
| **Sentry DSN / CSP report-uri / other vendor DSNs** | `trackers.*` · `server_headers` (CSP) | inspect value — leaks an **internal/backend host** | The DSN host and CSP allow-list often name staging/API hosts absent from the page. |
| **Crypto wallet reuse** | `crypto.*` | explorers, Chainabuse, Arkham/Breadcrumbs | Reused receiving wallet ties campaigns; trace the **next hop** (off-ramp exchange) for the actionable lead. |

---

## Tier C — Corroborating (only meaningful time-bound)

| Pivot | WebPivot field | How to use it right | Caveat |
|---|---|---|---|
| **Shared origin IP** | `whois.ip` / IPPivot (`dig`, IPinfo, FOFA `ip=`, Shodan) | Claim shared-origin **only when passive-DNS first/last-seen windows overlap in time** | "Both on IP X" is worthless if they were there years apart, or if X is shared hosting. Recover the **origin behind Cloudflare/AWS** before trusting the edge IP. |
| **Cloudflare per-zone NS pair** | `whois.name_servers` | Identical CF pair (e.g. `finley`+`novalee`) = **same CF account** = real link | But generic *managed* DNS (`*.ns.cloudflare.com` broadly, dnsowl, etc.) is **noise** — see `tools/kb/noise_filters.py`. State which rule you applied. |
| **ETag / cookie name-set / tech fingerprint** | `etag` · `cookie_names` · `tech_fingerprint` | corroborate a cluster you already have | Never a primary link on its own. |
| **Third-party / non-CDN hosts** | `third_party_hosts` | crt.sh, SecurityTrails, DNSlytics, Validin | Backend/API hosts the page trusts; strong when non-generic. |

---

## Tier D — Falsifiable (anchor of last resort)

| Pivot | WebPivot field | Search on | Caveat |
|---|---|---|---|
| **WHOIS registrant name / email / phone / org** | `whois.*` + `whois:registrant_phone/address` pivots · `--reverse-email/-phone/-name` | reverse-WHOIS (WhoisXML/ViewDNS), Epieos, hunter.io | **Self-asserted → falsifiable.** Great for *expanding* a cluster (reverse-WHOIS off a phone/org finds siblings), weak as the *foundation* of an identity call. Always cross-check against WHOIS **history**. |

---

## The checklist — run this order on every seed

1. **Archive first.** Pull the Wayback CDX timeline on *every* target (even live ones) + `wayback_ga.py`. A parked page today may have been a live funnel last year; scrubbed tokens survive in old snapshots.
2. **Extract everything.** `pivot_extract.py --render --leads` → one `raw/<host>.json`. Don't cherry-pick dimensions.
3. **Rank by tier.** Read off the highest tier present. If a Tier A token exists, that anchors attribution — not the WHOIS.
4. **Run each pivot on ≥2 engines.** Code-string pivots especially: FOFA `body=` **and** PublicWWW **and** urlscan — each indexes a different slice.
5. **Corroborate before asserting a cluster.** Require **≥2 independent artifacts** overlapping (favicon **and** GSC token; not favicon alone). `evidence_report.py` enforces this; so should your prose.
6. **Time-bound every infra claim.** Co-hosting / co-cert must overlap in time to mean shared origin.
7. **Strip platform noise.** Managed NS, parking favicons, registrar/privacy emails, malformed GA4 → `tools/kb/noise_filters.py` + `reference.py`. Don't let a Wix/Gname/CF commonality masquerade as an operator link.
8. **Persist + ingest + report.** `-o raw/<host>.json` → `ingest_webpivot.py` → `--misp` for the IOC bundle. A pivot found but not ingested is invisible to correlation.

---

## Gaps — do these manually for now (proposed skill enhancements)

Honest roadmap: these strengthen domain/IP hunting but WebPivot does **not** yet emit them. Run
them by hand; they're candidates for a new `@tool`.

- **JA3S** TLS-stack fingerprint — a companion to JARM on the backend/C2 hosts. *(JARM itself is now emitted — see Tier B `jarm.jarm`.)*
- **TLS leaf-cert fingerprint search** — pivot the exact cert SHA-256 on Censys/Shodan, beyond crt.sh name overlap. The Censys certificate LOOKUP is free-plan reachable and returns the cert's own hostname list.
- **Time-bound passive-DNS overlap** — programmatic first/last-seen intersection to separate *shared origin* from *shared hosting*.
- **Origin-behind-CDN recovery** — historical A-record before CF was added, origin's own TLS cert, favicon-on-Shodan, direct-IP `Host:` probing.
- **On-chain next-hop** — trace swept funds to the off-ramp exchange deposit address (the subpoena-able lead), and flag freezable USDT (TRC-20) to Tether. *(Analysis-side, cross-skill.)*

> Placeholders only in this file (`G-XXXXXXXXXX`, `example.com`, `CASE-0001`) — never a value
> from a live case. See the repo `CLAUDE.md`.
