# fx-dns-cert-history

> **Module ID:** DNS-CERT-HIST-001
> **Version:** 1.2.0
> **Classification:** Historical DNS Records & Certificate Timeline Intelligence

---

## 1. Overview

Retrieves historical DNS records and certificate-transparency timelines for a domain. Reveals infrastructure changes, hosting migrations, nameserver swaps, and certificate issuer patterns over time. The baseline is keyless (crt.sh + its PostgreSQL mirror, Shodan CTL, CertSpotter); CertKit, CertIndex, Netlas and Censys are optional backups that only run when crt.sh has nothing.

**Key use cases:** Infrastructure timeline reconstruction, hosting migration detection, domain ownership change indicators, expired certificate tracking, nameserver change correlation.

**Cross-references:** `domain-advanced.md` (current DNS/subdomain enum), `web-dns-forensics.md` (WHOIS/zone analysis), `scam-check.md` (current SSL check).

---

## 2. DNS History

### 2.1 Methods (all free, no API keys)

**Primary — SecurityTrails (web search, no auth for cached results):**
```bash
# Google dork to find cached SecurityTrails DNS history
# WebSearch: site:securitytrails.com/domain/<domain>/history/a
# WebSearch: site:securitytrails.com/domain/<domain>/dns

# Returns: historical A, AAAA, MX, NS, TXT record changes with dates
```

**Secondary — ViewDNS.info (free web lookup):**
```bash
# IP History — shows historical A record → IP mappings with dates
curl -s "https://viewdns.info/iphistory/?domain=<domain>"
# Parse HTML response for IP history table

# Reverse IP — find other domains on same historical IP
# WebSearch: site:viewdns.info/reverseip/?host=<IP>
```

**Tertiary — Mnemonic PassiveDNS (free API, no key):**
```bash
# Free passive DNS lookup — returns historical resolutions
curl -s "https://api.mnemonic.no/pdns/v3/<domain>" | python3 -m json.tool

# Response includes: rrtype, rrname, rdata, first_seen, last_seen, count
```

**Quaternary — Wayback CDX API (free, no auth):**
```bash
# Find archived DNS-related pages
curl -s "https://web.archive.org/cdx/search/cdx?url=<domain>&output=json&fl=timestamp,original&limit=50"
```

### 2.2 Investigation Workflow

```
Step 1: Query Mnemonic PassiveDNS API for historical A/AAAA/MX/NS records
  └─ curl -s "https://api.mnemonic.no/pdns/v3/<domain>" → parse JSON

Step 2: WebSearch for SecurityTrails cached history
  └─ site:securitytrails.com/domain/<domain>/history/a

Step 3: Check ViewDNS IP history
  └─ WebSearch: site:viewdns.info/iphistory/?domain=<domain>

Step 4: Cross-reference IP changes with WHOIS history
  └─ WebSearch: site:web.archive.org <domain> whois

Step 5: Build DNS timeline with dated record changes
  └─ Correlate across sources for HIGH confidence transitions
```

### 2.3 Expected Output

```
═══ DNS HISTORY: example.com ═══════════════════════

A Record Changes (synthetic):
  2024-03-15 → 198.51.100.21  (CDN edge)
  2023-01-08 → 203.0.113.40   (VPS provider)
  2021-06-22 → 192.0.2.77     (shared hosting)

NS Changes:
  2024-03-15 → ns1.cloudflare.com (migration to Cloudflare)
  2021-01-01 → ns1.digitalocean.com

MX Changes:
  2023-05-10 → aspmx.l.google.com (Google Workspace)
  2021-01-01 → mail.example.com (self-hosted)

Sources: Mnemonic PassiveDNS, SecurityTrails (cached), ViewDNS
```

### 2.4 Forensic Value

| Change Type | What It Reveals | Confidence |
|---|---|---|
| A record IP change | Hosting migration, infrastructure shift | HIGH |
| NS record change | DNS provider swap, possible ownership change | HIGH |
| MX record change | Email provider migration | HIGH |
| Multiple domains → same IP | Same infrastructure only. Dedicated host (few tenants, overlapping windows) = moderate lead; shared hosting / parking / CDN = information, not a link (§2.7) | LOW–MEDIUM |
| Sudden Cloudflare migration | May indicate DDoS attack or security incident | MEDIUM |

### 2.5 Fallback Cascade

```
Mnemonic API down?
  └─> SecurityTrails cached results via Google dork
  └─> ViewDNS.info IP history
  └─> Wayback CDX for archived DNS pages
  └─> WebSearch: "<domain>" "DNS history" OR "IP history"
```

### 2.6 Reading passive DNS for maliciousness (analyst checks)

**What this is.** A manual checklist over history the skill already collects (`/dns-history`,
`/origin-history <case>`, reverse-IP counts, `ip_info` ASN/country, WHOIS creation date). It is
built from the feature families of two trained classifiers: EXPOSURE's 15 features in four sets —
time-based, DNS answer-based, TTL value-based, domain name-based [P04 Bilge et al., NDSS 2011] — and
Notos's network-based, zone-based and evidence-based features over a domain's "Related Historic
IPs" (RHIPs) and "Related Historic Domains" (RHDNs) [P05 Antonakakis et al., USENIX Sec 2010].
**We do not implement either classifier**, compute no score, and inherit none of their accuracy:
both were trained on ISP-scale recursive DNS with labelled lists, and their reported rates (P04
~98% detection on its 2.5-month SIE trace; P05 0.38% FP / 96.8% TP on its two-ISP deployment)
describe those populations only. Each check returns `agile-consistent`, `benign-consistent` or
`insufficient`; none is a maliciousness verdict. Maliciousness comes from content, victim reports,
or detonation; these checks only rank what to look at next.

**Coverage gate (run first).** P04 dropped every domain with fewer than 20 queries in its window
because its time series were unreliable below that [P04]. Our analogue (adaptation): if the domain
has one pDNS source, a handful of rows, or a `capped`/`degraded` source, mark the time and change
checks `insufficient` before reading them. pDNS sees only what its sensors' users resolved, so an
obscure benign domain looks sparse and short-lived for the same reason a burner does.

| # | Check (source feature) | Analyst reading — adaptation unless marked | Benign confounders | Abstain when |
|---|---|---|---|---|
| 1 | **Lifetime / short life** [P04 F1 "Short life"; P05: agile malicious names are short-lived with high churn] | P04 measured a sudden rise then fall in query volume. We read the `first_seen → last_seen` span per name and per answer, against WHOIS creation: created days before first resolution, active days–weeks, then NXDOMAIN / hold / sinkhole. | New legitimate launch; event or campaign microsite; low-popularity site outside sensor coverage; a takedown or sinkhole (the end is the defender's act, not the operator's design) | Span still open (`last_seen` ≈ query date); one source only; sparse history |
| 2 | **Change pattern** [P04 F2 daily similarity, F3 repeating patterns, F4 access ratio — all on hourly query counts] | We have no hourly volume, so daily similarity and access ratio are **not measurable**; say so. What transfers: count change points in A/NS history — rapid rdata swaps, a fixed pool cycled repeatedly, NS hopping, return to an earlier IP. If the source gives per-row `count`, note volume concentrated in a short window vs. a long idle tail. | Hosting migration; CDN / DDoS-protection onboarding; load-balancer or autoscaling pools; cloud elastic IPs; failover | No dated rows; no counts (then never claim F2–F4) |
| 3 | **TTL behaviour** [P04 F9–F13: mean, std, distinct values, number of changes, share in ranges [0,1) [1,10) [10,100) [100,300) [300,900) [900,∞)] | In P04's data malicious domains had more TTL changes, more distinct values and a peak in [0,100); P04 itself notes CDNs and high-availability services also use low TTL + round robin, and that fast-flux detectors key on low TTL plus a growing answer list. Read: low TTL **and** many distinct values **and** a growing answer set together = fast-flux-like; low TTL alone = nothing. Confirm the authoritative TTL with `dig +norecurse @<ns>` — sensor TTLs can be resolver-decremented cache values (adaptation). | CDN / GSLB; dynamic DNS (low TTL by design); provider defaults (proxied records); failover setups | No TTL field in the source; TTL seen in one observation |
| 4 | **Answer-set diversity** [P04 F5 distinct IPs, F6 distinct countries, F8 reverse-DNS of the IPs; P05 BGP/AS/registration features over RHIPs = A(d) ∪ A(zone of 3LD) ∪ A(zone of 2LD)] | P04: malicious names resolve to opportunistically compromised hosts spread over ASNs and countries; P05: professionally run services have a stable profile owned by few organisations. Collapse IPs to provider org first (the skill's CDN / WAF / parking / cloud classifier), then tally distinct non-CDN orgs, BGP prefixes, ASNs, countries across the domain **and** its enumerated subdomains (an RHIP-lite). Residential / dynamic PTRs (`dyn`, `pool`, `adsl`, `cust`) behind a web A record are the proxy-bot shape P04 describes. | Multi-CDN and anycast (many ASNs, one provider class); GeoDNS; multi-region cloud; dynamic DNS — P05 modelled Akamai, other CDNs and dynamic DNS as separate benign profiles because they look agile, and still saw dynamic DNS confused with ordinary domains | After CDN/cloud collapse fewer than two independent non-CDN orgs remain; ASN/geo lookups dated to today for a historical IP |
| 5 | **Shared-IP tenancy size** [P04 F7 number of domains sharing the IP] | P04 saw one hosting-provider IP shared by 10,837 domains in its trace and screened shared hosting by web-searching the IP's reverse-DNS name; P05 found legitimate sites penalised for living in "bad neighbourhoods". Tenancy is informative only when **small and dated**. Above the engine's `MAX_IP_COHOSTS` apexes, or truncated past `BULK_IP_RESULTS` (`intel_engine/tools/case_state.py`, threshold from the noise-filter reference), it is a co-tenancy lead — `add_fact`, never an edge (SKILL.md rungs 8 vs 10). | Shared hosting; parking; registrar forwarding IPs; CDN edges; **sinkholes** (a sinkhole IP hosts many seized bad domains — the common party is the sinkhole operator) | Reverse-IP is undated (current tenants of a historical IP say nothing about then); tenancy above the guard |
| 6 | **Domain lexical** [P04 F14 % numeric chars, F15 longest-meaningful-substring ratio, on the SLD; P05 zone-based string + TLD features over RHDNs] | P04 reports benign Chinese/Russian alphanumeric names raised F15 false positives, reduced by combining F14 with F15, and checked search hit counts for popular non-word brands. P05: legitimate related names share a stem, campaign names look random and share little. Read the SLD and the set of names co-resolving with it; for NXDOMAIN-heavy or DGA-shaped sets use `domain-advanced.md` §7. | Pinyin / transliteration; numeric brands; acronyms; short brands with no dictionary word; CDN/hash hostnames | Label too short to judge; IDN / non-English; single name with no siblings |
| 7 | **Evidence association** [P05 evidence-based: malware samples contacting d, its BGP prefix or AS; blacklist hits for A(d), prefix, AS] | P05 states that being queried by malware does not by itself mean a low reputation. Use `/threat-check` and sandbox lookups on the domain and its **dated** IPs; prefix/AS-level hits describe the neighbourhood, never d. | Connectivity checks contacted by malware; previous tenant's listing; sinkhole listings | Hit only at prefix/AS level; listing predates the current registration |

**Combining (adaptation).** Report each check's outcome with the rows it rests on. Call a domain's
history "agile-DNS profile" only when at least two **different** families (time/change, network
diversity, TTL) read `agile-consistent` after confounders are removed; lexical and evidence checks
raise priority but never complete the profile alone. The profile is a collection lead for the
domain itself; it links the domain to nothing.

```
pDNS read — pay-portal.example (CASE-0001, synthetic)
  Coverage   2 sources (Mnemonic, CIRCL), 14 rows                          → checks runnable
  1 Lifetime created 2026-05-02, first_seen 2026-05-04, last_seen 2026-05-27, then NXDOMAIN → agile-consistent
  2 Change   9 A swaps in 23 days over a pool of 6 IPs; no counts          → agile-consistent (F2–F4 not measurable)
  3 TTL      not in source rows; live authoritative TTL 60                  → insufficient
  4 Diversity 6 IPs, 5 ASNs, 4 countries, 0 CDN; PTRs dyn-*/pool-*         → agile-consistent
  5 Tenancy  203.0.113.9: 3 apexes, dated 2026-05; 198.51.100.4: 250+      → small one = moderate lead; big one = co-tenancy fact
  6 Lexical  "pay-portal": dictionary words                                 → benign-consistent
  Verdict:   agile-DNS profile (families: time + diversity). Next: content capture, takedown status.
```

### 2.7 Temporal pivot rule — co-resolution and co-tenancy

1. **Two domains co-resolving link only when their windows overlap on that IP.** Take each
   domain's `[first_seen, last_seen]` for the shared answer; no overlap = **sequential tenancy**
   (IP reassigned, or the same tenant later — undecidable from DNS alone), a lead at most. Mirai's
   DNS expansion added a name only when it "concurrently resolved" the IP
   [P07 Antonakakis et al., USENIX Sec 2017]. Notos's RHDNs are deliberately broader ("ever
   resolved" within the AS) because they feed statistics, not links [P05] — do not reuse that set as
   a link set.
2. **Overlap gives same infrastructure, not same operator.** The rung is set by tenancy size
   (check 5): dedicated and small = moderate (SKILL.md rung 8); shared/reseller, CDN, parking,
   sinkhole = information (rung 10). Same operator needs an independent owner-side link (registrant
   join key, shared certificate, verification token); a named person needs more again.
3. **Rows before the current registration belong to the previous owner.** In P07's data at least
   17% of Mirai C2 domains were expired names re-registered to "abuse residual trust" [P07]; their
   older history and older co-tenants are someone else's.
4. **Write the windows into the finding**: shared IP, both windows, overlap days, tenancy count and
   its date, source. A co-resolution with no dates is not reported as a link at all.

```
Co-resolution on 192.0.2.50 (synthetic)
  alpha.example  2026-02-01 → 2026-03-10
  beta.example   2026-03-02 → 2026-04-15   overlap 9 days, 4 apexes on the IP (dated 2026-03) → moderate lead, same infrastructure
  gamma.example  2026-06-20 → 2026-07-01   no overlap with either                          → sequential tenancy, lead only
```

---

## 3. Certificate History (CT timeline)

`/cert-history <domain>` → `intel.py cert-history <domain>` → `WebPivot/tools/wp_ct.py`, the ONE CT
client every CT lookup in the skill uses (enrich_live, `/cert-pivot`, `/subdomain`, `ct_monitor`,
`/cert-overlap`, `/fallback`, the impersonation hunt). Historic **cert → IP** (which addresses served a
certificate) is a different question: `/pssl` (CIRCL passive SSL).

### 3.1 Sources and the fallback chain

crt.sh is the only full public CT history. Every backup is a partial mirror, so they run **only when
crt.sh is `degraded` or `empty`**, keyless first:

| Order | Source | Access | Window | Identity key |
|---|---|---|---|---|
| 1 | crt.sh web (`q=` → `identity=`, retry + backoff inside a wall-clock budget) | keyless | full CT history | crt.sh id, x509 serial |
| 1b | crt.sh public PostgreSQL (`guest@crt.sh/certwatch`) | keyless, needs optional `psycopg` | full CT history | crt.sh id, x509 serial |
| 2 | Shodan CTL + CertSpotter (merged) | keyless | ~1 year | sha256 |
| 3 | CertKit Discovery export | `CERTKIT_EMAIL` / `CERTKIT_PASSWORD` (web login) | ~1 year, expired included, day-only dates | x509 serial |
| 3 | CertIndex | `CERTINDEX_API_KEY` | ~1 year, currently valid only | sha256 |
| 4 | Netlas certificates | `NETLAS_API_KEY`, metered — **only when crt.sh failed**, never on an authoritative empty | multi-year, sparse | sha256 + serial |
| 5 | Censys certificate search | Censys PAT, metered — **only when everything above returned nothing** | capped sample of a global index (can hold non-CT certs) | sha256 |
| 6 | crt.name + agniops | keyless | names only, NOT CT evidence | — |

`--free-only` (or scope `no_spend`) skips Netlas and Censys (`skipped-free-only`); CertKit and
CertIndex spend no credits and still run. A missing key is `skipped-no-key`. CertIndex reads its free
`/v1/usage` first and is `skipped-quota` — never waited on — when the hour's 10 lookups are spent.

**Shodan host search is NOT a CT source.** `ssl.cert.subject.cn:<domain>` indexes certificates
*presented by scanned hosts*, dated by when seen, and token-matches: it measured 0 hits on small
domains and, on a large one, ~100 hosts of an unrelated company presenting a private-CA cert. Use
Shodan host search only for fingerprint / favicon / body pivots (`ssl.cert.fingerprint:`,
`http.favicon.hash:`, `http.html:`); for CT use crt.sh or the Shodan CTL mirror
(`https://ctl.shodan.io/api/v1/domain/<d>`).

### 3.2 Status contract — never conflated

| Source | Status | Meaning |
|---|---|---|
| crt.sh | `ok` | rows came back (web or PostgreSQL) |
| crt.sh | `empty` | HTTP 200 with `[]` — authoritative "none on record"; never retried away |
| crt.sh | `degraded` | web retries AND PostgreSQL failed, or one sub-query failed — history INCOMPLETE |
| others | `complete` / `capped` / `partial` | answered fully / hit its page or row cap / short or interrupted (asked again later) |
| others | `failed` / `skipped-quota` / `skipped-no-key` / `skipped-free-only` | not answered — the evidence class went unqueried |

One completeness line per lookup:

- `Full CT history (crt.sh)` — only when crt.sh is `ok` (or `empty` with nothing elsewhere).
- `crt.sh has no record yet (possible ingestion lag); backups cover ~1 year` — crt.sh `empty` but a backup has rows (fresh domains: crt.sh can lag issuance).
- `Incomplete: crt.sh unreachable; backups cover ~1 year` — crt.sh `degraded`, a backup answered.
- `Incomplete: crt.sh unreachable and no backup answered — CT history was not collected (this is not 'no certificates')`.

A degraded crt.sh with no backup rows is **never** reported as "no certificates", and turns
`/cert-overlap`'s negative into `INCONCLUSIVE-CT-DEGRADED` and `/fallback`'s cold verdict likewise.

**Dedup.** Same certificate when the crt.sh id, sha256 or x509 serial (hex, lowercased, leading zeros
stripped; under 16 hex chars only together with the issuer) matches, or — for rows with full
timestamps — the precert/final twin key (issuer CN, not_before and not_after to the second, SAN set).
Day-only rows (CertKit) never merge on dates with each other (same-day ECC + RSA twins); one attaches to
a sha256-only row only when the (issuer CN, day, SAN set) match is unique both ways. The richer row
wins. Confidence: **HIGH** for crt.sh rows and matches across 2+ sources, **MEDIUM** for a single
backup; Netlas/Censys rows are kept only after the name filter (look-alikes dropped).

**No silent truncation.** Listings are capped (`ct_sources.json → listing`) but always carry
`cert_total` / `subdomain_total` and a `truncated` flag; the frontier defers names it could not examine.

### 3.3 Worked example — degraded run (synthetic)

```
$ intel.py cert-history site-a.example
CT (certificate transparency) — site-a.example
  Completeness: Incomplete: crt.sh unreachable; backups cover ~1 year
  crt.sh                 degraded             0 certs  window: full CT history  (via=web, attempts=12)
                         [web %.site-a.example: HTTP 502; web site-a.example: HTTP 503;
                          PostgreSQL fallback: timed out after 180s]
  shodan-ctl             complete             4 certs  window: ~1 year
  certspotter            complete             2 certs  window: ~1 year (thin free tier)
  certkit                skipped-no-key       0 certs  window: ~1 year, expired included
  certindex              skipped-quota        0 certs  window: ~1 year, currently valid certificates only
  netlas                 skipped-free-only    0 certs  window: multi-year, sparse
  Merged: 5 certificate(s), 3 name(s)
    2026-08-02T04:11:09  HIGH   shodan-ctl+certspotter   example issuing ca 1   site-a.example, www.site-a.example
    2026-06-03T04:10:51  MEDIUM shodan-ctl               example issuing ca 1   site-a.example, www.site-a.example
    2026-05-30T12:00:00  MEDIUM shodan-ctl               example issuing ca 1   pay.site-a.example
    …
```

Report it as: "CT history **incomplete** — crt.sh was unreachable; Shodan CTL and CertSpotter (each
~1 year) returned 5 certificates; CertIndex quota spent, CertKit not configured, Netlas suppressed by
--free-only. Certificates older than ~1 year are not visible." Never "the domain has 5 certificates".

### 3.4 Pivot hits — "Related hosts (unverified)"

A host that shares a value with the target (leaf-cert fingerprint, favicon hash, tracking ID) is a
**related host**, never by itself the target's server or its origin behind a CDN:

- **Origin checks.** (1) the IP serves the target's content with `Host: <target>` (best: same body
  hash) — an active request, run only by `/cert-pivot`: one `audit.gate` decision before the first
  byte (a hostile case or `HARNESS_HOSTILE` without a proxy is DENIED and ledgered), every socket
  through the proxy layer (never a direct fallback when it is missing), `--passive` / `--no-live` =
  "not run", an unreachable IP = "not run", never "fail"; `--proxy <url>` routes it;
  (2) it presents a non-CDN certificate whose SANs include the target; (3) passive DNS
  or passive SSL shows the target on that IP before it moved behind the CDN (pDNS + pSSL agreeing is
  the strong case); (4) the IP/ASN is outside CDN ranges — an address that fails (4) is an edge and
  is never promoted, however many other checks pass. One check = **LOW** lead, two agreeing =
  **MEDIUM probable origin**, three or more = **HIGH**.
- **Never** derive hosting or abuse/takedown contacts from a pivot-only IP — only from the target's
  own current resolution or an IP found another way.
- A hit's IP/ASN is not the target's fingerprint in the KB; the shared value is.
- Favicons count only when custom or brand-impersonating (default nginx/cPanel/Laravel/WordPress/panel
  icons are noise — `/reference check`). One shared tracking ID is a lead; attribution needs a second,
  independent link. Co-listed apexes on one certificate are a lead (multi-tenant guard), not proof.
- Date every scanner hit: IPs get reassigned.

Worked example (synthetic) — `/cert-pivot site-a.example`, target behind a CDN:

```
Related hosts (unverified)
| Host         | Shared value            | Engine | Scan date  | Origin checks passed                         | Rung                     |
|--------------|-------------------------|--------|------------|----------------------------------------------|--------------------------|
| 192.0.2.10   | cert sha256 1a2b…9f     | Censys | 2026-10-12 | (2) non-CDN cert, SANs include target;       | probable origin (MEDIUM) |
|              |                         |        |            | (3) pDNS 2026-03 + pSSL agree before the CDN |                          |
| 198.51.100.7 | cert sha256 1a2b…9f     | Shodan | 2026-09-30 | (4) non-CDN ASN only                         | lead (LOW)               |
| 203.0.113.5  | favicon mmh3 123456789  | FOFA   | 2026-09-28 | none                                         | lead (LOW)               |
```

Only 192.0.2.10 is promoted, and only to "probable origin", because two independent checks agree. The
hosting/abuse section still lists only what `site-a.example` itself resolves to today; none of these
IPs becomes a takedown recipient.

### 3.5 Forensic value

| Pattern | What It Reveals | Confidence |
|---|---|---|
| Issuer change (EV → DV/LE) | Budget reduction, ownership change, or automation | MEDIUM |
| New SANs appearing | New services/subdomains launched | HIGH |
| SANs disappearing | Services discontinued or moved | MEDIUM |
| Validity gap (no cert for period) | Site downtime, abandonment, or migration — only when crt.sh answered | MEDIUM |
| Certs predating current registration | Previous owner's era — not this operator's | HIGH |
| Wildcard cert introduced | Infrastructure scaling or simplification | LOW |

---

## 4. Combined DNS + Cert Timeline

When running both `/dns-history` and `/cert-history` on the same domain, correlate findings:

```
Cross-Reference Analysis:
  • DNS A record changed on 2024-03-15 (Cloudflare migration)
    → New cert issued 2024-03-15 (Let's Encrypt via Cloudflare)
    → Confirms hosting migration date

  • SAN "shop.example.com" appeared in 2023 cert
    → Subdomain A record for shop.example.com first seen 2023-01-10
    → Confirms new service launch timeline

  • MX changed to Google Workspace on 2023-05-10
    → No cert change (email doesn't require web cert)
    → Independent infrastructure decision
```

---

## 5. Limitations

1. **Mnemonic PassiveDNS** — Coverage varies by domain popularity; obscure domains may have sparse history
2. **SecurityTrails** — **API now wired** (`wp_securitytrails.py`, freemium ~50/mo key: subdomains + DNS history, auto-run in enrich_live). The cached-Google-dork path below is the KEYLESS fallback for when no key is set or the monthly quota is spent.
3. **ViewDNS** — HTML parsing required; no structured API for free tier
4. **crt.sh** — the only full public CT history, but its web front end returns 502/503/504/timeouts for minutes or hours; the PostgreSQL fallback needs `psycopg`. Only public CT logs: private/internal CAs are absent (Censys can hold some)
5. **Backups are partial mirrors** — Shodan CTL, CertSpotter, CertIndex and CertKit hold ~1 year; Netlas is multi-year but sparse; Censys is a capped sample. A degraded crt.sh stays degraded whatever they return
6. **CertIndex** — free tier is **personal / non-commercial only**, 10 full-domain lookups per hour account-wide (each page counts); a domain's historical backfill can fail and stay a lower bound
7. **CertKit** — no API: depends on a web session, so it breaks if the site changes its login form or MFA is enabled on the account
8. **Historical gaps** — Passive DNS collection started ~2010; older records may not exist
9. **Rate limiting** — crt.sh and Mnemonic may throttle high-volume queries
10. **§2.6 checks are not classifiers** — EXPOSURE and Notos ran on labelled ISP-scale query streams; our sources carry no hourly volume and often no TTL, so several of their features are unmeasurable here, and no threshold from either paper is a rule for this skill

---

## 6. Command Reference

| Command | Purpose | Input |
|---|---|---|
| `/dns-history [domain]` | Historical DNS record changes (A, NS, MX) | Domain name |
| `/cert-history [domain]` | CT certificate timeline with per-source status + completeness line | Domain name |
| `/pssl [domain\|cert]` | Historic cert → IP (passive SSL; origin behind a CDN) | Domain or cert fingerprint |

---

*DNS & Certificate History Module v1.1.0*
*Part of CTI Expert Skill*
*For authorized investigation and educational purposes only*
