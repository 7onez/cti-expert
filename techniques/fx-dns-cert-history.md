# fx-dns-cert-history

> **Module ID:** DNS-CERT-HIST-001
> **Version:** 1.1.0
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

A Record Changes:
  2024-03-15 → 104.21.67.89  (Cloudflare)
  2023-01-08 → 192.168.1.100 (DigitalOcean)
  2021-06-22 → 45.33.32.156  (Linode)

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
| Multiple domains → same IP | Shared hosting, co-owned properties | MEDIUM |
| Sudden Cloudflare migration | May indicate DDoS attack or security incident | MEDIUM |

### 2.5 Fallback Cascade

```
Mnemonic API down?
  └─> SecurityTrails cached results via Google dork
  └─> ViewDNS.info IP history
  └─> Wayback CDX for archived DNS pages
  └─> WebSearch: "<domain>" "DNS history" OR "IP history"
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
