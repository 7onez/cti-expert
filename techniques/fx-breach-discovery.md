# fx-breach-discovery

## Purpose
Locate compromised credential sets and exposed PII tied to a subject across known breach databases, paste aggregators, and indexed dumps. Produces a severity-ranked finding set for the case record.

## Quick Reference
| Item | Detail |
|------|--------|
| Command | /breach-check |
| Input | Email address, username, or domain |
| Output | Breach finding report with severity tiers |
| Confidence | HIGH for indexed breaches; LOW for unverified pastes |

## Exposure Severity Table
| Data Class | Severity | Priority Action |
|------------|----------|-----------------|
| Email only | LOW | Monitor for phishing |
| Email + hashed password | MEDIUM | Assess hash strength |
| Email + plaintext password | HIGH | Check reuse across services |
| Full PII (name, DOB, address) | HIGH | Cross-reference with active accounts |
| Financial or government ID | CRITICAL | Incident response protocol |

## Methodology
1. Query HIBP (`haveibeenpwned.com`) with subject email — note breach names and data classes
2. Query HudsonRock Cavalier API with subject email — check infostealer exposure
3. If org case: run BOTH HudsonRock domain endpoints (`search-by-domain` impact + `urls-by-domain` attack surface) for compromised employee/client URLs, and run Lunar domain-exposure (see below) for org-level exposure trend + malware-family/service breakdown
4. Sweep domain variant (`@domain.com`) via HIBP domain search if org case
5. Run operator queries against paste aggregators: `site:pastebin.com "subject@domain.com"`
6. Check secondary paste indexes (psbdmp.ws, pastebinsearch.com) for dump fragments
7. Cross-reference breach dates + HudsonRock `date_compromised` to build exposure timeline
8. For each finding, assess hash type if passwords present (MD5/SHA1 = high crack risk)
9. Score cumulative severity using table above; flag credential reuse patterns
10. If HudsonRock returns a hit: auto-escalate to CRITICAL (active infostealer = live credential theft)

## Tools & Fallbacks
| Priority | Tool | Install | Notes |
|----------|------|---------|-------|
| 1 | HaveIBeenPwned | haveibeenpwned.com | Free tier; API key for bulk |
| 2 | **HudsonRock Cavalier** | cavalier.hudsonrock.com (free API) | **Infostealer data — no API key** (50 req/10s; premium key optional) |
| 3 | DeHashed | dehashed.com | Paid; broader breach coverage |
| 4 | **LeakCheck Public API** | https://leakcheck.io | Free public API — email/username/domain breach lookup |
| 5 | Pastebin operator query | Browser | Free; cover pastebin.com, gist.github.com |
| 6 | psbdmp.ws | Browser | Indexes deleted Pastebin content |
| 7 | IntelligenceX | intelx.io | Paid; dark web paste index |
| 8 | **Lunar Domain Exposure** | api.lunarcyber.com (free API) | **Domain-only** org-level infostealer + breach exposure, 12-mo trend, malware-family & VPN/SSO breakdown — no API key |

### HudsonRock Cavalier Community API (Free, No Key Required)

Checks if an email, username, IP, or domain appears in **infostealer** malware logs. Free,
open, unrestricted — no key, no approval. **Rate limit: 50 requests / 10 seconds.** A
premium/commercial key exists for higher tiers (see `handbook/api-keys.md`), but every
endpoint below is fully usable keyless.

**Canonical base:** `https://cavalier.hudsonrock.com/api/json/v2/osint-tools/`
Use the **osint-tools** base above for `search-by-email` / `search-by-username` / `search-by-ip` / `search-by-domain` / `urls-by-domain`. One deliberate exception: the **full, uncapped** domain login-URL list lives on the older `stats` host (row below) — it is a richer superset of `urls-by-domain`, not drift, so keep it.

**Endpoints:**

| Query Type | URL | Use Case |
|-----------|-----|----------|
| Email | `.../search-by-email?email={EMAIL}` | Is this email on an infected machine? |
| Username | `.../search-by-username?username={USER}` | Is this username on an infected machine? |
| IP | `.../search-by-ip?ip={IP}` | Is this IP tied to an infostealer infection? |
| Domain — impact | `.../search-by-domain?domain={DOMAIN}` | Infostealer impact stats for a domain |
| Domain — attack surface | `.../urls-by-domain?domain={DOMAIN}` | Employee/client login URLs from stealer logs |
| Domain — full URL list | `https://www.hudsonrock.com/api/json/v2/stats/website-results/urls/{DOMAIN}` | **Uncapped** superset of `urls-by-domain` — full long-tail incl. `occurrence:1` login/reset URLs (best for attack-surface enumeration) |

**Email lookup — example:**
```bash
curl -s "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email=target@example.com"
```
Top-level fields: `message`, `stealers[]`, `total_corporate_services`, `total_user_services`.
Each `stealers[]` entry carries `computer_name`, `date_compromised`, and the stolen
corporate/user service lists.

**Domain lookup — examples:**
```bash
# Impact stats (richest): totals, passwords, stealerFamilies, antiviruses, applications
curl -s "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=example.com"
# External attack surface: employee/client login URLs seen in stealer logs
curl -s "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/urls-by-domain?domain=example.com"
# Full/uncapped URL list (superset — richer for attack-surface/admin-endpoint pivots):
curl -s "https://www.hudsonrock.com/api/json/v2/stats/website-results/urls/example.com"
```
`search-by-domain` fields include `total`, `totalStealers`, `employees`, `users`,
`third_parties`, `totalUrls`, `stealerFamilies`, `employeePasswords`, `userPasswords`,
`last_employee_compromised`, `last_user_compromised`, and
`data.{employees_urls,clients_urls,all_urls}`. Both URL forms return
`data.{employees_urls,clients_urls}` (each entry: `url`, `occurrence`, `type`), but they
differ: `urls-by-domain` is **top-20 capped per list** with `type` **lowercase**
(`"employee"`); the `stats/website-results/urls/` form is the **full** list (plus `stats`
and `totalUrls`) with `type` **capitalized** (`"Employee"`). **Normalize `type`
case-insensitively**, and prefer the full list when enumerating attack surface.

**Integration into methodology:**
- Run the email check as step 1b (after HIBP, before paste sweeps).
- On org cases run the domain endpoints: `search-by-domain` for impact stats, and for the login-URL attack surface prefer the **uncapped** `stats/website-results/urls/` list (use `urls-by-domain` for a quick top-20).
- If HudsonRock returns data → mark finding CRITICAL (infostealer = active credential theft).
- Record `date_compromised` / `last_*_compromised` in the exposure timeline.

### LeakCheck Public API (Free, No Key Required for Public Endpoint)

Checks if an email, username, or domain appears in known data breaches. Returns breach source names and exposure metadata. More detailed than HIBP for some breaches; covers different breach sets.

**Public API Endpoint:**

| Query Type | URL | Use Case |
|-----------|-----|----------|
| Email lookup | `https://leakcheck.io/api/public?check={EMAIL}` | Check if email found in breaches |
| Username lookup | `https://leakcheck.io/api/public?check={USERNAME}` | Check if username found in breaches |
| Domain lookup | `https://leakcheck.io/api/public?check={DOMAIN}` | Check if domain has breach exposure |

**Email lookup — example:**
```bash
curl -s "https://leakcheck.io/api/public?check=target@example.com"
```

**Response fields:**
- `success` — boolean, whether the lookup succeeded
- `found` — number of breach entries found
- `fields` — data fields exposed (email, password, username, etc.)
- `sources` — list of breach sources where the data appeared

**Integration into methodology:**
- Run LeakCheck as step 2b (after HIBP, before HudsonRock)
- Cross-reference breach source names with HIBP to identify coverage gaps
- LeakCheck may return breach names not indexed by HIBP and vice versa
- If LeakCheck returns `found > 0`: document each source with exposed field types

**Rate limits:** Public API is rate-limited; add 2-second delay between requests. For bulk queries, a paid API key is available at https://wiki.leakcheck.io/en/api/public

**Docs:** https://wiki.leakcheck.io/en/api/public

### Lunar Domain Exposure API (Free, No Key Required) — domain only

Org-level aggregate view of a **domain's** infostealer + data-breach exposure over the last
12 months. Complements HudsonRock (per-URL/per-subject) with posture, trend, and breakdowns
HudsonRock's free tier does not give: malware-family attribution with dates, VPN/SSO
**service classification**, top login URLs, employee-vs-client split, combolist-vs-dump split.

**Canonical fetch (poll-aware, single implementation):**
```bash
uv run "$SKILL_DIR/scripts/lunar_domain_exposure.py" example.com          # analyst summary
uv run "$SKILL_DIR/scripts/lunar_domain_exposure.py" example.com --json    # full report JSON
```
The API is **asynchronous**: a cold/unseen domain returns HTTP 200 with
`{"status":"GENERATING_REPORT","report":null}` and only populates on a later request. The
script polls until `REPORT_READY` (bounded `--max-wait`, default 90s) so callers never parse a
null report. Raw endpoint (reference only — prefer the script):
`https://api.lunarcyber.com/domain-exposure?domain={DOMAIN}`.

**Report fields:** `summary`, `exposure_subject_breakdown`, `monthly_timeline`,
`event_family_breakdown`, `infostealer_summary`, `malware_family_breakdown`, `os_breakdown`,
`antivirus_breakdown`, `data_breach_summary`, `data_breach_source_type_breakdown`,
`service_classification_breakdown`, `top_login_urls`, `country_breakdown`.

**Grading (mandatory):** a Lunar hit is **EXPOSURE**, NOT clusterable / same-operator — same
rule as IntelX. Two domains in one combolist share victims, not an operator. Feed findings to
exposure/trend and attack-surface leads, never to attribution edges.

**Integration into methodology:**
- Run on org/domain cases alongside the HudsonRock domain endpoints (run all three; merge, dedup).
- `service_classification_breakdown` + `top_login_urls` (VPN/Citrix/AnyConnect/Pulse/Fortinet/Okta/Entra/ADFS) → register as `attack_surface` leads; feed to `/msftrecon` + edge-appliance recon.
- `monthly_timeline` → feed `analysis/risk-trend-tracker.md`, `analysis/exposure-model.md`.
- Corroborate `malware_family_breakdown` / `os_breakdown` against `/stealer-log` and HudsonRock.
- **Absence ≠ clean:** a domain stuck in `GENERATING_REPORT` after the poll cap is unknown, not clear.

---

## Output Format
```
Subject: user@example.com

Findings:
  LinkedIn (May 2016): email + SHA1 hash — MEDIUM
  Exactis (Jun 2018): email + name + phone — HIGH
  Collection #1 (Jan 2019): email + plaintext — HIGH

Exposure Timeline: 2016-05 → 2019-01
Reuse Risk: HIGH (same password pattern across 2 breaches)
Cumulative Severity: HIGH
```

## Limitations
- Breach databases capture only disclosed or discovered incidents; private breaches are not indexed
- Paste content is ephemeral — findings may disappear before verification
- Hash cracking feasibility depends on algorithm and compute resources — not performed here
- HIBP API rate-limits unauthenticated bulk requests
- Domain sweep requires administrator verification on HIBP

## Related Techniques
- [fx-leak-monitoring.md](fx-leak-monitoring.md) — ongoing alerting vs. point-in-time sweep
- [fx-email-header-analysis.md](fx-email-header-analysis.md) — validate contact addresses found in findings
- [fx-metadata-parsing.md](fx-metadata-parsing.md) — extract author fields from dumped documents
