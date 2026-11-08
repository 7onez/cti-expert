# Phishing Domain Survival & Registration-Strategy Profiling

> **Module ID:** PHISH-SURV-001
> **Version:** 1.0.0
> **Phase:** Measurement, Characterization & Attribution
> **Classification:** Registration / DNS strategy analysis — maliciously-registered vs compromised
> **Research basis:** Kyungchan Lim, Jaehwan Park, Raffaele Sommese, Mattijs Jonker,
> Ricky K. P. Mok, kc Claffy, Doowon Kim — *"Built to Last? Registration and DNS Strategies
> in Phishing Domain Survival"*, APWG Symposium on Electronic Crime Research (eCrime) 2026.

---

## 1. Overview

Turns the WHOIS + DNS the collector already gathers into a two-axis judgement about a
phishing domain:

1. **Registration class** — is this a **maliciously-registered** (purpose-built) domain, or a
   **compromised** legitimate one whose owner is a *victim*, not the operator?
2. **Survival outlook** — how takedown-resistant is it (registrar/registry abuse posture,
   privacy, self-run infrastructure)?

The eCrime paper's reproducible finding is that *how* a phishing domain is registered and
hosted both separates these two populations and predicts how long the domain survives. The
compromised/malicious split is the attribution-critical part: naming a compromised third-party
business as the actor is the single most damaging error this toolkit can make (see
`/cti-check` and CLAUDE.md RULE 5).

**When to use:** on every domain/URL target during characterization, after WHOIS + DNS
collection, before writing any abuse-reporting recommendation.

**What it is NOT:** a verdict. It is an auditable, analyst-tunable heuristic prior. Every
signal is returned with its weight and reason; seed lists are overridable with `--refs`.

---

## 2. Tool Inventory

| Priority | Tool | Purpose | Install |
|----------|------|---------|---------|
| Primary | `scripts/phish_domain_survival.py` | Offline, deterministic scorer (stdlib only) | none |
| Feeds it | `/whois` / `whois-universal.md` | creation date, registrar, privacy | none |
| Feeds it | `/webpivot` + passive DNS | nameservers, MX, hosting | none |

Fully keyless. No network calls — it scores features you pass in.

---

## 3. Investigation Workflow

```
1. Collect WHOIS (created date, registrar, privacy) and DNS (NS, MX, A) for the domain
2. Note whether the site serves UNRELATED legitimate content (a compromise tell)
3. Run phish_domain_survival.py with the collected features
4. Read registration_class:
     maliciously_registered  -> operator-owned infra; safe to pivot/cluster/report
     likely_compromised      -> a VICTIM; corroborate before naming; report to the owner
     indeterminate           -> collect more features (age/registrar/NS)
5. Read survival_outlook to prioritise takedown effort and set re-check cadence
6. Feed the class into /threat-model and the exposure/finding framework
```

---

## 4. CLI Commands & Expected Output

```bash
# Purpose-built lure domain (flags supplied directly)
python3 scripts/phish_domain_survival.py login-verify-paypa1.top \
  --age-days 3 --registrar NameSilo --brand paypal --nameserver ns1.duckdns.org

# Compromised long-lived business (features via JSON on stdin)
echo '{"domain":"old-bakery.com","age_days":4200,"registrar":"MarkMonitor",
       "has_mx":true,"content_legit":true}' \
  | python3 scripts/phish_domain_survival.py --features -

# JSON out for the pipeline / IOC bundle
python3 scripts/phish_domain_survival.py evil.top --features feats.json --json -o out.json

# Override the seed lists (abused TLDs/registrars, dynamic-DNS providers)
python3 scripts/phish_domain_survival.py evil.top --refs myrefs.json
```

**Feature keys** (all optional except `domain`): `age_days` or `created`, `first_seen`
(for the registration-to-use gap), `registrar`, `nameservers[]`, `has_mx`, `content_legit`,
`privacy`, `brand`, `bulletproof`.

**Output (text):** `registration_class`, `purpose_score`/`compromised_score` (0-100),
`survival_outlook` + index, a per-signal list (`axis`, weight, reason), an explicit
`not_assessed` list, and the not-a-verdict disclaimer.

---

## 5. Signal Model (default weights, tunable)

| Axis | Signal | Meaning |
|------|--------|---------|
| purpose | age < 7d / < 30d / < 180d | freshly/very/young — purpose-registered |
| purpose | reg→use gap ≤ 7d | served content immediately after registration |
| purpose | high label entropy | random/DGA-like label |
| purpose | long label + ≥2 hyphens | lure-string shape (`secure-login-update`) |
| purpose | digits mixed with letters | look-alike substitution (`paypa1`) |
| purpose | combosquat | known brand embedded in a non-brand label |
| purpose | abused TLD / registrar | over-represented in phishing telemetry |
| purpose | free / dynamic-DNS nameserver | legit businesses don't run prod DNS here |
| compromised | age > 730d | long-lived, fits an abused legitimate site |
| compromised | established registrar | brand-protection / responsive abuse desk |
| compromised | live MX on old domain | an operating business |
| compromised | unrelated legitimate content | phishing on a compromised path |
| survival | registrar abuse desk | responsive desk → **shorter** survival (negative) |
| survival | privacy proxy | slows registrant-based takedown |
| survival | bulletproof hosting | abuse-tolerant → long survival |

---

## 6. Output Interpretation

- **`maliciously_registered`** — the domain is operator infrastructure. Its selectors are
  attribution-grade; pivot and cluster freely (subject to `/cti-check`).
- **`likely_compromised`** — the registrant is almost certainly a **victim**. Do **not** cluster
  the domain to the operator on registrant identity. Corroborate the abuse (the phishing path,
  injected content) and report to the *owner*, not as the actor.
- **`indeterminate`** — not enough discriminating features. Collect age/registrar/NS and re-run.
- **`survival_outlook`** — `long` (bulletproof/lenient registry + privacy) means schedule
  earlier, harder takedown escalation; `short` means a responsive registrar will likely act.

---

## 7. Confidence Ratings

| Situation | Confidence | Notes |
|-----------|-----------|-------|
| purpose_score ≥ 60 with age + label + infra agreeing | HIGH | multiple independent axes |
| purpose_score 35-60 | MEDIUM | corroborate with content + clustering |
| likely_compromised with legit content + live MX + old age | HIGH (as *victim*) | do not name as actor |
| indeterminate | LOW | insufficient features, not a benign verdict |

---

## 8. Limitations

- **Heuristic, not ground truth.** Default weights encode the paper's *themes*, not its exact
  model; tune with `--refs` and local telemetry.
- **Public-suffix-free label parsing** is an approximation (`x.co.uk` → label `co`); label
  heuristics degrade gracefully rather than mislead.
- **No network.** It scores features you supply; garbage-in/garbage-out — pass real WHOIS/DNS.
- **Registrar/TLD seed lists** are small and conservative; they *nudge*, never decide.

---

## 9. Command Reference

### `phish_domain_survival.py <domain> [features]`

**Input:** a domain plus optional registration/DNS features.
**Process:** weight per-axis signals → purpose/compromised priors → class + survival band.
**Output:** class, scores, per-signal rationale, `not_assessed` list, disclaimer (text or JSON).

Regression-tested by `tests/test_phish_domain_survival.py` (run in `scripts/audit.sh`).

### `wp_takedown.py` — takedown / relocation watch

Survival does not end at a takedown: a held lure is usually rebuilt on a fresh name, often on
the same server. `intel_engine/WebPivot/tools/wp_takedown.py` checks the outcome:

```bash
python3 WebPivot/tools/wp_takedown.py held-shop.example --json
python3 WebPivot/tools/wp_takedown.py --case CASE-0001          # every collected apex, read-only
python3 WebPivot/tools/wp_takedown.py example.com --hunt --ip 203.0.113.10 --no-fetch
```

1. **Status** — RDAP EPP set: `clientHold`/`serverHold` → `held`; `redemptionPeriod`/
   `pendingDelete` → `deleted`; `serverDeleteProhibited` & other server locks count only on top
   of a hold. DNS adds `dns:nxdomain`, `dns:no_ns` and sinkhole/registry-hold nameservers
   (→ `suspended`). `held_since` is an RDAP event date with its basis (usually `last changed`).
2. **Successor hunt** (held/suspended/deleted, or `--hunt`) — last known origin IPs (case
   origin history → HackerTarget hostsearch → live A; CDN/parking/bogon edges skipped), keyless
   reverse-IP, then each co-tenant's live page vs the held domain's last capture (case raw, else
   Wayback): favicon mmh3, DOM skeleton (`body`), distinctive `<title>`.

Output per domain: `status` (active|held|suspended|deleted|unknown), `signals[]`,
`held_since`, `successors[]` {`domain`, `shared_ip`, `content_match` title|favicon|body|none,
`first_seen`, `rung`, `caveat`}. **RULE 5:** a shared IP alone is co-tenancy (`rung: lead`); a
content match raises a successor only to a kit sibling (`rung: kit`) — never an owner, never a
KB edge. A successor registered after `held_since` that serves the held kit is the relocation
lead to collect next. Patterns and limits: `WebPivot/references/takedown.json`.

---

*Phishing Domain Survival Module v1.0.0 — for authorized threat-intelligence use.*
