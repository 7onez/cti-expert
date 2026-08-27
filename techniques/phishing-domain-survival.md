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

---

*Phishing Domain Survival Module v1.0.0 — for authorized threat-intelligence use.*
