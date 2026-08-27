#!/usr/bin/env python3
# cti-expert skill — phishing-domain registration/DNS survival profiling.
# Technique reimplemented from published eCrime survival-study themes; no source copied.
"""phish_domain_survival.py — classify a domain as maliciously-registered vs compromised,
and estimate takedown resilience, from registration + DNS strategy alone.

Grounded in: Kyungchan Lim, Jaehwan Park, Raffaele Sommese, Mattijs Jonker, Ricky K. P.
Mok, kc Claffy, Doowon Kim — "Built to Last? Registration and DNS Strategies in Phishing
Domain Survival", APWG Symposium on Electronic Crime Research (eCrime) 2026. The paper's
central, reproducible finding is that *how* a phishing domain is registered and hosted
(registrar, TLD, nameserver posture, age, label composition) both distinguishes a
purpose-registered ("malicious") domain from an abused-but-legitimate ("compromised") one
AND predicts how long it survives before takedown. This script turns the WHOIS/DNS the
collector already gathers into that two-axis judgement — entirely offline and deterministic.

Two axes, reported separately (they answer different questions):
  * registration_class : maliciously_registered | likely_compromised | indeterminate
      A young random-label domain at a bulk registrar on an abused TLD is purpose-built.
      A decade-old domain at an established registrar with live MX serving unrelated content
      that now hosts a phishing path is a COMPROMISED third party — naming it as the actor
      is the classic attribution error, so this axis exists to prevent it.
  * survival_outlook  : short | moderate | long  (takedown resilience, NOT maliciousness)
      Registrar/registry abuse-handling leniency, privacy, and self-run infrastructure
      lengthen survival; that is orthogonal to whether the domain is malicious at all.

Everything is a WEIGHTED, ANALYST-TUNABLE heuristic — never a verdict. Every contributing
signal is returned with its weight and a one-line reason, so the score is auditable and any
seed list (abused TLDs/registrars, dynamic-DNS providers) can be overridden with --refs.

Inputs are all OPTIONAL except the domain; a missing feature is reported "not assessed",
never scored as if benign (an absent key must not read as an operator fact — CLAUDE.md RULE).

Usage:
  uv run phish_domain_survival.py login-secure-update.top --age-days 3 --registrar "NameSilo"
  uv run phish_domain_survival.py paypa1-verify.xyz --brand paypal --nameserver ns1.duckdns.org
  echo '{"domain":"x.com","age_days":4200,"registrar":"MarkMonitor","has_mx":true,
         "content_legit":true}' | uv run phish_domain_survival.py --features -
  uv run phish_domain_survival.py evil.top --features feats.json --json -o out.json
  uv run phish_domain_survival.py evil.top --refs myrefs.json   # override seed lists

Exit codes: 0 = assessed, 4 = bad input.
"""
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
import sys
import json
import math
import argparse
import datetime as _dt

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

# --------------------------------------------------------------- tunable seed lists
# Small, deliberately conservative seeds. These are NOT allowlists/denylists of guilt —
# they only nudge a score and every hit is shown with its reason. Override with --refs.
DEFAULT_REFS = {
    # TLDs repeatedly over-represented in phishing telemetry / cheap-to-bulk-register.
    "abused_tlds": [
        "top", "xyz", "icu", "rest", "cn", "gq", "ml", "cf", "ga", "tk", "buzz",
        "cyou", "sbs", "click", "link", "live", "shop", "monster", "quest", "lol",
        "cfd", "bond", "kim", "work", "support", "online", "site", "fun",
    ],
    # Registrars that surface disproportionately in bulk phishing registration and/or are
    # slow on abuse. Presence here only raises the purpose-built prior slightly.
    "abused_registrars": [
        "namesilo", "namecheap", "porkbun", "reg.ru", "regru", "hostinger",
        "publicdomainregistry", "pdr", "gname", "dominet", "west263", "alibaba",
        "aliyun", "dynadot", "openprovider", "nicenic",
    ],
    # Free / dynamic-DNS providers. A phishing domain delegated here is nearly always
    # purpose-built; a legitimate business almost never runs production DNS on these.
    "dynamic_dns_ns": [
        "duckdns.org", "no-ip.com", "noip.com", "dynu.com", "afraid.org",
        "freedns", "changeip.com", "ydns.io", "sslip.io", "nip.io", "freenom",
        "cloudns.net", "now-dns.com", "dnsexit.com",
    ],
    # Registrars with a strong abuse desk / brand-protection posture -> shorter survival,
    # and a legitimate-business tell (compromised, not registered-for-phishing).
    "established_registrars": [
        "markmonitor", "cscglobal", "csc corporate", "com laude", "safenames",
        "gandi", "google", "amazon", "cloudflare", "godaddy", "network solutions",
        "nom-iq", "ovh",
    ],
    # Managed DNS providers -> neutral for attribution; slightly resilient for survival.
    "managed_ns": [
        "cloudflare.com", "awsdns", "googledomains.com", "google.com",
        "azure-dns", "dnsmadeeasy.com", "nsone.net", "ns.cloudflare.com",
        "domaincontrol.com", "registrar-servers.com",
    ],
}


def _norm(s):
    return (s or "").strip().lower()


def _shannon(s):
    """Shannon entropy (bits/char) of the registrable label — high on random/DGA labels."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def _label(domain):
    """Registrable label under test: the segment immediately left of the final TLD.
    Public-suffix-free approximation (documented): 'a-b.example.top' -> 'example',
    'x.co.uk' -> 'co' is imperfect but the label heuristics degrade gracefully."""
    host = _norm(domain).rstrip(".")
    parts = [p for p in host.split(".") if p]
    if len(parts) >= 2:
        return parts[-2]
    return parts[0] if parts else ""


def _tld(domain):
    host = _norm(domain).rstrip(".")
    parts = [p for p in host.split(".") if p]
    return parts[-1] if parts else ""


def _age_days(features):
    """Prefer an explicit age_days; else derive from 'created' (ISO) against today."""
    if features.get("age_days") is not None:
        try:
            return int(features["age_days"])
        except (TypeError, ValueError):
            return None
    created = features.get("created")
    if not created:
        return None
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y/%m/%d"):
        try:
            d = _dt.datetime.strptime(str(created)[:len(fmt) + 2].strip(), fmt)
            return (_dt.datetime.utcnow() - d).days
        except ValueError:
            continue
    return None


def _reg_to_use_gap(features):
    """Days between registration and first-seen-serving-content. A near-zero gap is a
    strong purpose-built tell; a large gap fits a domain compromised long after registration."""
    c, f = features.get("created"), features.get("first_seen")
    if not c or not f:
        return None
    def _p(x):
        for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y/%m/%d"):
            try:
                return _dt.datetime.strptime(str(x)[:len(fmt) + 2].strip(), fmt)
            except ValueError:
                continue
        return None
    dc, df = _p(c), _p(f)
    if not dc or not df:
        return None
    return (df - dc).days


def _brands(features):
    b = features.get("brand")
    if not b:
        return []
    if isinstance(b, str):
        return [_norm(b)]
    return [_norm(x) for x in b if x]


def assess(features, refs=None):
    """Score a domain's registration/DNS profile. Pure, deterministic, offline.

    Returns a dict: domain, registration_class, purpose_score (0-100), survival_outlook,
    signals[] (each {axis, feature, weight, note}), assessed[], not_assessed[], rationale.
    """
    R = dict(DEFAULT_REFS)
    if refs:
        R.update(refs)
    domain = _norm(features.get("domain"))
    label, tld = _label(domain), _tld(domain)
    ns = [_norm(x) for x in (features.get("nameservers") or []) if x]
    registrar = _norm(features.get("registrar"))

    signals = []          # (axis, feature, weight, note)  axis: "purpose" | "compromised" | "survival"
    assessed, missing = [], []

    def sig(axis, feat, w, note):
        signals.append({"axis": axis, "feature": feat, "weight": w, "note": note})

    # ---- age -------------------------------------------------------------------
    age = _age_days(features)
    if age is None:
        missing.append("domain_age")
    else:
        assessed.append("domain_age")
        if age < 7:
            sig("purpose", "age", 25, f"registered {age}d ago — freshly registered")
        elif age < 30:
            sig("purpose", "age", 18, f"registered {age}d ago — very young")
        elif age < 180:
            sig("purpose", "age", 8, f"registered {age}d ago — young")
        elif age > 730:
            sig("compromised", "age", 20, f"{age}d old — long-lived, fits a compromised site")

    # ---- registration-to-use gap ----------------------------------------------
    gap = _reg_to_use_gap(features)
    if gap is not None:
        assessed.append("reg_to_use_gap")
        if gap <= 7:
            sig("purpose", "reg_to_use_gap", 15, f"served content {gap}d after registration")
        elif gap > 365:
            sig("compromised", "reg_to_use_gap", 12,
                f"first served {gap}d after registration — abused long after")

    # ---- label composition (random/DGA, combosquat) ---------------------------
    if label:
        assessed.append("label")
        ent = _shannon(label)
        digits = sum(c.isdigit() for c in label)
        hyphens = label.count("-")
        if len(label) >= 7 and ent >= 3.7:
            sig("purpose", "label_entropy", 14,
                f"label '{label}' entropy {ent:.2f} — random/DGA-like")
        if len(label) >= 12 and hyphens >= 2:
            sig("purpose", "label_shape", 8,
                f"label '{label}' long with {hyphens} hyphens — lure-string shape")
        if digits and any(ch.isalpha() for ch in label) and digits / len(label) >= 0.2:
            sig("purpose", "label_digits", 6,
                f"label '{label}' mixes {digits} digits with letters — look-alike substitution")
        # combosquat: a known brand appears inside a non-brand label
        for br in _brands(features):
            if br and br in label and label != br:
                sig("purpose", "combosquat", 16,
                    f"brand '{br}' embedded in label '{label}' — combosquatting")
                break

    # ---- TLD -------------------------------------------------------------------
    if tld:
        assessed.append("tld")
        if tld in R["abused_tlds"]:
            sig("purpose", "tld", 10, f".{tld} is over-represented in phishing telemetry")
            sig("survival", "tld_leniency", 4, f".{tld} registries vary in abuse response")

    # ---- registrar -------------------------------------------------------------
    if registrar:
        assessed.append("registrar")
        if any(a in registrar for a in R["abused_registrars"]):
            sig("purpose", "registrar", 8, f"'{registrar}' seen in bulk phishing registration")
        if any(e in registrar for e in R["established_registrars"]):
            sig("compromised", "registrar", 14,
                f"'{registrar}' is an established/brand-protection registrar")
            sig("survival", "registrar_abuse_desk", -6,
                f"'{registrar}' runs a responsive abuse desk — shorter survival")
    else:
        missing.append("registrar")

    # ---- nameservers -----------------------------------------------------------
    if ns:
        assessed.append("nameservers")
        if any(any(d in n for d in R["dynamic_dns_ns"]) for n in ns):
            sig("purpose", "dynamic_dns", 18, "delegated to a free/dynamic-DNS provider")
            sig("survival", "dynamic_dns", 3, "dynamic DNS enables fast host rotation")
        elif any(any(m in n for m in R["managed_ns"]) for n in ns):
            sig("survival", "managed_ns", 4, "managed DNS provider (CDN-fronted) — mild resilience")
        else:
            # self-run NS in the domain itself = operator controls the zone
            if any(domain and domain in n for n in ns):
                sig("survival", "self_hosted_ns", 5, "self-hosted nameservers — operator-run zone")
    else:
        missing.append("nameservers")

    # ---- MX + declared legitimate content (compromise tells) -------------------
    if features.get("has_mx") is not None:
        assessed.append("mx")
        if features.get("has_mx") and (age or 0) > 730:
            sig("compromised", "mx", 8, "live MX on a long-lived domain — an operating business")
    else:
        missing.append("mx")
    if features.get("content_legit"):
        assessed.append("content")
        sig("compromised", "content", 18,
            "unrelated legitimate content present — phishing likely on a compromised path")

    # ---- privacy proxy ---------------------------------------------------------
    if features.get("privacy") is not None:
        assessed.append("privacy")
        if features.get("privacy"):
            sig("purpose", "privacy", 4, "WHOIS privacy — common but mildly elevates the prior")
            sig("survival", "privacy", 4, "privacy proxy slows registrant-based takedown")

    # ---- IP hosting hint -------------------------------------------------------
    if features.get("bulletproof"):
        assessed.append("hosting")
        sig("survival", "bulletproof", 12, "flagged bulletproof/abuse-tolerant hosting — long survival")

    # -------------------------------------------------------------- aggregate
    purpose = sum(s["weight"] for s in signals if s["axis"] == "purpose")
    compromised = sum(s["weight"] for s in signals if s["axis"] == "compromised")
    purpose_score = max(0, min(100, purpose))
    compromised_score = max(0, min(100, compromised))

    if compromised_score >= 30 and compromised_score > purpose_score:
        reg_class = "likely_compromised"
    elif purpose_score >= 35 and purpose_score >= compromised_score:
        reg_class = "maliciously_registered"
    else:
        reg_class = "indeterminate"

    survival_pts = sum(s["weight"] for s in signals if s["axis"] == "survival")
    if survival_pts <= 2:
        survival = "short"
    elif survival_pts <= 10:
        survival = "moderate"
    else:
        survival = "long"

    rationale = (
        f"purpose-built prior {purpose_score}/100, compromised prior {compromised_score}/100 "
        f"-> {reg_class}; survival index {survival_pts} -> {survival}. "
        f"{len(assessed)} feature(s) assessed, {len(missing)} not assessed."
    )

    return {
        "domain": domain,
        "registration_class": reg_class,
        "purpose_score": purpose_score,
        "compromised_score": compromised_score,
        "survival_outlook": survival,
        "survival_index": survival_pts,
        "signals": signals,
        "assessed": assessed,
        "not_assessed": missing,
        "rationale": rationale,
        "disclaimer": "Heuristic prior from registration/DNS strategy — not a verdict. "
                      "A likely_compromised domain names a victim, not the operator: "
                      "corroborate before any abuse report.",
    }


def _fmt_text(r):
    out = []
    out.append(f"Domain            : {r['domain']}")
    out.append(f"Registration class: {r['registration_class']}  "
               f"(purpose {r['purpose_score']}/100, compromised {r['compromised_score']}/100)")
    out.append(f"Survival outlook  : {r['survival_outlook']}  (index {r['survival_index']})")
    out.append("")
    if r["signals"]:
        out.append("Signals:")
        for s in r["signals"]:
            sign = "+" if s["weight"] >= 0 else "-"
            out.append(f"  [{s['axis']:<11}] {sign}{abs(s['weight']):<3} {s['note']}")
    if r["not_assessed"]:
        out.append("")
        out.append("Not assessed (feature absent, NOT scored as benign): "
                   + ", ".join(r["not_assessed"]))
    out.append("")
    out.append(r["rationale"])
    out.append("")
    out.append("NOTE: " + r["disclaimer"])
    return "\n".join(out)


def _load_features(args):
    if args.features:
        raw = sys.stdin.read() if args.features == "-" else open(args.features, encoding="utf-8").read()
        feats = json.loads(raw)
        if not isinstance(feats, dict):
            raise ValueError("--features must be a JSON object")
    else:
        feats = {}
    # explicit flags override / supplement the features file
    if args.domain:
        feats["domain"] = args.domain
    for k in ("registrar",):
        v = getattr(args, k)
        if v is not None:
            feats[k] = v
    if args.age_days is not None:
        feats["age_days"] = args.age_days
    if args.created:
        feats["created"] = args.created
    if args.first_seen:
        feats["first_seen"] = args.first_seen
    if args.nameserver:
        feats["nameservers"] = args.nameserver
    if args.brand:
        feats["brand"] = args.brand
    if args.privacy is not None:
        feats["privacy"] = args.privacy
    if args.has_mx is not None:
        feats["has_mx"] = args.has_mx
    if args.content_legit:
        feats["content_legit"] = True
    if args.bulletproof:
        feats["bulletproof"] = True
    return feats


def _cli(argv):
    ap = argparse.ArgumentParser(
        description="Classify a domain as maliciously-registered vs compromised and estimate "
                    "takedown resilience from registration/DNS strategy (offline).")
    ap.add_argument("domain", nargs="?", help="domain to assess (or provide via --features)")
    ap.add_argument("--features", help="JSON object of features ('-' for stdin)")
    ap.add_argument("--registrar")
    ap.add_argument("--age-days", type=int, dest="age_days")
    ap.add_argument("--created", help="registration date ISO (YYYY-MM-DD)")
    ap.add_argument("--first-seen", dest="first_seen", help="first-seen-serving date ISO")
    ap.add_argument("--nameserver", action="append", help="nameserver (repeatable)")
    ap.add_argument("--brand", action="append", help="known brand term to check combosquat (repeatable)")
    ap.add_argument("--privacy", dest="privacy", action="store_const", const=True, default=None)
    ap.add_argument("--has-mx", dest="has_mx", action="store_const", const=True, default=None)
    ap.add_argument("--content-legit", dest="content_legit", action="store_true",
                    help="site serves unrelated legitimate content (compromise tell)")
    ap.add_argument("--bulletproof", action="store_true", help="hosting flagged abuse-tolerant")
    ap.add_argument("--refs", help="JSON overriding the seed lists")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of text")
    ap.add_argument("-o", "--out", help="write output to a file")
    args = ap.parse_args(argv)

    try:
        feats = _load_features(args)
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 4
    if not _norm(feats.get("domain")):
        print("error: a domain is required (positional or in --features)", file=sys.stderr)
        return 4

    refs = None
    if args.refs:
        try:
            refs = json.loads(open(args.refs, encoding="utf-8").read())
        except (OSError, ValueError) as e:
            print(f"error: --refs: {e}", file=sys.stderr)
            return 4

    result = assess(feats, refs=refs)
    text = json.dumps(result, indent=2, ensure_ascii=False) if args.json else _fmt_text(result)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
