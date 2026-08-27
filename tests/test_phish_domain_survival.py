#!/usr/bin/env python3
"""test_phish_domain_survival.py — gate on the registration/DNS survival profiler.

Run:  python3 tests/test_phish_domain_survival.py         (zero deps)
      pytest tests/test_phish_domain_survival.py -q         (also works)

WHAT THIS PROTECTS
------------------
The profiler emits an attribution-adjacent judgement (maliciously-registered vs compromised).
Each failure below ships a plausible-looking but wrong answer:

  1. THE COMPROMISED/MALICIOUS SPLIT (the one that matters). A long-lived domain at an
     established registrar serving unrelated legitimate content is a VICTIM. If the profiler
     ever calls that 'maliciously_registered', an analyst names an innocent third party — the
     exact error CLAUDE.md RULE 5 and /cti-check exist to prevent.
  2. HONEST DEGRADE. An absent feature must be reported 'not_assessed', never scored as if
     benign (an absent key is not an operator fact).
  3. DETERMINISM + BOUNDED SCORE. Same input -> same output; score stays in [0,100].
  4. EVERY SIGNAL IS AUDITABLE. Each contributing signal carries a weight and a reason.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))

import phish_domain_survival as ps  # noqa: E402

FAILURES = []


def check(label, cond, detail=""):
    if cond:
        print("  ok   {}".format(label))
    else:
        print("  FAIL {} {}".format(label, detail))
        FAILURES.append(label)


# ── 1. the compromised / malicious split ─────────────────────────────────────
def test_class_split():
    print("\n[1] compromised vs maliciously-registered split")

    mal = ps.assess({
        "domain": "secure-login-update.top", "age_days": 3, "registrar": "NameSilo",
        "nameservers": ["ns1.duckdns.org"], "brand": "microsoft",
    })
    check("young random domain -> maliciously_registered",
          mal["registration_class"] == "maliciously_registered", mal["registration_class"])
    check("purpose_score dominates", mal["purpose_score"] > mal["compromised_score"])

    victim = ps.assess({
        "domain": "old-family-bakery.com", "age_days": 4200, "registrar": "MarkMonitor",
        "has_mx": True, "content_legit": True,
    })
    check("long-lived legit-content domain -> likely_compromised",
          victim["registration_class"] == "likely_compromised", victim["registration_class"])
    check("compromised NOT called malicious (RULE 5)",
          victim["registration_class"] != "maliciously_registered")

    thin = ps.assess({"domain": "whatever.com"})
    check("no discriminating features -> indeterminate",
          thin["registration_class"] == "indeterminate", thin["registration_class"])


# ── 2. combosquat detection ──────────────────────────────────────────────────
def test_combosquat():
    print("\n[2] combosquat — brand embedded in a non-brand label")
    r = ps.assess({"domain": "paypal-verification.top", "brand": "paypal"})
    labels = [s["feature"] for s in r["signals"]]
    check("combosquat signal fires", "combosquat" in labels, labels)
    # a bare brand as the whole label is NOT combosquat (could be the brand itself)
    r2 = ps.assess({"domain": "paypal.com", "brand": "paypal"})
    check("exact-brand label is not combosquat",
          "combosquat" not in [s["feature"] for s in r2["signals"]])


# ── 3. honest degrade ────────────────────────────────────────────────────────
def test_honest_degrade():
    print("\n[3] absent features are 'not_assessed', never scored benign")
    r = ps.assess({"domain": "x.top"})
    check("registrar absent -> not_assessed", "registrar" in r["not_assessed"], r["not_assessed"])
    check("nameservers absent -> not_assessed", "nameservers" in r["not_assessed"])
    check("no compromised credit invented for missing age", r["compromised_score"] == 0)


# ── 4. determinism + bounded score ───────────────────────────────────────────
def test_determinism_bounds():
    print("\n[4] deterministic, bounded [0,100]")
    feats = {"domain": "a-b-c-d-e-f.xyz", "age_days": 2, "registrar": "namesilo",
             "nameservers": ["ns.duckdns.org"], "brand": "apple", "privacy": True}
    r1 = ps.assess(feats)
    r2 = ps.assess(dict(feats))
    check("same input -> same purpose_score", r1["purpose_score"] == r2["purpose_score"])
    check("same input -> same class", r1["registration_class"] == r2["registration_class"])
    check("purpose_score bounded", 0 <= r1["purpose_score"] <= 100, r1["purpose_score"])
    check("compromised_score bounded", 0 <= r1["compromised_score"] <= 100)


# ── 5. auditability ──────────────────────────────────────────────────────────
def test_auditability():
    print("\n[5] every signal carries an axis, weight, and reason")
    r = ps.assess({"domain": "login-secure.top", "age_days": 5, "registrar": "namesilo"})
    check("has signals", len(r["signals"]) > 0)
    ok = all(("axis" in s and "weight" in s and "note" in s and s["note"]) for s in r["signals"])
    check("all signals fully described", ok, r["signals"])
    check("carries the not-a-verdict disclaimer", "not a verdict" in r["disclaimer"].lower())


# ── 6. entropy helper ────────────────────────────────────────────────────────
def test_entropy():
    print("\n[6] Shannon entropy monotonicity sanity")
    check("random label > repeated label",
          ps._shannon("x8k2qzj") > ps._shannon("aaaaaaa"))
    check("empty label entropy is 0", ps._shannon("") == 0.0)


for _t in (test_class_split, test_combosquat, test_honest_degrade,
           test_determinism_bounds, test_auditability, test_entropy):
    _t()

if FAILURES:
    print(f"\nFAIL — {len(FAILURES)} check(s) failed:")
    for f in FAILURES:
        print("  -", f)
    sys.exit(1)
print("\nPASS — all phish-domain-survival checks green")


def test_phish_domain_survival():
    """pytest entry point — module body runs the checks at import time."""
    assert not FAILURES, FAILURES
