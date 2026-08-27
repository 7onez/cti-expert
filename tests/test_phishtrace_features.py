#!/usr/bin/env python3
"""test_phishtrace_features.py — gate on PhishTrace dynamic-feature characterization.

Run:  python3 tests/test_phishtrace_features.py     (zero deps)
      pytest tests/test_phishtrace_features.py -q     (also works)

WHAT THIS PROTECTS
  1. OFF-ORIGIN CREDENTIAL EXFIL -> phishing_likely, and the exfil host is an IOC.
  2. THIN/EMPTY TRACE ON A FLAGGED PAGE -> cloaked, NEVER benign (the anti-false-negative rule).
  3. BENIGN TRACE -> benign (no over-flagging of a normal same-origin page).
  4. IOCs ARE PIVOT LEADS, NOT ATTRIBUTION (note present).
  5. MALFORMED/EMPTY input degrades, never crashes.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))

import phishtrace_features as pt  # noqa: E402

FAILURES = []


def check(label, cond, detail=""):
    if cond:
        print("  ok   {}".format(label))
    else:
        print("  FAIL {} {}".format(label, detail))
        FAILURES.append(label)


PHISH_TRACE = {
    "landing_url": "https://login-bank.example/",
    "final_url": "https://login-bank.example/verify",
    "requests": [{"url": "https://login-bank.example/app.js", "method": "GET", "type": "script"}],
    "form_posts": [{"action": "https://collector.evil-host.top/steal",
                    "fields": ["username", "password", "otp"]}],
    "redirects": [{"from": "https://ads.example/x", "to": "https://login-bank.example/", "status": 302}],
    "timing_ms": 800, "dom_text_len": 3200,
}

CLOAKED_TRACE = {
    "landing_url": "https://susp.example/",
    "final_url": "https://susp.example/",
    "requests": [], "form_posts": [], "redirects": [],
    "bot_wall": True, "dom_text_len": 10,
}

BENIGN_TRACE = {
    "landing_url": "https://shop.example/",
    "final_url": "https://shop.example/",
    "requests": [{"url": "https://shop.example/main.js", "method": "GET", "type": "script"},
                 {"url": "https://cdn.shop.example/lib.js", "method": "GET", "type": "script"}],
    "form_posts": [{"action": "/cart/add", "fields": ["sku", "qty"]}],
    "redirects": [], "dom_text_len": 5000,
}


def test_phishing_likely():
    print("\n[1] off-origin credential exfil -> phishing_likely + IOC")
    r = pt.analyze_trace(PHISH_TRACE, origin="login-bank.example")
    check("verdict phishing_likely", r["verdict"] == "phishing_likely", r["verdict"])
    check("credential_form_offorigin true", r["features"]["credential_form_offorigin"] is True)
    check("exfil host surfaced as IOC",
          any("evil-host.top" in u for u in r["iocs"]["exfil_endpoints"]), r["iocs"])


def test_cloaked_not_benign():
    print("\n[2] thin/bot-walled trace on a flagged page -> cloaked, not benign")
    r = pt.analyze_trace(CLOAKED_TRACE, origin="susp.example", static_suspicious=True)
    check("verdict cloaked", r["verdict"] == "cloaked", r["verdict"])
    check("not benign", r["verdict"] != "benign")


def test_benign():
    print("\n[3] normal same-origin trace -> benign")
    r = pt.analyze_trace(BENIGN_TRACE, origin="shop.example")
    check("verdict benign", r["verdict"] == "benign", r["verdict"])
    check("no exfil endpoints", r["iocs"]["exfil_endpoints"] == [], r["iocs"])


def test_ioc_not_attribution():
    print("\n[4] IOCs framed as pivot leads, not attribution")
    r = pt.analyze_trace(PHISH_TRACE, origin="login-bank.example")
    check("note states not same-operator attribution", "attribution" in r["note"].lower())


def test_empty_degrades():
    print("\n[5] empty / malformed trace degrades")
    r = pt.analyze_trace({})
    check("empty trace -> inconclusive (not benign, not crash)", r["verdict"] == "inconclusive", r["verdict"])
    r2 = pt.analyze_trace({"requests": "notalist", "form_posts": None})
    check("bad field types handled", isinstance(r2, dict) and "verdict" in r2)


def test_regressions_from_review():
    print("\n[6] review regressions: same-origin login, token collisions, multi-suffix, decoy, crashes")
    # B1: same-origin credential form is NOT an exfil IOC and not 'suspicious'
    r = pt.analyze_trace({"landing_url": "https://shop.example/", "final_url": "https://shop.example/login",
                          "form_posts": [{"action": "https://shop.example/login",
                                          "fields": ["email", "password"]}],
                          "dom_text_len": 3000}, origin="shop.example")
    check("B1 same-origin login not suspicious", r["verdict"] in ("benign", "inconclusive"), r["verdict"])
    check("B1 no exfil IOC for own login", r["iocs"]["exfil_endpoints"] == [], r["iocs"])
    check("B1 credential_form_onorigin recorded neutrally", r["features"]["credential_form_onorigin"] is True)
    # B2: 'shipping' must not match 'pin'; benign off-origin checkout is not phishing_likely
    r = pt.analyze_trace({"landing_url": "https://shop.example/",
                          "form_posts": [{"action": "https://pay-processor.example/checkout",
                                          "fields": ["shipping", "email"]}],
                          "dom_text_len": 3000}, origin="shop.example")
    check("B2 'shipping' not credential", r["features"]["credential_form_offorigin"] is False, r["features"])
    check("B2 not phishing_likely", r["verdict"] != "phishing_likely", r["verdict"])
    check("B2 token 'user_pin' IS credential", pt._is_cred_field("user_pin") is True)
    check("B2 token 'discard' NOT credential", pt._is_cred_field("discard") is False)
    # B3: multi-label public suffix — evil.co.uk vs hsbc.co.uk is off-origin
    r = pt.analyze_trace({"landing_url": "https://login.hsbc.co.uk/",
                          "form_posts": [{"action": "https://collector.evil.co.uk/steal",
                                          "fields": ["username", "password"]}]}, origin="login.hsbc.co.uk")
    check("B3 .co.uk off-origin detected", r["verdict"] == "phishing_likely", r["verdict"])
    # M1: static_suspicious + rich innocuous trace must NOT be benign
    r = pt.analyze_trace({"landing_url": "https://susp.example/", "final_url": "https://susp.example/",
                          "requests": [{"url": "https://susp.example/a.js", "method": "GET"}],
                          "dom_text_len": 5000}, origin="susp.example", static_suspicious=True)
    check("M1 flagged+clean is not benign", r["verdict"] != "benign", r["verdict"])
    # M4: non-iterable field types must not crash
    for bad in ({"requests": 5}, {"form_posts": 7}, {"form_posts": [{"fields": 3}]}):
        rr = pt.analyze_trace(bad)
        check(f"M4 handled {bad}", isinstance(rr, dict) and "verdict" in rr)
    # M7: origin as URL == origin as host
    t = {"landing_url": "https://shop.example/", "form_posts": [{"action": "/login", "fields": ["email"]}]}
    check("M7 URL origin == host origin",
          pt.analyze_trace(t, origin="https://shop.example")["verdict"]
          == pt.analyze_trace(t, origin="shop.example")["verdict"])


for _t in (test_phishing_likely, test_cloaked_not_benign, test_benign,
           test_ioc_not_attribution, test_empty_degrades, test_regressions_from_review):
    _t()

if FAILURES:
    print(f"\nFAIL — {len(FAILURES)} check(s) failed:")
    for f in FAILURES:
        print("  -", f)
    sys.exit(1)
print("\nPASS — all phishtrace-features checks green")


def test_phishtrace_features():
    """pytest entry point — module body runs the checks at import time."""
    assert not FAILURES, FAILURES
