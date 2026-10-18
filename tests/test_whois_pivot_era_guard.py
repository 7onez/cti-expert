#!/usr/bin/env python3
"""Regression: wp_analyze.whois_enrich_result must turn WHOIS history into registrant_email/
phone/address PIVOTS using ONLY the current ownership era (whois_eras.owner_values), never a
flat, unfiltered 'history.registrant_emails'-style aggregate that mixes every previous owner in
with the current one (the drop-catch bug: a domain re-registered after expiry resets the
registrant, and every contact recorded before that belongs to a DIFFERENT, uninvolved party).

The OLD behaviour is re-implemented HERE (never restored in the tree) purely to prove this test
would have failed against it — the real wp_analyze module is exercised for the actual assertion.

Run:  python3 tests/test_whois_pivot_era_guard.py
Fully offline: whois_enrich.whois_summary_keyless is stubbed; no network, no metered calls.
Synthetic data only: site-a.example, obviously-fake registrant contacts.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
WP = os.path.join(ROOT, "intel_engine", "WebPivot", "tools")
if WP not in sys.path:
    sys.path.insert(0, WP)

import wp_analyze as WA  # noqa: E402

# A drop-catch history: the domain's CURRENT owner (era 2025-09-09) and a PREVIOUS, uninvolved
# owner (era 2016-04-06). `history` carries BOTH the OLD-style flat, unfiltered aggregate (which
# some WHOIS sources still emit) AND the proper per-record list whois_eras needs to tell the
# eras apart — the fix must read the records, never the flat aggregate.
_W = {
    "registrant_email": "owner@site-a.example",
    "registrant_name": "Real Owner",
    "registrant_org": None,
    "registrant_phone": "+15550100",
    "registrant_address": "123 Owner St",
    "created": "2025-09-09",
    "source": "rdap",
    "history": {
        "registrant_emails": ["owner@site-a.example", "prior-owner@example.net"],
        "registrant_phones": ["+15550100", "+15550199"],
        "registrant_addresses": ["123 Owner St", "999 Prior Rd"],
        "records": [
            {"created": "2025-09-09", "email": "owner@site-a.example", "phone": "+15550100",
             "address": "123 Owner St", "name": "Real Owner"},
            {"created": "2016-04-06", "email": "prior-owner@example.net", "phone": "+15550199",
             "address": "999 Prior Rd", "name": "Prior Owner"},
        ],
        "mode": "purchase",
    },
}


def _old_buggy_registrant_vals(w, hist, field):
    """The deleted pre-fix implementation, re-created here ONLY to prove the bug it had —
    never restored in wp_analyze.py itself."""
    vals = []
    cur = w.get(f"registrant_{field}")
    if cur:
        vals.append(cur)
    for v in hist.get(f"registrant_{field}s") or []:
        if v not in vals:
            vals.append(v)
    return vals


def test_old_flat_aggregate_would_have_leaked_the_prior_owner():
    # Documents the bug: reading the flat, unfiltered aggregate pulls the previous (uninvolved)
    # owner's email in alongside the current owner's.
    hist = _W["history"]
    old_emails = _old_buggy_registrant_vals(_W, hist, "email")
    assert "prior-owner@example.net" in old_emails, old_emails


def test_wp_analyze_pivots_only_current_era_contacts():
    saved = WA.whois_enrich.whois_summary_keyless
    WA.whois_enrich.whois_summary_keyless = lambda host: dict(_W)
    try:
        result = {"meta": {"host": "site-a.example"}, "pivots": []}
        WA.whois_enrich_result(result, do_reverse=False, free_only=True)
    finally:
        WA.whois_enrich.whois_summary_keyless = saved

    by_kind = {}
    for p in result["pivots"]:
        by_kind.setdefault(p["kind"], []).append(p["value"])

    emails = by_kind.get("whois:registrant_email", [])
    phones = by_kind.get("whois:registrant_phone", [])
    addresses = by_kind.get("whois:registrant_address", [])

    assert "owner@site-a.example" in emails, emails
    assert "prior-owner@example.net" not in emails, emails
    assert "+15550100" in phones, phones
    assert "+15550199" not in phones, phones
    assert "123 Owner St" in addresses, addresses
    assert "999 Prior Rd" not in addresses, addresses


_TESTS = [test_old_flat_aggregate_would_have_leaked_the_prior_owner,
          test_wp_analyze_pivots_only_current_era_contacts]


def check():
    passed = failed = 0
    lines = []
    for test in _TESTS:
        label = test.__name__.removeprefix("test_").replace("_", " ")
        try:
            test()
        except Exception as exc:  # noqa: BLE001
            failed += 1
            lines.append(("FAIL", f"{label}: {exc}"))
        else:
            passed += 1
            lines.append(("ok", label))
    return passed, failed, lines


if __name__ == "__main__":
    _passed, _failed, _lines = check()
    for _status, _label in _lines:
        print(("ok" if _status == "ok" else "FAIL") + "  " + _label)
    raise SystemExit(bool(_failed))
