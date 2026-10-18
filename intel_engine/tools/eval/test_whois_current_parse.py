#!/usr/bin/env python3
"""Gate for whois_current()'s registrant parsing — the drop-caught-domain case-run defect where
whois_current fell back to WhoisXML's top-level `contactEmail` (the REGISTRAR's abuse/role
mailbox, e.g. "Registrar Abuse Contact Email: abuse-contact@registrar.example") as if it were the registrant,
while a thin/text-only record's real "Registrant Name/.../Email:" lines in the raw text went
unread (registrant_name/org/phone came out null even though the full block was in `rawText`).

Defends (pre-fix, each of these reproduced the bug; post-fix none do):
  1. An empty `registrantContact` + a populated `rawText` block: whois_current() parses the
     registrant fields (name/org/phone/email/country/address) OUT of the text, and NEVER reads
     `contactEmail` as the registrant — it lands only in `registrar_contact_email`.
  2. A registrar/abuse mailbox that the text-parser happens to pick up as the only "Email:" line
     (a registrar-authored thin record) is still filtered by is_privacy() and never becomes
     registrant_email.
  3. A normal record WITH a populated registrantContact is unaffected: contactEmail is still split
     off as registrar_contact_email, never merged into the registrant.

Deterministic, no network (the HTTP seam `_get_json` is stubbed). Run standalone or via
run_eval.py.
"""
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WP = os.path.join(ROOT, "WebPivot", "tools")
if WP not in sys.path:
    sys.path.insert(0, WP)

import whois_enrich as we  # noqa: E402


def _run_current(fake_response):
    """Call whois_current() with `_get_json` stubbed to return `fake_response` for the
    current-WHOIS endpoint, isolated in a throwaway case dir (so wp_casememo never persists
    across scenarios in this file)."""
    _key0, _get0 = we._key, we._get_json
    try:
        we._key = lambda: "FAKEKEY"
        we._get_json = lambda url, params, timeout=30: fake_response
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["WP_CASE_DIR"] = tmp
            return we.whois_current("thin-record.example")
    finally:
        we._key, we._get_json = _key0, _get0
        os.environ.pop("WP_CASE_DIR", None)


def check():
    out, passed, failed = [], 0, 0

    def ok(cond, label):
        nonlocal passed, failed
        passed, failed = (passed + 1, failed) if cond else (passed, failed + 1)
        out.append(("ok" if cond else "FAIL", label))

    # --- 1+2. empty registrantContact, contactEmail is the registrar's abuse mailbox, real
    # registrant lives only in the raw text -------------------------------------------------
    thin = {
        "WhoisRecord": {
            "registrantContact": {},
            "contactEmail": "abuse@registrar.example",
            "registrarName": "Fake Registrar",
            "createdDateNormalized": "2020-01-01",
            "rawText": (
                "Domain Name: THIN-RECORD.EXAMPLE\n"
                "Registrar: Fake Registrar\n"
                "Registrant Name: John Doe\n"
                "Registrant Organization: Some Corp\n"
                "Registrant Street: 123 Main St\n"
                "Registrant City: Springfield\n"
                "Registrant Country: US\n"
                "Registrant Phone: +1.5551234567\n"
                "Registrant Email: owner@example.com\n"
                "Registrar Abuse Contact Email: abuse@registrar.example\n"
            ),
        }
    }
    r = _run_current(thin)
    ok(r["registrant_email"] == "owner@example.com",
       "registrant_email recovered from the raw-text 'Registrant Email:' line")
    ok(r["registrar_contact_email"] == "abuse@registrar.example",
       "registrar's own contactEmail is split off as registrar_contact_email")
    ok(r["registrant_email"] != r["registrar_contact_email"],
       "registrant_email is NEVER the registrar's abuse/role mailbox")
    ok(r["registrant_name"] == "John Doe", "registrant_name parsed from text")
    ok(r["registrant_org"] == "Some Corp", "registrant_org parsed from text")
    ok(r["registrant_phone"] == "+1.5551234567", "registrant_phone parsed from text")
    ok(r["registrant_address"] and "123 Main St" in r["registrant_address"],
       "registrant_address assembled from the parsed street/city")

    # --- 3. a registrar-authored thin record whose ONLY "Email:" line in the text is itself a
    # role mailbox (no distinct registrant line at all) must never surface as registrant_email --
    role_only = {
        "WhoisRecord": {
            "registrantContact": {},
            "contactEmail": "abuse@registrar.example",
            "registrarName": "Fake Registrar",
            "rawText": "Registrant Email: abuse@registrar.example\n",
        }
    }
    r2 = _run_current(role_only)
    ok(r2["registrant_email"] is None,
       "a role/abuse mailbox parsed AS the registrant line is still filtered (is_privacy)")
    ok(r2["registrar_contact_email"] == "abuse@registrar.example",
       "registrar_contact_email is preserved regardless")

    # --- 4. a normal record with a populated registrantContact is unaffected -------------------
    normal = {
        "WhoisRecord": {
            "registrantContact": {"email": "real-owner@example.com", "name": "Real Owner"},
            "contactEmail": "abuse@registrar.example",
            "registrarName": "Fake Registrar",
        }
    }
    r3 = _run_current(normal)
    ok(r3["registrant_email"] == "real-owner@example.com",
       "structured registrantContact still wins when present")
    ok(r3["registrar_contact_email"] == "abuse@registrar.example",
       "registrar_contact_email split off even when registrantContact is populated")

    return passed, failed, out


if __name__ == "__main__":
    p, f, lines = check()
    for status, label in lines:
        print(f"  [{status:4s}] {label}")
    print(f"\n{p} passed, {f} failed")
    sys.exit(1 if f else 0)
