#!/usr/bin/env python3
"""Gate for whois_current()'s RDAP-embedded-vCard registrant recovery — the false "no shared
identity" defect where a VN-reseller record ships an EMPTY registrantContact/registrant block
AND an empty "Registrant Name:/.../Email:" text block, but embeds the registrar's own RDAP JSON
verbatim in `rawText` (top-level and/or `registryData.rawText`). That RDAP object's `entities[]`
carries a "registrant"-rolled vCard (`vcardArray`) with the real name/org/email/phone — the ONLY
place the registrant exists for those records. Pre-fix, whois_current() never looked at it and
registrant_name/email/phone/org all came out null even though the record IS attributable.

Defends (pre-fix, each of these reproduced the bug; post-fix none do):
  1. Empty structured contacts + a `rawText` that is RDAP JSON with a "registrant" vCard:
     registrant_name/org/email/phone/country recovered from the vCard.
  2. A `rawText` whose only entities are registrar/abuse (no "registrant" role anywhere, including
     nested `entities[]`): registrant fields stay empty — a registrar/abuse contact must never be
     read as the registrant (SKILL.md RULE 5).
  3. A registrant vCard whose fields are all privacy-proxy placeholders ('REDACTED FOR PRIVACY',
     'Data Protected'): treated as privacy — no owner email (or name/org) surfaces.
  4. Malformed/non-JSON `rawText`: whois_current() never raises; registrant fields stay empty.
  5. A record WITH a populated structured registrantContact: the RDAP-vCard fallback is never
     consulted — the structured contact always wins.

Deterministic, no network (the HTTP seam `_get_json` is stubbed). Run standalone or via
run_eval.py.
"""
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WP = os.path.join(ROOT, "WebPivot", "tools")
if WP not in sys.path:
    sys.path.insert(0, WP)

import whois_enrich as we  # noqa: E402


def _run_current(fake_response, domain="rdap-vcard.example"):
    """Call whois_current() with `_get_json` stubbed to return `fake_response` for the
    current-WHOIS endpoint, isolated in a throwaway case dir (so wp_casememo never persists
    across scenarios in this file)."""
    _key0, _get0 = we._key, we._get_json
    try:
        we._key = lambda: "FAKEKEY"
        we._get_json = lambda url, params, timeout=30: fake_response
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["WP_CASE_DIR"] = tmp
            return we.whois_current(domain)
    finally:
        we._key, we._get_json = _key0, _get0
        os.environ.pop("WP_CASE_DIR", None)


def _rdap_registrant_rec(fn="Nguyen Van A", org="Some Trading Co Ltd", email="owner@example.com",
                         tel="tel:+84.28.1234567", cc="VN", extra_roles=("administrative",
                                                                          "technical")):
    """A WhoisXML WhoisRecord shaped exactly like the VN-reseller observed shape: EMPTY structured
    registrantContact, but `rawText` holding the registrar's raw RDAP JSON with a
    "registrant"-rolled entity vCard."""
    vcard = ["vcard", [
        ["version", {}, "text", "4.0"],
        ["fn", {}, "text", fn],
        ["org", {"type": "work"}, "text", org],
        ["adr", {"cc": cc}, "text", ["", "", "1 Fake Street", "Hanoi", "", "10000", ""]],
        ["email", {}, "text", email],
        ["tel", {"type": "voice"}, "uri", tel],
    ]]
    rdap = {
        "objectClassName": "domain",
        "entities": [
            {"roles": ["registrant"] + list(extra_roles), "vcardArray": vcard},
            {"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Fake Registrar"]]],
             "entities": [{"roles": ["abuse"],
                          "vcardArray": ["vcard", [["email", {}, "text", "abuse@registrar.example"]]]}]},
        ],
    }
    return {
        "WhoisRecord": {
            "registrantContact": {},
            "contactEmail": "abuse@registrar.example",
            "registrarName": "Fake Registrar",
            "createdDateNormalized": "2020-01-01",
            "rawText": json.dumps(rdap),
        }
    }


def check():
    out, passed, failed = [], 0, 0

    def ok(cond, label):
        nonlocal passed, failed
        passed, failed = (passed + 1, failed) if cond else (passed, failed + 1)
        out.append(("ok" if cond else "FAIL", label))

    # --- 1. empty structured contacts, rawText is RDAP JSON with a registrant vCard ------------
    r = _run_current(_rdap_registrant_rec())
    ok(r["registrant_name"] == "Nguyen Van A", "registrant_name recovered from the RDAP vCard")
    ok(r["registrant_org"] == "Some Trading Co Ltd",
       "registrant_org recovered from the RDAP vCard")
    ok(r["registrant_email"] == "owner@example.com",
       "registrant_email recovered from the RDAP vCard")
    ok(r["registrant_phone"] == "84281234567",
       "registrant_phone recovered from the RDAP vCard in WhoisXML's bare-digit shape (tel: scheme, "
       "'+' and dots dropped) — so the vCard and a history record yield ONE phone selector, not two")
    ok(r["registrant_country"] == "VN", "registrant_country recovered from the vCard adr.cc")
    ok(r["registrar_contact_email"] == "abuse@registrar.example",
       "registrar's own contactEmail still split off, never merged into the registrant")

    # --- 2. only registrar/abuse entities anywhere (no "registrant" role at all) ----------------
    registrar_only = {
        "WhoisRecord": {
            "registrantContact": {},
            "contactEmail": "abuse@registrar.example",
            "registrarName": "Fake Registrar",
            "rawText": json.dumps({
                "entities": [
                    {"roles": ["registrar"],
                     "vcardArray": ["vcard", [["fn", {}, "text", "Fake Registrar"]]],
                     "entities": [{"roles": ["abuse"],
                                  "vcardArray": ["vcard",
                                                [["email", {}, "text", "abuse@registrar.example"]]]},
                                 {"roles": ["technical"],
                                  "vcardArray": ["vcard",
                                                [["fn", {}, "text", "Tech Contact"]]]}]},
                    # the VN-reseller shape: the reseller's OWN staff vCard (named person, mailbox,
                    # phone) sits beside the registrar — it is shared by every customer it resells
                    {"roles": ["reseller"],
                     "vcardArray": ["vcard", [["fn", {}, "text", "Reseller Staff"],
                                              ["email", {}, "text", "staff@reseller.example"],
                                              ["tel", {}, "uri", "tel:+84.2400000001"]]]},
                ],
            }),
        }
    }
    r2 = _run_current(registrar_only)
    ok(r2["registrant_name"] is None,
       "a registrar/abuse/technical-only RDAP entity tree never fills registrant_name")
    ok(r2["registrant_email"] is None,
       "a registrar/abuse/technical-only RDAP entity tree never fills registrant_email")
    ok(r2["registrant_org"] is None,
       "a registrar/abuse/technical-only RDAP entity tree never fills registrant_org")
    ok(r2["registrant_phone"] is None,
       "a RESELLER entity's staff phone never becomes registrant_phone (it binds every customer)")

    # --- 3. registrant vCard whose fields are all privacy-proxy placeholders -------------------
    privacy = _rdap_registrant_rec(fn="REDACTED FOR PRIVACY", org="Data Protected",
                                   email="REDACTED FOR PRIVACY", tel="tel:+000000000")
    r3 = _run_current(privacy)
    ok(r3["registrant_email"] is None,
       "a privacy-placeholder vCard email never surfaces as registrant_email")
    ok(r3["registrant_name"] is None,
       "a privacy-placeholder vCard name never surfaces as registrant_name")
    ok(r3["registrant_org"] is None,
       "a privacy-placeholder vCard org never surfaces as registrant_org")
    ok(r3["registrant_phone"] is None,
       "an all-zero placeholder tel never surfaces as registrant_phone — as a decisive join key it "
       "would bind every placeholder-proxied domain into one 'operator'")

    # --- 3b. RFC 3966 extension parameter -------------------------------------------------------
    r3b = _run_current(_rdap_registrant_rec(tel="tel:+84-28-1234567;ext=12"))
    ok(r3b["registrant_phone"] == "84281234567x12",
       "a `;ext=` tel parameter is read as the extension, never glued onto the number's digits")

    # --- 4. malformed rawText must never raise --------------------------------------------------
    malformed = {
        "WhoisRecord": {
            "registrantContact": {},
            "contactEmail": None,
            "registrarName": "Fake Registrar",
            "rawText": "{not valid json at all::",
        }
    }
    try:
        r4 = _run_current(malformed)
        ok(r4["registrant_name"] is None and r4["registrant_email"] is None,
           "malformed rawText: registrant fields stay empty, no exception")
    except Exception as e:  # noqa: BLE001
        ok(False, f"malformed rawText must never raise (raised {e!r})")

    # --- 4b. nested adr street component (RFC 7095 multi-line street, as VN registrars emit) ----
    adr = we._vcard_get([["adr", {"cc": "VN"}, "text",
                          ["", "", ["", "", "1 Example Street"], "Example City", "", "10000", "VN"]]], "adr")
    ok(adr == "1 Example Street, Example City, 10000, VN",
       "a nested street list is flattened — never stored as a Python list repr ('['', '', …]')")

    # --- 5. a populated structured registrantContact must never be overridden by the vCard -----
    structured = _rdap_registrant_rec()
    structured["WhoisRecord"]["registrantContact"] = {
        "email": "real-owner@example.com", "name": "Real Owner",
    }
    r5 = _run_current(structured)
    ok(r5["registrant_email"] == "real-owner@example.com",
       "structured registrantContact wins over the RDAP vCard fallback")
    ok(r5["registrant_name"] == "Real Owner",
       "structured registrantContact name wins over the RDAP vCard fallback")

    return passed, failed, out


if __name__ == "__main__":
    p, f, lines = check()
    for status, label in lines:
        print(f"[{status}] {label}")
    print(f"\n{p} passed, {f} failed")
    sys.exit(1 if f else 0)
