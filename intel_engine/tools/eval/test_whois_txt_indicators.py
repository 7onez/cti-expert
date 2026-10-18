#!/usr/bin/env python3
"""Gate for the WHOIS / TXT owner indicators and registrar-boilerplate filters (case lessons:
a Google-Domains-style privacy proxy hid one customer id across an estate; a provider-wide TXT
verification value would have clustered every tenant; a registrar NIC-staff mailbox and the RDDS
notice text were offered as registrant terms).

Defends:
  1. whois_privacy_customer — 'Contact Privacy Inc. Customer <digits>' is parsed out of WHOIS
     history records (whois_history) and the live record; two domains sharing the id get an edge
     to ONE `whois_privacy_customer:<id>` indicator (shared_indicators links them), the proxy NAME
     itself never becomes a registered_by edge, and a prior-era id is a fact only.
  2. txt_verification — a token found in the provider's own zone is a provider constant and is
     NOT emitted (no edge, no fact); a token absent from a resolved provider zone is an owner edge;
     a token with no checkable provider zone is a lead fact, never an edge.
  3. Registrar boilerplate — a NIC-staff role mailbox and the literal RDDS notice never become
     registrant terms (is_noise_email / is_noise_phone / whois_enrich.is_privacy / ingest).
  4. rungs.json: whois.privacy_customer and txt.verification resolve to owner.

Deterministic, synthetic data, no network (HTTP + DNS seams stubbed). Run standalone or via run_eval.py.
"""
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WP = os.path.join(ROOT, "WebPivot", "tools")
KB_TOOLS = os.path.join(ROOT, "tools", "kb")
TOOLS = os.path.join(ROOT, "tools")
for _p in (WP, KB_TOOLS, TOOLS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import whois_eras as WE         # noqa: E402
import whois_enrich as WEN      # noqa: E402
import wp_recon                 # noqa: E402
import noise_filters as NF      # noqa: E402
import ingest_webpivot as IW    # noqa: E402
import selector_types as ST     # noqa: E402
from knowledge_base import KB   # noqa: E402

CID = "1234567890"
PROXY = f"Contact Privacy Inc. Customer {CID}"
NOTICE = ("Please query the RDDS service of the Registrar of Record identified in this output for "
          "information on how to contact the Registrant, Admin, or Tech contact of the queried domain name.")
TOK_OWNER = "0f1e2d3c-4b5a-4968-8776-655443322110"
TOK_CONST = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
TOK_UNCHECKED = "0123456789abcdef0123456789abcdef"


def _whois(created, records, **live):
    w = {"created": created, "registrar": "Registrar Example", "history": {"records": records}}
    w.update(live)
    return w


def _ingest(tmp, kb, host, artifacts):
    p = os.path.join(tmp, f"{host}.json")
    with open(p, "w", encoding="utf-8") as fh:
        json.dump({"meta": {"host": host}, "artifacts": artifacts, "pivots": []}, fh)
    IW.ingest_file(kb, p)


def check():
    out, passed, failed = [], 0, 0

    def ok(cond, label):
        nonlocal passed, failed
        passed, failed = (passed + 1, failed) if cond else (passed, failed + 1)
        out.append(("ok" if cond else "FAIL", label))

    # --- 1a. extraction ------------------------------------------------------------------------
    ok(WE.privacy_customer_ids(PROXY) == [CID], "customer id parsed from 'Contact Privacy Inc. Customer <digits>'")
    ok(WE.privacy_customer_ids("Contact Privacy Customer 7654321") == ["7654321"],
       "variant without 'Inc.' parsed")
    ok(WE.privacy_customer_ids("Redacted For Privacy", "Owner Example Ltd") == [],
       "no id from an ordinary privacy placeholder / org")

    # --- 1b. whois_history record build (HTTP seam stubbed) ------------------------------------
    def fake_get_json(url, params, timeout=30):
        return {"recordsCount": 1, "records": [{
            "registrantContact": {"name": "REDACTED FOR PRIVACY", "organization": PROXY,
                                  "email": "masked@privacy-proxy.example"},
            "registrarName": "Registrar Example", "createdDateNormalized": "2024-01-02"}]}

    _key0, _get0 = WEN._key, WEN._get_json
    try:
        WEN._key = lambda: "FAKEKEY"
        WEN._get_json = fake_get_json
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["WP_CASE_DIR"] = tmp
            hist = WEN.whois_history("alpha-estate.example", keep_raw=False) or {}
        recs = hist.get("records") or []
        ok(bool(recs) and recs[0].get("privacy_customer") == CID,
           "whois_history record carries privacy_customer from the organization field")
    finally:
        WEN._key, WEN._get_json = _key0, _get0
        os.environ.pop("WP_CASE_DIR", None)

    # --- 1c. two domains sharing the id link; proxy name never an edge; prior era = fact -------
    wa = _whois("2024-01-02", [{"name": PROXY, "registrar": "R", "created": "2024-01-02"}],
                registrant_name=PROXY)
    wb = _whois("2024-03-04", [
        {"name": "Contact Privacy Inc. Customer 5550001111", "registrar": "R", "created": "2019-05-06"},
        {"name": "REDACTED FOR PRIVACY", "privacy_customer": CID, "registrar": "R", "created": "2024-03-04"},
    ])
    ok(WE.owner_values(wa, "privacy_customer") == [CID], "owner_values(privacy_customer) from the live name")
    ok(WE.owner_values(wb, "privacy_customer") == [CID], "owner_values(privacy_customer): current era only")
    ok([p["value"] for p in WE.prior_values(wb, "privacy_customer")] == ["5550001111"],
       "prior-era customer id is a prior value, not an owner value")
    with tempfile.TemporaryDirectory() as tmp:
        kb = KB(os.path.join(tmp, "kb"))
        _ingest(tmp, kb, "alpha-estate.example", {"whois": wa})
        _ingest(tmp, kb, "beta-estate.example", {"whois": wb})
        ind = f"whois_privacy_customer:{CID}"
        linked = {e["src"] for e in kb._edges
                  if e["dst"] == ind and e["rel"] == "registered_via_privacy_customer"}
        ok(linked == {"alpha-estate.example", "beta-estate.example"},
           "both domains carry an edge to the shared whois_privacy_customer indicator")
        shared = [s for s in kb.shared_indicators() if s["indicator"] == ind]
        ok(bool(shared) and shared[0]["domain_count"] == 2,
           "shared_indicators links the two domains on the customer id (owner-link candidate)")
        ok(not any(e["rel"] == "registered_by" and "contact privacy" in str(e["dst"]).lower()
                   for e in kb._edges),
           "the proxy NAME never becomes a registered_by edge")
        ok(not any(e["dst"] == "whois_privacy_customer:5550001111" for e in kb._edges),
           "the prior-era customer id is never an edge")
        facts = kb.entity("domain", "beta-estate.example")["facts"]
        ok(any(f["attribute"] == "previous_privacy_customer" and "5550001111" in f["value"] for f in facts),
           "the prior-era customer id is recorded as a fact")
        ind_facts = kb.entity("indicator", ind)["facts"]
        ok(any(f["attribute"] == "population_caveat" for f in ind_facts),
           "the customer-id indicator carries the unmeasurable-population caveat")

    # --- 2. TXT verification: provider-constant never emitted ---------------------------------
    zones = {"spacemail.com": [f"spacemail-verification={TOK_CONST}", "v=spf1 -all"]}

    def fake_lookup(name):
        return zones.get(name, [])

    records = [f"spacemail-verification={TOK_CONST}",
               f"spacemail-verification={TOK_OWNER}",
               f"unknownvendor-verify={TOK_UNCHECKED}",
               "v=spf1 include:_spf.example.net -all"]
    got = {r["token"]: r["check"] for r in wp_recon.classify_txt_verifications(records, (), lookup=fake_lookup)}
    ok(got.get(TOK_CONST) == "provider_constant", "token present in the provider zone → provider_constant")
    ok(got.get(TOK_OWNER) == "owner", "token absent from a resolved provider zone → owner")
    ok(got.get(TOK_UNCHECKED) == "unchecked", "token with no known provider zone → unchecked")
    ok(len(got) == 3, "SPF record never yields a verification token")
    via_mx = wp_recon.classify_txt_verifications([f"verify={TOK_OWNER}"], ["mx1.spacemail.com"],
                                                 lookup=fake_lookup)
    ok(via_mx and via_mx[0]["check"] == "owner", "provider zone resolved from the MX host")
    dead = wp_recon.classify_txt_verifications([f"spacemail-verification={TOK_OWNER}"], (),
                                               lookup=lambda _n: [])
    ok(dead and dead[0]["check"] == "unchecked", "unresolvable provider zone → unchecked, never owner")
    with tempfile.TemporaryDirectory() as tmp:
        kb = KB(os.path.join(tmp, "kb"))
        mail = {"txt_verifications": wp_recon.classify_txt_verifications(records, (), lookup=fake_lookup)}
        _ingest(tmp, kb, "gamma-estate.example", {"mail": mail})
        dsts = {e["dst"] for e in kb._edges if e["rel"] == "uses_txt_verification"}
        ok(dsts == {f"txt_verification:{TOK_OWNER}"}, "only the owner-checked token becomes an edge")
        ok(not any(TOK_CONST in str(e["dst"]) for e in kb._edges),
           "provider-constant token is NOT emitted as an edge")
        facts = kb.entity("domain", "gamma-estate.example")["facts"]
        ok(not any(TOK_CONST in str(f["value"]) for f in facts),
           "provider-constant token is not emitted as a fact either")
        ok(any(f["attribute"] == "txt_verification_lead" and f["value"] == TOK_UNCHECKED for f in facts),
           "unchecked token is a lead fact")
        ok(not any(TOK_UNCHECKED in str(e["dst"]) for e in kb._edges), "unchecked token is never an edge")

    # --- 3. registrar boilerplate never a registrant term -------------------------------------
    ok(NF.is_noise_email("nic-staff@isp-registrar.example"), "NIC-staff role mailbox is noise on any domain")
    ok(NF.is_noise_email(NOTICE), "RDDS notice text in the email slot is noise")
    ok(NF.is_noise_phone(NOTICE), "RDDS notice text in the phone slot is noise")
    ok(NF.is_whois_notice(NOTICE.upper()), "notice match is case-insensitive")
    ok(not NF.is_noise_email("owner@operator.example"), "an ordinary registrant email is kept")
    ok(not NF.is_whois_notice("Owner Example Ltd"), "an ordinary registrant name is not a notice")
    ok(WEN.is_privacy("nic-staff@isp-registrar.example"), "is_privacy refuses the NIC-staff mailbox (no reverse-WHOIS)")
    ok(WEN.is_privacy(NOTICE), "is_privacy refuses the RDDS notice (no reverse-WHOIS)")
    with tempfile.TemporaryDirectory() as tmp:
        kb = KB(os.path.join(tmp, "kb"))
        wn = _whois("2024-05-06", [{"email": "nic-staff@isp-registrar.example", "name": NOTICE,
                                    "phone": NOTICE, "registrar": "R", "created": "2024-05-06"}],
                    registrant_email=NOTICE, registrant_name=NOTICE)
        _ingest(tmp, kb, "delta-estate.example", {"whois": wn})
        reg = [e for e in kb._edges if e["rel"] == "registered_by"]
        ok(not reg, f"no registered_by edge from NIC-staff mailbox / notice text (got {[e['dst'] for e in reg]})")
        facts = kb.entity("domain", "delta-estate.example")["facts"]
        ok(not any("rdds service" in str(f["value"]).lower() for f in facts),
           "the notice text is not recorded as a registrant fact either")

    # --- 4. rungs ------------------------------------------------------------------------------
    ok(ST.rung_for("whois.privacy_customer") == "owner", "rungs: whois.privacy_customer → owner")
    ok(ST.rung_for("txt.verification") == "owner", "rungs: txt.verification → owner")
    ok(ST._RUNGS_FALLBACK["rungs"].get("whois.privacy_customer") == "kit"
       and ST._RUNGS_FALLBACK["rungs"].get("txt.verification") == "kit",
       "rungs fallback keeps both new classes at kit (conservative)")

    return passed, failed, out


if __name__ == "__main__":
    p, f, lines = check()
    for status, label in lines:
        print(f"  [{status:4s}] {label}")
    print(f"\n{p} passed, {f} failed")
    sys.exit(1 if f else 0)
