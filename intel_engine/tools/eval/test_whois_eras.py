#!/usr/bin/env python3
"""Gate for whois_eras.py (WHOIS ownership eras) end-to-end — the drop-caught-domain case-run defect where a
domain's flat WHOIS-history aggregate mixed every previous owner into the current one: a drop-caught
apex's 2017/2018 registrants became `registered_by` edges, frontier seeds and metered reverse-WHOIS
leads alongside the 2025 owner, and three subdomains of one apex each bought their own WHOIS.

Defends (pre-fix, each of these reproduced the bug; post-fix none do):
  1. whois_eras.owner_values()/prior_values() on a synthetic drop-caught history (2017 owner A,
     2018 drop-catch placeholder, 2025 owner B) — owner_values returns ONLY B; prior_values returns
     A + the placeholder as facts, never as owner values.
  2. ingest_webpivot: `registered_by` edges land ONLY on B (email + person); A/placeholder become
     `previous_registrant_email`/`previous_registrant_name` FACTS, never edges — even when a stray
     pre-fix pivot still names A (ingest never reads pivots for this, only `wh`, so it cannot leak).
  3. case_state: enrichment leads (email-deep) and metered leads (reverse-WHOIS) are built ONLY for
     B, even when the raw file carries a STALE `whois:registrant_email` pivot for A left over from
     a pre-fix collection — the owner_values() membership gate rejects it.
  4. whois_current(): three subdomains of one apex resolve to the apex and hit the network ONCE
     (wp_casememo per-case memo) — not once per subdomain.

Deterministic, no network (the HTTP seam `_get_json` is stubbed). Run standalone or via run_eval.py.
"""
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

import whois_eras as we_eras   # noqa: E402
import whois_enrich as we      # noqa: E402
import ingest_webpivot as IW   # noqa: E402
from knowledge_base import KB  # noqa: E402
import case_state as CS        # noqa: E402


def _synthetic_whois():
    """A drop-caught apex's WHOIS block in the shape whois_summary()/pivot_extract writes:
    the CURRENT owner (B, 2025) plus a full unfiltered history — 2017 owner A, a 2018 drop-catch
    placeholder (no name), then B again."""
    return {
        "registrant_email": "owner-b@example.com", "registrant_name": "Owner B",
        "registrant_phone": "+18005550202", "registrar": "R3", "created": "2025-09-09",
        "history": {
            "registrant_emails": ["owner-b@example.com"],
            "registrant_names": ["Owner B"],
            "registrant_phones": ["+18005550202"],
            "prior_registrants": [
                {"created": "2018-09-03", "email": "placeholder@example.com", "name": None,
                 "phone": None, "registrar": "R2"},
                {"created": "2017-06-20", "email": "owner-a@example.com", "name": "Owner A",
                 "phone": "+18005550101", "registrar": "R1"},
            ],
            "records": [
                {"email": "owner-a@example.com", "name": "Owner A", "phone": "+18005550101",
                 "registrar": "R1", "created": "2017-06-20"},
                {"email": "placeholder@example.com", "name": None, "phone": None,
                 "registrar": "R2", "created": "2018-09-03"},
                {"email": "owner-b@example.com", "name": "Owner B", "phone": "+18005550202",
                 "registrar": "R3", "created": "2025-09-09"},
            ],
        },
    }


def check():
    out, passed, failed = [], 0, 0

    def ok(cond, label):
        nonlocal passed, failed
        passed, failed = (passed + 1, failed) if cond else (passed, failed + 1)
        out.append(("ok" if cond else "FAIL", label))

    wh = _synthetic_whois()

    # --- 1. whois_eras contract: owner_values / prior_values -----------------------------------
    ok(we_eras.owner_values(wh, "email") == ["owner-b@example.com"],
       "owner_values(email): current owner (B) only, no 2017/2018 mix-in")
    ok(we_eras.owner_values(wh, "name") == ["Owner B"], "owner_values(name): current owner only")
    ok(we_eras.owner_values(wh, "phone") == ["+18005550202"], "owner_values(phone): current owner only")
    prior_emails = {p["value"] for p in we_eras.prior_values(wh, "email")}
    ok(prior_emails == {"owner-a@example.com", "placeholder@example.com"},
       "prior_values(email): both previous eras, as facts")
    ok(all(p["value"] != "owner-b@example.com" for p in we_eras.prior_values(wh, "email")),
       "prior_values(email) never repeats the current owner")

    # --- 2. ingest_webpivot: edges only to B, facts for A/placeholder ---------------------------
    with tempfile.TemporaryDirectory() as tmp:
        import json
        raw = {"meta": {"host": "estate-a.example"}, "artifacts": {"whois": wh}, "pivots": []}
        p = os.path.join(tmp, "estate-a.example.json")
        json.dump(raw, open(p, "w", encoding="utf-8"))
        kb = KB(os.path.join(tmp, "kb"))
        IW.ingest_file(kb, p)
        reg_edges = [e for e in kb._edges if e["rel"] == "registered_by"]
        targets = {(e["dst_type"], e["dst"]) for e in reg_edges}
        ok(("email", "owner-b@example.com") in targets, "registered_by edge to current owner's email")
        ok(("person", "Owner B") in targets, "registered_by edge to current owner's name")
        ok(("email", "owner-a@example.com") not in targets,
           "NO registered_by edge to the 2017 previous owner's email")
        ok(("person", "Owner A") not in targets,
           "NO registered_by edge to the 2017 previous owner's name")
        ok(("phone", "18005550101") not in targets,
           "NO registered_by edge to the 2017 previous owner's phone")
        facts = kb.entity("domain", "estate-a.example")["facts"]
        prev_email_vals = {f["value"] for f in facts if f["attribute"] == "previous_registrant_email"}
        ok(any("owner-a@example.com" in v for v in prev_email_vals),
           "previous owner's email recorded as a FACT (previous_registrant_email)")
        ok(any("placeholder@example.com" in v for v in prev_email_vals),
           "drop-catch placeholder email also recorded as a FACT, never an edge")

    # --- 3. case_state: leads never mine a prior-era identity, even from a stale pivot ---------
    obj = {"meta": {"host": "estate-a.example"},
           "artifacts": {"whois": wh, "socials": {}},
           "pivots": [{"kind": "whois:registrant_email", "value": "owner-a@example.com"},
                      {"kind": "whois:registrant_email", "value": "owner-b@example.com"}]}
    enr = {}
    CS._enrichment_leads_from_raw(obj, enr)
    keys = set(enr.keys())
    ok(("email-deep", "owner-b@example.com") in keys, "email-deep lead built for the current owner")
    ok(("email-deep", "owner-a@example.com") not in keys,
       "NO email-deep lead for the 2017 owner, even though a stale pivot still names them")

    metered = {}
    CS._metered_leads_from_raw(obj, metered)
    mkeys = set(metered.keys())
    ok(("WhoisXML", "reverse_email=owner-b@example.com") in mkeys,
       "metered reverse-WHOIS lead offered for the current owner")
    ok(("WhoisXML", "reverse_email=owner-a@example.com") not in mkeys,
       "NO metered reverse-WHOIS lead for the 2017 owner, even from a stale pivot")

    # --- 4. whois_current(): subdomain -> apex, ONE network call for three hosts ----------------
    calls = []

    def fake_get_json(url, params, timeout=30):
        calls.append(params.get("domainName"))
        return {"WhoisRecord": {
            "registrantContact": {"email": "owner-b@example.com", "name": "Owner B"},
            "registrarName": "R3", "createdDateNormalized": "2025-09-09",
        }}

    _key0, _get0 = we._key, we._get_json
    try:
        we._key = lambda: "FAKEKEY"
        we._get_json = fake_get_json
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["WP_CASE_DIR"] = tmp
            r1 = we.whois_current("api.estate-a-apex.example")
            r2 = we.whois_current("wss.estate-a-apex.example")
            r3 = we.whois_current("uo.estate-a-apex.example")
            ok(len(calls) == 1, f"ONE network call for three subdomains of one apex (got {len(calls)})")
            ok(r1["domain"] == "estate-a-apex.example" == r2["domain"] == r3["domain"],
               "result 'domain' is the apex for every subdomain")
            ok({r1["queried_host"], r2["queried_host"], r3["queried_host"]}
               == {"api.estate-a-apex.example", "wss.estate-a-apex.example", "uo.estate-a-apex.example"},
               "'queried_host' preserves the literal subdomain queried, per call")
    finally:
        we._key, we._get_json = _key0, _get0
        os.environ.pop("WP_CASE_DIR", None)

    return passed, failed, out


if __name__ == "__main__":
    p, f, lines = check()
    for status, label in lines:
        print(f"  [{status:4s}] {label}")
    print(f"\n{p} passed, {f} failed")
    sys.exit(1 if f else 0)
