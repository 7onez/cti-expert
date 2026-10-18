#!/usr/bin/env python3
"""Offline regression gate: previous-owner-era registrant contacts go to analyst approval.

Analyst-confirmed era rule: a registrant e-mail/phone whose WHOIS observation date predates the
domain's CURRENT registration creation date belongs to a previous owner. It must not be seeded as a
normal pivot and must not be silently dropped — propose() surfaces it as an approval-required item
tagged `previous_owner_era` with both dates in its reason, and an analyst rejection is permanent.

Synthetic temp case (example.com, created 2013-12-05) with a WHOIS history holding:
  * a 2011 record (previous owner) — e-mail + phone
  * a 2015 record of the current registration — a different e-mail (dated after creation)
  * an undated record — must stay unaffected
plus a stale state node that still carries the 2011 e-mail as a registrant (pre-fix ingest).
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.dirname(HERE)
ENGINE = os.path.dirname(TOOLS)
sys.path.insert(0, TOOLS)
sys.path.insert(0, os.path.join(TOOLS, "kb"))
sys.path.insert(0, os.path.join(ENGINE, "WebPivot", "tools"))
sys.path.insert(0, os.path.join(ENGINE, "harness"))

import case_state as CS  # noqa: E402
import proposal as P  # noqa: E402
import whois_eras as WE  # noqa: E402

CASE = "CASE-0001"
HOST = "example.com"
CREATED = "2013-12-05"
PREV_EMAIL = "prev-owner@example.net"
PREV_PHONE = "+1.2025550101"
CUR_EMAIL = "owner@example.com"
LATE_EMAIL = "later-contact@example.org"
UNDATED_EMAIL = "undated@example.org"

WHOIS = {
    "registrant_email": CUR_EMAIL,
    "created": f"{CREATED} 13:19:26 UTC",
    "history": {"records": [
        {"created": "2011-03-04 00:00:00 UTC", "updated": "2011-06-01 00:00:00 UTC",
         "email": PREV_EMAIL, "phone": PREV_PHONE, "registrar": "Example Registrar A"},
        {"created": f"{CREATED} 13:19:26 UTC", "updated": "2015-01-10 00:00:00 UTC",
         "email": LATE_EMAIL, "registrar": "Example Registrar B"},
        {"email": UNDATED_EMAIL},
    ]},
}


def _build_case(tmp):
    cdir = os.path.join(tmp, "cases", CASE)
    os.makedirs(os.path.join(cdir, "raw"), exist_ok=True)
    with open(os.path.join(cdir, "raw", f"{HOST}.json"), "w", encoding="utf-8") as fh:
        json.dump({"meta": {"host": HOST}, "artifacts": {"whois": WHOIS}, "pivots": []}, fh)
    os.makedirs(os.path.join(tmp, "knowledge"), exist_ok=True)
    st = CS.load_state(cdir)
    st["hops"] = {HOST: 0}
    st["expansion_depth"] = 2
    # a stale pre-fix registrant node for the previous owner's e-mail: would be a normal seed
    st.setdefault("nodes", {})[CS._node_key("email", PREV_EMAIL)] = {
        "type": "email", "selector": PREV_EMAIL, "rung_class": "whois.registrant_email",
        "rung_classes": ["whois.registrant_email"], "hop": 1, "origins": [f"domain:{HOST}"],
        "route": "whois"}
    CS.save_state(cdir, st)
    return cdir


def check():
    out, passed, failed = [], 0, 0

    def ok(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1
            out.append(("ok", label))
        else:
            failed += 1
            out.append(("FAIL", label))

    # --- whois_eras: the decision itself ------------------------------------------------------
    got = WE.previous_owner_contacts(WHOIS) if hasattr(WE, "previous_owner_contacts") else []
    vals = {(c["kind"], c["value"].lower()): c for c in got}
    pe = vals.get(("email", PREV_EMAIL))
    ok(bool(pe) and pe["observed"] == "2011-06-01" and pe["current_created"] == CREATED,
       "2011 e-mail observed before the 2013-12-05 creation is a previous-owner contact")
    ok(("phone", PREV_PHONE.lower()) in vals, "2011 phone is a previous-owner contact")
    ok(("email", LATE_EMAIL) not in vals and ("email", CUR_EMAIL) not in vals,
       "contacts dated after creation are not flagged")
    ok(("email", UNDATED_EMAIL) not in vals, "a contact with no observation date is unaffected")

    # --- propose(): approval item, not a normal seed, not deleted ------------------------------
    prev_mod = sys.modules.get("pivot_routes")
    saved_root, saved_kb, saved_benign = CS.ROOT, CS.KB_DIR, list(CS._BENIGN)
    saved_env = os.environ.get("HARNESS_KB")
    try:
        with tempfile.TemporaryDirectory() as tmp:
            CS.ROOT = tmp
            CS.KB_DIR = os.path.join(tmp, "knowledge")
            CS._BENIGN = []
            os.environ["HARNESS_KB"] = CS.KB_DIR
            cdir = _build_case(tmp)

            cands = CS.propose(cdir, probe=False)
            on_prev = [c for c in cands if c.type == "email" and c.selector.lower() == PREV_EMAIL]
            flagged = [c for c in on_prev if "previous_owner_era" in (c.sources or ())]
            ok(len(flagged) == 1, f"one previous_owner_era item for the 2011 e-mail ({len(flagged)})")
            ok(len(on_prev) == len(flagged),
               "no normal (untagged) candidate for the 2011 e-mail — not a normal seed")
            f0 = flagged[0] if flagged else None
            ok(bool(f0) and "2011-06-01" in f0.why and CREATED in f0.why
               and "previous_owner_era" in f0.why,
               "the reason text carries both dates and the tag")
            ok(bool(f0) and f0.rung != "owner", "the previous-owner item is never owner rung")
            auto, needs, dropped = P.split(cands, no_spend=False, auto_max=10 ** 6)
            ok(bool(f0) and any(c.id == f0.id for c in needs)
               and not any(c.id == f0.id for c in auto + dropped),
               "proposal.split routes the previous_owner_era item to analyst approval")
            ph = [c for c in cands if c.type == "phone"
                  and "previous_owner_era" in (c.sources or ())]
            ok(len(ph) == 1, "the 2011 phone is surfaced as a previous_owner_era item")
            others = [c for c in cands if "previous_owner_era" in (c.sources or ())
                      and c.selector.lower() in (LATE_EMAIL, CUR_EMAIL, UNDATED_EMAIL)]
            ok(not others, "post-creation and undated contacts get no previous_owner_era item")
            capped = CS.propose(cdir, probe=False, max_per_type=0)
            ok(any("previous_owner_era" in (c.sources or ()) for c in capped),
               "a per-type cap never deletes a previous_owner_era item")

            # --- the analyst rejects it: the existing reject path keeps it rejected ---------------
            if f0:
                P.write(tmp, CASE, round_no=1, items=needs)
                res = P.approve(tmp, CASE, reject=[f0.id])
                ok(not res.get("error") and f0.id in (res.get("rejected") or []),
                   "proposal.approve records the rejection")
                CS.mark_pivoted(cdir, res.get("rejected") or [])   # orchestrator._run_approved
                again = CS.propose(cdir, probe=False)
                ok(not any(c.id == f0.id for c in again), "a rejected item is never re-proposed")
                ok(not any(c.type == "email" and c.selector.lower() == PREV_EMAIL for c in again),
                   "rejection does not resurrect the contact as a normal seed")
            else:
                ok(False, "proposal.approve records the rejection (no flagged item)")
    finally:
        CS.ROOT, CS.KB_DIR, CS._BENIGN = saved_root, saved_kb, saved_benign
        if saved_env is None:
            os.environ.pop("HARNESS_KB", None)
        else:
            os.environ["HARNESS_KB"] = saved_env
        if prev_mod is not None:
            sys.modules["pivot_routes"] = prev_mod

    return passed, failed, out


if __name__ == "__main__":
    p, f, lines = check()
    for s, l in lines:
        print(f"  {'ok ' if s == 'ok' else '✗  '} {l}")
    sys.exit(1 if f else 0)
