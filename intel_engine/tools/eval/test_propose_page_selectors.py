#!/usr/bin/env python3
"""Offline regression gate: propose() on a page that lists many phone numbers.

A phone-directory page yields hundreds of page-scraped `page.phone` nodes. propose() used to size
every one with a vendor count probe (a WhoisXML reverse-WHOIS preview + a urlscan count each)
before ranking, and offered reverse-WHOIS on strangers' numbers. Synthetic temp case: ~200
page.phone nodes, one whois.registrant_phone node, a collected raw for example.com. Asserts:

  * no rwhois.purchase candidate exists for a page.phone node
  * the registrant phone still gets an rwhois.purchase candidate (probed)
  * count probes are bounded by page_selector_cap + the owner items, not ~200 × routes
  * kit phone candidates are capped; the owner-rung registrant survives the cap
  * probe=False sends no probe at all
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.dirname(HERE)
sys.path.insert(0, TOOLS)
sys.path.insert(0, os.path.join(TOOLS, "kb"))

import case_state as CS  # noqa: E402
import selector_types as ST  # noqa: E402

HOST = "example.com"
N_PAGE = 200
# NANP fictional range 555-0100..0199 (RFC-style test numbers), two area codes for 200 values.
PAGE_PHONES = [f"+1 {200 + i // 100} 555 {100 + i % 100:04d}" for i in range(N_PAGE)]
REG_PHONE = "+1 202 555 0142"


def _build_case(tmp):
    cdir = os.path.join(tmp, "cases", "CASE-0001")
    os.makedirs(os.path.join(cdir, "raw"), exist_ok=True)
    with open(os.path.join(cdir, "raw", f"{HOST}.json"), "w", encoding="utf-8") as fh:
        json.dump({"meta": {"host": HOST}, "artifacts": {}, "pivots": []}, fh)
    os.makedirs(os.path.join(tmp, "knowledge"), exist_ok=True)   # empty KB: nodes are the source
    st = CS.load_state(cdir)
    st["hops"] = {HOST: 0}
    st["expansion_depth"] = 2
    nodes = st.setdefault("nodes", {})
    for ph in PAGE_PHONES:
        nodes[CS._node_key("phone", ph)] = {
            "type": "phone", "selector": ph, "rung_class": "page.phone",
            "rung_classes": ["page.phone"], "hop": 1, "origins": [f"domain:{HOST}"],
            "route": "quarry.page"}
    nodes[CS._node_key("phone", REG_PHONE)] = {
        "type": "phone", "selector": REG_PHONE, "rung_class": "whois.registrant_phone",
        "rung_classes": ["whois.registrant_phone"], "hop": 1, "origins": [f"domain:{HOST}"],
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

    # The REAL pivot_routes (another unit module may have left a stub in sys.modules).
    prev_mod = sys.modules.pop("pivot_routes", None)
    import pivot_routes as PR  # noqa: E402
    import wp_recon as WR  # noqa: E402
    import wp_wayback_search as WS  # noqa: E402

    calls = {"count": 0, "rwhois": [], "urlscan": 0, "wayback": 0}
    saved = (PR.count, PR._rwhois_preview_count, WR.urlscan_count, WS.count)
    real_count = PR.count

    def counting_count(route, query, *, free_only=False):
        calls["count"] += 1
        return real_count(route, query, free_only=free_only)

    def fake_rwhois(term):
        calls["rwhois"].append(term)
        return 3

    def fake_urlscan(query, timeout=30, free_only=False):
        calls["urlscan"] += 1
        return 0

    def fake_wayback(q, collection, timeout=None):
        calls["wayback"] += 1
        return 0

    saved_root, saved_kb, saved_benign = CS.ROOT, CS.KB_DIR, list(CS._BENIGN)
    saved_env = os.environ.get("HARNESS_KB")
    try:
        PR.count = counting_count
        PR._rwhois_preview_count = fake_rwhois
        WR.urlscan_count = fake_urlscan
        WS.count = fake_wayback
        sys.modules["pivot_routes"] = PR
        with tempfile.TemporaryDirectory() as tmp:
            CS.ROOT = tmp
            CS.KB_DIR = os.path.join(tmp, "knowledge")
            CS._BENIGN = []
            os.environ["HARNESS_KB"] = CS.KB_DIR
            cdir = _build_case(tmp)
            cap = ST.page_selector_cap()
            phone_routes = ST.routes_for("phone")

            cands = CS.propose(cdir, probe=True)
            page = set(PAGE_PHONES)
            rw_page = [c for c in cands if c.tool == "rwhois.purchase" and c.selector in page]
            ok(not rw_page, "no rwhois.purchase candidate for a page.phone node")
            rw_reg = [c for c in cands if c.tool == "rwhois.purchase" and c.selector == REG_PHONE]
            ok(len(rw_reg) == 1 and rw_reg[0].rung == "owner",
               "the registrant phone keeps its owner-rung rwhois.purchase candidate")
            ok(bool(rw_reg) and rw_reg[0].est_hits == 3,
               "the registrant rwhois candidate was sized by the preview probe")
            ok(calls["rwhois"] == [REG_PHONE],
               f"reverse-WHOIS preview sent only for the registrant ({len(calls['rwhois'])} call(s))")
            owner_items = len([c for c in cands if c.selector == REG_PHONE])
            ok(owner_items == len(phone_routes),
               f"every phone route survives the cap for the registrant ({owner_items})")
            ok(calls["count"] <= cap + owner_items,
               f"count probes bounded: {calls['count']} <= cap {cap} + {owner_items} owner item(s)")
            ok(calls["urlscan"] + calls["wayback"] <= cap + owner_items,
               f"urlscan/wayback probes bounded ({calls['urlscan']} + {calls['wayback']})")
            kit_phone = [c for c in cands if c.type == "phone" and c.rung != "owner"]
            ok(len(kit_phone) == cap,
               f"kit phone candidates capped at page_selector_cap ({len(kit_phone)} == {cap})")

            for k in calls:
                calls[k] = [] if k == "rwhois" else 0
            CS.propose(cdir, probe=False)
            ok(calls["count"] == 0 and not calls["rwhois"],
               "probe=False sends no count probe")
    finally:
        PR.count, PR._rwhois_preview_count, WR.urlscan_count, WS.count = saved
        CS.ROOT, CS.KB_DIR, CS._BENIGN = saved_root, saved_kb, saved_benign
        if saved_env is None:
            os.environ.pop("HARNESS_KB", None)
        else:
            os.environ["HARNESS_KB"] = saved_env
        if prev_mod is None:
            sys.modules["pivot_routes"] = PR
        else:
            sys.modules["pivot_routes"] = prev_mod

    return passed, failed, out


if __name__ == "__main__":
    p, f, lines = check()
    for s, l in lines:
        print(f"  {'ok ' if s == 'ok' else '✗  '} {l}")
    sys.exit(1 if f else 0)
