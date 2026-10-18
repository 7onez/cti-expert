#!/usr/bin/env python3
"""Offline regression gate: cross-type loop hygiene (lessons from a contact-directory case).

Synthetic temp case, synthetic KB, no network (pivot_routes.count stubbed). Asserts:

  * a Quarry page export with 100 page-scraped phones imports as 100 KB facts on the page and
    0 typed nodes, so propose() offers 0 phone pivots (owner-class registrant rows still nodes)
  * a candidate the Plan phase dropped (state.json `dropped`) is absent from the next propose()
    and from accept_extras(); reopen() clears the drop
  * a route whose credential is absent (publicwww.source without its key) is never offered, and
    anyrun.lookup is never offered for an ip selector (a hash still gets it)
  * the never-seed social platforms (twitter.com / x.com / linkedin.com / tiktok.com …) never
    become seeds — not via propose(extra=), not via a Quarry connection, not via seed_frontier —
    and a social-platform edge IP never seeds its co-tenants
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.dirname(HERE)
ENGINE = os.path.dirname(TOOLS)
for _p in (TOOLS, os.path.join(TOOLS, "kb"), os.path.join(ENGINE, "WebPivot", "tools")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import case_state as CS  # noqa: E402

HOST = "example.com"
# NANP fictional 555-0100..0199 — 100 distinct page-scraped numbers
PAGE_PHONES = [f"+1 202 555 {100 + i:04d}" for i in range(100)]
REG_EMAIL = "owner@example.com"
SOCIAL_IP = "198.51.100.7"          # RFC 5737 — stands in for a listed social-platform edge
PLAIN_IP = "198.51.100.8"
SOCIAL = ("twitter.com", "x.com", "facebook.com", "instagram.com", "linkedin.com",
          "tiktok.com", "youtube.com")


def _new_case(tmp, name):
    cdir = os.path.join(tmp, "cases", name)
    os.makedirs(os.path.join(cdir, "raw"), exist_ok=True)
    with open(os.path.join(cdir, "raw", f"{HOST}.json"), "w", encoding="utf-8") as fh:
        json.dump({"meta": {"host": HOST}, "artifacts": {}, "pivots": []}, fh)
    st = CS.load_state(cdir)
    st["hops"] = {HOST: 0}
    st["expansion_depth"] = 2
    CS.save_state(cdir, st)
    return cdir


def _add_node(cdir, type_, sel, rc, route="corpus"):
    st = CS.load_state(cdir)
    st["nodes"][CS._node_key(type_, sel)] = {
        "type": type_, "selector": sel, "rung_class": rc, "rung_classes": [rc], "hop": 1,
        "origins": [f"domain:{HOST}"], "route": route}
    CS.save_state(cdir, st)


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

    prev_mod = sys.modules.pop("pivot_routes", None)
    import pivot_routes as PR  # noqa: E402
    import quarry_bridge as QB  # noqa: E402
    import ingest_typed  # noqa: E402
    from knowledge_base import KB  # noqa: E402

    saved_pr = (PR.count, dict(PR._ROUTE_GATES))
    saved_qb_kb = QB._kb
    saved_cs = (CS.ROOT, CS.KB_DIR, list(CS._BENIGN), CS._is_social_ip)
    saved_env = os.environ.get("HARNESS_KB")
    try:
        PR.count = lambda route, query, *, free_only=False: 0        # no network, ever
        PR._ROUTE_GATES.update({
            "publicwww.source": lambda: False,                      # key absent
            "fofa.body": lambda: True, "webamon.corpus": lambda: True,
            "anyrun.lookup": lambda: True,
        })
        sys.modules["pivot_routes"] = PR
        with tempfile.TemporaryDirectory() as tmp:
            CS.ROOT = tmp
            CS.KB_DIR = os.path.join(tmp, "knowledge")
            CS._BENIGN = []
            os.environ["HARNESS_KB"] = CS.KB_DIR
            os.makedirs(CS.KB_DIR, exist_ok=True)
            kb = KB(CS.KB_DIR)
            QB._kb = lambda: (ingest_typed, kb)

            # ---- 1. page-scraped contacts are facts, not nodes ---------------------------------
            cdir = _new_case(tmp, "CASE-0001")
            groups, _notes = QB.build_row_groups({
                "export": {"content": {
                    "findings": {"phones": [{"value": p} for p in PAGE_PHONES]},
                    "whois": {"whois_history": [{"registrant": {"email": REG_EMAIL}}]}}},
                "connected": {"connections": []}}, target=HOST)
            page_rows = [r for g in groups for r in g["rows"] if r["rung_class"] == "page.phone"]
            ok(len(page_rows) == 100, f"the export carries 100 page.phone rows ({len(page_rows)})")
            imported = QB.import_groups(cdir, groups, target=HOST)
            nodes = CS.load_state(cdir).get("nodes") or {}
            phone_nodes = [n for n in nodes.values() if n.get("type") == "phone"]
            ok(not phone_nodes, f"0 page.phone nodes registered ({len(phone_nodes)})")
            ok(CS._node_key("email", REG_EMAIL) in nodes,
               "the registrant email (owner class, same route) is still a node")
            facts = [f for f in kb.entity("domain", HOST).get("facts") or []
                     if (f.get("value") or {}).get("rung_class") == "page.phone"]
            ok(len(facts) == 100, f"100 page.phone KB facts on the page ({len(facts)})")
            ok(not [e for e in kb.edges() if e.get("dst_type") == "phone" or e.get("src_type") == "phone"],
               "no phone edge was written")
            ok(imported.get("nodes_added") == 1, f"only the owner row became a node ({imported.get('nodes_added')})")
            cands = CS.propose(cdir, probe=False)
            ph = [c for c in cands if c.type == "phone"]
            ok(not ph, f"propose() offers 0 phone pivots ({len(ph)})")

            # ---- 2. Plan-phase drops persist ----------------------------------------------------
            cdir2 = _new_case(tmp, "CASE-0002")
            _add_node(cdir2, "string", "kit-token-example", "string")
            first = [c for c in CS.propose(cdir2, probe=False) if c.selector == "kit-token-example"]
            ok(len(first) >= 2, f"the string node yields candidates on several routes ({len(first)})")
            victim = first[0]
            ok(CS.mark_dropped(cdir2, [(victim.id, "planner: generic token")]) == 1,
               "mark_dropped records the drop")
            st = CS.load_state(cdir2)
            ok(st["dropped"].get(victim.id, {}).get("why") == "planner: generic token"
               and "round" in st["dropped"][victim.id], "state.json dropped = {id: {why, round}}")
            again = {c.id for c in CS.propose(cdir2, probe=False)}
            ok(victim.id not in again, "a dropped candidate id is absent from the next propose()")
            ok(any(c.id in again for c in first[1:]), "undropped siblings are still offered")
            extra = CS.accept_extras(cdir2, [{"type": victim.type, "selector": victim.selector,
                                              "tool": victim.tool, "query": victim.query}])
            ok(victim.id not in {c.id for c in extra}, "accept_extras() refuses a dropped id")
            CS.reopen(cdir2)
            ok(not CS.load_state(cdir2)["dropped"], "reopen() clears the dropped map")
            ok(victim.id in {c.id for c in CS.propose(cdir2, probe=False)},
               "a reopened case offers the once-dropped candidate again")

            # ---- 3. unrunnable routes are never offered -----------------------------------------
            tools = {c.tool for c in CS.propose(cdir2, probe=False) if c.selector == "kit-token-example"}
            ok("publicwww.source" not in tools, "publicwww.source without its key is not offered")
            ok("fofa.body" in tools, "a keyed source route (fofa.body) is still offered")
            ok(not PR.route_runnable("publicwww.source") and PR.route_runnable("urlscan.title"),
               "route_runnable: gated route false without a key, ungated route true")
            PR._ROUTE_GATES["webamon.corpus"] = lambda: (_ for _ in ()).throw(ImportError("x"))
            ok(not PR.route_runnable("webamon.corpus"), "a gate that cannot load answers not runnable")
            PR._ROUTE_GATES["webamon.corpus"] = lambda: True
            ext = CS.accept_extras(cdir2, [{"type": "string", "selector": "kit-token-example",
                                            "tool": "publicwww.source"}])
            ok(not ext, "accept_extras() refuses a planner addition on an unkeyed route")
            _add_node(cdir2, "ip", "203.0.113.50", "ip.cotenant")
            _add_node(cdir2, "hash", "a" * 64, "hash")
            cands = CS.propose(cdir2, probe=False)
            ok(not [c for c in cands if c.tool == "anyrun.lookup" and c.type == "ip"],
               "anyrun.lookup is never offered for an ip selector")
            ok([c for c in cands if c.tool == "anyrun.lookup" and c.type == "hash"],
               "anyrun.lookup is still offered for a hash")

            # ---- 4. never-seed social platforms -------------------------------------------------
            for apex in SOCIAL + ("api.twitter.com", "www.linkedin.com", "m.tiktok.com"):
                ok(CS.never_seed(CS._frontier_apex(apex)), f"never_seed({apex})")
            cands = CS.propose(cdir2, probe=False, extra=[
                {"type": "domain", "selector": s, "tool": "collect", "by": "planner"}
                for s in ("twitter.com", "www.linkedin.com", "tiktok.com")])
            ok(not [c for c in cands if c.type == "domain"
                    and CS._frontier_apex(c.selector) in SOCIAL],
               "propose(extra=…) never offers a social platform")
            g, _n = QB.build_row_groups({"export": {"content": {}}, "connected": {"connections": [
                {"domain": "twitter.com",
                 "shared": [{"kind": "registrant_email", "value": REG_EMAIL}]}]}}, target=HOST)
            ok(not [r for gg in g for r in gg["rows"] if r["value"] == "twitter.com"],
               "a Quarry connection to twitter.com is not even a row")
            ok(QB.seed_frontier(cdir2, ["twitter.com", "api.x.com", "site-b.example"]) == 1,
               "seed_frontier queues only the non-social peer")
            pend = CS.load_state(cdir2).get("pending") or []
            ok("twitter.com" not in pend and "api.x.com" not in pend, "twitter.com / x.com never pending")

            CS._is_social_ip = lambda ip: ip == SOCIAL_IP
            for ip, social in ((SOCIAL_IP, True), (PLAIN_IP, False)):
                fcands, deferred = {}, CS._new_deferred()
                CS._cohost_candidates({"ip": ip, "hosts": ["peer-a.example", "peer-b.example"]},
                                      fcands, {HOST}, deferred, HOST, "pdns_ip_reverse")
                if social:
                    lead = deferred["cohost"].get(ip) or {}
                    ok(not fcands and lead.get("never_seed"),
                       "a social-platform edge IP seeds no co-tenant and its lead is never_seed")
                    held = CS._domain_cands_from_frontier({"co_tenancy_leads": [lead]}, 25)
                    ok(not held, "a never_seed co-tenancy lead is not offered for approval either")
                else:
                    ok(bool(fcands), "control: a plain small-hosting IP still seeds its co-tenants")
            import noise_filters as NF
            ok(NF.is_social_platform_ip(str(NF.SOCIAL_PLATFORM_IP_RANGES[0].network_address))
               if NF.SOCIAL_PLATFORM_IP_RANGES else False,
               "noise_filters loads social_platform_ip_ranges from the reference")
            ok(not NF.is_social_platform_ip(PLAIN_IP), "a documentation IP is not a social edge")
    finally:
        PR.count = saved_pr[0]
        PR._ROUTE_GATES.clear()
        PR._ROUTE_GATES.update(saved_pr[1])
        QB._kb = saved_qb_kb
        CS.ROOT, CS.KB_DIR, CS._BENIGN, CS._is_social_ip = saved_cs
        if saved_env is None:
            os.environ.pop("HARNESS_KB", None)
        else:
            os.environ["HARNESS_KB"] = saved_env
        sys.modules["pivot_routes"] = prev_mod if prev_mod is not None else PR

    return passed, failed, out


if __name__ == "__main__":
    p, f, lines = check()
    for s, l in lines:
        print(f"  {'ok ' if s == 'ok' else '✗  '} {l}")
    print(f"{p} passed, {f} failed")
    sys.exit(1 if f else 0)
