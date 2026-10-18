#!/usr/bin/env python3
"""Offline unit gate for case_state.propose() — typed cross-type proposer.

Synthetic case (TemporaryDirectory; ROOT + HARNESS_KB pointed at temp) where a raw file
carries a wallet + GTM tracker + filename indicator `invoice.zip` + a co-hosted IP over
MAX_IP_COHOSTS. Asserts:

  * wallet / GTM produce typed candidates with the correct rung (owner)
  * invoice.zip never appears as a domain candidate (filename routes only)
  * co-tenant hold appears with est_hits > auto_max
  * state.json `pivoted` ids are excluded
  * an extra candidate with an unknown route is dropped
  * ranking is deterministic
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import types

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.dirname(HERE)
ENGINE = os.path.dirname(TOOLS)
sys.path.insert(0, TOOLS)
sys.path.insert(0, os.path.join(TOOLS, "kb"))

import case_state as CS  # noqa: E402
import selector_types as ST  # noqa: E402
from knowledge_base import KB  # noqa: E402


# Stable synthetic values (RFC 5737 / example.com / CASE-0001 family only).
SEED = "seed.example"
WALLET = "0x" + "11" * 20
GTM = "GTM-TEST"
FILENAME = "invoice.zip"
SHARED_IP = "203.0.113.50"


def _install_pivot_routes_stub():
    """Inject pivot_routes into sys.modules so propose() never needs phase-3 live code. Returns a
    restore() that puts back whatever was there: run_eval imports every unit module into ONE process,
    so a stub left installed made test_pivot_routes import this fake instead of the real module."""
    prev = sys.modules.get("pivot_routes")
    mod = types.ModuleType("pivot_routes")

    def query_for(route, type_, selector):
        routes = (ST.load_pivot_map().get("routes") or {})
        spec = routes.get(route) or {}
        if type_ not in (spec.get("types") or []):
            return None
        return str(selector)

    def count(route, query, *, free_only=False):
        # Deterministic fake counts so ranking/est_hits stay stable offline.
        # GTM string probes return a small free count; wallets a medium one; filename large.
        q = str(query or "")
        if q == GTM:
            return 3
        if q == WALLET:
            return 7
        if q == FILENAME:
            return 40
        return 1

    def run(route, query, *, case=None, free_only=False, hostile=False):
        return {"rows": [], "total": count(route, query, free_only=free_only)}

    mod.query_for = query_for
    mod.count = count
    mod.run = run
    sys.modules["pivot_routes"] = mod

    def restore():
        if prev is None:
            sys.modules.pop("pivot_routes", None)
        else:
            sys.modules["pivot_routes"] = prev
    return restore


def _raw_seed():
    """Raw pivot_extract-shaped JSON: wallet + GTM + filename + shared-IP cohost over max."""
    n = CS.MAX_IP_COHOSTS + 5
    many = {
        "query": f'ip="{SHARED_IP}"',
        "total": n,
        "results": [
            {"host": f"t{i}.example", "ip": SHARED_IP, "domain": f"t{i}.example"}
            for i in range(n)
        ],
    }
    return {
        "meta": {"host": SEED},
        "artifacts": {
            "trackers": {"google_tag_manager": [GTM]},
            "crypto": {"eth": [WALLET]},
            # filename as an artifact list some collectors emit; KB is the proposer source of truth
            "filenames": [FILENAME],
        },
        "pivots": [
            {"kind": "domain", "value": SEED,
             "live_results": {"fofa_ip_reverse": many}},
            {"kind": "filename", "value": FILENAME},
            {"kind": "wallet:eth", "value": WALLET},
            {"kind": "tracker:google_tag_manager", "value": GTM},
        ],
    }


def _seed_kb(kb_path, host=SEED):
    """Link wallet + GTM + filename indicators to the seed host the way ingest_webpivot does."""
    kb = KB(kb_path)
    observed = "2024-01-01T00:00:00+00:00"
    # wallet
    wind = f"wallet:eth:{WALLET}"
    kb.add_edge("domain", host, "uses_wallet", "indicator", wind,
                "webpivot", "test", observed, "high")
    kb.add_fact("indicator", wind, "kind", "wallet_eth",
                "webpivot", "test", observed, "high")
    # GTM
    gind = f"google_tag_manager:{GTM}"
    kb.add_edge("domain", host, "uses_analytics", "indicator", gind,
                "webpivot", "test", observed, "high")
    kb.add_fact("indicator", gind, "kind", "google_tag_manager",
                "webpivot", "test", observed, "high")
    # filename — must stay typed; never a domain
    find = f"filename:{FILENAME}"
    kb.add_edge("domain", host, "uses_file", "indicator", find,
                "webpivot", "test", observed, "medium")
    kb.add_fact("indicator", find, "kind", "filename",
                "webpivot", "test", observed, "medium")
    return kb


def _build_case(tmp):
    cdir = os.path.join(tmp, "cases", "CASE-0001")
    os.makedirs(os.path.join(cdir, "raw"), exist_ok=True)
    with open(os.path.join(cdir, "raw", f"{SEED}.json"), "w", encoding="utf-8") as fh:
        json.dump(_raw_seed(), fh)
    kb_path = os.path.join(tmp, "knowledge")
    os.makedirs(kb_path, exist_ok=True)
    _seed_kb(kb_path)
    st = CS.load_state(cdir)
    st["hops"] = {SEED: 0}
    st["expansion_depth"] = 2
    CS.save_state(cdir, st)
    return cdir, kb_path


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

    restore_pivot_routes = _install_pivot_routes_stub()
    auto_max = ST.auto_max_hits()

    saved_root = CS.ROOT
    saved_kb = CS.KB_DIR
    saved_benign = list(CS._BENIGN)
    try:
        with tempfile.TemporaryDirectory() as tmp:
            CS.ROOT = tmp
            CS.KB_DIR = os.path.join(tmp, "knowledge")
            CS._BENIGN = []  # force reload against empty/temp reference
            os.environ["HARNESS_KB"] = CS.KB_DIR

            cdir, kb_path = _build_case(tmp)
            ok(os.path.isdir(kb_path), "temp KB created")

            cands = CS.propose(cdir, probe=True)
            ok(isinstance(cands, list) and cands, "propose() returns a non-empty list")
            # deterministic across two calls
            cands2 = CS.propose(cdir, probe=True)
            ids1 = [c.id for c in cands]
            ids2 = [c.id for c in cands2]
            ok(ids1 == ids2, "ranking is deterministic (id order stable across calls)")
            ok(all(ids1[i] <= ids1[i] for i in range(len(ids1))), "id list well-formed")

            # --- wallet typed candidates, owner rung ---------------------------------
            wallet_c = [c for c in cands if c.type == "wallet" and c.selector == WALLET]
            ok(bool(wallet_c), "wallet produces typed candidate(s)")
            ok(all(c.rung == "owner" for c in wallet_c),
               "wallet candidates carry owner rung")
            ok(all(c.tool in ST.routes_for("wallet") for c in wallet_c),
               "wallet candidates use wallet-accepting routes")

            # --- GTM typed candidates (string), owner rung via analytics.gtm ----------
            gtm_c = [c for c in cands if c.selector == GTM]
            ok(bool(gtm_c), "GTM tracker produces typed candidate(s)")
            ok(all(c.type == "string" for c in gtm_c), "GTM classified as string")
            ok(all(c.rung == "owner" for c in gtm_c),
               "GTM candidates carry owner rung (analytics.gtm)")

            # --- filename: routes yes, domain candidate never -------------------------
            fn_c = [c for c in cands if c.selector == FILENAME]
            ok(bool(fn_c), "invoice.zip produces filename candidate(s)")
            ok(all(c.type == "filename" for c in fn_c),
               "invoice.zip candidates are type=filename")
            ok(not any(c.type == "domain" and c.selector == FILENAME for c in cands),
               "invoice.zip never appears as a domain candidate")
            ok(not any(c.type == "domain" and "invoice" in (c.selector or "") for c in cands),
               "no domain candidate contains 'invoice'")

            # --- co-tenant hold with est_hits > auto_max ------------------------------
            holds = [c for c in cands
                     if c.type == "domain"
                     and any(str(s).startswith("co_tenancy:") for s in (c.sources or ()))]
            ok(bool(holds), "co-tenancy hold surfaced as domain candidate(s)")
            ok(all(isinstance(c.est_hits, int) and c.est_hits > auto_max for c in holds),
               f"co-tenant hold est_hits > auto_max ({auto_max})")
            ok(all(c.rung == "neighbour" for c in holds),
               "co-tenant holds carry neighbour rung")

            # --- pivoted ids excluded -------------------------------------------------
            victim = cands[0]
            CS.mark_pivoted(cdir, [victim.id])
            after = CS.propose(cdir, probe=True)
            ok(victim.id not in {c.id for c in after},
               "pivoted candidate id is excluded on next propose()")
            st = CS.load_state(cdir)
            ok(victim.id in (st.get("pivoted") or []),
               "mark_pivoted persisted id into state.json")

            # --- unknown route extra dropped ------------------------------------------
            bogus = ST.Candidate(
                id="deadbeef01", type="string", selector="nope",
                tool="not.a.real.route", query="nope",
                metered=False, est_hits=None, rung="kit",
                origins=(), sources=("test",), why="bogus", by="test",
            )
            with_extra = CS.propose(cdir, extra=(bogus,), probe=True)
            ok(all(c.tool != "not.a.real.route" for c in with_extra),
               "extra candidate with unknown route is dropped")

            # known-route extra accepted
            route = (ST.routes_for("string") or ["urlscan.identifier"])[0]
            good = ST.Candidate(
                id=ST.candidate_id("string", "custom-token", route, "custom-token"),
                type="string", selector="custom-token", tool=route, query="custom-token",
                metered=False, est_hits=None, rung="kit",
                origins=(), sources=("planner",), why="planner", by="extra",
            )
            with_good = CS.propose(cdir, extra=(good,), probe=True)
            ok(any(c.selector == "custom-token" and c.tool == route for c in with_good),
               "extra candidate with accepting route is kept")

            # filename forced as domain extra is refused
            bad_fn = ST.Candidate(
                id="badfn00001", type="domain", selector=FILENAME,
                tool="collect", query=FILENAME,
                metered=False, est_hits=None, rung="owner",
                origins=(), sources=("evil",), why="bad", by="test",
            )
            with_bad = CS.propose(cdir, extra=(bad_fn,), probe=True)
            ok(not any(c.type == "domain" and c.selector == FILENAME for c in with_bad),
               "extra casting invoice.zip as domain is refused")

    finally:
        CS.ROOT = saved_root
        CS.KB_DIR = saved_kb
        CS._BENIGN = saved_benign
        os.environ.pop("HARNESS_KB", None)
        restore_pivot_routes()

    return passed, failed, out


if __name__ == "__main__":
    p, f, lines = check()
    for s, l in lines:
        print(f"  {'ok ' if s == 'ok' else '✗  '} {l}")
    sys.exit(1 if f else 0)
