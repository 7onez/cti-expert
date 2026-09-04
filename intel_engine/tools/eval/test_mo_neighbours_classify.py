#!/usr/bin/env python3
"""Offline unit gate for the MO-neighbour pivot (Phase A discover + Phase B classification).

The pivot names OTHER CUSTOMERS of the estate's provider (rung 10), so every rail that keeps that
from becoming false estate growth is asserted here: the raw discovery block never seeds the
frontier; only a join-key same_registrant does; the bulk-origin guard skips true bulk hosting
without a WHOIS call; a privacy registrant is never same_registrant/same_mo; WHOIS errors are
`unverifiable`, never `unrelated`; the KB ingester writes facts only. Synthetic data only
(RFC 5737 addresses, *.example / example.com names).
"""
import json
import os
import sys
import tempfile
import time

# Vendor clients ledger every (mocked) call via api_usage; a test must never write phantom credits
# into the real MEMORY/api_usage.jsonl (the Censys/urlscan monthly budgets are derived from it).
os.environ.setdefault("API_USAGE_LOG", os.path.join(tempfile.gettempdir(), "cti-tests-api_usage.jsonl"))

_HERE = os.path.dirname(os.path.abspath(__file__))
_ENGINE = os.path.dirname(os.path.dirname(_HERE))
for _p in (os.path.join(_ENGINE, "tools"), os.path.join(_ENGINE, "tools", "kb"),
           os.path.join(_ENGINE, "WebPivot", "tools")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import case_state as CS  # noqa: E402
import wp_mo_neighbours as MO  # noqa: E402
import ingest_mo_neighbours as IMO  # noqa: E402
from knowledge_base import KB  # noqa: E402

ORIGIN = "198.51.100.7"
BULK = "203.0.113.9"
ESTATE_WHOIS = {"registrant_email": "opsmail2024@example.com", "registrant_phone": "+84.912345678",
                "registrar": "Example Registrar LLC", "created": "2025-03-10 00:00:00 UTC"}


def _whois(email, created="2025-04-01", registrar="Example Registrar LLC", phone=None, error=None):
    if error:
        return {"error": error}
    return {"registrant_email": email, "registrant_phone": phone, "registrar": registrar,
            "created": created, "registrant_name": "Person"}


def _cand(apex, whois, sources=("netlas",)):
    return {"apex": apex, "sources": list(sources), "whois": whois}


def _case(tmp, blocks, whois_sidecar=True):
    """Synthetic case: three estate hosts (one registrant), an mo_neighbours block per `blocks` item."""
    cdir = os.path.join(tmp, "CASE-0001")
    os.makedirs(os.path.join(cdir, "raw"))
    hosts = ["vaytien-fast.example", "vaytien-now.example", "vaytien-go.example"]
    if whois_sidecar:
        os.makedirs(os.path.join(cdir, "whois"))
    for i, h in enumerate(hosts):
        piv = {"kind": "domain", "value": h, "live_results": {}}
        if i < len(blocks) and blocks[i] is not None:
            piv["live_results"]["mo_neighbours"] = blocks[i]
        raw = {"meta": {"host": h}, "artifacts": {"whois": dict(ESTATE_WHOIS, domain=h)}, "pivots": [piv]}
        json.dump(raw, open(os.path.join(cdir, "raw", h + ".json"), "w"))
        if whois_sidecar:
            json.dump(dict(ESTATE_WHOIS, domain=h), open(os.path.join(cdir, "whois", h + ".json"), "w"))
    return cdir


def _block(origin=ORIGIN, cands=(), bulk=False, fan_out=None):
    return {"origin_ip": origin, "seed_apex": "vaytien-fast.example", "bulk_skipped": bulk,
            "fan_out": fan_out if fan_out is not None else (400 if bulk else 12 + len(cands)),
            "sources": {"netlas": 60}, "candidate_total": len(cands), "sample_apexes": [c["apex"] for c in cands][:8],
            "candidates": list(cands), "unverified": [], "whois_calls": len(cands), "whois_cap_hit": False,
            "note": ""}


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

    # --- 0. static registry guard -----------------------------------------------------------
    ok(all(k != "mo_neighbours" for k, _f, _l in CS._HOST_YIELDING_SOURCES),
       "mo_neighbours is NOT in _HOST_YIELDING_SOURCES (raw block never auto-seeds)")
    ok((MO.MAX_IP_COHOSTS, MO.BULK_IP_RESULTS) == (CS.MAX_IP_COHOSTS, CS.BULK_IP_RESULTS),
       "discover() thresholds are case_state's (no drift)")
    ok(MO.MAX_CANDIDATES == CS.MO_MAX_CANDIDATES, "candidate cap mirrors case_state.MO_MAX_CANDIDATES")

    # --- 1. H1 guard: an UNCLASSIFIED block yields ZERO frontier candidates --------------------
    cands = [_cand("vaytien-clone.example", _whois("opsmail2024@example.com")),      # would be same_registrant
             _cand("other-play.example", _whois("someone7781@example.org"))]
    raw = {"meta": {"host": "vaytien-fast.example"},
           "pivots": [{"kind": "domain", "value": "vaytien-fast.example",
                       "live_results": {"mo_neighbours": _block(cands=cands)}}]}
    mined, deferred = {}, CS._new_deferred()
    CS._free_candidates_from_raw(raw, mined, {"vaytien-fast.example"}, deferred)
    ok(not mined, "unclassified mo_neighbours block in a raw file -> zero frontier candidates")

    # --- 2. classification -------------------------------------------------------------------
    cands = [
        _cand("vaytien-clone.example", _whois("opsmail2024@example.com")),                 # (a) exact email
        _cand("vaytien-phone.example", _whois("owner@example.net", phone="+84.912345678")),  # phone join key
        _cand("vaytien-proxyph.example", _whois("privacy@example-proxy.net", phone="+84.912345678")),  # PROXY phone: no join
        _cand("vaytien-mo.example", _whois("khoan5521@example.org", created="2025-04-20")),  # (b) same_mo: token+handle
        _cand("credit-mo.example", _whois("lan9931@example.org", created="2025-02-01")),     # (b') same_mo: handle only
        _cand("vaytien-old.example", _whois("ngoc4412@example.org", created="2024-06-01")),  # (c) outside window
        _cand("vaytien-priv.example", _whois("redacted for privacy", created="2025-04-01")),  # (d) privacy registrant
        _cand("broken.example", _whois(None, error="timeout")),                                # (e) unverifiable
        _cand("vaytien-fast.example", _whois("opsmail2024@example.com")),                       # (f) seed's own apex
        _cand("shoes-shop.example", _whois("shop@shoes-shop.example", registrar="Other Registrar", created="2025-04-01")),  # unrelated
    ]
    with tempfile.TemporaryDirectory() as tmp:
        cdir = _case(tmp, [_block(cands=cands), None, _block(origin=BULK, bulk=True, cands=[])])
        blk = CS.mo_neighbour_classification(cdir)
        sr = {r["apex"]: r for r in blk["same_registrant"]}
        ok(set(sr) == {"vaytien-clone.example", "vaytien-phone.example"},
           f"same_registrant = exact e-mail OR phone join key only ({sorted(sr)})")
        ok(sr["vaytien-clone.example"]["join_key"] == "registrant_email"
           and sr["vaytien-phone.example"]["join_key"] == "registrant_phone", "join_key names the matching field")
        ok("vaytien-proxyph.example" not in sr, "a privacy-proxied record's phone is NEVER a join key (RULE 5)")
        personas = {p["persona"]: p for p in blk["related_personas"]}
        ok(set(personas) == {"khoan5521@example.org", "lan9931@example.org"},
           f"same_mo personas = same registrar + in-window + (token or handle) ({sorted(personas)})")
        ok(any("naming token" in s for s in personas["khoan5521@example.org"]["signals"]),
           "token overlap recorded as a signal")
        ok(all(p["rung"] == 10 and "rung 10" in p["caveat"] for p in blk["related_personas"]),
           "every persona row carries the rung-10 caveat")
        ok("vaytien-old.example" in blk["unrelated_sample"], "200d outside window -> unrelated")
        ok("vaytien-priv.example" in blk["unrelated_sample"]
           and "redacted for privacy" not in personas, "privacy registrant never same_registrant/same_mo")
        ok(blk["unverifiable"] == ["broken.example"] and blk["unverifiable_count"] == 1,
           "WHOIS error -> unverifiable bucket, not unrelated")
        ok("vaytien-fast.example" not in sr and all(v["apex"] != "vaytien-fast.example" for v in blk["verified"]),
           "seed's own apex dropped")
        ok(blk["unrelated_count"] == 4 and "vaytien-proxyph.example" in blk["unrelated_sample"],
           f"unrelated counted, never enumerated by identity; proxied-phone row lands here ({blk['unrelated_count']})")
        ok(len(blk["bulk_origins"]) == 1 and blk["bulk_origins"][0]["origin_ip"] == BULK,
           "bulk-skipped origin surfaces as a bulk_origin lead, never classified")
        ok(blk["estate"]["context_source"] == "whois sidecar", "estate context read from the sidecar")
        # frontier: ONLY same_registrant seeds; same_mo/unrelated never
        json.dump(blk, open(os.path.join(cdir, "mo_neighbours.json"), "w"))
        fr = CS.frontier(cdir)
        ok(set(fr["pending"]) & {"vaytien-clone.example", "vaytien-phone.example"} == {"vaytien-clone.example", "vaytien-phone.example"},
           "classified same_registrant apexes seed the frontier")
        ok(not (set(fr["pending"]) & {"vaytien-mo.example", "credit-mo.example", "shoes-shop.example", "vaytien-old.example"}),
           "same_mo / unrelated NEVER seed the frontier")
        ok(all(v["sources"] == ["mo_neighbour_same_registrant"] for a, v in fr["candidates"].items()
               if a in ("vaytien-clone.example", "vaytien-phone.example")), "seed source label is mo_neighbour_same_registrant")

        # KB ingest: facts only, never an edge, never operator_lead
        kb = KB(os.path.join(tmp, "kb"))
        n = IMO.ingest(kb, blk)
        ok(n > 0, f"ingester wrote {n} facts")
        edges = os.path.join(kb.root, "relationships", "edges.jsonl")
        ok(not os.path.exists(edges) or not open(edges).read().strip(), "ingester wrote ZERO edges")
        ent = kb.entity("email", "khoan5521@example.org")
        attrs = {f["attribute"] for f in ent["facts"]}
        ok(attrs == {"co_tenant_observation"}, f"persona fact is co_tenant_observation only ({attrs})")
        dom = kb.entity("domain", "vaytien-mo.example")
        ok({f["attribute"] for f in dom["facts"]} == {"mo_neighbour_of", "mo_neighbour_class"}
           and not any("operator" in json.dumps(f) for f in dom["facts"]), "domain facts neutral; no operator_lead")
        src = open(IMO.__file__, encoding="utf-8").read()
        ok("add_edge(" not in src, "ingest_mo_neighbours source contains no add_edge call")

    # --- 2b. fresh case: no sidecar -> estate context from raw artifacts.whois ---------------
    with tempfile.TemporaryDirectory() as tmp:
        cdir = _case(tmp, [_block(cands=[_cand("vaytien-clone.example", _whois("opsmail2024@example.com"))])],
                     whois_sidecar=False)
        blk = CS.mo_neighbour_classification(cdir)
        ok(blk["estate"]["context_source"] == "raw artifacts.whois" and blk["estate"]["registrant_terms"] >= 1,
           "fresh case (no sidecar): estate registrants come from raw artifacts.whois")
        ok([r["apex"] for r in blk["same_registrant"]] == ["vaytien-clone.example"],
           "same_registrant matches on a fresh case within one cmd_open")

    # --- 2d. a PRIOR-era estate registrant (history) is a third party: never a join key ---------
    with tempfile.TemporaryDirectory() as tmp:
        cdir = _case(tmp, [_block(cands=[_cand("dropcatch-neighbour.example", _whois("previous-owner@example.org")),
                                          _cand("vaytien-clone.example", _whois("opsmail2024@example.com"))])])
        for h in ("vaytien-fast.example",):
            side = dict(ESTATE_WHOIS, domain=h, history={"registrant_emails": ["previous-owner@example.org"],
                                                          "registrant_phones": ["+1.5550001111"]})
            json.dump(side, open(os.path.join(cdir, "whois", h + ".json"), "w"))
        blk = CS.mo_neighbour_classification(cdir)
        ok([r["apex"] for r in blk["same_registrant"]] == ["vaytien-clone.example"],
           "estate join key = CURRENT registrants only; a prior-owner e-mail in history never matches")
        ok("dropcatch-neighbour.example" in blk["unrelated_sample"], "…the prior-owner co-tenant is unrelated")

    # --- 2e. classification policy is reference DATA (kb/references/mo_neighbours.json) ----------
    ok(CS._MO_REF is not CS._MO_FALLBACK and CS._MO_CLS is not CS._MO_FALLBACK["classification"],
       "case_state loaded mo_neighbours.json (not the fallback)")
    ok(CS.MO_WINDOW_DAYS >= CS._MO_FALLBACK["classification"]["window_days"]
       and set(CS._MO_STOP) >= set(CS._MO_FALLBACK["classification"]["stop_tokens"]),
       "fallback is the conservative minimum (narrower window, fewer stop tokens)")
    ok((MO.MAX_CANDIDATES, MO.WHOIS_RUN_CAP) == (CS.MO_MAX_CANDIDATES, CS.MO_WHOIS_RUN_CAP),
       "discover() candidate cap + run cap come from case_state (one source of truth)")
    # --- 2c. bulk registrant term guard on same_registrant seeding -----------------------------
    with tempfile.TemporaryDirectory() as tmp:
        cdir = _case(tmp, [])
        many = [{"apex": f"bulk{i}.example", "registrant": "reseller@example.com", "origin_ips": [ORIGIN], "sources": []}
                for i in range(CS.MAX_WHOIS_SIBLINGS + 3)]
        json.dump({"same_registrant": many, "related_personas": []}, open(os.path.join(cdir, "mo_neighbours.json"), "w"))
        fr = CS.frontier(cdir)
        ok(not any(a.startswith("bulk") for a in fr["pending"]), "> MAX_WHOIS_SIBLINGS same-registrant rows: not seeded")
        ok(any(l.get("source") == "mo_neighbour_same_registrant" for l in fr["co_tenancy_leads"]),
           "… surfaced as a bulk-registrant lead instead")

    # --- 3. discover(): bulk guard first, no WHOIS; memo; union/cap/drop-seed; never raises -----
    MO.reset_process_state()
    calls = []

    def fake_whois(apex, **kw):
        calls.append(apex)
        return {"registrant_email": f"{apex.split('.')[0]}@example.org", "registrar": "R", "created": "2025-01-01"}

    real_whois, real_cfg = MO.whois_enrich.whois_current, MO.whois_enrich.whois_configured
    MO.whois_enrich.whois_current = fake_whois
    MO.whois_enrich.whois_configured = lambda: True
    try:
        bulk_src = (("netlas", lambda ip: (1018, [f"t{i}.example" for i in range(50)], True)),)
        blk = MO.discover(BULK, "seed.example", sources=bulk_src)
        ok(blk["bulk_skipped"] is True and blk["candidates"] == [] and not calls,
           "true-bulk origin (fan-out > BULK_IP_RESULTS): skipped, no WHOIS calls")
        ok(blk["fan_out"] == 1018 and len(blk["sample_apexes"]) == 8, "bulk block keeps count + top-N sample")

        band_src = (("netlas", lambda ip: (87, [f"n{i}.example" for i in range(60)] + ["seed.example", "www.seed.example"], True)),
                    ("validin", lambda ip: (30, [f"n{i}.example" for i in range(20, 50)], False)),
                    ("urlscan", lambda ip: ("error: 429", [], False)))
        blk = MO.discover(ORIGIN, "seed.example", sources=band_src)
        ok(blk["bulk_skipped"] is False and blk["fan_out"] == 87, "12 < fan-out <= 120 band IS classified (not skipped)")
        ok(len(blk["candidates"]) == MO.MAX_CANDIDATES and len(blk["unverified"]) == 60 - MO.MAX_CANDIDATES,
           "union capped at MAX_CANDIDATES; rest listed unverified")
        # a source's total is a backstop ONLY when that source truncated: 500 urlscan SCANS over a
        # fully-returned 8-apex neighbourhood is not bulk hosting
        MO.reset_process_state()
        small_src = (("urlscan", lambda ip: (500, [f"s{i}.example" for i in range(8)], True)),)
        blk_s = MO.discover("192.0.2.5", "seed.example", sources=small_src)
        ok(blk_s["bulk_skipped"] is True and blk_s["fan_out"] == 500,
           "truncated source (total > rows returned): its total is the backstop -> bulk")
        MO.reset_process_state()
        full_src = (("urlscan", lambda ip: (8, [f"s{i}.example" for i in range(8)], False)),)
        blk_f = MO.discover("192.0.2.6", "seed.example", sources=full_src)
        ok(blk_f["bulk_skipped"] is False and blk_f["fan_out"] == 8, "fully-returned source: apex count decides, not total")
        MO.reset_process_state()
        blk = MO.discover(ORIGIN, "seed.example", sources=band_src)
        ok(all(c["apex"] != "seed.example" for c in blk["candidates"]) and "seed.example" not in blk["unverified"],
           "seed apex (and its subdomains) dropped from the union")
        ok(any(c["sources"] == ["netlas", "validin"] for c in blk["candidates"]), "per-apex source union recorded")
        ok(blk["sources"]["urlscan"].startswith("error"), "a failing index degrades to a note, never raises")
        n_calls = len(calls)
        blk2 = MO.discover(ORIGIN, "other-estate-host.example", sources=band_src)
        ok(len(calls) == n_calls and blk2["candidates"] == blk["candidates"],
           "per-origin memo: a second estate host on the same origin costs ZERO WHOIS calls")
        ok(all("_raw" not in c["whois"] and "raw" not in c["whois"] for c in blk["candidates"]),
           "candidate whois rows are slim (no raw payload)")

        # run cap
        MO.reset_process_state()
        MO._WHOIS_SPENT[0] = MO.WHOIS_RUN_CAP   # process-local cap path (no case dir)
        blk = MO.discover("192.0.2.77", "seed.example", sources=(("netlas", lambda ip: (5, ["a.example", "b.example"], False)),))
        ok(blk["whois_cap_hit"] and blk["candidates"] == [] and set(blk["unverified"]) == {"a.example", "b.example"},
           "WhoisXML run cap reached: candidates left unverified, flagged")

        # cross-round reuse of verified rows (errored rows are NOT reused)
        MO.reset_process_state()
        calls.clear()
        with tempfile.TemporaryDirectory() as tmp:
            cdir = os.path.join(tmp, "CASE-0001")
            os.makedirs(cdir)
            json.dump({"verified": [{"apex": "a.example", "whois": {"registrant_email": "prior@example.org"}},
                                    {"apex": "c.example", "whois": {"error": "timeout"}}]},
                      open(os.path.join(cdir, "mo_neighbours.json"), "w"))
            blk = MO.discover("192.0.2.78", "seed.example", case_dir=cdir,
                              sources=(("netlas", lambda ip: (5, ["a.example", "b.example", "c.example"], False)),))
            ok(sorted(calls) == ["b.example", "c.example"],
               "verified apex reused from mo_neighbours.json; an ERRORED prior row is re-verified")
            # cross-SUBPROCESS memo + ledger: a fresh process (reset) on the same case must not re-spend
            MO.reset_process_state()
            n_before = len(calls)
            blk_again = MO.discover("192.0.2.78", "seed.example", case_dir=cdir,
                                    sources=(("netlas", lambda ip: (99, ["zzz.example"], False)),))
            ok(len(calls) == n_before and blk_again.get("memo") == "case cache"
               and [c["apex"] for c in blk_again["candidates"]] == [c["apex"] for c in blk["candidates"]],
               "per-origin block cached on disk under the case: a new process costs ZERO WHOIS calls")
            ledger = os.path.join(cdir, MO.CACHE_SUBDIR, "whois_ledger.jsonl")
            ok(os.path.isfile(ledger) and sum(1 for _ in open(ledger)) == 2, "every WHOIS call is one ledger line on disk")
            MO.reset_process_state()
            ok(MO.spent(cdir) == 2, "run cap reads the on-disk ledger, not just the process counter")
            ok(next(c for c in blk["candidates"] if c["apex"] == "a.example")["whois"]["registrant_email"] == "prior@example.org",
               "reused row carries the prior verification")

        # per-RUN cap: lines from an earlier run do not count against this run
        with tempfile.TemporaryDirectory() as tmp:
            cdir = os.path.join(tmp, "CASE-0001")
            os.makedirs(os.path.join(cdir, MO.CACHE_SUBDIR))
            with open(os.path.join(cdir, MO.CACHE_SUBDIR, "whois_ledger.jsonl"), "w") as fh:
                for i in range(MO.WHOIS_RUN_CAP):
                    fh.write(json.dumps({"run": "old-run", "apex": f"o{i}.example"}) + "\n")
            os.environ[MO.RUN_ID_ENV] = "new-run"
            try:
                MO.reset_process_state()
                calls.clear()
                blk = MO.discover("192.0.2.80", "seed.example", case_dir=cdir,
                                  sources=(("netlas", lambda ip: (2, ["p.example", "q.example"], False)),))
                ok(sorted(calls) == ["p.example", "q.example"] and not blk["whois_cap_hit"],
                   "a full ledger from an EARLIER run does not exhaust this run's cap (per-run token)")
                ok(MO.spent(cdir) == 2, "spent() counts only the current run's lines")
            finally:
                os.environ.pop(MO.RUN_ID_ENV, None)

        # eight concurrent collector subprocesses: the origin lock makes ONE do the work
        with tempfile.TemporaryDirectory() as tmp:
            cdir = os.path.join(tmp, "CASE-0001")
            os.makedirs(os.path.join(cdir, MO.CACHE_SUBDIR))
            MO.reset_process_state()
            calls.clear()
            open(os.path.join(cdir, MO.CACHE_SUBDIR, "192.0.2.81.lock"), "w").write(str(os.getpid()))   # a LIVE sibling holds it
            t0 = time.time()
            blk = MO.discover("192.0.2.81", "seed.example", case_dir=cdir, sibling_wait_s=1,
                              sources=(("netlas", lambda ip: (2, ["p.example", "q.example"], False)),))
            ok(not calls and blk.get("memo") == "sibling in progress" and blk["candidates"] == [] and time.time() - t0 < 5,
               "origin held by a sibling: no vendor/WHOIS calls, bounded wait, placeholder block")
            ok("192.0.2.81" not in MO._MEMO, "placeholder is not memoised (the next call re-checks the cache)")
            # the sibling finishes: its cache is picked up without spending
            json.dump({"origin_ip": "192.0.2.81", "candidates": [{"apex": "p.example", "sources": ["netlas"], "whois": {}}],
                       "bulk_skipped": False, "unverified": []}, open(os.path.join(cdir, MO.CACHE_SUBDIR, "192.0.2.81.json"), "w"))
            blk = MO.discover("192.0.2.81", "seed.example", case_dir=cdir, sibling_wait_s=1,
                              sources=(("netlas", lambda ip: (2, ["p.example", "q.example"], False)),))
            ok(not calls and blk.get("memo") == "case cache" and blk["candidates"][0]["apex"] == "p.example",
               "sibling's finished block is reused from the case cache")
            os.remove(os.path.join(cdir, MO.CACHE_SUBDIR, "192.0.2.81.lock"))
            ok(not os.path.exists(os.path.join(cdir, MO.CACHE_SUBDIR, "192.0.2.82.lock")), "sanity")
            MO.reset_process_state()
            blk = MO.discover("192.0.2.82", "seed.example", case_dir=cdir,
                              sources=(("netlas", lambda ip: (1, ["r.example"], False)),))
            ok(not os.path.exists(os.path.join(cdir, MO.CACHE_SUBDIR, "192.0.2.82.lock"))
               and os.path.isfile(os.path.join(cdir, MO.CACHE_SUBDIR, "192.0.2.82.json")),
               "the winner releases its lock and leaves the block cached")
            # stale locks: a collector SIGKILLed on timeout leaves its lock behind — dead pid or old mtime
            import subprocess
            _p = subprocess.Popen(["true"]); _p.wait(); dead = _p.pid      # reaped -> os.kill(pid, 0) raises
            for label, pid_txt, age in (("dead pid", str(dead), 0), ("old mtime", str(os.getpid()), MO.STALE_LOCK_S + 60)):
                ip_s = "192.0.2.83"
                lk = os.path.join(cdir, MO.CACHE_SUBDIR, ip_s + ".lock")
                open(lk, "w").write(pid_txt)
                if age:
                    os.utime(lk, (time.time() - age, time.time() - age))
                MO.reset_process_state()
                calls.clear()
                blk = MO.discover(ip_s, "seed.example", case_dir=cdir, sibling_wait_s=1,
                                  sources=(("netlas", lambda ip: (1, ["s.example"], False)),))
                ok(calls == ["s.example"] and blk.get("memo") is None and not os.path.exists(lk),
                   f"stale lock ({label}) is broken and the origin IS verified; lock released after")
                for f in (lk, os.path.join(cdir, MO.CACHE_SUBDIR, ip_s + ".json")):
                    if os.path.exists(f):
                        os.remove(f)

        # netlas dedup vs truncation: many documents per host is NOT truncation
        MO.reset_process_state()
        real_search = MO.wp_netlas.search
        real_cfg_n = MO.wp_netlas.netlas_configured
        MO.wp_netlas.netlas_configured = lambda: True
        MO.wp_netlas.search = lambda coll, q, fields="*", max_results=200, timeout=45: {
            "query": q, "total": 24, "items": [{"domain": f"d{i % 6}.example"} for i in range(24)]}
        try:
            r = MO.wp_netlas.reverse_ip("192.0.2.90")
            ok(len(r["hosts"]) == 6 and r["truncated"] is False, "netlas: 24 docs over 6 hosts, all returned -> not truncated")
            MO.wp_netlas.search = lambda coll, q, fields="*", max_results=200, timeout=45: {
                "query": q, "total": 5000, "items": [{"domain": f"d{i}.example"} for i in range(400)]}
            r = MO.wp_netlas.reverse_ip("192.0.2.91")
            ok(r["truncated"] is True, "netlas: total beyond returned rows -> truncated")
        finally:
            MO.wp_netlas.search, MO.wp_netlas.netlas_configured = real_search, real_cfg_n

        MO.reset_process_state()
        blk = MO.discover(ORIGIN, "seed.example", classified={"cdn": True, "provider": "ExampleCDN"},
                          sources=(("netlas", lambda ip: (5, ["a.example"], False)),))
        ok(blk["candidates"] == [] and "CDN" in blk["note"], "a CDN edge origin is refused outright")
        blk = MO.discover("", "seed.example")
        ok(blk["candidates"] == [] and blk["note"] == "no origin IP", "empty origin -> empty block, no raise")
    finally:
        MO.whois_enrich.whois_current, MO.whois_enrich.whois_configured = real_whois, real_cfg
        MO.reset_process_state()

    return passed, failed, out


if __name__ == "__main__":
    p, f, lines = check()
    for s, l in lines:
        print(f"  {'ok ' if s == 'ok' else '✗  '} {l}")
    print(f"\n{p} passed, {f} failed")
    raise SystemExit(1 if f else 0)
