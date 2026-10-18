#!/usr/bin/env python3
"""
test_whois_era_purge.py — regression test for the WHOIS ownership-era rule (whois_eras.py's
contract: only the CURRENT owner's WHOIS values may become an operator edge/signal/report
subject; a previous owner from a drop-catch/resale is a dated FACT at most, never named as this
operator) across the case-graph builder, the relation scorer, the KB hygiene sweep and the
timeline.

Fixture: a synthetic drop-caught estate modelled on a real class of defect (a domain registered
once, dropped, re-caught by an unrelated party, then re-registered by the current owner) — 2010,
dropped and re-caught in 2018, re-registered by the current owner in 2025 (day precision), plus a
registrar-role mailbox (`abuse@`) parked in the CURRENT `registrant_email` field (the "abuse
contact read as the registrant" misparse class) and a managed (Cloudflare-suffixed) nameserver
pair. Every value below is synthetic (`*.example` per CLAUDE.md's placeholder table) — no real
case data, case ID or target domain.

Run:  python3 tests/test_whois_era_purge.py
      python3 -m pytest tests/test_whois_era_purge.py
"""
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts", "webpivot"))
sys.path.insert(0, os.path.join(ROOT, "intel_engine", "IntelGraph", "scripts"))

import graph_build as gb                                                       # noqa: E402
import rank_relations as rr                                                    # noqa: E402
import case_timeline as ct                                                     # noqa: E402

CLEAN_KB = os.path.join(ROOT, "intel_engine", "tools", "kb", "clean_kb.py")

_PRIOR_2010 = {"created": "2010-05-17", "updated": "2010-05-17",
              "email": "victim1@example.com", "name": "Victim One", "registrar": "OldReg"}
_PRIOR_2018 = {"created": "2018-09-03", "updated": "2018-09-03",
              "email": "dropcatch@example.com", "name": "Drop Catch Co", "registrar": "DropReg"}


def _whois(current_email, current_name=None, ns=("ns1.brand.cloudflare.com", "ns-own1.op.example"),
          created="2025-09-09"):
    """A drop-caught WHOIS record: 2010 -> 2018 -> <created> (current), day-precision eras."""
    cur_rec = {"created": created, "updated": created, "email": current_email,
              "name": current_name, "registrar": "Current Registrar Co"}
    return {
        "registrant_email": current_email, "registrant_name": current_name,
        "created": created, "registrar": "Current Registrar Co",
        "name_servers": list(ns),
        "history": {"records": [_PRIOR_2010, _PRIOR_2018, cur_rec]},
    }


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

    # ============================================================== 1. graph_build.build() =====
    # the current registrant_email field itself carries the registrar-abuse mailbox misparse.
    wh = _whois(current_email="abuse@example.com")
    analysis = {"meta": {"host": "site-a.example"}, "artifacts": {"whois": wh}}
    g = gb.build([analysis])
    op_edges = [e for e in g.edges.values() if e["link_class"] == "operator"]
    op_targets = {e["target"] for e in op_edges}

    ok(not any("victim1" in t for t in op_targets),
       "graph_build: the 2010 prior owner never becomes an operator-class edge")
    ok(not any("dropcatch" in t for t in op_targets),
       "graph_build: the 2018 drop-catch owner never becomes an operator-class edge")
    ok(not any("abuse@example.com" in t for t in op_targets),
       "graph_build: a registrar-role mailbox in the live registrant_email field never becomes "
       "an operator edge (whois_enrich.is_privacy/noise_filters.is_noise_email)")
    ok(not any(e["confidence"] == "confirmed" and "registrant" in e["rel"] for e in op_edges),
       "graph_build: no `confirmed` registrant edge is minted off a noise/prior value")
    prior = g.nodes["site-a.example"].get("previous_registrants") or []
    ok(any("2010-05-17" in p for p in prior) and any("2018-09-03" in p for p in prior),
       "graph_build: prior owners land only as a `previous_registrants` FACT attribute, dated")
    ok("ns:ns1.brand.cloudflare.com" not in g.nodes,
       "graph_build: a managed (Cloudflare-suffixed) nameserver never becomes a shared hub node")
    ok("ns:ns-own1.op.example" in g.nodes,
       "graph_build: a self-hosted nameserver still becomes a node (classification is conditional)")
    ok(g.nodes["site-a.example"].get("managed_nameservers") == ["ns1.brand.cloudflare.com"],
       "graph_build: the managed NS is recorded as a domain-level fact instead")

    # ============================================================ 2. rank_relations.rank() ======
    # two unrelated domains sharing ONLY a managed NS + the SAME prior (drop-catch) owner email —
    # both signals must be excluded outright, so no relation at all, let alone same_operator_likely.
    wh_a = _whois(current_email="ownerA@example.com", created="2025-09-09",
                 ns=("ns1.shared.cloudflare.com", "ns-a.example"))
    wh_b = _whois(current_email="ownerB@example.com", created="2025-06-01",
                 ns=("ns1.shared.cloudflare.com", "ns-b.example"))
    a1 = {"meta": {"host": "siteA.example"}, "artifacts": {"whois": wh_a}}
    a2 = {"meta": {"host": "siteB.example"}, "artifacts": {"whois": wh_b}}
    result = rr.rank([a1, a2], frozenset(), min_strength=1, include_weak=True)
    ok(result["relations"] == [],
       "rank_relations: a pair sharing only a managed NS + a prior-owner value scores NO "
       "relation at all (never same_operator_likely)")

    sig_a, _ = rr.extract_signals(a1, frozenset())
    ok("ns1.shared.cloudflare.com" not in sig_a.get("nameserver", set()),
       "rank_relations: the managed (shared) NS never enters the nameserver signal")
    ok("registrant_email" in sig_a and sig_a["registrant_email"] == {"ownera@example.com"},
       "rank_relations: registrant_email signal is the CURRENT owner only, not the drop-catch era")

    # current-era shared registrant email DOES score a relation (the positive control).
    wh_c = _whois(current_email="same-operator@example.com")
    wh_d = _whois(current_email="same-operator@example.com")
    a3 = {"meta": {"host": "siteC.example"}, "artifacts": {"whois": wh_c}}
    a4 = {"meta": {"host": "siteD.example"}, "artifacts": {"whois": wh_d}}
    result2 = rr.rank([a3, a4], frozenset(), min_strength=1, include_weak=True)
    ok(result2["relations"] and result2["relations"][0]["assessment"] == "same_operator_likely",
       "rank_relations: a shared CURRENT-era registrant email still scores same_operator_likely "
       "(the fix removes prior-era/managed-NS noise, not real signal)")

    # ============================================================ 3. clean_kb.py era-purge ======
    with tempfile.TemporaryDirectory() as td:
        kb_root = os.path.join(td, "knowledge")
        os.makedirs(os.path.join(kb_root, "relationships"))
        os.makedirs(os.path.join(kb_root, "entities"))
        ev_dir = os.path.join(kb_root, "evidence", "webpivot", "site-a.example")
        os.makedirs(ev_dir)
        clean_wh = _whois(current_email="operator@current.example", current_name="Current Operator")
        raw = {"meta": {"host": "site-a.example"}, "artifacts": {"whois": clean_wh}}
        ev_path = os.path.join(ev_dir, "2025-09-09.json")
        with open(ev_path, "w", encoding="utf-8") as fh:
            json.dump(raw, fh)
        evidence_ref = "evidence/webpivot/site-a.example/2025-09-09.json"

        def _edge(dst, dst_type, rel="registered_by"):
            return {"src": "site-a.example", "src_type": "domain", "dst": dst,
                   "dst_type": dst_type, "rel": rel, "source": "whoisxml",
                   "collector": "webpivot/whois_enrich", "observed_at": "2026-01-01T00:00:00Z",
                   "confidence": 0.9, "evidence_ref": evidence_ref}

        e_prior_email_2010 = _edge("victim1@example.com", "email")
        e_prior_email_2018 = _edge("dropcatch@example.com", "email")
        e_current_email = _edge("operator@current.example", "email")
        e_prior_person = _edge("Victim One", "person")
        e_ip_literal = {"src": "198.51.100.7", "src_type": "domain", "dst": "wallet:198.51.100.7",
                        "dst_type": "indicator", "rel": "uses_wallet", "source": "webpivot",
                        "collector": "webpivot", "observed_at": "2026-01-01T00:00:00Z",
                        "confidence": 0.5, "evidence_ref": None}
        edges = [e_prior_email_2010, e_prior_email_2018, e_current_email, e_prior_person, e_ip_literal]
        edges_path = os.path.join(kb_root, "relationships", "edges.jsonl")
        with open(edges_path, "w", encoding="utf-8") as fh:
            for e in edges:
                fh.write(json.dumps(e) + "\n")

        dry = subprocess.run([sys.executable, CLEAN_KB, "--kb", kb_root],
                             capture_output=True, text=True, timeout=30)
        ok(dry.returncode == 0, f"clean_kb dry-run exits cleanly: {dry.stderr[-300:]}")
        n_listed = dry.stdout.count("--registered_by--> email:victim1@example.com") \
            + dry.stdout.count("--registered_by--> email:dropcatch@example.com") \
            + dry.stdout.count("--registered_by--> person:Victim One")
        ok(n_listed == 3,
           "clean_kb dry-run lists exactly the 3 era-forbidden edges (2 email + 1 person)")
        ok("operator@current.example" not in dry.stdout.split("era-forbidden")[-1]
           if "era-forbidden" in dry.stdout else True,
           "clean_kb dry-run never lists the CURRENT-era registrant edge as forbidden")
        ok(os.path.getsize(edges_path) > 0, "clean_kb dry-run never rewrites edges.jsonl")
        with open(edges_path, encoding="utf-8") as fh:
            still = [json.loads(l) for l in fh if l.strip()]
        ok(len(still) == 5, "clean_kb dry-run leaves every edge on disk untouched")

        apply_run = subprocess.run([sys.executable, CLEAN_KB, "--kb", kb_root, "--apply"],
                                   capture_output=True, text=True, timeout=30)
        ok(apply_run.returncode == 0, f"clean_kb --apply exits cleanly: {apply_run.stderr[-300:]}")
        with open(edges_path, encoding="utf-8") as fh:
            kept = [json.loads(l) for l in fh if l.strip()]
        kept_keys = {(e["dst"], e["dst_type"]) for e in kept}
        ok(("victim1@example.com", "email") not in kept_keys
           and ("dropcatch@example.com", "email") not in kept_keys
           and ("Victim One", "person") not in kept_keys,
           "clean_kb --apply removes the 3 era-forbidden edges")
        ok(("operator@current.example", "email") in kept_keys,
           "clean_kb --apply KEEPS the current-era registered_by edge")
        ok(("wallet:198.51.100.7", "indicator") not in kept_keys,
           "clean_kb --apply still removes the unrelated legacy ip-literal-domain edge "
           "(existing sweep behaviour unchanged)")
        ok(len(kept) == 1, "clean_kb --apply removes ONLY the forbidden edges, nothing else")

    # --value targeted purge (dry-run only; a second synthetic KB, isolated from the run above)
    with tempfile.TemporaryDirectory() as td2:
        kb_root2 = os.path.join(td2, "knowledge")
        os.makedirs(os.path.join(kb_root2, "relationships"))
        os.makedirs(os.path.join(kb_root2, "entities"))
        edges2 = [
            {"src": "site-a.example", "src_type": "domain", "dst": "abuse@example.com",
             "dst_type": "email", "rel": "registered_by", "source": "whoisxml",
             "collector": "webpivot/whois_enrich", "observed_at": "2026-01-01T00:00:00Z",
             "confidence": 0.9, "evidence_ref": None},
            {"src": "other-site.example", "src_type": "domain", "dst": "keeper@example.com",
             "dst_type": "email", "rel": "registered_by", "source": "whoisxml",
             "collector": "webpivot/whois_enrich", "observed_at": "2026-01-01T00:00:00Z",
             "confidence": 0.9, "evidence_ref": None},
        ]
        edges_path2 = os.path.join(kb_root2, "relationships", "edges.jsonl")
        with open(edges_path2, "w", encoding="utf-8") as fh:
            for e in edges2:
                fh.write(json.dumps(e) + "\n")
        val_run = subprocess.run(
            [sys.executable, CLEAN_KB, "--kb", kb_root2, "--value", "abuse@example.com"],
            capture_output=True, text=True, timeout=30)
        ok(val_run.returncode == 0, f"clean_kb --value dry-run exits cleanly: {val_run.stderr[-300:]}")
        ok("abuse@example.com" in val_run.stdout and "keeper@example.com" not in val_run.stdout,
           "clean_kb --value <selector> targets exactly that selector's edges, not others")

    # ============================================================ 4. case_timeline.whois_events =
    wh_t = _whois(current_email="operator@current.example", current_name="Current Operator")
    events = []
    ct.whois_events("site-a.example", wh_t, events)
    eras = [e for e in events if e["kind"] == "registrant_era"]
    prior_eras = [e for e in eras if e["label"].startswith("previous registrant")]
    current_eras = [e for e in eras if e["label"].startswith("registrant:")]

    ok(len(prior_eras) == 2, "case_timeline: exactly 2 prior-era registrant_era events emitted")
    for e in prior_eras:
        blob = json.dumps({"label": e["label"], "detail": e["detail"], "value": e.get("value")})
        ok("victim1@example.com" in blob or "dropcatch@example.com" in blob,
           f"case_timeline: prior-era event ({e['label']}) carries the prior owner's identity "
           "in plain text (masking disabled)")
    ok(any("2010-05-17" in e["label"] for e in prior_eras)
       and any("2018-09-03" in e["label"] for e in prior_eras),
       "case_timeline: prior-era events keep the era date — drop-catch evidence is useful")
    ok(len(current_eras) == 1 and "operator@current.example" in current_eras[0]["label"],
       "case_timeline: the CURRENT owner's registrant_era event still shows the identity in clear")

    return passed, failed, out


_PASSED, _FAILED, _LINES = check()


def test_whois_era_purge():
    """pytest entry point — the module body does the work at import time."""
    assert not _FAILED, [l for s, l in _LINES if s != "ok"]


if __name__ == "__main__":
    for status, label in _LINES:
        print(f"{'  ok  ' if status == 'ok' else '  FAIL'} {label}")
    print()
    if _FAILED:
        print(f"FAIL — {_FAILED} whois-era-purge check(s) failed")
    else:
        print(f"PASS — whois ownership-era rule holds across graph/relations/clean_kb/timeline "
              f"({_PASSED} checks)")
    raise SystemExit(bool(_FAILED))
