#!/usr/bin/env python3
"""test_engine_additions.py — gate on the Validin-plan engine additions (Phases 5/8/10).

Run:  python3 tests/test_engine_additions.py     (zero deps)
      pytest tests/test_engine_additions.py -q     (also works)

WHAT THIS PROTECTS
------------------
  1. QUAKE / ZOOMEYE CLIENTS (Phase 8). Configured-gate is False without a key; no network at
     import; proxy-safe (no custom urllib opener); the favicon reverse normalises a captured
     response to {"total","hosts":[...]} and turns an API-level error code into a tri-state note.
  2. REPUTATION FOLD (Phase 5). risk_signals.score_domain treats Validin reputation as
     CORROBORATION ONLY — a risky reputation never escalates on its own, but sharpens an existing
     escalation.
  3. CROSS-ENGINE MERGE (Phase 10). The frontier merges one apex found by N engines into a single
     candidate whose `sources` set has length N; the evidence report lists a discovered host's
     engines instead of collapsing them.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..", "intel_engine")
for _p in ("WebPivot/tools", "tools", "tools/kb"):
    sys.path.insert(0, os.path.join(ROOT, _p))

FAILURES = []


def check(label, cond, detail=""):
    if cond:
        print("  ok   {}".format(label))
    else:
        print("  FAIL {} {}".format(label, detail))
        FAILURES.append(label)


# --- 1. Quake / ZoomEye clients ------------------------------------------------------------
import wp_quake      # noqa: E402
import wp_zoomeye    # noqa: E402


def test_quake_zoomeye_gate_and_proxy_safe():
    # No key in the test env -> configured() False, favicon_reverse() None (no network attempted).
    for name in ("QUAKE_API_KEY", "QUAKE_API_KEY_FALLBACK", "QUAKE_TOKEN",
                 "ZOOMEYE_API_KEY", "ZOOMEYE_API_KEY_FALLBACK", "ZOOMEYE_KEY"):
        os.environ.pop(name, None)
    check("quake unconfigured without a key", wp_quake.quake_configured() is False)
    check("zoomeye unconfigured without a key", wp_zoomeye.zoomeye_configured() is False)
    check("quake favicon_reverse returns None unconfigured", wp_quake.favicon_reverse("1") is None)
    check("zoomeye favicon_reverse returns None unconfigured", wp_zoomeye.favicon_reverse("1") is None)
    for mod in (wp_quake, wp_zoomeye):
        src = open(mod.__file__, encoding="utf-8").read()
        check("%s builds no custom urllib opener (proxy-safe)" % mod.__name__.split(".")[-1],
              "build_opener(" not in src and "install_opener(" not in src)


def test_quake_normalises_and_tri_states():
    os.environ["QUAKE_API_KEY"] = "dummy-not-a-real-key"
    wp_quake._RUN_CALLS = 0
    wp_quake._post = lambda path, body, timeout=25: (
        {"code": 0, "data": [{"domain": "a.example"},
                             {"service": {"http": {"host": "b.example"}}},
                             {"ip": "1.2.3.4"}]}, None)   # ip-only row (no name) is dropped
    r = wp_quake.favicon_reverse("325177753")
    check("quake normalises to total/hosts", r.get("total") == 2 and set(r.get("hosts") or []) ==
          {"a.example", "b.example"}, detail=str(r))
    wp_quake._RUN_CALLS = 0
    wp_quake._post = lambda *a, **k: ({"code": "q3005", "message": "invalid token"}, None)
    r2 = wp_quake.favicon_reverse("325177753")
    check("quake non-zero code -> skipped tri-state", "skipped" in (r2 or {}), detail=str(r2))
    os.environ.pop("QUAKE_API_KEY", None)


def test_zoomeye_normalises_and_tri_states():
    os.environ["ZOOMEYE_API_KEY"] = "dummy-not-a-real-key"
    wp_zoomeye._RUN_CALLS = 0
    wp_zoomeye._post = lambda path, body, timeout=25: (
        {"code": 60000, "data": [{"domain": "z.example"},
                                 {"url": "http://u.example/path"}]}, None)
    r = wp_zoomeye.favicon_reverse("325177753")
    check("zoomeye normalises to total/hosts (url host extracted)",
          r.get("total") == 2 and set(r.get("hosts") or []) == {"z.example", "u.example"}, detail=str(r))
    wp_zoomeye._RUN_CALLS = 0
    wp_zoomeye._post = lambda *a, **k: ({"code": 40000, "message": "unauthorized"}, None)
    r2 = wp_zoomeye.favicon_reverse("325177753")
    check("zoomeye non-success code -> skipped tri-state", "skipped" in (r2 or {}), detail=str(r2))
    os.environ.pop("ZOOMEYE_API_KEY", None)


# --- 2. Reputation fold (corroboration only) -----------------------------------------------
import risk_signals as rs   # noqa: E402


def test_reputation_is_corroboration_only():
    rep_only = {"meta": {"host": "x.example"}, "artifacts": {"whois": {}}, "pivots": [
        {"kind": "domain", "live_results": {"validin_reputation": {"annotations": ["MALICIOUS phishing"]}}}]}
    s = rs.score_domain(rep_only)
    check("reputation risky is detected", s["reputation"]["risky"] is True)
    check("risky reputation ALONE never escalates", "validin-reputation" not in s["escalate"],
          detail=str(s["escalate"]))
    both = {"meta": {"host": "y.example"}, "artifacts": {"whois": {}},
            "related_urlscan": {"verdict": {"malicious": True, "score": 80, "brands": ["PayPal"]}},
            "pivots": [{"kind": "domain", "live_results": {
                "validin_ip_reputation": {"1.2.3.4": {"annotations": [{"cat": "scam"}]}}}}]}
    s2 = rs.score_domain(both)
    check("risky reputation corroborates when another signal fired",
          "validin-reputation" in s2["escalate"], detail=str(s2["escalate"]))


# --- 3. Cross-engine merge (Phase 10) ------------------------------------------------------
import case_state as cs        # noqa: E402
import evidence_report as er   # noqa: E402

MULTI = {"meta": {"host": "seed.example"}, "pivots": [
    {"kind": "domain", "value": "seed.example", "live_results": {
        "validin": {"total": 1, "hosts": ["sibling.example"]},
        "fofa_ip_reverse": {"total": 1, "results": [{"domain": "sibling.example", "ip": "9.9.9.9"}]}}},
    {"kind": "favicon_hash", "value": "123", "live_results": {
        "hunterhow": {"total": 1, "hosts": [{"domain": "sibling.example"}]},
        "quake": {"total": 1, "hosts": ["quakeonly.example"]}}}]}


def test_frontier_merges_sources():
    cands, seeds = {}, {cs._frontier_apex("seed.example")}
    cs._free_candidates_from_raw(MULTI, cands, seeds)
    sib = cands.get(cs._frontier_apex("sibling.example"), {})
    check("sibling apex merges validin+hunterhow into one candidate",
          {"validin", "hunterhow"}.issubset(set(sib.get("sources") or [])), detail=str(sib))
    check("corroboration score = |sources| >= 2", len(sib.get("sources") or []) >= 2)
    qk = cands.get(cs._frontier_apex("quakeonly.example"), {})
    check("quake feeds the frontier (registry-driven)", "quake" in (qk.get("sources") or []))


def test_report_lists_engines():
    rep = er.render_cluster_report([MULTI], case="T")
    line = [l for l in rep.splitlines() if "sibling.example" in l and "seen by" in l]
    check("report shows a discovered host's engine list", bool(line), detail="no 'seen by' line")
    if line:
        check("report lists >=2 engines for the corroborated host",
              "Validin" in line[0] and "Hunter.how" in line[0] and "corroborated" in line[0],
              detail=line[0])


for _t in (test_quake_zoomeye_gate_and_proxy_safe, test_quake_normalises_and_tri_states,
           test_zoomeye_normalises_and_tri_states, test_reputation_is_corroboration_only,
           test_frontier_merges_sources, test_report_lists_engines):
    _t()

if FAILURES:
    print(f"\nFAIL — {len(FAILURES)} check(s) failed:")
    for f in FAILURES:
        print("  -", f)
    sys.exit(1)
print("\nPASS — all engine-addition checks green")


def test_engine_additions():
    """pytest entry point — module body runs the checks at import time."""
    assert not FAILURES, FAILURES
