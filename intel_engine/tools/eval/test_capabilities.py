#!/usr/bin/env python3
"""Offline unit gate for the capability / keyless-disclosure layer (wp_capabilities).

WebPivot runs keyless by design, so a missing key is never an error. The danger is subtler: a
keyless run and a fully-keyed run produce the same SHAPE of output, but they searched different
amounts of the internet. If the run does not say which one it was, "no sibling domains" gets read
as a finding about the operator when it is a fact about our credentials. Four failure modes here
are silent in production, and each is asserted below:

  1. **A false all-clear.** Reporting a key as present when it is not — or as absent when the tool
     is happily using it — is worse than no banner at all. The presence check must honour the
     documented aliases and only the `requires` companions, never a guess from the variable name
     (FOFA_EMAIL is optional; treating it as required reports a working FOFA key as missing).
  2. **A caveat that never reaches the file.** The banner scrolls past; `meta.capability` is what a
     reader sees months later. It has to carry the mode, the missing keys, and a statement written
     to be pasted into an assessment's collection-limitations note.
  3. **--free-only reading as full capability.** Keys can be present and still forbidden to spend.
     That run is analytically keyless for the metered indexes and must say so.
  4. **Banner fatigue.** A fully-keyed run must print NOTHING, or the analyst learns to ignore the
     block on the runs where it matters.

Run standalone (`python3 tools/eval/test_capabilities.py`) or via run_eval.py.
"""
import os
import sys
import tempfile

# Vendor clients ledger every (mocked) call via api_usage; a test must never write phantom credits
# into the real MEMORY/api_usage.jsonl (the Censys/urlscan monthly budgets are derived from it).
os.environ.setdefault("API_USAGE_LOG", os.path.join(tempfile.gettempdir(), "cti-tests-api_usage.jsonl"))

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))), "WebPivot", "tools"))
import wp_capabilities as cap  # noqa: E402

_ENVS = sorted({e for spec in cap.API_KEYS.values() if isinstance(spec, dict)
                for e in ([] if not spec else [])} |
               set(cap.API_KEYS.keys()) |
               {a for spec in cap.API_KEYS.values() if isinstance(spec, dict)
                for a in (spec.get("aliases") or [])} |
               {c for spec in cap.API_KEYS.values() if isinstance(spec, dict)
                for c in (spec.get("requires") or [])})


def check():
    """Return (passed, failed, [outcome lines])."""
    out, passed, failed = [], 0, 0

    def ok(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1
            out.append(("ok", label))
        else:
            failed += 1
            out.append(("FAIL", label))

    # --- the data itself: every entry must state a consequence, not just a feature ------------
    rows = cap.key_status()
    ok(len(rows) >= 5, f"api_keys.json registers the optional credentials ({len(rows)})")
    ok(all(r["without_it"] for r in rows),
       "every credential documents what is LOST without it (that text is the banner)")
    ok(all(r["impact"] in cap.IMPACT_LABELS or r["impact"] in ("medium", "low") for r in rows),
       "every impact level is one the banner knows how to phrase")
    ok(any(r["impact"] == "critical" for r in rows),
       "at least one credential is marked critical — the absences that void a negative result")
    ok(all(r["free_fallback"] for r in rows),
       "every credential names the free path that substitutes (keyless must not read as broken)")

    # --- presence: aliases honoured, only `requires` companions enforced ----------------------
    saved = {e: os.environ.pop(e, None) for e in _ENVS}
    try:
        c = cap.capability_meta()
        ok(c["mode"] == "keyless", "no credential at all -> mode 'keyless'")
        ok(not c["keys_present"] and len(c["keys_missing"]) == len(rows),
           "…and every registered credential is listed as missing")
        ok("not evidence" in c["statement"],
           "the statement warns that ABSENCE of siblings is not evidence (the whole point)")
        ok(len(c["reduced"]) >= 1 and all(b["lost"] for b in c["reduced"]),
           "reduced[] names each lost evidence class for the report's limitations note")
        ok(len(c["keyless_baseline"]) >= 5,
           "…alongside what still runs free, so keyless does not read as broken")
        lines = cap.banner_lines()
        ok(lines and "KEYLESS" in lines[0], "the keyless banner leads with the mode")
        ok(len(lines) <= 30,
           f"the banner stays readable ({len(lines)} lines) — a wall of text is a banner nobody reads")

        # an ALIAS must count as the key being present, or the banner cries wolf
        alias_env = next((r for r in rows if r["aliases"]), None)
        if alias_env:
            os.environ[alias_env["aliases"][0]] = "x"
            ok(alias_env["env"] not in cap.capability_meta()["keys_missing"],
               f"{alias_env['env']} set via its alias {alias_env['aliases'][0]} reads as PRESENT")
            os.environ.pop(alias_env["aliases"][0])

        # an OPTIONAL companion must not make a working key read as absent…
        fofa = next((r for r in rows if r["env"] == "FOFA_KEY"), None)
        if fofa:
            ok("FOFA_EMAIL" not in fofa["requires"],
               "FOFA_EMAIL is NOT required (classic-API only) — requiring it would hide a live key")
            os.environ["FOFA_KEY"] = "x"
            ok("FOFA_KEY" not in cap.capability_meta()["keys_missing"],
               "FOFA_KEY alone reads as PRESENT without FOFA_EMAIL")
            os.environ.pop("FOFA_KEY")

        # …while a genuinely required one must
        pdns = next((r for r in rows if r["requires"]), None)
        if pdns:
            os.environ[pdns["env"]] = "x"
            ok(pdns["env"] in cap.capability_meta()["keys_missing"],
               f"{pdns['env']} without {pdns['requires'][0]} correctly reads as UNUSABLE")
            os.environ.pop(pdns["env"])

        # --- every key present -> keyed, and the banner goes silent --------------------------
        for r in rows:
            os.environ[r["env"]] = "x"
            for req in r["requires"]:
                os.environ[req] = "x"
        full = cap.capability_meta()
        ok(full["mode"] == "keyed", "every credential present -> mode 'keyed'")
        ok(not full["reduced"], "…and nothing is reported as reduced")
        ok(cap.banner_lines() == [],
           "a fully-keyed run prints NO banner (or the analyst learns to ignore it)")

        # --- --free-only: keys present but unusable is NOT full capability -------------------
        fo = cap.capability_meta(free_only=True)
        ok(fo["mode"] == "free-only", "--free-only is its own mode, not 'keyed'")
        ok(fo["metered_suppressed"], "…and names the metered credentials it refused to spend")
        ok(fo["reduced"], "…and still warns which evidence classes went unqueried")
        ok("--free-only" in fo["statement"] or "free-only" in fo["statement"],
           "…with a statement that explains WHY they were unqueried")

        # --- entitlement DISCOVERY: measured plans, offline by default, per-case store -------------
        import json
        import tempfile
        import wp_plans
        _saved_case = os.environ.pop(wp_plans.CASE_DIR_ENV, None)   # a collector's env must not leak in
        ok(cap.capability_meta()["plans"] == {} and fo["plans"] == {},
           "default capability_meta() is OFFLINE: no probe, plans = the (empty) store")
        probes = (
            ("urlscan", lambda: {"tier": "pro", "products": ["pro"], "search_day": {"remaining": 5}}),
            ("netlas", lambda: {"tier": "free"}),
            ("securitytrails", lambda: {"tier": "free", "used": 3, "allowed": 50}),
            ("dnslytics", lambda: None),                       # not configured -> absent, not 'unknown'
            ("intelx", lambda: (_ for _ in ()).throw(RuntimeError("boom"))),   # a raising probe degrades
            ("validin", lambda: {"tier": "community", "registration": False}),
            ("grayhatwarfare", cap._probe_grayhatwarfare),
        )
        with tempfile.TemporaryDirectory() as tmp:
            case = os.path.join(tmp, "CASE-0001")
            os.makedirs(case)
            plans = cap.discover_plans(case_dir=case, probe=True, probes=probes)
            ok(plans["urlscan"]["tier"] == "pro" and plans["netlas"]["tier"] == "free"
               and plans["validin"]["registration"] is False, "plans carry the measured tier per vendor")
            ok("dnslytics" not in plans, "an unconfigured vendor is absent (presence decides, not a placeholder)")
            ok(plans["intelx"]["tier"] == "unknown" and "boom" in plans["intelx"]["error"],
               "a raising probe degrades to tier 'unknown' — discovery never raises")
            ok(plans["grayhatwarfare"]["tier"] == "unknown", "GrayHatWarfare has no quota endpoint -> 'unknown'")
            stored = json.load(open(os.path.join(case, wp_plans.FILE)))
            ok(stored["plans"]["urlscan"]["tier"] == "pro" and any(h["vendor"] == "urlscan" for h in stored["history"]),
               "measured plans persisted to cases/<id>/capability_plans.json with history")
            calls = []
            again = cap.discover_plans(case_dir=case, probe=True,
                                       probes=(("urlscan", lambda: calls.append(1) or {"tier": "free"}),))
            ok(not calls and again["urlscan"]["tier"] == "pro", "a SECOND process reads the store and does not re-probe")
            ok(cap.discover_plans(case_dir=case, probe=False)["netlas"]["tier"] == "free",
               "probe=False returns the store only")
            meta = cap.capability_meta(case_dir=case, probe=False)
            ok(meta["plans"].get("urlscan", {}).get("tier") == "pro", "capability_meta surfaces the stored plans")
            # Censys is NEVER probed here — its search is its own probe (red-team H0)
            ok("censys" not in dict(cap._PROBES), "no capability probe for Censys (the search is the probe)")
            wp_plans.record("censys", "free", why="test", case_dir=case)
            ok(wp_plans.get("censys", case_dir=case) == "free", "wp_plans.record/get round-trip")
            ok(wp_plans.record("censys", "free", case_dir=case) and
               sum(1 for h in json.load(open(os.path.join(case, wp_plans.FILE)))["history"] if h["vendor"] == "censys") == 1,
               "re-recording the same plan is idempotent (no history noise)")
            # a FAILED probe (unknown + error) is returned for this run but never frozen in the store
            json.dump({"plans": {}}, open(os.path.join(case, wp_plans.FILE), "w"))
            flaky = {"n": 0}

            def _flaky():
                flaky["n"] += 1
                return {"tier": "unknown", "error": "timeout"} if flaky["n"] == 1 else {"tier": "free"}
            p1 = cap.discover_plans(case_dir=case, probe=True, probes=(("netlas", _flaky),))
            ok(p1["netlas"]["tier"] == "unknown" and "netlas" not in wp_plans.load(case_dir=case),
               "a failed probe is reported this run but NOT persisted")
            p2 = cap.discover_plans(case_dir=case, probe=True, probes=(("netlas", _flaky),))
            ok(p2["netlas"]["tier"] == "free" and wp_plans.load(case_dir=case)["netlas"]["tier"] == "free",
               "…so the next process re-probes and records the real tier")
            # the enrichment-side predicate: gate ONLY on a positive `free`
            import wp_analyze
            ok(wp_analyze.measured_tier("urlscan", {"urlscan": {"tier": "free"}}) == "free"
               and wp_analyze.measured_tier("urlscan", {"urlscan": {"tier": "pro"}}) == "pro"
               and wp_analyze.measured_tier("urlscan", {}) == "unknown"
               and wp_analyze.measured_tier("censys", {"censys": "paid"}) == "paid",
               "measured_tier: dict or string entries, absent -> unknown")
            ok(wp_analyze.measured_tier("urlscan", {"urlscan": {"tier": "unknown", "error": "x"}}) == "unknown",
               "measured_tier: a failed probe reads as unknown (Pro call stays the probe)")
        # urlscan quotas -> tier: decided by the PRESENT products list; an absent field is 'unknown',
        # never 'free' (a persisted 'free' would switch the Pro calls off for the whole case)
        import io
        import urllib.request
        import wp_net
        saved_urlopen, saved_key = urllib.request.urlopen, os.environ.get("URLSCAN_API_KEY")
        try:
            os.environ["URLSCAN_API_KEY"] = "x"
            for body, want in (({"scope": "team", "limits": {"products": ["pro", "livescan"], "search": {"day": {"limit": 5, "used": 1, "remaining": 4}}}}, "pro"),
                               ({"scope": "user", "limits": {"products": [], "search": {"day": {}}}}, "free"),
                               ({"scope": "user", "limits": {"search": {"day": {}}}}, "unknown"),
                               ({"scope": "user"}, "unknown")):
                urllib.request.urlopen = lambda req, timeout=20, _b=body: io.BytesIO(json.dumps(_b).encode())
                q = wp_net.urlscan_quotas()
                ok(q["tier"] == want, f"urlscan quotas {body.get('limits', {}).get('products', 'absent')!s} -> tier {want}")
            ok(q.get("error") and "products" in q["error"], "…and the unknown case says why")
        finally:
            urllib.request.urlopen = saved_urlopen
            os.environ.pop("URLSCAN_API_KEY", None)
            if saved_key is not None:
                os.environ["URLSCAN_API_KEY"] = saved_key
        ok(wp_plans.load(case_dir=None) == {}, "no case dir -> store is a no-op, never an error")
        if _saved_case is not None:
            os.environ[wp_plans.CASE_DIR_ENV] = _saved_case
    finally:
        for e in _ENVS:
            os.environ.pop(e, None)
            if saved.get(e) is not None:
                os.environ[e] = saved[e]

    return passed, failed, out


if __name__ == "__main__":
    p, f, lines = check()
    for status, label in lines:
        print(("  ok  " if status == "ok" else "  FAIL") + " " + label)
    print(f"\n{p} passed, {f} failed")
    sys.exit(1 if f else 0)
