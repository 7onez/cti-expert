#!/usr/bin/env python3
"""Spend rails — a `no_spend` case never spends, and the SDK loop never auto-buys reverse-WHOIS.

Defends two leaks the cross-type loop plan closed:
  * `subdomain_enum` read `scope["no_spend"]`, but case_scope stores it under `constraints`, so a
    no-spend case still ran metered subfinder providers;
  * `orchestrator._reverse_whois_seeds` purchased the registrant estate (preview → purchase) with no
    approval and no `no_spend` check. It now previews only; buying is a proposal.json item.

Needs claude_agent_sdk (orchestrator / harness tools import it): run with the skill venv.
"""
import asyncio
import json
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "harness"))


def check():
    passed = failed = 0
    out = []

    def ok(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1
            out.append(("ok", label))
        else:
            failed += 1
            out.append(("FAIL", label))

    import orchestrator as O  # noqa: E402 — pulls the SDK
    import tools as T  # noqa: E402

    tmp = tempfile.mkdtemp(prefix="spend-rails-")
    saved = {"O.ROOT": O.ROOT, "T.ROOT": T.ROOT, "_run": T._run, "_rw_call": O._rw_call,
             "_terms": O._case_registrant_terms, "_scope": O._scope}
    try:
        O.ROOT = T.ROOT = tmp
        case = "CASE-0001"
        os.makedirs(os.path.join(tmp, "cases", case), exist_ok=True)

        # ---- 1. subdomain_enum honours constraints.no_spend --------------------------------
        cmds = []

        class _R:
            returncode, stdout, stderr = 0, "", ""

        def fake_run(cmd, timeout=None, **kw):
            cmds.append(list(cmd))
            return _R()

        T._run = fake_run
        scope_path = os.path.join(tmp, "cases", case, "scope.json")
        handler = getattr(T.subdomain_enum, "handler", T.subdomain_enum)

        with open(scope_path, "w") as fh:
            json.dump({"constraints": {"no_spend": True, "no_direct_contact": False}}, fh)
        asyncio.run(handler({"apex": "example.com", "case": case}))
        ok(bool(cmds) and "--free-only" in cmds[-1],
           "subdomain_enum: constraints.no_spend → --free-only (no metered providers)")

        with open(scope_path, "w") as fh:
            json.dump({"constraints": {"no_spend": False, "no_direct_contact": False}}, fh)
        asyncio.run(handler({"apex": "example.com", "case": case}))
        ok("--free-only" not in cmds[-1], "subdomain_enum: spend allowed → keyed providers stay on")

        # ---- 2. reverse-WHOIS: preview only, never purchase -------------------------------
        modes = []

        def fake_rw(flag, term, mode):
            modes.append((term, mode))
            return {"count": {"ops@example.com": 3, "+15550100": 400}.get(term, 0),
                    "domains": ["alpha.example", "beta.example"]}

        O._rw_call = fake_rw
        O._case_registrant_terms = lambda c: [("email", "ops@example.com"), ("phone", "+15550100")]
        O._scope = lambda c: {"constraints": {"no_spend": False}}
        seeds = O._reverse_whois_seeds(case, set(), cap=150)
        ok(seeds == {}, "reverse-WHOIS seed source returns no auto-purchased seeds")
        ok(modes and all(m == "preview" for _, m in modes), "reverse-WHOIS never calls purchase")
        rows = O._reverse_whois_previews(case, set(), cap=150)
        ok([r["term"] for r in rows] == ["ops@example.com"],
           "previews within cap are proposable; >cap (shared registrar) term is not")
        ok(len(modes) == 2, "each term is previewed once per case (cached, no repeat call)")

        # ---- 3. no_spend skips even the free preview ---------------------------------------
        modes.clear()
        os.remove(os.path.join(tmp, "cases", case, "rwhois_previews.json"))
        O._scope = lambda c: {"constraints": {"no_spend": True}}
        ok(O._reverse_whois_previews(case, set(), cap=150) == [] and not modes,
           "no_spend scope → no reverse-WHOIS call at all (not even preview)")

        # ---- 4. free_only is honoured, never a paid retry ------------------------------------
        cmds.clear()

        class _RW:
            returncode, stderr = 0, ""
            stdout = json.dumps({"reverse_email": {"count": 3, "domains": ["a.example"]}})

        T._run = lambda cmd, timeout=None, **kw: (cmds.append(list(cmd)), _RW())[1]
        rw = getattr(T.reverse_whois, "handler", T.reverse_whois)
        asyncio.run(rw({"term": "ops@example.com", "kind": "email", "free_only": True}))
        modes_run = [c[c.index("--reverse-mode") + 1] for c in cmds if "--reverse-mode" in c]
        ok(modes_run == ["preview"], f"reverse_whois free_only=true previews and never buys ({modes_run})")
        cmds.clear()
        asyncio.run(rw({"term": "ops@example.com", "kind": "email"}))
        ok("purchase" in [c[c.index("--reverse-mode") + 1] for c in cmds if "--reverse-mode" in c],
           "(control) without free_only the stubbed purchase path is reachable")
        cmds.clear()
        cz = getattr(T.censys, "handler", T.censys)
        res = asyncio.run(cz({"mode": "host", "value": "192.0.2.1", "free_only": True}))
        ok(res.get("is_error") and not cmds,
           "a metered tool with no keyless mode REFUSES free_only=true instead of spending")

        # ---- 5. loop-driven collects are free-only; only an approved enrich spends ---------
        import proposal as P  # noqa: E402
        flags = []
        saved_ch = T.collect_core.collect_host
        T.collect_core.collect_host = lambda *a, **k: (flags.append(list(k.get("extra_flags") or [])),
                                                       {"ok": True})[1]
        try:
            P.set_loop_active(tmp, case, True)
            T.collect_one("a.example", case)
            T.collect_one("a.example", case, allow_spend=True)
            P.set_loop_active(tmp, case, False)
            T.collect_one("a.example", case)
        finally:
            T.collect_core.collect_host = saved_ch
        ok(["--free-only" in f for f in flags] == [True, False, False],
           "while the loop is active a collect runs --free-only; approved enrich / no loop do not")

        # ---- 6. MCP `cti`: never nested inside a harness run; background reply names the case --
        cti = getattr(T.cti, "handler", T.cti)
        popens, runs = [], []
        saved_popen = T.subprocess.Popen
        T.subprocess.Popen = lambda cmd, **k: popens.append(list(cmd))
        T._run = lambda cmd, timeout=None, **kw: (runs.append(list(cmd)), _R())[1]
        try:
            os.environ["INTEL_IN_HARNESS"] = "1"      # SDK path: no HARNESS_PHASE, marker only
            asyncio.run(cti({"target": "example.com"}))
            os.environ.pop("INTEL_IN_HARNESS", None)
            ok(not popens and runs and "--pipeline" in runs[-1],
               "MCP cti inside a harness run (SDK path) runs the pipeline, never a nested harness")
            runs.clear()
            asyncio.run(cti({"target": "example.com", "passive": True}))
            ok(not popens and runs, "MCP cti --passive runs the pipeline synchronously, no harness")
            res = asyncio.run(cti({"target": "example.com"}))
            text = res["content"][0]["text"]
            ok(popens and "CTI-example-com" in text and "--case" in popens[-1],
               "MCP cti starts the harness in the background and names the derived case id")
        finally:
            os.environ.pop("INTEL_IN_HARNESS", None)
            T.subprocess.Popen = saved_popen
            shutil.rmtree(os.path.join(tmp, "cases", "CTI-example-com"), ignore_errors=True)
    finally:
        O.ROOT, T.ROOT, T._run = saved["O.ROOT"], saved["T.ROOT"], saved["_run"]
        O._rw_call, O._case_registrant_terms, O._scope = saved["_rw_call"], saved["_terms"], saved["_scope"]
        shutil.rmtree(tmp, ignore_errors=True)
    return passed, failed, out


def main():
    passed, failed, lines = check()
    for status, label in lines:
        print(f"  {'ok  ' if status == 'ok' else 'FAIL'} {label}")
    print(f"\n{'PASS' if not failed else 'FAIL'} — {passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
