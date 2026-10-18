#!/usr/bin/env python3
"""Offline unit gate: api_usage cost classes (free | quota | metered subtotals) and the
reverse-WHOIS auto-buy cap read from harness/references/reverse_whois.json (rwhois_auto_cap).

The ledger counts about one unit per call, including free reverse-WHOIS previews and keyless
lookups, so a single total read like a bill. The report now classes every row from
WebPivot/references/api_cost_classes.json and prints three subtotals; the total line says
"estimated units". The harness reverse gate used to hardcode 150; it now reads the reference,
proven here by stubbing the file to 60 and watching the same count flip from purchase to confirm.
Synthetic data only (example.com).
"""
import contextlib
import importlib.util
import io
import json
import os
import re
import sys
import tempfile

ENGINE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_WP_TOOLS = os.path.join(ENGINE, "WebPivot", "tools")
_HARNESS = os.path.join(ENGINE, "harness")
if _WP_TOOLS not in sys.path:
    sys.path.insert(0, _WP_TOOLS)
import api_usage as A  # noqa: E402


def _harness_tools():
    """harness/tools.py as a module (reuses an already-imported copy; needs claude_agent_sdk)."""
    mod = sys.modules.get("tools")
    if mod is not None and os.path.abspath(getattr(mod, "__file__", "") or "") == os.path.join(_HARNESS, "tools.py"):
        return mod
    if _HARNESS not in sys.path:
        sys.path.insert(0, _HARNESS)
    spec = importlib.util.spec_from_file_location("harness_tools_rwhois_cap", os.path.join(_HARNESS, "tools.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


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

    tmp = tempfile.mkdtemp(prefix="ledger-cost-")

    # --- A. three cost classes, three subtotals --------------------------------------------
    log = os.path.join(tmp, "api_usage.jsonl")
    rows = [
        {"ts": "2026-10-16T01:00:00Z", "provider": "whoisxml", "action": "reverse-whois-preview",
         "credits": 1, "query": "owner@example.com", "ok": True, "case": "CASE-SYNTH"},
        {"ts": "2026-10-16T02:00:00Z", "provider": "urlscan", "action": "search",
         "credits": 2, "query": "domain:example.com", "ok": True, "case": "CASE-SYNTH"},
        {"ts": "2026-10-16T03:00:00Z", "provider": "fofa", "action": "search",
         "credits": 3, "query": 'domain="example.com"', "ok": True, "case": "CASE-SYNTH"},
    ]
    with open(log, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")

    ref = A.load_cost_classes()
    ok([A.cost_class(r, ref) for r in rows] == ["free", "quota", "metered"],
       "one free (reverse-WHOIS preview), one quota (urlscan), one metered (FOFA) row classed")
    ok(A.cost_class({"provider": "ipinfo", "action": "lookup", "credits": 0}, ref) == "free",
       "a 0-credit keyless call is free whatever its provider")
    ok(A.cost_class({"provider": "brand-new-vendor", "action": "x", "credits": 1}, ref) == "metered",
       "an unclassified provider defaults to metered (never under-states)")
    ok(A.cost_class({"provider": "whoisxml", "action": "reverse-whois", "credits": 1}, ref) == "metered",
       "a reverse-WHOIS PURCHASE stays metered")

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = A._report(["report", "--log", log, "--last", "3"])
    txt = buf.getvalue()
    ok(rc == 0, "report exits 0")
    ok(bool(re.search(r"^\s+free\s+1 calls · ~\s*1 units$", txt, re.M)), "free subtotal: 1 call, 1 unit")
    ok(bool(re.search(r"^\s+quota\s+1 calls · ~\s*2 units$", txt, re.M)), "quota subtotal: 1 call, 2 units")
    ok(bool(re.search(r"^\s+metered\s+1 calls · ~\s*3 units$", txt, re.M)), "metered subtotal: 1 call, 3 units")
    ok("3 calls, ~6 estimated units" in txt.split("\n")[0], "total line kept, labelled 'estimated units'")
    ok("[free]" in txt and "[quota]" in txt and "[metered]" in txt, "--last rows carry their class")

    # the classes are DATA: a stubbed reference reclassifies urlscan without code changes
    stub = os.path.join(tmp, "api_cost_classes.json")
    with open(stub, "w", encoding="utf-8") as fh:
        json.dump({"_comment": "stub", "rules": {"default_class": "metered", "zero_credit_is_free": True},
                   "action_classes": {"entries": {}}, "provider_classes": {"entries": {"urlscan": "metered"}}}, fh)
    with contextlib.redirect_stderr(io.StringIO()):
        sref = A.load_cost_classes(stub)
    ok(A.cost_class(rows[1], sref) == "metered", "cost classes come from the reference file")

    # --- B. reverse-WHOIS auto-buy cap from harness/references/reverse_whois.json -------------
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            ht = _harness_tools()
    except ImportError as exc:
        out.append(("skip", f"B rwhois_auto_cap skipped — harness import needs the SDK venv ({exc})"))
        return passed, failed, out
    with open(os.path.join(_HARNESS, "references", "reverse_whois.json"), encoding="utf-8") as fh:
        real = json.load(fh)["rwhois_auto_cap"]["value"]
    ok(ht._rwhois_auto_cap() == real, f"gate cap loads from reverse_whois.json ({real})")
    ok(ht._reverse_gate("email", 100, None, False)[0] == "purchase", "100 domains under the reference cap → purchase")
    saved = ht._RWHOIS_REF
    stub_cap = os.path.join(tmp, "reverse_whois.json")
    with open(stub_cap, "w", encoding="utf-8") as fh:
        json.dump({"_comment": "stub", "rwhois_auto_cap": {"_comment": "stub", "value": 60}}, fh)
    try:
        ht._RWHOIS_REF = stub_cap
        ok(ht._rwhois_auto_cap() == 60, "stubbed reference → cap 60")
        act, reason = ht._reverse_gate("email", 100, None, False)
        ok(act == "confirm" and "> 60" in reason, "same 100 domains with the cap stubbed to 60 → confirm")
        ok(ht._reverse_gate("email", 60, None, False)[0] == "purchase", "count == stubbed cap → purchase")
        ok(ht._reverse_gate("email", 100, 500, False)[0] == "purchase", "explicit max_domains still overrides")
    finally:
        ht._RWHOIS_REF = saved
    return passed, failed, out


if __name__ == "__main__":
    p, f, lines = check()
    for s, l in lines:
        print(f"  {'ok ' if s == 'ok' else ('-- ' if s == 'skip' else '✗  ')} {l}")
    print(f"{p} passed, {f} failed")
    sys.exit(1 if f else 0)
