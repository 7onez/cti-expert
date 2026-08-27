#!/usr/bin/env python3
"""test_render_confirm.py — gate on renderer-confirmation reconcile logic + detector seams.

Run:  python3 tests/test_render_confirm.py     (zero deps)
      pytest tests/test_render_confirm.py -q     (also works)

WHAT THIS PROTECTS
  1. RENDERED CLIPBOARD PROMOTES. A page whose payload is assembled at runtime looks inert to
     the static ClickFix pass; feeding the renderer-captured clipboard string must promote the
     verdict to HIGH (the key detection win the Auckland/PaloAlto papers motivate).
  2. COMPUTED-HIDDEN PROMOTES. A JS-injected hidden credential form (computed style) must be
     surfaced when the renderer reports it, even if the static HTML looked clean.
  3. NO-EVIDENCE = STATIC AUTHORITATIVE. With no renderer evidence, verdicts equal the static
     ones (never a fabricated rendered result).
  4. NO-RENDERER DEGRADES, NEVER CRASHES. run_render with no renderer returns (None, note).
  5. SEAMS ARE ADDITIVE. The existing static behavior is unchanged when the seam args are absent.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))

import clickfix_detect as cf            # noqa: E402
import html_visibility_analysis as hv   # noqa: E402
import render_confirm as rc             # noqa: E402

FAILURES = []


def check(label, cond, detail=""):
    if cond:
        print("  ok   {}".format(label))
    else:
        print("  FAIL {} {}".format(label, detail))
        FAILURES.append(label)


# Static-inert page: a fake-verification lure, but the command is assembled by JS at runtime,
# so the static pass sees a lure only (not HIGH).
INERT_HTML = """<html><body><h1>Verify you are human</h1>
<p>Press Win+R then Ctrl+V then Enter.</p>
<script>var a='power';var b='shell';window.__x=a+b;</script></body></html>"""

CLEAN_HTML = "<html><body><p>Welcome to the shop.</p></body></html>"


def test_rendered_clipboard_promotes():
    print("\n[1] renderer-captured clipboard promotes ClickFix verdict")
    static = cf.detect(INERT_HTML)
    check("static is not HIGH (payload hidden in JS)", static["verdict"] != "high", static["verdict"])
    r = rc.confirm_from_evidence(
        INERT_HTML,
        {"clipboard": ["powershell -w hidden -enc SQBFAFgAKAAnAGgAdAB0AHAAOgAvAC8AYgAuAGUAeAAnACkA"]})
    c = r["clickfix"]
    check("rendered verdict HIGH", c["rendered_verdict"] == "high", c["rendered_verdict"])
    check("final promoted", c["final_verdict"] == "high" and c["reconciliation"] == "promoted_by_render",
          c)
    check("decoded/ioc surfaced from captured clipboard",
          bool(c["iocs"]["commands"]) , c["iocs"])


def test_computed_hidden_promotes():
    print("\n[2] renderer computed-hidden credential form promotes visibility verdict")
    static = hv.analyze(CLEAN_HTML, origin="shop.example")
    check("static clean page is none", static["verdict"] == "none", static["verdict"])
    r = rc.confirm_from_evidence(CLEAN_HTML, {"computed_hidden": [
        {"kind": "hidden_field", "detail": "name=password", "concealment": "display:none",
         "severity": "high"}]}, origin="shop.example")
    v = r["visibility"]
    check("rendered verdict HIGH", v["rendered_verdict"] == "high", v["rendered_verdict"])
    check("final promoted", v["final_verdict"] == "high" and v["reconciliation"] == "promoted_by_render",
          v)


def test_no_evidence_static_authoritative():
    print("\n[3] no renderer evidence -> verdicts equal the static ones")
    r = rc.confirm_from_evidence(INERT_HTML, {})
    check("no rendered evidence flag", r["rendered_evidence_present"] is False)
    check("clickfix final == static",
          r["clickfix"]["final_verdict"] == r["clickfix"]["static_verdict"])
    check("visibility final == static",
          r["visibility"]["final_verdict"] == r["visibility"]["static_verdict"])


def test_reconcile_directions():
    print("\n[4] reconcile direction labels")
    check("promote", rc._reconcile_verdict("none", "high") == ("high", "promoted_by_render"))
    check("agree", rc._reconcile_verdict("medium", "medium") == ("medium", "agree"))
    check("static higher (render didn't corroborate)",
          rc._reconcile_verdict("high", "none") == ("high", "static_only_higher"))


def test_no_renderer_degrades():
    print("\n[5] run_render with no renderer degrades to (None, note), never crashes")
    # We don't assert a renderer is absent (CI may vary); we assert the contract holds either way.
    ev, note = rc.run_render("https://example.invalid/")
    if ev is None:
        check("returns a note when unavailable/failed", isinstance(note, str) and note)
    else:
        check("returns evidence dict when available", isinstance(ev, dict))


def test_seams_additive():
    print("\n[6] seam args absent -> static behavior unchanged")
    a = cf.detect(INERT_HTML)
    b = cf.detect(INERT_HTML, captured_clipboard=None)
    check("clickfix seam None == no-arg", a["verdict"] == b["verdict"])
    c = hv.analyze(CLEAN_HTML)
    d = hv.analyze(CLEAN_HTML, computed_hidden=None)
    check("visibility seam None == no-arg", c["verdict"] == d["verdict"])


def test_nondict_evidence_no_crash():
    print("\n[7] M2: non-dict evidence is treated as none, never raises")
    r = rc.confirm_from_evidence("<html></html>", [1, 2])   # a list, not a dict
    check("list evidence -> no rendered evidence", r["rendered_evidence_present"] is False, r)
    check("still returns a verdict", r["clickfix"]["final_verdict"] in ("none", "low", "medium", "high"))
    r2 = rc.confirm_from_evidence("<html></html>", "nonsense")
    check("string evidence -> no crash", isinstance(r2, dict))


def test_reconcile_unknown_vocab_fails_closed():
    print("\n[8] m11: unknown verdict vocabulary retains the static verdict, never downgrades")
    final, direction = rc._reconcile_verdict("critical", "none")
    check("m11 unknown static retained", final == "critical", (final, direction))
    check("m11 direction flags unknown", "unknown" in direction, direction)


for _t in (test_rendered_clipboard_promotes, test_computed_hidden_promotes,
           test_no_evidence_static_authoritative, test_reconcile_directions,
           test_no_renderer_degrades, test_seams_additive,
           test_nondict_evidence_no_crash, test_reconcile_unknown_vocab_fails_closed):
    _t()

if FAILURES:
    print(f"\nFAIL — {len(FAILURES)} check(s) failed:")
    for f in FAILURES:
        print("  -", f)
    sys.exit(1)
print("\nPASS — all render-confirm checks green")


def test_render_confirm():
    """pytest entry point — module body runs the checks at import time."""
    assert not FAILURES, FAILURES
