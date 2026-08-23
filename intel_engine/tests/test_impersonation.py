#!/usr/bin/env python3
"""Impersonation / typosquat generation tests (PRD criteria ISC-32, ISC-33).

`wp_impersonate` turns ONE seed domain into the lookalike domains an operator would register to
impersonate a brand (typosquats, combosquats, TLD sweep). Its generation engine is pure and
deterministic — no network — which is exactly the part worth pinning: a regression here either
floods the operator with junk candidates or silently drops a whole technique class, and neither
shows up until a real hunt misses a lookalike.

This file exercises ONLY the offline, pure functions:
  * split_registrable(domain)          — brand-label / TLD split (multi-part-TLD aware)
  * _typo_variants(label)              — {mutation: technique} in-label typosquats
  * generate_variants(domain, max=...) — ordered, capped candidate set + metadata

It never touches build_impersonation_result / crtsh_keyword_hunt / check_existence / the
FOFA / urlscan sweeps — those hit DNS / CT / metered APIs and have no place in a unit test.

Run:  python3 tests/test_impersonation.py      (zero deps, no pytest needed)
      .venv/bin/pytest tests/test_impersonation.py -q   (also works)

No case data here — only obvious placeholders (`example.com`, `moon`, `brandname`) as CLAUDE.md
RULE 1 requires: skills and their tests carry tradecraft, never a real brand or scam domain.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "WebPivot", "tools"))

import wp_impersonate  # noqa: E402

FAILURES = []


def check(label, got, want):
    if got != want:
        FAILURES.append(f"{label}: got {got!r}, want {want!r}")


# ---------------------------------------------------------------------------
# 1. split_registrable — brand label vs TLD suffix, multi-part-TLD aware (ISC-32).
#
# The brand label is what the engine permutes; the TLD is what it keeps for typo variants and
# swaps out for the sweep. Getting the eTLD+1 boundary wrong (e.g. treating 'com.vn' as label
# 'com') would permute the wrong token and generate nonsense.
# ---------------------------------------------------------------------------
check("split example.com", wp_impersonate.split_registrable("example.com"), ("example", "com"))
check("split multi-part TLD shop.example.com.vn",
      wp_impersonate.split_registrable("shop.example.com.vn"), ("example", "com.vn"))
check("split strips www www.example.net",
      wp_impersonate.split_registrable("www.example.net"), ("example", "net"))


# ---------------------------------------------------------------------------
# 2. _typo_variants — every documented technique class is actually emitted (ISC-33).
#
# The function returns {mutation_string: technique}. A missing technique means that whole class
# of lookalike is never generated, so we assert the technique VALUES cover the full set.
# ---------------------------------------------------------------------------
tv = wp_impersonate._typo_variants("example")
tv_techniques = set(tv.values())
REQUIRED_TECHNIQUES = [
    "omission", "insertion", "replacement", "transposition",
    "repetition", "homoglyph", "hyphenation", "vowel-swap",
]
for tech in REQUIRED_TECHNIQUES:
    check(f"_typo_variants emits technique {tech!r}", tech in tv_techniques, True)


# ---------------------------------------------------------------------------
# 3. _typo_variants hygiene — never yields the original label, and every key is ASCII.
#
# The seed itself is not a "variant"; and a non-ASCII (IDN/punycode) key here would mean the
# ASCII-confusable engine leaked a Unicode mutation it can't reason about.
# ---------------------------------------------------------------------------
check("_typo_variants excludes the original label", "example" in tv, False)
check("_typo_variants keys are all ASCII", all(k.isascii() for k in tv), True)


# ---------------------------------------------------------------------------
# 4. generate_variants — shape, metadata, and technique coverage at a non-truncating cap.
#
# max_variants=600 is well above the ~200 candidates 'example' produces, so nothing is dropped:
# the seed must be absent, every entry well-formed, count consistent, and both the combosquat
# and TLD-sweep passes represented.
# ---------------------------------------------------------------------------
gen = wp_impersonate.generate_variants("example.com", max_variants=600)
for key in ("seed", "label", "tld", "variants", "count", "truncated"):
    check(f"generate_variants result has key {key!r}", key in gen, True)
check("generate_variants label", gen["label"], "example")
check("generate_variants tld", gen["tld"], "com")

variant_domains = [v["domain"] for v in gen["variants"]]
check("seed absent from variants", "example.com" in variant_domains, False)
check("every variant has 'domain' and 'technique'",
      all(isinstance(v, dict) and "domain" in v and "technique" in v for v in gen["variants"]),
      True)

gen_techniques = set(v["technique"] for v in gen["variants"])
check("generate_variants includes 'tld-sweep' (not truncated)",
      "tld-sweep" in gen_techniques, True)
check("generate_variants includes 'combosquat' (not truncated)",
      "combosquat" in gen_techniques, True)
check("generate_variants count == len(variants)", gen["count"], len(gen["variants"]))
check("generate_variants not truncated at max=600", gen["truncated"], False)


# ---------------------------------------------------------------------------
# 5. generate_variants — the cap is enforced and reported.
# ---------------------------------------------------------------------------
capped = wp_impersonate.generate_variants("example.com", max_variants=10)
check("generate_variants honours max_variants=10", len(capped["variants"]), 10)
check("generate_variants reports truncated at max=10", capped["truncated"], True)
check("generate_variants count matches cap", capped["count"], 10)


# ---------------------------------------------------------------------------
# 6. Homoglyph substitution — the o->0 visual confusable actually fires.
#
# NOTE: the engine applies ONE edit per mutation, so 'moon' yields 'm0on' and 'mo0n' (a single
# o->0), never 'm00n' (that would be a two-edit mutation the single-edit engine does not emit).
# We assert the real single-edit homoglyph output, tagged as the 'homoglyph' technique.
# ---------------------------------------------------------------------------
moon = wp_impersonate._typo_variants("moon")
check("_typo_variants('moon') yields o->0 homoglyph 'm0on'", "m0on" in moon, True)
check("'m0on' is tagged as a homoglyph", moon.get("m0on"), "homoglyph")


# ---------------------------------------------------------------------------
if FAILURES:
    print(f"FAIL — {len(FAILURES)} impersonation check(s) failed:")
    for f in FAILURES:
        print("  -", f)
    sys.exit(1)
print("PASS — all impersonation checks green "
      f"({len(REQUIRED_TECHNIQUES)} technique classes, "
      f"{gen['count']} generated variants for the example seed)")


def test_impersonation():
    """pytest entry point — the module body does the work at import time."""
    assert not FAILURES, FAILURES
