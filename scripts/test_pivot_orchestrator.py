#!/usr/bin/env python3
"""Classification + edge-matrix checks for the pivot orchestrator.

Contributor RULE 5: any change to the pivot/clustering logic ships with a check.
This one is dependency-free — run it directly:

    python3 scripts/test_pivot_orchestrator.py      (or: uv run …)

It guards two things:
  1. New forensics/identity identifier types classify correctly and do not
     regress the existing ones (esp. a .pdf/.jpg link must type as document/image,
     NOT as a generic url).
  2. THE INVARIANT: no auto-classified identifier type is silently dead-ended —
     every type classify() can return must have at least one EDGE_MATRIX action.
     This is exactly the bug class the document/image/ipv6/coordinates/vin/
     youtube_channel wiring fixed; the invariant keeps it fixed.
"""
import importlib.util
import pathlib
import sys

_MOD = pathlib.Path(__file__).with_name("pivot_orchestrator.py")
_spec = importlib.util.spec_from_file_location("pivot_orchestrator", _MOD)
po = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(po)

failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)


# 1. classification — new types ------------------------------------------------
CLASSIFY_CASES = {
    # documents (URL and bare filename) route to forensics, not `url`
    "https://acme.example/quarterly-report.pdf": "document",
    "invoice.DOCX": "document",
    "https://acme.example/sheet.xlsx?dl=1": "document",
    # images
    "https://cdn.example/team/photo.JPG": "image",
    "avatar.png": "image",
    "https://cdn.example/logo.svg#v2": "image",
    # previously typed-but-dead-ended trio
    "37.7749,-122.4194": "coordinates",
    "1HGCM82633A004352": "vin",
    "UCXuqSBlHAE6Xw-yeJA0Tunw": "youtube_channel",
    # regression: these must NOT be captured by the new document/image patterns
    "user@example.com": "email",
    "https://example.com/": "url",
    "https://example.com/index.html": "url",
    "example.com": "domain",
    "203.0.113.5": "ipv4",
    "2001:db8::1": "ipv6",
}
for value, expected in CLASSIFY_CASES.items():
    got = po.classify(value)
    check(got == expected, f"classify({value!r}) -> {got!r}, expected {expected!r}")

# 2. new edges carry the intended yields --------------------------------------
def yields_of(t):
    return {y for a in po.EDGE_MATRIX.get(t, []) for y in a["yields"]}

check({"person", "email", "org", "coordinates"} <= yields_of("document"),
      "document edge must yield person/email/org/coordinates")
check("coordinates" in yields_of("image") and "person" in yields_of("image"),
      "image edge must yield coordinates (EXIF) and person (face/reverse)")
check({"domain", "email"} <= yields_of("youtube_channel"),
      "youtube_channel edge must yield domain/email")
check(yields_of("ipv6") == {"domain", "asn", "ipv6"},
      "ipv6 edge must mirror ipv4 (domain/asn)")
# terminal-enrichment types: actioned but deliberately spawn no new seed
for t in ("coordinates", "vin"):
    check(len(po.EDGE_MATRIX.get(t, [])) >= 1, f"{t} must have >=1 action (not dead-ended)")
    check(yields_of(t) == set(), f"{t} is enrichment-only; must yield no new seed")

# 3. THE INVARIANT — no auto-classified type is dead-ended --------------------
# Every type classify() can return (all _RX keys + the three text fallbacks) must
# have an EDGE_MATRIX entry. "unknown" is the sole intentional no-pivot sink.
classifiable = set(po._RX.keys()) | {"person", "username", "cn_name"}
for t in sorted(classifiable):
    check(t in po.EDGE_MATRIX and len(po.EDGE_MATRIX[t]) >= 1,
          f"INVARIANT: type {t!r} is classifiable but has no EDGE_MATRIX pivot (dead-ended)")

# ---------------------------------------------------------------------------
if failures:
    print(f"FAIL — {len(failures)} check(s):")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1)
print(f"OK — {len(CLASSIFY_CASES)} classify cases + edge/invariant checks passed "
      f"({len(po.EDGE_MATRIX)} identifier types wired).")
