#!/usr/bin/env python3
"""Regression: a DISTINCTIVE page <title> is emitted as a reverse-search pivot; generic ones are not.

Two halves, both pinning REAL runtime behaviour (not a helper nothing calls):
  1. EMIT PATH (the fix): wp_pivots.build_pivots() must put a `kind:"title"` pivot into the pivots
     list for a distinctive title, and MUST NOT for a generic/echo/CMS-default one. This is the
     entry that lands in every raw collection JSON, so a unique title can actually pivot.
  2. SPIDER ACTION: pivot_orchestrator.EDGE_MATRIX["title"] exists and yields a domain, so the
     emitted title has a reverse action (FOFA/urlscan) to run.

Zero deps (both modules import stdlib-only):  python3 tests/test_title_pivot.py
No case data — synthetic placeholder titles/hosts only (CLAUDE.md RULE 5).
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "intel_engine", "WebPivot", "tools"))
sys.path.insert(0, os.path.join(HERE, "..", "scripts"))

import wp_pivots as wp          # noqa: E402  — the collector that emits pivots
import pivot_orchestrator as po  # noqa: E402  — the spider that acts on them

FAILURES = []


def check(label, got, want):
    if got != want:
        FAILURES.append(f"{label}: got {got!r}, want {want!r}")


def _title_kinds(title, host):
    """kinds of pivots build_pivots emits for a page carrying just this <title>."""
    return [p["kind"] for p in wp.build_pivots({"title": title}, host)]


def main():
    # 1. EMIT PATH — distinctive titles produce a kind:"title" pivot in the raw pivots list
    good = [
        ("Acme Group Careers Application Portal", "acme-careers.example"),
        ("Tuyển dụng Acme Group 2026 - Nộp hồ sơ trực tuyến", "recruit-acme.example"),
        ("投资理财平台 - 高收益保证", "invest-demo.example"),
    ]
    for title, host in good:
        check(f"distinctive gate keeps: {title!r}", bool(wp._distinctive_title(title, host)), True)
        check(f"build_pivots emits kind:title for {title!r}",
              "title" in _title_kinds(title, host), True)

    # ...and never for a generic / host-echo / junk title
    bad = [
        ("Home", "x.example"),
        ("Just another WordPress site", "blog.example"),
        ("", "x.example"),
        ("kit-apex", "kit-apex.example"),            # echoes the host base
        ("acme-careers.example", "acme-careers.example"),  # echoes the full host
        ("Login", "portal.example"),
        ("2026", "x.example"),                        # pure numeric
        ("Shop", "store.example"),                    # single generic word
    ]
    for title, host in bad:
        check(f"generic gate rejects: {title!r}", wp._distinctive_title(title, host), None)
        check(f"build_pivots emits NO title for {title!r}",
              "title" in _title_kinds(title, host), False)

    # the emitted pivot carries a ready-to-run reverse query (FOFA title=)
    pivs = [p for p in wp.build_pivots({"title": "Acme Group Careers Application Portal"},
                                       "acme-careers.example") if p["kind"] == "title"]
    check("title pivot carries reverse queries", bool(pivs and pivs[0].get("queries")), True)
    check("title pivot has a FOFA title= query",
          any('title="' in q.get("query", "") for q in (pivs[0]["queries"] if pivs else [])), True)

    # 2. SPIDER ACTION — the emitted title has a reverse pivot to run, and dedups case-insensitively
    check("EDGE_MATRIX has a title pivot", bool(po.EDGE_MATRIX.get("title")), True)
    check("title pivot yields a domain", "domain" in po.EDGE_MATRIX["title"][0]["yields"], True)
    check("title normalises for dedup",
          po.key_of("Big   Brand   Portal", "title"), "title:big brand portal")

    if FAILURES:
        print("FAIL:")
        for f in FAILURES:
            print("  -", f)
        sys.exit(1)
    print("ok - title pivot (emit + action)")


if __name__ == "__main__":
    main()
