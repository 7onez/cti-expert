#!/usr/bin/env python3
"""Which case(s) does an artifact already appear in? — a cross-case provenance lookup.

The KB stores facts sourced to a collector but NOT to a case, so on its own it can't answer
"I'm about to pivot on favicon:123456789 / site-a.example — where have I seen this before?". That
mapping does exist on disk: every collected host lives at cases/<case>/raw/<host>.json. This
builds a derived index over those files — domain -> cases, and indicator -> (case, host) — so
when an analyst pivots or searches a known artifact they immediately get its prior case context
instead of re-investigating it cold. Reuses the KB's noise-filtered indicator extractor so the
indicator strings match what the KB clusters on.

Usage:
  python3 tools/case_index.py site-a.example          # a domain
  python3 tools/case_index.py favicon:123456789       # an indicator
  python3 tools/case_index.py --json wallet:eth:0x...
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from urllib.parse import urlparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools", "kb"))
try:
    from convergence import _indicators_from_raw  # same noise-filtered extractor the KB uses
except Exception:  # noqa: BLE001
    def _indicators_from_raw(_obj):
        return set()


def _host(s: str) -> str:
    s = s.strip()
    if "://" in s:
        s = urlparse(s).hostname or s
    return s.split("/")[0].lower()


def _case_of(path: str) -> str:
    parts = os.path.normpath(path).split(os.sep)
    return parts[parts.index("cases") + 1] if "cases" in parts else "?"


def _iter_raw():
    for path in glob.glob(os.path.join(ROOT, "cases", "*", "raw", "*.json")):
        try:
            obj = json.load(open(path, encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        host = (obj.get("meta") or {}).get("host") or os.path.basename(path)[:-5]
        yield _case_of(path), host, obj


def lookup(artifact: str) -> dict:
    """Return the case(s) an artifact appears in. `artifact` is a domain/URL, or an indicator
    string like 'favicon:<h>', 'ga:<id>', 'wallet:<coin>:<addr>', 'email:<addr>', 'social:...'."""
    art = artifact.strip()
    is_indicator = ("://" not in art) and (":" in art)

    if is_indicator:
        locs = []  # (case, host)
        for case, host, obj in _iter_raw():
            if art in _indicators_from_raw(obj):
                locs.append({"case": case, "host": host})
        cases = sorted({l["case"] for l in locs})
        return {"artifact": art, "kind": "indicator", "cases": cases,
                "locations": sorted(locs, key=lambda l: (l["case"], l["host"])),
                "seen": bool(locs)}

    host = _host(art)
    hits = []  # (case, path)
    for case, h, _ in _iter_raw():
        if h == host:
            hits.append(case)
    cases = sorted(set(hits))
    return {"artifact": host, "kind": "domain", "cases": cases,
            "locations": [{"case": c, "host": host} for c in cases], "seen": bool(cases)}


def _human(r: dict) -> str:
    if not r["seen"]:
        return f"{r['artifact']} ({r['kind']}): NOT seen in any existing case — treat as new."
    head = (f"{r['artifact']} ({r['kind']}): seen in {len(r['cases'])} case(s) → "
            f"{', '.join(r['cases'])}")
    if r["kind"] == "indicator":
        by = {}
        for l in r["locations"]:
            by.setdefault(l["case"], []).append(l["host"])
        lines = [f"  · {c}: {', '.join(sorted(hs))}" for c, hs in sorted(by.items())]
        return head + "\n" + "\n".join(lines)
    return head


def _main() -> None:
    ap = argparse.ArgumentParser(description="which case(s) an artifact appears in")
    ap.add_argument("artifact", help="domain/URL or indicator (favicon:<h>, ga:<id>, wallet:<c>:<a>, email:<a>)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    r = lookup(a.artifact)
    print(json.dumps(r, ensure_ascii=False, indent=2) if a.json else _human(r))


if __name__ == "__main__":
    _main()
