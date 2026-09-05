#!/usr/bin/env python3
"""
wp_psl_update.py — refresh references/public_suffix_list.json from publicsuffix.org.

WHY
---
`wp_common._registrable` (the eTLD+1 reducer every collector, the KB ingester and the frontier
key on) needs the real Public Suffix List. Without it, `horizon.io.vn` reduces to `io.vn`,
`zc2.sa.com` to `sa.com`, `kit.pages.dev` to `pages.dev` — collapsing every unrelated tenant of
a second-level registry or hosting platform into ONE fake apex, which then gets enumerated and
collected as if it were the operator's domain. That is exactly how a case drifts into hundreds
of strangers' hosts.

The list is reference DATA (RULE 3): this script only fetches and re-shapes it. Rule syntax is
kept verbatim (`*.ck` wildcards, `!www.ck` exceptions); ICANN and PRIVATE sections are stored
separately so a caller can tell a registry suffix from a hosting-platform suffix.

Usage:
  python3 WebPivot/tools/wp_psl_update.py            # fetch + write (network: publicsuffix.org)
  python3 WebPivot/tools/wp_psl_update.py --from public_suffix_list.dat   # offline re-shape
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(os.path.dirname(HERE), "references", "public_suffix_list.json")
SOURCE = "https://publicsuffix.org/list/public_suffix_list.dat"


def parse(text: str) -> tuple[list[str], list[str]]:
    icann, private = [], []
    bucket = icann
    for raw in text.splitlines():
        line = raw.strip()
        if "BEGIN PRIVATE DOMAINS" in line:
            bucket = private
            continue
        if not line or line.startswith("//"):
            continue
        bucket.append(line.split()[0].lower())
    return icann, private


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--from", dest="src", help="local public_suffix_list.dat instead of fetching")
    ap.add_argument("-o", "--out", default=OUT)
    a = ap.parse_args()
    if a.src:
        text = open(a.src, encoding="utf-8").read()
    else:
        sys.path.insert(0, HERE)
        import wp_common  # noqa: F401,E402 — proxy policy + timeout floor for the fetch
        with urllib.request.urlopen(SOURCE, timeout=60) as r:
            text = r.read().decode("utf-8")
    icann, private = parse(text)
    if len(icann) < 5000 or len(private) < 2000:
        sys.exit(f"refusing to write a suspiciously short list ({len(icann)} icann / {len(private)} private rules)")
    doc = {
        "_comment": ("Mozilla Public Suffix List, re-shaped for wp_common._registrable (eTLD+1). Rules keep "
                     "the PSL syntax: a bare suffix, '*.<suffix>' (one extra label is part of the suffix), "
                     "'!<name>' (exception: that name is registrable). `icann` = registry-operated suffixes "
                     "(co.uk, com.vn, io.vn, sa.com …); `private` = hosting/SaaS platforms whose tenants are "
                     "separately-owned sites (github.io, pages.dev, blogspot.com …). generic_labels.json → "
                     "multi_part_tlds is merged on top as an analyst override. Refresh with "
                     "WebPivot/tools/wp_psl_update.py — never edit by hand."),
        "source": SOURCE,
        "fetched_utc": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "icann": {"_comment": "ICANN section — registry-operated public suffixes.", "values": icann},
        "private": {"_comment": "PRIVATE section — hosting/SaaS platform suffixes (tenant = registrable unit).",
                    "values": private},
    }
    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=0)
        fh.write("\n")
    print(f"wrote {a.out}: {len(icann)} icann + {len(private)} private rules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
