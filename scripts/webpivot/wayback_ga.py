#!/usr/bin/env python3
# Part of the WebPivot toolkit by Zeroska — https://github.com/Zeroska
# Adapted for the cti-expert skill by Hieu Ngo (chongluadao.vn).
"""
wayback_ga.py — historical analytics-ID pivoting via the Wayback Machine.

Implements the Bellingcat technique (Using the Wayback Machine and Google
Analytics to Uncover Disinformation Networks, 2024-01-09): a site may have
shared a Google Analytics / AdSense / verification ID with sibling sites in the
PAST, then scrubbed it. A single live snapshot misses that. This walks a
domain's Wayback history, extracts every tracker/verification ID seen over time,
and builds a first-seen/last-seen timeline plus ready-to-run pivot queries.

Complements the Bellingcat / community tool `wayback-google-analytics`
(github.com/Lyra-in-a-Bottle/wayback-google-analytics) — use that for scale/UI;
this is the zero-dependency, harness-native version that reuses the same
extractors as pivot_extract.py.

Usage:
  python3 wayback_ga.py <domain> [--max 12] [--from 2018] [--to 2026] [--timeline] [--pretty]
  python3 wayback_ga.py baoxinviec.info --timeline
  python3 wayback_ga.py -f domains.txt --pretty          # one domain per line

FOR AUTHORIZED INVESTIGATIONS ONLY. All fetches hit web.archive.org, never the
target — this is passive by construction.
"""
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///

import sys
import os
import re
import json
import argparse
import urllib.request
import urllib.error

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pivot_extract import (extract_trackers, VERIFICATION_META, extract_meta,
                           DEFAULT_UA, shodan_favicon_hash)  # reuse the harness

CDX = "http://web.archive.org/cdx/search/cdx"


def cdx_snapshots(domain, year_from=None, year_to=None, limit_scan=800):
    """Return [(timestamp, original_url)] of archived HTML 200s, deduped by digest."""
    q = (f"{CDX}?url={domain}&output=json&fl=timestamp,original,statuscode,digest"
         f"&filter=statuscode:200&filter=mimetype:text/html"
         f"&collapse=digest&limit={limit_scan}")
    if year_from:
        q += f"&from={year_from}"
    if year_to:
        q += f"&to={year_to}"
    try:
        req = urllib.request.Request(q, headers={"User-Agent": DEFAULT_UA})
        with urllib.request.urlopen(req, timeout=40) as r:
            rows = json.load(r)
    except Exception as e:
        print(f"  cdx error for {domain}: {e}", file=sys.stderr)
        return []
    if not rows or len(rows) < 2:
        return []
    return [(row[0], row[1]) for row in rows[1:]]


def sample_evenly(snaps, n):
    """Pick up to n snapshots spread evenly across time (keep first & last)."""
    if len(snaps) <= n:
        return snaps
    step = (len(snaps) - 1) / (n - 1)
    return [snaps[round(i * step)] for i in range(n)]


def fetch_raw(timestamp, original, ua=DEFAULT_UA):
    """Fetch the un-rewritten archived HTML via the id_ modifier."""
    url = f"https://web.archive.org/web/{timestamp}id_/{original}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": ua})
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.read().decode("utf-8", "ignore")
    except Exception:
        return ""


def analyze_domain(domain, max_snaps=12, year_from=None, year_to=None):
    snaps = cdx_snapshots(domain, year_from, year_to)
    picked = sample_evenly(snaps, max_snaps)
    # id -> {"kind":..., "first":ts, "last":ts, "hits":n, "seen":[ts,...]}
    ids = {}

    def note(kind, value, ts):
        key = (kind, value)
        rec = ids.get(key)
        if rec is None:
            ids[key] = {"kind": kind, "value": value, "first": ts, "last": ts,
                        "hits": 1, "seen": [ts]}
        else:
            rec["hits"] += 1
            rec["seen"].append(ts)
            rec["first"] = min(rec["first"], ts)
            rec["last"] = max(rec["last"], ts)

    scanned = 0
    for ts, original in picked:
        html = fetch_raw(ts, original)
        if not html or "<title" not in html.lower() and len(html) < 400:
            continue  # skip empty/placeholder captures
        scanned += 1
        for label, vals in extract_trackers(html).items():
            for v in vals:
                note("tracker:" + label, v, ts)
        meta = extract_meta(html)
        for mk, label in VERIFICATION_META.items():
            if mk in meta:
                note("verification:" + label, meta[mk], ts)

    records = sorted(ids.values(), key=lambda r: (r["kind"], -r["hits"]))
    return {
        "domain": domain,
        "snapshots_total": len(snaps),
        "snapshots_scanned": scanned,
        "span": [snaps[0][0], snaps[-1][0]] if snaps else None,
        "historical_ids": records,
        "pivots": build_pivots(records),
    }


def build_pivots(records):
    out = []
    for r in records:
        val = r["value"]
        out.append({
            "kind": r["kind"], "value": val,
            "first_seen": r["first"], "last_seen": r["last"], "hits": r["hits"],
            "queries": [
                {"service": "PublicWWW", "query": f'"{val}"'},
                {"service": "urlscan.io", "query": f'"{val}"'},
                {"service": "DNSlytics reverse-analytics", "query": val},
                {"service": "NerdyData", "query": f'"{val}"'},
            ],
        })
    return out


def _fmt_ts(ts):
    return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}" if len(ts) >= 8 else ts


def render_timeline(res):
    lines = [f"# Historical analytics IDs — {res['domain']}",
             f"({res['snapshots_scanned']} of {res['snapshots_total']} snapshots scanned"
             + (f", {_fmt_ts(res['span'][0])} → {_fmt_ts(res['span'][1])})" if res['span'] else ")"),
             ""]
    if not res["historical_ids"]:
        lines.append("_No tracker/verification IDs found in sampled snapshots._")
        return "\n".join(lines)
    for r in res["historical_ids"]:
        lines.append(f"- **{r['kind']}** `{r['value']}`  "
                     f"seen {r['hits']}× | {_fmt_ts(r['first'])} → {_fmt_ts(r['last'])}")
        lines.append(f"    pivot: PublicWWW `\"{r['value']}\"` · DNSlytics reverse-analytics")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Historical analytics-ID pivoting via Wayback (Bellingcat method).")
    ap.add_argument("domain", nargs="?", help="domain, e.g. example.com")
    ap.add_argument("-f", "--file", help="file of domains, one per line")
    ap.add_argument("--max", type=int, default=12, help="max snapshots to sample per domain")
    ap.add_argument("--from", dest="yfrom", help="earliest year, e.g. 2018")
    ap.add_argument("--to", dest="yto", help="latest year, e.g. 2026")
    ap.add_argument("--timeline", action="store_true", help="markdown timeline instead of JSON")
    ap.add_argument("--pretty", action="store_true")
    args = ap.parse_args()

    domains = []
    if args.file:
        with open(args.file) as fh:
            domains = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    elif args.domain:
        domains = [args.domain]
    else:
        ap.error("provide a domain or -f file")

    results = [analyze_domain(d, args.max, args.yfrom, args.yto) for d in domains]

    if args.timeline:
        print("\n\n".join(render_timeline(r) for r in results))
        return
    out = results[0] if len(results) == 1 else results
    print(json.dumps(out, indent=2 if args.pretty else None, ensure_ascii=False))


if __name__ == "__main__":
    main()
