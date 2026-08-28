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
  python3 wayback_ga.py example.com --timeline
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

# --- egress proxy / rotation: route outbound HTTP through the /proxy pool ----
def _install_cti_proxy():
    import os as _o, sys as _s
    _b = _o.path.dirname(_o.path.abspath(__file__))
    for _ in range(6):
        _c = _o.path.join(_b, "proxy", "cti_proxy.py")
        if _o.path.isfile(_c):
            _s.path.insert(0, _o.path.dirname(_c))
            try:
                import cti_proxy
                cti_proxy.install()
            except Exception:
                pass
            return
        _p = _o.path.dirname(_b)
        if _p == _b:
            return
        _b = _p
_install_cti_proxy()

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pivot_extract import (extract_trackers, VERIFICATION_META, extract_meta,
                           DEFAULT_UA, shodan_favicon_hash)  # reuse the harness

CDX = "http://web.archive.org/cdx/search/cdx"


# mimetypes worth harvesting: HTML plus the JS/JSON where selectors (GA/GTM IDs, wallet
# addresses, API endpoints, config blobs) frequently live. text/html-only silently drops them.
_CDX_HTML_RE = "(text/html|application/xhtml.*)"
_CDX_ASSET_RE = "(text/javascript|application/javascript|application/x-javascript|application/json)"
# combined (accepted verbatim by CDX; kept for callers/tests that want one filter string)
_CDX_MIME_RE = "(text/html|application/xhtml.*|text/javascript|application/javascript|application/json)"


def _cdx_host(domain):
    """Bare host for a CDX query: strip scheme, path, query, and a leading www."""
    d = (domain or "").strip()
    if "://" in d:
        d = d.split("://", 1)[1]
    d = d.split("/", 1)[0].split("?", 1)[0].strip().lower()
    return d[4:] if d.startswith("www.") else d


def _cdx_fetch(host, mime_re, limit_scan, root_only, collapse, year_from, year_to):
    """One CDX call for a single mimetype group → list of (timestamp, original). [] on error."""
    q = (f"{CDX}?url={host}&output=json&fl=timestamp,original,statuscode,digest,mimetype"
         f"&filter=statuscode:200&collapse={collapse}&limit={limit_scan}"
         f"&filter=mimetype:{mime_re}")
    if not root_only:
        q += "&matchType=domain"        # widen url=host to *.host + every path
    if year_from:
        q += f"&from={year_from}"
    if year_to:
        q += f"&to={year_to}"
    try:
        req = urllib.request.Request(q, headers={"User-Agent": DEFAULT_UA})
        with urllib.request.urlopen(req, timeout=120) as r:
            rows = json.load(r)
    except Exception as e:
        print(f"  cdx error for {host}: {e}", file=sys.stderr)
        return []
    if not rows or len(rows) < 2:
        return []
    return [(row[0], row[1]) for row in rows[1:] if len(row) >= 2]


def cdx_snapshots(domain, year_from=None, year_to=None, limit_scan=2000,
                  root_only=False, include_assets=True, collapse="digest"):
    """Archived 200 captures for a domain -> [(timestamp, original_url)], time-sorted.

    By default this covers the WHOLE registrable domain — every subdomain and subpath
    (CDX matchType=domain) — and includes archived JS/JSON, not just HTML, because
    selectors routinely live in those. HTML and assets are fetched as SEPARATE capped
    queries and merged, so an HTML-saturated domain (whose html rows would fill the row cap
    ahead of assets in SURT order) never crowds the JS/JSON out. Deduped by `collapse`
    (digest = distinct content; urlkey = one row per URL). Pass root_only=True for the legacy
    exact-apex behaviour, or include_assets=False to restrict to text/html."""
    host = _cdx_host(domain)
    groups = [_CDX_HTML_RE] + ([_CDX_ASSET_RE] if include_assets else [])
    seen = set()
    snaps = []
    for mime_re in groups:
        for ts, orig in _cdx_fetch(host, mime_re, limit_scan, root_only, collapse, year_from, year_to):
            key = (ts, orig)
            if key in seen:
                continue
            seen.add(key)
            snaps.append(key)
    # matchType=domain returns rows grouped by URL, so sort chronologically to keep
    # sample_evenly's "spread across time, keep first & last".
    snaps.sort(key=lambda t: t[0])
    return snaps


def sample_evenly(snaps, n):
    """Pick up to n snapshots spread evenly across time (keep first & last)."""
    if len(snaps) <= n:
        return snaps
    if n <= 1:                       # n==1 → one sample; avoids /(n-1) ZeroDivisionError
        return snaps[:n]
    step = (len(snaps) - 1) / (n - 1)
    return [snaps[round(i * step)] for i in range(n)]


def fetch_raw(timestamp, original, ua=DEFAULT_UA, timeout=45):
    """Fetch the un-rewritten archived HTML via the id_ modifier."""
    url = f"https://web.archive.org/web/{timestamp}id_/{original}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": ua})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", "ignore")
    except Exception:
        return ""


def analyze_domain(domain, max_snaps=12, year_from=None, year_to=None,
                   root_only=False, include_assets=True, limit_scan=2000):
    snaps = cdx_snapshots(domain, year_from, year_to, limit_scan=limit_scan,
                          root_only=root_only, include_assets=include_assets)
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
    ap.add_argument("--root-only", action="store_true",
                    help="legacy exact-apex scan (no subdomains/subpaths); faster, narrower")
    ap.add_argument("--html-only", action="store_true",
                    help="restrict to text/html captures (skip archived JS/JSON)")
    ap.add_argument("--limit-scan", type=int, default=2000, help="max CDX rows to pull")
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

    results = [analyze_domain(d, args.max, args.yfrom, args.yto,
                              root_only=args.root_only, include_assets=not args.html_only,
                              limit_scan=args.limit_scan) for d in domains]

    if args.timeline:
        print("\n\n".join(render_timeline(r) for r in results))
        return
    out = results[0] if len(results) == 1 else results
    print(json.dumps(out, indent=2 if args.pretty else None, ensure_ascii=False))


if __name__ == "__main__":
    main()
