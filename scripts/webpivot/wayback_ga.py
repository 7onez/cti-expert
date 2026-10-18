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
import wp_wayback  # noqa: E402 (WebPivot/tools now on sys.path via the pivot_extract shim)
import wp_wayback_guard  # noqa: E402


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


def _cdx_fetch(host, mime_re, limit_scan, root_only, collapse, year_from, year_to, report=None,
               newest=False):
    """One index query for a single mimetype group → list of (timestamp, original). [] when the
    archive holds nothing OR did not answer; in the latter case the reason is printed and
    appended to report["errors"] (wp_wayback already retried every index endpoint). A result that
    fills `limit_scan` sets report["truncated"]. `newest` asks for the LAST `limit_scan` rows."""
    q = [("url", host), ("output", "json"), ("fl", "timestamp,original,statuscode,digest,mimetype"),
         ("filter", "statuscode:200"), ("collapse", collapse),
         ("limit", f"-{int(limit_scan)}" if newest else limit_scan),
         ("filter", f"mimetype:{mime_re}")]
    if not root_only:
        q.append(("matchType", "domain"))   # widen url=host to *.host + every path
    if year_from:
        q.append(("from", year_from))
    if year_to:
        q.append(("to", year_to))
    rows, err = wp_wayback.index(q, ua=DEFAULT_UA, timeout=120)
    if err:
        print(f"  cdx error for {host}: {err}", file=sys.stderr)
        if report is not None:
            report.setdefault("errors", []).append(err)
        return []
    if report is not None and not newest and len(rows) >= int(limit_scan):
        report["truncated"] = True
    return [(row[0], row[1]) for row in rows if len(row) >= 2]


# rows of the apex's own newest captures merged in when a whole-domain query hits its row cap
_TOPUP_ROWS = wp_wayback.TOPUP_ROWS


def cdx_snapshots(domain, year_from=None, year_to=None, limit_scan=2000,
                  root_only=False, include_assets=True, collapse="digest", report=None):
    """Archived 200 captures for a domain -> [(timestamp, original_url)], time-sorted.

    By default this covers the WHOLE registrable domain — every subdomain and subpath
    (CDX matchType=domain) — and includes archived JS/JSON, not just HTML, because
    selectors routinely live in those. HTML and assets are fetched as SEPARATE capped
    queries and merged, so an HTML-saturated domain (whose html rows would fill the row cap
    ahead of assets in SURT order) never crowds the JS/JSON out. Deduped by `collapse`
    (digest = distinct content; urlkey = one row per URL). Pass root_only=True for the legacy
    exact-apex behaviour, or include_assets=False to restrict to text/html.

    The index returns a whole-domain query in URL order, oldest first per URL, so a query that
    fills `limit_scan` silently loses later URLs and recent years (measured: iana.org's 2000 html
    rows end in 2020 though captures run to 2026). When that happens the apex's own newest html
    captures are merged in (one extra query) and report["truncated"] is set — the span is then
    NOT the whole history. Pass a dict as `report` to also learn whether an empty result is a real
    'no captures' (no "errors" key) or an archive that did not answer (report["errors"])."""
    host = _cdx_host(domain)
    groups = [_CDX_HTML_RE] + ([_CDX_ASSET_RE] if include_assets else [])
    report = report if report is not None else {}
    seen = set()
    snaps = []

    def _add(pairs):
        for key in pairs:
            if key not in seen:
                seen.add(key)
                snaps.append(key)

    for mime_re in groups:
        _add(_cdx_fetch(host, mime_re, limit_scan, root_only, collapse, year_from, year_to, report))
    if report.get("truncated") and not root_only:
        _add(_cdx_fetch(host, _CDX_HTML_RE, min(_TOPUP_ROWS, int(limit_scan)), True, collapse,
                        year_from, year_to, report, newest=True))
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
    """Fetch the un-rewritten archived HTML via the id_ modifier ('' when not fetched)."""
    resp, _err = wp_wayback.fetch(timestamp, original, ua=ua, timeout=timeout)
    if resp is None or resp.status != 200:
        return ""
    return resp.body.decode("utf-8", "ignore")


def analyze_domain(domain, max_snaps=12, year_from=None, year_to=None,
                   root_only=False, include_assets=True, limit_scan=2000):
    _breaker = wp_wayback_guard.blocked() if wp_wayback_guard is not None else None
    if _breaker:
        return {
            "domain": domain, "snapshots_total": 0, "snapshots_scanned": 0, "span": None,
            "historical_ids": [], "pivots": [],
            "skipped": _breaker, "skipped_kind": "breaker",
        }
    cdx_report = {}
    snaps = cdx_snapshots(domain, year_from, year_to, limit_scan=limit_scan,
                          root_only=root_only, include_assets=include_assets, report=cdx_report)
    cdx_errors = cdx_report.get("errors") or []
    if cdx_errors and not snaps:
        # the archive never answered: a GAP (nothing queried), never "no history"
        return {
            "domain": domain, "snapshots_total": 0, "snapshots_scanned": 0, "span": None,
            "historical_ids": [], "pivots": [],
            "skipped": cdx_errors[0], "skipped_kind": "breaker",
        }
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
        # the index row cap was hit: the span/sample is NOT the whole history (see cdx_snapshots)
        "truncated": bool(cdx_report.get("truncated")),
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
    if res.get("skipped"):
        lines.append(f"_Archive NOT queried — {res['skipped']}. This is a gap, not an empty "
                     f"history: re-run later._")
        return "\n".join(lines)
    if res.get("truncated"):
        lines.append("_Index row cap hit — this is NOT the whole capture history (the apex's newest "
                     "captures were merged in). Narrow with --from/--to per era for full coverage._")
        lines.append("")
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
