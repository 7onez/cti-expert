#!/usr/bin/env python3
# Part of the cti-expert WebPivot toolkit.
"""wp_deep_archive.py — exhaustive archival pass for one host.

`pivot_extract` reads a single live/representative capture. This module runs the
DEEP archival collection behind `pivot_extract --deep-archive` and the autonomous
loop's deep seeds, aggregating four passive corpora into one merged pivot/indicator
set so historical, scrubbed, and taken-down selectors are not missed:

  1. Wayback Machine  — full history across the WHOLE domain (subdomains + subpaths,
     HTML + JS/JSON), via wayback_harvest (which now uses matchType=domain).
  2. urlscan.io       — EVERY distinct cached DOM (paginated search + de-duped /dom/),
     not just the newest, plus urlscan's related-domain/IP reverse index.
  3. CommonCrawl      — URL inventory + range-fetched stored response bodies.
  4. archive.today    — every memento (best-effort content fetch).

Passive by construction (touches only the archives, never the target), keyless, and
every source degrades to empty on error — a failing corpus must not abort the pass.

Returns {'pivots', 'indicators', 'meta'}: `pivots` (WebPivot schema) merge into the
collector result so kb_ingest clusters them and the frontier chases new domains;
`indicators` (case schema) roll into the /case IOC bundle.

Lazy imports throughout: wayback_harvest imports pivot_extract at module load, and
pivot_extract imports this module, so importing at call time (after both are loaded)
is what keeps that cycle from deadlocking.
"""
from __future__ import annotations

import sys

try:
    from wp_common import _registrable   # collectors' apex reducer — keep apex logic identical
except Exception:                        # pragma: no cover - degrade, never block
    def _registrable(host):
        parts = (host or "").strip(".").lower().split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else (host or "")


def _host(domain):
    d = (domain or "").strip()
    if "://" in d:
        d = d.split("://", 1)[1]
    d = d.split("/", 1)[0].split("?", 1)[0].strip().lower()
    return d[4:] if d.startswith("www.") else d


def _note(records, kind, value, ts, url, source):
    """Merge one (kind,value) observation, tracking first/last-seen and provenance."""
    if not value:
        return
    key = (kind, value)
    rec = records.get(key)
    if rec is None:
        records[key] = {"kind": kind, "value": value, "first": ts or "", "last": ts or "",
                        "hits": 1, "seen": [ts] if ts else [], "first_url": url,
                        "sources": {source}}
        return
    rec["hits"] += 1
    if ts:
        if ts not in rec["seen"]:
            rec["seen"].append(ts)
        if not rec["first"] or ts < rec["first"]:
            rec["first"], rec["first_url"] = ts, url
        if ts > rec["last"]:
            rec["last"] = ts
    rec["sources"].add(source)


def deep_archive(domain, *, ua=None, max_snaps=25, cdx_limit=2000, root_only=False,
                 include_assets=True, urlscan_pages=5, max_doms=25,
                 commoncrawl=True, cc_indexes=2, cc_records=8,
                 archive_today=True, at_max=6, budget_s=240, free_only=False):
    """Run the full deep archival pass for `domain`. See module docstring."""
    host = _host(domain)
    seed_apex = _registrable(host)
    records: dict = {}
    domains_found: set[str] = set()      # NEW registrable apexes -> frontier
    meta = {"host": host, "wayback_snapshots": 0, "urlscan_doms": 0, "urlscan_scans": 0,
            "cc_records": 0, "cc_fetched": 0, "at_mementos": 0, "sources": []}

    # lazy imports (break the pivot_extract <-> wayback_harvest cycle) --------
    import wayback_harvest as WH
    from wayback_harvest import harvest_html, build_indicators
    import wp_net
    DEFAULT_UA = getattr(wp_net, "DEFAULT_UA", None)
    ua = ua or DEFAULT_UA
    # Overall wall-clock budget. The loop kills the collector subprocess at ~240s
    # (collect_core), and each corpus here does its own network I/O, so cap total work
    # well under that and skip whatever a slow/blocked source would otherwise stall on.
    import time as _time
    _deadline = _time.monotonic() + max(30, budget_s)

    def _over():
        hit = _time.monotonic() > _deadline
        if hit:
            meta["budget_exhausted"] = True
        return hit

    # 1) Wayback — full-history harvest across the whole domain -----------------
    try:
        wb = WH.analyze_domain(host, max_snaps=max_snaps, root_only=root_only,
                               include_assets=include_assets, limit_scan=cdx_limit,
                               with_urlscan=False,
                               fetch_budget=max(20, budget_s * 0.4))
        meta["wayback_snapshots"] = wb.get("snapshots_scanned", 0)
        for r in wb.get("records", []):
            key = (r["kind"], r["value"])
            records[key] = {**r, "sources": {"wayback"}}
        if meta["wayback_snapshots"]:
            meta["sources"].append("wayback")
    except Exception as e:
        print(f"  deep_archive wayback error for {host}: {e}", file=sys.stderr)

    # 2) urlscan — every distinct cached DOM + related-domain reverse ----------
    urlscan_intel = None
    try:
        intel = wp_net.urlscan_intel(host, ua=ua, max_pages=urlscan_pages, free_only=free_only)
        urlscan_intel = intel
        # capability truth: /dom/ is 403 without a key; and under --free-only the (metered) key is
        # deliberately NOT spent — either way the cached-DOM layer yields zero for want of a spent
        # credential, NOT for want of data. Say which, so it never reads as "no historical selectors".
        if free_only:
            meta["urlscan_dom_capability"] = ("free-only — urlscan key not spent (metered index); "
                                              "cached-DOM harvest skipped by policy")
        elif wp_net._secret("URLSCAN_API_KEY"):
            meta["urlscan_dom_capability"] = "keyed"
        else:
            meta["urlscan_dom_capability"] = ("keyless — set URLSCAN_API_KEY to fetch cached DOMs "
                                              "(/dom/ is 403 without it)")
        meta["urlscan_scans"] = len(intel.get("all_scans") or intel.get("recent_scans") or [])
        for d in intel.get("related_domains") or []:
            apex = _registrable(_host(d))
            if apex and apex != seed_apex:
                domains_found.add(("urlscan", apex))
        # cap the DOM phase at ~40% of the budget: a scan-heavy host must not consume the
        # whole budget and starve CommonCrawl + archive.today (which run after this).
        _us_deadline = min(_deadline, _time.monotonic() + max(15, budget_s * 0.4))
        doms = wp_net.urlscan_dom_all(intel, ua=ua, max_doms=max_doms, deadline=_us_deadline,
                                      free_only=free_only)
        meta["urlscan_doms"] = len(doms)
        for d in doms:
            if _over():
                break
            ts = (d.get("time") or "")[:10].replace("-", "")
            for kind, values in harvest_html(d["html"]).items():
                for v in values:
                    _note(records, kind, v, ts, d.get("result") or d.get("url"), "urlscan")
        if meta["urlscan_scans"]:
            meta["sources"].append("urlscan")
    except Exception as e:
        print(f"  deep_archive urlscan error for {host}: {e}", file=sys.stderr)

    # 3) CommonCrawl — URL inventory + range-fetched stored bodies -------------
    if commoncrawl and not _over():
        try:
            import wp_extra_archives as XA
            rows = XA.commoncrawl_index(host, index_count=cc_indexes, ua=ua)
            meta["cc_records"] = len(rows)
            for row in rows:
                apex = _registrable(_host(row.get("url") or ""))
                if apex and apex != seed_apex:
                    domains_found.add(("commoncrawl", apex))
            # sample rows evenly and mine their stored bodies
            picked = rows[:: max(1, len(rows) // cc_records)] if rows else []
            for row in picked[:cc_records]:
                if _over():
                    break
                body = XA.commoncrawl_fetch(row, ua=ua)
                if not body or len(body) < 200:
                    continue
                meta["cc_fetched"] += 1
                ts = (row.get("timestamp") or "")[:8]
                for kind, values in harvest_html(body).items():
                    for v in values:
                        _note(records, kind, v, ts, row.get("url"), "commoncrawl")
            if meta["cc_records"]:
                meta["sources"].append("commoncrawl")
        except Exception as e:
            print(f"  deep_archive commoncrawl error for {host}: {e}", file=sys.stderr)

    # 4) archive.today — mementos (best-effort content) -----------------------
    if archive_today and not _over():
        try:
            import wp_extra_archives as XA
            mems = XA.archive_today_timemap(host, ua=ua)
            meta["at_mementos"] = len(mems)
            for m in mems[-at_max:]:
                if _over():
                    break
                html = XA.archive_today_fetch(m["url"], ua=ua)
                if not html:
                    continue
                for kind, values in harvest_html(html).items():
                    for v in values:
                        _note(records, kind, v, "", m["url"], "archive_today")
            if mems:
                meta["sources"].append("archive_today")
        except Exception as e:
            print(f"  deep_archive archive.today error for {host}: {e}", file=sys.stderr)

    # --- assemble pivots + indicators ----------------------------------------
    record_list = sorted(records.values(), key=lambda r: (r["kind"], -r["hits"], r["value"]))
    pivots = []
    for r in record_list:
        srcs = sorted(r.get("sources", []))
        conf = "high" if (r["hits"] >= 3 or len(srcs) >= 2) else "medium"
        pivots.append({
            "kind": r["kind"], "value": r["value"], "confidence": conf,
            "first_seen": r.get("first") or None, "last_seen": r.get("last") or None,
            "hits": r["hits"],
            "note": f"deep-archive: recovered from {', '.join(srcs)} "
                    f"({r['hits']}× capture(s))",
            "queries": [{"service": "urlscan.io", "query": f'"{r["value"]}"'},
                        {"service": "PublicWWW", "query": f'"{r["value"]}"'}],
        })
    # NEW registrable domains -> frontier-consumable pivots (see case_state miner)
    for source, apex in sorted(domains_found):
        kind = "urlscan_related_domain" if source == "urlscan" else "archive_related_domain"
        pivots.append({
            "kind": kind, "value": apex, "confidence": "medium",
            "note": f"deep-archive: co-domain discovered via {source}",
            "queries": [{"service": "urlscan.io", "query": f"domain:{apex}"},
                        {"service": "crt.sh", "query": f"%.{apex}"}],
        })

    # indicators via the harvest builder (records schema + urlscan related folded in)
    synth = {"domain": host, "records": record_list, "urlscan": urlscan_intel or {}}
    try:
        indicators = build_indicators(synth)
    except Exception:
        indicators = []

    meta["pivots"] = len(pivots)
    meta["indicators"] = len(indicators)
    return {"pivots": pivots, "indicators": indicators, "meta": meta}


def _main(argv=None):
    import argparse
    import json
    ap = argparse.ArgumentParser(description="Deep archival pass (Wayback+urlscan+CC+archive.today).")
    ap.add_argument("domain")
    ap.add_argument("--max-snaps", type=int, default=25)
    ap.add_argument("--max-doms", type=int, default=25)
    ap.add_argument("--urlscan-pages", type=int, default=5)
    ap.add_argument("--root-only", action="store_true")
    ap.add_argument("--no-commoncrawl", action="store_true")
    ap.add_argument("--no-archive-today", action="store_true")
    ap.add_argument("--free-only", action="store_true",
                    help="forbid spending the urlscan credential (metered index) — keyless urlscan")
    ap.add_argument("--pretty", action="store_true")
    a = ap.parse_args(argv)
    res = deep_archive(a.domain, max_snaps=a.max_snaps, max_doms=a.max_doms,
                       urlscan_pages=a.urlscan_pages, root_only=a.root_only,
                       commoncrawl=not a.no_commoncrawl, archive_today=not a.no_archive_today,
                       free_only=a.free_only)
    print(json.dumps(res, indent=2 if a.pretty else None, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(_main())
