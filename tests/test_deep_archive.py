#!/usr/bin/env python3
"""test_deep_archive.py — gate on the exhaustive-archival pass (0-4).

Run:  python3 tests/test_deep_archive.py      (zero deps, network fully mocked)
      pytest tests/test_deep_archive.py -q     (also works)

WHAT THIS PROTECTS
------------------
  0. urlscan_intel PAGINATES with search_after (a host with >1 page of scans is not
     truncated to one), and urlscan_dom_all fetches EVERY distinct cached DOM (de-duped
     by content sha256).
  1. cdx_snapshots widens to the WHOLE domain (matchType=domain), includes archived
     JS/JSON, and time-sorts; --root-only/--html-only restore the legacy narrow scan.
  2. the harvest samples per-URL, not just the apex (falls out of matchType=domain).
  4. CommonCrawl WARC bodies parse; archive.today TimeMap parses.
  3. deep_archive merges all four corpora and emits FRONTIER-consumable domain pivots
     (urlscan_related_domain / archive_related_domain) that case_state actually mines,
     with the seed apex excluded; indicators are built for the IOC bundle.
"""
import gzip
import io
import json
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
# scripts/webpivot FIRST so `import wayback_ga`/`wayback_harvest`/`pivot_extract` resolve to the
# canonical copies; WebPivot/tools supplies wp_net/wp_extra_archives/wp_deep_archive.
for _p in (os.path.join(ROOT, "scripts", "webpivot"),
           os.path.join(ROOT, "intel_engine", "WebPivot", "tools"),
           os.path.join(ROOT, "intel_engine", "tools")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

FAILURES = []


def check(label, cond, detail=""):
    if cond:
        print("  ok   {}".format(label))
    else:
        print("  FAIL {} {}".format(label, detail))
        FAILURES.append(label)


class _Resp(io.BytesIO):
    def __init__(self, data, headers=None):
        super().__init__(data if isinstance(data, bytes) else data.encode())
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _patch_urlopen(router):
    """Patch urllib.request.urlopen with a router(url, req)->_Resp; return (calls, restore)."""
    calls = []
    orig = urllib.request.urlopen

    def _u(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else req
        calls.append(url)
        return router(url, req)

    urllib.request.urlopen = _u
    return calls, (lambda: setattr(urllib.request, "urlopen", orig))


# --- 0. urlscan pagination + all-DOM dedup ------------------------------------------------
import wp_net  # noqa: E402


def test_urlscan_pagination_and_dom_dedup():
    p1 = {"total": 150, "has_more": True, "results": [
        {"_id": f"id{i}", "page": {"domain": f"d{i}.ex", "ip": f"1.1.1.{i}",
         "url": f"http://d{i}.ex/"}, "task": {"time": "2024-01-01T00:00:00Z"},
         "sort": [100 + i, f"id{i}"]} for i in range(3)]}
    p2 = {"total": 150, "has_more": False, "results": [
        {"_id": f"id{i}", "page": {"domain": f"d{i}.ex", "ip": "2.2.2.2",
         "url": f"http://d{i}.ex/x"}, "task": {"time": "2024-02-02T00:00:00Z"},
         "sort": [200 + i, f"id{i}"]} for i in range(3, 5)]}
    seq = [p1, p2]

    def router(url, req):
        if "/search/" in url:
            return _Resp(json.dumps(seq.pop(0)))
        if "/dom/" in url:
            uid = url.rstrip("/").split("/")[-1]
            # id0 & id1 identical content -> collapse to one; id2/id3/id4 distinct
            body = ("<html>dup</html>" if uid in ("id0", "id1")
                    else f"<html>{uid}</html>") + " " * 300
            return _Resp(body)
        raise RuntimeError("unexpected " + url)

    calls, restore = _patch_urlopen(router)
    try:
        intel = wp_net.urlscan_intel("d.ex", max_pages=5)
        check("urlscan follows search_after to page 2", intel["pages"] == 2, detail=intel["pages"])
        check("urlscan aggregates every scan across pages", len(intel["all_scans"]) == 5,
              detail=len(intel["all_scans"]))
        check("urlscan cursor uses the last row's sort value",
              any("search_after=102,id2" in c for c in calls), detail=[c for c in calls if "search_after" in c])
        doms = wp_net.urlscan_dom_all(intel, max_doms=25)
        check("urlscan_dom_all de-dups identical DOMs by sha256", len(doms) == 4,
              detail=[d["uuid"] for d in doms])
    finally:
        restore()


# --- 1/2. CDX widening --------------------------------------------------------------------
import wayback_ga  # noqa: E402


def test_cdx_widens_domain_and_assets():
    rows = [["timestamp", "original", "statuscode", "digest", "mimetype"],
            ["20230102", "http://a.ex/", "200", "D1", "text/html"],
            ["20220101", "http://sub.a.ex/app.js", "200", "D2", "application/javascript"]]
    calls, restore = _patch_urlopen(lambda url, req: _Resp(json.dumps(rows)))
    try:
        snaps = wayback_ga.cdx_snapshots("http://www.a.ex/path")
        check("cdx issues separate html + asset queries", len(calls) == 2, detail=len(calls))
        check("cdx uses matchType=domain (subdomains+subpaths)",
              all("matchType=domain" in c for c in calls), detail=calls)
        check("cdx asset query includes archived JS/JSON",
              any("application/javascript" in c for c in calls), detail=calls)
        check("cdx html query is html-only (no js filter)",
              any("application/javascript" not in c and "text/html" in c for c in calls), detail=calls)
        check("cdx normalises url to the bare host", all("url=a.ex&" in c for c in calls), detail=calls)
        check("cdx captures a subdomain/subpath row", any("sub.a.ex" in s[1] for s in snaps),
              detail=snaps)
        check("cdx merges+time-sorts across queries",
              [s[0] for s in snaps] == ["20220101", "20230102"], detail=snaps)
        calls.clear()
        wayback_ga.cdx_snapshots("a.ex", root_only=True, include_assets=False)
        check("--html-only issues a single html query only", len(calls) == 1, detail=len(calls))
        q2 = calls[-1]
        check("--root-only drops matchType (legacy exact-apex)", "matchType=domain" not in q2, detail=q2)
        check("--html-only excludes JS/JSON", "application/javascript" not in q2, detail=q2)
    finally:
        restore()


# --- 4. CommonCrawl + archive.today -------------------------------------------------------
import wp_extra_archives as XA  # noqa: E402


def test_commoncrawl_warc_parse():
    warc = ("WARC/1.0\r\nWARC-Type: response\r\n\r\n"
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
            "<html>hi support@a.ex</html>")
    comp = gzip.compress(warc.encode())
    _, restore = _patch_urlopen(lambda url, req: _Resp(comp))
    try:
        body = XA.commoncrawl_fetch({"filename": "f.warc.gz", "offset": 0, "length": len(comp)})
        check("commoncrawl_fetch strips WARC+HTTP headers to the body",
              body.startswith("<html>") and "support@a.ex" in body, detail=body[:60])
    finally:
        restore()


def test_archive_today_timemap_parse():
    tm = ('<http://a.ex>; rel="original", '
          '<https://archive.ph/abc/http://a.ex>; rel="memento"; '
          'datetime="Fri, 01 Jan 2021 00:00:00 GMT"')
    orig = XA._get
    XA._get = lambda url, ua=None, timeout=45, raw=False: tm
    try:
        mems = XA.archive_today_timemap("a.ex")
        check("archive.today TimeMap yields memento urls",
              bool(mems) and mems[0]["url"] == "https://archive.ph/abc/http://a.ex", detail=mems)
    finally:
        XA._get = orig


# --- 3. deep_archive merge + frontier consumption -----------------------------------------
import wayback_harvest as WH  # noqa: E402
import wp_deep_archive as DA  # noqa: E402
import case_state as CS  # noqa: E402


def test_deep_archive_merges_and_feeds_frontier():
    _orig = (WH.analyze_domain, wp_net.urlscan_intel, wp_net.urlscan_dom_all,
             XA.commoncrawl_index, XA.commoncrawl_fetch,
             XA.archive_today_timemap, XA.archive_today_fetch)
    WH.analyze_domain = lambda host, **k: {"snapshots_scanned": 3, "records": [
        {"kind": "email", "value": "op@a.ex", "first": "20220101", "last": "20230101",
         "hits": 2, "seen": ["20220101"], "first_url": "http://a.ex/"}]}
    wp_net.urlscan_intel = lambda host, ua=None, max_pages=1, **k: {
        "all_scans": [{"uuid": "u1", "result": "https://urlscan.io/result/u1/",
                       "time": "2024-01-01T00:00:00Z", "url": "http://a.ex/"}],
        "related_domains": ["sibling.ex", "a.ex"], "ips": ["9.9.9.9"], "recent_scans": []}
    wp_net.urlscan_dom_all = lambda intel, ua=None, max_doms=25, **k: [
        {"uuid": "u1", "time": "2024-01-01T00:00:00Z", "url": "http://a.ex/", "sha256": "h",
         "html": "<html>tel:+18005550100</html>" + " " * 300}]
    XA.commoncrawl_index = lambda host, index_count=2, ua=None: [
        {"url": "http://cc.a.ex/", "timestamp": "20210101", "filename": "f", "offset": 0, "length": 1},
        {"url": "http://other.ex/", "timestamp": "20210101", "filename": "f", "offset": 0, "length": 1}]
    XA.commoncrawl_fetch = lambda row, ua=None: "<html>x@a.ex</html>" + " " * 300
    XA.archive_today_timemap = lambda host, ua=None: [{"datetime": "x", "url": "https://archive.ph/z/http://a.ex"}]
    XA.archive_today_fetch = lambda url, ua=None: "<html>https://t.me/opchan</html>" + " " * 300
    try:
        res = DA.deep_archive("www.a.ex", commoncrawl=True, archive_today=True)
        vals = {(p["kind"], p["value"]) for p in res["pivots"]}
        check("deep_archive ran all four corpora",
              set(res["meta"]["sources"]) == {"wayback", "urlscan", "commoncrawl", "archive_today"},
              detail=res["meta"]["sources"])
        check("urlscan sibling → frontier pivot", ("urlscan_related_domain", "sibling.ex") in vals)
        check("commoncrawl off-apex domain → frontier pivot", ("archive_related_domain", "other.ex") in vals)
        check("seed apex never emitted as a related-domain lead",
              not any(v == "a.ex" for k, v in vals if k.endswith("related_domain")))
        check("historical selectors merged as pivots",
              any(k == "email" for k, _ in vals) and any(k == "phone" for k, _ in vals))
        check("indicators built for the IOC bundle", bool(res["indicators"]))

        # the two archive kinds must actually be mined by the frontier
        cands, deferred = {}, CS._new_deferred()
        obj = {"meta": {"host": "seed.ex"}, "pivots": [
            {"kind": "urlscan_related_domain", "value": "sibling.ex"},
            {"kind": "archive_related_domain", "value": "other.ex"}]}
        CS._free_candidates_from_raw(obj, cands, {CS._registrable("seed.ex")}, deferred)
        check("frontier mines urlscan_related_domain", "sibling.ex" in cands, detail=set(cands))
        check("frontier mines archive_related_domain", "other.ex" in cands, detail=set(cands))
    finally:
        (WH.analyze_domain, wp_net.urlscan_intel, wp_net.urlscan_dom_all,
         XA.commoncrawl_index, XA.commoncrawl_fetch,
         XA.archive_today_timemap, XA.archive_today_fetch) = _orig


def test_free_only_suppresses_urlscan_key():
    """--free-only must NOT send the urlscan API-Key (metered index) — search, DOM, and
    wp_recon.urlscan_search all stay analytically keyless; with a key and free_only=False the
    header IS sent."""
    import wp_recon
    FAKE = "deadbeef-free-only-test-key"
    _os = (wp_net._secret, wp_recon._secret)
    wp_net._secret = lambda name, *a: FAKE if name == "URLSCAN_API_KEY" else None
    wp_recon._secret = lambda name, *a: FAKE if name == "URLSCAN_API_KEY" else None

    def _run(fn, router):
        hdrs = []
        orig = urllib.request.urlopen

        def _u(req, timeout=None):
            hdrs.append({k.lower(): v for k, v in (req.headers or {}).items()})
            return router(req.full_url if hasattr(req, "full_url") else req)
        urllib.request.urlopen = _u
        try:
            return fn(), hdrs
        finally:
            urllib.request.urlopen = orig
    try:
        page = json.dumps({"total": 1, "has_more": False, "results": [
            {"_id": "u1", "page": {"domain": "d.ex", "ip": "1.1.1.1", "url": "http://d.ex/"},
             "task": {"time": "2024"}, "sort": [1, "u1"]}]})
        dom = "<html>x</html>" + " " * 300
        srch = lambda url: _Resp(page) if "/search/" in url else _Resp(dom)

        # free_only=True → no API-Key anywhere
        (_i, h_intel) = _run(lambda: wp_net.urlscan_intel("d.ex", max_pages=3, free_only=True), srch)
        check("free-only urlscan_intel sends no API-Key",
              all("api-key" not in h for h in h_intel), detail=h_intel)
        check("free-only urlscan_intel is single-page", _i["pages"] == 1, detail=_i["pages"])
        intel = {"query": "d.ex", "all_scans": [{"uuid": "abc1234567890abc", "url": "http://d.ex/"}]}
        (_d, h_dom) = _run(lambda: wp_net.urlscan_dom_all(intel, max_doms=1, free_only=True), srch)
        check("free-only urlscan_dom_all sends no API-Key",
              all("api-key" not in h for h in h_dom), detail=h_dom)
        (_s, h_srch) = _run(lambda: wp_recon.urlscan_search("domain:d.ex", free_only=True), srch)
        check("free-only wp_recon.urlscan_search sends no API-Key",
              all("api-key" not in h for h in h_srch), detail=h_srch)

        # free_only=False + key present → API-Key IS sent (keys used when in .env)
        (_i2, h2) = _run(lambda: wp_net.urlscan_intel("d.ex", max_pages=1, free_only=False), srch)
        check("keyed urlscan_intel DOES send API-Key", any("api-key" in h for h in h2), detail=h2)
    finally:
        wp_net._secret, wp_recon._secret = _os


_TESTS = (test_urlscan_pagination_and_dom_dedup, test_cdx_widens_domain_and_assets,
          test_commoncrawl_warc_parse, test_archive_today_timemap_parse,
          test_deep_archive_merges_and_feeds_frontier, test_free_only_suppresses_urlscan_key)

for _t in _TESTS:
    _t()

if FAILURES:
    print(f"\nFAIL — {len(FAILURES)} check(s) failed:")
    for f in FAILURES:
        print("  -", f)
    sys.exit(1)
print("\nPASS — all deep-archive checks green")


def test_deep_archive():
    """pytest entry point — module body runs the checks at import time."""
    assert not FAILURES, FAILURES
