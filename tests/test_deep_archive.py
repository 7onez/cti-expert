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
import tempfile
import urllib.request

# Vendor clients ledger every (mocked) call via api_usage; a test must never write phantom credits
# into the real MEMORY/api_usage.jsonl (the Censys/urlscan monthly budgets are derived from it).
os.environ.setdefault("API_USAGE_LOG", os.path.join(tempfile.gettempdir(), "cti-tests-api_usage.jsonl"))

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


# --- 5. urlscan Pro hostname lifecycle (audit item 2) ---------------------------------------
def test_urlscan_hostname_eras_pagination_and_degrade():
    """The hostname index is folded into dated eras, paginates via pageState under a cap, is
    ledgered per page, and NEVER raises (enrich_live's executor would abort the whole pivot)."""
    FAKE = "deadbeef-hostname-test-key"
    _os = wp_net._secret
    wp_net._secret = lambda name, *a: FAKE if name == "URLSCAN_API_KEY" else None

    def row(seen_on, source, sub_id, first, last, data=None, data_type=None):
        return {"seen_on": seen_on, "source": source, "sub_id": sub_id, "first_seen": first,
                "last_seen": last, "data_type": data_type, "data": data}
    # page 1: recent daily rows (newest first) + the whole-index summary rows; page 2: the old
    # registrar-parking era of a drop-catch host; page 3 would exist but the cap stops at 2.
    p1 = {"item": "recycled.example", "pageState": "PS1", "results": [
        row("2200-01-01", "seenDates", "", "2015-01-01T00:00:00Z", "2026-09-01T00:00:00Z"),
        row("2100-01-01", "ct", "", "2015-02-01T00:00:00Z", "2026-07-01T00:00:00Z"),
        row("2100-01-01", "zonefile", "", "2023-02-14T00:00:00Z", "2025-12-17T00:00:00Z"),
        row("2026-09-01", "pdns", "A#203.0.113.10", "2026-09-01T00:00:00Z", "2026-09-01T12:00:00Z",
            {"rdata": "203.0.113.10", "asn": {"asn": "64500"}}, "json"),
        row("2026-08-31", "pdns", "A#203.0.113.10", "2026-08-31T00:00:00Z", "2026-08-31T12:00:00Z",
            {"rdata": "203.0.113.10", "asn": {"asn": "64500"}}, "json"),
        row("2026-09-01", "pdns", "NS#ns1.operator.example", "2026-09-01T00:00:00Z", "2026-09-01T12:00:00Z",
            {"rdata": "ns1.operator.example"}, "json"),
        row("2026-09-01", "scan", "VIA-SCAN#203.0.113.10", "2026-09-01T00:00:00Z", "2026-09-01T01:00:00Z",
            {"asn": {"asn": "64500"}}, "json"),
        "not-a-dict",
    ]}
    p2 = {"item": "recycled.example", "pageState": "PS2", "results": [
        row("2023-06-01", "pdns", "A#198.51.100.7", "2023-02-14T00:00:00Z", "2026-07-01T00:00:00Z",
            {"rdata": "198.51.100.7", "asn": {"asn": "64501"}}, "json"),
        row("2023-06-01", "pdns", "NS#ns1.registrar-parking.example", "2023-02-14T00:00:00Z",
            "2026-05-20T00:00:00Z", {"rdata": "ns1.registrar-parking.example"}, "json"),
        row("2023-06-01", "pdns", "MX#0 .", "2023-02-14T00:00:00Z", "2023-06-01T00:00:00Z", {"rdata": "0 ."}, "json"),
    ]}
    _rec = []
    _orig_rec = getattr(wp_net.api_usage, "record", None) if wp_net.api_usage else None
    if wp_net.api_usage:
        wp_net.api_usage.record = lambda *a, **k: _rec.append((a, k))

    def router(url, req):
        check("hostname call sends the API-Key", "api-key" in {k.lower() for k in (req.headers or {})})
        return _Resp(json.dumps(p2 if "pageState=PS1" in url else p1))
    calls, restore = _patch_urlopen(router)
    try:
        r = wp_net.urlscan_hostname("recycled.example", max_pages=2)
        check("two pages walked under the cap, then truncated", r["pages"] == 2 and r["truncated"] is True,
              detail=(r["pages"], r["truncated"]))
        check("pageState cursor is carried into the second call", any("pageState=PS1" in u for u in calls), detail=calls)
        check("daily rows of one (type,value) collapse into ONE era with min first / max last",
              [(e["value"], e["first_seen"][:10], e["last_seen"][:10], e["asn"]) for e in r["a_eras"]]
              == [("198.51.100.7", "2023-02-14", "2026-07-01", "64501"), ("203.0.113.10", "2026-08-31", "2026-09-01", "64500")],
              detail=r["a_eras"])
        check("NS eras separate the registrar-parking era from the operator's",
              [e["value"] for e in r["ns_eras"]] == ["ns1.registrar-parking.example", "ns1.operator.example"],
              detail=r["ns_eras"])
        check("summary rows feed the whole-index firsts, not the eras",
              r["ct_first"] == "2015-02-01T00:00:00Z" and r["zonefile_first"] == "2023-02-14T00:00:00Z"
              and r["first_seen"] == "2015-01-01T00:00:00Z", detail=(r["ct_first"], r["zonefile_first"], r["first_seen"]))
        check("VIA-SCAN rows become scan_ips, never eras", r["scan_ips"] == ["203.0.113.10"], detail=r["scan_ips"])
        check("MX rows land under mx", [e["type"] for e in r["mx"]] == ["MX"], detail=r["mx"])
        check("one ledger entry per page", sum(1 for a, k in _rec if a[:2] == ("urlscan", "hostname")) == 2, detail=_rec)
        check("pages are requested at the reference page_limit (one credit per page, any size)",
              all("limit=" in u for u in calls), detail=calls)
        check("oldest daily row reached is recorded as the censoring boundary",
              r["oldest_seen_on"] == "2023-06-01", detail=r["oldest_seen_on"])
        open_flags = {e["value"]: e["first_seen_open"] for e in r["a_eras"] + r["ns_eras"]}
        check("an era whose earliest row touches the truncation boundary is LEFT-CENSORED (start unknown)",
              open_flags["198.51.100.7"] is True and open_flags["ns1.registrar-parking.example"] is True, detail=open_flags)
        check("an era that began after the boundary (every newer row was read) is NOT censored",
              open_flags["203.0.113.10"] is False and open_flags["ns1.operator.example"] is False, detail=open_flags)
    finally:
        restore()
    # a complete walk (no pageState on the last page) censors nothing
    p2_last = dict(p2, pageState=None)
    calls, restore = _patch_urlopen(lambda url, req: _Resp(json.dumps(p2_last if "pageState=PS1" in url else p1)))
    try:
        r = wp_net.urlscan_hostname("recycled.example", max_pages=5)
        check("a complete walk is not truncated", r["truncated"] is False and r["pages"] == 2, detail=(r["truncated"], r["pages"]))
        check("nothing is censored on a complete walk", not any(e["first_seen_open"] for e in r["a_eras"] + r["ns_eras"]))
        sys.path.insert(0, os.path.join(ROOT, "intel_engine", "IntelGraph", "scripts"))
        import case_timeline as ct
        ev = []
        r_trunc = dict(r, truncated=True)
        for e in r_trunc["a_eras"]:
            e["first_seen_open"] = e["value"] == "198.51.100.7"
        ct.urlscan_hostname_events("recycled.example", {"pivots": [{"kind": "domain", "value": "recycled.example",
                                                                      "live_results": {"urlscan_hostname": r_trunc}}]}, ev)
        cens = [e for e in ev if e and e["kind"] == "hosting" and e["value"]["ip"] == "198.51.100.7"][0]
        dated = [e for e in ev if e and e["kind"] == "hosting" and e["value"]["ip"] == "203.0.113.10"][0]
        check("timeline renders a censored era as an open start ('since ≤'), never a dated beginning",
              "since ≤" in cens["detail"] and cens["value"]["left_censored"] is True and "(start ≤)" in cens["label"], detail=cens)
        check("timeline renders an uncensored era with its real start", "since ≤" not in dated["detail"]
              and dated["value"]["left_censored"] is False, detail=dated)
    finally:
        restore()
    # degrade paths — never raise
    try:
        class _E(Exception):
            pass

        def boom(url, req):
            raise _E("connection reset")
        _c, restore = _patch_urlopen(boom)
        r = wp_net.urlscan_hostname("recycled.example", max_pages=2)
        check("transport fault degrades to {error}, never raises", "error" in r and "connection reset" in r["error"], detail=r)
        restore()

        def forbidden(url, req):
            raise urllib.error.HTTPError(url, 403, "Forbidden", {}, io.BytesIO(b""))
        _c, restore = _patch_urlopen(forbidden)
        r = wp_net.urlscan_hostname("recycled.example", max_pages=2)
        check("non-Pro 403 degrades to {skipped}", "skipped" in r and "Pro" in r["skipped"], detail=r)
        restore()
        check("free_only never spends the credential",
              wp_net.urlscan_hostname("recycled.example", free_only=True).get("skipped", "").startswith("--free-only"))
        wp_net._secret = lambda name, *a: None
        check("keyless degrades to {skipped}", "skipped" in wp_net.urlscan_hostname("recycled.example"))
    finally:
        wp_net._secret = _os
        if wp_net.api_usage and _orig_rec:
            wp_net.api_usage.record = _orig_rec


def test_urlscan_hostname_eras_reach_the_timeline():
    """A/AAAA eras land on the shared `hosting` track (source urlscan), NS eras on `ns_era`; a
    skipped block yields nothing."""
    sys.path.insert(0, os.path.join(ROOT, "intel_engine", "IntelGraph", "scripts"))
    import case_timeline as ct
    analysis = {"meta": {"host": "recycled.example"}, "artifacts": {}, "pivots": [
        {"kind": "domain", "value": "recycled.example", "live_results": {"urlscan_hostname": {
            "a_eras": [{"type": "A", "value": "198.51.100.7", "first_seen": "2023-02-14T00:00:00Z",
                        "last_seen": "2026-05-20T00:00:00Z", "asn": "64501"}],
            "ns_eras": [{"type": "NS", "value": "ns1.registrar-parking.example",
                         "first_seen": "2023-02-14T00:00:00Z", "last_seen": "2026-05-20T00:00:00Z"}]}}}]}
    out = []
    ct.urlscan_hostname_events("recycled.example", analysis, out)
    kinds = sorted(e["kind"] for e in out if e)
    check("A era -> hosting, NS era -> ns_era", kinds == ["hosting", "ns_era"], detail=kinds)
    check("hosting era carries the IP for the tenancy correlation",
          any(e["kind"] == "hosting" and e["value"]["ip"] == "198.51.100.7" for e in out if e))
    check("source class is the public web-scan index (urlscan)", all(e["source"] == "urlscan" for e in out if e))
    check("every era row cites a public register", all(e.get("url") for e in out if e))
    check("ns_era is a known figure track", "ns_era" in ct.TRACKS and "ns_era" in ct.TRACK_LABEL)
    out2 = []
    ct.urlscan_hostname_events("x.example", {"pivots": [{"kind": "domain", "value": "x.example",
                                                      "live_results": {"urlscan_hostname": {"skipped": "no key"}}}]}, out2)
    check("a skipped block yields no events", out2 == [])


def test_measured_free_plan_skips_urlscan_pro_calls():
    """A urlscan key measured FREE (cases/<id>/capability_plans.json) must skip the two Pro calls
    (similar + hostname) that would 403 on every host; an unknown/pro plan runs them. Censys stays
    un-gated (its search is its own probe). Offline: every vendor call is stubbed."""
    import tempfile
    import wp_analyze as WA
    import wp_plans
    ran = []
    stubs = {"resolve_live_dns": lambda h, **k: {"ips": []}, "ct_search": lambda h, **k: {},
             "passivedns_search": lambda h, **k: {}, "urlscan_search": lambda q, **k: {"domains": []},
             "urlscan_similar": lambda h, **k: ran.append("similar") or {}, "urlscan_hostname": lambda h, **k: ran.append("hostname") or {}}
    saved = {k: getattr(WA, k) for k in stubs}
    # every other keyed vendor OFF for this test (real keys may exist on the box): gates are
    # module-level `*_configured()` functions or env vars — neutralise both, restore after.
    gates = [(WA, "censys_configured"), (WA, "hunterhow_configured"), (WA.wp_validin, "validin_configured"),
             (WA.wp_securitytrails, "securitytrails_configured"), (WA.wp_dnslytics, "dnslytics_configured"),
             (WA.wp_quake, "quake_configured"), (WA.wp_zoomeye, "zoomeye_configured"), (WA.wp_pssl, "pssl_configured")]
    saved_gates = [(m, n, getattr(m, n)) for m, n in gates]
    for m, n in gates:
        setattr(m, n, lambda: False)
    # …and every REGISTERED credential (+ aliases / companions / requires) is popped for the test —
    # `_secret` is env-only, so an empty env is a keyless run for whatever a `*_configured()` stub misses.
    import wp_capabilities
    env_keys = {wp_plans.CASE_DIR_ENV, "FOFA_KEY", "FOFA_API_KEY", "PDNS_USERNAME", "PDNS_PASSWORD",
                "WHOISXML_API_KEY", "WHOISXMLAPI_KEY", "WHOIS_API_KEY", "CENSYS_PAT", "CENSYS_API_KEY"}
    for row in wp_capabilities.key_status():
        env_keys.add(row["env"])
        env_keys.update(row.get("aliases") or [])
        env_keys.update(row.get("companion") or [])
        env_keys.update(row.get("requires") or [])
    saved_env = {k: os.environ.pop(k, None) for k in sorted(env_keys)}
    ledger = os.environ["API_USAGE_LOG"]            # the active ledger (redirected for tests)
    real_ledger = os.path.join(ROOT, "intel_engine", "MEMORY", "api_usage.jsonl")
    real_before = os.path.getsize(real_ledger) if os.path.exists(real_ledger) else 0
    ledger_before = os.path.getsize(ledger) if os.path.exists(ledger) else 0
    for k, v in stubs.items():
        setattr(WA, k, v)
    try:
        os.environ["URLSCAN_API_KEY"] = "x"
        for tier, expect in (("free", []), ("pro", ["hostname", "similar"]), (None, ["hostname", "similar"])):
            with tempfile.TemporaryDirectory() as tmp:
                case = os.path.join(tmp, "CASE-0001")
                os.makedirs(case)
                os.environ[wp_plans.CASE_DIR_ENV] = case
                if tier:
                    wp_plans.record("urlscan", {"tier": tier}, case_dir=case)
                ran.clear()
                res = {"meta": {"host": "site-a.example"}, "artifacts": {},
                       "pivots": [{"kind": "domain", "value": "site-a.example"}]}
                WA.enrich_live(res, free_only=False)
                check(f"urlscan plan {tier or 'unknown'} -> Pro calls {expect or 'skipped'}", sorted(ran) == expect, detail=ran)
                check(f"…enriched_with reflects it ({tier or 'unknown'})",
                      ("urlscan-hostname" in res["meta"]["enriched_with"]) == bool(expect))
        ledger_after = os.path.getsize(ledger) if os.path.exists(ledger) else 0
        check("no metered call was ledgered during the gate test (fully offline)", ledger_after == ledger_before)
        check("the REAL ledger is untouched by this suite", (os.path.getsize(real_ledger) if os.path.exists(real_ledger) else 0) == real_before)
    finally:
        for k, v in saved.items():
            setattr(WA, k, v)
        for m, n, v in saved_gates:
            setattr(m, n, v)
        for k, v in saved_env.items():
            os.environ.pop(k, None)
            if v is not None:
                os.environ[k] = v


_TESTS = (test_urlscan_pagination_and_dom_dedup, test_cdx_widens_domain_and_assets,
          test_commoncrawl_warc_parse, test_archive_today_timemap_parse,
          test_deep_archive_merges_and_feeds_frontier, test_free_only_suppresses_urlscan_key,
          test_urlscan_hostname_eras_pagination_and_degrade, test_urlscan_hostname_eras_reach_the_timeline,
          test_measured_free_plan_skips_urlscan_pro_calls)

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
