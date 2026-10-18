#!/usr/bin/env python3
"""Regression: the exhaustive Wayback collector (wp_wayback_exhaust), the paged index and the
gzip-decompression fix in wp_wayback, and the per-route exits (wp_exits).

WHAT THIS PROTECTS
------------------
- id_ playback replays a capture's original Content-Encoding (gzip); wp_wayback must decompress, or
  every gzip capture reaches the extractors as binary junk and yields no selectors (the bug that
  made "25/25 fetched" find nothing).
- index_pages must walk the WHOLE index via resumeKey — the row cap is exactly what the exhaustive
  mode exists to defeat.
- enumerate_captures dedupes by content digest GLOBALLY (one asset under 100 URLs = one fetch).
- fetch_all spreads across exits, records a dead 404 capture as done (never re-queued), re-queues a
  transport failure, and a resume skips everything already done.
- the urlscan step spends the credential even on a free-only run (the exhaustive posture), while the
  default sampled path's no-spend rule is untouched.
- wp_exits parses direct / http / socks / pool specs and strips credentials from the exit id.

Fully offline: every network seam is stubbed. Synthetic data only.

Run:  python3 tests/test_wayback_exhaust.py
"""
import gzip
import io
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
WP = os.path.join(ROOT, "intel_engine", "WebPivot", "tools")
SWP = os.path.join(ROOT, "scripts", "webpivot")
for _p in (WP, SWP):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# isolate the run breaker / egress pacer; never touch real state, never space stubbed calls
_TMP = tempfile.mkdtemp(prefix="wb-exhaust-")
os.environ.setdefault("WAYBACK_GUARD_STATE", os.path.join(_TMP, "breaker.json"))
os.environ.setdefault("WAYBACK_PACE_STATE", os.path.join(_TMP, "pace.json"))
os.environ.setdefault("WAYBACK_MIN_INTERVAL", "0")
os.environ.setdefault("INTEL_RUN_ID", "exhaust-test")
os.environ.setdefault("API_USAGE_LOG", os.path.join(_TMP, "api_usage.jsonl"))

import wp_wayback as W  # noqa: E402
import wp_wayback_exhaust as WE  # noqa: E402
import wp_exits  # noqa: E402

FAILURES = []


def check(label, cond, detail=""):
    print(("  ok   " if cond else "  FAIL ") + label + ("" if cond else f"  [{detail}]"))
    if not cond:
        FAILURES.append(label)


class _Resp(io.BytesIO):
    def __init__(self, data, headers=None, status=200):
        super().__init__(data if isinstance(data, bytes) else data.encode())
        self.headers, self.status = headers or {}, status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def geturl(self):
        return ""


def _patch(fn):
    import urllib.request
    orig = urllib.request.urlopen
    urllib.request.urlopen = fn
    return lambda: setattr(urllib.request, "urlopen", orig)


# --- 1. gzip decompression (the critical bug) --------------------------------
def test_id_playback_gzip_is_decompressed():
    html = "<html>selector info@a.example +1 GA-9</html>"
    body = gzip.compress(html.encode())
    restore = _patch(lambda req, timeout=None: _Resp(body, {"Content-Encoding": "gzip"}))
    try:
        resp, err = W.fetch("20200101000000", "https://a.example/")
        check("gzip id_ body is decompressed to the original HTML",
              err is None and resp.body == html.encode(), detail=resp.body[:20] if resp else err)
        # gzip magic without a header (the archive sometimes mislabels) still decompresses
        restore2 = _patch(lambda req, timeout=None: _Resp(body, {}))
        try:
            resp2, _ = W.fetch("20200101000000", "https://a.example/")
            check("gzip magic sniffed even without Content-Encoding", resp2.body == html.encode(),
                  detail=resp2.body[:20])
        finally:
            restore2()
    finally:
        restore()


# --- 2. paged index (resumeKey) ----------------------------------------------
def test_index_pages_walks_every_page_via_resumekey():
    pages = [
        [["ts", "orig"], ["1", "http://a.example/p1"], ["2", "http://a.example/p2"], [], ["RK1"]],
        [["ts", "orig"], ["3", "http://a.example/p3"], [], ["RK2"]],
        [["ts", "orig"], ["4", "http://a.example/p4"]],   # no resumeKey → last page
    ]
    seen_keys = []

    def route(req, timeout=None):
        url = req.full_url
        rk = None
        if "resumeKey=" in url:
            rk = url.split("resumeKey=", 1)[1].split("&", 1)[0]
        seen_keys.append(rk)
        idx = 0 if rk is None else (1 if rk == "RK1" else 2)
        return _Resp(json.dumps(pages[idx]))

    restore = _patch(route)
    try:
        rows = []
        err = None
        for page, perr in W.index_pages([("url", "a.example"), ("matchType", "domain")], page_rows=2):
            if perr:
                err = perr
                break
            rows += page
        check("index_pages aggregates every page", [r[0] for r in rows] == ["1", "2", "3", "4"],
              detail=rows)
        check("index_pages stops when no resumeKey", err is None and seen_keys == [None, "RK1", "RK2"],
              detail=seen_keys)
        check("index_pages strips the resumeKey + separator rows",
              all(len(r) == 2 for r in rows), detail=rows)
    finally:
        restore()


# --- 3. global digest dedup in enumeration -----------------------------------
def test_enumerate_dedupes_by_digest_across_urls():
    # same digest D1 under three URLs → one capture; D2 distinct
    page = [["ts", "orig", "digest"],
            ["20200101", "http://a.example/", "D1"],
            ["20200102", "http://a.example/index.html", "D1"],
            ["20200103", "http://sub.a.example/", "D1"],
            ["20200104", "http://a.example/x", "D2"]]
    restore = _patch(lambda req, timeout=None: _Resp(json.dumps(page)))
    try:
        caps, err = WE.enumerate_captures("a.example", include_assets=False, page_rows=100)
        check("enumeration dedupes by content digest across URLs",
              err is None and set(caps) == {"D1", "D2"}, detail=list(caps))
    finally:
        restore()


# --- 4. parallel fetch: dead vs transient, and resume ------------------------
class _Exit:
    def __init__(self, id):
        self.id = id


def test_fetch_all_records_dead_requeues_transient_and_resume_skips_done():
    captures = {f"D{i}": {"timestamp": "20200101000000", "original": f"http://a.example/{i}", "digest": f"D{i}"}
                for i in range(6)}
    # D0 is a permanent 404 (dead capture); D5 fails once then succeeds; the rest succeed
    state = {"tries": {}}

    def fake_fetch(ts, original, mode="id_", *, ua=None, timeout=60, exit=None, attempts=None):
        n = original.rsplit("/", 1)[1]
        if n == "0":
            return W.Response(404, original, {}, b""), None            # dead: answered 404
        if n == "5" and state["tries"].get(n, 0) == 0:
            state["tries"][n] = 1
            return None, "timeout"                                     # transient: re-queue
        return W.Response(200, original, {}, f"<html>{n}</html>".encode()), None

    orig = W.fetch
    W.fetch = fake_fetch
    try:
        got = {}
        summary = WE.fetch_all(captures, [_Exit("direct"), _Exit("p1:80")],
                               on_body=lambda dg, cap, body: got.__setitem__(dg, body))
        check("every capture is processed exactly once (dead + transient + ok)",
              set(got) == set(captures), detail=sorted(got))
        check("a dead 404 capture is recorded with no body (never re-queued)", got["D0"] is None)
        check("a transient failure is re-queued and eventually fetched", got["D5"] == b"<html>5</html>")
        check("summary counts the successful fetches", summary["fetched"] == 5, detail=summary)

        # resume: with all done, nothing is re-queued
        again = {}
        s2 = WE.fetch_all(captures, [_Exit("direct")], done_digests=set(captures),
                          on_body=lambda dg, cap, body: again.__setitem__(dg, body))
        check("resume skips everything already done", s2["queued"] == 0 and again == {}, detail=s2)
    finally:
        W.fetch = orig


# --- 5. urlscan step: self-paged search, spends key even free-only, resumable, stops on 429 ------
def test_urlscan_exhaust_pages_search_spends_and_resumes():
    import wp_net
    import urllib.error
    calls = {"search_pages": 0, "dom_fetches": []}

    # two search pages of 2 scans each (has_more on page 1), then a DOM per uuid
    pages = {
        None: {"results": [{"_id": "u0", "page": {"url": "http://b.example/", "domain": "b.example"},
                            "task": {"time": "2024-01-01"}, "sort": [1, "u0"]},
                           {"_id": "u1", "page": {"url": "http://b.example/x", "domain": "b.example"},
                            "task": {"time": "2024-01-02"}, "sort": [2, "u1"]}],
               "has_more": True, "total": 4},
        "2,u1": {"results": [{"_id": "u2", "page": {"url": "http://c.example/", "domain": "c.example"},
                              "task": {"time": "2024-01-03"}, "sort": [3, "u2"]},
                             {"_id": "u3", "page": {"url": "http://c.example/y", "domain": "c.example"},
                              "task": {"time": "2024-01-04"}, "sort": [4, "u3"]}],
                 "has_more": False, "total": 4},
    }
    doms = {u: "<html>%s@x.example %s</html>" % (u, "z" * 250) for u in ("u0", "u1", "u2", "u3")}

    def router(req, timeout=None):
        url = req.full_url
        if "/api/v1/search/" in url:
            calls["search_pages"] += 1
            cur = None
            if "search_after=" in url:
                import urllib.parse
                cur = urllib.parse.unquote(url.split("search_after=", 1)[1].split("&", 1)[0])
            return _Resp(json.dumps(pages[cur]))
        uid = url.rstrip("/").rsplit("/", 1)[1]
        calls["dom_fetches"].append(uid)
        return _Resp(doms[uid], {"Content-Type": "text/html"})

    o_secret, o_q = wp_net._secret, wp_net.urlscan_quotas
    wp_net._secret = lambda *n: "KEY" if "URLSCAN_API_KEY" in n else o_secret(*n)
    wp_net.urlscan_quotas = lambda ua=None, **k: {"max_search_results": 10000}
    restore = _patch(router)
    sp = os.path.join(_TMP, "us_state.json")
    for junk in (sp, WE._dom_ledger_path(sp)):
        try:
            os.remove(junk)
        except OSError:
            pass
    try:
        state = {"records": {}}
        WE._urlscan_exhaust("a.example", state, None, spend_key=True, state_path=sp)
        check("search is paged to the end via the cursor", calls["search_pages"] == 2,
              detail=calls["search_pages"])
        check("search marked complete", state.get("urlscan_search_complete") is True)
        check("vendor total + plan window recorded (listed N of total T, window W)",
              state.get("urlscan_vendor_total") == 4 and state.get("urlscan_plan_window") == 10000,
              detail=(state.get("urlscan_vendor_total"), state.get("urlscan_plan_window")))
        check("every DOM across both pages fetched (no local cap)",
              set(calls["dom_fetches"]) == {"u0", "u1", "u2", "u3"}, detail=calls["dom_fetches"])
        check("selectors from multiple DOMs folded", len([k for k in state["records"] if k.startswith("email\t")]) == 4,
              detail=list(state["records"]))
        check("fetched uuids in the crash-safe ledger",
              WE._load_dom_ledger(sp) == {"u0", "u1", "u2", "u3"}, detail=WE._load_dom_ledger(sp))

        # resume: everything done → no DOM re-fetch (search re-runs are cheap: complete flag skips)
        calls["dom_fetches"].clear()
        calls["search_pages"] = 0
        WE._urlscan_exhaust("a.example", state, None, spend_key=True, state_path=sp)
        check("a resume re-fetches no DOM already pulled", calls["dom_fetches"] == [],
              detail=calls["dom_fetches"])
        check("a resume does not re-page a completed search", calls["search_pages"] == 0,
              detail=calls["search_pages"])
    finally:
        wp_net._secret, wp_net.urlscan_quotas = o_secret, o_q
        restore()


def test_urlscan_search_cursor_is_saved_per_page_so_a_kill_resumes_mid_listing():
    """A kill after page 1 must leave the page-2 cursor in state; the next run asks for page 2,
    never page 1 again (page 1 is a metered keyed call)."""
    import wp_net
    asked = []

    def router(req, timeout=None):
        url = req.full_url
        if "/api/v1/search/" not in url:           # a /dom/ fetch — not part of this test
            return _Resp("<html>" + "z" * 300 + "</html>")
        cur = None
        if "search_after=" in url:
            import urllib.parse
            cur = urllib.parse.unquote(url.split("search_after=", 1)[1].split("&", 1)[0])
        asked.append(cur)
        if cur is None:
            return _Resp(json.dumps({"results": [{"_id": "u0", "page": {}, "task": {},
                         "sort": [1, "u+0"]}], "has_more": True, "total": 2}))
        if "kill" in _MODE:
            raise KeyboardInterrupt                # the process dies before page 2 answers
        return _Resp(json.dumps({"results": [{"_id": "u1", "page": {}, "task": {},
                     "sort": [2, "u1"]}], "has_more": False, "total": 2}))

    o_secret, o_q = wp_net._secret, wp_net.urlscan_quotas
    wp_net._secret = lambda *n: "KEY" if "URLSCAN_API_KEY" in n else None
    wp_net.urlscan_quotas = lambda ua=None, **k: {"max_search_results": 10000}
    restore = _patch(router)
    try:
        _MODE.add("kill")
        st = {"records": {}}
        try:
            WE._urlscan_exhaust("a.example", st, None, spend_key=True, state_path=None)
        except KeyboardInterrupt:
            pass
        check("cursor saved after page 1 before the kill", st.get("urlscan_search_cursor") == "1,u+0",
              detail=st.get("urlscan_search_cursor"))
        _MODE.discard("kill")
        asked.clear()
        WE._urlscan_exhaust("a.example", st, None, spend_key=True, state_path=None)
        check("resume asks for page 2 only (a '+' in the cursor survives encoding)",
              asked and asked[0] == "1,u+0" and None not in asked, detail=asked)
    finally:
        wp_net._secret, wp_net.urlscan_quotas = o_secret, o_q
        restore()


_MODE = set()


def test_urlscan_paging_ignores_a_false_has_more_while_total_says_more():
    """Measured live: urlscan answered has_more=false on a full page while total=248 and page 2 held
    100 fresh scans. Both the exhaustive search and wp_net.urlscan_intel must follow the cursor."""
    import wp_net
    pages = {None: [("u0", [1, "u0"]), ("u1", [2, "u1"])], "2,u1": [("u2", [3, "u2"]), ("u3", [4, "u3"])],
             "4,u3": []}

    def router(req, timeout=None):
        url = req.full_url
        if "/api/v1/search/" not in url:
            return _Resp("<html>" + "z" * 300 + "</html>")
        cur = None
        if "search_after=" in url:
            import urllib.parse
            cur = urllib.parse.unquote(url.split("search_after=", 1)[1].split("&", 1)[0])
        rows = [{"_id": u, "page": {"domain": "b.example"}, "task": {}, "sort": sv} for u, sv in pages[cur]]
        return _Resp(json.dumps({"results": rows, "has_more": False, "total": 4}))   # the vendor lie

    o_secret, o_q = wp_net._secret, wp_net.urlscan_quotas
    wp_net._secret = lambda *n: "KEY" if "URLSCAN_API_KEY" in n else None
    wp_net.urlscan_quotas = lambda ua=None, **k: {"max_search_results": 10000}
    restore = _patch(router)
    try:
        st = {"records": {}}
        WE._urlscan_exhaust("a.example", st, None, spend_key=True, state_path=None)
        check("exhaustive search lists all 4 despite has_more=false", st.get("urlscan_scan_count") == 4,
              detail=st.get("urlscan_scan_count"))
        intel = wp_net.urlscan_intel("a.example", max_pages=5)
        check("urlscan_intel pages past a false has_more (bounded by max_pages)",
              len(intel.get("all_scans") or []) == 4, detail=len(intel.get("all_scans") or []))
    finally:
        wp_net._secret, wp_net.urlscan_quotas = o_secret, o_q
        restore()


def test_urlscan_dom_429_stops_and_a_kill_never_respends():
    import wp_net
    import urllib.error
    fetched = []
    scans = [{"uuid": f"u{i}", "url": f"http://b.example/{i}", "time": "2024-01-0{}".format(i + 1)}
             for i in range(4)]
    doms = {f"u{i}": "<html>u%d@x.example %s</html>" % (i, "z" * 250) for i in range(4)}

    def router(req, timeout=None):
        url = req.full_url
        if "/api/v1/search/" in url:
            return _Resp(json.dumps({"results": [], "has_more": False, "total": 0}))
        uid = url.rstrip("/").rsplit("/", 1)[1]
        fetched.append(uid)
        if uid == "u2":
            raise urllib.error.HTTPError(url, 429, "rate", {}, None)
        return _Resp(doms[uid], {})

    ledger = []

    class _Ledger:
        @staticmethod
        def record(provider, action, **k):
            if action == "dom":
                ledger.append(k.get("query"))

    o_secret, o_q, o_au = wp_net._secret, wp_net.urlscan_quotas, getattr(wp_net, "api_usage", None)
    wp_net._secret = lambda *n: "KEY" if "URLSCAN_API_KEY" in n else o_secret(*n)
    wp_net.urlscan_quotas = lambda ua=None, **k: {"max_search_results": 10000}
    wp_net.api_usage = _Ledger
    sp = os.path.join(_TMP, "us_429.json")
    for junk in (sp, WE._dom_ledger_path(sp)):
        try:
            os.remove(junk)
        except OSError:
            pass
    restore = _patch(router)
    try:
        st = {"records": {}, "urlscan_scans": scans, "urlscan_search_complete": True}
        WE._urlscan_exhaust("a.example", st, None, spend_key=True, state_path=sp)
        check("a 429 stops the DOM pass with a gap", bool(st.get("urlscan_dom_gap")),
              detail=st.get("urlscan_dom_gap"))
        check("exactly one ledger row per sent DOM request (the 429 is not double-counted)",
              ledger == ["u0", "u1", "u2"], detail=ledger)
        check("DOMs fetched before the 429 are in the crash-safe ledger (incl. the 429 uuid, billed)",
              WE._load_dom_ledger(sp) == {"u0", "u1"}, detail=WE._load_dom_ledger(sp))
        # the 429 uuid u2 is NOT marked done (it can be retried), earlier ones are
        check("the throttled uuid is retried next run, earlier ones are not",
              "u2" not in WE._load_dom_ledger(sp))
        # simulate a kill: state never flushed, but the sidecar ledger persisted → resume skips u0,u1
        fetched.clear()
        st2 = {"records": {}, "urlscan_scans": scans, "urlscan_search_complete": True}
        WE._urlscan_exhaust("a.example", st2, None, spend_key=True, state_path=sp)
        check("a resume after a kill re-fetches no already-billed uuid",
              "u0" not in fetched and "u1" not in fetched, detail=fetched)
        check("a resume does fetch the previously-throttled uuid", "u2" in fetched, detail=fetched)
    finally:
        wp_net._secret, wp_net.urlscan_quotas, wp_net.api_usage = o_secret, o_q, o_au
        restore()


def test_urlscan_free_only_lists_but_spends_nothing():
    import wp_net
    dom_fetches, search_hdrs, ledger = [], [], []

    def router(req, timeout=None):
        url = req.full_url
        if "/api/v1/search/" in url:
            search_hdrs.append({k.lower(): v for k, v in req.header_items()})
            # has_more=True: a keyed run would page on; an anonymous one must stop after one page
            return _Resp(json.dumps({"results": [{"_id": "u0", "page": {"url": "http://b.example/",
                         "domain": "b.example"}, "task": {"time": "2024-01-01"}, "sort": [1, "u0"]}],
                         "has_more": True, "total": 500}))
        dom_fetches.append(url)
        return _Resp("<html>x</html>")

    class _Ledger:
        @staticmethod
        def record(*a, **k):
            ledger.append((a, k))

    o_secret, o_au = wp_net._secret, getattr(wp_net, "api_usage", None)
    wp_net.api_usage = _Ledger
    sp = os.path.join(_TMP, "us_free.json")
    restore = _patch(router)
    try:
        for label, secret in (("key configured but free-only", "KEY"), ("no key at all", None)):
            wp_net._secret = (lambda s: (lambda *n: s if "URLSCAN_API_KEY" in n else None))(secret)
            dom_fetches.clear(); search_hdrs.clear(); ledger.clear()
            st = {"records": {}}
            WE._urlscan_exhaust("a.example", st, None, spend_key=False, state_path=sp)
            check(f"{label}: search sends NO API-Key header",
                  search_hdrs and all("api-key" not in h for h in search_hdrs), detail=search_hdrs)
            check(f"{label}: anonymous search stops after one page", len(search_hdrs) == 1,
                  detail=len(search_hdrs))
            check(f"{label}: nothing ledgered as a credit", ledger == [], detail=ledger)
            check(f"{label}: fetches no DOM", dom_fetches == [], detail=dom_fetches)
            check(f"{label}: still lists scans, gap says why", st.get("urlscan_scan_count") == 1
                  and "anonymous" in (st.get("urlscan_search_gap") or ""), detail=st.get("urlscan_search_gap"))
    finally:
        wp_net._secret = o_secret
        wp_net.api_usage = o_au
        restore()


# --- 6. wp_exits spec parsing + credential-safe ids --------------------------
def test_exits_parse_specs_and_strip_credentials():
    exits = wp_exits.configured_exits("direct,http://u:p@proxy.example:8080,socks5h://127.0.0.1:9050")
    ids = [e.id for e in exits]
    kinds = [e.kind for e in exits]
    check("exit ids strip scheme + credentials", ids == ["direct", "proxy.example:8080", "127.0.0.1:9050"],
          detail=ids)
    check("exit kinds classify direct / http / socks", kinds == ["direct", "http", "socks5"], detail=kinds)
    check("exit_id never leaks a credential", wp_exits.exit_id("http://user:secret@h.example:80") == "h.example:80")
    # duplicate ids de-dupe
    dup = wp_exits.configured_exits("direct,direct")
    check("duplicate exits collapse to one", [e.id for e in dup] == ["direct"], detail=[e.id for e in dup])


# --- 7. brotli: decoded when the library is present, else NOT READ (never read-as-empty) ---------
def test_brotli_body_is_decoded_or_marked_not_read():
    html = b"<html>br-body info@br.example</html>"
    try:
        import brotli
        body = brotli.compress(html)
    except ImportError:
        brotli, body = None, b"\x8b\x0b\x80not-really-brotli"
    restore = _patch(lambda req, timeout=None: _Resp(body, {"Content-Encoding": "br"}))
    try:
        if brotli is not None:
            resp, err = W.fetch("20200101000000", "https://a.example/")
            check("br body decoded when brotli is installed",
                  resp.body == html and not W.undecodable(resp), detail=resp.body[:30])
        o = W._brotli_decompress
        W._brotli_decompress = lambda raw: None          # the library is absent
        try:
            resp, err = W.fetch("20200101000000", "https://a.example/")
            check("without brotli the body is EMPTY and marked undecodable (not binary junk)",
                  resp.body == b"" and "br" in (W.undecodable(resp) or ""), detail=W.undecodable(resp))
            caps = {"D0": {"timestamp": "20200101000000", "original": "https://a.example/", "digest": "D0"}}
            got = {}
            of = W.fetch
            W.fetch = lambda *a, **k: (W.Response(200, "u", {W.UNDECODABLE: "br"}, b""), None)
            try:
                summ = WE.fetch_all(caps, [_Exit("direct")], on_body=lambda d, c, b: got.__setitem__(d, b))
            finally:
                W.fetch = of
            check("an undecodable capture is NOT marked done (a later run retries it)",
                  got == {} and "D0" in summ["undecodable"], detail=(got, summ.get("undecodable")))
        finally:
            W._brotli_decompress = o
    finally:
        restore()


# --- 8. first/last seen span the digest's WHOLE capture range --------------------------------
def test_digest_range_spans_every_run_and_url():
    # one content version D1: captured 2019 (run of 3) under /, then again 2024 under /index.html
    page = [["timestamp", "original", "digest", "endtimestamp", "groupcount"],
            ["20190101000000", "http://a.example/", "D1", "20190301000000", "3"],
            ["20200101000000", "http://a.example/", "D2", "20200101000000", "1"],
            ["20240601000000", "http://a.example/index.html", "D1", "20240901000000", "2"]]
    restore = _patch(lambda req, timeout=None: _Resp(json.dumps(page)))
    try:
        caps, err = WE.enumerate_captures("a.example", include_assets=False, page_rows=100)
        d1 = caps.get("D1") or {}
        check("a digest's first/last cover every run and URL (2019 → 2024), fetched once",
              (d1.get("first"), d1.get("last"), d1.get("n")) == ("20190101000000", "20240901000000", 5),
              detail=d1)
    finally:
        restore()


# --- 9. earlier-owner split at the registration date ----------------------------------------
def test_prior_owner_selectors_are_split_out_and_never_indicators():
    recs = {"email\told@prev.example": {"kind": "email", "value": "old@prev.example",
                                        "first": "20180101000000", "last": "20201231000000", "hits": 4},
            "email\tops@now.example": {"kind": "email", "value": "ops@now.example",
                                       "first": "20220301000000", "last": "20240101000000", "hits": 9},
            "email\tkept@both.example": {"kind": "email", "value": "kept@both.example",
                                         "first": "20200601000000", "last": "20230101000000", "hits": 5}}
    eras = WE.split_eras(recs, "20220101")                   # registered 2022-01-01
    check("seen only before registration → prior era",
          [r["value"] for r in eras["prior"]] == ["old@prev.example"], detail=eras["prior"])
    check("seen only after → current", [r["value"] for r in eras["current"]] == ["ops@now.example"])
    check("seen before AND after → spans (kept, flagged)", [r["value"] for r in eras["spans"]] == ["kept@both.example"])
    check("no registration date → every record undated (split not claimed)",
          len(WE.split_eras(recs, "")["undated"]) == 3)

    sp = os.path.join(_TMP, "eras_state.json")
    WE._save_state(sp, {"host": "a.example", "records": recs, "registration_created": "20220101",
                        "registration_source": "test"})
    inds = WE.indicators(sp)
    blob = json.dumps(inds)
    check("a prior-era selector never becomes an indicator", "old@prev.example" not in blob, detail=blob[:200])
    check("current + spanning selectors do", "ops@now.example" in blob and "kept@both.example" in blob)
    counts = WE.write_eras(sp, WE._load_state(sp))
    doc = json.load(open(counts["file"]))
    check("eras file carries the prior-era caveat and records",
          counts["prior_era"] == 1 and "EARLIER owner" in doc["prior_era"]["caveat"], detail=counts)

    # registration date from a case WHOIS sidecar under $INTEL_HOME (no network)
    home = tempfile.mkdtemp(prefix="wb-home-")
    os.makedirs(os.path.join(home, "cases", "CASE-0001", "whois"))
    json.dump({"created": "2022-01-01 00:00:00 UTC"},
              open(os.path.join(home, "cases", "CASE-0001", "whois", "a.example.json"), "w"))
    saved = os.environ.get("INTEL_HOME")
    os.environ["INTEL_HOME"] = home
    try:
        got = WE.registration_date("a.example", "CASE-0001", lookup=False)
        check("registration date read from the case WHOIS sidecar", got[0] == "20220101", detail=got)
        check("explicit --created wins", WE.registration_date("a.example", "CASE-0001", "2021-05-05",
                                                              lookup=False)[0] == "20210505")
    finally:
        if saved is None:
            os.environ.pop("INTEL_HOME", None)
        else:
            os.environ["INTEL_HOME"] = saved


# --- 10. detached-job lock: one job per state file, stale lock reclaimed --------------------------
def test_job_lock_is_exclusive_and_a_dead_holder_is_reclaimed():
    sp = os.path.join(_TMP, "lock_state.json")
    for p in (WE._lock_path(sp),):
        try:
            os.remove(p)
        except OSError:
            pass
    check("first acquire succeeds", WE._acquire_lock(sp) is True)
    check("a second acquire on the same state is refused while the holder lives",
          WE._acquire_lock(sp) is False)
    WE._release_lock(sp)
    # a lock left by a killed job (dead pid) must not block the next run
    json.dump({"pid": 999999, "started": 0}, open(WE._lock_path(sp), "w"))
    check("a stale lock (dead pid) is reclaimed", WE._acquire_lock(sp) is True)
    WE._save_state(sp, {"host": "a.example", "captures": {"D0": {}}, "done": [], "records": {}})
    check("status shows the job running while its lock is held", WE.job_status(sp)["running"] is True)
    WE._release_lock(sp)
    st = WE.job_status(sp)
    check("status reads progress from the state file once the job ended (no network)",
          st["running"] is False and st["state_captures"] == 1 and st["remaining"] == 1, detail=st)


_TESTS = [
    test_id_playback_gzip_is_decompressed,
    test_index_pages_walks_every_page_via_resumekey,
    test_enumerate_dedupes_by_digest_across_urls,
    test_fetch_all_records_dead_requeues_transient_and_resume_skips_done,
    test_urlscan_exhaust_pages_search_spends_and_resumes,
    test_urlscan_search_cursor_is_saved_per_page_so_a_kill_resumes_mid_listing,
    test_urlscan_paging_ignores_a_false_has_more_while_total_says_more,
    test_urlscan_dom_429_stops_and_a_kill_never_respends,
    test_urlscan_free_only_lists_but_spends_nothing,
    test_exits_parse_specs_and_strip_credentials,
    test_brotli_body_is_decoded_or_marked_not_read,
    test_digest_range_spans_every_run_and_url,
    test_prior_owner_selectors_are_split_out_and_never_indicators,
    test_job_lock_is_exclusive_and_a_dead_holder_is_reclaimed,
]


def check_all():
    for t in _TESTS:
        try:
            t()
        except Exception as exc:  # noqa: BLE001
            FAILURES.append(f"{t.__name__}: {exc}")
            print(f"  FAIL {t.__name__}: {exc}")


if __name__ == "__main__":
    check_all()
    print(f"\n{'PASS — exhaustive archive tests green' if not FAILURES else 'FAIL: ' + '; '.join(FAILURES)}")
    raise SystemExit(bool(FAILURES))
