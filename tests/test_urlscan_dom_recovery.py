#!/usr/bin/env python3
"""Regression: urlscan_dom / urlscan_dom_all must decode the stored response body through
wp_common._decode_body (honouring Content-Encoding, with a gzip-magic sniff fallback) before
treating it as text. Before the fix, a bare `.decode("utf-8", "ignore")` of a gzip body (urlscan
serves gzip bytes without always sending an accurate Content-Encoding) produced binary junk:
every extractor then returned empty while meta still said the run was fine.

Run:  python3 tests/test_urlscan_dom_recovery.py
Fully offline (urllib.request.urlopen stubbed); no network, no metered calls.
Synthetic data only: site-a.example.
"""
import gzip
import io
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
WP = os.path.join(ROOT, "intel_engine", "WebPivot", "tools")
if WP not in sys.path:
    sys.path.insert(0, WP)

import wp_common as C  # noqa: E402
import wp_net as N  # noqa: E402
import wp_analyze as WA  # noqa: E402


class _Resp(io.BytesIO):
    def __init__(self, data, headers=None):
        super().__init__(data)
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


# padded past the 200-byte DOM-recovery minimum floor (urlscan_dom/urlscan_dom_all both refuse
# a shorter body — a genuine landing page clears it easily; this mirrors that, not a shortcut).
_PAGE = ("<html><head><title>Example shop</title></head><body>"
        "<p>Real product copy, prices, and a cart, repeated so the page clears the DOM-recovery "
        "minimum-length floor (200 bytes) the same way a genuine landing page would.</p>"
        "<p>Contact us: owner@site-a.example for support.</p>"
        "</body></html>")


def test_decode_body_sniffs_gzip_magic_without_header():
    raw = gzip.compress(b"hello world")
    assert C._decode_body(raw, None) == b"hello world", "missing Content-Encoding still sniffs gzip"
    assert C._decode_body(raw, "") == b"hello world"
    assert C._decode_body(raw, "gzip") == b"hello world", "an accurate header still works"
    assert C._decode_body(b"plain text", None) == b"plain text", "uncompressed body passes through"


def test_urlscan_dom_decodes_gzip_body_and_yields_extracted_emails():
    gz = gzip.compress(_PAGE.encode("utf-8"))
    saved_urlopen = N.urllib.request.urlopen

    def _fake_urlopen(req, timeout=None):
        # urlscan can serve gzip bytes without an accurate Content-Encoding (measured 2026-09) —
        # the magic-byte sniff in _decode_body must recover it regardless of the (absent) header.
        return _Resp(gz, headers={})

    N.urllib.request.urlopen = _fake_urlopen
    try:
        intel = {"recent_scans": [{"result": "https://urlscan.io/result/" + "a" * 36 + "/"}]}
        html, uid, gate = N.urlscan_dom(intel, free_only=False)
    finally:
        N.urllib.request.urlopen = saved_urlopen
    assert uid == "a" * 36, uid
    assert "owner@site-a.example" in html, html
    assert gate is None, gate
    assert not N.dom_is_binary_junk(html), "properly decoded HTML must never read as junk"
    result = WA.analyze("site-a.example", html, "https://site-a.example/", {}, C.DEFAULT_UA)
    assert "owner@site-a.example" in result["artifacts"]["emails"], result["artifacts"]["emails"]


def test_urlscan_dom_all_dedupes_on_decoded_text_not_raw_bytes():
    gz = gzip.compress(_PAGE.encode("utf-8"))
    saved_urlopen = N.urllib.request.urlopen
    N.urllib.request.urlopen = lambda req, timeout=None: _Resp(gz, headers={})
    try:
        intel = {"all_scans": [
            {"uuid": "c" * 36, "url": "https://site-a.example/", "time": "2026-01-01T00:00:00Z"},
            {"uuid": "d" * 36, "url": "https://site-a.example/", "time": "2026-01-02T00:00:00Z"},
        ]}
        doms = N.urlscan_dom_all(intel, free_only=True)  # keyless: no api_usage ledgering
    finally:
        N.urllib.request.urlopen = saved_urlopen
    assert len(doms) == 1, doms  # identical decoded text -> deduped by sha256 of the DECODED body
    assert "owner@site-a.example" in doms[0]["html"], doms


def test_dom_is_binary_junk_flags_undecoded_gzip():
    gz = gzip.compress(_PAGE.encode("utf-8"))
    junk = gz.decode("utf-8", "ignore")  # the OLD bug: gzip bytes decoded straight as UTF-8
    assert N.dom_is_binary_junk(junk), junk[:80]
    assert not N.dom_is_binary_junk(_PAGE)
    assert not N.dom_is_binary_junk("")


# --- gated scans (Quarry gated_reason port) -----------------------------------------------------
_CHALLENGE = ("<html><head><title>Just a moment...</title></head><body>"
              + "<div id='cf-challenge'>Checking if the site connection is secure</div>" * 6
              + "<script src='/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1'></script>"
              "</body></html>")
_NEW, _OLD = "e" * 36, "f" * 36


def _search_row(uid, time, status, title, ip="192.0.2.10"):
    return {"_id": uid, "task": {"time": time},
            "page": {"domain": "site-a.example", "url": "https://site-a.example/", "ip": ip,
                     "status": status, "title": title}}


def _stub(search_rows, dom_by_uuid, calls):
    import json as _json

    def _urlopen(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else req
        calls.append(url)
        if "/api/v1/search/" in url:
            return _Resp(_json.dumps({"total": len(search_rows), "results": search_rows}).encode())
        uid = url.rstrip("/").rsplit("/", 1)[-1]
        if "/dom/" in url and uid in dom_by_uuid:
            return _Resp(dom_by_uuid[uid].encode("utf-8"))
        raise OSError("unexpected " + url)
    return _urlopen


def _with(urlopen, fn):
    saved, saved_usage = N.urllib.request.urlopen, N.api_usage
    N.urllib.request.urlopen, N.api_usage = urlopen, None     # no ledger writes from tests
    try:
        return fn()
    finally:
        N.urllib.request.urlopen, N.api_usage = saved, saved_usage


def test_cloudflare_challenge_scan_is_gated_and_dom_uses_older_ungated_scan():
    calls = []
    rows = [_search_row(_NEW, "2026-03-01T00:00:00Z", "403", "Just  a moment..."),
            _search_row(_OLD, "2026-01-01T00:00:00Z", "200", "Example shop")]
    stub = _stub(rows, {_NEW: _CHALLENGE, _OLD: _PAGE}, calls)
    intel = _with(stub, lambda: N.urlscan_intel("site-a.example", free_only=True))
    assert [s["gated"] for s in intel["recent_scans"]] == ["http_403", None], intel["recent_scans"]
    html, uid, gate = _with(stub, lambda: N.urlscan_dom(intel, free_only=True))
    assert uid == _OLD and "owner@site-a.example" in html, (uid, html[:80])
    assert gate is None, gate
    assert not any(f"/dom/{_NEW}/" in c for c in calls), "a row known gated must not be fetched"
    assert [s["uuid"] for s in N.urlscan_ungated_scans(intel)] == [_OLD]
    doms = _with(stub, lambda: N.urlscan_dom_all(intel, free_only=True))
    assert [d["uuid"] for d in doms] == [_OLD], [d["uuid"] for d in doms]


def test_challenge_dom_without_row_metadata_is_gated_by_its_title():
    # legacy / keyless intel rows carry no status or title — the fetched DOM's <title> decides
    intel = {"recent_scans": [{"result": f"https://urlscan.io/result/{_NEW}/"},
                              {"result": f"https://urlscan.io/result/{_OLD}/"}]}
    html, uid, gate = _with(_stub([], {_NEW: _CHALLENGE, _OLD: _PAGE}, []),
                            lambda: N.urlscan_dom(intel, free_only=True))
    assert uid == _OLD and gate is None, (uid, gate)


def test_gated_reason_labels_statuses_titles_and_real_pages():
    assert N.urlscan_gated_reason({"labels": ["content.chromeerror"],
                                   "page": {"status": "200", "ip": "192.0.2.1"}}) == "chrome_error"
    assert N.urlscan_gated_reason({"page": {"status": "200", "ip": "192.0.2.1",
                                            "title": "Attention Required! | Cloudflare"}}) == "challenge_page"
    assert N.urlscan_gated_reason({"page": {"status": 521, "ip": "192.0.2.1"}}) == "http_521"
    assert N.urlscan_gated_reason({"page": {}}) == "no_response"
    # exact title match: a real page whose title merely CONTAINS a gate phrase is the site
    assert N.urlscan_gated_reason({"page": {"status": "200", "ip": "192.0.2.1",
                                            "title": "Access denied — member login"}}) is None
    assert N.urlscan_gated_reason({"result": f"https://urlscan.io/result/{_OLD}/"}) is None


def test_all_gated_scans_report_skipped_reason_not_a_challenge_page():
    rows = [_search_row(_NEW, "2026-03-01T00:00:00Z", "503", "Just a moment..."),
            _search_row(_OLD, "2026-01-01T00:00:00Z", "200", "DDoS-Guard")]
    stub = _stub(rows, {_NEW: _CHALLENGE, _OLD: _CHALLENGE}, [])
    intel = _with(stub, lambda: N.urlscan_intel("site-a.example", free_only=True))
    html, uid, gate = _with(stub, lambda: N.urlscan_dom(intel, free_only=True))
    assert html == "" and uid is None, (uid, html[:60])
    assert gate and gate["all_gated"] and "gated" in gate["skipped"], gate
    assert {g["reason"] for g in gate["gated"]} == {"http_503", "challenge_page"}, gate
    assert _with(stub, lambda: N.urlscan_dom_all(intel, free_only=True)) == []


def test_all_gated_vn_target_plans_one_country_and_android_ua_submit():
    intel = {"recent_scans": [{"uuid": _NEW, "gated": "http_403"},
                              {"uuid": _OLD, "gated": "challenge_page"}]}
    plan = N.urlscan_gated_resubmit("https://shop.site-a.example.vn/", intel=intel)
    assert plan and plan["country"] == "vn" and "Android" in plan["customagent"], plan
    sent = []

    def _urlopen(req, timeout=None):
        import json as _json
        sent.append(_json.loads(req.data.decode()))
        return _Resp(b'{"uuid": "' + _NEW.encode() + b'", "visibility": "unlisted"}')
    saved = (N.HAVE_REQUESTS, os.environ.get("URLSCAN_API_KEY"))
    N.HAVE_REQUESTS, os.environ["URLSCAN_API_KEY"] = False, "test-key"
    try:
        out = _with(_urlopen, lambda: N.urlscan_submit("https://shop.site-a.example.vn/",
                                                       country=plan["country"],
                                                       customagent=plan["customagent"]))
    finally:
        N.HAVE_REQUESTS = saved[0]
        if saved[1] is None:
            os.environ.pop("URLSCAN_API_KEY", None)
        else:
            os.environ["URLSCAN_API_KEY"] = saved[1]
    assert len(sent) == 1 and sent[0]["country"] == "vn", sent
    assert sent[0]["customagent"] == C.DEFAULT_UA, sent
    assert out.get("uuid") == _NEW and out.get("country") == "vn", out


def test_resubmit_plan_needs_every_scan_gated_and_a_real_cctld():
    one_ok = {"recent_scans": [{"uuid": _NEW, "gated": "http_403"}, {"uuid": _OLD, "gated": None}]}
    assert N.urlscan_gated_resubmit("https://site-a.example.vn/", intel=one_ok) is None
    assert N.urlscan_gated_resubmit("https://site-a.example.vn/", intel={"recent_scans": []}) is None
    gated = {"recent_scans": [{"uuid": _NEW, "gated": "http_403"}]}
    assert "country" not in N.urlscan_gated_resubmit("https://site-a.example.io/", intel=gated)
    assert N.urlscan_cctld_country("https://site-a.example.co.uk/x") == "gb"
    assert N.urlscan_cctld_country("192.0.2.7") == ""
    # a DOM-title gate alone (rows carried no metadata) still triggers the plan
    legacy = {"recent_scans": [{"result": f"https://urlscan.io/result/{_NEW}/"}]}
    dom_gate = {"all_gated": True, "gated": [{"uuid": _NEW, "reason": "challenge_page"}]}
    assert N.urlscan_gated_resubmit("https://site-a.example.vn/", intel=legacy,
                                    dom_gate=dom_gate)["country"] == "vn"


def test_free_only_blocks_the_gated_resubmit():
    calls = []
    saved = os.environ.get("URLSCAN_API_KEY")
    os.environ["URLSCAN_API_KEY"] = "test-key"
    try:
        out = _with(lambda req, timeout=None: calls.append(req) or _Resp(b"{}"),
                    lambda: N.urlscan_submit("https://site-a.example.vn/", country="vn",
                                             customagent=C.DEFAULT_UA, free_only=True))
    finally:
        if saved is None:
            os.environ.pop("URLSCAN_API_KEY", None)
        else:
            os.environ["URLSCAN_API_KEY"] = saved
    assert "free-only" in (out.get("skipped") or ""), out
    assert calls == [], "free-only must not reach urlscan"


_TESTS = [
    test_decode_body_sniffs_gzip_magic_without_header,
    test_urlscan_dom_decodes_gzip_body_and_yields_extracted_emails,
    test_urlscan_dom_all_dedupes_on_decoded_text_not_raw_bytes,
    test_dom_is_binary_junk_flags_undecoded_gzip,
    test_cloudflare_challenge_scan_is_gated_and_dom_uses_older_ungated_scan,
    test_challenge_dom_without_row_metadata_is_gated_by_its_title,
    test_gated_reason_labels_statuses_titles_and_real_pages,
    test_all_gated_scans_report_skipped_reason_not_a_challenge_page,
    test_all_gated_vn_target_plans_one_country_and_android_ua_submit,
    test_resubmit_plan_needs_every_scan_gated_and_a_real_cctld,
    test_free_only_blocks_the_gated_resubmit,
]


def check():
    passed = failed = 0
    lines = []
    for test in _TESTS:
        label = test.__name__.removeprefix("test_").replace("_", " ")
        try:
            test()
        except Exception as exc:  # noqa: BLE001 — report every independent contract
            failed += 1
            lines.append(("FAIL", f"{label}: {exc}"))
        else:
            passed += 1
            lines.append(("ok", label))
    return passed, failed, lines


if __name__ == "__main__":
    _passed, _failed, _lines = check()
    for _status, _label in _lines:
        print(("ok" if _status == "ok" else "FAIL") + "  " + _label)
    raise SystemExit(bool(_failed))
