"""Regression: the collector must not manufacture same-operator evidence out of its own recovery
path, and must not misreport a live capture as dead.

  1. `wp_net._playwright_proxy` hands Chromium the pool's credentials as separate fields (an
     inline `user:pass@` URL made every render answer 407 → empty DOM → silent archive fallback).
  2. `wp_net.wayback_raw_url` turns a snapshot URL into its `id_` form (original bytes, no
     archive toolbar) — the toolbar's HTML comments once linked every archive-recovered host in
     the KB to every other one.
  3. `noise_filters.is_boilerplate_comment` treats the toolbar comments as boilerplate (belt).
  4. `wp_liveness.from_pivot_result` reads the status / DOM path where the collector writes them
     (artifacts.http.status, meta.raw_dom_file) and does not call a served page `no_http`.
Synthetic data only: example.com, RFC 5737 addresses."""
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "intel_engine", "WebPivot", "tools"))
sys.path.insert(0, os.path.join(ROOT, "intel_engine", "tools", "kb"))

import wp_net  # noqa: E402
import wp_liveness  # noqa: E402
import noise_filters  # noqa: E402

_PROXY_ENV = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy",
              "NO_PROXY", "no_proxy")


def _clear_env():
    saved = {k: os.environ.pop(k) for k in _PROXY_ENV if k in os.environ}
    return saved


def _restore_env(saved):
    for k in _PROXY_ENV:
        os.environ.pop(k, None)
    os.environ.update(saved)


def test_proxy_credentials_are_split_for_chromium():
    saved = _clear_env()
    try:
        cfg = wp_net._playwright_proxy("http://us%40er:p%3Ass@198.51.100.7:8080")
        assert cfg == {"server": "http://198.51.100.7:8080", "username": "us@er", "password": "p:ss"}, cfg
        assert wp_net._playwright_proxy("socks5h://198.51.100.7:1080") == {"server": "socks5://198.51.100.7:1080"}
        assert wp_net._playwright_proxy(None) is None, "no proxy anywhere must mean a direct launch"
        os.environ["HTTPS_PROXY"] = "http://u:p@198.51.100.9:3128"
        os.environ["NO_PROXY"] = "localhost,127.0.0.1"
        cfg = wp_net._playwright_proxy(None)
        assert cfg["server"] == "http://198.51.100.9:3128" and cfg["username"] == "u" \
            and cfg["password"] == "p" and cfg["bypass"] == "localhost,127.0.0.1", cfg
    finally:
        _restore_env(saved)


def test_wayback_snapshot_is_fetched_in_raw_id_mode():
    raw = wp_net.wayback_raw_url("http://web.archive.org/web/20260211101335/https://seed.example.com/")
    assert raw == "https://web.archive.org/web/20260211101335id_/https://seed.example.com/", raw
    # already-flagged forms are normalised, non-Wayback input is untouched
    assert wp_net.wayback_raw_url("https://web.archive.org/web/20260211101335if_/https://seed.example.com/x") \
        == "https://web.archive.org/web/20260211101335id_/https://seed.example.com/x"
    assert wp_net.wayback_raw_url("https://seed.example.com/") == "https://seed.example.com/"


def test_archive_toolbar_and_widget_comments_are_boilerplate():
    for c in ("next/prev month nav and month indicator", "next/prev capture nav and day of month indicator",
              "begin wayback toolbar insert", "end wayback rewrite js include",
              "gtranslate: https://gtranslate.com", "start of fchat.vn"):
        assert noise_filters.is_boilerplate_comment(c), c
    assert not noise_filters.is_boilerplate_comment("thiết kế bởi example studio - license 0201234567"), \
        "an operator's own credit line must survive as a tell"


def _raw(tmp, status, dom_html, recovered=None, live_error=None):
    dom = os.path.join(tmp, "seed.example.com.html")
    open(dom, "w", encoding="utf-8").write(dom_html)
    meta = {"source": "https://seed.example.com", "final_url": "https://seed.example.com/",
            "host": "seed.example.com", "raw_dom_file": dom, "recovered_via": recovered}
    if live_error:
        meta["live_error"] = live_error
    return {"meta": meta,
            "artifacts": {"title": "Example shop", "http": {"status": status},
                          "server_headers": {"server": "cloudflare"}},
            "pivots": [{"kind": "domain", "value": "seed.example.com",
                        "live_results": {"dns": {"ips": ["203.0.113.10"], "ns": ["ns1.example.net"]}}}]}


_PAGE = "<html><head><title>Example shop</title></head><body>" + ("<p>Real product copy, prices, cart.</p>" * 40) + "</body></html>"


def test_live_capture_with_status_under_artifacts_is_live():
    with tempfile.TemporaryDirectory() as tmp:
        r = wp_liveness.from_pivot_result(_raw(tmp, 200, _PAGE))
        assert r["state"] == "live" and r["http_status"] == 200, r
        assert r["server"] == "cloudflare"


def test_live_capture_missing_status_code_is_not_no_http():
    with tempfile.TemporaryDirectory() as tmp:
        r = wp_liveness.from_pivot_result(_raw(tmp, None, _PAGE))
        assert r["state"] == "live", r["state"]


def test_archive_recovered_capture_without_status_stays_no_http():
    with tempfile.TemporaryDirectory() as tmp:
        r = wp_liveness.from_pivot_result(_raw(tmp, None, _PAGE, recovered="wayback:20250101000000"))
        assert r["state"] == "no_http", r["state"]


def test_title_only_capture_never_infers_a_status():
    with tempfile.TemporaryDirectory() as tmp:
        raw = _raw(tmp, None, _PAGE)
        raw["meta"].pop("raw_dom_file")                       # no document on disk, only the title
        raw["artifacts"]["description"] = "x" * 400            # a long description is not a page read
        r = wp_liveness.from_pivot_result(raw)
        assert r["state"] != "live" and r["http_status"] is None, (r["state"], r["http_status"])


def test_captcha_widget_on_a_real_page_is_not_a_bot_wall():
    page = ("<html><head><title>Example shop</title></head><body>"
            + "<p>Real product copy, prices, cart, terms and contact details.</p>" * 40
            + '<div class="grecaptcha-badge"><iframe title="reCAPTCHA"></iframe></div></body></html>')
    r = wp_liveness.classify(url="https://seed.example.com", status=200, body=page, ips=["203.0.113.10"])
    assert r["state"] == "live", (r["state"], r["reason"])
    wall = ("<html><head><title>Just a moment...</title></head><body>Checking your browser before "
            "accessing seed.example.com. Please complete the captcha.</body></html>")
    r = wp_liveness.classify(url="https://seed.example.com", status=200, body=wall, ips=["203.0.113.10"])
    assert r["state"] == "blocked", r["state"]


_TESTS = [
    test_proxy_credentials_are_split_for_chromium,
    test_wayback_snapshot_is_fetched_in_raw_id_mode,
    test_archive_toolbar_and_widget_comments_are_boilerplate,
    test_live_capture_with_status_under_artifacts_is_live,
    test_live_capture_missing_status_code_is_not_no_http,
    test_archive_recovered_capture_without_status_stays_no_http,
    test_title_only_capture_never_infers_a_status,
    test_captcha_widget_on_a_real_page_is_not_a_bot_wall,
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
