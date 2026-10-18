#!/usr/bin/env python3
"""Regression: the default fetch/screenshot/archive User-Agent is Android Chrome (project
decision), not a desktop OS. Covers wp_common.DEFAULT_UA, the fetch_profile.json rotation pool,
screenshot.json's capture UA, and house_report_captures's archive UA (read from the SAME
reference data — never a separate hardcoded literal). The ONE exception: archive.org hosts get
wp_wayback_guard's honest client UA (archive.org 429s a browser UA from a script client) —
proven here on the real Wayback request path, and that every other host keeps Android.

Run:  python3 tests/test_android_ua_defaults.py
Fully offline; no network, no metered calls.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
ENGINE = os.path.join(ROOT, "intel_engine")
WP = os.path.join(ENGINE, "WebPivot", "tools")
if WP not in sys.path:
    sys.path.insert(0, WP)
TOOLS = os.path.join(ENGINE, "tools")
if TOOLS not in sys.path:
    sys.path.insert(0, TOOLS)


def _is_android_chrome(ua: str) -> bool:
    return "Android" in ua and "Chrome/" in ua


def test_wp_common_default_ua_is_android():
    import wp_common as C
    assert _is_android_chrome(C.DEFAULT_UA), C.DEFAULT_UA
    # fetch()/screenshot() call sites default to this same constant — no per-call literal.
    assert _is_android_chrome(C.UA_POOL[0]), C.UA_POOL


def test_fetch_profile_json_rotation_pool_is_android_only():
    path = os.path.join(ENGINE, "WebPivot", "references", "fetch_profile.json")
    doc = json.load(open(path, encoding="utf-8"))
    values = doc["ua_pool"]["values"]
    assert len(values) >= 2, values
    assert all(_is_android_chrome(v) for v in values), values
    assert not any("Windows" in v or "Macintosh" in v or "iPhone" in v for v in values), values


def test_screenshot_json_user_agent_is_android():
    path = os.path.join(ENGINE, "WebPivot", "references", "screenshot.json")
    doc = json.load(open(path, encoding="utf-8"))
    ua = doc["capture"]["user_agent"]
    assert _is_android_chrome(ua), ua


def test_house_report_archive_ua_reads_the_shared_reference_not_a_literal():
    import house_report_captures as hrc
    ua = hrc._archive_ua()
    assert _is_android_chrome(ua), ua
    # it must be sourced from wp_common's reference-backed pool, not its own literal
    import wp_common as C
    assert ua == C.UA_POOL[0], (ua, C.UA_POOL)


def test_archive_org_alone_gets_the_honest_client_ua():
    # archive.org 429s a browser UA from a script client; every OTHER host keeps the Android UA.
    import wp_common as C
    import wp_wayback_guard as wg
    honest = wg.archive_user_agent()
    assert honest and not _is_android_chrome(honest), honest
    for url in ("https://web.archive.org/web/2024id_/https://site.example/",
                "https://web.archive.org/save/https://site.example/", "archive.org"):
        assert wg.ua_for(url, C.DEFAULT_UA) == honest, url
    for url in ("https://site.example/", "https://urlscan.io/api/v1/search/",
                "https://archive.org.evil.example/", "https://archive.ph/x"):
        assert wg.ua_for(url, C.DEFAULT_UA) == C.DEFAULT_UA, url


class _ArchiveProxy:
    """A loopback HTTP proxy that impersonates web.archive.org and a target host, records the UA
    each hop arrives with, and redirects archive paths: /off → the target, /in → back to archive."""

    def __init__(self):
        import http.server
        import threading
        seen = self.seen = []

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append((self.path, self.headers.get("User-Agent")))
                loc = {"http://web.archive.org/off": "http://target.example/page",
                       "http://web.archive.org/in": "http://web.archive.org/final"}.get(self.path)
                self.send_response(302 if loc else 200)
                if loc:
                    self.send_header("Location", loc)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"[]")

            def log_message(self, *a):
                pass

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def ua_at(self, url):
        return next((ua for p, ua in self.seen if p == url), None)

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


def test_wayback_client_scopes_the_ua_on_every_redirect_hop():
    # The real request path through urllib's own redirect handling: callers hand the client the
    # Android UA; archive.org hops get the honest UA, a hop OFF the archive gets Android back.
    import tempfile
    import urllib.request
    import wp_common as C
    import wp_wayback as W
    import wp_wayback_guard as wg
    proxy = _ArchiveProxy()

    class _Exit:
        id = "test-exit"

        def open(self, req, timeout=None):
            return urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": proxy.url})).open(req, timeout=timeout)

    keys = ("WAYBACK_MIN_INTERVAL", "WAYBACK_PACE_STATE", "WAYBACK_GUARD_STATE")
    saved = {k: os.environ.get(k) for k in keys}
    try:
        with tempfile.TemporaryDirectory() as td:
            os.environ.update({"WAYBACK_MIN_INTERVAL": "0",
                               "WAYBACK_PACE_STATE": os.path.join(td, "pace.json"),
                               "WAYBACK_GUARD_STATE": os.path.join(td, "breaker.json")})
            for path in ("off", "in"):
                W._once(f"http://web.archive.org/{path}", C.DEFAULT_UA, 10, "GET", None,
                        exit=_Exit())
    finally:
        proxy.close()
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    honest = wg.archive_user_agent()
    assert proxy.ua_at("http://web.archive.org/off") == honest, proxy.seen
    assert proxy.ua_at("http://target.example/page") == C.DEFAULT_UA, \
        f"archive -> target redirect leaked the archive UA to the target: {proxy.seen}"
    assert proxy.ua_at("http://web.archive.org/final") == honest, \
        f"archive -> archive redirect lost the honest UA: {proxy.seen}"


def test_save_page_now_session_scopes_the_ua_on_every_redirect_hop():
    # wayback_save's requests path: requests keeps headers across redirects unless re-scoped.
    import wp_common as C
    import wp_net
    import wp_wayback_guard as wg
    if not wp_net.HAVE_REQUESTS:
        return                      # urllib fallback is covered by the wayback-client test
    proxy = _ArchiveProxy()
    try:
        with wp_net._UAScopedSession(C.DEFAULT_UA) as s:
            s.trust_env = False
            s.get("http://web.archive.org/off",
                  headers={"User-Agent": wg.ua_for("web.archive.org", C.DEFAULT_UA)},
                  proxies={"http": proxy.url}, timeout=10)
    finally:
        proxy.close()
    assert proxy.ua_at("http://web.archive.org/off") == wg.archive_user_agent(), proxy.seen
    assert proxy.ua_at("http://target.example/page") == C.DEFAULT_UA, \
        f"Save Page Now redirect leaked the archive UA to the target: {proxy.seen}"


_TESTS = [test_wp_common_default_ua_is_android, test_fetch_profile_json_rotation_pool_is_android_only,
          test_screenshot_json_user_agent_is_android,
          test_house_report_archive_ua_reads_the_shared_reference_not_a_literal,
          test_archive_org_alone_gets_the_honest_client_ua,
          test_wayback_client_scopes_the_ua_on_every_redirect_hop,
          test_save_page_now_session_scopes_the_ua_on_every_redirect_hop]


def check():
    passed = failed = 0
    lines = []
    for test in _TESTS:
        label = test.__name__.removeprefix("test_").replace("_", " ")
        try:
            test()
        except Exception as exc:  # noqa: BLE001
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
