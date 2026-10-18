#!/usr/bin/env python3
"""test_render_parity.py — the rails around the two browser engines (wp_browser / wp_moli).

Run:  python3 tests/test_render_parity.py        (zero deps; engine-dependent checks skip)

WHAT THIS PROTECTS
  1. Evidence PIXELS and the Cloudflare-escalation render never reach Moli, whatever CTI_BROWSER
     says: without Chromium they are refused, never substituted.
  2. A proxy whose scheme did not pass the Gate-0 egress probe is never handed to Moli — `auto`
     routes that render to Chromium, `moli` refuses — and the check reads the process proxy env
     too (cti_proxy exports a SOCKS pool only as ALL_PROXY).
  3. Chromium counts as installed only when the exact revision Playwright launches is on disk.
  4. A Moli render egresses through the configured proxy or not at all: wrong credentials and a
     dead proxy fail without the origin ever seeing a direct connection. (Needs moli.)
  5. A Moli DOM that is a Cloudflare interstitial is recorded as a challenge, not collected as the
     page, and the escalation refuses without Chromium. (Needs moli.)
  6. Moli and Chromium yield the same pivots on a JavaScript-built page. (Needs both.)
Synthetic data only: *.example, loopback servers."""
import base64
import http.server
import json
import os
import select
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WP = os.path.join(ROOT, "intel_engine", "WebPivot", "tools")
sys.path.insert(0, WP)

import wp_browser  # noqa: E402
import wp_moli  # noqa: E402

_PROXY_ENV = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy",
              "NO_PROXY", "no_proxy", "CTI_BROWSER", "PLAYWRIGHT_BROWSERS_PATH")


class Skip(Exception):
    pass


class _Env:
    """Isolate proxy/engine env and stub the two availability probes for one routing check."""

    def __init__(self, moli=True, chromium=True, **env):
        self.moli, self.chromium, self.env = moli, chromium, env

    def __enter__(self):
        self.saved_env = {k: os.environ.pop(k) for k in _PROXY_ENV if k in os.environ}
        os.environ.update(self.env)
        self.saved = (wp_moli.moli_configured, wp_browser.chromium_available)
        wp_moli.moli_configured = lambda: self.moli
        wp_browser.chromium_available = lambda: self.chromium
        return self

    def __exit__(self, *exc):
        wp_moli.moli_configured, wp_browser.chromium_available = self.saved
        for k in _PROXY_ENV:
            os.environ.pop(k, None)
        os.environ.update(self.saved_env)


def _engine(proxy=None, **kw):
    return wp_browser.select_dom_engine(proxy, **kw)[0]


# --------------------------------------------------------------------------- routing rails
def test_pixels_and_cloudflare_escalation_never_route_to_moli():
    for setting in ("auto", "moli", "chromium"):
        with _Env(CTI_BROWSER=setting):
            assert _engine(screenshot=True) == "chromium", setting
            assert _engine(cf_challenge=True) == "chromium", setting
        with _Env(chromium=False, CTI_BROWSER=setting):
            e, why = wp_browser.select_dom_engine(None, screenshot=True)
            assert e is None and "Chromium" in why, (setting, why)
            e, why = wp_browser.select_dom_engine(None, cf_challenge=True)
            assert e is None and "Chromium" in why, (setting, why)


def test_unverified_proxy_scheme_never_reaches_moli():
    verified = sorted(wp_moli.VERIFIED_PROXY_SCHEMES)
    assert "socks4" not in verified, "socks4 was never Gate-0 probed"
    with _Env(CTI_BROWSER="auto"):
        for s in verified:
            assert _engine(f"{s}://u:p@198.51.100.7:1080") == "moli", s
        assert _engine("socks4://198.51.100.7:1080") == "chromium"
        assert _engine(None) == "moli", "no proxy = direct, Moli allowed"
    with _Env(CTI_BROWSER="auto", ALL_PROXY="socks4://198.51.100.7:1080"):
        assert _engine(None) == "chromium", "the env SOCKS pool must be judged, not ignored"
    with _Env(chromium=False, CTI_BROWSER="auto"):
        assert _engine("socks4://198.51.100.7:1080") is None, "no engine may egress it -> refuse"
    with _Env(CTI_BROWSER="moli"):
        e, why = wp_browser.select_dom_engine("socks4://198.51.100.7:1080")
        assert e is None and "not verified" in why, why


def test_engine_setting_precedence():
    with _Env(CTI_BROWSER="chromium"):
        assert _engine() == "chromium"
    with _Env(chromium=False, CTI_BROWSER="chromium"):
        assert _engine() is None, "explicit chromium never silently becomes Moli"
    with _Env(moli=False, CTI_BROWSER="auto"):
        assert _engine() == "chromium"
    with _Env(moli=False, CTI_BROWSER="moli"):
        assert _engine() is None
    with _Env(CTI_BROWSER="netscape"):
        assert wp_browser.engine_setting() == "chromium", "unknown value degrades to chromium"


def test_moli_proxy_rides_the_environment_never_the_command_line():
    saved = (wp_moli.moli_bin, wp_moli._run)
    wp_moli.moli_bin = lambda: "/opt/moli"
    seen = []
    wp_moli._run = lambda argv, t, env: (seen.append((argv, env)), types.SimpleNamespace(
        returncode=0, stdout=json.dumps({"status": 200, "html": "x" * 500}), stderr=""))[1]
    try:
        with _Env(ALL_PROXY="socks4://198.51.100.9:1080"):
            try:
                wp_moli.fetch_dom("https://seed.example/")          # proxy=None -> the env pool
            except wp_moli.MoliError as e:
                assert "not verified" in str(e)
            else:
                raise AssertionError("an inherited unverified proxy was handed to moli")
            assert not seen, "a process was spawned for an unverified proxy"
            wp_moli.fetch_dom("https://seed.example/", proxy="http://us%40er:s3cr3t@198.51.100.7:3128",
                              ua="UA/1")
        argv, env = seen[-1]
        assert not any("s3cr3t" in a for a in argv), f"credentials on the command line: {argv}"
        assert not any("web-bot-auth" in a for a in argv), argv
        assert argv[argv.index("--user-agent") + 1] == "UA/1"
        for k in ("http_proxy", "HTTPS_PROXY", "ALL_PROXY", "all_proxy"):
            assert env[k] == "http://us%40er:s3cr3t@198.51.100.7:3128", (k, env.get(k))
    finally:
        wp_moli.moli_bin, wp_moli._run = saved


def test_moli_proxy_rejection_and_empty_shell_are_errors_not_pages():
    saved = (wp_moli.moli_bin, wp_moli._run)
    wp_moli.moli_bin = lambda: "/opt/moli"
    try:
        for doc, needle in (({"status": 407, "html": "x" * 500}, "407"),
                            ({"status": 200, "html": "<html></html>"}, "bytes"),
                            ({"status": 200, "html": None}, "non-HTML")):
            wp_moli._run = lambda argv, t, env, d=doc: types.SimpleNamespace(
                returncode=0, stdout=json.dumps(d), stderr="")
            try:
                wp_moli.fetch_dom("https://seed.example/", proxy="http://198.51.100.7:3128")
            except wp_moli.MoliError as e:
                assert needle in str(e), (needle, e)
            else:
                raise AssertionError(f"{doc} returned as a page")
    finally:
        wp_moli.moli_bin, wp_moli._run = saved


def test_moli_session_cookie_set_on_a_redirect_hop_is_kept():
    saved = (wp_moli.moli_bin, wp_moli._run)
    wp_moli.moli_bin = lambda: "/opt/moli"
    doc = {"status": 200, "html": "x" * 500, "headers": [{"name": "set-cookie", "value": "lang=vi; Path=/"}],
           "redirect_chain": [{"from_url": "https://panel.example/", "to_url": "https://panel.example/login",
                               "status": 302, "headers": [{"name": "Set-Cookie", "value": "PHPSESSID=abc; path=/"}]}]}
    wp_moli._run = lambda argv, t, env: types.SimpleNamespace(returncode=0, stdout=json.dumps(doc), stderr="")
    try:
        names = [c["name"] for c in wp_moli.fetch_dom("https://panel.example/", proxy="http://198.51.100.7:3128")["cookies"]]
        assert names == ["PHPSESSID", "lang"], names
    finally:
        wp_moli.moli_bin, wp_moli._run = saved


def test_chromium_counts_only_when_the_launched_revision_is_downloaded():
    import importlib.util
    with tempfile.TemporaryDirectory() as tmp:
        pkg = os.path.join(tmp, "playwright")
        os.makedirs(os.path.join(pkg, "driver", "package"))
        with open(os.path.join(pkg, "driver", "package", "browsers.json"), "w") as fh:
            json.dump({"browsers": [{"name": "chromium", "revision": "1208"},
                                    {"name": "chromium-headless-shell", "revision": "1208"}]}, fh)
        cache = os.path.join(tmp, "ms-playwright")
        os.makedirs(os.path.join(cache, "chromium_headless_shell-1223"))   # a DIFFERENT build
        saved_find, saved_env = importlib.util.find_spec, os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
        importlib.util.find_spec = lambda n, *a: (types.SimpleNamespace(submodule_search_locations=[pkg])
                                                  if n == "playwright" else saved_find(n, *a))
        os.environ["PLAYWRIGHT_BROWSERS_PATH"] = cache
        try:
            assert not wp_browser.chromium_available(), "a stale cached build is not a usable Chromium"
            os.makedirs(os.path.join(cache, "chromium_headless_shell-1208"))
            assert wp_browser.chromium_available()
        finally:
            importlib.util.find_spec = saved_find
            if saved_env is None:
                os.environ.pop("PLAYWRIGHT_BROWSERS_PATH", None)
            else:
                os.environ["PLAYWRIGHT_BROWSERS_PATH"] = saved_env


def test_evidence_screenshot_refuses_without_chromium():
    import wp_screenshot
    with tempfile.TemporaryDirectory() as tmp, _Env(chromium=False, CTI_BROWSER="moli"):
        try:
            wp_screenshot.capture_screenshot("https://seed.example/", outdir=tmp)
        except RuntimeError as e:
            assert "Chromium" in str(e), e
        else:
            raise AssertionError("a screenshot was attempted without Chromium")
        assert not any(f.endswith(".png") for _, _, fs in os.walk(tmp) for f in fs)


# --------------------------------------------------------------------------- live fixtures
SPA = (b"<html><head><title>Yield Desk</title></head><body><div id=app>loading</div><script>"
       b"document.getElementById('app').innerHTML='<p>support@desk.example</p>"
       b"<a href=\"https://t.me/desk_support_example\">tg</a><p>TExampLeTronAddressDoNotUseXXXXXXX</p>';"
       b"document.title='Yield Desk - Deposit';</script>" + b"<p>" + b"pad " * 80 + b"</p></body></html>")
CF = (b"<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>"
      b"<div id=cf-wrapper>Checking your browser. cf_chl_opt</div>" + b"<p>" + b"pad " * 80 + b"</p></body></html>")
USER, PASS = "gate", "p@ss:w0rd"
CRED = "gate:p%40ss%3Aw0rd"


class _Origin(http.server.BaseHTTPRequestHandler):
    hits = []

    def do_GET(self):
        _Origin.hits.append((self.path, self.headers.get("X-Via-Proxy")))
        cf = self.path.startswith("/cf")
        # /cfonce: the challenge only on the FIRST request (the render); the raw fetch that follows
        # gets a bare 503 that is not itself recognisable as Cloudflare.
        if self.path.startswith("/cfonce") and sum(p == self.path for p, _ in _Origin.hits) > 1:
            self.send_response(503)
            self.send_header("Content-Length", "4")
            self.end_headers()
            self.wfile.write(b"busy")
            return
        body = CF if cf else SPA
        self.send_response(403 if cf else 200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        if cf:
            self.send_header("Server", "cloudflare")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _pipe(a, b):
    try:
        while True:
            r, _, _ = select.select([a, b], [], [], 10)
            if not r:
                return
            for s in r:
                d = s.recv(65536)
                if not d:
                    return
                (b if s is a else a).sendall(d)
    except OSError:
        return


class _HttpProxy(socketserver.StreamRequestHandler):
    log = []

    def handle(self):
        from urllib.parse import urlsplit
        line = self.rfile.readline().decode("latin1")
        hdrs = {}
        while True:
            h = self.rfile.readline().decode("latin1")
            if h in ("\r\n", "\n", ""):
                break
            k, _, v = h.partition(":")
            hdrs[k.strip().lower()] = v.strip()
        method, target, _ = line.split(" ", 2)
        if hdrs.get("proxy-authorization") != "Basic " + base64.b64encode(f"{USER}:{PASS}".encode()).decode():
            _HttpProxy.log.append("DENIED")
            self.wfile.write(b"HTTP/1.1 407 Proxy Auth Required\r\nProxy-Authenticate: Basic realm=x\r\n"
                             b"Content-Length: 0\r\n\r\n")
            return
        _HttpProxy.log.append(method)
        u = urlsplit(target)
        up = socket.create_connection((u.hostname, u.port or 80))
        req = f"{method} {u.path or '/'} HTTP/1.1\r\n" + "".join(
            f"{k}: {v}\r\n" for k, v in hdrs.items() if not k.startswith("proxy-")) + \
            "X-Via-Proxy: http\r\nConnection: close\r\n\r\n"
        up.sendall(req.encode())
        _pipe(self.connection, up)


class _Socks5(socketserver.StreamRequestHandler):
    log = []

    def handle(self):
        c = self.connection
        _, n = c.recv(2)
        c.recv(n)
        c.sendall(b"\x05\x02")
        _, ul = c.recv(2)
        u = c.recv(ul).decode()
        p = c.recv(c.recv(1)[0]).decode()
        if (u, p) != (USER, PASS):
            _Socks5.log.append("DENIED")
            c.sendall(b"\x01\x01")
            return
        c.sendall(b"\x01\x00")
        _, _, _, atyp = c.recv(4)
        host = socket.inet_ntoa(c.recv(4)) if atyp == 1 else c.recv(c.recv(1)[0]).decode()
        port = struct.unpack(">H", c.recv(2))[0]
        _Socks5.log.append("CONNECT")
        up = socket.create_connection((host, port))
        c.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        _pipe(c, up)


class _TS(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


_SERVERS = {}


def _servers():
    if not _SERVERS:
        for name, srv in (("origin", http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Origin)),
                          ("http", _TS(("127.0.0.1", 0), _HttpProxy)),
                          ("socks5", _TS(("127.0.0.1", 0), _Socks5))):
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            _SERVERS[name] = srv.server_address[1]
    return _SERVERS


def _need_moli():
    if not wp_moli.moli_configured():
        raise Skip("moli not installed")


def test_moli_egresses_through_the_proxy_or_not_at_all():
    _need_moli()
    s = _servers()
    url = f"http://127.0.0.1:{s['origin']}/spa"
    saved_env = {k: os.environ.pop(k) for k in _PROXY_ENV if k in os.environ}
    try:
        for scheme, port, log in (("http", s["http"], _HttpProxy.log), ("socks5h", s["socks5"], _Socks5.log)):
            log.clear()
            _Origin.hits.clear()
            d = wp_moli.fetch_dom(url, proxy=f"{scheme}://{CRED}@127.0.0.1:{port}")
            assert "desk_support_example" in d["html"], "page JavaScript did not run"
            assert log and log[-1] in ("GET", "CONNECT"), (scheme, log)
            assert _Origin.hits, scheme
            for bad in (f"{scheme}://gate:wrong@127.0.0.1:{port}", f"{scheme}://127.0.0.1:9"):
                _Origin.hits.clear()
                try:
                    wp_moli.fetch_dom(url, proxy=bad)
                except wp_moli.MoliError:
                    pass
                else:
                    raise AssertionError(f"{bad} returned a page")
                assert _Origin.hits == [], f"{bad}: origin was reached directly"
    finally:
        os.environ.update(saved_env)


def _pivot_extract(url, env, *flags):
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "out.json")
        full_env = {k: v for k, v in os.environ.items() if k not in _PROXY_ENV}
        full_env.update(env)
        r = subprocess.run([sys.executable, os.path.join(WP, "pivot_extract.py"), url, "--render",
                            "--no-enrich", "--no-whois", "--no-fallback", "-o", out, *flags],
                           capture_output=True, text=True, env=full_env, timeout=240)
        data = json.load(open(out)) if os.path.exists(out) else None
    return data, r.stderr


def test_moli_cloudflare_interstitial_is_a_challenge_not_the_page():
    _need_moli()
    s = _servers()
    for path in ("/cf", "/cfonce"):
        _Origin.hits.clear()
        data, err = _pivot_extract(f"http://127.0.0.1:{s['origin']}{path}", {
            "CTI_BROWSER": "moli", "PLAYWRIGHT_BROWSERS_PATH": os.path.join(tempfile.gettempdir(), "no-chromium")},
            "--solve-cf")
        assert data is not None, err[-400:]
        meta = data["meta"]
        assert meta.get("cloudflare") == "cloudflare_challenge", (path, meta)
        assert "renderer" not in meta, "the interstitial must not be stamped as a rendered page"
        assert "Chromium is required for the Cloudflare-escalation render" in err, (path, err[-600:])


def test_moli_and_chromium_extract_the_same_pivots():
    _need_moli()
    if not wp_browser.chromium_available():
        raise Skip("Chromium (Playwright) not installed")
    s = _servers()
    url = f"http://127.0.0.1:{s['origin']}/spa"
    got = {}
    for eng in ("moli", "chromium"):
        data, err = _pivot_extract(url, {"CTI_BROWSER": eng})
        assert data is not None, (eng, err[-400:])
        assert data["meta"].get("renderer", "").startswith(eng), (eng, data["meta"].get("renderer"))
        got[eng] = {(p["kind"], str(p["value"])) for p in data["pivots"]}
    assert ("telegram", "desk_support_example") in got["moli"], got["moli"]
    assert got["moli"] == got["chromium"], {"moli_only": got["moli"] - got["chromium"],
                                            "chromium_only": got["chromium"] - got["moli"]}


_TESTS = [
    test_pixels_and_cloudflare_escalation_never_route_to_moli,
    test_unverified_proxy_scheme_never_reaches_moli,
    test_engine_setting_precedence,
    test_moli_proxy_rides_the_environment_never_the_command_line,
    test_moli_proxy_rejection_and_empty_shell_are_errors_not_pages,
    test_moli_session_cookie_set_on_a_redirect_hop_is_kept,
    test_chromium_counts_only_when_the_launched_revision_is_downloaded,
    test_evidence_screenshot_refuses_without_chromium,
    test_moli_egresses_through_the_proxy_or_not_at_all,
    test_moli_cloudflare_interstitial_is_a_challenge_not_the_page,
    test_moli_and_chromium_extract_the_same_pivots,
]


def check():
    passed = failed = 0
    lines = []
    for test in _TESTS:
        label = test.__name__.removeprefix("test_").replace("_", " ")
        try:
            test()
        except Skip as s:
            passed += 1
            lines.append(("ok", f"{label} (skipped: {s})"))
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
