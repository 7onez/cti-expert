#!/usr/bin/env python3
"""
test_proxy.py — the gate on the egress-proxy layer (`scripts/proxy/cti_proxy.py`).

Run:  python3 tests/test_proxy.py                 (zero deps, no pytest needed)
      .venv/bin/pytest tests/test_proxy.py -q       (also works)

WHAT THIS PROTECTS
------------------
The proxy layer is installed process-globally and every collector inherits it, so a
silent bug here mis-routes (or leaks) every outbound request in the skill:

  1. NORMALIZATION. A bare host:port must default to http://; an unusable scheme must
     be rejected, not half-configured.
  2. PRECEDENCE. env CTI_PROXIES/CTI_PROXY must override the file store — that is how a
     CI run or one-off session redirects egress without editing proxies.json.
  3. ROTATION. round-robin must advance + persist across invocations (per-call egress
     rotation is the whole point); random/sticky/off must not.
  4. FAILOVER ORDER. A dead proxy is skipped to the next one; an origin HTTPError is
     NOT retried (the proxy worked, so burning the pool would be wrong and slow).
  5. NO-LEAK DEFAULT. With a pool present and allow_direct off, a direct connection is
     never in the failover order — the point of a proxy is to not expose the real IP.
  6. NO_PROXY BYPASS. Listed hosts go direct regardless of the pool.
"""
import os
import sys
import urllib.error

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "scripts", "proxy"))

# Isolate from any real store/env before importing the module.
for _v in ("CTI_PROXY", "CTI_PROXIES", "CTI_PROXY_ENABLED", "CTI_PROXY_ROTATION",
           "CTI_PROXY_ALLOW_DIRECT", "NO_PROXY", "no_proxy", "HTTP_PROXY",
           "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
    os.environ.pop(_v, None)
os.environ["CTI_PROXY_STORE"] = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), ".proxy-test-store.json")

import cti_proxy as cp  # noqa: E402

FAILURES = []


def check(label, cond, detail=""):
    if cond:
        print("  ok   {}".format(label))
    else:
        print("  FAIL {} {}".format(label, detail))
        FAILURES.append(label)


def _clear_env():
    for v in ("CTI_PROXY", "CTI_PROXIES", "CTI_PROXY_ENABLED", "CTI_PROXY_ROTATION",
              "CTI_PROXY_ALLOW_DIRECT", "CTI_PROXY_SOCKS_ACTIVE", "NO_PROXY", "no_proxy",
              "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy",
              "all_proxy"):
        os.environ.pop(v, None)


def _cfg(**over):
    c = {"enabled": True, "rotation": "round-robin", "allow_direct": False,
         "test_url": cp.DEFAULT_TEST_URL, "no_proxy": ["localhost"],
         "proxies": [{"url": "http://a:8080"}, {"url": "http://b:8080"}]}
    c.update(over)
    return c


# ── 1. normalization ─────────────────────────────────────────────────────────
def test_normalize():
    print("\n[1] proxy URL normalization")
    check("bare host:port defaults to http://",
          cp.normalize_proxy("1.2.3.4:8080") == "http://1.2.3.4:8080")
    check("keeps an explicit scheme + creds",
          cp.normalize_proxy("socks5h://u:p@h:1080") == "socks5h://u:p@h:1080")
    check("rejects an unusable scheme", cp.normalize_proxy("ftp://h:21") is None)
    check("rejects empty", cp.normalize_proxy("   ") is None)
    # provider shorthands the user pastes verbatim
    check("host:port:user:pass -> http://user:pass@host:port",
          cp.normalize_proxy("relay.prx.network:80:npx-customer-hay123:f00323cd")
          == "http://npx-customer-hay123:f00323cd@relay.prx.network:80")
    check("user:pass@host:port (no scheme) -> http://…",
          cp.normalize_proxy("apicall:secret@14.225.198.139:17779")
          == "http://apicall:secret@14.225.198.139:17779")
    check("a full url with creds is preserved",
          cp.normalize_proxy("http://apicall:secret@14.225.198.139:17779")
          == "http://apicall:secret@14.225.198.139:17779")
    check("a pasted http_proxy=\"…\" assignment is unwrapped",
          cp.normalize_proxy('http_proxy="http://apicall:secret@14.225.198.139:17779"')
          == "http://apicall:secret@14.225.198.139:17779")
    check("user:pass:host:port (port auto-detected) also works",
          cp.normalize_proxy("u:p:host.example:3128")
          == "http://u:p@host.example:3128")
    check("a non-numeric port is rejected",
          cp.normalize_proxy("host:notaport") is None)
    check("all-digit password is not mistaken for the port (host:port:user:pass)",
          cp.normalize_proxy("relay.prx.network:80:user:1234")
          == "http://user:1234@relay.prx.network:80")
    check("token[1] not a valid port -> user:pass:host:port fallback",
          cp.normalize_proxy("user:secret:host.example:8080")
          == "http://user:secret@host.example:8080")
    check("out-of-range port in shorthand is rejected",
          cp.normalize_proxy("host:99999:user:pass") is None)


# ── 2. env precedence ────────────────────────────────────────────────────────
def test_precedence():
    print("\n[2] env overrides the file store")
    _clear_env()
    cfg = cp.load_store(os.environ["CTI_PROXY_STORE"]) if os.path.exists(
        os.environ["CTI_PROXY_STORE"]) else _cfg()
    check("file pool used when env is empty",
          cp.build_pool(_cfg()) == ["http://a:8080", "http://b:8080"])
    os.environ["CTI_PROXIES"] = "9.9.9.9:1, http://8.8.8.8:2"
    check("CTI_PROXIES overrides the file",
          cp.build_pool(_cfg()) == ["http://9.9.9.9:1", "http://8.8.8.8:2"])
    _clear_env()
    os.environ["CTI_PROXY"] = "7.7.7.7:7"
    check("CTI_PROXY (single) overrides the file",
          cp.build_pool(_cfg()) == ["http://7.7.7.7:7"])
    _clear_env()


# ── 3. rotation ──────────────────────────────────────────────────────────────
def test_rotation():
    print("\n[3] rotation policy")
    _clear_env()
    pool = ["http://a:8080", "http://b:8080", "http://c:8080"]
    try:
        os.remove(cp.STATE_PATH)
    except OSError:
        pass
    seq = [pool[cp.pick_start(pool, "round-robin")] for _ in range(4)]
    check("round-robin advances + wraps + persists",
          seq == [pool[0], pool[1], pool[2], pool[0]], detail=str(seq))
    before = cp._read_cursor()
    cp.pick_start(pool, "sticky")
    cp.pick_start(pool, "off")
    check("sticky/off never advance the cursor", cp._read_cursor() == before)


# ── 4. failover order + HTTPError passthrough ────────────────────────────────
class _FakeSubOpener:
    """Records the proxy it was built for; open() succeeds/raises per script."""
    def __init__(self, proxy, script):
        self.proxy = proxy
        self.script = script

    def open(self, url, data=None, timeout=None):
        outcome = self.script.get(self.proxy, "ok")
        if outcome == "ok":
            return ("RESPONSE", self.proxy)
        if outcome == "http":
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
        if outcome == "http407":
            raise urllib.error.HTTPError(url, 407, "Proxy Auth Required", {}, None)
        raise urllib.error.URLError("connection refused")


def _opener(pool, start, direct_ok, no_proxy, script):
    fo = cp.FailoverOpener(pool, start, direct_ok, no_proxy)
    fo._cache = {p: _FakeSubOpener(p, script) for p in pool + [None]}
    fo._opener_for = lambda proxy: fo._cache[proxy]  # bypass real build_opener
    return fo


def test_failover():
    print("\n[4] failover order + HTTPError passthrough")
    pool = ["http://a:1", "http://b:1", "http://c:1"]
    # a dead, b dead, c ok -> lands on c, does not go direct
    fo = _opener(pool, 0, False, [], {"http://a:1": "down", "http://b:1": "down"})
    _, used = fo.open("http://target.example/")
    check("skips dead proxies to the first live one", used == "http://c:1")

    # origin 404 through the first proxy -> raise, do NOT try the rest
    tries = {"n": 0}
    fo2 = _opener(pool, 0, True, [], {"http://a:1": "http"})
    # count opens by wrapping
    orig = fo2._opener_for
    def counting(proxy):
        tries["n"] += 1
        return orig(proxy)
    fo2._opener_for = counting
    raised = False
    try:
        fo2.open("http://target.example/")
    except urllib.error.HTTPError:
        raised = True
    check("an origin HTTPError is raised immediately", raised)
    check("HTTPError does not burn the rest of the pool", tries["n"] == 1)

    # 407 = the PROXY rejected auth -> rotate to the next proxy, do not surface it
    fo3 = _opener(pool, 0, False, [], {"http://a:1": "http407"})
    _, used3 = fo3.open("http://target.example/")
    check("407 proxy-auth rotates to the next proxy", used3 == "http://b:1")


# ── 5. no-leak default + no_proxy bypass ─────────────────────────────────────
def test_no_leak_and_bypass():
    print("\n[5] no-leak default + no_proxy bypass")
    pool = ["http://a:1", "http://b:1"]
    fo = cp.FailoverOpener(pool, 0, False, ["internal.example"])
    order = fo._order("target.example")
    check("allow_direct off -> no direct (None) in the order", None not in order)
    fo2 = cp.FailoverOpener(pool, 0, True, ["internal.example"])
    check("allow_direct on -> direct is the last resort", fo2._order("t.example")[-1] is None)
    check("no_proxy host bypasses the pool entirely",
          fo._order("internal.example") == [None])
    check("subdomain of a no_proxy host is bypassed too",
          fo._order("api.internal.example") == [None])


# ── 6. disabled / empty are inert ────────────────────────────────────────────
def test_disabled_inert():
    print("\n[6] disabled or empty pool installs nothing")
    _clear_env()
    os.environ["CTI_PROXY_ENABLED"] = "0"
    cp._INSTALLED = False
    check("install() returns None when disabled", cp.install(_cfg()) is None)
    _clear_env()
    cp._INSTALLED = False
    check("install() returns None with an empty pool",
          cp.install(_cfg(proxies=[])) is None)


# ── 6b. SOCKS raw-socket fail-closed contract ────────────────────────────────
def test_socks_failclosed():
    print("\n[6b] SOCKS proxied_connection: fail closed when the hook is absent")
    _clear_env()
    # A SOCKS pool is configured (via ALL_PROXY, as install() sets it) but the
    # in-process PySocks hook never installed -> a direct dial would leak, so
    # proxied_connection must RAISE, never return a direct socket.
    os.environ["ALL_PROXY"] = "socks5://127.0.0.1:1080"
    os.environ.pop("CTI_PROXY_SOCKS_ACTIVE", None)
    raised = False
    try:
        cp.proxied_connection("target.example", 443, timeout=2)
    except OSError:
        raised = True
    check("SOCKS pool without an active hook raises (fail closed)", raised)
    # Hook active -> the caller's own socket is routed, so return None (go direct
    # through the hooked socket).
    os.environ["CTI_PROXY_SOCKS_ACTIVE"] = "1"
    check("SOCKS pool with an active hook returns None (socket already routed)",
          cp.proxied_connection("target.example", 443, timeout=2) is None)
    _clear_env()


# ── 7. real proxy — bytes actually traverse it (not a mock) ──────────────────
class _RecordingProxy(__import__("threading").Thread):
    """A ~real stdlib proxy on 127.0.0.1: records the first request line of each
    connection. Answers a forward GET with a canned body; answers CONNECT with
    '200 established' then closes (enough to prove the HTTPS tunnel path fired)."""
    def __init__(self):
        import socket, threading
        super().__init__(daemon=True)
        self.requests = []
        self._stop = False
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(8)
        self.port = self._srv.getsockname()[1]

    def run(self):
        import socket, threading
        while not self._stop:
            try:
                self._srv.settimeout(0.5)
                conn, _ = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            conn.settimeout(2.0)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            line = data.split(b"\r\n", 1)[0].decode("latin1")
            self.requests.append(line)
            if line.startswith("CONNECT"):
                conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            else:
                body = b"PROXIED_OK"
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n"
                             b"Connection: close\r\n\r\n%s" % (len(body), body))
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self):
        self._stop = True
        try:
            self._srv.close()
        except OSError:
            pass


def test_live_proxy_roundtrip():
    print("\n[7] real proxy — bytes actually traverse it")
    import urllib.request as ur
    px = _RecordingProxy()
    px.start()
    try:
        proxy = f"http://127.0.0.1:{px.port}"
        # (a) FailoverOpener: a forward http:// GET fully round-trips THROUGH the proxy
        fo = cp.FailoverOpener([proxy], 0, False, [])
        body = fo.open(ur.Request("http://example.invalid/probe",
                                  headers={"User-Agent": "t"}), timeout=3).read()
        check("http request round-trips through the FailoverOpener proxy",
              body == b"PROXIED_OK")
        check("proxy saw the absolute-URI forward GET",
              any(l.startswith("GET http://example.invalid/probe")
                  for l in px.requests))
        # (b) HTTPS -> CONNECT tunnel (TLS then fails against our dummy — expected;
        #     we only need to prove ProxyHandler issued the CONNECT).
        try:
            fo.open(ur.Request("https://example.invalid/x"), timeout=3)
        except Exception:
            pass
        check("proxy received a CONNECT for the https target",
              any(l.startswith("CONNECT example.invalid:443") for l in px.requests))
        # (c) env-only path (how intel_engine subprocess tools inherit it): the
        #     stdlib DEFAULT opener honors HTTPS/HTTP_PROXY with no install_opener.
        for v in ("HTTP_PROXY", "http_proxy"):
            os.environ[v] = proxy
        try:
            ur.install_opener(None)  # force the default env-reading opener
            b2 = ur.urlopen("http://example.invalid/envprobe", timeout=3).read()
            check("default opener honors HTTP_PROXY env (intel_engine path)",
                  b2 == b"PROXIED_OK")
        finally:
            for v in ("HTTP_PROXY", "http_proxy"):
                os.environ.pop(v, None)
        # (d) proxied_connection: the raw-socket cert-probe path also tunnels via
        #     CONNECT (so cert_pivot cannot leak the real IP behind an http proxy).
        _clear_env()
        for v in ("HTTPS_PROXY", "https_proxy"):
            os.environ[v] = proxy
        try:
            s = cp.proxied_connection("cert.invalid", 443, timeout=3)
            check("proxied_connection returns a live tunnelled socket", s is not None)
            if s:
                s.close()
            check("proxied_connection issued a CONNECT for that exact host",
                  any(l.startswith("CONNECT cert.invalid:443") for l in px.requests))
            os.environ["NO_PROXY"] = os.environ["no_proxy"] = "example.invalid"
            check("proxied_connection returns None for a no_proxy host (direct ok)",
                  cp.proxied_connection("example.invalid", 443, timeout=3) is None)
        finally:
            _clear_env()
    finally:
        px.stop()


def main():
    print("cti_proxy — normalization, precedence, rotation, failover, no-leak, live")
    for fn in (test_normalize, test_precedence, test_rotation, test_failover,
               test_no_leak_and_bypass, test_disabled_inert, test_socks_failclosed,
               test_live_proxy_roundtrip):
        fn()
    try:
        os.remove(os.environ["CTI_PROXY_STORE"])
    except OSError:
        pass
    print()
    if FAILURES:
        print("FAILED ({}): {}".format(len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("all cti_proxy tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
