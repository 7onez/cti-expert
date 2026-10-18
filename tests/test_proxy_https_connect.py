#!/usr/bin/env python3
"""Regression: `proxy.py test` must probe an HTTPS CONNECT tunnel through each proxy, SEPARATE
from the HTTP-level `cp.test_proxy` check — a forward proxy that answers plain HTTP fine can
still refuse or mishandle a CONNECT tunnel. `_https_connect_probe` must report a refused tunnel,
a broken tunnel, and an unreachable proxy with DISTINCT wording, never conflated with a TLS
handshake failure.

Run:  python3 tests/test_proxy_https_connect.py
Fully offline: a hermetic TCP server stands in for the proxy; no real egress, no network.
"""
import os
import socket
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
PROXY_DIR = os.path.join(ROOT, "scripts", "proxy")
if PROXY_DIR not in sys.path:
    sys.path.insert(0, PROXY_DIR)

import proxy as P  # noqa: E402


class _FakeProxyServer:
    """A minimal TCP listener that answers every CONNECT with a fixed status line, then closes
    (never actually tunnels bytes) — enough to exercise the CONNECT-reply branch without a real
    upstream."""

    def __init__(self, reply: bytes):
        self._reply = reply
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        self.sock.settimeout(5)
        try:
            conn, _ = self.sock.accept()
        except OSError:
            return
        try:
            conn.settimeout(5)
            conn.recv(4096)          # read (and discard) the CONNECT request line
            conn.sendall(self._reply)
        except OSError:
            pass
        finally:
            conn.close()

    def stop(self):
        try:
            self.sock.close()
        except OSError:
            pass
        self._thread.join(timeout=2)


def test_connect_refused_is_reported_distinctly():
    srv = _FakeProxyServer(b"HTTP/1.1 403 Forbidden\r\n\r\n")
    try:
        ok, detail = P._https_connect_probe(f"http://127.0.0.1:{srv.port}", "example.com", 443, 3)
        assert ok is False, (ok, detail)
        assert "CONNECT refused" in detail, detail
        assert "TLS" not in detail, detail  # never conflated with a handshake failure
    finally:
        srv.stop()


def test_connect_ok_but_tls_handshake_failure_is_reported_distinctly():
    # 200 tunnel, then the "upstream" just closes instead of speaking TLS — a handshake failure
    # AFTER a successful CONNECT, which must read differently from a refused tunnel.
    srv = _FakeProxyServer(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    try:
        ok, detail = P._https_connect_probe(f"http://127.0.0.1:{srv.port}", "example.com", 443, 3)
        assert ok is False, (ok, detail)
        assert "TLS handshake failed" in detail, detail
        assert "refused" not in detail, detail
    finally:
        srv.stop()


def test_unreachable_proxy_is_reported_distinctly():
    # nothing listening on this port
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    ok, detail = P._https_connect_probe(f"http://127.0.0.1:{port}", "example.com", 443, 2)
    assert ok is False, (ok, detail)
    assert "proxy unreachable" in detail, detail


def test_socks_proxy_is_skipped_not_failed():
    ok, detail = P._https_connect_probe("socks5://127.0.0.1:1", "example.com", 443, 2)
    assert ok is None, (ok, detail)
    assert "SOCKS" in detail, detail


_TESTS = [test_connect_refused_is_reported_distinctly,
          test_connect_ok_but_tls_handshake_failure_is_reported_distinctly,
          test_unreachable_proxy_is_reported_distinctly,
          test_socks_proxy_is_skipped_not_failed]


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
