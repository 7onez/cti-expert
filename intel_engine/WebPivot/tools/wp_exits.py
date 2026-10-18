#!/usr/bin/env python3
"""wp_exits — explicit egress routes ("exits") for archive traffic: direct, an HTTP(S) proxy, or a
SOCKS5 proxy, each with its own urllib opener, so one process can spread Wayback work across
several IPs at once (the archive rate-limits per IP; measured 2026-09-28, paced, every exit —
direct, WARP, Tor, the CTI_PROXIES HTTP pool — reached the archive equally and returned
byte-identical snapshots).

Only for traffic to the ARCHIVES (web.archive.org, urlscan.io), never to a target: going direct
here exposes this IP to the archive, not to the operator.

Exit ids are "direct" or "<host>:<port>" — credentials are stripped and never logged or persisted.
SOCKS5 is implemented here (stdlib only; PySocks is not a dependency): remote DNS (socks5h
semantics), optional username/password auth.

Configuration: env CTI_WAYBACK_EXITS (comma list), else references/wayback_endpoints.json →
exits. Tokens: "direct", "pool" (= every CTI_PROXIES / proxy-store entry via scripts/proxy/
cti_proxy), or a proxy URL (http://, https://, socks5://, socks5h://).
"""
from __future__ import annotations

import functools
import http.client
import os
import re
import socket
import ssl
import struct
import sys
import threading
import urllib.parse
import urllib.request
from typing import NamedTuple

__all__ = ["Exit", "configured_exits", "exit_id", "EXITS_ENV"]

EXITS_ENV = "CTI_WAYBACK_EXITS"

_SOCKS_REPLIES = {1: "general failure", 2: "not allowed by ruleset", 3: "network unreachable",
                  4: "host unreachable", 5: "connection refused", 6: "TTL expired",
                  7: "command not supported", 8: "address type not supported"}


def exit_id(url: str | None) -> str:
    """'direct', or the proxy's host:port with scheme and userinfo stripped."""
    if not url:
        return "direct"
    p = urllib.parse.urlsplit(url if "://" in url else "http://" + url)
    return f"{p.hostname}:{p.port}" if p.port else (p.hostname or "proxy")


def _recv(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("SOCKS5 proxy closed the connection mid-handshake")
        buf += chunk
    return buf


def socks5_connect(proxy_host, proxy_port, dest_host, dest_port, timeout=None,
                   username=None, password=None):
    """A TCP socket to dest via a SOCKS5 proxy (destination resolved BY THE PROXY). Error texts are
    chosen for wp_wayback_guard: an unreachable proxy says 'error connecting to SOCKS5 proxy' (the
    archive never saw us); a refusal relayed by the proxy says 'SOCKS5 … connection refused'."""
    try:
        s = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    except OSError as e:
        raise OSError(f"error connecting to SOCKS5 proxy {proxy_host}:{proxy_port}: {e}") from e
    try:
        methods = b"\x00" + (b"\x02" if username else b"")
        s.sendall(b"\x05" + bytes([len(methods)]) + methods)
        ver, meth = _recv(s, 2)
        if ver != 5:
            raise OSError("SOCKS5 proxy answered with a non-SOCKS5 greeting")
        if meth == 2:
            u, pw = (username or "").encode(), (password or "").encode()
            s.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(pw)]) + pw)
            if _recv(s, 2)[1] != 0:
                raise OSError("SOCKS5 proxy rejected the credentials (auth failure)")
        elif meth != 0:
            raise OSError("SOCKS5 proxy accepts none of our auth methods")
        host_b = dest_host.encode("idna")
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b + struct.pack(">H", dest_port))
        rep = _recv(s, 4)
        if rep[1] != 0:
            raise OSError(f"SOCKS5 connect to {dest_host}:{dest_port} failed: reply {rep[1]} "
                          f"({_SOCKS_REPLIES.get(rep[1], 'unknown')})")
        atyp = rep[3]
        _recv(s, {1: 4, 4: 16}.get(atyp, 0) or _recv(s, 1)[0])
        _recv(s, 2)
        return s
    except Exception:
        s.close()
        raise


class _SocksCfg(NamedTuple):
    host: str
    port: int
    username: str | None = None
    password: str | None = None


def _socks_socket(cfg: "_SocksCfg", dest_host, dest_port, timeout):
    return socks5_connect(cfg.host, cfg.port, dest_host, dest_port, timeout,
                          cfg.username, cfg.password)


class _SocksHTTPConnection(http.client.HTTPConnection):
    def __init__(self, *a, socks_cfg=None, **k):
        super().__init__(*a, **k)
        self._socks_cfg = socks_cfg

    def connect(self):
        self.sock = _socks_socket(self._socks_cfg, self.host, self.port, self.timeout)


class _SocksHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, *a, socks_cfg=None, **k):
        super().__init__(*a, **k)
        self._socks_cfg = socks_cfg

    def connect(self):
        raw = _socks_socket(self._socks_cfg, self.host, self.port, self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


class _SocksHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, socks_cfg):
        super().__init__()
        self._socks_cfg = socks_cfg

    def http_open(self, req):
        return self.do_open(functools.partial(_SocksHTTPConnection, socks_cfg=self._socks_cfg), req)


class _SocksHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, socks_cfg):
        super().__init__(context=ssl.create_default_context())
        self._socks_cfg = socks_cfg

    def https_open(self, req):
        return self.do_open(functools.partial(_SocksHTTPSConnection, socks_cfg=self._socks_cfg),
                            req, context=self._context)


class Exit:
    """One egress route with its own opener. `id` is safe to log/persist; `url` may hold a
    credential and is never printed."""

    def __init__(self, url: str | None):
        self.url = url or None
        self.id = exit_id(self.url)
        scheme = urllib.parse.urlsplit(self.url).scheme.lower() if self.url else ""
        self.kind = "direct" if not self.url else ("socks5" if scheme.startswith("socks") else "http")
        self._opener = None
        self._lock = threading.Lock()

    def __repr__(self):
        return f"Exit({self.id})"

    def opener(self):
        with self._lock:
            if self._opener is None:
                if self.kind == "direct":
                    self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                elif self.kind == "http":
                    self._opener = urllib.request.build_opener(
                        urllib.request.ProxyHandler({"http": self.url, "https": self.url}))
                else:
                    p = urllib.parse.urlsplit(self.url)
                    cfg = _SocksCfg(p.hostname, p.port or 1080,
                                    urllib.parse.unquote(p.username) if p.username else None,
                                    urllib.parse.unquote(p.password) if p.password else None)
                    self._opener = urllib.request.build_opener(
                        urllib.request.ProxyHandler({}), _SocksHTTPHandler(cfg),
                        _SocksHTTPSHandler(cfg))
            return self._opener

    def open(self, req, timeout):
        return self.opener().open(req, timeout=timeout)


def _pool_urls() -> list:
    """The analyst's proxy pool (CTI_PROXIES / CTI_PROXY / proxy store) via cti_proxy."""
    here = os.path.dirname(os.path.abspath(__file__))
    cand = os.path.normpath(os.path.join(here, "..", "..", "..", "scripts", "proxy"))
    if os.path.isfile(os.path.join(cand, "cti_proxy.py")) and cand not in sys.path:
        sys.path.insert(0, cand)
    try:
        import cti_proxy
        cti_proxy.load_env_file()
        return list(cti_proxy.build_pool())
    except Exception:  # noqa: BLE001 — no pool is a valid configuration
        return []


def configured_exits(spec=None, default=None) -> list:
    """The exits to use, de-duplicated by id, in configured order."""
    raw = spec if spec is not None else os.environ.get(EXITS_ENV)
    tokens = ([t.strip() for t in raw.split(",")] if isinstance(raw, str)
              else list(raw if raw is not None else (default or ["direct"])))
    out, seen = [], set()
    for t in tokens:
        if not t:
            continue
        urls = _pool_urls() if t == "pool" else [None if t == "direct" else t]
        for u in urls:
            if u and not re.match(r"^(https?|socks5h?)://", u, re.I):
                u = "http://" + u
            ex = Exit(u)
            if ex.id not in seen:
                seen.add(ex.id)
                out.append(ex)
    return out
