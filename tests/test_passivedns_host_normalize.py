#!/usr/bin/env python3
"""Regression: wp_recon.passivedns_search returned "error invalid host" for EVERY domain —
HackerTarget's hostsearch answers that for any query that is not a bare host (measured live: a
scheme prefix, a trailing path/slash, a port suffix, or stray whitespace all trip it). The fix
normalizes the query to a bare host before building the request; this defends that a malformed
(but recoverable) input still yields parsed rows instead of a blanket error.

Run:  python3 tests/test_passivedns_host_normalize.py
Fully offline (urllib.request.urlopen stubbed); no network, no metered calls.
Synthetic data only: site-a.example, RFC 5737 addresses.
"""
import io
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
WP = os.path.join(ROOT, "intel_engine", "WebPivot", "tools")
if WP not in sys.path:
    sys.path.insert(0, WP)

import wp_recon as R  # noqa: E402


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


_CSV = b"site-a.example,203.0.113.10\nwww.site-a.example,203.0.113.11\n"


def _run_with_stub(body: bytes, expect_url_contains: str, domain: str):
    seen = {}
    saved = R.urllib.request.urlopen

    def _fake(req, timeout=None):
        seen["url"] = req.full_url
        return _Resp(body)

    R.urllib.request.urlopen = _fake
    try:
        return R.passivedns_search(domain), seen
    finally:
        R.urllib.request.urlopen = saved


def test_normalizes_scheme_path_port_and_whitespace_before_querying():
    for domain in ("site-a.example", "https://site-a.example", "https://site-a.example/",
                   "site-a.example/", "site-a.example:443", " site-a.example "):
        r, seen = _run_with_stub(_CSV, "q=site-a.example", domain)
        assert "q=site-a.example" in seen["url"] and "q=https" not in seen["url"], (domain, seen)
        assert r.get("error") is None, (domain, r)
        assert r["query"] == "site-a.example", (domain, r)


def test_stub_returns_parsed_rows():
    r, _ = _run_with_stub(_CSV, "", "site-a.example")
    assert r["total"] == 2, r
    assert {"host": "site-a.example", "ip": "203.0.113.10"} in r["hosts"], r
    assert sorted(r["ips"]) == ["203.0.113.10", "203.0.113.11"], r


def test_empty_host_never_queries_the_network():
    saved = R.urllib.request.urlopen
    called = []
    R.urllib.request.urlopen = lambda *a, **k: called.append(1) or _Resp(_CSV)
    try:
        r = R.passivedns_search("   ")
    finally:
        R.urllib.request.urlopen = saved
    assert r == {"query": "   ", "error": "empty host"}, r
    assert not called, "an empty/whitespace-only host must never reach the network"


_TESTS = [test_normalizes_scheme_path_port_and_whitespace_before_querying,
          test_stub_returns_parsed_rows, test_empty_host_never_queries_the_network]


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
