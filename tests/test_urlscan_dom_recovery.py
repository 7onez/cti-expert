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
        html, uid = N.urlscan_dom(intel, free_only=False)
    finally:
        N.urllib.request.urlopen = saved_urlopen
    assert uid == "a" * 36, uid
    assert "owner@site-a.example" in html, html
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


_TESTS = [
    test_decode_body_sniffs_gzip_magic_without_header,
    test_urlscan_dom_decodes_gzip_body_and_yields_extracted_emails,
    test_urlscan_dom_all_dedupes_on_decoded_text_not_raw_bytes,
    test_dom_is_binary_junk_flags_undecoded_gzip,
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
