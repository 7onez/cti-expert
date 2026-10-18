#!/usr/bin/env python3
"""pivot_extract regression: a urlscan DOM recovery that decodes to binary junk (a gzip body
read straight as UTF-8 because Content-Encoding lied/was missing) must be REJECTED — never
accepted as the page — and the run must say so (`meta.dom_undecodable`) instead of silently
reporting the host as investigated live/recovered with nothing behind it.

Run:  python3 tests/test_pivot_extract_dom_undecodable.py
Fully offline: fetch/wayback/urlscan are all stubbed; no network, no metered calls.
Synthetic data only: site-a.example.
"""
import gzip
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
WP = os.path.join(ROOT, "intel_engine", "WebPivot", "tools")
if WP not in sys.path:
    sys.path.insert(0, WP)

import pivot_extract as p  # noqa: E402


def test_junk_urlscan_dom_recovery_is_rejected_and_flagged():
    junk = gzip.compress(
        b"<html>irrelevant bytes, never decoded through _decode_body by the old bug</html>"
    ).decode("utf-8", "ignore")
    assert p.dom_is_binary_junk(junk), junk[:80]  # sanity: the synthetic junk trips the detector

    saved = {"fetch": p.fetch, "wayback_closest": p.wayback_closest,
             "urlscan_intel": p.urlscan_intel, "urlscan_dom": p.urlscan_dom}

    def _fail_fetch(*a, **k):
        raise OSError("connection refused (simulated live-fetch failure)")

    scan_uuid = "b" * 36
    p.fetch = _fail_fetch
    p.wayback_closest = lambda *a, **k: (None, None)
    p.urlscan_intel = lambda *a, **k: {
        "total": 1, "related_domains": [],
        "recent_scans": [{"result": f"https://urlscan.io/result/{scan_uuid}/"}]}
    p.urlscan_dom = lambda *a, **k: (junk, scan_uuid)

    old_argv = sys.argv
    try:
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out.json")
            sys.argv = ["pivot_extract.py", "https://site-a.example/", "--no-enrich",
                        "--no-whois", "-o", out]
            p.main()
            data = json.load(open(out, encoding="utf-8"))
    finally:
        sys.argv = old_argv
        for k, v in saved.items():
            setattr(p, k, v)

    meta = data["meta"]
    assert meta.get("dom_undecodable") == f"urlscan_dom:{scan_uuid}", meta
    assert meta.get("recovered_via") != f"urlscan_dom:{scan_uuid}", meta
    assert meta.get("live_error"), meta


_TESTS = [test_junk_urlscan_dom_recovery_is_rejected_and_flagged]


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
