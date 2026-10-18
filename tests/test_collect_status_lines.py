#!/usr/bin/env python3
"""Regression: collect_host's per-host status must reflect reality, not "ok" whenever a JSON
file merely exists. Before the fix, a completely unreachable live target (proxy CONNECT
refused, nothing recovered) still returned an empty `note`, and the printer's fallback then
showed the literal string "ok" — the exact defect from the case run ("[ok ] brandsite.example ok").

Run:  python3 tests/test_collect_status_lines.py
Fully offline: pivot_extract is replaced by a hermetic stub collector; no network.
Synthetic data only: site-a.example.
"""
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.join(HERE, "..", "intel_engine")
sys.path.insert(0, os.path.join(ENGINE, "tools"))

import collect_core as C  # noqa: E402

# A stub collector whose behaviour is picked by an env var, so one script covers all three
# meta shapes (ok / recovered / unreachable) without three separate files.
_STUB = r'''
import sys, json, os
a = sys.argv[1:]
if "--help" in a:
    print("usage: stub [--pretty] [-o O] [--save-dom D] [--timeout T] [--render]"
          " [--whois-reverse] [--no-enrich] [--no-whois] [--fofa-full]"
          " [--submit] [--archive-missing] [--master] [--case C]")
    sys.exit(0)
out = a[a.index("-o") + 1] if "-o" in a else None
host = a[0].split("://", 1)[-1].split("/", 1)[0]
mode = os.environ.get("STUB_MODE", "ok")
meta = {"host": host}
if mode == "recovered":
    meta["live_error"] = "connection refused"
    meta["recovered_via"] = "wayback:20260101000000"
elif mode == "unreachable":
    meta["live_error"] = "connection refused"
if out:
    json.dump({"meta": meta, "artifacts": {}, "pivots": [{"kind": "x", "value": "1"}]},
              open(out, "w"))
'''


def _write_stub(dirpath):
    p = os.path.join(dirpath, "stub_collector.py")
    with open(p, "w") as fh:
        fh.write(_STUB)
    return p


def _collect(root, stub, mode):
    old = os.environ.get("STUB_MODE")
    os.environ["STUB_MODE"] = mode
    try:
        return C.collect_host(f"https://site-a-{mode}.example", "CASE-0001", root=root,
                              py=sys.executable, collector=stub, no_archive=True, force=True)
    finally:
        if old is None:
            os.environ.pop("STUB_MODE", None)
        else:
            os.environ["STUB_MODE"] = old


def test_status_strings_reflect_reality():
    root = tempfile.mkdtemp(prefix="cc-status-test-")
    try:
        stub = _write_stub(root)

        r_ok = _collect(root, stub, "ok")
        assert r_ok["status"] == "ok", r_ok
        assert r_ok["note"].startswith("ok"), r_ok

        r_rec = _collect(root, stub, "recovered")
        assert r_rec["status"] == "recovered (wayback:20260101000000)", r_rec
        assert r_rec["note"].startswith("recovered (wayback:20260101000000)"), r_rec

        r_unreach = _collect(root, stub, "unreachable")
        assert r_unreach["status"] == "unreachable (connection refused)", r_unreach
        assert r_unreach["note"].startswith("unreachable (connection refused)"), r_unreach
        # the historical bug: a blank note fell back to the literal string "ok" regardless
        assert r_unreach["note"] != "ok", r_unreach
    finally:
        shutil.rmtree(root, ignore_errors=True)


_TESTS = [test_status_strings_reflect_reality]


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
