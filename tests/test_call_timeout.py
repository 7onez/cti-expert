#!/usr/bin/env python3
"""Regression: the centralised per-call timeout ceiling (wp_common.CALL_TIMEOUT + urlopen floor).

WHAT THIS PROTECTS
------------------
The engine's policy is that every DATA-FETCHING / API / collector call runs up to CALL_TIMEOUT
(default 1800s / 30 min, env CTI_CALL_TIMEOUT), then times out and the run moves on. Rather than
edit 40 call sites, wp_common floors urllib.request.urlopen process-wide. This asserts:
  1. the constant is 1800 by default and honours the env override;
  2. the urlopen floor raises a short timeout to the ceiling, preserves a larger one, and fills a
     missing one — for both kwarg and positional timeout forms;
  3. DNS/TLS/JARM socket probes are NOT urlopen, so they are untouched (documented invariant).
"""
import os
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "intel_engine", "WebPivot", "tools"))

import wp_common  # noqa: E402


def check():
    passed = failed = 0
    lines = []

    def ok(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1
            lines.append(("ok", label))
        else:
            failed += 1
            lines.append(("FAIL", label))

    # 1. the DEFAULT comes from references/timeouts.json (RULE 3); env overrides at runtime. Clear
    # any inherited CTI_CALL_TIMEOUT (audit's §6 pins it low) so this asserts the json default.
    _saved = os.environ.pop("CTI_CALL_TIMEOUT", None)
    try:
        ok(wp_common._TIMEOUTS.get("call_timeout") == 1800
           and os.path.isfile(os.path.join(ROOT, "intel_engine", "WebPivot", "references", "timeouts.json")),
           "the ceiling default is loaded from references/timeouts.json, not the embedded fallback")
        ok(wp_common._call_timeout() == 1800, "with no env override the ceiling is the json default (1800s)")
        os.environ["CTI_CALL_TIMEOUT"] = "600"
        ok(wp_common._call_timeout() == 600, "CTI_CALL_TIMEOUT overrides the ceiling")
        for _bad in ("0", "-5", "abc", ""):
            os.environ["CTI_CALL_TIMEOUT"] = _bad
            ok(wp_common._call_timeout() == 1800, f"a non-positive/garbage override ({_bad!r}) falls back to the default")
        os.environ.pop("CTI_CALL_TIMEOUT", None)
    finally:
        if _saved is not None:
            os.environ["CTI_CALL_TIMEOUT"] = _saved

    # 2. the urlopen floor — install it over a fake original and inspect the timeout it forwards.
    # Assert against the LIVE ceiling (CT), not a literal, so the gate can pin CTI_CALL_TIMEOUT low.
    CT = wp_common.CALL_TIMEOUT
    seen = []

    def fake(url, *a, **k):
        seen.append((a, k.get("timeout")))
        return "OK"

    saved = urllib.request.urlopen
    try:
        urllib.request.urlopen = fake                 # a fresh, uncapped original
        wp_common._install_urlopen_floor()            # captures `fake`, wraps it
        capped = urllib.request.urlopen
        ok(getattr(capped, "_cti_capped", False), "the floor wrapper is installed")

        capped("http://x", timeout=1)
        ok(seen[-1][1] == CT, "a short kwarg timeout is raised to the ceiling")
        capped("http://x", timeout=CT * 2)
        ok(seen[-1][1] == CT * 2, "a timeout already above the ceiling is preserved")
        capped("http://x")
        ok(seen[-1][1] == CT, "a call with no timeout gets the ceiling")
        capped("http://x", None, 1)                   # positional: urlopen(url, data, timeout)
        ok(seen[-1][0][1] == CT, "a short POSITIONAL timeout is raised to the ceiling")
    finally:
        urllib.request.urlopen = saved

    # 3. idempotency: installing again over an already-capped opener is a no-op
    before = urllib.request.urlopen
    wp_common._install_urlopen_floor()
    ok(urllib.request.urlopen is before, "re-installing the floor over a capped opener is a no-op")

    # 4. mirror parity: the subprocess-layer copies (env-driven) agree with wp_common
    sys.path.insert(0, os.path.join(ROOT, "intel_engine", "tools"))
    import collect_core, fallback_probe, wp_subenum, wp_screenshot  # noqa: E402
    for mod in (collect_core, fallback_probe, wp_subenum, wp_screenshot):
        ok(mod.CALL_TIMEOUT == wp_common.CALL_TIMEOUT,
           f"{mod.__name__}.CALL_TIMEOUT ({mod.CALL_TIMEOUT}) matches wp_common ({wp_common.CALL_TIMEOUT})")

    return passed, failed, lines


if __name__ == "__main__":
    _passed, _failed, _lines = check()
    for _status, _label in _lines:
        print(f"{_status:>4}  {_label}")
    print(f"\n{_passed} passed, {_failed} failed")
    raise SystemExit(bool(_failed))
