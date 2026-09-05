#!/usr/bin/env python3
"""Regression: the centralised per-call timeout ceiling (wp_timeouts → wp_common.CALL_TIMEOUT + floors).

WHAT THIS PROTECTS
------------------
The engine's policy is that every DATA-FETCHING / API / collector / renderer / subprocess call runs
up to CALL_TIMEOUT (default 1800s / 30 min), then times out and the run moves on. ONE resolver
(wp_timeouts) reads env CTI_CALL_TIMEOUT → the skill-root .env → references/timeouts.json → 1800 and
exports the result so child processes inherit it; wp_common floors urllib.request.urlopen
process-wide and every subprocess runner floors its bound. This asserts:
  1. the resolver's order: reference default, env override, .env file, garbage fall-through;
  2. the resolved value is exported to os.environ for children;
  3. the urlopen floor raises a short timeout to the ceiling, preserves a larger one, and fills a
     missing one (kwarg and positional forms), and re-installing is a no-op;
  4. every subprocess-layer mirror agrees with wp_common (parity).
"""
import os
import sys
import tempfile
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "intel_engine", "WebPivot", "tools"))

import wp_common  # noqa: E402
import wp_timeouts  # noqa: E402


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

    # 1. resolution order. `env_files=()` makes the assertion hermetic against the analyst's own
    # .env; `export=False` keeps os.environ untouched. Clear any inherited CTI_CALL_TIMEOUT (audit's
    # §6 pins it low) so the reference default is what gets asserted.
    R = wp_timeouts.resolve_call_timeout
    _saved = os.environ.pop("CTI_CALL_TIMEOUT", None)
    try:
        ok(os.path.isfile(os.path.join(ROOT, "intel_engine", "WebPivot", "references", "timeouts.json"))
           and wp_timeouts._reference_default() == 1800,
           "the ceiling default is loaded from references/timeouts.json, not the embedded fallback")
        ok(R(env_files=(), export=False) == 1800, "with no env and no .env the ceiling is the json default (1800s)")
        os.environ["CTI_CALL_TIMEOUT"] = "600"
        ok(R(env_files=(), export=False) == 600, "an exported CTI_CALL_TIMEOUT overrides the ceiling")
        for _bad in ("0", "-5", "abc", ""):
            os.environ["CTI_CALL_TIMEOUT"] = _bad
            ok(R(env_files=(), export=False) == 1800, f"a non-positive/garbage override ({_bad!r}) falls back to the default")
        os.environ.pop("CTI_CALL_TIMEOUT", None)

        with tempfile.TemporaryDirectory() as td:
            envf = os.path.join(td, ".env")
            with open(envf, "w", encoding="utf-8") as fh:
                fh.write("# analyst knobs\nSHODAN_API_KEY=\nCTI_CALL_TIMEOUT=\"2400\"\n")
            ok(R(env_files=(envf,), export=False) == 2400, "CTI_CALL_TIMEOUT= in the skill .env sets the ceiling")
            os.environ["CTI_CALL_TIMEOUT"] = "900"
            ok(R(env_files=(envf,), export=False) == 900, "an exported env var beats the .env file")
            os.environ.pop("CTI_CALL_TIMEOUT", None)
            with open(envf, "w", encoding="utf-8") as fh:
                fh.write("CTI_CALL_TIMEOUT=oops\n")
            ok(R(env_files=(envf,), export=False) == 1800, "a garbage .env value falls through to the reference default")
            ok(R(env_files=(os.path.join(td, "missing.env"),), export=False) == 1800,
               "a missing .env file is skipped, not an error")
            # 2. export: the resolved value is published to children via os.environ.
            with open(envf, "w", encoding="utf-8") as fh:
                fh.write("CTI_CALL_TIMEOUT=2400\n")
            ok(R(env_files=(envf,)) == 2400 and os.environ.get("CTI_CALL_TIMEOUT") == "2400",
               "the resolved ceiling is exported to os.environ so subprocesses inherit it")
            os.environ.pop("CTI_CALL_TIMEOUT", None)
        ok(wp_timeouts.floor(1) == wp_timeouts.CALL_TIMEOUT and wp_timeouts.floor(None) == wp_timeouts.CALL_TIMEOUT
           and wp_timeouts.floor(wp_timeouts.CALL_TIMEOUT * 2) == wp_timeouts.CALL_TIMEOUT * 2,
           "floor(): short/None → ceiling, longer kept")
    finally:
        if _saved is not None:
            os.environ["CTI_CALL_TIMEOUT"] = _saved
        else:
            os.environ.pop("CTI_CALL_TIMEOUT", None)

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

    # 4. mirror parity: every subprocess-layer runner floors to the SAME ceiling as wp_common.
    sys.path.insert(0, os.path.join(ROOT, "intel_engine", "tools"))
    sys.path.insert(0, os.path.join(ROOT, "intel_engine", "IntelGraph", "scripts"))
    sys.path.insert(0, os.path.join(ROOT, "intel_engine", "BinaryPivot", "tools"))
    sys.path.insert(0, os.path.join(ROOT, "scripts"))
    import collect_core, fallback_probe, wp_subenum, wp_screenshot, house_report_charts  # noqa: E402
    import cti_timeouts  # noqa: E402 — the root scripts' shim
    for mod in (wp_timeouts, collect_core, fallback_probe, wp_subenum, wp_screenshot, house_report_charts, cti_timeouts):
        ok(mod.CALL_TIMEOUT == wp_common.CALL_TIMEOUT,
           f"{mod.__name__}.CALL_TIMEOUT ({mod.CALL_TIMEOUT}) matches wp_common ({wp_common.CALL_TIMEOUT})")
    import render_mermaid, render_graphviz, analyze_artifact, whois_enrich  # noqa: E402
    for mod, fn in ((render_mermaid, "_floor"), (render_graphviz, "_floor"), (analyze_artifact, "_floor"),
                    (whois_enrich, "_floor_timeout"), (collect_core, "_floor"), (fallback_probe, "_floor")):
        ok(getattr(mod, fn)(1) == CT and getattr(mod, fn)(None) == CT,
           f"{mod.__name__}.{fn} raises a 1s / missing bound to the ceiling ({CT})")

    return passed, failed, lines


if __name__ == "__main__":
    _passed, _failed, _lines = check()
    for _status, _label in _lines:
        print(f"{_status:>4}  {_label}")
    print(f"\n{_passed} passed, {_failed} failed")
    raise SystemExit(bool(_failed))
