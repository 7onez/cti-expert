#!/usr/bin/env python3
"""Regression — no pipeline sub-step may hang or crash the whole `/cti` (/case) run.

`intel_engine/tools/intel.py` orchestrates the deterministic pipeline (extract -> ingest ->
shared -> clusters -> graph -> assess) through `_run()`. A child that wedges (a stuck render, a
network-bound tool, a missing binary) must degrade to a bounded, logged skip — returncode 124,
never an unbounded stall or an uncaught exception — so the pipeline always reaches Done with
whatever completed. This test locks that contract in.

Run:  python3 tests/test_pipeline_step_timeout.py   |   pytest -q tests/test_pipeline_step_timeout.py
"""
import importlib.util
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_INTEL = os.path.join(ROOT, "intel_engine", "tools", "intel.py")


def _load():
    spec = importlib.util.spec_from_file_location("intel_pipeline_under_test", _INTEL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)                     # module inserts its own dir on sys.path
    return mod


def test_hung_step_is_bounded_not_stalled():
    m = _load()
    start = time.monotonic()
    r = m._run(["sleep", "30"], timeout=1)           # a wedged child
    elapsed = time.monotonic() - start
    assert isinstance(r, subprocess.CompletedProcess), "must return a result, never raise"
    assert r.returncode == 124, "timed-out step must degrade to rc 124"
    assert elapsed < 10, f"step was not bounded (took {elapsed:.1f}s)"


def test_stdout_caller_degrades_to_empty_on_timeout():
    m = _load()
    r = m._run(["sleep", "30"], timeout=1, capture_output=True, text=True)
    assert r.returncode == 124 and r.stdout == "", "stdout caller must get '' on a bounded skip"


def test_missing_binary_degrades_not_crashes():
    m = _load()
    r = m._run(["/nonexistent/cti-tool-xyz", "arg"])
    assert isinstance(r, subprocess.CompletedProcess) and r.returncode == 124


def test_normal_step_still_runs():
    m = _load()
    assert m._run(["true"]).returncode == 0
    assert isinstance(m._STEP_TIMEOUT, int) and m._STEP_TIMEOUT > 0, "a default bound must exist"


def test_env_override_of_default_bound():
    prev = os.environ.get("INTEL_STEP_TIMEOUT")
    os.environ["INTEL_STEP_TIMEOUT"] = "7"
    try:
        assert _load()._STEP_TIMEOUT == 7, "INTEL_STEP_TIMEOUT must override the default"
    finally:
        if prev is None:
            os.environ.pop("INTEL_STEP_TIMEOUT", None)
        else:
            os.environ["INTEL_STEP_TIMEOUT"] = prev


_TESTS = [test_hung_step_is_bounded_not_stalled,
          test_stdout_caller_degrades_to_empty_on_timeout,
          test_missing_binary_degrades_not_crashes,
          test_normal_step_still_runs,
          test_env_override_of_default_bound]


def check():
    passed = failed = 0
    out = []
    for t in _TESTS:
        label = t.__name__.removeprefix("test_").replace("_", " ")
        try:
            t()
        except Exception as exc:  # noqa: BLE001
            failed += 1
            out.append(("FAIL", f"{label}: {exc}"))
        else:
            passed += 1
            out.append(("ok", label))
    return passed, failed, out


if __name__ == "__main__":
    _p, _f, _lines = check()
    for _s, _l in _lines:
        print(("ok   " if _s == "ok" else "FAIL ") + _l)
    print(f"\n{_p} passed, {_f} failed")
    raise SystemExit(bool(_f))
