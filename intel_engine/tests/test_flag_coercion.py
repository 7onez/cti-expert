#!/usr/bin/env python3
"""
test_flag_coercion.py — the gate and the handlers must read a boolean argument the SAME way.

Run:  python3 tests/test_flag_coercion.py

WHAT THIS PROTECTS
------------------
audit.gate() decides with `_truthy`, where "false" / "no" / "0" / "off" / "" are NO. A handler that
tested `bool(args.get("confirm"))` read the STRING "false" as yes. So `confirm:"false"` passed the
gate as a harmless briefing and then the handler appended `--confirm-submission`: a real sandbox
detonation with no HARNESS_ALLOW_SUBMIT. The same split let `search_pivot run:"false"` spend
SerpApi and `quarry start:"no"` start a scan the gate had classed as free.

Each case drives the real handler with `_run` stubbed (nothing executes) and asserts the command it
WOULD run carries the action flag exactly when the gate would treat the call as that action.
"""
import asyncio
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "harness"))

import audit  # noqa: E402
import tools as T  # noqa: E402

FALSEY = ["false", "False", "no", "0", "off", "", "none", 0, False, None]
TRUTHY = [True, "true", "yes", "1", 1]

# tool, base args, the flag argument, the CLI switch it must (not) produce
CASES = [
    ("anyrun_submit", {"target": "http://site-a.example/x"}, "confirm", "--confirm-submission"),
    ("webamon_scan", {"target": "http://site-a.example/x", "wait": 0}, "confirm", "--confirm-submission"),
    ("search_pivot", {"indicator": "site-a.example"}, "run", "--run"),
    ("quarry", {"case": "CASE-0001", "target": "site-a.example"}, "start", "--quarry-scan"),
]


def _drive(name, args):
    seen = []

    def fake_run(cmd, timeout=180):
        seen.append(list(cmd))
        return subprocess.CompletedProcess(cmd, 0, stdout="{}", stderr="")

    saved = T._run
    T._run = fake_run
    try:
        handler = getattr(T, name).handler
        asyncio.run(handler(dict(args)))
    finally:
        T._run = saved
    return [a for cmd in seen for a in cmd]


def check():
    passed = failed = 0
    out = []

    def ok(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1
            out.append(("ok", label))
        else:
            failed += 1
            out.append(("FAIL", label))

    for env in ("INTEL_IN_HARNESS", "HARNESS_PHASE"):   # quarry refuses start inside a phase
        os.environ.pop(env, None)
    for name, base, flag, switch in CASES:
        for v in FALSEY:
            argv = _drive(name, {**base, flag: v})
            ok(switch not in argv, f"{name} {flag}={v!r} → no {switch}")
            ok(not audit._truthy({flag: v}, {flag}),
               f"{name} {flag}={v!r} → the gate also reads it as NO (handler and gate agree)")
        for v in TRUTHY:
            argv = _drive(name, {**base, flag: v})
            ok(switch in argv, f"{name} {flag}={v!r} → {switch} (a real yes still acts)")

    # the bypass itself: the gate must not treat confirm="false" as an approved submission while the
    # handler submits. With the lock unset, a briefing-shaped call is allowed and must stay a briefing.
    os.environ.pop("HARNESS_ALLOW_SUBMIT", None)
    allowed, _, _ = audit.decide("anyrun_submit", {"target": "http://site-a.example/x", "confirm": "false"},
                                 hostile=False)
    argv = _drive("anyrun_submit", {"target": "http://site-a.example/x", "confirm": "false"})
    ok(allowed and "--confirm-submission" not in argv,
       "confirm='false' with no HARNESS_ALLOW_SUBMIT: allowed as a briefing AND nothing is submitted")
    denied, _, _ = audit.decide("anyrun_submit", {"target": "http://site-a.example/x", "confirm": "true"},
                                hostile=False)
    ok(not denied, "confirm='true' with no HARNESS_ALLOW_SUBMIT is still DENIED by the gate")
    return passed, failed, out


if __name__ == "__main__":
    p, f, lines = check()
    for status, label in lines:
        if status != "ok":
            print(f"  FAIL {label}")
    print(f"{'PASS' if not f else 'FAIL'} — {p} passed, {f} failed")
    raise SystemExit(bool(f))
