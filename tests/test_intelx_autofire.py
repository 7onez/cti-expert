#!/usr/bin/env python3
"""IntelX auto-fire in the deterministic pipeline (premium-key plan, Phase 5 item 8).

SKILL.md declares IntelX auto-fire required; `intel.py` never appended `--intelx`. The rule now:
`cmd_open` appends it iff a key is present (any registered alias) AND the case is not a no-spend
posture; `cmd_loop` appends it ONLY under `--full` — the default loop is free-only and must never
spend an IntelX search on its own. Pure decision function (`intel._intelx_flag`), no network,
no key value ever read here. Synthetic case dirs only."""
import json
import os
import sys
import tempfile

os.environ.setdefault("API_USAGE_LOG", os.path.join(tempfile.gettempdir(), "cti-tests-api_usage.jsonl"))
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "intel_engine", "tools"))

import intel as ip  # noqa: E402

FAILURES = []


def check(label, cond, detail=""):
    if cond:
        print("  ok   " + label)
    else:
        print("  FAIL " + label + (" " + str(detail) if detail else ""))
        FAILURES.append(label)


def _case(tmp, no_spend=None):
    case = os.path.join(tmp, "CASE-0001")
    os.makedirs(os.path.join(case, "raw"))
    if no_spend is not None:
        json.dump({"claim": "x", "constraints": {"no_spend": no_spend}}, open(os.path.join(case, "scope.json"), "w"))
    return case


saved = ip._intelx_keyed
try:
    with tempfile.TemporaryDirectory() as tmp:
        case = _case(tmp)
        ip._intelx_keyed = lambda: True
        check("cmd_open: key present -> --intelx", ip._intelx_flag(case, loop=False) == ["--intelx"])
        check("cmd_loop default (free-only) NEVER fires IntelX even with a key", ip._intelx_flag(case, loop=True, full=False) == [])
        check("cmd_loop --full with a key -> --intelx", ip._intelx_flag(case, loop=True, full=True) == ["--intelx"])
        ip._intelx_keyed = lambda: False
        check("cmd_open: no key -> nothing", ip._intelx_flag(case, loop=False) == [])
        check("cmd_loop --full: no key -> nothing", ip._intelx_flag(case, loop=True, full=True) == [])
    with tempfile.TemporaryDirectory() as tmp:
        case = _case(tmp, no_spend=True)
        ip._intelx_keyed = lambda: True
        check("no_spend posture blocks IntelX in cmd_open even with a key", ip._intelx_flag(case, loop=False) == [])
        check("no_spend posture blocks IntelX in cmd_loop --full", ip._intelx_flag(case, loop=True, full=True) == [])
    with tempfile.TemporaryDirectory() as tmp:
        case = _case(tmp, no_spend=False)
        check("an explicit no_spend=false does not block", ip._intelx_flag(case, loop=False) == ["--intelx"])
    # the two call sites actually consume the helper (a refactor must not silently drop one)
    src = open(ip.__file__, encoding="utf-8").read()
    check("cmd_open wires _intelx_flag(loop=False)", "extra += _intelx_flag(case_dir, loop=False)" in src)
    check("cmd_loop wires _intelx_flag(loop=True, full=…)", 'loop_extra += _intelx_flag(case_dir, loop=True, full=getattr(a, "full", False))' in src)
    check("the default loop still passes --free-only", 'loop_extra = [] if getattr(a, "full", False) else ["--free-only"]' in src)
finally:
    ip._intelx_keyed = saved

if FAILURES:
    print(f"\nFAIL — {len(FAILURES)} check(s) failed:")
    for f in FAILURES:
        print("  -", f)
    raise SystemExit(1)
print("\nPASS — IntelX auto-fire gate green")


def test_intelx_autofire():
    assert not FAILURES, FAILURES
