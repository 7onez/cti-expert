#!/usr/bin/env python3
"""Regression test for intel_engine/tools/next_actions.py: candidate action synthesis,
non-interactive NEXT_ACTIONS JSON emission, and interactive menu dispatch."""
from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.dirname(HERE)
ROOT = os.path.dirname(TOOLS)
for p in (TOOLS, os.path.join(ROOT, "tools", "kb")):
    if p not in sys.path:
        sys.path.insert(0, p)

import next_actions


def check():
    out, passed, failed = [], 0, 0

    def ok(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1
            out.append(("ok", label))
        else:
            failed += 1
            out.append(("FAIL", label))

    case = "CASE-TEST-0001"

    # 1. Action synthesis
    actions_none = next_actions.compute_actions(case, pending=[], metered=[], status="converged")
    ids_none = [a["id"] for a in actions_none]
    ok("reopen" in ids_none and "report" in ids_none, "converged case still offers reopen and report")
    ok("continue_harness" not in ids_none and "review_metered" not in ids_none,
       "converged case does not offer continue or metered")

    actions_pending = next_actions.compute_actions(case, pending=["a.example", "b.example"], status="awaiting-analyst")
    ids_pending = [a["id"] for a in actions_pending]
    ok("continue_harness" in ids_pending and "continue_loop_free" in ids_pending,
       "pending hosts offer both harness and loop continuations")
    ok(any(a.get("recommended") for a in actions_pending if a["id"] == "continue_harness"),
       "harness continuation is marked recommended when pending hosts exist")

    actions_metered = next_actions.compute_actions(case, metered=[{"service": "FOFA", "query": 'icon_hash="1"'}])
    rev = [a for a in actions_metered if a["id"] == "review_metered"]
    ok(rev and not rev[0].get("command") and rev[0]["leads"][0]["query"] == 'icon_hash="1"',
       "metered leads are listed for per-lead approval and NOTHING is executed for them "
       "(loop --full never runs a frontier metered lead — offering it as 'run' was false)")
    rep = [a for a in actions_metered if a["id"] == "report"][0]
    ok(not rep.get("command"), "report only points at the Deliver contract; the menu never renders a report")

    # every executable command must be an op its CLI actually accepts (a dead subcommand shipped once)
    import subprocess as _sp
    for a in actions_pending:
        cmd = a.get("command")
        if not cmd:
            continue
        probe = cmd[:cmd.index(case)] + ["--help"] if case in cmd else cmd + ["--help"]
        r = _sp.run(probe, capture_output=True, text=True, timeout=60)
        ok(r.returncode == 0 and "unknown op" not in (r.stdout + r.stderr)
           and "invalid choice" not in (r.stdout + r.stderr),
           f"action {a['id']} runs a real op ({' '.join(os.path.basename(c) for c in probe[1:4])})")

    # nested entry points: the in-process loop inside `cti` must stay silent
    os.environ["INTEL_NO_PROMPT"] = "1"
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        quiet = next_actions.emit_or_prompt(case, pending=["p1.example"])
    del os.environ["INTEL_NO_PROMPT"]
    ok(quiet is None and buf.getvalue() == "",
       "INTEL_NO_PROMPT silences both the prompt and the NEXT_ACTIONS line (cti's JSON stays last)")

    # 2. Non-interactive emission (agent parseable JSON)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        res = next_actions.emit_or_prompt(
            case, pending=["p1.example"], metered=[{"service": "FOFA", "query": "q1"}],
            status="awaiting-analyst"
        )
    ok(res is None, "non-interactive run returns None without blocking")
    lines = [l for l in buf.getvalue().splitlines() if l.startswith("NEXT_ACTIONS:")]
    ok(len(lines) == 1, "exactly one NEXT_ACTIONS line emitted")
    payload = json.loads(lines[0].partition("NEXT_ACTIONS:")[2].strip())
    ok(payload["case"] == case and payload["pending_count"] == 1 and payload["metered_count"] == 1,
       "NEXT_ACTIONS payload carries accurate case context")
    ok(len(payload["actions"]) >= 4, "NEXT_ACTIONS payload includes computed candidate actions")

    # 3. Interactive prompt mock: selecting option '0' (exit)
    import builtins
    saved_input = builtins.input
    builtins.input = lambda prompt="": "0"
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        res_exit = next_actions.emit_or_prompt(case, pending=["p1.example"], force_prompt=True)
    builtins.input = saved_input
    ok(res_exit is None, "interactive option 0 cleanly exits")
    ok("Next Actions Available" in buf.getvalue(), "interactive prompt displays menu")

    # 4. Interactive prompt mock: selecting reopen with text prompt
    inputs = iter(["4", "new-target.example"])  # 4 is reopen in actions with pending+metered
    builtins.input = lambda prompt="": next(inputs)
    # Stub subprocess so we don't actually invoke case_state.py
    saved_sub = next_actions.subprocess.run
    called_cmd = []
    next_actions.subprocess.run = lambda cmd, **kw: called_cmd.append(cmd)
    try:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            res_reopen = next_actions.emit_or_prompt(case, pending=["p1.example"],
                                                     metered=[{"service": "FOFA", "query": "q"}],
                                                     force_prompt=True)
        ok(res_reopen and res_reopen.get("id") == "reopen", "user selected reopen")
        ok(res_reopen and res_reopen.get("user_input") == "new-target.example",
           "user input captured in result")
        ok(called_cmd and "reopen" in called_cmd[0] and "new-target.example" in called_cmd[0],
           "reopen command executed with user's input")
    finally:
        builtins.input = saved_input
        next_actions.subprocess.run = saved_sub

    return passed, failed, out


if __name__ == "__main__":
    p, f, lines = check()
    for status, label in lines:
        print(f"[{status:4s}] {label}")
    print(f"\n{p} passed, {f} failed")
    sys.exit(1 if f else 0)
