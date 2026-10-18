#!/usr/bin/env python3
"""Regression: scripts/backend/intel.py's `cti` op + per-case env injection (#23, #27), and
`convergence.py`'s default subcommand (#25).

WHAT THIS PROTECTS
------------------
1. `intel.py cti <target>` is registered in DISPATCH and resolves to a real script (`list` shows
   it) — the new one-call driver must be reachable through the same Tier-2 CLI as every other op.
2. `_case_for(op, rest)` extracts the case id an op is about to operate on (positional, subcommand-
   scoped, or an explicit --case VALUE) so `main()` can export INTEL_CASE into the spawned
   subprocess's env — without it every metered-vendor ledger row from that subprocess logged
   case=null and `api-usage --case X` found nothing.
3. `python3 tools/kb/convergence.py <CASE>` (no snapshot|status subcommand — exactly what the
   dispatcher forwards for `intel.py convergence <CASE>`) now defaults to `status` instead of
   failing argparse's required subparser.
"""
import importlib.util
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENGINE = os.path.join(ROOT, "intel_engine")


def _load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


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

    D = _load_module(os.path.join(ROOT, "scripts", "backend", "intel.py"),
                      "cti_dispatcher_under_test")

    # 1) the `cti` op is registered and resolves to a real engine script
    ok("cti" in D.DISPATCH, "cti op registered in DISPATCH")
    if "cti" in D.DISPATCH:
        script, prefix = D.DISPATCH["cti"]
        ok(os.path.isfile(os.path.join(ENGINE, script)), "cti op resolves to a real script")
        ok(prefix == ["cti"], "cti op forwards the `cti` subcommand to tools/intel.py")

    # 2) _case_for: positional / subcommand-scoped / explicit --case extraction
    ok(D._case_for("loop", ["CASE-A", "seeds.txt"]) == "CASE-A", "loop: case is argv[0]")
    ok(D._case_for("pipeline", ["open", "CASE-B", "seeds.txt"]) == "CASE-B",
       "pipeline open: case is argv[1] after the subcommand")
    ok(D._case_for("pipeline", ["status", "CASE-C"]) == "CASE-C",
       "pipeline status: case is argv[1] after the subcommand")
    ok(D._case_for("convergence", ["CASE-D"]) == "CASE-D",
       "convergence <CASE> (bare, no subcommand): case is argv[0]")
    ok(D._case_for("convergence", ["snapshot", "CASE-E"]) == "CASE-E",
       "convergence snapshot <CASE>: case is argv[1]")
    ok(D._case_for("email-deep", ["a@b.example", "--case", "CASE-F"]) == "CASE-F",
       "an op with no _CASE_ARG entry still resolves an explicit --case VALUE")
    ok(D._case_for("stats", []) is None, "an op with no case argument at all resolves to None")

    # 3) main() propagates that case into the spawned subprocess's env (no real subprocess: patch
    #    subprocess.run to capture the call instead of spawning anything).
    captured = {}
    real_run = D.subprocess.run

    def _fake_run(cmd, **kw):
        captured["cmd"], captured["env"] = cmd, kw.get("env")
        return real_run([sys.executable, "-c", "pass"])
    D.subprocess.run = _fake_run
    try:
        rc = D.main(["loop", "CASE-ENV-PROP", "--max-rounds", "0"])
        ok(rc == 0, "patched main() run completes")
        ok(bool(captured.get("env")) and captured["env"].get("INTEL_CASE") == "CASE-ENV-PROP",
           "main() exports INTEL_CASE into the spawned subprocess env for a case-bearing op")
    finally:
        D.subprocess.run = real_run

    # 4) convergence.py's own CLI defaults the bare-case form to `status`
    CV = _load_module(os.path.join(ENGINE, "tools", "kb", "convergence.py"),
                       "cti_convergence_under_test")
    calls = []
    CV.cmd_status = lambda a: calls.append(("status", a.case)) or 0
    CV.cmd_snapshot = lambda a: calls.append(("snapshot", a.case)) or 0
    CV.main(["CASE-BARE"])
    ok(calls == [("status", "CASE-BARE")], "convergence.py <CASE> (bare) defaults to `status`")
    calls.clear()
    CV.main(["snapshot", "CASE-SNAP"])
    ok(calls == [("snapshot", "CASE-SNAP")], "convergence.py snapshot <CASE> still works")
    calls.clear()
    CV.main(["status", "CASE-STAT"])
    ok(calls == [("status", "CASE-STAT")], "convergence.py status <CASE> still works")

    # 5) the dispatcher runs the engine with cwd=<engine root>; an existing CALLER-relative path must
    #    reach it absolute (else `loop CASE seeds.txt` is looked up inside intel_engine/), while the
    #    case id — even when a same-named directory exists here — and non-existent names stay as typed.
    import tempfile
    here = os.getcwd()
    D.subprocess.run = _fake_run
    with tempfile.TemporaryDirectory() as tmp:
        try:
            os.chdir(tmp)
            open("seeds.txt", "w").write("site-a.example\n")
            os.mkdir("CASE-PATHS")
            captured.clear()
            D.main(["loop", "CASE-PATHS", "seeds.txt"])
            cmd = captured.get("cmd") or []
            ok(os.path.join(os.path.realpath(tmp), "seeds.txt") in [os.path.realpath(c) for c in cmd]
               and "seeds.txt" not in cmd,
               "loop: a caller-relative seeds file is passed to the engine as an absolute path")
            ok("CASE-PATHS" in cmd, "loop: the case id is never rewritten, even if a same-named dir exists")
            captured.clear()
            D.main(["report", "missing.md", "out"])
            ok((captured.get("cmd") or [])[-2:] == ["missing.md", "out"],
               "a name that does not exist in the caller's cwd passes through unchanged")
        finally:
            os.chdir(here)
            D.subprocess.run = real_run

    # 6) the engine's loop refuses a path-shaped seeds argument that does not resolve, BEFORE it
    #    writes anything — it used to queue `seeds.txt` as a pending host, or read a typo as no seeds.
    sys.path.insert(0, os.path.join(ENGINE, "tools"))
    I = _load_module(os.path.join(ENGINE, "tools", "intel.py"), "cti_engine_intel_under_test")
    import argparse
    for seeds in ("seeds.txt", "/nonexistent/dir/seeds.lst", "./x"):
        with tempfile.TemporaryDirectory() as tmp:
            saved_root = I.ROOT
            I.ROOT = tmp
            try:
                I.cmd_loop(argparse.Namespace(case="CASE-SEEDGUARD", seeds=seeds, max_rounds=0))
                exited = None
            except SystemExit as e:
                exited = str(e.code)
            finally:
                I.ROOT = saved_root
            ok(bool(exited) and "seeds file not found" in exited
               and not os.path.exists(os.path.join(tmp, "cases")),
               f"loop {seeds!r} (missing file) → 'seeds file not found', nothing written")

    return passed, failed, lines


if __name__ == "__main__":
    _passed, _failed, _lines = check()
    for _status, _label in _lines:
        print(f"{_status:>4}  {_label}")
    print(f"\n{_passed} passed, {_failed} failed")
    raise SystemExit(bool(_failed))
