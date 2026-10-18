#!/usr/bin/env python3
"""Regression: the `cti` driver's sequencing and machine-readable summary (#27).

Every step it calls is stubbed here (recall, collect, enrich, loop, and the case_state frontier/
convergence reads) — this test is about ORDER and FLAG MAPPING, not re-proving those steps' own
behaviour (each already has its own tests). No network, no real case directories are collected.
"""
import argparse
import contextlib
import importlib.util
import io
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENGINE = os.path.join(ROOT, "intel_engine")
TOOLS_DIR = os.path.join(ENGINE, "tools")
sys.path.insert(0, TOOLS_DIR)
import case_state  # noqa: E402 — patched below; `cmd_cti`'s own `import case_state as cs` reuses
                    # this exact cached module object, so patching it here reaches that import too.


class _FakeCP:
    def __init__(self, returncode=0, stderr=""):
        self.returncode = returncode
        self.stderr = stderr


def _load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _cti_args(target, **kw):
    base = dict(target=target, case=None, quick=False, deep=False, passive=False,
                free_only=False, extend=False, pipeline=True, depth=None)
    base.update(kw)
    return argparse.Namespace(**base)


def _run(IP, a, tmp_root):
    IP.ROOT = tmp_root   # keep every case dir this run creates inside the temp dir
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        IP.cmd_cti(a)
    out = buf.getvalue().rstrip("\n")
    last_line = out.splitlines()[-1] if out else ""
    return json.loads(last_line), out


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

    with tempfile.TemporaryDirectory() as tmp:
        # wp_common loads .env at import, so a configured Quarry would hold collection on an
        # unanswered ask. This file tests sequencing; Quarry stays off except the hold test.
        saved_env = {k: os.environ.pop(k, None) for k in
                     ("QUARRY_ENABLED", "QUARRY_API_KEY", "QUARRY_MCP_URL", "QUARRY_KEY")}
        IP = _load_module(os.path.join(TOOLS_DIR, "intel.py"), "cti_driver_under_test")
        calls = []
        IP.cmd_open = lambda a: calls.append(("cmd_open", a.case, a.no_enrich, a.free_only))
        IP._run_enrichment = lambda case, **kw: calls.append(("enrich", case, kw))
        IP.cmd_loop = lambda a: calls.append(("cmd_loop", a.case, a.full, a.deep_archive, a.max_rounds))
        IP._run_dispatch_op = lambda op, args, timeout=None: (
            calls.append(("dispatch", op, tuple(args))) or _FakeCP(0))
        IP._recall_attribution = lambda target, kind: None
        IP._load_env = lambda: None
        # 1) already-attributed domain stops BEFORE any collection, unless --extend
        calls.clear()
        IP._recall_attribution = lambda target, kind: "Operator X"
        summary, _ = _run(IP, _cti_args("attributed.example"), tmp)
        ok(summary["status"] == "attributed" and summary["converged"] is True,
           "an attributed target reports status=attributed, converged=True")
        ok(summary["next"] == ["report"], "an attributed target's next is just report")
        ok(not calls, "an attributed target never reaches collect/enrich/loop")

        # --extend continues past the attribution
        calls.clear()
        case_state.frontier = lambda case, max_new=8: {"pending": [], "metered_leads": []}
        case_state.convergence_verdict = lambda case, stale=2: {"verdict": "CONVERGED"}
        summary, _ = _run(IP, _cti_args("attributed.example", extend=True), tmp)
        ok(any(c[0] == "cmd_open" for c in calls), "--extend continues past a confirmed attribution")

        # 2) a fresh domain that is already CONVERGED on first read never reaches `loop`
        calls.clear()
        IP._recall_attribution = lambda target, kind: None
        case_state.frontier = lambda case, max_new=8: {"pending": [], "metered_leads": []}
        case_state.convergence_verdict = lambda case, stale=2: {"verdict": "CONVERGED"}
        summary, _ = _run(IP, _cti_args("fresh.example"), tmp)
        ok([c[0] for c in calls] == ["cmd_open", "enrich"],
           f"converged-on-first-read: collect + enrich only, no loop ({calls})")
        ok(summary["converged"] is True and summary["status"] == "converged", "summary reflects CONVERGED")
        ok(summary["next"] == ["report"], "a converged case's next is just report (no harness)")

        # 3) unconverged domain chases the frontier with `loop`; --deep maps onto --full/--deep-archive
        calls.clear()
        case_state.convergence_verdict = lambda case, stale=2: {"verdict": "EXPANDING"}
        case_state.load_state = lambda case: {"status": "converged"}   # the loop's own outcome
        summary, _ = _run(IP, _cti_args("fresh2.example", deep=True), tmp)
        ok([c[0] for c in calls] == ["cmd_open", "enrich", "cmd_loop"],
           f"unconverged domain runs collect + enrich + loop ({calls})")
        loop_call = next(c for c in calls if c[0] == "cmd_loop")
        ok(loop_call[2] is True and loop_call[3] is True,
           "--deep maps onto the loop's --full and --deep-archive")
        ok(summary["status"] == "converged" and summary["converged"] is True,
           "summary reflects the loop's own post-run state")
        ok(summary["next"] == ["report"], "converged after the loop: next is report only")

        # 4) --quick holds enrichment AND loop back even though unconverged
        calls.clear()
        summary, _ = _run(IP, _cti_args("fresh3.example", quick=True), tmp)
        ok([c[0] for c in calls] == ["cmd_open"], f"--quick: collect only ({calls})")
        ok("harness" in summary["next"], "an unconverged --quick run still asks for harness escalation")

        # 5) --passive holds the loop back but NOT enrichment
        calls.clear()
        summary, _ = _run(IP, _cti_args("fresh4.example", passive=True), tmp)
        ok([c[0] for c in calls] == ["cmd_open", "enrich"],
           f"--passive: collect + enrich, no loop ({calls})")
        ok(calls[0][3] is True, "--passive forces free_only on the collection pass")

        # 6) a non-domain selector routes through the type-matched dispatcher op, never cmd_open
        calls.clear()
        summary, _ = _run(IP, _cti_args("operator@example.com"), tmp)
        ok([c[0] for c in calls][0] == "dispatch", f"an email selector dispatches, not cmd_open ({calls})")
        ok(calls[0][1] == "email-deep", "email selector routes to the email-deep op")
        ok(summary["kind"] == "email", "summary records the classified selector kind")

        # 7) the DEFAULT engine is the harness loop (subprocess stubbed — never a real LLM run)
        hcalls = []
        real_sp = IP.subprocess.run

        def _fake_run(cmd, **k):
            hcalls.append(list(cmd))
            return argparse.Namespace(returncode=0)

        IP.subprocess.run = _fake_run
        try:
            calls.clear()
            st_path = None
            summary, _ = _run(IP, _cti_args("fresh7.example", pipeline=False, deep=True,
                                            free_only=True), tmp)
        finally:
            IP.subprocess.run = real_sp
        ok(hcalls and hcalls[0][2:5] == ["harness", "open", summary["case"]]
           and "--depth" in hcalls[0] and hcalls[0][hcalls[0].index("--depth") + 1] == "6"
           and "--no-spend" in hcalls[0] and not calls,
           f"default /cti runs the harness loop (deep → 6 rounds, free-only → --no-spend), no pipeline ({hcalls})")
        ok(summary.get("engine") == "harness", "the summary names the harness engine")

        # 8) a harness that cannot run (non-zero exit, nothing collected) falls back to the pipeline
        IP.subprocess.run = lambda cmd, **k: argparse.Namespace(returncode=75)
        try:
            calls.clear()
            summary, _ = _run(IP, _cti_args("fresh8.example", pipeline=False), tmp)
        finally:
            IP.subprocess.run = real_sp
        ok(calls and calls[0][0] == "cmd_open" and summary.get("engine") != "harness",
           f"no backend → the deterministic pipeline runs instead ({calls})")

        # 9) never a nested harness: INTEL_IN_HARNESS (set by the orchestrator for EVERY backend,
        #    the SDK path included) forces the pipeline; so does --passive (no live contact)
        spawned = []
        IP.subprocess.run = lambda cmd, **k: (spawned.append(cmd), argparse.Namespace(returncode=0))[1]
        os.environ["INTEL_IN_HARNESS"] = "1"
        try:
            calls.clear()
            _run(IP, _cti_args("fresh9.example", pipeline=False), tmp)
            nested_ok = not spawned and calls and calls[0][0] == "cmd_open"
        finally:
            os.environ.pop("INTEL_IN_HARNESS", None)
        try:
            calls.clear()
            _run(IP, _cti_args("fresh10.example", pipeline=False, passive=True), tmp)
            passive_ok = not spawned and calls and calls[0][0] == "cmd_open"
        finally:
            IP.subprocess.run = real_sp
        ok(nested_ok, "inside a harness run (INTEL_IN_HARNESS) /cti never starts a nested harness")
        ok(passive_ok, "--passive never runs the harness loop (no live contact, no chase loop)")

        # 10) stdin: a non-terminal caller gets DEVNULL so the run checkpoints, never blocks
        seen = {}
        IP.subprocess.run = lambda cmd, **k: (seen.update(k), argparse.Namespace(returncode=0))[1]
        try:
            _run(IP, _cti_args("fresh11.example", pipeline=False), tmp)
        finally:
            IP.subprocess.run = real_sp
        ok(sys.stdin.isatty() or seen.get("stdin") is IP.subprocess.DEVNULL,
           "a non-TTY caller runs the harness with stdin=DEVNULL (no hang on the approval prompt)")
        # 11) a Quarry wait that has not imported — cap, failure, or an unanswered ask — never
        # reaches a collector. The job file is the checkpoint; the next run resumes it.
        real_stage = IP._cti_quarry_stage
        try:
            for status in ("running", "error", "failed", "undecided"):
                calls.clear()
                IP._cti_quarry_stage = lambda *a, status=status, **k: {
                    "status": status, "job_id": "job-1", "resumable": True}
                summary, _ = _run(IP, _cti_args("held.example", pipeline=False), tmp)
                ok(not calls, f"quarry status={status} never reaches collect/enrich/harness ({calls})")
                ok(summary["status"] == "awaiting-quarry" and summary["next"] == ["quarry"],
                   f"quarry status={status} checkpoints as awaiting-quarry")
        finally:
            IP._cti_quarry_stage = real_stage
            for k, v in saved_env.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v


    return passed, failed, lines


if __name__ == "__main__":
    _passed, _failed, _lines = check()
    for _status, _label in _lines:
        print(f"{_status:>4}  {_label}")
    print(f"\n{_passed} passed, {_failed} failed")
    raise SystemExit(bool(_failed))
