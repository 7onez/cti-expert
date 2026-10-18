#!/usr/bin/env python3
"""Regression: `cmd_loop`'s per-round collection label must say what the round ACTUALLY spends,
not a hardcoded "(free-only)" regardless of `--full` (#26).

Every side-effecting dependency (collector fan-out, binary ingest, KB ingest/cluster writes, the
convergence-snapshot subprocess, enrichment, assessment render, MO-neighbour classification) is
stubbed so exactly one round runs, entirely inside a temp case dir — nothing here touches
intel_engine/cases, knowledge/ or MEMORY/, and no network call is made.
"""
import argparse
import contextlib
import importlib.util
import io
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENGINE = os.path.join(ROOT, "intel_engine")
TOOLS_DIR = os.path.join(ENGINE, "tools")
sys.path.insert(0, TOOLS_DIR)
import case_state  # noqa: E402 — patched below; cmd_loop's own `import case_state as cs` reuses
                    # this exact cached module object.


def _load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _loop_args(case, **kw):
    base = dict(case=case, seeds="onehost.example", max_rounds=3, max_new=8, depth=None,
                stale=2, jobs=4, timeout=20, render_extract=False, deep_archive=False,
                no_deep_primary=False, full=False, min=2, analyst=None,
                classification="UNCLASSIFIED//FOR OFFICIAL USE ONLY")
    base.update(kw)
    return argparse.Namespace(**base)


def _stub_everything(IP, tmp_root):
    """Neutralise every side-effecting call cmd_loop makes so one round runs harmlessly."""
    IP.ROOT = tmp_root
    IP._load_env = lambda: None
    IP._export_run_env = lambda case_dir: None
    IP.collect_core.collect_many = lambda *a, **kw: None
    IP.binary_auto.run = lambda case, free_only=False: []
    IP.binary_auto.ingest = lambda case_dir, kb: (True, "")
    IP._all_raw = lambda case_dir: []
    IP._ingest_case = lambda raw_files: None
    IP._case_hosts = lambda case_dir: set()
    IP._write_shared = lambda case_dir, min_shared, hosts=None: None
    IP._write_clusters = lambda case_dir, case, hosts=None, min_shared=2, max_prevalence=8: []
    IP._run = lambda cmd, **kw: None           # would otherwise shell out to the REAL convergence.py
    IP._run_enrichment = lambda case, **kw: None
    IP._render_assessment = lambda *a, **kw: set()
    IP._write_mo_neighbours = lambda case_dir, case: None
    IP._intelx_flag = lambda case_dir, loop=False, full=False: []

    case_state.load_state = lambda case: {
        "case": case, "status": "expanding", "round": 0, "pending": [], "consumed": [],
        "collected": [], "history": [], "enrichment_done": {}, "expansion_depth": 2,
        "metered_leads": [], "hops": {},
    }
    case_state.collected_hosts = lambda case_dir: set()
    case_state.save_state = lambda case, st: None
    case_state.frontier = lambda case, max_new=8: {"metered_leads": [], "candidate_total": 0}
    case_state.is_leaf = lambda host, hops, depth: False
    case_state.convergence_verdict = lambda case, stale=2: {"verdict": "CONVERGED", "new_hosts_recent": 0}


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
        IP = _load_module(os.path.join(TOOLS_DIR, "intel.py"), "cti_loop_label_under_test")
        _stub_everything(IP, tmp)

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            IP.cmd_loop(_loop_args("CASE-LABEL-DEFAULT", full=False))
        out_default = buf.getvalue()
        ok("collecting 1 host(s) (free-only)" in out_default,
           "default (no --full) round label says free-only")
        ok("metered engines ON" not in out_default,
           "default round label never claims metered engines are on")

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            IP.cmd_loop(_loop_args("CASE-LABEL-FULL", full=True))
        out_full = buf.getvalue()
        ok("collecting 1 host(s) (metered engines ON)" in out_full,
           "--full round label says metered engines ON")
        ok("(free-only)" not in out_full,
           "--full round label does not ALSO claim free-only (the pre-fix defect)")

    return passed, failed, lines


if __name__ == "__main__":
    _passed, _failed, _lines = check()
    for _status, _label in _lines:
        print(f"{_status:>4}  {_label}")
    print(f"\n{_passed} passed, {_failed} failed")
    raise SystemExit(bool(_failed))
