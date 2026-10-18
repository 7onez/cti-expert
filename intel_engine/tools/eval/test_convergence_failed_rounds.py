#!/usr/bin/env python3
"""Offline unit gate for two convergence-loop defects found in a live cti-expert run.

A4 — a round where a host FAILED to collect (403/SSL/timeout — no live content, no archive
recovery) must never read as CONVERGED just because it also produced no new hosts/indicators.
convergence.py's `zero_growth`/`is_converged` are the single source of truth every reader
(cmd_status, case_state.convergence_verdict, the harness) must agree with; `snapshot --failed`
is how a round records which hosts failed.

A5 — `intel.py cmd_cti`'s final summary JSON must report every still-open lead (free pending
apexes + metered leads awaiting approval + OPEN enrichment legs), including AFTER the `loop`
step, not just the free pending queue — the driver used to overwrite a correct pre-loop
open_leads with a pending-only list once the loop ran.

Fully offline: no network, synthetic domains only, cases built in TemporaryDirectory.
"""
import contextlib
import io
import json
import os
import sys
import tempfile

_TOOLS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_KB_TOOLS = os.path.join(_TOOLS, "kb")
for _p in (_TOOLS, _KB_TOOLS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import convergence  # noqa: E402 — tools/kb/convergence.py
import case_state  # noqa: E402
import intel  # noqa: E402


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

    # --- 1. zero_growth / is_converged: the module-level contract -------------------------------
    failing_rows = [{"new_hosts": 0, "new_indicators": 0, "failed": ["bad.example"]} for _ in range(2)]
    ok(not convergence.is_converged(failing_rows, 2),
       "rows with failed hosts never converge, even with zero new hosts/indicators")

    legacy_rows = [{"new_hosts": 0, "new_indicators": 0} for _ in range(2)]  # no `failed` key at all
    ok(convergence.is_converged(legacy_rows, 2),
       "legacy rows without a `failed` key converge exactly as before")

    mixed_rows = [{"new_hosts": 0, "new_indicators": 0},
                  {"new_hosts": 0, "new_indicators": 0, "failed": ["bad.example"]}]
    ok(not convergence.is_converged(mixed_rows, 2),
       "one failed round inside the stale window blocks convergence")

    growing_rows = [{"new_hosts": 1, "new_indicators": 0, "failed": []},
                    {"new_hosts": 0, "new_indicators": 0, "failed": []}]
    ok(not convergence.is_converged(growing_rows, 2),
       "an empty `failed` list does not itself block convergence — real growth still does")

    # --- 2. `snapshot --failed` writes the field -------------------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, "raw"), exist_ok=True)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = convergence.main(["snapshot", tmp, "--failed", "b.example, a.example"])
        ok(rc == 0, "snapshot --failed exits 0")
        rows = convergence._load_rounds(tmp)
        ok(len(rows) == 1 and rows[0].get("failed") == ["a.example", "b.example"],
           "snapshot --failed persists a sorted `failed` list in rounds.jsonl")

        buf2 = io.StringIO()
        with contextlib.redirect_stdout(buf2):
            rc2 = convergence.main(["snapshot", tmp])
        rows2 = convergence._load_rounds(tmp)
        ok(rc2 == 0 and rows2[1].get("failed") == [],
           "snapshot with no --failed writes an empty list, not a missing key")

    # --- 3. case_state.convergence_verdict agrees with convergence.is_converged -----------------
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, "raw"), exist_ok=True)
        rows = [
            {"ts": "2026-01-01T00:00:00", "round": 1, "hosts": 3, "indicators": 5,
             "new_hosts": 0, "new_indicators": 0, "host_set": [], "ind_set": [],
             "failed": ["dead.example"]},
            {"ts": "2026-01-01T00:05:00", "round": 2, "hosts": 3, "indicators": 5,
             "new_hosts": 0, "new_indicators": 0, "host_set": [], "ind_set": [],
             "failed": ["dead.example"]},
        ]
        with open(os.path.join(tmp, "rounds.jsonl"), "w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")
        verdict = case_state.convergence_verdict(tmp, stale=2)
        ok(verdict["verdict"] == "EXPANDING",
           "case_state.convergence_verdict: a persistently failing host keeps the case EXPANDING")
        ok(convergence.is_converged(convergence._load_rounds(tmp), 2) == (verdict["verdict"] == "CONVERGED"),
           "case_state.convergence_verdict agrees with convergence.is_converged on the same rows")
        ok(verdict.get("failed_recent") == ["dead.example"],
           "convergence_verdict surfaces the recent failed hosts")

        # now the host recovers (round 3 succeeds, no failures) — legacy zero-growth behaviour
        # applies again once nothing is failing.
        with open(os.path.join(tmp, "rounds.jsonl"), "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"ts": "2026-01-01T00:10:00", "round": 3, "hosts": 3,
                                 "indicators": 5, "new_hosts": 0, "new_indicators": 0,
                                 "host_set": [], "ind_set": [], "failed": []}) + "\n")
            fh.write(json.dumps({"ts": "2026-01-01T00:15:00", "round": 4, "hosts": 3,
                                 "indicators": 5, "new_hosts": 0, "new_indicators": 0,
                                 "host_set": [], "ind_set": [], "failed": []}) + "\n")
        verdict2 = case_state.convergence_verdict(tmp, stale=2)
        ok(verdict2["verdict"] == "CONVERGED",
           "once the failing host is gone, two clean zero-growth rounds converge normally")
        ok(verdict2.get("failed_recent") == [],
           "failed_recent is empty once nothing failed in the stale window")

    # --- 4. legacy rounds.jsonl (no `failed` key anywhere) still converge via case_state --------
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, "raw"), exist_ok=True)
        with open(os.path.join(tmp, "rounds.jsonl"), "w", encoding="utf-8") as fh:
            for i in (1, 2):
                fh.write(json.dumps({"ts": "2026-01-01T00:00:00", "round": i, "hosts": 2,
                                     "indicators": 2, "new_hosts": 0, "new_indicators": 0,
                                     "host_set": [], "ind_set": []}) + "\n")  # no `failed` key
        verdict = case_state.convergence_verdict(tmp, stale=2)
        ok(verdict["verdict"] == "CONVERGED",
           "legacy rounds.jsonl rows (predating `failed`) still converge exactly as before")

    # --- 5. cmd_cti's final open_leads includes metered + OPEN enrichment leads after the loop --
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, "raw"), exist_ok=True)
        fixture = {
            "pending": ["new1.example", "new2.example"],
            # the REAL frontier metered-lead shape: {service, query, cost, why} — no `key` field
            # (a fixture with a synthetic `key` hid that the live driver dropped every metered lead)
            "metered_leads": [{"service": "FOFA", "query": 'ip="203.0.113.5"', "cost": "metered",
                               "why": "synthetic"},
                              {"service": "WhoisXML", "query": 'reverse-whois email="a@example.com"',
                               "cost": "metered", "why": "synthetic"}],
            "enrichment_leads": [{"key": "enrich:phone:+15550100"},
                                 {"key": "enrich:email:analyst@example.com"}],
        }
        orig_frontier = case_state.frontier
        orig_cmd_open = intel.cmd_open
        orig_run_enrichment = intel._run_enrichment
        orig_cmd_loop = intel.cmd_loop
        loop_calls = []

        def _stub_frontier(case, max_new=8):
            return dict(fixture)

        def _stub_cmd_open(oargs):
            return None  # no network — the loop/frontier seams are stubbed, not collection

        def _stub_run_enrichment(*a, **k):
            return None

        def _stub_cmd_loop(largs):
            loop_calls.append(largs.case)
            return None  # state.json stays at its fresh default (status=expanding)

        case_state.frontier = _stub_frontier
        intel.cmd_open = _stub_cmd_open
        intel._run_enrichment = _stub_run_enrichment
        intel.cmd_loop = _stub_cmd_loop
        saved_quarry = os.environ.get("QUARRY_ENABLED")
        os.environ["QUARRY_ENABLED"] = "off"   # this test is the pipeline path, not the Quarry wait
        try:
            import argparse
            a = argparse.Namespace(target="synthetic-target.example", case=tmp, quick=False,
                                   deep=False, passive=False, free_only=False, extend=False,
                                   pipeline=True)   # the PIPELINE path; never spawn the LLM harness
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                intel.cmd_cti(a)
            printed = buf.getvalue().strip().splitlines()
            summary = json.loads(printed[-1])
        finally:
            if saved_quarry is None:
                os.environ.pop("QUARRY_ENABLED", None)
            else:
                os.environ["QUARRY_ENABLED"] = saved_quarry
            case_state.frontier = orig_frontier
            intel.cmd_open = orig_cmd_open
            intel._run_enrichment = orig_run_enrichment
            intel.cmd_loop = orig_cmd_loop

        ok(loop_calls == [tmp], "cmd_cti actually reached the loop step (unconverged domain target)")
        leads = set(summary.get("open_leads") or [])
        ok({"new1.example", "new2.example"} <= leads,
           "cmd_cti final open_leads still contains the free pending apexes after the loop")
        ok({'FOFA:ip="203.0.113.5"', 'WhoisXML:reverse-whois email="a@example.com"'} <= leads,
           "cmd_cti final open_leads names every metered lead by service:query after the loop")
        ok({"enrich:phone:+15550100", "enrich:email:analyst@example.com"} <= leads,
           "cmd_cti final open_leads includes OPEN enrichment lead keys after the loop (was dropped)")
        ok(len(summary.get("open_leads") or []) == len(leads),
           "open_leads is deduplicated (no repeated keys across pending/metered/enrichment)")

    return passed, failed, out


if __name__ == "__main__":
    p, f, lines = check()
    for s, l in lines:
        print(f"  {'ok ' if s == 'ok' else '✗  '} {l}")
    print(f"\n{p} passed, {f} failed")
    sys.exit(1 if f else 0)
