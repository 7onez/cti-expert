#!/usr/bin/env python3
"""
test_timeline_inputs.py — case_timeline.py must READ a case's raw/*.json however it is named.

Run:  python3 tests/test_timeline_inputs.py      (stdlib only; --no-figure, no matplotlib)

The regression: callers (the MCP tool, the CLI backend, a shell) pass `cases/<case>/raw/*.json`
as ONE literal argument from a working directory that is not the engine root. The script opened
it verbatim, so a glob never expanded and a relative path anchored only at the CWD — and every
call ended in "no pivot_extract JSON could be read — nothing to time" although the case held valid
pivot JSON (181 such failures in one case ledger). Each input form below must yield events.
Synthetic data only (RULE 1): example.com hosts, RFC 5737 addresses.
"""
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "IntelGraph", "scripts", "case_timeline.py")
CASE = "CASE-00000000-01"

_ANALYSIS = {
    "meta": {"source": "https://alpha.example.com", "final_url": "https://alpha.example.com/",
             "host": "alpha.example.com"},
    "artifacts": {"whois": {"domain": "alpha.example.com", "registrar": "Example Registrar",
                            "created": "2024-01-10", "expires": "2026-01-10",
                            "updated": "2025-02-01"}},
    "pivots": [{"kind": "domain", "value": "alpha.example.com", "live_results": {
        "pdns": {"records": [{"rrname": "alpha.example.com", "rrtype": "A",
                              "rdata": "192.0.2.10", "time_first": "2024-02-01",
                              "time_last": "2025-06-01", "count": 3}]}}}],
}


def _run(inputs, cwd, home, stem):
    env = dict(os.environ, INTEL_HOME=home)
    r = subprocess.run([sys.executable, SCRIPT, *inputs, "--stem", stem, "--no-figure"],
                       cwd=cwd, env=env, capture_output=True, text=True, timeout=120)
    ledger = stem + "_events.json"
    events = 0
    if r.returncode == 0 and os.path.isfile(ledger):
        with open(ledger, encoding="utf-8") as fh:
            events = len(json.load(fh).get("events") or [])
    return r, events


def check():
    out, passed, failed = [], 0, 0
    with tempfile.TemporaryDirectory() as home, tempfile.TemporaryDirectory() as elsewhere:
        raw = os.path.join(home, "cases", CASE, "raw")
        os.makedirs(raw)
        with open(os.path.join(raw, "alpha.example.com.json"), "w", encoding="utf-8") as fh:
            json.dump(_ANALYSIS, fh)
        rel_dir = f"cases/{CASE}/raw"
        forms = [
            ("relative glob (unexpanded)", [f"{rel_dir}/*.json"]),
            ("relative file", [f"{rel_dir}/alpha.example.com.json"]),
            ("absolute glob (unexpanded)", [os.path.join(raw, "*.json")]),
            ("absolute file", [os.path.join(raw, "alpha.example.com.json")]),
            ("one space-separated string", [f"{rel_dir}/alpha*.json {rel_dir}/*.example.com.json"]),
            ("docs' out/ spelling falls back to raw/", [f"cases/{CASE}/out/*.json"]),
        ]
        for i, (label, inputs) in enumerate(forms):
            stem = os.path.join(elsewhere, f"tl{i}")
            r, events = _run(inputs, elsewhere, home, stem)
            good = r.returncode == 0 and events > 0
            passed += good
            failed += not good
            detail = "" if good else f" (rc={r.returncode}: {r.stderr.strip()[-160:]})"
            out.append(("ok" if good else "FAIL", f"{label} -> {events} event(s){detail}"))
    return passed, failed, out


if __name__ == "__main__":
    p, f, lines = check()
    for status, label in lines:
        print(f"{'  ok  ' if status == 'ok' else '  FAIL'} {label}")
    if f:
        print(f"FAIL — {f} input form(s) read nothing")
        sys.exit(1)
    print(f"PASS — case_timeline reads raw/*.json in all {p} input forms")
