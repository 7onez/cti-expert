#!/usr/bin/env python3
"""intel — one console entrypoint for the OSINT harness.

    intel open     CASE  <seed-url> ...        # one Collect→Correlate→Assess round
    intel continue CASE  <seed-url> ...        # iterate to convergence (--continue)
    intel status   [CASE]                      # case state, NO LLM, NO API key

`open` / `continue` are thin wrappers over `orchestrator.py` — every extra flag
(`--hostile`, `--parallel`, `--depth N`, `--collect-conc N`, …) is passed straight
through, so the CLI never has to know about them. `status` reads the git-ignored
`cases/` store directly (stdlib only): it does not import the Agent SDK and spends
no tokens, so it works with no `ANTHROPIC_API_KEY` and while a run is in flight.

Run it via the repo-root `intel` shim (`./intel status`) or `python3 harness/cli.py …`.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))            # harness/
ROOT = os.path.dirname(HERE)                                 # repo root
CASES = os.path.join(ROOT, "cases")


# ---------------------------------------------------------------- open / continue
def _run_orchestrator(passthrough: list[str], *, cont: bool) -> int:
    """Forward to orchestrator.py verbatim (inserting --continue for `continue`). cwd=ROOT so the
    harness's .env discovery — which starts at the invocation cwd — finds the repo-root keys."""
    if not passthrough:
        sys.exit("need a CASE id and at least one seed url")
    case, rest = passthrough[0], passthrough[1:]
    cmd = [sys.executable, os.path.join(HERE, "orchestrator.py"), case]
    if cont:
        cmd.append("--continue")
    cmd += rest
    return subprocess.run(cmd, cwd=ROOT).returncode


# ---------------------------------------------------------------- status (no LLM)
def _load_json(path: str) -> dict | None:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:  # noqa: BLE001 — a half-written/absent file just means "no data yet"
        return None


def _rounds(case_dir: str) -> list[dict]:
    p = os.path.join(case_dir, "rounds.jsonl")
    if not os.path.exists(p):
        return []
    out = []
    for line in open(p, encoding="utf-8"):
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except Exception:  # noqa: BLE001
                pass
    return out


def _converged(rounds: list[dict], stale: int = 2) -> bool:
    """Same rule as convergence.py / orchestrator._is_converged: the last `stale` snapshot rounds
    each added zero new hosts and zero new indicators."""
    if len(rounds) < stale:
        return False
    return all(r.get("new_hosts") == 0 and r.get("new_indicators") == 0 for r in rounds[-stale:])


def _latest_assessment(case_dir: str) -> dict | None:
    """The newest immutable snapshot (assessments/<UTC>_r*.json), falling back to the
    back-compat head assessment.json."""
    snaps = sorted(glob.glob(os.path.join(case_dir, "assessments", "*.json")))
    if snaps:
        return _load_json(snaps[-1])
    return _load_json(os.path.join(case_dir, "assessment.json"))


def _wc(path: str) -> int:
    if not os.path.exists(path):
        return 0
    with open(path, encoding="utf-8") as f:
        return sum(1 for line in f if line.strip())


def _case_stat(case: str) -> dict:
    case_dir = os.path.join(CASES, case)
    a = _latest_assessment(case_dir) or {}
    rounds = _rounds(case_dir)
    return {
        "case": case,
        "collected": len(glob.glob(os.path.join(case_dir, "raw", "*.json"))),
        "snapshots": len(glob.glob(os.path.join(case_dir, "assessments", "*.json"))),
        "evidence": _wc(os.path.join(case_dir, "evidence", "manifest.jsonl")),
        "attribution": a.get("attribution_level", "—"),
        "confidence": a.get("confidence", "—"),
        "cluster": len(a.get("cluster") or []),
        "bluf": (a.get("bluf") or "").replace("\n", " ").strip(),
        "next_pivots": a.get("next_pivots") or [],
        "converged": _converged(rounds),
        "rounds": len(rounds),
    }


def _cmd_status(case: str | None) -> int:
    if not os.path.isdir(CASES):
        print("no cases/ store yet.")
        return 0

    # No case → one line per case (a fleet view).
    if not case:
        cases = sorted(d for d in os.listdir(CASES) if os.path.isdir(os.path.join(CASES, d)))
        if not cases:
            print("no cases yet.")
            return 0
        print(f"{'CASE':<28} {'DOM':>4} {'RND':>4} {'ATTRIB/CONF':<20} {'CONV':<5} BLUF")
        for c in cases:
            s = _case_stat(c)
            conv = "yes" if s["converged"] else ("—" if not s["rounds"] else "no")
            print(f"{c:<28} {s['collected']:>4} {s['snapshots']:>4} "
                  f"{(s['attribution'] + '/' + s['confidence']):<20} {conv:<5} {s['bluf'][:60]}")
        return 0

    # One case → the detail view.
    if not os.path.isdir(os.path.join(CASES, case)):
        print(f"no such case: {case}  (looked in {os.path.relpath(os.path.join(CASES, case), ROOT)})")
        return 1
    s = _case_stat(case)
    print(f"# {case}")
    print(f"  domains collected : {s['collected']}")
    print(f"  assessment rounds : {s['snapshots']}"
          + (f"   (converged after {s['rounds']} snapshot round(s))" if s["converged"]
             else (f"   ({s['rounds']} snapshot round(s), not converged)" if s["rounds"] else "")))
    print(f"  attribution       : {s['attribution']} / {s['confidence']}"
          + (f"   ({s['cluster']} in cluster)" if s["cluster"] else ""))
    print(f"  evidence rows     : {s['evidence']}")
    if s["bluf"]:
        print(f"\n  BLUF: {s['bluf']}")
    if s["next_pivots"]:
        print("\n  next pivots:")
        for p in s["next_pivots"][:8]:
            print(f"    - {p}")
    print(f"\n  files: {os.path.relpath(os.path.join(CASES, case), ROOT)}/"
          f"  (SUMMARY.md · CHANGELOG.md · assessments/ · evidence/)")
    return 0


# ---------------------------------------------------------------- entry
def main() -> int:
    ap = argparse.ArgumentParser(prog="intel", description="OSINT harness console")
    sub = ap.add_subparsers(dest="cmd", required=True)
    o = sub.add_parser("open", help="one Collect→Correlate→Assess round over the seeds")
    o.add_argument("args", nargs=argparse.REMAINDER, help="CASE <seed-url> ... [orchestrator flags]")
    c = sub.add_parser("continue", help="iterate to convergence (--continue)")
    c.add_argument("args", nargs=argparse.REMAINDER, help="CASE <seed-url> ... [--depth N ...]")
    st = sub.add_parser("status", help="case state (no LLM, no API key)")
    st.add_argument("case", nargs="?", help="a CASE id; omit to list every case")
    a = ap.parse_args()

    if a.cmd == "open":
        return _run_orchestrator(a.args, cont=False)
    if a.cmd == "continue":
        return _run_orchestrator(a.args, cont=True)
    if a.cmd == "status":
        return _cmd_status(a.case)
    return 2


if __name__ == "__main__":
    sys.exit(main())
