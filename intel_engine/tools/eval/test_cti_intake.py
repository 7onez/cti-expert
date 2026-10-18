#!/usr/bin/env python3
"""Offline unit gate: the `cti` driver scopes the case BEFORE any collection.

The driver used to start collecting with target_class defaulted to `unknown` and never asked. Now:
  * at a terminal (stubbed TTY here) it asks target class + purpose and persists the answers to
    cases/<case>/scope.json before the collect step runs;
  * a non-interactive run without flags proceeds on the default and SAYS it was defaulted — it
    never blocks on input;
  * `--class benign_check` persists the class without prompting, even at a terminal.

Fully offline: recall, Quarry, collect and the frontier/convergence reads are stubbed; ROOT points
at a TemporaryDirectory, so no real case store is touched. Synthetic targets only.
"""
import argparse
import builtins
import contextlib
import io
import json
import os
import sys
import tempfile
import types

_TOOLS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_KB_TOOLS = os.path.join(_TOOLS, "kb")
for _p in (_TOOLS, _KB_TOOLS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import case_state  # noqa: E402
import intel  # noqa: E402


class _TTY(io.StringIO):
    def isatty(self):
        return True


class _NoTTY(io.StringIO):
    def isatty(self):
        return False


def _args(target, case, **kw):
    base = dict(target=target, case=case, quick=True, deep=False, passive=False,
                free_only=False, extend=False, pipeline=True, depth=None, quarry=False,
                no_quarry=True, target_class=None, purpose=None, yes=False)
    base.update(kw)
    return argparse.Namespace(**base)


def _run(a, tmp, *, tty, answers=None):
    """Run cmd_cti with every collection seam stubbed. Returns (summary, stdout, prompts asked,
    scope.json as seen by the collect step)."""
    prompts, seen_at_collect = [], {}
    feed = list(answers or [])

    def _input(prompt=""):
        prompts.append(prompt)
        if not feed:
            raise EOFError
        return feed.pop(0)

    def _cmd_open(oargs):
        p = os.path.join(tmp, "cases", oargs.case, "scope.json")
        seen_at_collect["scope"] = json.load(open(p, encoding="utf-8")) if os.path.isfile(p) else None

    saved = dict(ROOT=intel.ROOT, cmd_open=intel.cmd_open, recall=intel._recall_attribution,
                 quarry=intel._cti_quarry_stage, frontier=case_state.frontier,
                 verdict=case_state.convergence_verdict, stdin=sys.stdin, input=builtins.input,
                 next_actions=sys.modules.get("next_actions"))
    saved_env = {k: os.environ.pop(k, None)
                 for k in ("INTEL_NO_PROMPT", "INTEL_IN_HARNESS", "HARNESS_PHASE")}
    # the post-summary NEXT_ACTIONS menu is its own gate (test_next_actions); silence it here
    sys.modules["next_actions"] = types.SimpleNamespace(emit_or_prompt=lambda *x, **k: None)
    intel.ROOT = tmp
    intel.cmd_open = _cmd_open
    intel._recall_attribution = lambda *x, **k: None
    intel._cti_quarry_stage = lambda *x, **k: None
    case_state.frontier = lambda case, max_new=8: {"pending": [], "metered_leads": [],
                                                    "enrichment_leads": []}
    case_state.convergence_verdict = lambda case: {"verdict": "EXPANDING"}
    sys.stdin = _TTY() if tty else _NoTTY()
    builtins.input = _input
    buf = _TTY() if tty else _NoTTY()
    try:
        with contextlib.redirect_stdout(buf):
            intel.cmd_cti(a)
    finally:
        intel.ROOT = saved["ROOT"]
        intel.cmd_open = saved["cmd_open"]
        intel._recall_attribution = saved["recall"]
        intel._cti_quarry_stage = saved["quarry"]
        case_state.frontier = saved["frontier"]
        case_state.convergence_verdict = saved["verdict"]
        sys.stdin = saved["stdin"]
        builtins.input = saved["input"]
        if saved["next_actions"] is None:
            sys.modules.pop("next_actions", None)
        else:
            sys.modules["next_actions"] = saved["next_actions"]
        for k, v in saved_env.items():
            if v is not None:
                os.environ[k] = v
    out = buf.getvalue()
    return json.loads(out.strip().splitlines()[-1]), out, prompts, seen_at_collect.get("scope")


def _scope(tmp, case):
    p = os.path.join(tmp, "cases", case, "scope.json")
    return json.load(open(p, encoding="utf-8")) if os.path.isfile(p) else None


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

    # --- 1. interactive: the answered class + purpose are persisted before collection --------------
    with tempfile.TemporaryDirectory() as tmp:
        summary, text, prompts, at_collect = _run(
            _args("shop.example", "CASE-T1"), tmp, tty=True,
            answers=["suspected_scam", "attribution"])
        s = _scope(tmp, "CASE-T1") or {}
        ok(len(prompts) == 2, "interactive run asks exactly the two intake questions")
        ok(s.get("target_class") == "suspected_scam" and s.get("purpose") == "attribution",
           "interactive answers are persisted to cases/<case>/scope.json")
        ok({"target_class", "purpose"} <= set(s.get("stated_fields") or []),
           "persisted answers are recorded as STATED, not defaulted")
        ok((at_collect or {}).get("target_class") == "suspected_scam",
           "scope.json already holds the answered class when the collect step runs")
        ok(summary.get("target_class") == "suspected_scam",
           "the JSON summary reports the class the run used")

        # a resumed case keeps its answers: no second interview
        _, _, prompts2, _ = _run(_args("shop.example", "CASE-T1"), tmp, tty=True,
                                 answers=["benign_check", "x"])
        ok(prompts2 == [] and (_scope(tmp, "CASE-T1") or {}).get("target_class") == "suspected_scam",
           "a case with a stated scope is not re-asked and its class is kept")

    # --- 1b. interactive by number; an empty purpose takes the default --------------------------
    with tempfile.TemporaryDirectory() as tmp:
        sys.path.append(os.path.join(os.path.dirname(_TOOLS), "harness"))
        import case_scope as CS
        idx = list(CS.CLASSES).index("victim_host") + 1
        _run(_args("host-a.example", "CASE-T1B"), tmp, tty=True, answers=[str(idx), ""])
        s = _scope(tmp, "CASE-T1B") or {}
        ok(s.get("target_class") == "victim_host" and "purpose" not in (s.get("stated_fields") or []),
           "class accepted by number; an empty purpose stays defaulted (not marked stated)")

    # --- 2. non-interactive, no flags: never prompts, proceeds on the default, says so -----------
    with tempfile.TemporaryDirectory() as tmp:
        summary, text, prompts, at_collect = _run(_args("shop.example", "CASE-T2"), tmp, tty=False)
        s = _scope(tmp, "CASE-T2") or {}
        ok(prompts == [], "a non-interactive run never prompts")
        ok(s.get("target_class") == "unknown" and not s.get("stated"),
           "non-interactive run without flags proceeds on the default class (unstated)")
        ok("DEFAULTED" in text and "--class" in text,
           "non-interactive run prints that the scope was defaulted and how to state it")
        ok(at_collect is not None, "the defaulted scope is persisted before collection")
        ok(summary.get("status") in ("expanding", "converged"),
           "the scripted run completes and still ends on the JSON summary line")

    # --- 2b. --yes at a terminal behaves as non-interactive --------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        _, text, prompts, _ = _run(_args("shop.example", "CASE-T2B", yes=True), tmp, tty=True,
                                   answers=["confirmed_scam", "attribution"])
        ok(prompts == [] and "DEFAULTED" in text,
           "--yes at a terminal never prompts and reports the default")

    # --- 3. --class benign_check persists without prompting, even at a terminal -----------------
    with tempfile.TemporaryDirectory() as tmp:
        _, text, prompts, at_collect = _run(
            _args("shop.example", "CASE-T3", target_class="benign_check"), tmp, tty=True,
            answers=["confirmed_scam", "attribution"])
        s = _scope(tmp, "CASE-T3") or {}
        ok(prompts == [], "--class skips the interactive prompt")
        ok(s.get("target_class") == "benign_check" and "target_class" in (s.get("stated_fields") or []),
           "--class benign_check is persisted as the stated class")
        ok((at_collect or {}).get("target_class") == "benign_check",
           "--class is persisted before the collect step runs")
        _, _, _, _ = _run(_args("shop.example", "CASE-T3B", target_class="benign_check",
                                purpose="triage"), tmp, tty=False)
        s = _scope(tmp, "CASE-T3B") or {}
        ok(s.get("purpose") == "triage" and "purpose" in (s.get("stated_fields") or []),
           "--purpose persists as stated on a non-interactive run")

    # --- 4. the CLI exposes the flags ------------------------------------------------------------
    src = open(os.path.join(_TOOLS, "intel.py"), encoding="utf-8").read()
    ok('"--class", dest="target_class"' in src and 'ct.add_argument("--purpose"' in src
       and 'ct.add_argument("--yes"' in src, "cti parser declares --class / --purpose / --yes")

    return passed, failed, out


def main():
    passed, failed, lines = check()
    for status, label in lines:
        print(f"  {'ok  ' if status == 'ok' else 'FAIL'} {label}")
    print(f"\n{'PASS' if not failed else 'FAIL'} — {passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
