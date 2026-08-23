#!/usr/bin/env python3
"""
test_context_budget.py — the gate on the context-management layer.

Run:  python3 tests/test_context_budget.py
      python3 tools/eval/run_eval.py     (runs as part of the regression gate)

TWO THINGS ARE PROTECTED HERE, and both failure modes are silent.

1. TOOL-RESULT GOVERNOR (harness/tools.py `_bounded` / `_governed`)
   Before this layer, four tools capped their own output with a hand-placed slice and every
   other tool returned its full payload, so one collection over a large cluster could crowd a
   phase's own instructions out of the window. The governor now binds each tool's NAME around
   its handler by SWEEPING the module, so a tool added later cannot escape it by forgetting to
   opt in — which is exactly how the gap opened the first time. The assertions check that the
   sweep really reached every registered tool, that head AND tail survive (our JSON leads with
   `meta` and ends with the summary), and above all that a cut is ANNOUNCED: a quietly
   shortened result is indistinguishable from a tool that found less, and "found less" is how
   a false negative enters a case.

2. TRANSCRIPT TRIM (harness/openai_backend.py `_trim_history`)
   The OpenAI-compat shim owns its own message history and appended to it forever. Trimming it
   WRONG is worse than not trimming: drop an assistant `tool_calls` message without its `tool`
   replies (or the reverse) and the provider rejects the whole request, turning a context
   problem into a hard API failure. So the invariants are pairing, keeping the system prompt
   and the original task, and announcing what was elided.

No network, no case data (contributor RULE 1).
"""
import importlib
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "WebPivot", "tools"))
sys.path.insert(0, os.path.join(ROOT, "harness"))

import openai_backend as OB  # noqa: E402
import tools as T            # noqa: E402


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

    # --- 1. the tool-result governor --------------------------------------------------------
    small = "x" * 100
    ok(T._bounded(small) == small, "a result under budget is passed through byte-identical")

    big = "HEAD" + ("m" * 200000) + "TAIL"
    cut = T._bounded(big, tool=None, where="cases/CASE-0001/raw/site-a.example.json")
    ok(len(cut) < len(big) and len(cut) <= T._budget_for(None) + 800,
       f"an over-budget result is cut to the budget ({len(cut)} chars out)")
    ok(cut.startswith("HEAD"), "the HEAD survives — our JSON leads with meta (host/status/capability)")
    ok(cut.endswith("TAIL"), "the TAIL survives — list-shaped output carries its summary at the end")
    ok("TRUNCATED" in cut, "the cut is ANNOUNCED, never silent")
    ok(f"{len(big):,}" in cut, "the marker states the ORIGINAL size, so the loss is measurable")
    ok("NOT evidence of absence" in cut,
       "the marker forbids reading the omitted middle as 'nothing found'")
    ok("cases/CASE-0001/raw/site-a.example.json" in cut,
       "the marker points at the full copy on disk")

    ok(T._budget_for("pivot_extract") > T._budget_for(None),
       "collectors get the LARGE budget — their payload IS the evidence")
    ok(T._budget_for("api_usage") == T._budget_for(None),
       "a status tool gets the default budget — its long tail is noise")

    os.environ["HARNESS_RESULT_CHARS"] = "2000"
    try:
        importlib.reload(T)
        ok(T._budget_for("pivot_extract") == 2000,
           f"HARNESS_RESULT_CHARS overrides the data file per run "
           f"(got {T._budget_for('pivot_extract')})")
    finally:
        del os.environ["HARNESS_RESULT_CHARS"]
        importlib.reload(T)

    # The SWEEP, not a hand-maintained list, is what guarantees coverage — assert it reached all.
    registered = [v for v in vars(T).values()
                  if hasattr(v, "handler") and hasattr(v, "name") and hasattr(v, "input_schema")]
    ungoverned = sorted(t.name for t in registered if not getattr(t, "_governed", False))
    ok(not ungoverned,
       f"every registered tool is governed — {len(registered)} tools (ungoverned: {ungoverned})")
    ok(len(T._err("e" * 100000)["content"][0]["text"]) < 100000,
       "_err is bounded too — a stderr dump is frequently a long stack trace")
    ok(T._err("boom")["is_error"] is True, "a bounded error result still reports is_error")

    # --- 2. the transcript trim -------------------------------------------------------------
    prev_cap, prev_keep = OB.TRANSCRIPT_CAP, OB.KEEP_RECENT_ROUNDS
    try:
        OB.TRANSCRIPT_CAP, OB.KEEP_RECENT_ROUNDS = 5000, 2
        msgs = [{"role": "system", "content": "SYSTEM PROMPT"},
                {"role": "user", "content": "THE ORIGINAL TASK"}]
        for i in range(12):
            msgs.append({"role": "assistant", "content": None,
                         "tool_calls": [{"id": f"c{i}", "type": "function",
                                         "function": {"name": "pivot_extract",
                                                      "arguments": "{}"}}]})
            msgs.append({"role": "tool", "tool_call_id": f"c{i}", "content": "R" * 900})

        trimmed = OB._trim_history(list(msgs))
        ok(len(trimmed) < len(msgs),
           f"an over-budget history is trimmed ({len(msgs)} -> {len(trimmed)} messages)")
        ok(trimmed[0]["content"] == "SYSTEM PROMPT", "the SYSTEM prompt is never elided")
        ok(any(m.get("content") == "THE ORIGINAL TASK" for m in trimmed),
           "the ORIGINAL TASK is never elided — losing it makes the agent answer another question")
        ok(any("context budget" in str(m.get("content", "")) for m in trimmed),
           "the elision is ANNOUNCED in-band to the model")
        ok(any("on disk" in str(m.get("content", "")) for m in trimmed),
           "the note says the elided findings are ON DISK, not that they never happened")

        ids = {tc["id"] for m in trimmed if m.get("role") == "assistant"
               for tc in (m.get("tool_calls") or [])}
        tool_ids = {m["tool_call_id"] for m in trimmed if m.get("role") == "tool"}
        ok(tool_ids <= ids,
           f"no orphan tool REPLY — the provider rejects those (orphans: {sorted(tool_ids - ids)})")
        ok(ids <= tool_ids,
           f"no orphan tool CALL — the provider rejects those (orphans: {sorted(ids - tool_ids)})")
        ok(sum(OB._msg_chars(m) for m in trimmed) <= OB.TRANSCRIPT_CAP + 2000,
           f"the trimmed history is under the cap "
           f"({sum(OB._msg_chars(m) for m in trimmed)} chars)")

        OB.TRANSCRIPT_CAP = 10_000_000
        under = [{"role": "system", "content": "S"}, {"role": "user", "content": "U"}]
        ok(OB._trim_history(under) == under, "an under-budget history is returned untouched")
    finally:
        OB.TRANSCRIPT_CAP, OB.KEEP_RECENT_ROUNDS = prev_cap, prev_keep

    capped = OB._cap_tool_output("z" * 500000, "pivot_extract")
    ok(len(capped) < 500000, "one tool result is capped at INSERTION time, before it enters history")
    ok("TRUNCATED" in capped, "the insertion-time cap is announced too (it used to be a silent slice)")
    ok("pivot_extract" in capped, "the insertion-time marker names the tool that was cut")
    ok(OB._cap_tool_output("z" * 10, "t") == "z" * 10, "a small tool result is untouched")

    return passed, failed, out


def main():
    passed, failed, lines = check()
    for status, label in lines:
        print(f"  {'ok  ' if status == 'ok' else 'FAIL'} {label}")
    print(f"\n{'PASS' if not failed else 'FAIL'} — {passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
