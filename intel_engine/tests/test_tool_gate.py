#!/usr/bin/env python3
"""
test_tool_gate.py — the gate on the TOOL-CALL GATE (harness/audit.py).

Run:  python3 tests/test_tool_gate.py
      python3 tools/eval/run_eval.py        (runs as part of the regression gate)

WHAT THIS PROTECTS
------------------
The gate is the only thing standing between an autonomous agent loop and three irreversible
mistakes: touching hostile infrastructure from the analyst's IP, detonating a sample in a public
sandbox without a human 'yes', and burning a month of per-account API credits in one runaway
round. All three failure modes are SILENT — the run looks successful either way, and you only
learn it went wrong from the operator's behaviour afterwards. So each is asserted here.

Three front-ends reach the same policy by three different mechanisms, and the tests below cover
all three, because a gate enforced on one path and not the others is worse than none: it produces
a governance banner you would be wrong to trust.

  SDK driver     PreToolUse hook closure  -> _gate_hook returns a deny payload
  DeepSeek shim  audit.gate() inline      -> the handler must NOT run
  Claude Code    audit.gate() in MCP call -> covered by the same decide() assertions

WHY THE SDK PATH USES A HOOK AND NOT `can_use_tool`
---------------------------------------------------
`can_use_tool` is only consulted for calls that would otherwise PROMPT, and both
permission_mode="bypassPermissions" and whole-tool allowed_tools entries shadow it — the exact
configuration the harness runs. The SDK emits CanUseToolShadowedWarning to say so. The last test
here turns warnings into errors while constructing the real options object, so if a future edit
reintroduces can_use_tool (or narrows the config into a shadowing shape) the gate fails loudly
instead of silently never firing.
"""
import asyncio
import io
import json
import os
import shutil
import sys
import tempfile
import warnings

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "harness"))


def check():
    """Return (passed, failed, [(status, label)]) — the tools/eval unit-module contract."""
    out, passed, failed = [], 0, 0

    def ok(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1
            out.append(("ok", label))
        else:
            failed += 1
            out.append(("FAIL", label))

    import audit

    def allows(tool, args, hostile=False):
        return audit.decide(tool, args, hostile=hostile)[0]

    # --- 1. hostile egress: the rule lifted ABOVE the tools ----------------------------------
    # pivot_extract enforced this internally; the other outbound collectors never did. The gate
    # is what makes the rule apply to a tool that forgot to implement it.
    ok(allows("pivot_extract", {"url": "http://x.example"}),
       "benign posture: a live fetch is allowed")
    ok(not allows("pivot_extract", {"url": "http://x.example"}, hostile=True),
       "hostile posture: a direct live fetch is DENIED")
    for t in ("impersonation_hunt", "analyze_artifact", "fallback_probe"):
        ok(not allows(t, {"url": "http://x.example"}, hostile=True),
           f"hostile posture: {t} is DENIED too (rule is not pivot_extract-only)")
    ok(allows("pivot_extract", {"url": "http://x.example", "passive": True}, hostile=True),
       "hostile + passive=true is allowed (archive/third-party sources only)")
    # A proxy is a VALUE, not a boolean — testing `v is True` denied every real proxy.
    ok(allows("pivot_extract", {"url": "http://x.example", "proxy": "http://127.0.0.1:8080"},
              hostile=True),
       "hostile + proxy=<host> is allowed (a host string counts as set)")
    ok(not allows("pivot_extract", {"url": "http://x.example", "proxy": ""}, hostile=True),
       "hostile + proxy='' is DENIED (an empty proxy is not a proxy)")
    ok(not allows("pivot_extract", {"url": "http://x.example", "passive": "false"}, hostile=True),
       "hostile + passive='false' is DENIED (string false is false)")
    ok(allows("kb_cluster", {"domain": "x.example"}, hostile=True),
       "hostile posture does not block read-only KB analysis")

    # --- 2. sandbox submission needs a human, not a prompt — but the BRIEFING stays reachable ---
    env = audit.APPROVAL_REQUIRED.get("anyrun_submit")
    ok(bool(env), "anyrun_submit is registered as approval-required")
    ok("anyrun_submit" in audit.APPROVAL_BRIEFING,
       "anyrun_submit has a briefing exemption so the two-step gate's first step is possible")
    # RULE 3 parity: the exemption is DATA (tool_policy.json) and the embedded fallback is OFF —
    # a module silently on its fallback keeps the tool fully gated rather than opening a branch.
    ok(bool(audit.APPROVAL_BRIEFING) and not audit._POLICY_FALLBACK["approval_briefing"],
       "briefing exemption came from JSON; the fallback is OFF (fail-closed)")
    prior = os.environ.get(env or "X")
    try:
        os.environ.pop(env, None)
        # the offline briefing branch (no confirm, no verify_task) is ALLOWED without approval —
        # otherwise the model can never show the analyst the risks before asking
        ok(allows("anyrun_submit", {"target": "http://x.example"}),
           "the briefing call (confirm/verify_task falsy) is allowed without approval")
        # the confirmed POST is the real, irreversible action — DENIED without approval
        ok(not allows("anyrun_submit", {"target": "http://x.example", "confirm": True}),
           "a CONFIRMED submit is DENIED without explicit approval (outbound + irreversible)")
        # the follow-up read-back can DELETE a task — also gated
        ok(not allows("anyrun_submit", {"target": "uuid", "verify_task": True}),
           "a verify_task read-back (delete-capable) is DENIED without approval")
        os.environ[env] = "1"
        ok(allows("anyrun_submit", {"target": "http://x.example", "confirm": True}),
           f"a confirmed submit is allowed once {env}=1")
        os.environ[env] = "0"
        ok(not allows("anyrun_submit", {"target": "http://x.example", "confirm": True}),
           f"{env}=0 does not count as approval")
        # the exemption is EXACT: a truthy string on an exempt arg is still the gated action
        ok(not allows("anyrun_submit", {"target": "x", "confirm": "yes"}),
           "confirm='yes' (truthy) is the gated action, not the briefing")
    finally:
        os.environ.pop(env, None)
        if prior is not None:
            os.environ[env] = prior

    # --- 2b. the exemption fails CLOSED: with no exemption data an approval tool stays fully gated
    _saved_brief = audit.APPROVAL_BRIEFING
    try:
        audit.APPROVAL_BRIEFING = {}                     # the conservative-minimum fallback shape
        os.environ.pop(env, None)
        ok(not allows("anyrun_submit", {"target": "http://x.example"}),
           "with no briefing exemption (unreadable data file) even the briefing is denied — safe-closed")
    finally:
        audit.APPROVAL_BRIEFING = _saved_brief
        if prior is not None:
            os.environ[env] = prior

    # --- 3. metered budget: the runaway-loop backstop -----------------------------------------
    audit.reset()
    ok(allows("pivot_extract", {"url": "http://x.example"}), "metered call allowed under budget")
    audit._COUNTS["metered"] = audit.MAX_METERED
    ok(not allows("pivot_extract", {"url": "http://x.example"}),
       "metered call DENIED once the run's credit budget is exhausted")
    ok(allows("pivot_extract", {"url": "http://x.example", "free_only": True}),
       "free_only=true still allowed over budget (keyless work never stops)")
    ok("metered" not in audit.classify("pivot_extract", {"url": "u", "free_only": True}),
       "free_only=true is not counted as metered spend")
    # passive protects your IP, not your credits — it must NOT buy free metered calls.
    ok("metered" in audit.classify("pivot_extract", {"url": "u", "passive": True}),
       "passive=true is still METERED (it hides your IP, not your spend)")
    audit.reset()

    # --- 4. name resolution: one policy entry covers every front-end's naming ------------------
    ok(audit.bare("mcp__collect__pivot_extract") == "pivot_extract",
       "fully-qualified SDK tool name reduces to the bare policy key")
    ok(audit.decide("mcp__collect__pivot_extract", {"url": "u"}, hostile=True)[0] is False
       and audit.decide("pivot_extract", {"url": "u"}, hostile=True)[0] is False,
       "SDK and MCP naming reach the SAME decision")

    # --- 5. the ledger: every call recorded, no credential written -----------------------------
    tmp = tempfile.mkdtemp()
    real_root = audit.ROOT
    try:
        audit.ROOT = tmp
        audit.reset()
        audit.gate("mcp__collect__pivot_extract", {"url": "http://a.example"},
                   case="C", phase="collect", backend="claude")
        audit.gate("pivot_extract", {"url": "http://b.example", "token": "SECRET-VALUE",
                                     "blob": "x" * 900},
                   case="C", phase="collect", hostile=True)
        audit.gate("kb_ingest", {"case": "C"}, case="C", phase="collect")
        raw = open(os.path.join(tmp, "cases", "C", "tool_calls.jsonl"), encoding="utf-8").read()
        recs = [json.loads(l) for l in raw.splitlines() if l.strip()]
        ok(len(recs) == 3, f"every call is on the ledger, allowed and denied ({len(recs)}/3)")
        ok([r["decision"] for r in recs] == ["allow", "DENY", "allow"],
           "the ledger records the DECISION, not just the attempt")
        ok("SECRET-VALUE" not in raw, "a credential-shaped argument is never written to disk")
        ok(recs[1]["args"]["token"] == "<redacted>", "redacted arguments are marked, not dropped")
        ok(len(recs[1]["args"]["blob"]) < 400, "a long argument is truncated, not stored whole")
        ok(recs[0]["classes"] == ["outbound", "metered"] and recs[2]["classes"] == ["mutating"],
           "each call carries its risk classes (why it mattered)")
        ok(all(r.get("phase") and r.get("case") == "C" for r in recs),
           "each call is attributed to its case and phase")
        # No case in scope (interactive Claude Code) -> the repo-level ledger, never a crash.
        audit.gate("kb_cluster", {"domain": "x.example"})
        ok(os.path.exists(os.path.join(tmp, "MEMORY", "tool_calls.jsonl")),
           "a call with no case still lands in MEMORY/tool_calls.jsonl")
        c = audit.counts()
        ok(c["total"] == 4 and c["denied"] == 1 and c["metered"] == 1,
           f"counters: only calls that RAN can spend ({c['total']} total, {c['metered']} metered)")
        ok("DENIED" in audit.summary("C"), "the run banner reports denials")

        # An unwritable ledger must warn, not kill a case mid-round.
        audit.ROOT = os.path.join(tmp, "nope")
        os.makedirs(audit.ROOT)
        os.chmod(audit.ROOT, 0o500)
        err = io.StringIO()
        try:
            import contextlib
            with contextlib.redirect_stderr(err):
                audit.record._warned = False           # type: ignore[attr-defined]
                audit.gate("kb_cluster", {"domain": "x.example"}, case="C2")
            ok("WARNING" in err.getvalue(),
               "an unwritable ledger WARNS (never silent, never fatal)")
        finally:
            os.chmod(audit.ROOT, 0o700)
    finally:
        audit.ROOT = real_root
        audit.reset()
        shutil.rmtree(tmp, ignore_errors=True)

    # --- 6. SDK path: the PreToolUse hook payload ---------------------------------------------
    import orchestrator as o
    cb = o._gate_hook("C", "collect", True)
    deny = asyncio.run(cb({"hook_event_name": "PreToolUse",
                           "tool_name": "mcp__collect__pivot_extract",
                           "tool_input": {"url": "http://x.example"}, "tool_use_id": "t1"},
                          "t1", None))
    spec = (deny or {}).get("hookSpecificOutput", {})
    ok(spec.get("permissionDecision") == "deny", "hook DENIES a hostile live fetch")
    ok(spec.get("hookEventName") == "PreToolUse", "hook payload names its event (wire contract)")
    ok(len(spec.get("permissionDecisionReason", "")) > 40,
       "the denial tells the MODEL how to adapt, so the run continues rather than dying")
    allow = asyncio.run(cb({"hook_event_name": "PreToolUse", "tool_name": "mcp__analyze__kb_cluster",
                            "tool_input": {"domain": "x.example"}, "tool_use_id": "t2"},
                           "t2", None))
    ok(allow == {}, "hook returns {} for a permitted call (falls through, decides nothing)")

    # Concurrency: phases run in parallel, so two closures must not share state.
    a, b = o._gate_hook("CASE-A", "collect:a", False), o._gate_hook("CASE-B", "collect:b", True)
    ok(asyncio.run(a({"tool_name": "pivot_extract", "tool_input": {"url": "u"}}, "x", None)) == {}
       and asyncio.run(b({"tool_name": "pivot_extract", "tool_input": {"url": "u"}},
                         "y", None)).get("hookSpecificOutput", {}).get("permissionDecision")
       == "deny",
       "concurrent phases keep their OWN posture (closure, not shared global)")
    shutil.rmtree(os.path.join(ROOT, "cases", "CASE-A"), ignore_errors=True)
    shutil.rmtree(os.path.join(ROOT, "cases", "CASE-B"), ignore_errors=True)
    shutil.rmtree(os.path.join(ROOT, "cases", "C"), ignore_errors=True)

    # --- 7. the hook is not shadowed by our own configuration ---------------------------------
    # The failure this catches is invisible at runtime: a gate that is wired but never consulted.
    from sdk_compat import BACKEND, ClaudeAgentOptions, HookMatcher
    if BACKEND == "claude":
        try:
            from claude_agent_sdk import CanUseToolShadowedWarning
            with warnings.catch_warnings():
                warnings.simplefilter("error", CanUseToolShadowedWarning)
                opts = ClaudeAgentOptions(
                    system_prompt="x", tools=[], allowed_tools=["mcp__collect__pivot_extract"],
                    permission_mode="bypassPermissions",
                    hooks={"PreToolUse": [HookMatcher(hooks=[cb])]})
            ok(opts.can_use_tool is None,
               "the harness gates via PreToolUse, not the shadowed can_use_tool")
            ok("PreToolUse" in (opts.hooks or {}), "the SDK accepts the PreToolUse gate config")
        except ImportError:
            ok(True, "SDK too old for CanUseToolShadowedWarning — shadow check skipped")
    else:
        ok(True, f"shadow check skipped (HARNESS_BACKEND={BACKEND})")

    # --- 8. DeepSeek/OpenAI shim: the handler must NOT run --------------------------------------
    ok(_shim_blocks(), "OpenAI/DeepSeek shim: a denied tool's handler never executes")

    # --- 9. the analyst hand-back: cold vs awaiting-analyst -------------------------------------
    # The distinction is the whole point — 'stopping is the finding' must not be reported for a run
    # that merely ran out of permission to continue, and 'continue' must not be offered when there
    # is nothing to continue with.
    ok(o._STOP_STATUS["converged"] == "converged"
       and o._STOP_STATUS["no-frontier"] == "cold"
       and o._STOP_STATUS["round-cap"] == "awaiting-analyst"
       and o._STOP_STATUS["failed"] == "error",
       "stop reasons map onto the state.json vocabulary the deterministic loop already uses")
    real_discover = o._discover_new_seeds
    case = "_GATE_TEST_HANDBACK"
    cdir = os.path.join(ROOT, "cases", case)
    try:
        os.makedirs(os.path.join(cdir, "raw"), exist_ok=True)
        o._discover_new_seeds = lambda c, k, max_new=None: ["peer-a.example", "peer-b.example"]
        o._hand_back(case, "round-cap", rounds=1, seeds=["site-a.example"], depth=1)
        st = json.load(open(os.path.join(cdir, "state.json"), encoding="utf-8"))
        ok(st["status"] == "awaiting-analyst",
           "a depth-1 run WITH frontier left hands back as awaiting-analyst (asks to continue)")
        ok(st["pending"] == ["peer-a.example", "peer-b.example"],
           "the pending frontier is persisted, so the next run resumes it")
        o._discover_new_seeds = lambda c, k, max_new=None: []
        o._hand_back(case, "round-cap", rounds=1, seeds=["site-a.example"], depth=1)
        st = json.load(open(os.path.join(cdir, "state.json"), encoding="utf-8"))
        ok(st["status"] == "cold",
           "the SAME stop reason with NO frontier left hands back as cold, not awaiting-analyst")

        # A frontier probe that THREW must never be reported as an empty frontier: 'cold' means
        # "the free search is exhausted", which is a finding, not a default.
        def _boom(*_a, **_kw):
            raise RuntimeError("kb query unavailable")

        o._discover_new_seeds = _boom
        o._hand_back(case, "round-cap", rounds=1, seeds=["site-a.example"], depth=1)
        st = json.load(open(os.path.join(cdir, "state.json"), encoding="utf-8"))
        ok(st["status"] == "awaiting-analyst",
           "a FAILED frontier probe hands back as awaiting-analyst, never as cold")
        o._hand_back(case, "converged", rounds=4, seeds=["site-a.example"], depth=4)
        st = json.load(open(os.path.join(cdir, "state.json"), encoding="utf-8"))
        ok(st["status"] == "converged" and len(st["history"]) == 4,
           "convergence is recorded and every hand-back appends to the case history")

        # The state file the SDK writes must be the one the deterministic loop reads.
        sys.path.insert(0, os.path.join(ROOT, "tools"))
        import case_state as cs
        loaded = cs.load_state(case)
        ok(loaded["status"] == "converged" and loaded["case"] == case,
           "case_state.load_state reads the SDK's hand-back (ONE state file, both drivers)")
        cs.reopen(case, ["new-seed.example"])
        ok(cs.load_state(case)["status"] == "expanding",
           "case_state.reopen can revive an SDK-finished case")
    finally:
        o._discover_new_seeds = real_discover
        shutil.rmtree(cdir, ignore_errors=True)

    # --- 10. reading the ledger back ------------------------------------------------------------
    # An audit trail nobody can read is theatre. The reader is also where an ABSENT ledger must be
    # reported as absence of record rather than as "the run did nothing" — the same discipline as
    # the keyless-capability banner, and the same failure if it slips.
    tmp = tempfile.mkdtemp()
    real_root = audit.ROOT
    try:
        audit.ROOT = tmp
        audit.reset()
        miss = audit.report("NOPE")
        ok("ABSENCE OF RECORD" in miss and "not evidence of no activity" in miss,
           "a missing ledger reads as ABSENCE OF RECORD, never as zero activity")
        ok("cases/NOPE/tool_calls.jsonl" in miss.replace(os.sep, "/"),
           "the missing-ledger message names where it looked")

        audit.gate("mcp__collect__pivot_extract", {"url": "http://a.example"},
                   case="C", phase="collect")
        audit.gate("mcp__collect__pivot_extract", {"url": "http://b.example", "free_only": True},
                   case="C", phase="collect")
        audit.gate("kb_ingest", {"case": "C"}, case="C", phase="collect")
        audit.gate("pivot_extract", {"url": "http://h.example"}, case="C", phase="collect:b",
                   hostile=True)
        audit.gate("mcp__analyze__kb_cluster", {"domain": "a.example"}, case="C", phase="correlate")

        rep = audit.report("C")
        ok("5 call(s): 4 allowed, 1 DENIED" in rep, "the report counts allowed and denied calls")
        ok("outbound" in rep and "mutating" in rep, "the report tallies risk classes")
        ok("(1 DENIED)" in rep, "the report attributes denials to the tool that attempted them")
        ok("BLOCKED by egress policy" in rep,
           "the report shows WHY each denial happened, not just that it did")
        ok("correlate" in rep and "collect:b" in rep, "the report breaks calls down by phase")

        d = audit.report("C", denied_only=True)
        ok("1 call(s): 0 allowed, 1 DENIED" in d, "denied=true filters to blocked calls only")
        t = audit.report("C", tool="mcp__collect__pivot_extract")
        ok("3 call(s)" in t,
           "tool= filters on the BARE name, so it matches both naming conventions")
        ok("no calls match that filter" in audit.report("C", tool="nonexistent_tool"),
           "an empty filter result is distinguished from an absent ledger")

        # A ledger torn by a kill mid-write must stay readable up to the tear.
        with open(os.path.join(tmp, "cases", "C", "tool_calls.jsonl"), "a", encoding="utf-8") as fh:
            fh.write('{"ts": "2026-01-01T00:00:00Z", "tool": "trunc')
        recs, _ = audit.read_ledger("C")
        ok(len(recs) == 5, "a half-written trailing line is skipped, not fatal")
    finally:
        audit.ROOT = real_root
        audit.reset()
        shutil.rmtree(tmp, ignore_errors=True)

    # RULE 2: a capability reachable only as a bash line is not registered. Assert the reader is
    # a real @tool and is in the judgment phase's allowlist, beside api_usage.
    try:
        import tools as harness_tools
        names = {v.name for v in vars(harness_tools).values() if hasattr(v, "handler")}
        ok("tool_calls" in names, "the ledger reader is registered as an @tool (RULE 2)")
        ok("mcp__analyze__tool_calls" in harness_tools.ANALYZE_TOOLS,
           "the judgment phase can read the ledger, as it can read api_usage")
    except Exception as e:  # noqa: BLE001 — tools.py needs the WebPivot venv; don't fail elsewhere
        ok(True, f"@tool registration check skipped (tools.py unimportable here: {e})")

    return passed, failed, out


def _shim_blocks():
    """Drive the OpenAI-compat shim's tool loop with a stubbed HTTP layer and a tool whose handler
    records that it ran. Returns True only if the gate stopped it BEFORE execution — the shim has
    no CLI to run hooks, so this is the only place that failure would show up."""
    import audit
    import openai_backend as ob

    ran = {"handler": False}

    async def handler(_args):
        ran["handler"] = True
        return {"content": [{"type": "text", "text": "live fetch happened"}]}

    server = ob.create_sdk_mcp_server(
        "collect", [ob.SdkMcpTool("pivot_extract", "collect", {"url": str}, handler)])

    state = {"turn": 0}
    real_post = ob._http_post_retry

    def fake_post(payload, timeout, tries=3):
        state["turn"] += 1
        if state["turn"] == 1:
            return {"choices": [{"message": {"content": None, "tool_calls": [{
                "id": "t1", "type": "function",
                "function": {"name": "mcp__collect__pivot_extract",
                             "arguments": '{"url": "http://hostile.example"}'}}]}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1}}
        state["tool_msgs"] = [m for m in payload["messages"] if m.get("role") == "tool"]
        return {"choices": [{"message": {"content": "done"}}], "usage": {}}

    tmp = tempfile.mkdtemp()
    real_root = audit.ROOT
    try:
        ob._http_post_retry = fake_post
        audit.ROOT = tmp

        async def run():
            audit.set_context(case="_SHIM", phase="collect", hostile=True, backend="openai")
            opts = ob.ClaudeAgentOptions(mcp_servers={"collect": server},
                                         allowed_tools=["mcp__collect__pivot_extract"], max_turns=3)
            async for _ in ob.query(prompt="collect", options=opts):
                pass

        asyncio.run(run())
        told = (state.get("tool_msgs") or [{}])[0].get("content", "")
        return not ran["handler"] and "BLOCKED by harness policy" in told
    finally:
        ob._http_post_retry = real_post
        audit.ROOT = real_root
        audit.reset()
        shutil.rmtree(tmp, ignore_errors=True)


_PASSED, _FAILED, _LINES = check()


def test_tool_gate():
    """pytest entry point — the module body does the work at import time."""
    assert not _FAILED, [l for s, l in _LINES if s != "ok"]


if __name__ == "__main__":
    for status, label in _LINES:
        print(f"{'  ok  ' if status == 'ok' else '  FAIL'} {label}")
    print()
    if _FAILED:
        print(f"FAIL — {_FAILED} tool-gate check(s) failed")
        sys.exit(1)
    print(f"PASS — tool-call gate green ({_PASSED} checks: hostile egress blocked above the "
          f"tools, submission needs approval, credit budget enforced, every call on the ledger, "
          f"all three front-ends gated, hand-back distinguishes cold from awaiting-analyst)")
