#!/usr/bin/env python3
"""
test_openai_backend.py — the gate on the OpenAI-compatible backend (Kimi / DeepSeek / local).

Run:  python3 tests/test_openai_backend.py
      python3 tools/eval/run_eval.py     (runs as part of the regression gate)

WHY THIS EXISTS
---------------
`harness/openai_backend.py` is what lets the SAME orchestrator run on Moonshot/Kimi, DeepSeek or a
local vLLM/Ollama server instead of Anthropic. It is also the least-exercised path in the repo: no
one notices it has rotted until the day they point the harness at a local model, and by then the
failure looks like the MODEL being bad rather than the shim being broken.

So the whole tool loop is driven here against a STUBBED `/chat/completions` — no network, no key,
no provider. The stub returns a canned tool call, then a canned final answer, exactly as a real
endpoint would, which exercises: tool-spec construction, the fully-qualified mcp__server__tool
naming, argument parsing, the audit gate, tool-result insertion, and the ResultMessage contract
the orchestrator depends on.

The assertions that matter most for an open-weight target:
  * OPTIONAL PARAMS reach the schema. A mid-size model will not infer `passive=true` from a
    description paragraph; if it cannot SEE the parameter it never sends it, the gate denies the
    call on hostile infra, and the run burns turns. This is the difference between "the model is
    too weak" and "we never told it the argument exists".
  * `enum` reaches the schema, so a model cannot invent a seventh value for a six-value `mode`.
  * A denied tool call comes back as tool OUTPUT, not an exception — the model must be able to
    adapt rather than the run dying.
  * The structured-output path (forced emit_result) produces a valid Assessment, because that is
    the one place the harness cannot degrade gracefully.
"""
import asyncio
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "WebPivot", "tools"))
sys.path.insert(0, os.path.join(ROOT, "harness"))

import openai_backend as OB  # noqa: E402
import tools as T            # noqa: E402


def _shim_server(name, allowlist):
    """Build a SHIM-NATIVE server from the same tool objects.

    The eval gate imports this module without HARNESS_BACKEND set, so `tools.py` resolves to the
    real Anthropic SDK and T.COLLECT_SERVER is an SDK object the shim cannot read. The tool
    objects themselves are duck-typed (.name/.description/.input_schema/.handler) regardless of
    which decorator produced them, so re-wrapping them here exercises the shim identically under
    either backend — which is the point: this test must run in the normal gate, not only when
    someone remembers to set an env var."""
    want = {a.split("__")[-1] for a in allowlist}
    objs = [v for v in vars(T).values()
            if hasattr(v, "name") and hasattr(v, "handler") and hasattr(v, "input_schema")
            and v.name in want]
    return OB.create_sdk_mcp_server(name, tools=objs)


def _completion(tool_calls=None, content=""):
    """One canned /chat/completions response, shaped exactly as a real provider returns it."""
    msg = {"role": "assistant", "content": content}
    if tool_calls:
        msg["tool_calls"] = tool_calls
    return {"choices": [{"message": msg}], "usage": {"prompt_tokens": 10, "completion_tokens": 5}}


def _call(name, args, cid="c1"):
    return [{"id": cid, "type": "function",
             "function": {"name": name, "arguments": json.dumps(args)}}]


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

    # --- 1. the tool schema an open-weight model actually receives ---------------------------
    collect = _shim_server("collect", T.COLLECT_TOOLS)
    opts = OB.ClaudeAgentOptions(system_prompt="sys", mcp_servers={"collect": collect},
                                 allowed_tools=T.COLLECT_TOOLS)
    reg, specs = OB._resolve_tools(opts)
    ok(len(reg) == len(T.COLLECT_TOOLS),
       f"every allowlisted collect tool is wired to the shim ({len(reg)}/{len(T.COLLECT_TOOLS)})")
    ok(all(n.startswith("mcp__collect__") for n in reg),
       "tools carry the fully-qualified mcp__server__tool name the SDK path uses")

    pe = next(s for s in specs if s["function"]["name"].endswith("pivot_extract"))
    props = pe["function"]["parameters"]["properties"]
    req = pe["function"]["parameters"]["required"]
    ok("passive" in props and props["passive"]["type"] == "boolean",
       "pivot_extract DECLARES passive — a weak model cannot infer it from prose")
    ok("proxy" in props and "free" not in props.get("proxy", {}).get("type", ""),
       "pivot_extract declares proxy as a typed parameter")
    ok(props.get("passive", {}).get("description", "").strip() != "",
       "each optional param carries a one-line instruction, not just a type")
    ok("passive" not in req and "url" in req,
       "optional params are NOT marked required — only the declared ones are")

    cen = next(s for s in specs if s["function"]["name"].endswith("censys"))
    mode = cen["function"]["parameters"]["properties"].get("mode", {})
    ok(mode.get("enum") and "budget" in mode["enum"],
       f"censys.mode carries an enum so a model cannot invent a value ({mode.get('enum')})")

    ax = next(s for s in specs if s["function"]["name"].endswith("anyrun_submit"))
    ok("confirm" in ax["function"]["parameters"]["properties"],
       "anyrun_submit declares `confirm` — the per-submission approval must be reachable")

    ok(all(s["function"]["parameters"].get("additionalProperties") is True for s in specs),
       "additionalProperties stays true, so an undeclared arg still passes through")

    # --- 2. the tool loop, end to end, against a stubbed endpoint ----------------------------
    async def drive(responses, options, prompt="go"):
        """Run query() with _http_post_retry stubbed to return `responses` in order."""
        seen = []
        it = iter(responses)

        def fake(payload, timeout, tries=3):
            seen.append(payload)
            return next(it)

        real, OB._http_post_retry = OB._http_post_retry, fake
        try:
            msgs = [m async for m in OB.query(prompt=prompt, options=options)]
        finally:
            OB._http_post_retry = real
        return msgs, seen

    o = OB.ClaudeAgentOptions(system_prompt="sys", mcp_servers={"collect": collect},
                              allowed_tools=T.COLLECT_TOOLS, max_turns=5)
    msgs, seen = asyncio.run(drive([
        _completion(_call("mcp__collect__capability_check", {"free_only": True})),
        _completion(content="done"),
    ], o))

    result = [m for m in msgs if isinstance(m, OB.ResultMessage)]
    ok(len(result) == 1, "the loop yields exactly one ResultMessage (the orchestrator's contract)")
    ok(getattr(result[0], "subtype", "") == "success",
       f"a clean run reports subtype=success (got {getattr(result[0], 'subtype', None)})")
    ok(any(isinstance(m, OB.AssistantMessage) for m in msgs),
       "each tool-using turn is surfaced as an AssistantMessage for the live worklog")
    ok(len(seen) == 2, f"the loop made one follow-up request after the tool result ({len(seen)})")
    ok(any(m.get("role") == "tool" for m in seen[-1]["messages"]),
       "the tool RESULT was fed back into the next request")
    ok(seen[0]["messages"][0]["role"] == "system",
       "the phase system prompt (the SKILL body) leads the request")
    ok(any(t["function"]["name"].endswith("capability_check") for t in seen[0]["tools"]),
       "tool specs are sent with the request")

    # --- 3. a DENIED call must reach the model as output, not kill the run -------------------
    o2 = OB.ClaudeAgentOptions(system_prompt="sys", mcp_servers={"collect": collect},
                               allowed_tools=T.COLLECT_TOOLS, max_turns=5)
    # NOTE: the shim resolves hostile posture from `audit`'s OWN context var, not tools.POLICY.
    # orchestrator._phase sets BOTH per phase; anything driving this backend directly must call
    # audit.set_context() or the egress gate silently runs permissive.
    import audit  # noqa: E402
    prev = T.POLICY.get("hostile")
    T.POLICY["hostile"] = True
    audit.set_context(hostile=True)
    try:
        msgs, seen = asyncio.run(drive([
            _completion(_call("mcp__collect__pivot_extract",
                              {"url": "site-a.example", "case": "CASE-0001"})),
            _completion(content="adapting"),
        ], o2))
    finally:
        T.POLICY["hostile"] = prev
        audit.set_context(hostile=False)
    tool_msgs = [m for m in seen[-1]["messages"] if m.get("role") == "tool"]
    ok(tool_msgs and "BLOCKED by harness policy" in tool_msgs[0]["content"],
       "a hostile-egress denial comes back as TOOL OUTPUT so the model can adapt")
    ok(any(isinstance(m, OB.ResultMessage) for m in msgs),
       "…and the run continues to a ResultMessage instead of raising")

    # --- 4. an unknown tool is reported, not raised ------------------------------------------
    o3 = OB.ClaudeAgentOptions(system_prompt="sys", mcp_servers={"collect": collect},
                               allowed_tools=T.COLLECT_TOOLS, max_turns=5)
    msgs, seen = asyncio.run(drive([
        _completion(_call("mcp__collect__no_such_tool", {})),
        _completion(content="ok"),
    ], o3))
    tool_msgs = [m for m in seen[-1]["messages"] if m.get("role") == "tool"]
    ok(tool_msgs and "unknown tool" in tool_msgs[0]["content"],
       "an invented tool name is reported back to the model, never raised")

    # --- 5. structured output — the one path that cannot degrade -----------------------------
    from schemas import Assessment  # noqa: E402
    good = {"bluf": "Assessed one operator.", "cluster": [],
            "attribution_level": "same-operator", "confidence": "moderate",
            "evidence": ["shared registrant"], "gaps": [], "next_pivots": []}
    o4 = OB.ClaudeAgentOptions(system_prompt="sys", mcp_servers={}, allowed_tools=[],
                               max_turns=5,
                               output_format={"type": "json_schema",
                                              "schema": Assessment.model_json_schema()})
    msgs, seen = asyncio.run(drive([_completion(_call(OB.EMIT_NAME, good))], o4))
    res = [m for m in msgs if isinstance(m, OB.ResultMessage)][0]
    ok(getattr(res, "subtype", "") == "success", "a schema-forced phase reports success")
    payload = getattr(res, "structured_output", None) or getattr(res, "structured", None)
    ok(payload is not None, "the validated structured result is carried on the ResultMessage")
    if payload:
        ok(Assessment.model_validate(payload).attribution_level == "same-operator",
           "the emitted object validates against the Assessment schema")
    ok(any(t["function"]["name"] == OB.EMIT_NAME for t in seen[0].get("tools", [])),
       "the forced emit_result tool is offered on a schema-forced phase")

    # --- 6. the documented limits are really honoured ----------------------------------------
    o5 = OB.ClaudeAgentOptions(system_prompt="s", mcp_servers={}, allowed_tools=[],
                               hooks={"PreToolUse": ["ignored"]}, effort="high", max_turns=3)
    ok(o5.hooks and o5.effort == "high",
       "hooks/effort are ACCEPTED (then ignored) so orchestrator.py needs no branch")
    ok(OB._cost("definitely-not-a-real-model", 1000, 1000) is None,
       "an unknown/local model reports cost as n/a rather than inventing a price")
    ok(isinstance(OB._model_for("opus"), str) and OB._model_for("opus"),
       "every harness tier maps to a concrete model id")

    return passed, failed, out


def main():
    passed, failed, lines = check()
    for status, label in lines:
        print(f"  {'ok  ' if status == 'ok' else 'FAIL'} {label}")
    print(f"\n{'PASS' if not failed else 'FAIL'} — {passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
