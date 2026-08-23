#!/usr/bin/env python3
"""
smoke_backend.py — will this OpenAI-compatible endpoint actually run the harness?

The shim (openai_backend.py) lets the SAME orchestrator run on Moonshot/Kimi, DeepSeek or a local
vLLM / SGLang / Ollama / LM Studio server. Whether a given endpoint can really drive a case is NOT
answered by "does it reply" — it is answered by four capabilities, and when one is missing the
symptom is indirect enough to be misread as "the model is bad":

  1. CHAT           — reachable, authenticated, returns a completion.
  2. TOOL CALLING   — emits a `tool_calls` message against our fully-qualified mcp__server__tool
                      names. Without this the harness cannot collect at all. Many local builds
                      advertise tool support that their template does not actually emit.
  3. OPTIONAL ARGS  — sends `passive=true` when the task requires it. This is the one that fails
                      quietly: the model calls the right tool with incomplete arguments, the
                      egress gate correctly DENIES it, and the run burns turns looping. It is why
                      references/tool_params.json declares those arguments as real schema.
  4. STRUCTURED OUT — produces a valid Assessment through the forced `emit_result` tool. The
                      Assess phase cannot degrade gracefully without it.

It also reports CONTEXT HEADROOM, because the harness has a fixed floor before it reads any
evidence: each phase pins a SKILL.md as its system prompt (WebPivot ~12.5k tok, IntelAnalysis
~16.8k tok) and ships 16-21 tool schemas. On a 32k-context model that floor is most of the window,
and Ollama in particular defaults `num_ctx` to 4096 and SILENTLY TRUNCATES rather than erroring —
which looks like a model that ignores its instructions.

This SPENDS TOKENS on whatever endpoint you point it at (four small calls). It never touches a
target, never spends third-party OSINT credits, and never writes to a case.

USAGE
  # Moonshot / Kimi
  export OPENAI_BASE_URL=https://api.moonshot.cn/v1
  export MOONSHOT_API_KEY=...
  python3 harness/smoke_backend.py --model kimi-k2-0905-preview

  # a local server (Ollama shown; vLLM/LM Studio are the same shape)
  export OPENAI_BASE_URL=http://localhost:11434/v1
  python3 harness/smoke_backend.py --model qwen3:32b

Exit code 0 = the harness will run on this endpoint; 1 = a required capability is missing.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "WebPivot", "tools"))
os.environ.setdefault("HARNESS_BACKEND", "local")   # force the shim, whatever else is configured

import openai_backend as OB  # noqa: E402
import tools as T            # noqa: E402
from schemas import Assessment  # noqa: E402

GREEN, RED, YELLOW, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[0m"


def _line(state: str, label: str, detail: str = "") -> None:
    mark = {"ok": f"{GREEN}✔{RESET}", "fail": f"{RED}✗{RESET}", "warn": f"{YELLOW}!{RESET}"}[state]
    print(f"  {mark} {label}" + (f"\n      {detail}" if detail else ""))


async def _run(prompt: str, *, model: str, tools_on: bool, schema=None, turns: int = 3):
    opts = OB.ClaudeAgentOptions(
        system_prompt="You are a collection agent. Use the provided tools. Be terse.",
        mcp_servers={"collect": T.COLLECT_SERVER} if tools_on else {},
        allowed_tools=T.COLLECT_TOOLS if tools_on else [],
        max_turns=turns, model=model,
        output_format=({"type": "json_schema", "schema": schema} if schema else None))
    calls, result = [], None
    async for m in OB.query(prompt=prompt, options=opts):
        if isinstance(m, OB.AssistantMessage):
            for b in m.content:
                if isinstance(b, OB.ToolUseBlock):
                    calls.append((b.name, b.input))
        elif isinstance(m, OB.ResultMessage):
            result = m
    return calls, result


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", required=True, help="concrete model id at the endpoint")
    ap.add_argument("--context", type=int, default=0,
                    help="the model's context window in TOKENS, to check headroom against")
    a = ap.parse_args()

    print(f"\nendpoint : {OB._base_url()}")
    print(f"model    : {a.model}")
    print(f"api key  : {'set' if OB._api_key() else 'NONE (fine for a keyless local server)'}\n")

    failures = 0

    # -- 1. chat -----------------------------------------------------------------------------
    try:
        _, res = asyncio.run(_run("Reply with the single word: ready.",
                                  model=a.model, tools_on=False, turns=1))
        text = (getattr(res, "result", "") or "").strip()
        if res is None or getattr(res, "subtype", "") == "error":
            _line("fail", "CHAT", f"endpoint returned an error: {text[:300]}")
            failures += 1
            print("\nStopping — nothing else can be tested without a working completion.")
            return 1
        _line("ok", "CHAT", f"replied: {text[:80]!r}")
    except Exception as e:  # noqa: BLE001
        _line("fail", "CHAT", f"{type(e).__name__}: {e}")
        print("\nStopping — check OPENAI_BASE_URL and the API key.")
        return 1

    # -- 2. tool calling ---------------------------------------------------------------------
    calls, res = asyncio.run(_run(
        "Check what collection capability this run has when spending no API credits. "
        "Call exactly one tool, then stop.", model=a.model, tools_on=True, turns=2))
    if calls:
        _line("ok", "TOOL CALLING", f"called {calls[0][0]} with {json.dumps(calls[0][1])[:120]}")
    else:
        _line("fail", "TOOL CALLING",
              "the model returned prose instead of a tool_calls message. The harness cannot "
              "collect on this endpoint. Check the server's tool/function-calling template.")
        failures += 1

    # -- 3. optional arguments (the quiet failure) -------------------------------------------
    calls, res = asyncio.run(_run(
        "The target site-a.example is HOSTILE infrastructure — we must not touch it from our own "
        "IP. Collect it into case CASE-0001 without any direct fetch. Call exactly one tool.",
        model=a.model, tools_on=True, turns=2))
    pe = [(n, i) for n, i in calls if n.endswith("pivot_extract")]
    if not pe:
        _line("warn", "OPTIONAL ARGS", "did not reach pivot_extract; cannot judge this capability")
    elif pe[0][1].get("passive") or pe[0][1].get("proxy"):
        _line("ok", "OPTIONAL ARGS", f"passed {json.dumps(pe[0][1])[:140]}")
    else:
        _line("fail", "OPTIONAL ARGS",
              f"called pivot_extract WITHOUT passive/proxy: {json.dumps(pe[0][1])[:140]}\n"
              "      On a real hostile run the egress gate denies this and the run loops. The "
              "model can see the parameter (it is declared in the schema), so this endpoint "
              "needs a stronger model for the collect phase.")
        failures += 1

    # -- 4. structured output ----------------------------------------------------------------
    _, res = asyncio.run(_run(
        "Two domains share one registrant email. Produce the final assessment now.",
        model=a.model, tools_on=False, schema=Assessment.model_json_schema(), turns=3))
    payload = getattr(res, "structured_output", None) or getattr(res, "structured", None)
    if payload:
        try:
            Assessment.model_validate(payload)
            _line("ok", "STRUCTURED OUT", f"valid Assessment ({payload.get('attribution_level')})")
        except Exception as e:  # noqa: BLE001
            _line("fail", "STRUCTURED OUT", f"emitted an object that failed validation: {e}")
            failures += 1
    else:
        _line("fail", "STRUCTURED OUT",
              "never called emit_result. The Assess phase will fail on this endpoint; raise "
              "HARNESS_STRUCT_RETRIES or use a stronger model for judgment.")
        failures += 1

    # -- 5. context headroom ------------------------------------------------------------------
    floors = {}
    for skill, srv in (("WebPivot", T.COLLECT_SERVER), ("IntelAnalysis", T.ANALYZE_SERVER)):
        body = os.path.join(ROOT, skill, "SKILL.md")
        sys_tok = (os.path.getsize(body) // 4) if os.path.exists(body) else 0
        specs = json.dumps([{"name": t.name, "description": t.description,
                             "parameters": OB._params_schema(t.input_schema,
                                                             getattr(t, "optional_schema", None))}
                            for t in getattr(srv, "tools", [])])
        floors[skill] = sys_tok + len(specs) // 4
    print()
    for skill, tok in floors.items():
        print(f"  · {skill} phase floor: ~{tok:,} tok (system prompt + tool schemas, "
              f"before any evidence)")
    worst = max(floors.values())
    if a.context:
        head = a.context - worst
        state = "ok" if head > 40000 else ("warn" if head > 12000 else "fail")
        _line(state, f"CONTEXT HEADROOM  {a.context:,} tok window",
              f"~{head:,} tok left for evidence after the worst phase floor."
              + ("" if state == "ok" else
                 "  Lower HARNESS_RESULT_CHARS and HARNESS_TRANSCRIPT_CHARS, or use a larger window."))
        if state == "fail":
            failures += 1
    else:
        print(f"  · pass --context <tokens> to check headroom against this model's window.")
        print(f"    Ollama note: num_ctx defaults to 4096 and TRUNCATES SILENTLY — set it "
              f"explicitly to at least {worst + 40000:,}.")

    print()
    if failures:
        print(f"{RED}NOT READY{RESET} — {failures} required capability/ies missing above.\n")
        return 1
    print(f"{GREEN}READY{RESET} — this endpoint can drive the harness.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
