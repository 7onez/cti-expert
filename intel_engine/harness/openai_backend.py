"""openai_backend.py — an OpenAI-compatible drop-in for the slice of `claude_agent_sdk`
the harness actually uses, so the SAME orchestrator can run on DeepSeek / Kimi(Moonshot) /
any local OpenAI-compatible server (Ollama, vLLM, LM Studio) instead of Anthropic.

WHY A SHIM (not a fork)
  orchestrator.py / tools.py / agents.py import a small, fixed set of names from the SDK:
      query, ClaudeAgentOptions, ResultMessage, AssistantMessage, ToolUseBlock,
      AgentDefinition, ToolAnnotations, create_sdk_mcp_server, tool
  This module re-implements exactly those against a `/chat/completions` endpoint. The 700-line
  orchestrator (convergence loop, clustering, cascade, deliverables) is untouched — sdk_compat.py
  picks this module over the real SDK when HARNESS_BACKEND is openai/deepseek/kimi/local.

  Because tools.py's `@tool`/`create_sdk_mcp_server` also resolve here, the stdio MCP server
  (mcp_server.py, which duck-types on .name/.handler/.input_schema) keeps working with NO
  Anthropic SDK installed at all.

CONFIG (env)
  HARNESS_BACKEND      openai|deepseek|kimi|local  (the switch, read by sdk_compat.py)
  OPENAI_BASE_URL      default https://api.deepseek.com  (Kimi: https://api.moonshot.cn/v1;
                       local: http://localhost:11434/v1 etc.)  "/chat/completions" is appended.
  OPENAI_API_KEY       (or DEEPSEEK_API_KEY / MOONSHOT_API_KEY) — omitted for keyless local servers
  HARNESS_MODEL_MAP    JSON mapping the harness tiers to real model ids, e.g.
                       {"haiku":"deepseek-chat","sonnet":"deepseek-chat","opus":"deepseek-chat"}
  HARNESS_PRICE_MAP    JSON {model: [usd_per_1M_in, usd_per_1M_out]} for the cost ledger
  HARNESS_STRUCT_RETRIES  forced emit_result retries for the schema-forced Assess phase (default 3)

KNOWN LIMITS (documented, not hidden)
  - Structured output is enforced via a forced `emit_result` tool + validate/retry, NOT a native
    strict json_schema. Expect a lower first-pass rate than Claude on the Assess phase.
  - `hooks` (PreToolUse et al.) are ACCEPTED AND IGNORED — there is no CLI process here to run
    them. The tool-call gate is not skipped, though: this module calls `audit.gate()` directly in
    its tool loop, which is the same policy point the SDK path reaches via its PreToolUse hook.
    Same denials, same ledger, one implementation.
  - `effort` has no cross-vendor equivalent — it is accepted and ignored (map capability via the
    model instead).
  - deepseek-reasoner historically does not support function calling; the default map keeps every
    tier on deepseek-chat (tool-capable). Opt into a reasoner only via HARNESS_MODEL_MAP.
  - Cost is an ESTIMATE from token usage × HARNESS_PRICE_MAP; unknown/local models report n/a.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # harness/ — find audit.py
import audit  # noqa: E402  — the shared tool-call gate + ledger (front-end neutral)


# --------------------------------------------------------------------- config
def _base_url() -> str:
    return os.environ.get("OPENAI_BASE_URL", "https://api.deepseek.com").rstrip("/")


def _api_key() -> str:
    return (os.environ.get("OPENAI_API_KEY") or os.environ.get("DEEPSEEK_API_KEY")
            or os.environ.get("MOONSHOT_API_KEY") or "")


# DATA: harness/references/model_pricing.json — tier->model map and per-model prices, so a
# deployment retunes them without a code change (env vars still override per run).
_OB_HERE = os.path.dirname(os.path.abspath(__file__))
_OB_WP = os.path.join(os.path.dirname(_OB_HERE), "WebPivot", "tools")
if _OB_WP not in sys.path:
    sys.path.append(_OB_WP)
try:
    from wp_refs import load_ref as _ob_load_ref
except Exception:                                             # noqa: BLE001 — degrade, never block
    def _ob_load_ref(path, fallback):
        print("[openai_backend] WARNING: wp_refs unavailable; model_pricing.json not read.",
              file=sys.stderr)
        return dict(fallback)
_OB_FALLBACK = {
    "openai_compatible_models": {"deepseek-chat": [0.27, 1.10]},
    "harness_tier_model_map": {"opus": "deepseek-chat"},
}
_OB_REF = _ob_load_ref(os.path.join(_OB_HERE, "references", "model_pricing.json"), _OB_FALLBACK)

# Harness tier -> concrete model; override per deployment with HARNESS_MODEL_MAP.
_DEFAULT_MODEL_MAP = dict(_OB_REF["harness_tier_model_map"])
# USD per 1M tokens (input, output); override with HARNESS_MODEL_PRICE for accuracy.
_DEFAULT_PRICE = {k: tuple(v) for k, v in _OB_REF["openai_compatible_models"].items()}

STRUCT_RETRIES = int(os.environ.get("HARNESS_STRUCT_RETRIES", "3"))
HTTP_TIMEOUT = int(os.environ.get("HARNESS_HTTP_TIMEOUT", "180"))

# CONTEXT BUDGET — harness/references/context_budget.json → transcript_budget.
# Unlike the Anthropic SDK, this shim owns its own message history: it appends one assistant
# message plus one tool message per call, every turn, forever. Without a ceiling a long collect
# grows the request until the provider rejects it — which surfaces as an opaque API error rather
# than "you ran out of room". `_trim_history` below is that ceiling.
_CTX_FALLBACK = {"transcript_budget": {"max_total_chars": 360000,
                                       "max_tool_result_chars": 24000,
                                       "keep_recent_rounds": 6}}
_CTX_REF = _ob_load_ref(os.path.join(_OB_HERE, "references", "context_budget.json"), _CTX_FALLBACK)
_TB = dict(_CTX_REF["transcript_budget"])

TOOL_RESULT_CAP = int(os.environ.get("HARNESS_TOOL_RESULT_CAP")
                      or _TB.get("max_tool_result_chars", 24000))   # chars fed back per tool
TRANSCRIPT_CAP = int(os.environ.get("HARNESS_TRANSCRIPT_CHARS")
                     or _TB.get("max_total_chars", 360000))         # chars of whole history
KEEP_RECENT_ROUNDS = int(_TB.get("keep_recent_rounds", 6))


def _env_json(name: str) -> dict:
    raw = os.environ.get(name)
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except Exception:  # noqa: BLE001
        return {}


def _model_for(tier: Optional[str]) -> str:
    table = {**_DEFAULT_MODEL_MAP, **_env_json("HARNESS_MODEL_MAP")}
    return table.get(tier or "", tier or "deepseek-chat")


def _price_for(model: str) -> Optional[tuple[float, float]]:
    table = dict(_DEFAULT_PRICE)
    for k, v in _env_json("HARNESS_PRICE_MAP").items():
        try:
            table[k] = (float(v[0]), float(v[1]))
        except Exception:  # noqa: BLE001
            pass
    return table.get(model)


def _cost(model: str, tok_in: int, tok_out: int) -> Optional[float]:
    p = _price_for(model)
    if not p:
        return None  # unknown / local -> honest n/a (tokens still logged to stderr)
    return round(tok_in / 1e6 * p[0] + tok_out / 1e6 * p[1], 6)


# ------------------------------------------------------- SDK-compatible surface
class ToolAnnotations:
    """Stand-in for the SDK's ToolAnnotations — stores hints (e.g. readOnlyHint=True) verbatim."""

    def __init__(self, **kw: Any) -> None:
        self.__dict__.update(kw)


class SdkMcpTool:
    """Duck-compatible with the SDK tool object mcp_server.py auto-discovers:
    .name / .description / .input_schema ({param: python_type}) / .handler (async args->result)."""

    def __init__(self, name: str, description: str, input_schema: dict,
                 handler: Callable, annotations: Any = None) -> None:
        self.name = name
        self.description = description
        self.input_schema = input_schema or {}
        self.handler = handler
        self.annotations = annotations


def tool(name: str, description: str, input_schema: Optional[dict] = None,
         annotations: Any = None) -> Callable:
    """@tool(name, description, {param: type}, annotations=...) — same call shape as the SDK's."""

    def deco(fn: Callable) -> SdkMcpTool:
        return SdkMcpTool(name, description, input_schema or {}, fn, annotations)

    return deco


class SdkMcpServer:
    def __init__(self, name: str, tools: Optional[list] = None) -> None:
        self.name = name
        self.tools = list(tools or [])


def create_sdk_mcp_server(name: str, tools: Optional[list] = None, **_kw: Any) -> SdkMcpServer:
    return SdkMcpServer(name, tools)


@dataclass
class AgentDefinition:
    description: str = ""
    prompt: str = ""
    tools: list = field(default_factory=list)
    model: Optional[str] = None
    effort: Optional[str] = None


@dataclass
class HookMatcher:
    """Stand-in for the SDK's HookMatcher so orchestrator.py can pass `hooks=` on either backend.
    Stored and ignored — see KNOWN LIMITS: this module gates tool calls through `audit.gate()`
    directly rather than replaying hook callbacks."""

    matcher: Optional[str] = None
    hooks: list = field(default_factory=list)
    timeout: Optional[float] = None


@dataclass
class ToolUseBlock:
    name: str
    input: dict
    id: str = ""


@dataclass
class TextBlock:
    text: str


@dataclass
class AssistantMessage:
    content: list


@dataclass
class ResultMessage:
    subtype: str = "success"
    session_id: str = ""
    total_cost_usd: Optional[float] = None
    structured_output: Optional[dict] = None
    result: str = ""


class ClaudeAgentOptions:
    """Accepts the exact kwargs orchestrator._phase passes; extras are tolerated and ignored."""

    def __init__(self, system_prompt: str = "", mcp_servers: Optional[dict] = None,
                 tools: Optional[list] = None, allowed_tools: Optional[list] = None,
                 permission_mode: str = "default", setting_sources: Optional[list] = None,
                 resume: Optional[str] = None, max_turns: int = 40, model: Optional[str] = None,
                 effort: Optional[str] = None, output_format: Optional[dict] = None,
                 hooks: Optional[dict] = None, **_extra: Any) -> None:
        self.system_prompt = system_prompt
        self.mcp_servers = mcp_servers or {}
        self.tools = tools or []
        self.allowed_tools = allowed_tools or []
        self.permission_mode = permission_mode
        self.setting_sources = setting_sources or []
        self.resume = resume
        self.max_turns = max_turns
        self.model = model
        self.effort = effort              # accepted, ignored (no cross-vendor equivalent)
        self.output_format = output_format
        self.hooks = hooks or {}          # accepted, ignored — audit.gate() is called directly


# -------------------------------------------------------------------- HTTP I/O
_JSON_TYPE = {str: "string", int: "integer", float: "number", bool: "boolean"}
_SESSIONS: dict[str, list] = {}   # session_id -> message list (in-process resume, like SDK sessions)
EMIT_NAME = "emit_result"


def _params_schema(input_schema: dict, optional: Optional[dict] = None) -> dict:
    """tools.py's {param: python_type} -> OpenAI function `parameters` JSON Schema.

    `optional` carries the documented-but-undeclared arguments from references/tool_params.json.
    This matters MORE here than on the Anthropic path: this backend exists to run open-weight
    models, and a mid-size model does not reliably infer `passive=true` or `free_only=true` from a
    description paragraph the way a frontier model does. When it misses them the tool-call gate
    denies the call — correctly — and the run burns turns looping instead of adapting. The `enum`
    lists are the highest-value part: without them a model invents a seventh value for `mode`."""
    props = {k: {"type": _JSON_TYPE.get(v, "string")} for k, v in (input_schema or {}).items()}
    required = list(props.keys())
    for name, spec in (optional or {}).items():
        extra = {k: v for k, v in spec.items() if k in ("type", "description", "enum")}
        if name in props:
            # A REQUIRED param keeps its declared type but still gains the description and — the
            # part that matters — the `enum`. censys.mode is required and accepts exactly six
            # values; without the enum a model sends a seventh and the call fails for no visible
            # reason. Required-ness itself is never changed here.
            extra.pop("type", None)
            props[name].update(extra)
        else:
            props[name] = extra
    return {"type": "object", "properties": props,
            "required": required, "additionalProperties": True}


def _resolve_tools(options: ClaudeAgentOptions) -> tuple[dict, list]:
    """Build (fq_name -> SdkMcpTool, [openai function specs]) from the phase's servers, filtered to
    allowed_tools. Fully-qualified name matches the SDK's mcp__<server>__<tool> convention."""
    reg: dict[str, SdkMcpTool] = {}
    specs: list = []
    allowed = set(options.allowed_tools or [])
    for sname, server in (options.mcp_servers or {}).items():
        for t in getattr(server, "tools", []):
            fq = f"mcp__{sname}__{t.name}"
            if allowed and fq not in allowed:
                continue
            reg[fq] = t
            specs.append({"type": "function", "function": {
                "name": fq, "description": t.description,
                "parameters": _params_schema(t.input_schema,
                                             getattr(t, "optional_schema", None))}})
    return reg, specs


def _http_post(payload: dict, timeout: int) -> tuple[Optional[dict], Optional[str]]:
    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    key = _api_key()
    if key:
        headers["Authorization"] = f"Bearer {key}"
    req = urllib.request.Request(_base_url() + "/chat/completions", data=data,
                                 headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8")), None
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")[:600]
        return None, f"HTTP {e.code}: {body}"
    except Exception as e:  # noqa: BLE001 — urllib.error.URLError, socket timeout, JSON errors
        return None, repr(e)


def _http_post_retry(payload: dict, timeout: int, tries: int = 3) -> dict:
    err = None
    for i in range(tries):
        resp, err = _http_post(payload, timeout)
        if resp is not None:
            return resp
        transient = err and ("HTTP 5" in err or "HTTP 429" in err or "timed out" in err
                             or "URLError" in err or "RemoteDisconnected" in err)
        if transient and i < tries - 1:
            time.sleep(min(2 ** i, 8))
            continue
        break
    raise RuntimeError(err or "request failed")


def _parse_args(tool_call: dict) -> dict:
    try:
        return json.loads((tool_call.get("function") or {}).get("arguments") or "{}")
    except Exception:  # noqa: BLE001
        return {}


def _content_text(res: dict) -> str:
    """Flatten a tool handler's {content:[{type:text,text:…}], is_error} into a plain string."""
    parts = [b.get("text", "") for b in (res or {}).get("content", []) if b.get("type") == "text"]
    txt = "\n".join(p for p in parts if p)
    if (res or {}).get("is_error"):
        txt = "[tool error] " + txt
    return txt or "(no output)"


def _missing_required(schema: dict, obj: Optional[dict]) -> list:
    return [k for k in (schema or {}).get("required", []) if k not in (obj or {})]


# ------------------------------------------------------------------ the loop
def _cap_tool_output(text: str, fname: str) -> str:
    """One tool result, capped at insertion time — LOUDLY.

    The previous `out[:TOOL_RESULT_CAP]` was a silent slice, which is the dangerous kind: a
    quietly shortened result is indistinguishable from a tool that found less, and the model
    then reports the missing part as 'nothing found'. Head and tail are both kept because our
    JSON leads with `meta` and list output carries its summary at the end."""
    if len(text) <= TOOL_RESULT_CAP:
        return text
    head = int(TOOL_RESULT_CAP * 0.7)
    tail = TOOL_RESULT_CAP - head
    return (text[:head]
            + f"\n\n… ⚠️ {fname} OUTPUT TRUNCATED TO FIT THE CONTEXT BUDGET — {len(text):,} chars "
              f"→ {TOOL_RESULT_CAP:,}; {len(text) - TOOL_RESULT_CAP:,} omitted from the middle. "
              f"A context cut, NOT evidence of absence — re-run narrowed to see the rest.\n… \n\n"
            + text[-tail:])


def _msg_chars(m: dict) -> int:
    n = len(str(m.get("content") or ""))
    for tc in (m.get("tool_calls") or []):
        n += len(json.dumps(tc))
    return n


def _trim_history(messages: list) -> list:
    """Keep the request under TRANSCRIPT_CAP by eliding the OLDEST tool-call rounds.

    Three invariants, each protecting against a distinct way a trimmed agent goes wrong:

      1. The SYSTEM prompt and the ORIGINAL task message are never dropped. Losing the task is
         how a trimmed agent starts confidently answering a different question.
      2. Whole ROUNDS are dropped, never individual messages. An assistant message carrying
         `tool_calls` must be followed by a `tool` message for every one of its ids — orphan
         either half and the provider rejects the request outright, so a naive
         "drop the oldest message" trim turns a context problem into a hard API failure.
      3. The most recent `KEEP_RECENT_ROUNDS` are never elided, so the model keeps its immediate
         working state no matter how tight the budget gets.

    What was dropped is announced in-band, because the facts from those rounds are on disk in
    the case store — the model needs to know to re-read them rather than assume they never
    happened."""
    total = sum(_msg_chars(m) for m in messages)
    if total <= TRANSCRIPT_CAP:
        return messages

    head, i = [], 0
    while i < len(messages) and messages[i].get("role") == "system":
        head.append(messages[i]); i += 1
    if i < len(messages) and messages[i].get("role") == "user":     # the original task
        head.append(messages[i]); i += 1

    rounds, cur = [], []
    for m in messages[i:]:
        if m.get("role") == "assistant" and cur:
            rounds.append(cur); cur = []
        cur.append(m)
    if cur:
        rounds.append(cur)

    dropped = 0
    while (sum(_msg_chars(m) for m in head)
           + sum(_msg_chars(m) for r in rounds for m in r)) > TRANSCRIPT_CAP \
            and len(rounds) > KEEP_RECENT_ROUNDS:
        dropped += len(rounds.pop(0))
    if not dropped:
        return messages

    note = {"role": "user", "content":
            f"[harness context budget] {dropped} earlier message(s) covering the oldest tool-call "
            f"rounds were elided to stay within this model's context window. They HAPPENED — "
            f"their findings are on disk in the case store (cases/<case>/raw, the KB). If you "
            f"need one, re-read it with a tool rather than assuming it was never collected."}
    print(f"[openai_backend] context budget: elided {dropped} old message(s) "
          f"(> {TRANSCRIPT_CAP:,} chars)", file=sys.stderr)
    return head + [note] + [m for r in rounds for m in r]


async def query(*, prompt: str, options: ClaudeAgentOptions):
    """Async generator mirroring claude_agent_sdk.query: yields AssistantMessage per tool-using turn
    (so orchestrator's live worklog prints each call) and one final ResultMessage. Runs a standard
    OpenAI tool loop against OPENAI_BASE_URL, up to options.max_turns."""
    model = _model_for(options.model)
    reg, specs = _resolve_tools(options)

    want_struct = bool(options.output_format)
    schema = (options.output_format or {}).get("schema") or {} if want_struct else {}
    emit_spec = {"type": "function", "function": {
        "name": EMIT_NAME,
        "description": "Return the FINAL structured result. Call this exactly once when finished.",
        "parameters": schema}}
    if want_struct:
        specs = specs + [emit_spec]

    # messages: resume an in-process session, else open a fresh one with the phase system prompt.
    if options.resume and options.resume in _SESSIONS:
        messages = list(_SESSIONS[options.resume])
        sid = options.resume
    else:
        messages = []
        if options.system_prompt:
            messages.append({"role": "system", "content": options.system_prompt})
        sid = uuid.uuid4().hex
    user = prompt
    if want_struct:
        user += "\n\nWhen finished, call the `emit_result` tool with the final structured result."
    messages.append({"role": "user", "content": user})

    tok_in = tok_out = 0
    structured: Optional[dict] = None
    final_text = ""
    hit_max = True
    backend_error: Optional[str] = None

    for _turn in range(max(1, options.max_turns)):
        messages = _trim_history(messages)      # context ceiling — see _trim_history's invariants
        payload: dict = {"model": model, "messages": messages}
        if specs:
            payload["tools"] = specs
            payload["tool_choice"] = "auto"
        try:
            resp = await asyncio.to_thread(_http_post_retry, payload, HTTP_TIMEOUT)
        except Exception as e:  # noqa: BLE001
            backend_error = str(e)
            hit_max = False
            break
        usage = resp.get("usage") or {}
        tok_in += usage.get("prompt_tokens", 0) or 0
        tok_out += usage.get("completion_tokens", 0) or 0
        msg = (resp.get("choices") or [{}])[0].get("message") or {}
        tcs = msg.get("tool_calls") or []

        if not tcs:
            final_text = msg.get("content") or ""
            messages.append({"role": "assistant", "content": final_text})
            hit_max = False
            break

        # echo the assistant tool-call turn, then surface it to the worklog
        messages.append({"role": "assistant", "content": msg.get("content"), "tool_calls": tcs})
        yield AssistantMessage(content=[
            ToolUseBlock(name=(tc.get("function") or {}).get("name", ""),
                         input=_parse_args(tc), id=tc.get("id", "")) for tc in tcs])

        done = False
        for tc in tcs:
            fname = (tc.get("function") or {}).get("name", "")
            args = _parse_args(tc)
            if want_struct and fname == EMIT_NAME:
                structured = args
                messages.append({"role": "tool", "tool_call_id": tc.get("id", ""), "content": "ok"})
                done = True
                continue
            t = reg.get(fname)
            if t is None:
                out = f"unknown tool: {fname}"
            else:
                # THE GATE — the shim's equivalent of the SDK path's PreToolUse hook. Same module,
                # same policy, same ledger; a denial comes back as tool output so the model can
                # adapt (passive=true / free_only=true) instead of the run dying.
                allowed, why = audit.gate(fname, args, backend="openai")
                if not allowed:
                    out = f"[BLOCKED by harness policy] {why}"
                else:
                    try:
                        out = _content_text(await t.handler(args))
                    except Exception as e:  # noqa: BLE001 — surface faults to the model, keep looping
                        out = f"{fname} raised: {e!r}"
            messages.append({"role": "tool", "tool_call_id": tc.get("id", ""),
                             "content": _cap_tool_output(out, fname)})
        if done:
            hit_max = False
            break

    # Schema-forced phase that never emitted (or emitted an incomplete object): force it now.
    if want_struct and backend_error is None:
        ok = structured is not None and not _missing_required(schema, structured)
        tries = 0
        while not ok and tries < STRUCT_RETRIES:
            tries += 1
            forced = _trim_history(messages) + [
                {"role": "user",
                 "content": "Call the emit_result tool now with the complete final "
                            "result matching the required schema."}]
            payload = {"model": model, "messages": forced, "tools": [emit_spec],
                       "tool_choice": {"type": "function", "function": {"name": EMIT_NAME}}}
            try:
                resp = await asyncio.to_thread(_http_post_retry, payload, HTTP_TIMEOUT)
            except Exception as e:  # noqa: BLE001
                backend_error = str(e)
                break
            usage = resp.get("usage") or {}
            tok_in += usage.get("prompt_tokens", 0) or 0
            tok_out += usage.get("completion_tokens", 0) or 0
            m = (resp.get("choices") or [{}])[0].get("message") or {}
            tcs = m.get("tool_calls") or []
            if tcs:
                cand = _parse_args(tcs[0])
                if cand:
                    structured = cand  # keep best effort even if a field is missing
                    ok = not _missing_required(schema, cand)

    # subtype semantics orchestrator checks: "success" gates Assessment.model_validate + the cascade.
    if backend_error is not None:
        subtype = "error"
        final_text = final_text or backend_error
    elif want_struct:
        subtype = "success" if structured is not None else "error"
    elif hit_max:
        subtype = "error_max_turns"
    else:
        subtype = "success"

    _SESSIONS[sid] = messages
    yield ResultMessage(subtype=subtype, session_id=sid, total_cost_usd=_cost(model, tok_in, tok_out),
                        structured_output=structured, result=final_text)
