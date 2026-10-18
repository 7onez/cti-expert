#!/usr/bin/env python3
"""mcp_server.py — a standalone stdio MCP server exposing the harness's OSINT tools.

WHY THIS EXISTS
  The SDK driver (orchestrator.py) already gets clean, typed tools instead of shell-flailing.
  The Claude-Code front-end (the IntelHarness skill) does NOT — it drives the same work by
  telling the model to run raw `python3 …/pivot_extract.py` bash. This server closes that gap:
  it serves the SAME tool objects to Claude Code (or any MCP client) over stdio, so both
  front-ends share one typed, permission-gated tool surface.

ZERO DUPLICATION
  It does NOT re-implement any tool. It imports `tools.py` and auto-discovers every `@tool`
  (each an `SdkMcpTool` with .name/.description/.input_schema/.handler) — the handlers, and the
  CLIs underneath them, stay the single source of truth. Add a tool to tools.py and it appears
  here automatically.

RUN / WIRE UP
  Must run with a Python that has `claude_agent_sdk` (tools.py imports it) — the WebPivot venv.
  Claude Code discovers it via the repo-root `.mcp.json`; standalone smoke test:
    WebPivot/.venv/bin/python3 harness/mcp_server.py   # then speak JSON-RPC on stdin
    printf '{"jsonrpc":"2.0","id":1,"method":"ping"}\\n' | WebPivot/.venv/bin/python3 harness/mcp_server.py
  Requests still in flight when stdin closes are answered before the process exits.

  Protocol: MCP over stdio = newline-delimited JSON-RPC 2.0. Methods handled:
  initialize · notifications/initialized · tools/list · tools/call · ping.

NOTE — egress policy: this server has no phase loop to flip tools.POLICY, so it inherits the
  import-time default, which reads the HARNESS_HOSTILE env var (see tools.py). Run a hostile-infra
  session with `HARNESS_HOSTILE=1` and pivot_extract refuses direct live fetch (forces passive= /
  proxy=), matching the SDK driver's per-phase gate. Left unset it defaults permissive, which suits
  benign interactive use.

  That env gate is now the SECOND lock, not the only one: every tools/call goes through
  `audit.gate()` first — the same policy point the SDK driver reaches via its PreToolUse hook and
  the OpenAI shim calls inline. It blocks hostile egress across ALL outbound tools (not just the
  ones that implement their own refusal), refuses an unapproved sandbox submission, and writes
  every call — allowed or denied — to cases/<case>/tool_calls.jsonl. Interactive calls that carry
  no `case` argument land in MEMORY/tool_calls.jsonl.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # find harness/tools.py first


def _install_research_egress() -> None:
    """Collectors reach targets through the research proxy pool (scripts/proxy) — the same egress
    scripts/backend/intel.py installs. This server is often started WITHOUT that dispatcher (Claude
    Code via .mcp.json, Codex/OMP harness phases, which pass MCP servers a trimmed env), so it
    installs the pool itself; otherwise every tool subprocess would reach the target from the
    analyst's own IP. No-op when the pool is disabled or unconfigured."""
    here = os.path.dirname(os.path.abspath(__file__))
    proxy_dir = os.path.normpath(os.path.join(here, "..", "..", "scripts", "proxy"))
    if not os.path.isfile(os.path.join(proxy_dir, "cti_proxy.py")):
        return
    sys.path.insert(0, proxy_dir)
    try:
        import cti_proxy  # noqa: WPS433
        cti_proxy.install()
    except Exception as e:  # noqa: BLE001 — degrade loudly, never silently go direct
        print(f"[mcp_server] WARNING: research egress proxy not installed ({e!r}) — tool traffic "
              f"may leave from this machine's own IP", file=sys.stderr)


_install_research_egress()
import audit  # noqa: E402  — the shared tool-call gate + ledger (front-end neutral)
import tools as T  # noqa: E402  (imports claude_agent_sdk — needs the WebPivot venv)

SERVER_INFO = {"name": "intel-harness", "version": "0.1.0"}
# MCP revisions this server speaks, newest first. initialize echoes the client's version only when
# it is one of these; any other value (unknown date, non-string) is answered with the newest, which
# per the MCP lifecycle spec tells the client to disconnect if it cannot speak that revision.
SUPPORTED_PROTOCOLS = ("2025-06-18", "2025-03-26", "2024-11-05")
DEFAULT_PROTOCOL = SUPPORTED_PROTOCOLS[0]

# Auto-discover every decorated tool in tools.py (duck-typed, so no SDK-internal import needed).
TOOLS = {
    v.name: v
    for v in vars(T).values()
    if hasattr(v, "name") and hasattr(v, "handler") and hasattr(v, "input_schema")
}

# Per-phase scoping for the CLI backend (harness/cli_backend.py). HARNESS_ALLOWED_TOOLS narrows
# tools/list to one phase's tool set (collect vs analyze — the same lists orchestrator passes as
# allowed_tools on the SDK path); HARNESS_EMIT_SCHEMA_FILE adds a synthetic `emit_result` tool whose
# payload is validated against that JSON schema's required keys and written to
# HARNESS_EMIT_OUT_FILE — the stdio equivalent of the SDK's structured output_format. INTEL_CASE
# binds the audit ledger to the case when the model's arguments carry none. Unset = the
# interactive Claude-Code behaviour, unchanged.
_ALLOWED = {t.strip() for t in os.environ.get("HARNESS_ALLOWED_TOOLS", "").split(",") if t.strip()}
_EMIT_SCHEMA_FILE = os.environ.get("HARNESS_EMIT_SCHEMA_FILE", "")
_EMIT_OUT_FILE = os.environ.get("HARNESS_EMIT_OUT_FILE", "")
_ENV_CASE = os.environ.get("INTEL_CASE") or None
EMIT_NAME = "emit_result"


def _emit_schema() -> dict:
    try:
        with open(_EMIT_SCHEMA_FILE, encoding="utf-8") as f:
            s = json.load(f)
        return s if isinstance(s, dict) else {}
    except Exception:  # noqa: BLE001 — a missing/invalid schema disables the tool, loudly below
        return {}


def _emit_result(arguments: dict) -> dict:
    schema = _emit_schema()
    missing = [k for k in schema.get("required", []) if k not in (arguments or {})]
    if missing:
        return {"content": [{"type": "text", "text": "emit_result rejected — missing required "
                             f"field(s): {', '.join(missing)}. Call again with the complete object."}],
                "isError": True}
    try:
        with open(_EMIT_OUT_FILE, "w", encoding="utf-8") as f:
            json.dump(arguments, f, ensure_ascii=False)
    except OSError as e:
        return {"content": [{"type": "text", "text": f"emit_result could not persist: {e!r}"}], "isError": True}
    return {"content": [{"type": "text", "text": "ok — final result recorded. You are done; reply DONE."}],
            "isError": False}

_JSON_TYPE = {str: "string", int: "integer", float: "number", bool: "boolean"}

# Executor for blocking tool coroutines (concurrency governed by vendor limits, not a codebase cap)
_EXECUTOR = ThreadPoolExecutor()
_WRITE_LOCK = threading.Lock()


def _input_schema(sdk_schema: dict, optional: dict | None = None) -> dict:
    """Convert tools.py's `{param: python_type}` into a JSON Schema object.

    The declared params are REQUIRED (matching how the SDK treated them). `optional` carries the
    documented-but-undeclared arguments from references/tool_params.json — passive, free_only,
    mode, max_domains and the rest — as real properties with types, one-line descriptions and, for
    the fixed-value ones, an `enum`. They used to live only in the description paragraph, which a
    strong model reads reliably and a mid-size open-weight model largely does not; a model that
    cannot see `mode` accepts exactly six values invents a seventh. additionalProperties stays true
    so an argument not yet declared here still passes through.

    A tool_params.json entry for a DECLARED param keeps its declared type but adds the description
    and `enum`; it also drops the param from `required` when the entry says `"required": false` —
    the handler defaults it (kb_query_shared.min, reverse_whois.kind), so demanding it from the
    model is wrong."""
    props = {k: {"type": _JSON_TYPE.get(v, "string")} for k, v in (sdk_schema or {}).items()}
    required = list(props.keys())
    for name, spec in (optional or {}).items():
        extra = {k: v for k, v in spec.items() if k in ("type", "description", "enum")}
        if name in props:
            # A REQUIRED param keeps its declared type but still gains the description and the
            # `enum` — censys.mode is required and accepts exactly six values, and without the
            # enum a model sends a seventh.
            extra.pop("type", None)
            props[name].update(extra)
            if spec.get("required") is False and name in required:
                required.remove(name)
        else:
            props[name] = extra
    return {"type": "object", "properties": props,
            "required": required, "additionalProperties": True}


def _annotations(tool) -> dict | None:
    """The tool's MCP annotations (readOnlyHint …) as a plain dict, None-valued hints dropped.
    Handles the SDK's pydantic ToolAnnotations, the shim's attribute bag, and a plain dict. Keys are
    emitted in the protocol's camelCase whatever the source spells: older SDK builds (0.2.144)
    name the pydantic fields `read_only_hint`, and a client only honours `readOnlyHint`."""
    ann = getattr(tool, "annotations", None)
    if ann is None:
        return None
    if isinstance(ann, dict):
        raw = ann
    elif hasattr(ann, "model_dump"):
        raw = ann.model_dump()
    else:
        raw = vars(ann)

    def camel(k: str) -> str:
        head, *rest = k.split("_")
        return head + "".join(p[:1].upper() + p[1:] for p in rest)

    out = {camel(str(k)): v for k, v in raw.items() if v is not None and not str(k).startswith("_")}
    return out or None


def _list_tools() -> list[dict]:
    out = []
    for t in TOOLS.values():
        if _ALLOWED and t.name not in _ALLOWED:
            continue
        entry = {"name": t.name, "description": t.description,
                 "inputSchema": _input_schema(t.input_schema, getattr(t, "optional_schema", None))}
        ann = _annotations(t)
        if ann:
            entry["annotations"] = ann
        out.append(entry)
    if _EMIT_SCHEMA_FILE and _EMIT_OUT_FILE:
        schema = _emit_schema() or {"type": "object", "properties": {}, "additionalProperties": True}
        out.append({"name": EMIT_NAME,
                    "description": "Return the FINAL structured result. Call this exactly once when "
                                   "finished; it is the only accepted way to finish this phase.",
                    "inputSchema": schema})
    return out


async def _call_tool(name: str, arguments: dict) -> dict:
    """Invoke a tool handler and translate its {content, is_error} into an MCP tools/call result.
    A missing tool or a raised handler becomes an isError result (the model sees the message),
    never a transport-level failure.

    Gated: `audit.gate` runs BEFORE the handler. A denial is returned as an isError result carrying
    the reason, so Claude Code can adapt (re-call passive / free_only, or ask the analyst for the
    approval a sandbox submission needs) instead of silently proceeding."""
    if name == EMIT_NAME and _EMIT_SCHEMA_FILE and _EMIT_OUT_FILE:
        return _emit_result(arguments or {})
    tool = TOOLS.get(name)
    if tool is None or (_ALLOWED and name not in _ALLOWED):
        return {"content": [{"type": "text", "text": f"unknown tool: {name}"}], "isError": True}
    allowed, why = audit.gate(name, arguments or {}, case=(arguments or {}).get("case") or _ENV_CASE,
                              phase=os.environ.get("HARNESS_PHASE") or "interactive",
                              backend=os.environ.get("HARNESS_BACKEND") or "claude-code")
    if not allowed:
        return {"content": [{"type": "text", "text": f"[BLOCKED by harness policy] {why}"}],
                "isError": True}
    try:
        res = await tool.handler(arguments or {})
    except Exception as e:  # noqa: BLE001 — surface tool faults to the model, keep the server alive
        return {"content": [{"type": "text", "text": f"{name} raised: {e!r}"}], "isError": True}
    return {"content": res.get("content") or [], "isError": bool(res.get("is_error"))}


async def _dispatch(method: str, params: dict) -> dict:
    if method == "initialize":
        asked = params.get("protocolVersion")
        return {
            "protocolVersion": asked if asked in SUPPORTED_PROTOCOLS else DEFAULT_PROTOCOL,
            "capabilities": {"tools": {}},
            "serverInfo": SERVER_INFO,
        }
    if method == "tools/list":
        return {"tools": _list_tools()}
    if method == "tools/call":
        return await _call_tool(params["name"], params.get("arguments") or {})
    if method == "ping":
        return {}
    raise _MethodNotFound(method)


class _MethodNotFound(Exception):
    pass


def _write(obj: dict) -> None:
    try:
        line = json.dumps(obj, ensure_ascii=False) + "\n"
        line.encode(sys.stdout.encoding or "utf-8")
    except (UnicodeError, LookupError):
        # A lone surrogate (or a char the stdout encoding lacks) in a tool result: \u-escape it
        # rather than lose the reply — the JSON is identical once decoded.
        line = json.dumps(obj, ensure_ascii=True) + "\n"
    with _WRITE_LOCK:
        sys.stdout.write(line)
        sys.stdout.flush()


def _error(mid, code: int, message: str) -> None:
    _write({"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}})


def _validate(msg):
    """Classify one parsed stdin message. Returns ("ignore", None), ("reply", (id, code, message))
    for a protocol-level rejection, or ("run", (id, method, params)) for a dispatchable request or
    notification. Never raises — any JSON value at all is a legal input to this function."""
    if not isinstance(msg, dict):
        # Batches (arrays) are not part of MCP since 2025-06-18; scalars and null are not requests.
        return "reply", (None, -32600, "invalid request: expected a single JSON-RPC object")
    mid = msg.get("id")
    if mid is not None and (isinstance(mid, bool) or not isinstance(mid, (str, int))):
        return "reply", (None, -32600, "invalid request: id must be a string or integer")
    if "method" not in msg and "id" in msg and ("result" in msg or "error" in msg):
        return "ignore", None        # a client RESPONSE (e.g. to a request we never sent): no reply
    if msg.get("jsonrpc") != "2.0":
        return "reply", (mid, -32600, "invalid request: jsonrpc must be \"2.0\"")
    method = msg.get("method")
    if not isinstance(method, str) or not method:
        return "reply", (mid, -32600, "invalid request: missing or non-string method")
    params = msg.get("params")
    if params is None:
        params = {}
    if not isinstance(params, dict):
        return "reply", (mid, -32602, "invalid params: params must be an object")
    if method == "tools/call":
        if not isinstance(params.get("name"), str):
            return "reply", (mid, -32602, "invalid params: tools/call needs a string `name`")
        if not isinstance(params.get("arguments") or {}, dict):
            return "reply", (mid, -32602, "invalid params: tools/call `arguments` must be an object")
    return "run", (mid, method, params)


async def _handle(msg) -> None:
    try:
        verdict, payload = _validate(msg)
    except Exception as e:  # noqa: BLE001 — _validate is total; this only guards a future edit
        verdict, payload = "reply", (None, -32603, f"internal error: {e!r}")
    if verdict == "ignore":
        return
    if verdict == "reply":
        mid, code, message = payload
        # A notification (no id) is never answered — except a malformed message, which JSON-RPC
        # answers with id null because the server cannot tell whether a reply was wanted.
        if mid is not None or code == -32600:
            _error(mid, code, message)
        return
    mid, method, params = payload
    try:
        def _run_dispatch():
            return asyncio.run(_dispatch(method, params))
        result = await asyncio.get_running_loop().run_in_executor(_EXECUTOR, _run_dispatch)
        if mid is not None:
            _write({"jsonrpc": "2.0", "id": mid, "result": result})
    except _MethodNotFound:
        if mid is not None:
            _error(mid, -32601, f"method not found: {method}")
    except Exception as e:  # noqa: BLE001
        if mid is not None:
            _error(mid, -32603, f"internal error: {e!r}")


# Handler tasks still running. At stdin EOF the loop must not stop until every one has written its
# reply: `printf '<request>\n' | mcp_server.py` closes stdin immediately, and stopping the loop
# there destroyed the pending task — the request was silently dropped.
_PENDING: set = set()


def _spawn(msg) -> None:
    task = asyncio.get_running_loop().create_task(_handle(msg))
    _PENDING.add(task)
    task.add_done_callback(_PENDING.discard)


async def _drain_and_stop() -> None:
    while _PENDING:
        await asyncio.gather(*list(_PENDING), return_exceptions=True)
    asyncio.get_running_loop().stop()


def _schedule_drain(loop: asyncio.AbstractEventLoop) -> None:
    loop.create_task(_drain_and_stop())


def _stdin_reader(loop: asyncio.AbstractEventLoop) -> None:
    """Background thread: reads stdin and schedules work on the main loop. call_soon_threadsafe is
    FIFO, so the EOF drain is scheduled after every request read before it."""
    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                _error(None, -32700, "parse error")
                continue
            loop.call_soon_threadsafe(_spawn, msg)
    finally:
        loop.call_soon_threadsafe(_schedule_drain, loop)


def _serve() -> None:
    """Main thread owns the event loop. Stdin is read by a daemon thread."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    reader = threading.Thread(target=_stdin_reader, args=(loop,), daemon=True)
    reader.start()
    try:
        loop.run_forever()
    finally:
        loop.close()
        _EXECUTOR.shutdown(wait=False)


if __name__ == "__main__":
    _serve()