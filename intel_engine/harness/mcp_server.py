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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # find harness/tools.py first
import audit  # noqa: E402  — the shared tool-call gate + ledger (front-end neutral)
import tools as T  # noqa: E402  (imports claude_agent_sdk — needs the WebPivot venv)

SERVER_INFO = {"name": "intel-harness", "version": "0.1.0"}
DEFAULT_PROTOCOL = "2025-06-18"

# Auto-discover every decorated tool in tools.py (duck-typed, so no SDK-internal import needed).
TOOLS = {
    v.name: v
    for v in vars(T).values()
    if hasattr(v, "name") and hasattr(v, "handler") and hasattr(v, "input_schema")
}

_JSON_TYPE = {str: "string", int: "integer", float: "number", bool: "boolean"}


def _input_schema(sdk_schema: dict, optional: dict | None = None) -> dict:
    """Convert tools.py's `{param: python_type}` into a JSON Schema object.

    The declared params are REQUIRED (matching how the SDK treated them). `optional` carries the
    documented-but-undeclared arguments from references/tool_params.json — passive, free_only,
    mode, max_domains and the rest — as real properties with types, one-line descriptions and, for
    the fixed-value ones, an `enum`. They used to live only in the description paragraph, which a
    strong model reads reliably and a mid-size open-weight model largely does not; a model that
    cannot see `mode` accepts exactly six values invents a seventh. additionalProperties stays true
    so an argument not yet declared here still passes through."""
    props = {k: {"type": _JSON_TYPE.get(v, "string")} for k, v in (sdk_schema or {}).items()}
    required = list(props.keys())
    for name, spec in (optional or {}).items():
        extra = {k: v for k, v in spec.items() if k in ("type", "description", "enum")}
        if name in props:
            # A REQUIRED param keeps its declared type but still gains the description and the
            # `enum` — censys.mode is required and accepts exactly six values, and without the
            # enum a model sends a seventh. Required-ness is never changed here.
            extra.pop("type", None)
            props[name].update(extra)
        else:
            props[name] = extra
    return {"type": "object", "properties": props,
            "required": required, "additionalProperties": True}


def _list_tools() -> list[dict]:
    return [{"name": t.name, "description": t.description,
             "inputSchema": _input_schema(t.input_schema, getattr(t, "optional_schema", None))}
            for t in TOOLS.values()]


async def _call_tool(name: str, arguments: dict) -> dict:
    """Invoke a tool handler and translate its {content, is_error} into an MCP tools/call result.
    A missing tool or a raised handler becomes an isError result (the model sees the message),
    never a transport-level failure.

    Gated: `audit.gate` runs BEFORE the handler. A denial is returned as an isError result carrying
    the reason, so Claude Code can adapt (re-call passive / free_only, or ask the analyst for the
    approval a sandbox submission needs) instead of silently proceeding."""
    tool = TOOLS.get(name)
    if tool is None:
        return {"content": [{"type": "text", "text": f"unknown tool: {name}"}], "isError": True}
    allowed, why = audit.gate(name, arguments or {}, case=(arguments or {}).get("case"),
                              phase="interactive", backend="claude-code")
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
        return {
            "protocolVersion": params.get("protocolVersion") or DEFAULT_PROTOCOL,
            "capabilities": {"tools": {}},
            "serverInfo": SERVER_INFO,
        }
    if method == "tools/list":
        return {"tools": _list_tools()}
    if method == "tools/call":
        return await _call_tool(params.get("name", ""), params.get("arguments") or {})
    if method == "ping":
        return {}
    raise _MethodNotFound(method)


class _MethodNotFound(Exception):
    pass


def _write(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def _serve() -> None:
    """Blocking read loop over newline-delimited JSON-RPC. Requests carry an `id` and get a
    reply; notifications (no `id`, e.g. notifications/initialized) are acted on but never answered."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                _write({"jsonrpc": "2.0", "id": None,
                        "error": {"code": -32700, "message": "parse error"}})
                continue
            mid = msg.get("id")
            method = msg.get("method", "")
            params = msg.get("params") or {}
            try:
                result = loop.run_until_complete(_dispatch(method, params))
            except _MethodNotFound:
                if mid is not None:
                    _write({"jsonrpc": "2.0", "id": mid,
                            "error": {"code": -32601, "message": f"method not found: {method}"}})
                continue
            except Exception as e:  # noqa: BLE001
                if mid is not None:
                    _write({"jsonrpc": "2.0", "id": mid,
                            "error": {"code": -32603, "message": f"internal error: {e!r}"}})
                continue
            if mid is not None:  # a request — reply; a notification carries no id, so stay silent
                _write({"jsonrpc": "2.0", "id": mid, "result": result})
    finally:
        loop.close()


if __name__ == "__main__":
    _serve()
