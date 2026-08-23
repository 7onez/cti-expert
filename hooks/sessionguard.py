#!/usr/bin/env python3
"""sessionguard.py — SessionStart hook: tell the session what backend it actually has.

THE PROBLEM THIS SOLVES
-----------------------
Claude Code resolves an MCP server's tool list when it CONNECTS, and keeps it for the session. If
the engine gained tools since that connection was made, the session drives a stale surface and
nothing says so — the model simply never sees the new tools and works around their absence. That
is exactly what happened on 2026-08-23: a session was holding 17 tools while the engine on disk
served 46, a four-week-old surface, with no error anywhere.

A hook cannot read the live registration, so this one does not pretend to. It reports what the
code on disk serves and remembers what it reported last time. When that number CHANGES, it says so
once — which is precisely when a cached registration would have gone stale.

It also states the resolved backend tier, so the model does not have to guess whether it has the
typed MCP surface (T1), the CLI (T2), or neither (T3) before choosing how to run a case.

CONTRACT
--------
stdin : {"session_id": "...", ...}
stdout: {"systemMessage": "...",                       # only when something changed
         "hookSpecificOutput": {"hookEventName": "SessionStart",
                                "additionalContext": "..."}}

Purely informational — it can never block a session. Any internal error exits quietly.
"""
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS_PY = os.path.join(ROOT, "intel_engine", "harness", "tools.py")
BACKEND = os.path.join(ROOT, "scripts", "backend", "backend.py")
# State lives in the git-ignored MEMORY store — it is runtime data, not part of the skill.
STATE = os.path.join(ROOT, "intel_engine", "MEMORY", "hook_state.json")


def tool_count():
    """How many @tool the engine serves ON DISK right now."""
    try:
        with open(TOOLS_PY, encoding="utf-8") as fh:
            return len(re.findall(r"(?m)^@tool\(", fh.read()))
    except Exception:  # noqa: BLE001
        return None


def backend_line():
    try:
        r = subprocess.run([sys.executable, BACKEND, "status"], cwd=ROOT,
                           capture_output=True, text=True, timeout=20)
        for line in (r.stdout or "").splitlines():
            if line.strip():
                return line.strip()
    except Exception:  # noqa: BLE001
        pass
    return ""


def read_state():
    try:
        with open(STATE, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:  # noqa: BLE001
        return {}


def write_state(d):
    try:
        os.makedirs(os.path.dirname(STATE), exist_ok=True)
        with open(STATE, "w", encoding="utf-8") as fh:
            json.dump(d, fh, indent=2)
    except Exception:  # noqa: BLE001
        pass          # state is a convenience; losing it costs one redundant notice


def main():
    n = tool_count()
    if n is None:
        return 0                      # not a cti-expert checkout, or no engine — say nothing

    tier = backend_line()
    state = read_state()
    prev = state.get("tool_count")

    ctx = [f"cti-expert engine: {n} MCP @tool on disk."]
    if tier:
        ctx.append(tier)
    ctx.append("Outbound actions (engage_account, anyrun_submit, harvest_authenticated, any "
               "--submit) are gated by hooks/actionguard.py and will prompt. Writes into tracked "
               "files are scanned for RULE 1 case data by hooks/leakguard.py before they land.")

    out = {"hookSpecificOutput": {"hookEventName": "SessionStart",
                                  "additionalContext": " ".join(ctx)}}

    if prev is not None and prev != n:
        out["systemMessage"] = (
            f"cti-expert: the engine now serves {n} MCP tools (was {prev} when last seen). "
            "Claude Code caches an MCP server's tool list at CONNECT time — if /mcp shows fewer "
            f"than {n}, reconnect the `intel` server or restart, or this session will drive the "
            "old surface with no error.")

    state["tool_count"] = n
    write_state(state)
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001 — informational only; never disturb a session
        print(f"sessionguard: {e}", file=sys.stderr)
        sys.exit(0)
