"""sdk_compat.py — one seam that decides which agent backend the harness runs on.

  HARNESS_BACKEND claude                     -> the real claude_agent_sdk (Anthropic / Claude Code CLI)
  HARNESS_BACKEND codex | omp                -> cli_backend.py (the Codex / OMP CLI on its own login,
                                                driving harness/mcp_server.py over stdio)
  HARNESS_BACKEND openai|deepseek|kimi|local -> openai_backend.py (any /chat/completions endpoint)
  HARNESS_BACKEND unset / auto               -> claude_agent_sdk when importable, else the
                                                openai_backend shim (enough for tools.py's @tool
                                                registry, i.e. the interactive MCP server). The
                                                ORCHESTRATOR never runs on this default: it calls
                                                backend_select.ensure_env() first, which probes and
                                                exports a concrete HARNESS_BACKEND.

All expose the identical symbol set orchestrator.py / tools.py / agents.py import, so those files
just swap `from claude_agent_sdk import …` for `from sdk_compat import …` and never branch on the
backend themselves.
"""
from __future__ import annotations

import importlib.util
import os
import sys

import backend_select

_REQUESTED = (os.environ.get("HARNESS_BACKEND") or "auto").strip().lower()

if _REQUESTED in backend_select.OPENAI_BACKENDS:
    _MODULE = "openai"
elif _REQUESTED in backend_select.CLI_BACKENDS:
    _MODULE = "cli"
elif _REQUESTED == "claude":
    _MODULE = "claude"
else:  # auto / unset — import-only consumers (tools.py via mcp_server.py)
    def _sdk_importable() -> bool:
        if "claude_agent_sdk" in sys.modules:          # a test stub or an already-loaded SDK
            return True
        try:
            return importlib.util.find_spec("claude_agent_sdk") is not None
        except (ValueError, ImportError):
            return False
    _MODULE = "claude" if _sdk_importable() else "openai"

if _MODULE == "openai":
    from openai_backend import (  # noqa: F401
        AgentDefinition,
        AssistantMessage,
        ClaudeAgentOptions,
        HookMatcher,
        ResultMessage,
        ToolAnnotations,
        ToolUseBlock,
        create_sdk_mcp_server,
        query,
        tool,
    )
    BACKEND = "openai"
elif _MODULE == "cli":
    from cli_backend import (  # noqa: F401
        AgentDefinition,
        AssistantMessage,
        ClaudeAgentOptions,
        HookMatcher,
        ResultMessage,
        ToolAnnotations,
        ToolUseBlock,
        create_sdk_mcp_server,
        query,
        tool,
    )
    BACKEND = _REQUESTED
else:
    backend_select.ensure_root_sandbox_env()   # euid 0: the Claude CLI needs IS_SANDBOX=1
    import claude_agent_sdk as _sdk
    import openai_backend as _shim             # fills any symbol a partial SDK (or a test stub) lacks
    _NAMES = ("AgentDefinition", "AssistantMessage", "ClaudeAgentOptions", "HookMatcher",
              "ResultMessage", "ToolAnnotations", "ToolUseBlock", "create_sdk_mcp_server",
              "query", "tool")
    for _n in _NAMES:
        globals()[_n] = getattr(_sdk, _n, None) or getattr(_shim, _n)
    del _n
    BACKEND = "claude"
