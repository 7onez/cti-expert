"""sdk_compat.py — one seam that decides which agent backend the harness runs on.

  HARNESS_BACKEND unset / "claude"           -> the real claude_agent_sdk (Anthropic)
  HARNESS_BACKEND openai|deepseek|kimi|local -> openai_backend.py (any /chat/completions endpoint)

Both expose the identical symbol set orchestrator.py / tools.py / agents.py import, so those files
just swap `from claude_agent_sdk import …` for `from sdk_compat import …` and never branch on the
backend themselves.
"""
from __future__ import annotations

import os

_OPENAI_BACKENDS = {"openai", "deepseek", "kimi", "moonshot", "local", "ollama", "vllm", "lmstudio"}
BACKEND = os.environ.get("HARNESS_BACKEND", "claude").strip().lower()

if BACKEND in _OPENAI_BACKENDS:
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
else:
    from claude_agent_sdk import (  # noqa: F401
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
    BACKEND = "claude"
