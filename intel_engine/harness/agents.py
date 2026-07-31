"""OPTIONAL: the same skills as SDK subagents, for parallel fan-out.

orchestrator.py runs one linear case (phase = a query() with a pinned skill prompt).
When you want to fan a fleet of collectors across N seeds concurrently (your
WebPivot/Workflows/ParallelBatch.md pattern), define them as subagents and let a
thin orchestrator agent dispatch them. AgentDefinition fields are camelCase.

This module is illustrative scaffolding — wire it into a driver query() that has
the `Agent`/dispatch tool available. Kept separate so the linear path stays simple.
"""
from __future__ import annotations

import os

from claude_agent_sdk import AgentDefinition

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _skill(name: str) -> str:
    with open(os.path.join(ROOT, name, "SKILL.md"), encoding="utf-8") as f:
        return f.read()


AGENTS: dict[str, AgentDefinition] = {
    "collector": AgentDefinition(
        description="Extracts pivot artifacts from ONE url/host and ingests them. Use for fan-out.",
        prompt=_skill("WebPivot"),
        tools=["mcp__collect__pivot_extract", "mcp__collect__kb_ingest"],
        model="haiku",   # mechanical collection -> cheap model
    ),
    "analyst": AgentDefinition(
        description="Correlates the KB, attributes clusters, assesses confidence. Read-only.",
        prompt=_skill("IntelAnalysis"),
        tools=["mcp__analyze__kb_query_shared", "mcp__analyze__risk_signals"],
        model="opus",
        effort="high",
    ),
    "grapher": AgentDefinition(
        description="Renders the case graph into a relationship diagram.",
        prompt=_skill("IntelGraph"),
        tools=["Bash"],  # calls IntelGraph/scripts/render_network.py
        model="sonnet",
    ),
}
