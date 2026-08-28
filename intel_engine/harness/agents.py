"""The same skills as SDK subagents — the declarative catalog of the harness's agent personas.

orchestrator.py runs one linear case (phase = a query() with a pinned skill prompt).
When you want to fan a fleet of collectors across N seeds concurrently (your
WebPivot/Workflows/ParallelBatch.md pattern), define them as subagents. AgentDefinition
fields are camelCase.

The `collector` persona below is now WIRED: `orchestrator.collect_fanout` instantiates exactly
this persona (WebPivot skill body + COLLECT_TOOLS + cheap model) once per seed and runs them
concurrently — reached via `run_case(..., collect_conc>1)` / the CLI `--fanout` flag. This module
stays the single declarative source for the persona definitions; `analyst`/`grapher` remain
available for a dispatch-driver query() that has the `Agent` tool. Kept separate so the linear
path stays simple.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # harness/ on path for sdk_compat
from sdk_compat import AgentDefinition  # real SDK or OpenAI-compat shim (HARNESS_BACKEND)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _skill(name: str) -> str:
    """Read a component's skill body.

    cti-expert vendors these components, and the vendoring convention renames each `SKILL.md` to
    `SKILL.reference.md` — the repo must contain exactly ONE `SKILL.md` (the root entrypoint), or
    Claude Code registers duplicate skills. Upstream has no such constraint and ships `SKILL.md`.

    So try the vendored name first, then the upstream one. Before this, the module raised
    FileNotFoundError at IMPORT time in a cti-expert checkout: `AGENTS` is built at module scope,
    so merely importing it blew up. Nothing in the shipped path imports it today
    (`orchestrator.collect_fanout` reimplements the collector persona), which is exactly why the
    breakage survived — a dormant module that cannot be imported is a landmine for whoever wires
    `analyst`/`grapher` up next, and no test would have caught it.
    """
    for fname in ("SKILL.reference.md", "SKILL.md"):
        p = os.path.join(ROOT, name, fname)
        if os.path.isfile(p):
            with open(p, encoding="utf-8") as f:
                return f.read()
    raise FileNotFoundError(
        f"no SKILL.reference.md or SKILL.md for component {name!r} under {ROOT} — "
        "the vendored engine is incomplete; re-sync per STRUCTURE.md")


AGENTS: dict[str, AgentDefinition] = {
    "collector": AgentDefinition(
        description="Extracts pivot artifacts from ONE url/host and ingests them. Use for fan-out.",
        prompt=_skill("WebPivot"),
        # Passive collectors only. Every one of these reads an archive, a CT log or a
        # third-party metadata endpoint — none touches the target beyond what pivot_extract
        # already does, so widening the fan-out costs no extra exposure. wayback_harvest is the
        # high-value addition: the tracker that clusters an estate has usually been SCRUBBED from
        # the live page and survives only in an old capture.
        tools=["mcp__collect__pivot_extract", "mcp__collect__kb_ingest",
               "mcp__collect__wayback_harvest", "mcp__collect__wayback_fetch",
               "mcp__collect__cert_pivot", "mcp__collect__msft_recon",
               "mcp__collect__threat_check"],
        model="haiku",   # mechanical collection -> cheap model
    ),
    "analyst": AgentDefinition(
        description="Correlates the KB, attributes clusters, assesses confidence. Read-only.",
        prompt=_skill("IntelAnalysis"),
        # rank_relations is the one that matters: it mechanizes "one artifact is a lead, two
        # independent ones are a cluster", which the analyst was otherwise applying from memory.
        # exposure_score is the SUBJECT counterpart to risk_signals' INFRASTRUCTURE score — the
        # prompt must keep them distinct in the write-up. All read-only.
        tools=["mcp__analyze__kb_query_shared", "mcp__analyze__risk_signals",
               "mcp__analyze__rank_relations", "mcp__analyze__exposure_score",
               "mcp__analyze__hash_id", "mcp__analyze__vuln_check"],
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
