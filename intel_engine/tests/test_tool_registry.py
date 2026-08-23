#!/usr/bin/env python3
"""
test_tool_registry.py — the gate on RULE 2: the two front-ends must expose the SAME tools.

Run:  python3 tests/test_tool_registry.py
      python3 tools/eval/run_eval.py          (runs as part of the regression gate)

WHAT THIS PROTECTS
------------------
A capability reaches the model through two independent paths and they are maintained differently:

  - the **stdio MCP server** (`harness/mcp_server.py`) AUTO-DISCOVERS every `@tool`, so a new tool
    appears in Claude Code the moment it is decorated — no second edit, nothing to forget;
  - the **SDK orchestrator** takes an explicit `create_sdk_mcp_server(tools=[...])` list AND a
    separate `allowed_tools` allowlist, both hand-maintained.

So the default failure is silent and one-directional: a tool works perfectly in Claude Code and
does not exist for the SDK harness. Nothing errors — the phase prompt simply never gets the
capability, and a run quietly collects less than the author intended. The mirror failure is worse:
an allowlist entry naming a tool no server exposes tells the model it may call something that
isn't there, so the model spends a turn discovering the tool is missing.

This test asserts the three lists agree exactly, which is the only way that stays true.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "harness", "tools.py")


def _decorated_tools(src: str):
    """Every name declared with @tool(...) — the ground truth the stdio server auto-discovers."""
    return re.findall(r'@tool\(\s*\n\s*"([a-z0-9_]+)"', src)


def _server_tools(src: str, server: str):
    """The python identifiers passed to create_sdk_mcp_server("<server>", tools=[...])."""
    m = re.search(r'create_sdk_mcp_server\(\s*\n?\s*"%s",\s*tools=\[(.*?)\]\)' % server, src, re.S)
    if not m:
        return set()
    return {t.strip() for t in m.group(1).replace("\n", " ").split(",") if t.strip()}


def _allowlist(src: str, const: str, prefix: str):
    """The bare tool names in COLLECT_TOOLS / ANALYZE_TOOLS."""
    m = re.search(r"%s = \[(.*?)\]" % const, src, re.S)
    if not m:
        return set()
    return set(re.findall(r'"mcp__%s__(\w+)"' % prefix, m.group(1)))


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

    src = open(SRC, encoding="utf-8").read()
    declared = _decorated_tools(src)
    ok(len(declared) > 20, f"found the @tool declarations ({len(declared)})")
    ok(len(declared) == len(set(declared)), "no tool name is declared twice")

    collect_srv, analyze_srv = _server_tools(src, "collect"), _server_tools(src, "analyze")
    ok(bool(collect_srv) and bool(analyze_srv), "both SDK servers declare a tools=[...] list")

    served = collect_srv | analyze_srv
    # 1. Every declared tool is served by exactly one SDK server.
    missing = sorted(set(declared) - served)
    ok(not missing,
       "every @tool is in an SDK server — else it works in Claude Code and is INVISIBLE to the "
       "SDK harness" + (f" (orphans: {missing})" if missing else ""))
    both = sorted(collect_srv & analyze_srv)
    ok(not both, f"no tool is served by BOTH servers{f' (dupes: {both})' if both else ''}")

    # 2. Everything a server serves is a real declared tool (catches a renamed/removed function).
    ghosts = sorted(t for t in served if t not in declared)
    ok(not ghosts, f"no server lists a non-existent tool{f' (ghosts: {ghosts})' if ghosts else ''}")

    # 3. The allowlists match their servers exactly, in both directions.
    for const, prefix, srv in (("COLLECT_TOOLS", "collect", collect_srv),
                               ("ANALYZE_TOOLS", "analyze", analyze_srv)):
        allow = _allowlist(src, const, prefix)
        not_allowed = sorted(srv - allow)
        not_served = sorted(allow - srv)
        ok(not not_allowed,
           f"{const}: every tool the server exposes is allowlisted"
           + (f" (served but not allowlisted: {not_allowed})" if not_allowed else ""))
        ok(not not_served,
           f"{const}: every allowlisted entry is actually served — an entry with no tool tells "
           "the model it may call something that does not exist"
           + (f" (allowlisted but not served: {not_served})" if not_served else ""))

    # 4. Every tool carries a description the model can route on. RULE 2 says the description IS
    #    the interface: an empty or stub one is a tool the model will never choose correctly.
    thin = re.findall(r'@tool\(\s*\n\s*"([a-z0-9_]+)",\s*\n\s*"([^"]{0,80})"\s*\n', src)
    ok(not thin, f"no tool has a stub description{f' ({[t[0] for t in thin]})' if thin else ''}")

    # 5. The SDK PHASE PROMPTS must not hardcode a tool roster.
    #    A prompt that says "you have ONLY (a, b, c)" while the server provides fourteen is a
    #    silent capability cut: the model believes the sentence and never calls the rest. This is
    #    how the collect phase quietly stopped reaching half its collectors. Naming a tool as
    #    GUIDANCE is fine; claiming the list is exhaustive is not.
    pdir = os.path.join(ROOT, "harness", "prompts")
    for fn in sorted(os.listdir(pdir)) if os.path.isdir(pdir) else []:
        if not fn.endswith(".md"):
            continue
        body = open(os.path.join(pdir, fn), encoding="utf-8").read()
        roster = re.search(r"ONLY the provided tools\s*\(([^)]*)\)", body)
        ok(not roster,
           f"prompts/{fn} does not claim an exhaustive tool roster"
           + (f" (found: {roster.group(1)[:60]}…)" if roster else ""))
        # Any tool-shaped name it DOES mention must still exist — catches a rename that leaves a
        # dead nudge behind ("call pivot_extract" after the tool became something else).
        stale = {n for n in re.findall(r"\b([a-z][a-z0-9_]{4,})\b", body)
                 if n.endswith(("_extract", "_ingest", "_cluster", "_probe", "_search"))
                 and n not in declared}
        ok(not stale, f"prompts/{fn} mentions no renamed/removed tool"
                      + (f" (stale: {sorted(stale)})" if stale else ""))

    return passed, failed, out


def main():
    passed, failed, lines = check()
    for status, label in lines:
        print(f"  {'ok  ' if status == 'ok' else 'FAIL'} {label}")
    print(f"\n{'PASS' if not failed else 'FAIL'} — {passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
