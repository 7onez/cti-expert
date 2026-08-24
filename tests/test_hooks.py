#!/usr/bin/env python3
"""test_hooks.py — the Claude Code hooks are safety rails, so they get the same treatment as one.

WHAT THESE HOOKS ARE FOR
------------------------
cti-expert runs mostly inside Claude Code, which writes files continuously and commits rarely. Two
of its safety properties were enforced at the wrong layer for that:

  * RULE 1 (no case data in a tracked file) ran only as a *git* pre-commit hook — so a leak could
    sit in the working tree all session, and `git commit --no-verify` skipped it outright.
  * the outbound-action gates (create an account on the target, detonate a sample) lived only
    inside `intel_engine/`, which is VENDORED. Re-syncing it is a three-way merge where a
    deliberate local behaviour can be reverted silently.

`hooks/leakguard.py` and `hooks/actionguard.py` move both above the tools, into cti-expert's own
tree. That only helps if they keep working, hence this file.

WHAT IS ASSERTED, AND WHY EACH DIRECTION MATTERS
------------------------------------------------
A guard is only proven by testing BOTH directions. A hook that denies everything passes a
"catches the bad case" test and is useless; a hook that allows everything passes a "does not
annoy me" test and is worse than useless. So every rail here is asserted to fire on the thing it
targets AND to stay silent on the neighbouring thing it must not touch:

  deny a real indicator in a tracked file   / allow the approved placeholders
  allow case data in the git-ignored stores / deny the same value in a tracked file
  ask on engage_account                     / allow on detect_login (passive)
  ask on pivot_extract --submit             / allow on plain pivot_extract
  ask on `intel.py engage `                 / allow on `intel.py engage-report` (local render)

Both hooks must also FAIL OPEN on malformed input — a crashing hook that defaults to deny would
brick every write in the repo, and the git hook plus scripts/audit.sh remain as the backstop.
"""
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOKS = os.path.join(ROOT, "hooks")
LEAKGUARD = os.path.join(HOOKS, "leakguard.py")
ACTIONGUARD = os.path.join(HOOKS, "actionguard.py")
SESSIONGUARD = os.path.join(HOOKS, "sessionguard.py")
HOOKS_JSON = os.path.join(HOOKS, "hooks.json")
PLUGIN_JSON = os.path.join(ROOT, ".claude-plugin", "plugin.json")

# The probe payload: one value per RULE 1 pattern — personal-provider email, GTM container, ETH
# wallet, TRON wallet, case id.
#
# Two deliberate properties, and the second one needs explaining:
#
#   1. Every value is DEGENERATE — a repeated character, a reserved-future year. There is nothing
#      here to leak: `0x` followed by forty a's is not an address anyone holds, and it exists only
#      to match a regex.
#   2. They are ASSEMBLED AT RUNTIME, so no complete indicator literal appears in this file. That
#      keeps this test from tripping the very gate it tests, without needing an exemption in
#      scripts/leakcheck.sh — and an exemption is the thing to avoid, because a file with a
#      standing free pass is a file where a REAL indicator could later sit unnoticed.
#
# This is not a technique for hiding case data. It is safe here only because the values are
# synthetic by construction. Never split a real indicator to get it past the gate — that is the
# exact behaviour RULE 1 exists to prevent.
_A = "a"
LEAK = " ".join([
    "registrant probe@" + "gmail" + ".com",
    "GTM-" + "A" * 7,
    "0x" + _A * 40,
    "T" + _A * 33,
    "CASE-" + "2099",
])
CLEAN = "registrant@example.com on CASE-0001 with G-XXXXXXXXXX and GTM-XXXXXXX"

TRACKED = os.path.join(ROOT, "techniques", "_hookprobe.md")      # never written, path only
IGNORED = os.path.join(ROOT, "intel_engine", "cases", "CASE-0001", "notes.md")


def _decide(script, event):
    """Run a hook the way Claude Code does and return its permissionDecision."""
    r = subprocess.run([sys.executable, script], input=json.dumps(event),
                       capture_output=True, text=True, timeout=60)
    try:
        return json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"]
    except Exception:  # noqa: BLE001
        return f"UNPARSEABLE(rc={r.returncode}, out={r.stdout[:120]!r}, err={r.stderr[:120]!r})"


def _write(path, content, tool="Write", **extra):
    ti = {"file_path": path, "content": content}
    ti.update(extra)
    return {"tool_name": tool, "tool_input": ti}


def check():
    """Return (passed, failed, [(status, label)]) — the tools/eval unit-module contract."""
    out, passed, failed = [], 0, 0

    def ok(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1
            out.append(("ok", label))
        else:
            failed += 1
            out.append(("FAIL", label))

    for p in (LEAKGUARD, ACTIONGUARD, SESSIONGUARD, HOOKS_JSON, PLUGIN_JSON):
        ok(os.path.exists(p), f"{os.path.relpath(p, ROOT)} present")
    if not all(os.path.exists(p) for p in (LEAKGUARD, ACTIONGUARD, HOOKS_JSON, PLUGIN_JSON)):
        return passed, failed, out

    # ---- leakguard: fires on a tracked file ------------------------------------------------
    ok(_decide(LEAKGUARD, _write(TRACKED, LEAK)) == "deny",
       "leakguard DENIES case data written to a tracked file")
    ok(_decide(LEAKGUARD, _write(TRACKED, CLEAN)) == "allow",
       "leakguard ALLOWS the approved placeholders (no crying wolf)")
    # An Edit moves text as much as it adds it; scanning only new_string would let a leak be
    # relocated past the guard.
    ok(_decide(LEAKGUARD, {"tool_name": "Edit",
                           "tool_input": {"file_path": TRACKED, "old_string": LEAK,
                                          "new_string": "redacted"}}) == "deny",
       "leakguard scans an Edit's old_string, not just the new text")
    # A case id in the FILENAME is a leak even when the body is innocent.
    ok(_decide(LEAKGUARD, _write(os.path.join(ROOT, "analysis", "CASE-" + "2099" + ".md"),
                                 "nothing here")) == "deny",
       "leakguard catches a case id hidden in the file PATH")

    # ---- leakguard: stays out of the way where case data BELONGS ----------------------------
    ok(_decide(LEAKGUARD, _write(IGNORED, LEAK)) == "allow",
       "leakguard ALLOWS case data in the git-ignored case store")
    ok(_decide(LEAKGUARD, _write("/tmp/analyst-scratch.md", LEAK)) == "allow",
       "leakguard ALLOWS writes outside any cti-expert checkout")

    # ---- leakguard: fails open --------------------------------------------------------------
    r = subprocess.run([sys.executable, LEAKGUARD], input="not json",
                       capture_output=True, text=True, timeout=30)
    ok(json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] == "allow",
       "leakguard fails OPEN on malformed input (a broken hook must not brick the repo)")

    # ---- actionguard: asks on the irreversible ones ------------------------------------------
    for tool in ("engage_account", "harvest_authenticated", "anyrun_submit"):
        ok(_decide(ACTIONGUARD, {"tool_name": f"mcp__intel__{tool}", "tool_input": {}}) == "ask",
           f"actionguard ASKS on {tool}")
    ok(_decide(ACTIONGUARD, {"tool_name": "mcp__other__engage_account",
                             "tool_input": {}}) == "ask",
       "actionguard matches the bare tool name, so a renamed MCP server is still gated")

    # ---- actionguard: silent on passive / local work -----------------------------------------
    for tool in ("detect_login", "make_persona", "url_paths", "passive_ssl", "kb_cluster"):
        ok(_decide(ACTIONGUARD, {"tool_name": f"mcp__intel__{tool}", "tool_input": {}}) == "allow",
           f"actionguard stays silent on {tool} (detection is free)")

    # ---- actionguard: dual-mode tools gate on the FLAG, not the tool -------------------------
    ok(_decide(ACTIONGUARD, {"tool_name": "mcp__intel__pivot_extract",
                             "tool_input": {"url": "https://site-a.example"}}) == "allow",
       "actionguard allows ordinary pivot_extract collection")
    ok(_decide(ACTIONGUARD, {"tool_name": "mcp__intel__pivot_extract",
                             "tool_input": {"url": "https://site-a.example",
                                            "flags": "--submit"}}) == "ask",
       "actionguard asks on pivot_extract --submit (it publishes the URL)")

    # ---- actionguard: dissemination (IntelShare) ---------------------------------------------
    # MISP splits into two decisions and the gate must respect that split. `push` STAGES an
    # organisation-only, unpublished event — a real write to a shared system, still deletable.
    # `publish` syncs it to peers and CANNOT be recalled; every attribute becomes somebody else's
    # blocking rule. Both ask. Building the event locally and searching the instance do NOT.
    for tool in ("misp_push", "misp_publish"):
        ok(_decide(ACTIONGUARD, {"tool_name": f"mcp__intel__{tool}", "tool_input": {}}) == "ask",
           f"actionguard ASKS on {tool}")
    for tool in ("misp_export", "misp_search", "collection_gaps"):
        ok(_decide(ACTIONGUARD, {"tool_name": f"mcp__intel__{tool}", "tool_input": {}}) == "allow",
           f"actionguard stays silent on {tool} (local build / read-only)")

    # ---- actionguard: the shell front-end is covered too -------------------------------------
    def bash(cmd):
        return _decide(ACTIONGUARD, {"tool_name": "Bash", "tool_input": {"command": cmd}})

    ok(bash("python3 bp_anyrun.py submit s.bin --confirm-submission") == "ask",
       "actionguard asks on the ANY.RUN detonation flag from the shell")
    ok(bash("python3 scripts/backend/intel.py engage https://site-a.example") == "ask",
       "actionguard asks on `intel.py engage <url>`")
    ok(bash("python3 scripts/backend/intel.py engage-harvest") == "ask",
       "actionguard asks on `intel.py engage-harvest`")
    # The near-miss that decides whether this rail survives contact with daily use.
    ok(bash("python3 scripts/backend/intel.py engage-report -o out.md") == "allow",
       "actionguard does NOT ask on `intel.py engage-report` (local render, no egress)")
    ok(bash("python3 IntelShare/tools/sh_misp.py publish 42") == "ask",
       "actionguard asks on `sh_misp.py publish` from the shell")
    ok(bash("python3 scripts/backend/intel.py misp push") == "ask",
       "actionguard asks on `intel.py misp push`")
    # The near-misses that decide whether the MISP rail survives daily use.
    ok(bash("python3 scripts/backend/intel.py misp keycheck") == "allow",
       "actionguard does NOT ask on `intel.py misp keycheck` (credential probe)")
    ok(bash("python3 scripts/backend/intel.py misp-export CASE-0001") == "allow",
       "actionguard does NOT ask on `intel.py misp-export` (builds the event locally)")
    ok(bash("python3 scripts/backend/intel.py kb --stats") == "allow",
       "actionguard stays silent on ordinary engine commands")
    ok(bash("ls -la") == "allow", "actionguard stays silent on ordinary shell")

    r = subprocess.run([sys.executable, ACTIONGUARD], input="not json",
                       capture_output=True, text=True, timeout=30)
    ok(json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] == "allow",
       "actionguard fails OPEN on malformed input (the in-code gate still refuses)")

    # ---- the reference data must not be able to silently empty the gate ----------------------
    ref = os.path.join(HOOKS, "references", "outbound_actions.json")
    ok(os.path.exists(ref), "hooks/references/outbound_actions.json present")
    if os.path.exists(ref):
        d = json.load(open(ref, encoding="utf-8"))
        names = set((d.get("mcp_tools") or {}).get("entries", {}))
        for must in ("engage_account", "anyrun_submit", "harvest_authenticated",
                     "misp_push", "misp_publish"):
            ok(must in names, f"reference data still gates {must}")

    # ---- the wiring: a hook nobody registered is a comment that runs -------------------------
    hj = json.load(open(HOOKS_JSON, encoding="utf-8"))
    pre = hj.get("hooks", {}).get("PreToolUse", [])
    wired = " ".join(json.dumps(g) for g in pre)
    ok("leakguard.py" in wired, "hooks.json registers leakguard on PreToolUse")
    ok("actionguard.py" in wired, "hooks.json registers actionguard on PreToolUse")
    ok(any("Write" in (g.get("matcher") or "") for g in pre),
       "leakguard's matcher covers Write")
    ok(any("Bash" in (g.get("matcher") or "") for g in pre),
       "actionguard's matcher covers Bash")
    ok("sessionguard.py" in json.dumps(hj.get("hooks", {}).get("SessionStart", [])),
       "hooks.json registers sessionguard on SessionStart")
    # Exec form (command + args) rather than a shell string: ${CLAUDE_PLUGIN_ROOT} is substituted
    # per-element as a plain string, so a path containing a quote or $ never reaches a parser.
    every = [h for g in pre for h in g.get("hooks", [])]
    ok(all(isinstance(h.get("args"), list) for h in every),
       "every hook uses exec form (args list), so plugin paths are never shell-parsed")
    ok(all("${CLAUDE_PLUGIN_ROOT}" in " ".join(h.get("args", [])) for h in every),
       "hook paths are plugin-relative, not hardcoded to one machine")

    pj = json.load(open(PLUGIN_JSON, encoding="utf-8"))
    for k in ("name", "description", "version"):
        ok(bool(pj.get(k)), f"plugin.json declares {k}")
    ok(pj.get("hooks") == "./hooks/hooks.json", "plugin.json points at hooks/hooks.json")
    ok("intel" in (pj.get("mcpServers") or {}), "plugin.json ships the intel MCP server")
    ok("${CLAUDE_PLUGIN_ROOT}" in json.dumps(pj.get("mcpServers")),
       "the bundled MCP server path is plugin-relative")

    return passed, failed, out


_PASSED, _FAILED, _LINES = check()


def test_hooks():
    """pytest entry point — the module body does the work at import time."""
    assert not _FAILED, [l for s, l in _LINES if s != "ok"]


if __name__ == "__main__":
    for status, label in _LINES:
        print(f"{'  ok  ' if status == 'ok' else '  FAIL'} {label}")
    print()
    if _FAILED:
        print(f"FAIL — Claude Code hooks ({_PASSED} passed, {_FAILED} failed)")
        sys.exit(1)
    print(f"PASS — Claude Code hooks ({_PASSED} checks: RULE 1 write-time gate fires on tracked "
          f"files and stays out of the case stores, outbound actions ask, passive work is silent, "
          f"both hooks fail open, and the plugin wiring is machine-independent)")
