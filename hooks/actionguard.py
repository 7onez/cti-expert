#!/usr/bin/env python3
"""actionguard.py — PreToolUse hook: a harness-layer confirmation gate on OUTBOUND actions.

WHY, GIVEN THE TOOLS ALREADY GATE THEMSELVES
--------------------------------------------
`submit()` in bp_anyrun refuses without `confirm=True`; the Engage tools refuse a non-synthetic
persona and stop at a CAPTCHA. Those gates are real, and this hook does not replace them.

It exists because those gates live in *vendored* code. `intel_engine/` is a one-way copy of an
upstream repo, and re-syncing it is a three-way merge over ~150 files where a deliberate local
behaviour can be reverted silently (see STRUCTURE.md — that is not hypothetical; three such
reversions were caught by hand on 2026-08-23). A gate that lives only inside the merged code is a
gate that a bad merge can delete without failing a single test.

This one sits above the tools, in cti-expert's own tree, and fires on the tool NAME. A vendor sync
cannot reach it.

WHAT IT DOES NOT DO
-------------------
It does not block. Every match returns `ask`, so you get the risk briefing and decide — the same
shape as the in-code preflight. Blocking outright would mean remembering to unlock before a
legitimate engagement run, and a rail you have to disable to work is a rail that gets disabled.

Detection stays free: `detect_login`, `make_persona`, `url_paths`, `passive_ssl` and ordinary
collection are NOT gated. Only the actions that touch the target in a way you cannot take back.

CONTRACT
--------
stdin : {"tool_name": "...", "tool_input": {...}}
stdout: {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                "permissionDecision": "ask"|"allow",
                                "permissionDecisionReason": "..."}}

Fails OPEN on an internal error — but note the direction of that risk is different here than in
leakguard: failing open on THIS hook means falling back to the in-code gate, which still refuses
without explicit confirmation. There is no configuration in which both are absent.
"""
import json
import os
import sys

REF = os.path.join(os.path.dirname(os.path.abspath(__file__)), "references",
                   "outbound_actions.json")

# Minimal safety net, used only if the reference file is missing or unparseable. Trimmed on
# purpose and in the CONSERVATIVE direction: the entries kept are the two that are irreversible
# in the strongest sense — a created account and a detonated sample.
_FALLBACK = {
    "mcp_tools": {"entries": {
        "engage_account": {"why": "Creates an account on the target (outbound, irreversible).",
                           "before": "Confirm the persona is synthetic and you are authorized."},
        "anyrun_submit": {"why": "Detonates a sample in a public sandbox (irreversible).",
                          "before": "A public task is world-readable. Ask the analyst first."},
    }},
    "bash_patterns": {"entries": [
        {"match": "--confirm-submission", "why": "Detonates the sample."},
        {"match": "en_engage.py", "why": "Registers/logs in on the target."},
    ]},
}


def _out(decision, reason=""):
    return json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                              "permissionDecision": decision,
                                              "permissionDecisionReason": reason}})


def load_ref():
    try:
        with open(REF, encoding="utf-8") as fh:
            d = json.load(fh)
        # a truncated file must not read as "nothing is gated"
        if d.get("mcp_tools", {}).get("entries") or d.get("bash_patterns", {}).get("entries"):
            return d
    except Exception:  # noqa: BLE001
        pass
    return _FALLBACK


def briefing(label, why, before):
    return (f"OUTBOUND ACTION — {label}\n\n"
            f"{why}\n\n"
            + (f"Before you approve: {before}\n\n" if before else "")
            + "This is attributable to you and cannot be undone. Approve only if the analyst has "
              "explicitly asked for it in this session.")


# Kept in step with _FALSEY in intel_engine/harness/audit.py. It cannot be imported — hooks/ is
# stdlib-only on purpose, so the guard still runs when the vendored engine is broken — so the
# values are duplicated deliberately. Divergence here runs PERMISSIVE: a spelling this set omits
# reads as truthy, i.e. as an opt-out, and silences the gate while the action still happens.
_FALSEY = {"", "0", "false", "no", "off", "none", "null"}


def _truthy(v):
    return str(v).strip().lower() not in _FALSEY


def outbound_now(spec, tool_input):
    """True when a tool whose DEFAULT path is outbound is in fact taking it on THIS call.

    `spec` names the opt-outs, never the flag: an env var that disables the behaviour, and any
    typed parameter that does the same. Anything else means the action happens.
    """
    env = spec.get("unless_env") or []
    for name in ([env] if isinstance(env, str) else env):
        if _truthy(os.environ.get(name, "")):
            return False
    for p in spec.get("unless_params") or []:
        if _truthy((tool_input or {}).get(p, "")):
            return False
    return True


def check_mcp(tool_name, tool_input, ref):
    """Match on the bare tool name so mcp__intel__x and mcp__other__x behave identically."""
    bare = tool_name.split("__")[-1]
    ent = (ref.get("mcp_tools") or {}).get("entries", {}).get(bare)
    if not ent:
        return None
    # A tool whose DEFAULT path is ALREADY outbound cannot be gated on flag text. The MCP surface
    # is typed, so a CLI flag never appears in tool_input, and the harness appends that flag inside
    # its own subprocess — so neither this check nor check_bash would ever see it, and the row
    # would read as coverage while allowing every call. Gate on the effective behaviour instead;
    # the opt-out, not the flag, is what makes it silent. `flag_required` still applies below for
    # the case where the default has been disabled.
    dflt = ent.get("outbound_by_default")
    if dflt and outbound_now(dflt, tool_input):
        return briefing(bare, dflt.get("why") or ent.get("why", ""),
                        dflt.get("before") or ent.get("before", ""))
    need = ent.get("flag_required")
    if need:
        blob = json.dumps(tool_input, ensure_ascii=False)
        if not any(f in blob for f in need):
            return None                      # the safe default path of a dual-mode tool
    return briefing(bare, ent.get("why", ""), ent.get("before", ""))


def check_bash(command, ref):
    for e in (ref.get("bash_patterns") or {}).get("entries", []):
        m = e.get("match")
        if m and m in command:
            return briefing(m, e.get("why", ""), e.get("before", ""))
    return None


def main():
    try:
        ev = json.load(sys.stdin)
    except Exception:  # noqa: BLE001
        print(_out("allow"))
        return 0

    tool = str(ev.get("tool_name") or "")
    ti = ev.get("tool_input") or {}
    ref = load_ref()

    reason = None
    if tool == "Bash":
        reason = check_bash(str(ti.get("command") or ""), ref)
    elif tool.startswith("mcp__"):
        reason = check_mcp(tool, ti, ref)

    print(_out("ask", reason) if reason else _out("allow"))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001 — fail open; the in-code gate still refuses
        print(f"actionguard: internal error, deferring to the in-code gate: {e}", file=sys.stderr)
        print(_out("allow", f"actionguard error: {e}"))
        sys.exit(0)
