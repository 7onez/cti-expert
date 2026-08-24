"""audit.py — the harness's tool-call GATE and LEDGER, shared by all three front-ends.

WHY THIS EXISTS
---------------
Two invariants were being asserted in comments and enforced nowhere:

  1. "the agent does not directly bypass permissions" — the SDK driver ran with
     `permission_mode="bypassPermissions"` and the only guardrails lived INSIDE individual
     tools (pivot_extract's hostile-egress refusal, bp_anyrun's submission gate). A tool that
     forgot to implement its own gate had nothing above it, and the two other front-ends
     (the OpenAI/DeepSeek shim, the stdio MCP server) shared none of that logic.
  2. "all high-risk actions leave evidence" — true for METERED API credits
     (MEMORY/api_usage.jsonl) and for model cost (run_cost.jsonl), but the tool calls
     themselves were only printed to stderr. A finished run's *decisions* were auditable;
     its *actions* were not.

This module is the one policy point both invariants need. It is deliberately front-end
neutral: it takes a tool name and its arguments, returns allow/deny, and appends one JSON
line per call to the ledger — regardless of who is calling.

  SDK driver (Anthropic)   orchestrator._phase installs a PreToolUse HOOK per phase
  DeepSeek / OpenAI shim   openai_backend.query calls gate() before invoking a handler
  Claude Code (stdio MCP)  mcp_server._call_tool calls gate() before invoking a handler

WHY A PreToolUse HOOK AND NOT `can_use_tool`
--------------------------------------------
`can_use_tool` looks like the right seam and is not: the SDK only consults it for calls that
would otherwise PROMPT the user. Two things the harness does on purpose both shadow it —
`permission_mode="bypassPermissions"`, and `allowed_tools` entries that allow a whole tool
(which is exactly what COLLECT_TOOLS / ANALYZE_TOOLS are). The SDK says so itself, in
`ClaudeAgentOptions.can_use_tool`'s docstring and by emitting `CanUseToolShadowedWarning`:
"To observe or gate *every* tool call regardless of permission rules, use a PreToolUse hook."
So the gate is a hook. The callback is built per phase as a CLOSURE over that phase's case and
label, because phases run CONCURRENTLY (collect fan-out, parallel cluster judgment) and the
hook fires on the SDK's own task — a module-global or a ContextVar would cross-contaminate.

WHAT IT DENIES (everything else is allowed, and still logged)
-------------------------------------------------------------
  * hostile posture + an OUTBOUND tool with no passive/proxy argument
  * an APPROVAL-REQUIRED tool (sandbox submission) without its env var set
  * a METERED call once the run's credit-spend budget is exhausted
The lists, the budget and the env-var map are DATA — see references/tool_policy.json — so an
analyst re-classifies a tool without editing this file. A denial is returned to the MODEL as
text, so it can adapt (re-call with passive=true / free_only=true) rather than dying.
"""
from __future__ import annotations

import contextvars
import datetime
import json
import os
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))            # harness/
ROOT = os.path.dirname(HERE)                                  # repo root
_WP = os.path.join(ROOT, "WebPivot", "tools")
if _WP not in sys.path:
    sys.path.append(_WP)                                      # append: never shadow harness/tools.py

try:
    from wp_refs import load_ref, ref_path                    # the shared RULE 3 loader
except Exception:                                             # noqa: BLE001 — degrade, never block a run
    def ref_path(module_file: str, name: str) -> str:
        return os.path.join(os.path.dirname(os.path.abspath(module_file)), "references", name)

    def load_ref(path: str, fallback: dict) -> dict:
        print(f"[audit] WARNING: wp_refs unavailable; {os.path.basename(path)} not read — "
              f"running on the minimal embedded policy.", file=sys.stderr)
        return dict(fallback)


# Minimal embedded policy. Deliberately CONSERVATIVE: on a broken/missing data file the gate
# still blocks hostile egress and still refuses sandbox submission — it just knows fewer tools.
_POLICY_FALLBACK = {
    "outbound_tools": ["pivot_extract", "impersonation_hunt", "anyrun_submit"],
    "passive_args": ["passive", "proxy", "free_only"],
    "metered_tools": ["pivot_extract", "reverse_whois", "intelx_search", "anyrun_lookup"],
    "free_only_args": ["free_only"],
    "metered_arg_triggers": ["whois_reverse", "fofa_full"],
    "approval_required_tools": {"anyrun_submit": "HARNESS_ALLOW_SUBMIT",
                                "misp_publish": "INTEL_MISP_PUBLISH"},
    "mutating_tools": ["kb_ingest", "reference_add", "misp_push", "misp_publish"],
    "redact_args": ["key", "api_key", "token", "password", "secret"],
    "budget": {"max_metered_calls_per_run": 60, "max_arg_chars": 200},
}

_P = load_ref(ref_path(__file__, "tool_policy.json"), _POLICY_FALLBACK)

OUTBOUND_TOOLS = set(_P["outbound_tools"])
PASSIVE_ARGS = set(_P["passive_args"])
METERED_TOOLS = set(_P["metered_tools"])
FREE_ONLY_ARGS = set(_P["free_only_args"])
METERED_ARG_TRIGGERS = set(_P["metered_arg_triggers"])
APPROVAL_REQUIRED = dict(_P["approval_required_tools"])
MUTATING_TOOLS = set(_P["mutating_tools"])
REDACT_ARGS = set(_P["redact_args"])
BUDGET = dict(_P["budget"])

MAX_METERED = int(os.environ.get("HARNESS_METERED_BUDGET")
                  or BUDGET.get("max_metered_calls_per_run", 60))
MAX_ARG_CHARS = int(BUDGET.get("max_arg_chars", 200))

# Same floor as tools.POLICY: an env-set hostile posture applies even to a front-end that has no
# phase loop to flip it (the stdio MCP server, an ad-hoc shim run).
_ENV_HOSTILE = os.environ.get("HARNESS_HOSTILE", "").strip().lower() in ("1", "true", "yes", "on")

# Ambient context for front-ends that execute tools on the CALLER's task (the OpenAI shim). The
# SDK hook path does NOT use this — it closes over its phase's values, because hook callbacks
# fire on the SDK's own task and concurrent phases would otherwise overwrite each other.
_CTX: contextvars.ContextVar[dict] = contextvars.ContextVar("harness_audit_ctx", default={})

_LOCK = threading.Lock()
_COUNTS = {"total": 0, "allowed": 0, "denied": 0, "metered": 0, "outbound": 0, "mutating": 0}
_DENIALS: list[str] = []


def set_context(*, case: str | None = None, phase: str | None = None,
                backend: str | None = None, hostile: bool | None = None) -> None:
    """Bind the ambient run context for the current async task (shim + MCP paths)."""
    ctx = dict(_CTX.get() or {})
    for k, v in (("case", case), ("phase", phase), ("backend", backend), ("hostile", hostile)):
        if v is not None:
            ctx[k] = v
    _CTX.set(ctx)


def bare(tool_name: str) -> str:
    """`mcp__collect__pivot_extract` -> `pivot_extract`. The policy file names bare tools, so one
    entry covers the SDK's fully-qualified name and the shim's/MCP's bare one."""
    return (tool_name or "").split("__")[-1]


# A flag argument is SET unless it is explicitly false-ish. This matters because these arguments
# are not all booleans: `passive=true` is a flag, but `proxy=http://127.0.0.1:8080` is a value whose
# mere presence is the instruction. Testing `v is True` treated every real proxy as absent and
# denied the very call that was safe.
_FALSEY = {"", "0", "false", "no", "off", "none", "null"}


def _truthy(args: dict, names: set) -> bool:
    for n in names:
        v = (args or {}).get(n)
        if v is None or v is False:
            continue
        if isinstance(v, str) and v.strip().lower() in _FALSEY:
            continue
        if isinstance(v, (int, float)) and v == 0:
            continue
        return True
    return False


def classify(tool_name: str, args: dict) -> list[str]:
    """The risk classes this call belongs to — the ledger's `classes` field."""
    t = bare(tool_name)
    out = []
    if t in OUTBOUND_TOOLS and not _truthy(args, PASSIVE_ARGS):
        out.append("outbound")
    if t in METERED_TOOLS and not _truthy(args, FREE_ONLY_ARGS):
        out.append("metered")
        if _truthy(args, METERED_ARG_TRIGGERS):
            out.append("metered-expanded")
    if t in APPROVAL_REQUIRED:
        out.append("approval-required")
    if t in MUTATING_TOOLS:
        out.append("mutating")
    return out


def decide(tool_name: str, args: dict, *, hostile: bool | None = None) -> tuple[bool, str, list]:
    """(allow, reason, classes). Pure — no logging, no counter mutation, so it is testable."""
    t = bare(tool_name)
    args = args or {}
    classes = classify(tool_name, args)
    if hostile is None:
        hostile = bool((_CTX.get() or {}).get("hostile", _ENV_HOSTILE))

    env = APPROVAL_REQUIRED.get(t)
    if env and os.environ.get(env, "").strip().lower() not in ("1", "true", "yes", "on"):
        return (False,
                f"{t} is attributable and IRREVERSIBLE — once it has happened nothing can recall "
                f"it (a sandbox detonation tells the operator they are being analysed; a "
                f"published MISP event syncs to every peer server). It requires an explicit "
                f"human approval this run does not have. Ask the analyst; if they agree, the run "
                f"must be re-launched with {env}=1. Do not retry.", classes)

    if hostile and "outbound" in classes:
        return (False,
                f"BLOCKED by egress policy: the target is HOSTILE and {t} would touch its "
                f"infrastructure from the analyst's IP. Re-call with passive=true (archive / "
                f"third-party sources only) or proxy=<host> — do not retry unchanged.", classes)

    if "metered" in classes:
        with _LOCK:
            spent = _COUNTS["metered"]
        if spent >= MAX_METERED:
            return (False,
                    f"metered-call budget exhausted for this run ({spent}/{MAX_METERED} "
                    f"credit-spending calls). Third-party credits are per-account and do not roll "
                    f"over. Re-call with free_only=true to continue on keyless sources, or hand "
                    f"the remaining pivots to the analyst as metered leads.", classes)

    return True, "", classes


def _ledger_path(case: str | None) -> str:
    """cases/<case>/tool_calls.jsonl, or MEMORY/tool_calls.jsonl when no case is in scope
    (interactive Claude Code use). Both stores are git-ignored."""
    if case:
        return os.path.join(ROOT, "cases", str(case), "tool_calls.jsonl")
    return os.path.join(ROOT, "MEMORY", "tool_calls.jsonl")


def _safe_args(args: dict) -> dict:
    """Argument preview for the ledger: credentials replaced, long values truncated. The ledger is
    an audit trail of WHAT was called, not a copy of the payload."""
    out = {}
    for k, v in (args or {}).items():
        if k.lower() in REDACT_ARGS:
            out[k] = "<redacted>"
            continue
        s = v if isinstance(v, (int, float, bool)) or v is None else str(v)
        if isinstance(s, str) and len(s) > MAX_ARG_CHARS:
            s = s[:MAX_ARG_CHARS] + f"…(+{len(str(v)) - MAX_ARG_CHARS} chars)"
        out[k] = s
    return out


def record(tool_name: str, args: dict, *, allowed: bool, reason: str, classes: list,
           case: str | None = None, phase: str | None = None,
           backend: str | None = None) -> None:
    """Append one line to the ledger. Never raises: an unwritable ledger must not kill a case —
    it warns once to stderr and the run continues (the alternative, a run that dies at round 4
    because cases/ went read-only, loses far more evidence than it protects)."""
    ctx = _CTX.get() or {}
    case = case or ctx.get("case")
    rec = {
        "ts": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "case": case, "phase": phase or ctx.get("phase"),
        "backend": backend or ctx.get("backend") or "?",
        "tool": bare(tool_name), "tool_fq": tool_name,
        "decision": "allow" if allowed else "DENY",
        "classes": classes, "args": _safe_args(args),
    }
    if reason:
        rec["reason"] = reason
    path = _ledger_path(case)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with _LOCK:                                    # concurrent collectors share one ledger file
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError as e:
        if not getattr(record, "_warned", False):
            print(f"[audit] WARNING: tool-call ledger unwritable ({e}); the run continues but "
                  f"its actions are NOT being recorded.", file=sys.stderr)
            record._warned = True                      # type: ignore[attr-defined]


def gate(tool_name: str, args: dict, *, case: str | None = None, phase: str | None = None,
         backend: str | None = None, hostile: bool | None = None) -> tuple[bool, str]:
    """Decide + count + record, in one call. Returns (allow, reason_if_denied).

    This is the ONLY entry point a front-end needs. `case`/`phase` are explicit for callers that
    run concurrently (the SDK hook closure); everything else may rely on the ambient context."""
    allowed, reason, classes = decide(tool_name, args, hostile=hostile)
    with _LOCK:
        _COUNTS["total"] += 1
        _COUNTS["allowed" if allowed else "denied"] += 1
        if allowed:                                    # only a call that actually RAN can spend
            for c in ("metered", "outbound", "mutating"):
                if c in classes:
                    _COUNTS[c] += 1
        else:
            _DENIALS.append(f"{bare(tool_name)}: {reason.split('.')[0]}")
    record(tool_name, args, allowed=allowed, reason=reason, classes=classes,
           case=case, phase=phase, backend=backend)
    return allowed, reason


def counts() -> dict:
    with _LOCK:
        return dict(_COUNTS)


def summary(case: str | None = None) -> str:
    """One block for the end-of-run banner — the counterpart to the cost ledger."""
    c = counts()
    if not c["total"]:
        return ""
    lines = [f"  {'tool calls':<12} {c['total']:>10}   "
             f"({c['metered']} metered, {c['outbound']} outbound, {c['mutating']} KB-mutating)"]
    if c["denied"]:
        lines.append(f"  {'DENIED':<12} {c['denied']:>10}   by the gate — "
                     + "; ".join(dict.fromkeys(_DENIALS))[:160])
    lines.append(f"  (ledger → {os.path.relpath(_ledger_path(case), ROOT)})")
    return "\n".join(lines)


def reset() -> None:
    """Zero the per-run counters (tests, and any driver that runs several cases in one process)."""
    with _LOCK:
        for k in _COUNTS:
            _COUNTS[k] = 0
        _DENIALS.clear()


# ------------------------------------------------------------------ reading the ledger back
# Writing an audit trail nobody can read is theatre. This half answers "what did this case
# actually DO", the way api_usage.py answers "what did it spend". Exposed as the `tool_calls`
# MCP tool (harness/tools.py) so both front-ends reach it without a bash line.

def read_ledger(case: str | None = None, *, every_case: bool = False) -> tuple[list, list]:
    """Return (records, sources_read). Malformed lines are skipped, not fatal — a ledger truncated
    by a kill mid-write must still be readable for everything before the tear."""
    paths = []
    if every_case:
        cases_dir = os.path.join(ROOT, "cases")
        if os.path.isdir(cases_dir):
            paths += sorted(os.path.join(cases_dir, d, "tool_calls.jsonl")
                            for d in os.listdir(cases_dir)
                            if os.path.isfile(os.path.join(cases_dir, d, "tool_calls.jsonl")))
        paths.append(os.path.join(ROOT, "MEMORY", "tool_calls.jsonl"))
    else:
        paths.append(_ledger_path(case))
    recs, read = [], []
    for p in paths:
        if not os.path.isfile(p):
            continue
        read.append(p)
        with open(p, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    recs.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    recs.sort(key=lambda r: r.get("ts") or "")
    return recs, read


def _tally(recs: list, key) -> list:
    counts: dict = {}
    for r in recs:
        k = key(r)
        for k in (k if isinstance(k, list) else [k]):
            if k:
                counts[k] = counts.get(k, 0) + 1
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))


def report(case: str | None = None, *, every_case: bool = False, last: int = 0,
           denied_only: bool = False, tool: str | None = None, since: str | None = None) -> str:
    """The human-readable ledger report. Absence is reported as ABSENCE, never as zero activity:
    a missing ledger means the case predates the gate or no tool has run — it is not evidence that
    nothing happened, and saying so is the same discipline as the keyless-capability banner."""
    recs, read = read_ledger(case, every_case=every_case)
    where = case or ("every case + MEMORY" if every_case else "MEMORY (no case scope)")
    if not read:
        return (f"no tool-call ledger found for {where}.\n"
                f"  This is ABSENCE OF RECORD, not evidence of no activity: the case may predate "
                f"the gate, or no tool has run yet.\n"
                f"  Expected at: {os.path.relpath(_ledger_path(case), ROOT)}")
    if since:
        recs = [r for r in recs if (r.get("ts") or "") >= since]
    if tool:
        recs = [r for r in recs if bare(r.get("tool", "")) == bare(tool)]
    denied = [r for r in recs if r.get("decision") == "DENY"]
    if denied_only:
        recs = denied
    if not recs:
        return f"tool-call ledger — {where}: no calls match that filter ({len(read)} file(s) read)."

    allowed = [r for r in recs if r.get("decision") != "DENY"]
    out = [f"tool-call ledger — {where}   ({len(read)} file(s))",
           f"  window: {recs[0].get('ts')} → {recs[-1].get('ts')}   ·   {len(recs)} call(s): "
           f"{len(allowed)} allowed, {len(denied)} DENIED"]

    out.append("\n  risk class  (allowed calls only — a denied call never ran, so it spent nothing)")
    cls = _tally(allowed, lambda r: r.get("classes") or [])
    out += [f"    {k:<18} {v:>5}" for k, v in cls] or ["    (none)"]

    out.append("\n  by tool")
    for k, v in _tally(recs, lambda r: r.get("tool")):
        d = sum(1 for r in denied if r.get("tool") == k)
        out.append(f"    {k:<24} {v:>5}" + (f"   ({d} DENIED)" if d else ""))

    by_phase = _tally(recs, lambda r: r.get("phase"))
    if len(by_phase) > 1:
        out.append("\n  by phase")
        out += [f"    {k:<24} {v:>5}" for k, v in by_phase]
    if every_case or not case:
        by_case = _tally(recs, lambda r: r.get("case") or "(no case)")
        if len(by_case) > 1:
            out.append("\n  by case")
            out += [f"    {k:<24} {v:>5}" for k, v in by_case]

    if denied:
        out.append(f"\n  DENIED ({len(denied)}) — blocked by the gate BEFORE the tool ran")
        for r in denied[-20:]:
            out.append(f"    {r.get('ts')}  {r.get('phase') or '-'}  {r.get('tool')}  "
                       f"{json.dumps(r.get('args') or {}, ensure_ascii=False)[:90]}")
            out.append(f"        → {(r.get('reason') or '').splitlines()[0][:150]}")
    if last:
        out.append(f"\n  last {min(last, len(recs))} call(s)")
        for r in recs[-last:]:
            out.append(f"    {r.get('ts')}  {r.get('decision'):<5} {r.get('phase') or '-':<12} "
                       f"{r.get('tool'):<22} {json.dumps(r.get('args') or {}, ensure_ascii=False)[:70]}")
    return "\n".join(out)


def _main() -> int:
    import argparse
    ap = argparse.ArgumentParser(
        description="Read back the harness tool-call ledger — what a case actually DID "
                    "(the action counterpart to api_usage.py's credit ledger).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("report", help="summarise the ledger")
    r.add_argument("case", nargs="?", default=None,
                   help="case id; omit for the interactive MEMORY ledger")
    r.add_argument("--all", action="store_true", help="every case plus MEMORY")
    r.add_argument("--last", type=int, default=0, help="also list the N most recent calls")
    r.add_argument("--denied", action="store_true", help="only calls the gate blocked")
    r.add_argument("--tool", default=None, help="filter to one tool name")
    r.add_argument("--since", default=None, help="ISO timestamp/date lower bound (YYYY-MM-DD)")
    r.add_argument("--json", action="store_true", help="emit the raw records instead")
    a = ap.parse_args()
    if a.json:
        recs, _ = read_ledger(a.case, every_case=a.all)
        print(json.dumps(recs, ensure_ascii=False, indent=2))
        return 0
    print(report(a.case, every_case=a.all, last=a.last, denied_only=a.denied,
                 tool=a.tool, since=a.since))
    return 0


if __name__ == "__main__":
    sys.exit(_main())
