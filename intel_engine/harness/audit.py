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
  * an APPROVAL-REQUIRED tool (sandbox submission) without its env var set — EXCEPT its offline
    briefing branch (see references/tool_policy.json → approval_briefing), so the risk briefing
    the two-step gate depends on stays reachable to show the analyst before a confirmed submit
  * a METERED call once the run's credit-spend budget is exhausted
The lists, the budget and the env-var map are DATA — see references/tool_policy.json — so an
analyst re-classifies a tool without editing this file. A denial is returned to the MODEL as
text, so it can adapt (re-call with passive=true / free_only=true) rather than dying.
"""
from __future__ import annotations

import contextvars
import datetime
import json
import math
import os
import re
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
                                "webamon_scan": "HARNESS_ALLOW_SUBMIT",
                                "misp_publish": "INTEL_MISP_PUBLISH"},
    # Conservative minimum: NO briefing exemption when the data file is unreadable, so an
    # approval-required tool stays fully gated rather than opening a branch the fallback cannot see.
    "approval_briefing": {},
    "mutating_tools": ["kb_ingest", "reference_add", "misp_push", "misp_publish"],
    # Name FRAGMENTS, matched as substrings of the normalised argument name (see _secret_key).
    "redact_args": ["key", "token", "secret", "pass", "auth"],
    # Declared BOOLEAN parameters whose names happen to contain a redact fragment (passive ⊃ pass,
    # secrets ⊃ secret). Only these keep a switch value in the ledger. Conservative = none: with
    # the data file unreadable they are redacted too, never a credential let through.
    "redact_bool_switches": [],
    "budget": {"max_metered_calls_per_run": 60, "max_arg_chars": 200},
    # Cross-type loop: metered pivots it proposes are gated on cases/<case>/proposal.json while the
    # loop is active. Conservative minimum = gate both pivot tools the loop proposes.
    "proposal_gated_tools": ["corpus_search", "reverse_whois"],
    # Tools whose meteredness depends on a ROUTE argument (pivot_map.json → routes.<r>.metered).
    # An unknown route counts as metered (conservative).
    "route_metered_tools": {"corpus_search": "route"},
    # Tools that spend only when an argument is truthy (search_pivot run=true -> SerpApi fallback).
    # Conservative minimum = the one known entry, so a missing data file never under-counts it.
    "arg_metered_tools": {"search_pivot": "run"},
    # The analyst's consent step; never callable from a harness phase.
    "operator_only_tools": ["case_approve"],
    # Metered tools whose handler honours free_only (a keyless mode). Every OTHER metered tool
    # refuses free_only rather than spend (tools._free_only_refusal). Conservative = empty.
    "free_only_capable_tools": [],
}

_P = load_ref(ref_path(__file__, "tool_policy.json"), _POLICY_FALLBACK)

OUTBOUND_TOOLS = set(_P["outbound_tools"])
PASSIVE_ARGS = set(_P["passive_args"])
METERED_TOOLS = set(_P["metered_tools"])
FREE_ONLY_ARGS = set(_P["free_only_args"])
METERED_ARG_TRIGGERS = set(_P["metered_arg_triggers"])
APPROVAL_REQUIRED = dict(_P["approval_required_tools"])
APPROVAL_BRIEFING = {k: set(v) for k, v in dict(_P.get("approval_briefing") or {}).items()}
MUTATING_TOOLS = set(_P["mutating_tools"])
REDACT_ARGS = set(_P["redact_args"])
_REDACT_FRAGS = {str(f).lower().replace("_", "").replace("-", "") for f in REDACT_ARGS if f}
REDACT_BOOL_SWITCHES = {str(f).lower().replace("_", "").replace("-", "")
                        for f in (_P.get("redact_bool_switches") or []) if f}
BUDGET = dict(_P["budget"])
PROPOSAL_GATED = set(_P.get("proposal_gated_tools") or [])
ROUTE_METERED = dict(_P.get("route_metered_tools") or {})
ARG_METERED = dict(_P.get("arg_metered_tools") or {})
OPERATOR_ONLY = set(_P.get("operator_only_tools") or [])
FREE_ONLY_CAPABLE = set(_P.get("free_only_capable_tools") or [])

_TOOLS_DIR = os.path.join(ROOT, "tools")


def _route_metered(route: str) -> bool:
    """pivot_map.json routes.<route>.metered; unknown route or unreadable map → metered."""
    try:
        if _TOOLS_DIR not in sys.path:
            sys.path.append(_TOOLS_DIR)                       # append: never shadow harness/tools.py
        import selector_types as _st  # noqa: E402
        spec = (_st.load_pivot_map().get("routes") or {}).get(str(route or ""))
    except Exception:  # noqa: BLE001 — conservative
        return True
    return True if not isinstance(spec, dict) else bool(spec.get("metered", True))

# Project decision: no CTI-wide local usage caps — vendor HTTP 402/429 responses enforce limits.
# The per-run metered counter stays in the ledger/summary, but it DENIES only when an operator
# opts in with HARNESS_METERED_BUDGET=<n> (0/unset = never deny on count).
MAX_METERED = int(os.environ.get("HARNESS_METERED_BUDGET") or 0)
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
    route_field = ROUTE_METERED.get(t)
    route_metered = (route_field is None or _route_metered((args or {}).get(route_field)))
    arg_field = ARG_METERED.get(t)
    arg_metered = arg_field is None or _truthy(args, {arg_field})
    if ((t in METERED_TOOLS or route_field or arg_field) and route_metered and arg_metered
            and not _truthy(args, FREE_ONLY_ARGS)):
        out.append("metered")
        if _truthy(args, METERED_ARG_TRIGGERS):
            out.append("metered-expanded")
    if t in APPROVAL_REQUIRED:
        out.append("approval-required")
    if t in MUTATING_TOOLS:
        out.append("mutating")
    return out


def decide(tool_name: str, args: dict, *, hostile: bool | None = None,
           case: str | None = None, phase: str | None = None) -> tuple[bool, str, list]:
    """(allow, reason, classes). No logging, no counter mutation, so it is testable. The one read
    it does is cases/<case>/proposal.json, for the cross-type loop's per-round approval gate."""
    t = bare(tool_name)
    args = args or {}
    classes = classify(tool_name, args)
    if hostile is None:
        hostile = bool((_CTX.get() or {}).get("hostile", _ENV_HOSTILE))

    # Operator-only tools (case_approve): the analyst's consent step. A harness PHASE calling it
    # would be the loop approving its own spend, so any non-interactive phase is denied.
    ph = phase if phase is not None else (_CTX.get() or {}).get("phase")
    if t in OPERATOR_ONLY and ph not in (None, "", "interactive"):
        return (False,
                f"{t} is the ANALYST's consent step and cannot be called from a harness phase "
                f"({ph}). Stop and hand the proposal back; the analyst approves it with "
                f"`harness approve` or this tool in an interactive session.", classes)

    env = APPROVAL_REQUIRED.get(t)
    if env and os.environ.get(env, "").strip().lower() not in ("1", "true", "yes", "on"):
        # The read-only briefing branch stays reachable without approval: with every exempt arg
        # falsy the call composes the briefing offline and does nothing outbound or irreversible,
        # so the analyst can actually SEE it before saying yes. Any exempt arg set → the real
        # gated action, denied. `_truthy` is the same falsy interpretation the flag gates use.
        exempt = APPROVAL_BRIEFING.get(t)
        is_briefing = exempt is not None and not _truthy(args, exempt)
        if not is_briefing:
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
        # A no_spend case scope rules out EVERY credit-spending call — pivot_extract's keyed
        # layers, censys, intelx_search, anyrun_lookup, reverse_whois, corpus_search's metered
        # routes — not only the cross-type loop's pivots. free_only=true drops the class.
        if HERE not in sys.path:
            sys.path.append(HERE)
        import proposal as _proposal  # noqa: E402 — harness/proposal.py, stdlib only
        _case = case or (_CTX.get() or {}).get("case")
        if _case and _proposal._no_spend(ROOT, _case):
            return (False,
                    f"{t} would spend metered credits and case {_case}'s scope is no_spend — the "
                    f"analyst ruled out spending on this case. Re-call with free_only=true. "
                    f"Do not retry unchanged.", classes)
        with _LOCK:
            spent = _COUNTS["metered"]
        if MAX_METERED and spent >= MAX_METERED:
            return (False,
                    f"metered-call budget exhausted for this run ({spent}/{MAX_METERED} "
                    f"credit-spending calls). Third-party credits are per-account and do not roll "
                    f"over. Re-call with free_only=true to continue on keyless sources, or hand "
                    f"the remaining pivots to the analyst as metered leads.", classes)
        # Cross-type loop: while it is active for this case, a proposal-gated metered pivot runs
        # only if it matches an item the analyst approved (digest-current). Not prompt-enforced.
        if t in PROPOSAL_GATED:
            if HERE not in sys.path:
                sys.path.append(HERE)
            import proposal as _proposal  # noqa: E402 — harness/proposal.py, stdlib only
            ok, why = _proposal.gate_check(ROOT, case or (_CTX.get() or {}).get("case"), t, args,
                                           gated=PROPOSAL_GATED)
            if not ok:
                return False, why, classes
        elif (_case and _proposal.loop_active(_proposal.load(ROOT, _case))
              and not (t == "pivot_extract"
                       and _proposal.is_seed_host(ROOT, _case, (args or {}).get("url")))):
            # Any OTHER metered call while the case's cross-type loop is active (a collect/judge
            # agent reaching for deep_profile, censys, intelx_search, a keyed pivot_extract of a
            # host the analyst did not type …) has no approved proposal item — denied. The one
            # exemption is collecting an analyst-typed SEED host with its keyed layers.
            return (False,
                    f"{t} would spend metered credits while case {_case}'s cross-type loop is "
                    f"active — paid pivots run only as items the analyst approved in "
                    f"cases/{_case}/proposal.json. Re-call with free_only=true, or leave it to the "
                    f"next proposal. Do not retry unchanged.", classes)

    return True, "", classes


def _ledger_path(case: str | None) -> str:
    """cases/<case>/tool_calls.jsonl, or MEMORY/tool_calls.jsonl when no case is in scope
    (interactive Claude Code use). Both stores are git-ignored."""
    if case:
        return os.path.join(ROOT, "cases", str(case), "tool_calls.jsonl")
    return os.path.join(ROOT, "MEMORY", "tool_calls.jsonl")


def _norm_key(k) -> str:
    """`apiKey`, `x-api-key`, `X_API_KEY` -> `apikey` / `xapikey`: lowercase, `_` and `-` stripped."""
    return str(k).lower().replace("_", "").replace("-", "")


def _secret_key(k) -> bool:
    """A key/parameter NAME that carries a credential: its normalised form contains any
    redact_args fragment (key, token, secret, pass, auth, cookie, bearer …)."""
    n = _norm_key(k)
    return any(frag in n for frag in _REDACT_FRAGS)


_URL_RE = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://)([^/\s?#@]*@)")
_QUERY_RE = re.compile(r"([?&;])([^=&;#\s]+)=([^&;#\s]*)")
_BEARER_RE = re.compile(r"(?i)\b(bearer|basic|token)\s+[A-Za-z0-9._~+/=\-]{6,}")


def _scrub(s: str) -> str:
    """Credentials embedded in a free string value: URL userinfo (`user:pass@`), secret-named query
    parameters (`?token=…&apikey=…`) and `Bearer <token>` — the host, path and non-secret
    parameters stay readable, because the ledger's job is to show WHAT was touched."""
    s = _URL_RE.sub(lambda m: m.group(1) + "<redacted>@", s)
    s = _QUERY_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}=<redacted>"
                      if _secret_key(m.group(2)) else m.group(0), s)
    return _BEARER_RE.sub(lambda m: f"{m.group(1)} <redacted>", s)


_BOOL_WORDS = {"true", "false", "yes", "no", "on", "off", "1", "0", "none", "null", ""}
_MAX_ITEMS = 20                                       # list/dict entries previewed per container


def _is_switch(k, v) -> bool:
    """A declared boolean switch (`passive=true`, `secrets="yes"`) — the NAME must be one of
    redact_bool_switches. A switch-shaped VALUE alone proves nothing: `password="true"` or
    `token="1"` is a credential like any other and is redacted."""
    if _norm_key(k) not in REDACT_BOOL_SWITCHES:
        return False
    if isinstance(v, bool) or v is None or (isinstance(v, int) and v in (0, 1)):
        return True
    return isinstance(v, str) and v.strip().lower() in _BOOL_WORDS


def _safe_value(v, depth: int = 0):
    if isinstance(v, bool) or v is None or isinstance(v, int):
        return v
    if isinstance(v, float):
        return v if math.isfinite(v) else str(v)       # NaN/inf are not JSON
    if isinstance(v, (dict, list, tuple)):
        if depth >= 4:
            return "<nested>"
        items = list(v.items()) if isinstance(v, dict) else list(v)
        more = len(items) - _MAX_ITEMS
        items = items[:_MAX_ITEMS]
        if isinstance(v, dict):
            out = {str(k): ("<redacted>" if _secret_key(k) and not _is_switch(k, x)
                            else _safe_value(x, depth + 1)) for k, x in items}
            if more > 0:
                out["…"] = f"+{more} keys"
            return out
        out = [_safe_value(x, depth + 1) for x in items]
        if more > 0:
            out.append(f"…(+{more} items)")
        return out
    s = _scrub(str(v))
    if len(s) > MAX_ARG_CHARS:
        s = s[:MAX_ARG_CHARS] + f"…(+{len(s) - MAX_ARG_CHARS} chars)"
    return s


def _safe_args(args: dict) -> dict:
    """Argument preview for the ledger: credentials replaced, long values truncated. The ledger is
    an audit trail of WHAT was called, not a copy of the payload. A secret-NAMED argument (matched
    by fragment on the normalised name, at any nesting depth) is replaced outright — unless it is a
    declared boolean switch (redact_bool_switches: `passive`, `secrets`) carrying a boolean value,
    which the audit trail needs; any other string is scrubbed of embedded URL userinfo / secret
    query params."""
    if not isinstance(args, dict):
        return {"_args": _safe_value(args)}
    return _safe_value(args)


def _ledger_line(rec: dict) -> str:
    """One JSON line that ALWAYS serialises: NaN/inf are already strings (_safe_value); anything
    else unencodable (a lone surrogate) is \\u-escaped rather than allowed to raise."""
    try:
        line = json.dumps(rec, ensure_ascii=False, allow_nan=False)
        line.encode("utf-8")
        return line
    except (ValueError, TypeError, UnicodeError):
        return json.dumps(rec, ensure_ascii=True, default=str)


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
        line = _ledger_line(rec)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with _LOCK:                                    # concurrent collectors share one ledger file
            with open(path, "a", encoding="utf-8", errors="backslashreplace") as f:
                f.write(line + "\n")
    except Exception as e:  # noqa: BLE001 — the ledger must never fail the call it records
        if not getattr(record, "_warned", False):
            print(f"[audit] WARNING: tool-call ledger unwritable ({e}); the run continues but "
                  f"its actions are NOT being recorded.", file=sys.stderr)
            record._warned = True                      # type: ignore[attr-defined]


def gate(tool_name: str, args: dict, *, case: str | None = None, phase: str | None = None,
         backend: str | None = None, hostile: bool | None = None) -> tuple[bool, str]:
    """Decide + count + record, in one call. Returns (allow, reason_if_denied).

    This is the ONLY entry point a front-end needs. `case`/`phase` are explicit for callers that
    run concurrently (the SDK hook closure); everything else may rely on the ambient context."""
    allowed, reason, classes = decide(tool_name, args, hostile=hostile, case=case, phase=phase)
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
