"""OSINT harness — a phased agent loop over your existing skills + tools.

The LLM still reasons and chooses tools; the harness fixes the ENVIRONMENT so the
run is repeatable:
  - each phase uses a pinned skill body as its system_prompt (WebPivot / IntelAnalysis)
  - each phase exposes only its own tool subset
  - judgment (Correlate->Assess) runs in its OWN session and reads facts from the KB via
    tools, rather than resuming the large collect transcript (keeps Opus cost down)
  - the final Assess phase is schema-forced (output_format) -> validated Assessment,
    rendered to a rich terminal report + cases/<case>/assessment.{md,json}

Phases:  Collect -> Correlate -> Assess

Run:
  export ANTHROPIC_API_KEY=...            # or be logged into Claude Code
  python3 harness/orchestrator.py CASE-0001 https://site-a.example https://site-b.example
  python3 harness/orchestrator.py CASE-0001 --hostile https://sketchy.example
"""
from __future__ import annotations

import asyncio
import datetime
import glob
import ipaddress
import json
import os
import re
import sys
import time
from dataclasses import dataclass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import audit  # noqa: E402  — the tool-call gate + ledger, shared by all three front-ends
import backend_select  # noqa: E402  — which LLM backend runs the phases (claude / codex / omp / openai)
if __name__ == "__main__":
    # Resolve BEFORE sdk_compat is imported: it exports HARNESS_BACKEND (probing auth once) so an
    # unusable backend fails here with every candidate's reason — never as "✓ phase · $0.00".
    backend_select.ensure_env()
import case_scope  # noqa: E402  — the case INTAKE record (target class, posture, premise)
import render  # noqa: E402
import tools as T  # noqa: E402
from schemas import Assessment, Plan  # noqa: E402
import proposal as P  # noqa: E402  — per-round pivot approval (cases/<case>/proposal.json)
from sdk_compat import (  # noqa: E402  — real Anthropic SDK, the CLI backend, or the OpenAI-compat shim
    AssistantMessage,
    ClaudeAgentOptions,
    HookMatcher,
    ResultMessage,
    ToolUseBlock,
    query,
)

HERE = os.path.dirname(os.path.abspath(__file__))            # harness/
ROOT = os.path.dirname(HERE)                                  # repo root
sys.path.append(os.path.join(ROOT, "tools"))  # case_state (APPEND — must not shadow harness/tools.py)
sys.path.append(os.path.join(ROOT, "tools", "kb"))  # convergence.py (APPEND — same append style as
                                                     # the tools/ path above; never shadow harness/tools.py)
try:
    import convergence as _conv  # tools/kb/convergence.py — the single source of truth for CONVERGED
except Exception:  # noqa: BLE001 — degrade to the old bare rule if the KB toolkit isn't importable
    _conv = None


@dataclass(frozen=True)
class Profile:
    """Per-phase model + reasoning effort. Cheap model / minimal thinking for the
    mechanical collection phase; strong model / deep thinking for judgment. Tune per
    run via env vars — no code edit needed."""

    model: str
    effort: str  # low | medium | high | xhigh | max


# Mechanical collection -> cheap model, minimal reasoning.
COLLECT = Profile(
    os.environ.get("HARNESS_COLLECT_MODEL", "haiku"),
    os.environ.get("HARNESS_COLLECT_EFFORT", "low"),
)
# Judgment (correlate + assess) -> capable-but-cheaper model by default (Sonnet).
JUDGE = Profile(
    os.environ.get("HARNESS_JUDGE_MODEL", "sonnet"),
    os.environ.get("HARNESS_JUDGE_EFFORT", "high"),
)
# Cascade: escalate the ASSESS phase to a stronger model only when the cheap judge
# returns low confidence (a minority of cases) — cost of Opus only where it earns it.
ESCALATE = Profile(
    os.environ.get("HARNESS_ESCALATE_MODEL", "opus"),
    os.environ.get("HARNESS_ESCALATE_EFFORT", "high"),
)
ESCALATE_ON = os.environ.get("HARNESS_ESCALATE", "1").lower() not in ("0", "false", "no", "")

# Adversarial verify: between CORRELATE and ASSESS, a skeptic pass that tries to REFUTE every
# same-operator link before it's committed (benign/over-prevalent/managed-DNS/competing-explanation
# → dropped). Defaults to the judge model — refutation is the harness's core false-positive control,
# so it runs on by default; disable per run with HARNESS_VERIFY=0 or `--no-verify`.
VERIFY = Profile(
    os.environ.get("HARNESS_VERIFY_MODEL", JUDGE.model),
    os.environ.get("HARNESS_VERIFY_EFFORT", JUDGE.effort),
)
VERIFY_ON = os.environ.get("HARNESS_VERIFY", "1").lower() not in ("0", "false", "no", "")


MAX_TURNS = int(os.environ.get("HARNESS_MAX_TURNS", "40"))  # lower for cheap smoke runs


def _log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def _argpreview(inp: object) -> str:
    if not isinstance(inp, dict):
        return ""
    return ", ".join(f"{k}={str(v)[:36]}" for k, v in inp.items())


def _report_cost(phases: dict[str, object], case: str | None = None) -> None:
    """Print the SDK's own per-run cost estimate (ResultMessage.total_cost_usd) to stderr, so stdout
    stays clean for the assessment JSON, and (when `case` is given) append one line per run to
    `cases/<case>/run_cost.jsonl` so cost is calculable over time. Values are per phase; the total
    is their sum. NOTE: this is the ANTHROPIC model cost only — FOFA/WhoisXML/urlscan/IPinfo/Shodan
    API credits are NOT included (track those in each provider's console)."""
    print("\n--- run cost (SDK total_cost_usd; Anthropic only, excludes API credits) ---",
          file=sys.stderr)
    total = 0.0
    per_phase = {}
    for name, r in phases.items():
        c = getattr(r, "total_cost_usd", None)
        total += c or 0.0
        per_phase[name] = c
        print(f"  {name:<10} {(f'${c:.4f}' if c is not None else 'n/a'):>10}", file=sys.stderr)
    print(
        f"  {'TOTAL':<10} {('$%.4f' % total):>10}   "
        f"(collect={COLLECT.model}/{COLLECT.effort}, judge={JUDGE.model}/{JUDGE.effort})",
        file=sys.stderr,
    )
    # The governance counterpart to the cost ledger: what the run DID, not just what it spent.
    gate = audit.summary(case)
    if gate:
        print("--- tool-call gate (every call recorded; DENY = blocked before it ran) ---",
              file=sys.stderr)
        print(gate, file=sys.stderr)
    if case:
        rec = {"ts": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
               "case": case, "total_cost_usd": round(total, 6),
               "phases": {k: (round(v, 6) if v is not None else None) for k, v in per_phase.items()},
               "collect_model": COLLECT.model, "judge_model": JUDGE.model,
               "note": "anthropic model cost only; excludes third-party API credits"}
        try:
            path = os.path.join(ROOT, "cases", case, "run_cost.jsonl")
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            print(f"  (logged → cases/{case}/run_cost.jsonl)", file=sys.stderr)
        except Exception as e:
            print(f"  (run_cost log failed: {e})", file=sys.stderr)


def _skill(name: str) -> str:
    """Load a SKILL body to use as a phase system prompt (inlined for portability;
    the SDK can also auto-load skills from .claude/ via setting_sources).
    cti-expert vendoring renames each component's SKILL.md to SKILL.reference.md
    (the repo keeps exactly one SKILL.md — the root entrypoint), so try the vendored
    name first, then the upstream one (mirrors agents._load_skill)."""
    for fname in ("SKILL.reference.md", "SKILL.md"):
        p = os.path.join(ROOT, name, fname)
        if os.path.isfile(p):
            with open(p, encoding="utf-8") as f:
                return f.read()
    raise FileNotFoundError(
        f"no SKILL.reference.md or SKILL.md for component {name!r} under {ROOT}")


def _prompt(name: str, **kw: object) -> str:
    """Load a phase TASK prompt from harness/prompts/<name>.md — the single editable source
    of truth for what each phase instructs (the phase system_prompt still comes from the SKILL
    body via _skill). Placeholders are {{token}}, filled from kwargs; a token with no matching
    kwarg is left intact. Plain { } and $ are NOT special, so the prose can be edited freely."""
    with open(os.path.join(HERE, "prompts", name + ".md"), encoding="utf-8") as f:
        body = f.read().rstrip("\n")
    for k, v in kw.items():
        body = body.replace("{{" + k + "}}", str(v))
    return body


# --------------------------------------------------------------------------- case scope (intake)
# Resolved ONCE per case and cached, then read by every phase. A module-level cache is safe here
# where the per-phase `hostile` closure was not: the scope is constant for the whole run, while
# `hostile` had to be bound per phase. Any entry point works — a `--continue` resume or the other
# front-end picks the same record back up off `cases/<case>/scope.json`.
_SCOPE_CACHE: dict[str, dict] = {}


def _scope(case: str) -> dict:
    """This case's intake record. Never raises and never returns None: an unscoped case resolves
    to the conservative `unknown` class, which the rendered block discloses."""
    if case not in _SCOPE_CACHE:
        _SCOPE_CACHE[case] = case_scope.resolve(case, persist=False)
    return _SCOPE_CACHE[case]


def _domain_table(case: str) -> str:
    """Render the standard analyst Domain Summary table for the case's collected domains."""
    raw = os.path.join(ROOT, "cases", case, "raw")
    files = [os.path.join(raw, f) for f in os.listdir(raw)] if os.path.isdir(raw) else []
    if not files:
        return ""
    r = T._run([sys.executable, os.path.join("tools", "domain_table.py"), *files,
     "--case", case, "--kb", T.KB_DIR], timeout=180)
    return r.stdout if r.returncode == 0 else ""


def _prior_knowledge(seeds: list[str]) -> str:
    """Per-seed status so collect can skip re-work: already collected? already attributed?"""
    lines = []
    for s in seeds:
        host = T._host(s)
        collected = bool(T._find_cached_raw(host))
        op = T._run([sys.executable, os.path.join("tools", "kb", "operator_registry.py"), "find", host], timeout=60)
        first = (op.stdout or "").strip().splitlines()
        attributed = bool(first) and "not attributed" not in first[0].lower()
        tags = [t for t, on in (("already-collected", collected), ("attributed", attributed)) if on]
        note = f"  [{first[0]}]" if attributed else ""
        lines.append(f"- {host}: {', '.join(tags) if tags else 'NEW'}{note}")
    return "\n".join(lines)


def _gate_hook(case, phase, hostile):
    """Build this phase's PreToolUse callback as a CLOSURE over (case, phase, hostile).

    Why a closure and not ambient state: phases run concurrently (collect fan-out, parallel
    cluster judgment) and the hook fires on the SDK's own task, so a module global — or even a
    ContextVar set in _phase — would attribute one phase's tool calls to another. The closure
    binds the right values at construction time and cannot race.

    Why a hook and not `can_use_tool`: the SDK only consults `can_use_tool` for calls that would
    otherwise PROMPT, and both `permission_mode="bypassPermissions"` and whole-tool `allowed_tools`
    entries (exactly what COLLECT_TOOLS / ANALYZE_TOOLS are) shadow it — the SDK emits
    CanUseToolShadowedWarning and points at PreToolUse for gating every call. See audit.py."""

    async def _cb(input_data, tool_use_id, context):    # HookCallback signature
        name = (input_data or {}).get("tool_name", "")
        args = (input_data or {}).get("tool_input") or {}
        allowed, why = audit.gate(name, args, case=case, phase=phase,
                                  backend="claude", hostile=hostile)
        if allowed:
            return {}          # neutral: fall through to the normal permission flow
        _log(f"    ⛔ DENIED {audit.bare(name)} — {why.split('.')[0]}")
        return {"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "deny",
            "permissionDecisionReason": why}}

    return _cb


# Wall-clock ceiling per phase. The CLI backends already stop a phase at HARNESS_CLI_TIMEOUT; the
# SDK path only had max_turns, so one hung tool call could stall a round (and a loop that pauses
# for approvals) forever. One ceiling, same default, both paths.
PHASE_TIMEOUT = int(os.environ.get("HARNESS_PHASE_TIMEOUT")
                    or os.environ.get("HARNESS_CLI_TIMEOUT") or 1800)


async def _phase(prompt, *, label, **kw):
    """Run one phase under PHASE_TIMEOUT; a timeout is a FAILED phase (never a silent pass)."""
    try:
        return await asyncio.wait_for(_phase_run(prompt, label=label, **kw), timeout=PHASE_TIMEOUT)
    except asyncio.TimeoutError:
        _log(f"  ✗ {label} · timed out after {PHASE_TIMEOUT}s (HARNESS_PHASE_TIMEOUT)")
        raise RuntimeError(f"phase {label} timed out after {PHASE_TIMEOUT}s") from None


async def _phase_run(prompt, *, label, system, tools, servers, resume=None,
                     model=None, effort=None, output_schema=None, hostile=False, case=None):
    T.POLICY["hostile"] = hostile
    # Ambient context for the OpenAI/DeepSeek shim, which executes tools on THIS task (the SDK
    # path uses the closure above instead). Set per phase, inherited by nothing else.
    audit.set_context(case=case, phase=label, hostile=hostile,
                      backend=os.environ.get("HARNESS_BACKEND", "claude"))
    t0 = time.time()
    _log(f"\n▶ {label}  ·  {model}/{effort}")
    opts = ClaudeAgentOptions(
        system_prompt=system,
        mcp_servers=servers,
        tools=[],             # remove ALL built-ins (Bash/Read/…) -> force the clean MCP tools,
        allowed_tools=tools,  #   not shell flailing over the skill prompt's bash instructions
        # Headless: no interactive approval prompts — but NOT ungoverned. Every tool call passes
        # the PreToolUse gate below (hostile egress, sandbox submission, metered budget) and is
        # written to the ledger. bypassPermissions suppresses the PROMPT; the hook is what decides.
        permission_mode="bypassPermissions",
        hooks={"PreToolUse": [HookMatcher(hooks=[_gate_hook(case, label, hostile)])]},
        setting_sources=[],          # don't inherit machine/project .claude settings
        resume=resume,
        max_turns=MAX_TURNS,
        model=model,
        effort=effort,
        output_format=(
            {"type": "json_schema", "schema": output_schema.model_json_schema()}
            if output_schema else None
        ),
    )
    result = None
    try:
        async for msg in query(prompt=prompt, options=opts):
            if isinstance(msg, AssistantMessage):
                for block in msg.content:            # live worklog: each tool call + its args
                    if isinstance(block, ToolUseBlock):
                        _log(f"    · {block.name.split('__')[-1]}({_argpreview(block.input)})")
            elif isinstance(msg, ResultMessage):
                result = msg
    except Exception as e:  # query() raises AFTER yielding an error ResultMessage
        if result is None:
            kind = backend_select.classify_failure(str(e))
            if kind:
                raise backend_select.BackendUnavailable(
                    os.environ.get("HARNESS_BACKEND", "claude"), str(e)[:300], kind) from e
            raise
    cost = getattr(result, "total_cost_usd", None)
    subtype = getattr(result, "subtype", None) if result is not None else None
    hard = result is None or getattr(result, "is_error", False) or subtype in ("error", "error_during_execution")
    if hard:
        # An auth failure / backend error is a FAILED phase — never a ✓ at $0.00. (max-turns is a
        # soft stop: the tool calls it made still landed, so it is logged, not raised.)
        detail = (getattr(result, "result", "") or subtype or "no result message").strip()
        _log(f"  ✗ {label} · {time.time() - t0:.0f}s · {subtype or 'none'} — {detail[:300]}")
        kind = backend_select.classify_failure(detail)
        if kind:
            # The BACKEND stopped answering (login / credits / rate limit) — the case is fine and
            # resumable on another backend; harness/cli.py offers that switch.
            raise backend_select.BackendUnavailable(
                os.environ.get("HARNESS_BACKEND", "claude"), detail[:300], kind)
        raise RuntimeError(f"phase {label} failed ({subtype or 'no result'}): {detail[:200]}")
    if subtype and subtype != "success":
        _log(f"  ⚠ {label} ended with {subtype}")
    _log(f"  ✓ {label} · {time.time() - t0:.0f}s"
         + (f" · ${cost:.4f}" if cost is not None else ""))
    return result


async def collect_fanout(seeds: list[str], case: str, *, hostile: bool = False,
                         max_conc: int = 6) -> dict:
    """COLLECT, fanned out — one WebPivot *collector agent* per seed, all running CONCURRENTLY
    under a semaphore. This is the wired realization of `agents.py`'s dormant `collector` persona:
    it combines `run_case_parallel`'s parallelism with the per-seed *reactive* tradecraft
    (empty→fallback_probe, hostile→passive) that `collect_many`'s deterministic thread-pool can't
    do. Collectors do NOT ingest — the caller ingests once after, avoiding a concurrent KB write
    race. Returns {host: ResultMessage} so the caller aggregates per-seed cost."""
    sem = asyncio.Semaphore(max_conc)

    async def _one(seed: str) -> tuple[str, object]:
        host = T._host(seed)
        async with sem:
            r = await _phase(
                _prompt(
                    "collect_one",
                    scope=case_scope.collect_directives(_scope(case)),
                    case=case,
                    prior=_prior_knowledge([seed]),
                    seed_lines=f"- {seed}",
                    hostile_note=("Target is HOSTILE — pass passive=true or a proxy on pivot_extract.\n"
                                  if hostile else ""),
                ),
                label=f"collect:{host}",
                system=_skill("WebPivot"),
                tools=T.COLLECT_TOOLS,
                servers={"collect": T.COLLECT_SERVER},
                model=COLLECT.model,
                effort=COLLECT.effort,
                hostile=hostile,
                case=case,
            )
            return host, r

    return dict(await asyncio.gather(*[_one(s) for s in seeds]))


async def investigate(seeds: list[str], case: str, hostile: bool = False,
                      collect_conc: int = 1) -> Assessment:
    seed_lines = "\n".join(f"- {s}" for s in seeds)
    seed_csv = ", ".join(seeds)

    # PHASE 1 — COLLECT  (WebPivot brain, cheap model). Writes raw + ingests into the KB.
    prior = _prior_knowledge(seeds)
    _log("prior knowledge:\n" + prior)
    if collect_conc > 1 and len(seeds) > 1:
        # Fan-out: one reactive collector agent per seed, concurrently. Collectors don't ingest;
        # we ingest all of their raw output once here (sync) to avoid a concurrent KB write race.
        _log(f"collect fan-out: {len(seeds)} seeds · ≤{collect_conc} concurrent collector agents")
        collect_phases = {f"collect:{h}": r
                          for h, r in (await collect_fanout(seeds, case, hostile=hostile,
                                                            max_conc=collect_conc)).items()}
        ok, msg = T.ingest(case)
        _log(f"  ingest · {'ok' if ok else 'FAILED'} · {msg.splitlines()[0] if msg else ''}")
    else:
        p1 = await _phase(
            _prompt(
                "collect",
                scope=case_scope.collect_directives(_scope(case)),
                case=case,
                prior=prior,
                seed_lines=seed_lines,
                hostile_note=("Targets are HOSTILE — pass passive=true or a proxy on pivot_extract.\n"
                              if hostile else ""),
            ),
            label="collect",
            system=_skill("WebPivot"),
            tools=T.COLLECT_TOOLS,
            servers={"collect": T.COLLECT_SERVER},
            model=COLLECT.model,
            effort=COLLECT.effort,
            hostile=hostile,
            case=case,
        )
        collect_phases = {"collect": p1}
    # We do NOT resume the collect session into judgment. The facts now live in the KB,
    # which the judgment phases read via tools — carrying the (large) collect transcript
    # into every Opus turn was the main cost driver. Judgment runs in its own session.

    # PHASE 2+3 — judgment (Correlate → Assess) over the seeds, reading the ingested KB.
    assessment, jphases = await _judge(seeds, case)
    _report_cost({**collect_phases, **jphases}, case=case)
    if assessment is None:
        raise RuntimeError("assessment failed (correlate/assess produced nothing)")
    return assessment


def _out_of_scope(assessment: Assessment, members: list[str]) -> list[str]:
    """Cluster hosts the judge named that are NOT in the member set it was asked to judge."""
    allowed = {m.strip().lower().rstrip(".") for m in members}
    return sorted({(c.domain or "").strip().lower().rstrip(".") for c in assessment.cluster}
                  - allowed - {""})


_SCOPE_NOTE = ("\n\nSCOPE OF THIS JUDGMENT: you are judging ONE cluster whose members are exactly: "
               "{members}. The `cluster` field must list ONLY these hosts. Other hosts in the case or "
               "the knowledge base may appear in evidence, alternatives, gaps or next_pivots as "
               "context, never as cluster members — each other cluster is judged separately.")


async def _judge(domains: list[str], case: str,
                 members_only: bool = False) -> tuple[Assessment | None, dict]:
    """The judgment half — Correlate → Assess (+cascade) over `domains`, reusable per cluster. No
    collection; reads the already-ingested KB in its own fresh session. Returns (Assessment|None,
    phases_dict) so the caller aggregates cost across one or many clusters.

    `members_only` (the per-cluster parallel judge): `domains` IS the cluster, so the assessment's
    `cluster` must be a subset of it. A judge that reads the case-wide KB and assesses a different
    cluster (seen live: a single-host cluster's judge returned the neighbouring estate as its
    members, which then shipped under that cluster's _cN id) is re-prompted once with the exact
    member list; if it still names out-of-scope hosts, the judgment is refused (RuntimeError), so
    the caller records it as a failed cluster instead of persisting a mislabeled verdict. The
    single-judge `investigate` path leaves it off — there the seeds legitimately grow into
    discovered siblings."""
    seed_csv = ", ".join(domains)
    # PHASE 2 — CORRELATE  (IntelAnalysis brain, judge model). Fresh session, reads the KB.
    p2 = await _phase(
        _prompt("correlate", scope=case_scope.judgment_directives(_scope(case)),
                case=case, seed_csv=seed_csv)
        + (_SCOPE_NOTE.format(members=seed_csv) if members_only else ""),
        label="correlate",
        system=_skill("IntelAnalysis"),
        tools=T.ANALYZE_TOOLS,
        servers={"analyze": T.ANALYZE_SERVER},
        model=JUDGE.model,
        effort=JUDGE.effort,
        case=case,
    )
    session = p2.session_id if p2 else None
    if not session:
        return None, {"correlate": p2}
    phases = {"correlate": p2}

    # PHASE 2.5 — ADVERSARIAL VERIFY  (resume CORRELATE; refute each same-operator link before it's
    # committed). Runs in the correlate session so it attacks the very cluster it just drew; ASSESS
    # then resumes THIS session, so the structured output reflects only the surviving links.
    if VERIFY_ON:
        pv = await _phase(
            _prompt("verify", scope=case_scope.judgment_directives(_scope(case)),
                    case=case, seed_csv=seed_csv),
            label="verify", system=_skill("IntelAnalysis"), tools=T.ANALYZE_TOOLS,
            servers={"analyze": T.ANALYZE_SERVER}, resume=session,
            model=VERIFY.model, effort=VERIFY.effort, case=case)
        phases["verify"] = pv
        if pv and pv.session_id:
            session = pv.session_id      # ASSESS resumes the adversarial session, not raw correlate

    # PHASE 3 — ASSESS  (resume the (verified) judgment session; schema-forced structured assessment)
    assess_prompt = _prompt("assess", scope=case_scope.judgment_directives(_scope(case)))
    if members_only:
        assess_prompt += _SCOPE_NOTE.format(members=seed_csv)
    assess_kw = dict(system=_skill("IntelAnalysis"), tools=T.ANALYZE_TOOLS,
                     servers={"analyze": T.ANALYZE_SERVER}, resume=session,
                     output_schema=Assessment, case=case)
    p3 = await _phase(assess_prompt, label="assess", model=JUDGE.model, effort=JUDGE.effort, **assess_kw)
    phases["assess"] = p3

    assessment = None
    if p3 and p3.subtype == "success" and p3.structured_output:
        assessment = Assessment.model_validate(p3.structured_output)

    # CASCADE: escalate the assessment to the stronger model only if the cheap judge was unsure.
    if (assessment is not None and ESCALATE_ON and assessment.confidence == "low"
            and ESCALATE.model != JUDGE.model):
        _log(f"low confidence — escalating assess to {ESCALATE.model}")
        p3b = await _phase(assess_prompt, label="assess+", model=ESCALATE.model,
                           effort=ESCALATE.effort, **assess_kw)
        phases["assess+"] = p3b
        if p3b and p3b.subtype == "success" and p3b.structured_output:
            assessment = Assessment.model_validate(p3b.structured_output)
    if assessment is not None and members_only:
        stray = _out_of_scope(assessment, domains)
        if stray:
            _log(f"assess named {len(stray)} host(s) outside the judged cluster — re-prompting once")
            last = phases.get("assess+") or p3
            fix = await _phase(
                f"Your `cluster` field listed hosts that are NOT in the cluster you were asked to "
                f"judge: {', '.join(stray)}. Re-emit the COMPLETE assessment for this cluster only."
                + _SCOPE_NOTE.format(members=seed_csv),
                label="assess-scope", model=JUDGE.model, effort=JUDGE.effort,
                **{**assess_kw, "resume": (last.session_id if last and last.session_id else session)})
            phases["assess-scope"] = fix
            assessment = (Assessment.model_validate(fix.structured_output)
                          if fix and fix.subtype == "success" and fix.structured_output else None)
            stray = _out_of_scope(assessment, domains) if assessment is not None else stray
            if assessment is None or stray:
                raise RuntimeError("judge assessed out-of-scope hosts: " + ", ".join(stray[:8]))
    if assessment is not None:
        assessment = _enforce_tiers(assessment, case)
    return assessment, phases


# ------------------------------------------------------------- tiers (collecting ≠ attributing)
_TIER_CAVEAT = {"kit": "shared kit artifact — not attribution",
                "neighbour": "co-tenant / exchange flow — not attribution"}


def _seed_file(case: str) -> str:
    return os.path.join(ROOT, "cases", case, "harness_seeds.json")


def _record_seeds(case: str, domains: list[str]) -> None:
    """Remember the analyst's own domain seeds (harness-owned file, merged across runs). A seed
    is the investigation's subject: the tier rail never moves it out of the cluster, whatever a
    later corpus pivot reports about it (a kit-rung hit on the seed's own title is still the seed)."""
    hosts = {T._host(d).lower() for d in domains or () if d}
    if not hosts:
        return
    try:
        with open(_seed_file(case), encoding="utf-8") as fh:
            hosts |= set(json.load(fh) or [])
    except (OSError, ValueError):
        pass
    os.makedirs(os.path.dirname(_seed_file(case)), exist_ok=True)
    with open(_seed_file(case), "w", encoding="utf-8") as fh:
        json.dump(sorted(hosts), fh, indent=1)


def _run_seeds(case: str) -> set:
    try:
        with open(_seed_file(case), encoding="utf-8") as fh:
            return {str(h).lower() for h in (json.load(fh) or [])}
    except (OSError, ValueError):
        return set()


def _tier_hosts(case: str) -> dict:
    """{domain: kit|neighbour} — hosts the cross-type loop reached ONLY via kit/neighbour rows.
    The analyst's own seeds (and their apexes) are never tiered."""
    try:
        import case_state as cs
        tiers = cs.tier_hosts(os.path.join(ROOT, "cases", case))
    except Exception as e:  # noqa: BLE001
        _log(f"  (tier map unavailable: {e})")
        return {}
    seeds = _run_seeds(case)
    seed_apexes = {cs._frontier_apex(s) for s in seeds}
    return {h: t for h, t in tiers.items() if h not in seeds and h not in seed_apexes}


def _enforce_tiers(assessment: Assessment, case: str) -> Assessment:
    """Deterministic rail, not a prompt: a kit- or neighbour-tier host the judge put in `cluster`
    is moved to kit_siblings / neighbours with the rung caveat. Attribution can never rest on it."""
    tiers = _tier_hosts(case)
    leaked = [m for m in assessment.cluster
              if (m.domain or "").strip().lower().rstrip(".") in tiers]
    if not leaked:
        return assessment
    from schemas import TierMember
    keep = [m for m in assessment.cluster if m not in leaked]
    kit, nb = list(assessment.kit_siblings), list(assessment.neighbours)
    for m in leaked:
        d = m.domain.strip().lower().rstrip(".")
        t = tiers[d]
        (kit if t == "kit" else nb).append(TierMember(
            node_type="domain", value=d, rung_class=t, via=", ".join(m.shared_artifacts[:4]),
            caveat=_TIER_CAVEAT[t]))
    _log(f"  tier rail: moved {len(leaked)} kit/neighbour host(s) out of the cluster: "
         f"{', '.join(m.domain for m in leaked[:8])}")
    return assessment.model_copy(update={"cluster": keep, "kit_siblings": kit, "neighbours": nb})


# --------------------------------------------------------------- convergence loop (--continue)
def _convergence_snapshot(case: str, failed: list[str] | None = None) -> str:
    """Record this round in cases/<case>/rounds.jsonl via the convergence tool (its own authority
    on what counts as a new host/indicator). `failed` are hosts that failed to collect THIS round
    (run_case_parallel's `fails`; run_case has no partial-failure list — a hard collect failure
    there raises and the round never reaches this call) — convergence.py's zero_growth/is_converged
    then refuse to call a round zero-growth just because a failure also produced nothing new.
    Returns its one-line summary for the worklog."""
    cmd = [sys.executable, os.path.join("tools", "kb", "convergence.py"), "snapshot", case]
    if failed:
        cmd += ["--failed", ",".join(sorted(set(failed)))]
    r = T._run(cmd, timeout=120)
    return (r.stdout or r.stderr or "").strip()


def _is_converged(case: str, stale: int) -> bool:
    """CONVERGED = the last `stale` snapshot rounds are all zero-growth AND failure-free —
    convergence.is_converged is the single source of truth, shared with convergence.py's own
    `status` and case_state.convergence_verdict, so a round that collected 0/N due to failures
    never reads as CONVERGED here either. Falls back to the old bare rule only if the KB toolkit
    itself isn't importable."""
    p = os.path.join(ROOT, "cases", case, "rounds.jsonl")
    if not os.path.exists(p):
        return False
    rounds = [json.loads(l) for l in open(p, encoding="utf-8") if l.strip()]
    if _conv is not None:
        return _conv.is_converged(rounds, stale)
    if len(rounds) < stale:
        return False
    return all(r["new_hosts"] == 0 and r["new_indicators"] == 0 for r in rounds[-stale:])


# Registrant identifiers -> reverse-WHOIS estate. Only email+phone (hard rung-1 IDs); NAME is
# excluded (a common name false-merges unrelated domains — RULE 5).
_REVERSE_FLAG_ORCH = {"email": "--reverse-email", "phone": "--reverse-phone"}
_PLACEHOLDER_PHONES = {"14806242599", "4806242599", "15555555555", "5555555555",
                       "0000000000", "9999999999", "1234567890", "11111111111"}


def _rw_call(flag: str, term: str, mode: str) -> dict:
    """One whois_enrich reverse call (preview=free count / purchase=spend). Returns the reverse_*
    record or {} — never raises, so a network/credit failure degrades the frontier, never aborts."""
    try:
        r = T._run([sys.executable, os.path.join("WebPivot", "tools", "whois_enrich.py"),
                            flag, term, "--search-type", "historic", "--reverse-mode", mode, "--json"], timeout=150)
        data = json.loads(r.stdout or "{}")
    except Exception:  # noqa: BLE001
        return {}
    return (data.get("reverse_email") or data.get("reverse_name")
            or data.get("reverse_phone") or {})


def _case_registrant_terms(case: str) -> list[tuple[str, str]]:
    """(kind, value) registrant email/phone from the case's collected raw — the estate-builder
    seed. Privacy-proxy emails and placeholder/short phones are dropped so a shared registrar
    default never seeds a false estate (same noise doctrine as the assessment renderer)."""
    raw = os.path.join(ROOT, "cases", case, "raw")
    emails: set = set()
    phones: set = set()
    for p in glob.glob(os.path.join(raw, "*.json")):
        try:
            with open(p, encoding="utf-8") as fh:
                wh = (json.load(fh).get("artifacts") or {}).get("whois") or {}
        except Exception:  # noqa: BLE001
            continue
        em = (wh.get("registrant_email") or "").strip().lower()
        ph = "".join(ch for ch in str(wh.get("registrant_phone") or "") if ch.isdigit())
        if em and not T._is_noise_email(em):
            emails.add(em)
        if len(ph) >= 7 and len(set(ph)) > 1 and ph not in _PLACEHOLDER_PHONES:
            phones.add(ph)
    return [("email", e) for e in sorted(emails)] + [("phone", p) for p in sorted(phones)]


def _case_no_spend(case: str) -> bool:
    """The case intake's spend constraint (`scope.json` → constraints.no_spend)."""
    return bool((_scope(case).get("constraints") or {}).get("no_spend"))


def _reverse_whois_previews(case: str, known: set, cap: int) -> list[dict]:
    """FREE reverse-WHOIS preview counts for the case's registrant email/phone — never a purchase.

    Returns [{kind, term, count}] for every term whose count is 0 < count ≤ cap: the estate the
    cross-type loop may PROPOSE buying (an `rwhois.purchase` item in proposal.json, run only after
    the analyst approves it). A >cap count is shared-registrar NOISE and is never proposed. Under a
    `no_spend` scope even the preview is skipped. Each term is previewed at most once per case; the
    counts persist in cases/<case>/rwhois_previews.json so later rounds re-read them for free.
    `known` is accepted for call-site symmetry with the other seed sources; purchased domains are
    deduplicated downstream when the approved purchase is ingested."""
    if _case_no_spend(case):
        return []
    path = os.path.join(ROOT, "cases", case, "rwhois_previews.json")
    try:
        with open(path, encoding="utf-8") as fh:
            seen: dict = json.load(fh) or {}
    except Exception:  # noqa: BLE001 — missing/corrupt cache = nothing previewed yet
        seen = {}
    changed = False
    for kind, term in _case_registrant_terms(case):
        tag = f"{kind}:{term}"
        if tag in seen:
            continue
        n = (_rw_call(_REVERSE_FLAG_ORCH[kind], term, "preview") or {}).get("count", 0) or 0
        seen[tag] = {"kind": kind, "term": term, "count": int(n)}
        changed = True
        _log(f"  reverse-whois preview {kind}={term}: {n} domains"
             + (" — noise (>cap), never proposed" if n > cap else ""))
    if changed:
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(seen, fh, indent=2, sort_keys=True)
        except Exception:  # noqa: BLE001
            pass
    return [r for r in seen.values() if 0 < r.get("count", 0) <= cap]


def _reverse_whois_seeds(case: str, known: set, cap: int) -> dict:
    """Registrant reverse-WHOIS as a seed source: runs the FREE preview only (see
    _reverse_whois_previews) and returns no seeds by itself — buying the estate is a metered pivot
    the analyst approves per round through proposal.json, never an automatic purchase. Kept for its
    callers (`_discover_new_seeds`, `_hand_back`), which now receive {} from this source."""
    _reverse_whois_previews(case, known, cap)
    return {}

# A Censys/FOFA reverse-IP returning more co-hosted names than this is a SHARED/reseller box —
# its co-tenants are unrelated (§2.5 rung-10 noise) and must not seed. At/under it the box is
# plausibly one operator's (rung-8), so its co-tenants are chased. Kept small and conservative.
_DEDICATED_TENANT_MAX = int(os.environ.get("HARNESS_DEDICATED_TENANT_MAX", "8"))


# A `*.apex` wildcard zone answers EVERY fabricated label, so subdomain enumerators (validin_subs /
# securitytrails / censys_cert) keep returning the same handful of labels recombined — mail.mail.x,
# giaoduc.mail.x, thietbi.giaoduc.x — and each collected synthetic host spawns more, an unbounded
# frontier that never converges. These guards cap re-seeding to genuine direct subdomains of a known
# apex. HARNESS_MAX_SUB_DEPTH raises the cap for the rare legitimately-deep zone.
_MAX_SUB_DEPTH = int(os.environ.get("HARNESS_MAX_SUB_DEPTH", "1"))


def _has_repeated_label(host: str) -> bool:
    """mail.mail.x / giaoduc.giaoduc.x — an adjacent duplicated DNS label is a wildcard artifact."""
    labs = host.split(".")
    return any(labs[i] == labs[i + 1] for i in range(len(labs) - 1))


def _apex_set(hosts) -> set:
    """Registrable roots among `hosts`: a host that is NOT itself a subdomain of another host here."""
    hs = {h for h in hosts if h}
    return {h for h in hs if not any(h != g and h.endswith("." + g) for g in hs)}


def _too_deep(host: str, apexes: set) -> bool:
    """host nests more than _MAX_SUB_DEPTH labels below its matching apex (giaoduc.mail.x under
    apex x is depth 2). A host under no known apex is not our call, so it is allowed (False).
    Applied ONLY to subdomain-ENUMERATION sources (validin_subs / securitytrails): on a `*.apex`
    wildcard zone those recombine labels without bound. Cert-SAN and IP-co-tenant hosts are
    operator-chosen (a real `login.secure.brand.com` SAN is depth 2), so the depth cap is NOT
    applied to them — only the repeated-adjacent-label check is."""
    for a in apexes:
        if host == a:
            return False
        if host.endswith("." + a):
            sub = host[: -(len(a) + 1)]
            depth = sub.count(".") + 1 if sub else 0
            return depth > _MAX_SUB_DEPTH
    return False


def _wildcard_recursion(host: str, apexes: set) -> bool:
    """Full subdomain-enumeration guard: a repeated adjacent label (unambiguous junk, checked on
    every source) OR too-deep nesting below a known apex (the enumeration-only cap). Kept as the
    single predicate the subdomain path uses; the cert/co-tenant paths apply _has_repeated_label
    alone (see _discovered_infra_seeds)."""
    return _has_repeated_label(host) or _too_deep(host, apexes)


def _discovered_infra_seeds(case: str, known: set) -> dict:
    """Hosts surfaced by the STRONG premium reverses that pivot_extract ran but the loop left on the
    floor — re-seeded so the next round actually chases them. Restricted, on purpose, to the reverse
    sources that carry same-operator weight: an EXACT-LEAF cert reverse (censys_cert, §2.5 rung-4)
    and the target's OWN subdomains (validin_subs / securitytrails, same operator by construction).

    The broad favicon/body/IP-co-tenant reverses (FOFA/Hunter.how/Validin/urlscan/pdns) are
    DELIBERATELY EXCLUDED: on this very case they returned 54 hosts dominated by unrelated domains
    sharing only the commodity Flatsome template (rung-9 kit noise) — auto-seeding them would balloon
    the case with innocents (§2.5). Those stay LEADS in 'Discovered Infrastructure'; the verified way
    to promote an IP co-tenant is IP→co-tenant→forward-WHOIS (registrant match), not a blind reseed."""
    try:
        _wp = os.path.join(ROOT, "WebPivot", "tools")
        if _wp not in sys.path:
            sys.path.insert(0, _wp)
        import evidence_report as _er  # noqa: E402 — reuse its host extractor/noise filter
    except Exception:  # noqa: BLE001 — enhancement; a missing renderer must not break the loop
        return {}
    # STRONG-only: exact-leaf cert co-hosts + the target's own subdomains. NOT the favicon/body/IP
    # reverses (kit-level / shared-host = §2.5 noise; they remain unseeded leads).
    disc_keys = ("censys_cert", "validin_subs", "securitytrails")
    out: dict = {}
    apexes = _apex_set(known)
    for p in glob.glob(os.path.join(ROOT, "cases", case, "raw", "*.json")):
        try:
            with open(p, encoding="utf-8") as fh:
                doc = json.load(fh)
        except Exception:  # noqa: BLE001
            continue
        for piv in (doc.get("pivots") or []):
            lr = piv.get("live_results") or {}
            for key in disc_keys:
                blk = lr.get(key) or {}
                if not isinstance(blk, dict):
                    continue
                for h in (blk.get("hosts") or blk.get("domains")
                          or blk.get("names") or blk.get("results") or []):
                    hh = _er._discovered_host(h)
                    if (hh and "." in hh and "*" not in hh and not hh.replace(".", "").isdigit()
                            and hh not in known and not _er._is_infra_noise_host(hh)
                            and not (_wildcard_recursion(hh, apexes)
                                     if key in ("validin_subs", "securitytrails")
                                     else _has_repeated_label(hh))
                            and not T._find_cached_raw(hh)):
                        out[hh] = max(out.get(hh, 0), 50)   # moderate: a reverse-lookup lead
        # Censys IP-host co-tenants (live_results["censys"].dns_names, wp_ippivot) — reseeded ONLY
        # from a DEDICATED box (few co-hosted names). §2.5: co-tenancy on a dedicated host is a
        # moderate same-operator signal (rung-8); on a shared/reseller box (many tenants) it is
        # rung-10 NOISE, so a >threshold box is skipped rather than dumping innocents into the
        # frontier. (A shared box's genuine siblings are recovered by registrant reverse-WHOIS +
        # the forward-WHOIS-filtered path, not by a blind co-tenant reseed.)
        for piv in (doc.get("pivots") or []):
            cz = (piv.get("live_results") or {}).get("censys") or {}
            tenants = cz.get("dns_names") if isinstance(cz, dict) else None
            if not tenants or len(tenants) > _DEDICATED_TENANT_MAX:
                continue
            for h in tenants:
                hh = _er._discovered_host(h)
                if (hh and "." in hh and "*" not in hh and not hh.replace(".", "").isdigit()
                        and hh not in known and not _er._is_infra_noise_host(hh)
                        and not _has_repeated_label(hh)
                        and not T._find_cached_raw(hh)):
                    out[hh] = max(out.get(hh, 0), 40)   # moderate-: dedicated-box co-tenant (rung-8)
    return out


def _discover_new_seeds(case: str, known: list[str], max_new: int) -> list[str]:
    """The next round's frontier: KB cluster-peers of the case's collected domains that are NOT
    yet collected anywhere (genuinely new infrastructure). Uses --strong so peers linked only by
    boilerplate (shared WP-Rocket CSS/comment/DOM template) are excluded — that noise otherwise
    balloons the case into unrelated operators. Ranked by shared-indicator count, capped at
    max_new. Peers already investigated in any case are excluded (known, not new frontier) —
    cross-case links surface via which_cases instead."""
    known_hosts = {T._host(s) for s in known}
    raw = os.path.join(ROOT, "cases", case, "raw")
    collected = [os.path.basename(p)[:-5] for p in glob.glob(os.path.join(raw, "*.json"))]
    scores: dict[str, int] = {}
    for dom in collected:
        r = T._run([sys.executable, os.path.join("tools", "kb", "query.py"),
                            "--kb", T.KB_DIR, "--cluster", dom, "--strong"], timeout=120)
        for line in (r.stdout or "").splitlines():
            m = re.match(r"^\s+(\S+)\s+via\s+(\d+)\s+shared", line)
            if not m:
                continue
            peer, nshared = m.group(1), int(m.group(2))
            if peer in known_hosts or T._host(peer) != peer or T._find_cached_raw(peer):
                continue
            scores[peer] = max(scores.get(peer, 0), nshared)
    # AUTO REVERSE-WHOIS (whoisxml): the case registrant → its estate, merged at top priority so the
    # loop pivots the whole operator estate without an analyst approving the single highest-yield lead.
    rw_cap = int(os.environ.get("HARNESS_RWHOIS_CAP", "150"))
    for d, sc in _reverse_whois_seeds(case, known_hosts, cap=rw_cap).items():
        scores[d] = max(scores.get(d, 0), sc)
    # REVERSE-DISCOVERED INFRA (fofa/urlscan/hunter.how/censys/validin/…): hosts the per-host
    # reverses already surfaced, now re-seeded so the loop actually chases them (moderate priority).
    for d, sc in _discovered_infra_seeds(case, known_hosts).items():
        scores[d] = max(scores.get(d, 0), sc)
    return sorted(scores, key=lambda p: -scores[p])[:max_new]


def _sdk_seed_sources(case: str, known) -> list:
    """Wrap the three kept SDK seed functions as Candidates for case_state.propose(extra=...).

    - `_discover_new_seeds` peers → type=domain tool=collect sources=('sdk.kb_peer',)
      (infra hosts already returned by `_discovered_infra_seeds` are labelled sdk.infra instead)
    - `_discovered_infra_seeds` → type=domain tool=collect sources=('sdk.infra',)
    - `_reverse_whois_previews` → type=email|phone tool=rwhois.purchase metered=True
      est_hits=count rung=owner sources=('sdk.rwhois_preview',)

    Does not change the three underlying functions. propose() still runs never_seed / noise /
    depth guards on anything domain-typed.
    """
    # selector_types lives on tools/ (already on sys.path via orchestrator bootstrap)
    try:
        from selector_types import Candidate, candidate_id  # noqa: WPS433
    except Exception:  # noqa: BLE001 — propose path optional at import time
        return []

    if isinstance(known, (set, frozenset, tuple)):
        known_list = list(known)
    else:
        known_list = list(known or [])
    known_set = {str(k).strip().lower() for k in known_list if k}

    out: list = []
    seen_ids: set = set()

    def _add(c: "Candidate") -> None:
        if c.id in seen_ids:
            return
        seen_ids.add(c.id)
        out.append(c)

    # 1) infra reverses (strong cert / own-sub / dedicated co-tenant)
    try:
        infra = _discovered_infra_seeds(case, known_set) or {}
    except Exception:  # noqa: BLE001
        infra = {}
    infra_hosts = set()
    for host, sc in infra.items():
        h = (host or "").strip().lower()
        if not h:
            continue
        infra_hosts.add(h)
        q = h
        tool = "collect"
        _add(Candidate(
            id=candidate_id("domain", h, tool, q),
            type="domain", selector=h, tool=tool, query=q,
            # Reverse-IP / dedicated-tenant mining: co-tenancy, not ownership (rung table) — the
            # host is collected free-only but stays a NEIGHBOUR, never attributed.
            metered=False, est_hits=1, rung="neighbour",
            origins=(), sources=("sdk.infra",),
            why=f"SDK discovered infra (score {sc})", by="sdk",
        ))

    # 2) KB cluster peers (+ any leftover from discover not already infra-labelled)
    max_new = int(os.environ.get("HARNESS_MAX_NEW", "32") or 32)
    try:
        peers = _discover_new_seeds(case, known_list, max_new) or []
    except Exception:  # noqa: BLE001
        peers = []
    for peer in peers:
        h = (peer or "").strip().lower()
        if not h or h in infra_hosts:
            continue
        q = h
        tool = "collect"
        _add(Candidate(
            id=candidate_id("domain", h, tool, q),
            type="domain", selector=h, tool=tool, query=q,
            # `query.py --strong` peers still join on favicon / social / css-hash edges (kit
            # classes) — kit unless other evidence (a frontier owner source) merges in.
            metered=False, est_hits=1, rung="kit",
            origins=(), sources=("sdk.kb_peer",),
            why="SDK KB cluster peer", by="sdk",
        ))

    # 3) reverse-WHOIS free previews → metered purchase candidates
    rw_cap = int(os.environ.get("HARNESS_RWHOIS_CAP", "150"))
    try:
        previews = _reverse_whois_previews(case, known_set, rw_cap) or []
    except Exception:  # noqa: BLE001
        previews = []
    for row in previews:
        if not isinstance(row, dict):
            continue
        kind = str(row.get("kind") or "").strip().lower()
        term = str(row.get("term") or "").strip()
        if kind not in ("email", "phone") or not term:
            continue
        try:
            count = int(row.get("count") or 0)
        except (TypeError, ValueError):
            count = 0
        tool = "rwhois.purchase"
        q = term
        _add(Candidate(
            id=candidate_id(kind, term, tool, q),
            type=kind, selector=term, tool=tool, query=q,
            metered=True, est_hits=count, rung="owner",
            origins=(), sources=("sdk.rwhois_preview",),
            why=f"reverse-WHOIS preview count={count}", by="sdk",
        ))
    return out


# --------------------------------------------------------------- cross-type loop (typed pivots)
# Every selector type is a frontier node. Between rounds: case_state.propose() lists typed
# candidates (frontier miners + KB-linked nodes + the case's node registry + the SDK seed sources),
# the PLAN phase (read-only PLAN_TOOLS) re-ranks them and adds cross-type pivots, proposal.split()
# runs the free/quota-backed ones within auto_max on its own and writes everything else to a
# digest-bound proposal.json the analyst approves. audit.gate() enforces the approval.
PLAN_TOP = int(os.environ.get("HARNESS_PLAN_TOP", "60"))     # candidates shown to the planner


def _cand_rows(cands) -> str:
    lines = ["id | type | selector | route | metered | est_hits | rung | sources | why"]
    for c in cands[:PLAN_TOP]:
        lines.append(f"{c.id} | {c.type} | {c.selector} | {c.tool} | {'yes' if c.metered else 'no'} | "
                     f"{'?' if c.est_hits is None else c.est_hits} | {c.rung} | "
                     f"{','.join(c.sources)[:60]} | {c.why[:90]}")
    if len(cands) > PLAN_TOP:
        lines.append(f"… {len(cands) - PLAN_TOP} more (lower-ranked) candidates not shown")
    return "\n".join(lines)


async def _plan_round(case: str, cands: list, *, hostile: bool) -> list:
    """The PLAN phase: re-rank the proposer's candidates and add cross-type pivots. REQUIRED — a
    failed plan stops the round (raises); the loop never pivots unplanned. Additions are validated
    by case_state (route exists and accepts the type, domain guards, count probe, pivot_map
    pricing) — the planner can neither size nor price its own pivot."""
    import case_state as cs
    from selector_types import auto_max_hits
    res = await _phase(
        _prompt("plan", scope=case_scope.judgment_directives(_scope(case)), case=case,
                auto_max=str(auto_max_hits()), candidates=_cand_rows(cands)),
        label="plan", system=_skill("IntelAnalysis"), tools=T.PLAN_TOOLS,
        servers={"analyze": T.ANALYZE_SERVER}, model=JUDGE.model, effort=JUDGE.effort,
        output_schema=Plan, hostile=hostile, case=case)
    if not (res and res.subtype == "success" and res.structured_output):
        raise RuntimeError("plan phase produced no structured plan")
    plan = Plan.model_validate(res.structured_output)
    by_id = {c.id: c for c in cands}
    dropped = {d.id for d in plan.dropped}
    for d in plan.dropped:
        _log(f"    plan drop {d.id}: {d.why[:100]}")
    # persisted (state.json `dropped`) so propose() never re-offers a vetoed candidate next round
    cs.mark_dropped(case, [(d.id, d.why) for d in plan.dropped if d.id in by_id and d.why])
    order = [i for i in plan.ranked if i in by_id and i not in dropped]
    order += [c.id for c in cands if c.id not in set(order) and c.id not in dropped]
    added = cs.accept_extras(case, [{"type": a.type, "selector": a.selector, "tool": a.tool,
                                     "query": a.selector, "why": a.why, "by": "planner",
                                     "sources": ["planner"]} for a in plan.added])
    if len(added) < len(plan.added):
        _log(f"    plan: {len(plan.added) - len(added)} addition(s) rejected by validation "
             f"(unknown route / type mismatch / never-seed / filename-as-host)")
    if plan.notes:
        _log(f"    plan notes: {plan.notes[:200]}")
    seen = set(order)
    return [by_id[i] for i in order] + [c for c in added if c.id not in seen]


def _execute_items(case: str, items, *, hostile: bool, approved_run: bool = False) -> list[str]:
    """Run pivots: a `collect` domain (or historical origin IP) becomes next round's seed; every
    other route goes through audit.gate() (the approval rule lives there) and pivot_routes.execute
    (rows → KB rung-aware, → typed nodes). Returns the seeds to collect. Marks every dispatched id
    pivoted."""
    import case_state as cs
    import pivot_routes as PR
    new, done = [], []
    kb = T.KB_DIR if os.path.isabs(T.KB_DIR) else os.path.join(ROOT, T.KB_DIR)
    for it in items:
        d = it if isinstance(it, dict) else it.to_dict()
        if d.get("tool") == "collect":
            sel = str(d["selector"]).lower()
            if sel not in new:
                new.append(sel)
            # Record HOW the host was reached, so the tier rail (case_state.tier_hosts) keeps an
            # IP co-tenant / kit-only host out of attribution even though it is collected. An origin
            # IP is recorded as an `ip` node (collect_core routes a bare IP to IPPivot).
            cls = {"owner": "owner_link", "neighbour": "ip.cotenant"}.get(d.get("rung"), "kit_link")
            origin = (d.get("origins") or ["frontier"])[0]
            ntype = "ip" if d.get("type") == "ip" else "domain"
            cs.add_nodes(case, [{"type": ntype, "value": sel, "rung_class": cls}],
                         origin_type="domain", origin_value=origin,
                         route="collect:" + ",".join(d.get("sources") or [])[:80])
            if ntype == "ip":
                # the hop of the HOST that resolved there (same rule as intel._promote), before
                # _record_hops would otherwise place it after the deepest seed of the round
                cs.record_origin_ip_hop(case, sel, d.get("origins") or ())
            if approved_run:
                # an APPROVED `vps co-tenancy — approve` item carries its box: record THIS domain as
                # approved for that box — only items that actually ran, never the whole IP
                for src in d.get("sources") or ():
                    if str(src).startswith("approve_ip:"):
                        cs.record_approved_cohost(case, str(src).split(":", 1)[1], [sel])
            done.append(d["id"])
            continue
        args = {"route": d["tool"], "query": d["query"], "case": case}
        allowed, why = audit.gate("corpus_search", args, case=case, phase="xtype-exec",
                                  hostile=hostile)
        if not allowed:
            _log(f"    ✗ {d['id']} {d['tool']} {d['selector'][:40]} — {why[:120]}")
            continue
        if d["tool"] == "enrich.host":
            # APPROVED keyed enrichment: re-collect the host with the metered layers on (the only
            # path that passes allow_spend), then ingest — the gate above already consumed the id.
            # passive on a hostile case: keyed enrichment then uses third-party sources only
            res = T.collect_one(d["selector"], case, hostile=hostile, passive=hostile, force=True,
                                allow_spend=True)
            ok_, _note = T.ingest(case) if res.get("ok") else (False, "")
            _log(f"    · enrich.host({d['selector'][:40]}) → "
                 f"{'ok' if res.get('ok') else 'ERROR: ' + str(res.get('error') or res.get('note'))[:120]}")
            if res.get("ok") and ok_:
                done.append(d["id"])
            continue
        # Hits are never stronger than the candidate: a pivot sourced from a kit/neighbour host
        # (rung capped in propose) cannot write owner edges or create owner evidence.
        r = PR.execute(d["tool"], d["query"], case=case, origin_type=d["type"],
                       origin_value=d["selector"], hostile=hostile, kb_root=kb,
                       rung_cap=d.get("rung") if d.get("rung") in ("kit", "neighbour") else "")
        state = ("skipped: " + str(r.get("skipped"))) if r.get("skipped") else \
                ("ERROR: " + str(r.get("error"))) if r.get("error") else \
                f"{r.get('rows', 0)} row(s), {r.get('nodes_added', 0)} new node(s)"
        _log(f"    · {d['tool']}({d['selector'][:40]}) → {state}")
        # A transient error (a Wayback 503, a urlscan timeout) must not drop the lead for good:
        # it stays un-pivoted and is re-offered next round. A skip (no key, unsupported coin) is
        # a stable answer and is recorded as done.
        if not r.get("error") and not r.get("ingest_error") and not r.get("nodes_error"):
            done.append(d["id"])
    if done:
        cs.mark_pivoted(case, done)
    return new


def _run_approved(case: str, *, hostile: bool) -> tuple[list[str], bool]:
    """Resume path: run exactly the ids the analyst approved (digest re-checked, set frozen),
    then close the proposal. Returns (domain seeds those items produced, whether a proposal ran)."""
    started = P.begin_run(ROOT, case)
    if started.get("error"):
        data = P.load(ROOT, case) or {}
        if data.get("status") in ("pending", "approved"):
            _log(f"  proposal: {started['error']}")
        return [], False
    items = started.get("items") or []
    rejected = (P.load(ROOT, case) or {}).get("rejected") or []
    if rejected:
        import case_state as cs
        cs.mark_pivoted(case, rejected)   # the analyst said no: never re-propose these ids
    _log(f"\n▶ approved proposal · running {len(items)} item(s) · {len(rejected)} rejected")
    try:
        return _execute_items(case, items, hostile=hostile, approved_run=True), True
    finally:
        P.mark_consumed(ROOT, case)


async def _xtype_step(case: str, current: list[str], *, hostile: bool, round_no: int,
                      max_new: int = 8, last_round: bool = False):
    """One round boundary of the cross-type loop → (new domain seeds, stop reason | None).

    FREE WORK DRAINS FIRST: free corpus pivots within auto_max run, and host collections
    (`collect`, at most `max_new` per round) continue, while metered / oversized / unknown-size
    pivots are HELD. The loop pauses for approval only when no free work is left (or on the last
    round, so the analyst still sees what is pending) — so routes without a count probe never
    stall free-frontier collection. Held items are not marked pivoted; propose() re-offers them."""
    import case_state as cs
    from selector_types import auto_max_hits
    cands = cs.propose(case, extra=_sdk_seed_sources(case, _all_collected(case) + list(current)))
    if not cands:
        # Only Plan-dropped leads left (state.json `dropped`, never re-offered): still a planner
        # judgment, not an exhausted frontier — hand back, same as a whole-frontier veto.
        if cs.load_state(case).get("dropped"):
            _log("  ⏸ only planner-dropped candidate(s) remain — handing back to the analyst")
            return [], "plan-veto"
        return [], "no-frontier"
    _log(f"\n▶ cross-type frontier · {len(cands)} candidate(s)")
    planned = await _plan_round(case, cands, hostile=hostile)
    if not planned:
        # The planner vetoed EVERY candidate. That is a judgment to show the analyst, never a
        # finding that the frontier is exhausted — so the case is handed back, not marked cold.
        _log(f"  ⏸ the planner dropped all {len(cands)} candidate(s) — handing back to the analyst")
        return [], "plan-veto"
    auto, needs, dropped = P.split(planned, no_spend=_case_no_spend(case), auto_max=auto_max_hits())
    for c in dropped:
        _log(f"    no_spend: dropped metered {c.tool}({c.selector[:40]})")
    pivots = [c for c in auto if c.tool != "collect"]
    collects = [c for c in auto if c.tool == "collect"]
    if pivots:
        _execute_items(case, pivots, hostile=hostile)
    pause = bool(needs) and ((not pivots and not collects) or last_round)
    # a pausing or FINAL round never consumes collects it cannot run (nothing investigates them
    # after it) — they stay un-pivoted, so the next run's propose() offers them again
    new = (_execute_items(case, collects[:max(0, max_new)], hostile=hostile)
           if collects and not pause and not last_round else [])
    if pause:
        P.write(ROOT, case, round_no=round_no, items=needs, dropped=dropped)
        _log(f"  ⏸ {len(needs)} pivot(s) need approval (metered / >{auto_max_hits()} hits / unknown "
             f"size) → cases/{case}/{P.PROPOSAL_FILE}")
        return [], "awaiting-approval"
    if needs:
        _log(f"  … {len(needs)} pivot(s) held for approval until the free work drains")
    if not pivots and not collects:
        return [], "no-frontier"
    return new, None


def _xtype_pending(case: str) -> bool:
    """Typed candidates still open (probe-free) — zero host/indicator growth is not convergence
    while the cross-type frontier still has work. Plan-dropped leads (state.json `dropped`) are
    never re-offered but still await the analyst, so they keep the case from reading converged."""
    try:
        import case_state as cs
        return bool(cs.propose(case, probe=False)) or bool(cs.load_state(case).get("dropped"))
    except Exception:  # noqa: BLE001 — unknown frontier is never 'converged'
        return True


def _binary_round(case: str, *, hostile: bool, free_only: bool) -> None:
    """Download/static-analyze binaries; ingest separately from the web-host collections."""
    import binary_auto
    for note in binary_auto.run(case, hostile=hostile, free_only=free_only):
        _log("  " + note)
    ok, note = binary_auto.ingest(os.path.join(ROOT, "cases", case),
                                  os.path.join(ROOT, T.KB_DIR))
    if not ok:
        _log("  binary KB ingest failed: " + note[-500:])


async def _leak_round(case: str, *, hostile: bool) -> None:
    """MANDATORY leak/stealer fan-out on the case's CONFIRMED selectors (seeds, owner-rung nodes,
    first-round registrant contacts — never kit/neighbour ones), run after collection and BEFORE
    the cross-type step, so metered co-tenant/frontier pivots can never starve it. It is
    case_enrich restricted to its leak leads: the spend gate still applies (scope.json no_spend →
    keyless CLD only, metered vendors recorded as not consulted; HARNESS_NO_ENRICH smoke →
    --free-only). ONCE PER CASE: the attempt is recorded in state.json `leak_round` (ran_at, exit)
    whatever its outcome, so later rounds and resumes never re-fan-out — retryable / held legs stay
    OPEN for `intel.py enrich <case> --leak-only` (or case_enrich), which reuses the checkpoints.
    Off the event loop (a slow vendor must not block the stdin/MCP loop)."""
    import case_state as cs
    try:
        if cs.load_state(case).get("leak_round"):
            return
    except Exception as e:  # noqa: BLE001 — unreadable state: skip rather than risk a repeat
        _log(f"  leak fan-out skipped (state unreadable: {e}) — run intel.py enrich {case} --leak-only")
        return
    cmd = [sys.executable, os.path.join("tools", "intel.py"), "enrich", case, "--leak-only"]
    if T.SMOKE:
        cmd.append("--free-only")
    if hostile:
        cmd.append("--passive")
    rc = None
    try:
        r = await asyncio.to_thread(T._run, cmd, 1800)
        rc = r.returncode
        for line in (r.stdout or "").splitlines():
            if "leak coverage" in line or line.startswith("     ") or "enrichment" in line:
                _log("  " + line.strip())
        if rc != 0:
            _log(f"  leak fan-out exit {rc}: {(r.stderr or '')[-300:]}")
    except Exception as e:  # noqa: BLE001 — a failed leak step is reported, never fatal
        _log(f"  leak fan-out failed: {e}")
    if rc != 0:
        _log(f"  → open leak legs stay on the frontier; rerun: intel.py enrich {case} --leak-only")
    try:
        st = cs.load_state(case)
        st["leak_round"] = {"ran_at": datetime.datetime.now(datetime.timezone.utc)
                            .strftime("%Y-%m-%dT%H:%M:%SZ"), "exit": rc}
        cs.save_state(case, st)
    except Exception as e:  # noqa: BLE001
        _log(f"  (leak_round marker not written: {e})")


# Stop reason -> the state.json status vocabulary the deterministic loop already uses
# (tools/case_state.py: expanding | converged | cold | awaiting-analyst | awaiting-approval |
# error). ONE vocabulary, ONE state file: `./intel status`, `case_state.py reopen` and
# `intel.py loop` all read what an SDK run leaves behind, and an SDK run resumes what the
# deterministic loop left. awaiting-approval = the cross-type loop wrote a proposal.json.
_STOP_STATUS = {"converged": "converged", "no-frontier": "cold",
                "depth-cap": "awaiting-analyst", "round-cap": "awaiting-analyst",
                "failed": "error", "backend-unavailable": "awaiting-analyst",
                "awaiting-approval": "awaiting-approval", "plan-veto": "awaiting-analyst"}


def _hand_back(case: str, stop: str, *, rounds: int, seeds: list[str], depth: int) -> None:
    """The end-of-run hand-back to the analyst — the SDK path's equivalent of what `intel.py loop`
    already prints. A run that just stops is a run whose next step lives only in the operator's
    head; this writes WHY it stopped and WHAT is still pending into the shared
    cases/<case>/state.json, then says how to resume.

    The distinction that matters is `cold` vs `awaiting-analyst`: cold means the free frontier is
    genuinely exhausted (stopping is the finding), awaiting-analyst means work remains and only the
    round cap ended the run — including the DEFAULT single-round `./intel open`, which previously
    exited identically whether it had converged or merely run out of permission to continue.
    Metered leads are surfaced but never auto-run: spending FOFA/WhoisXML/Censys credits stays an
    analyst decision. Best-effort throughout — a failure here must not fail an otherwise good case."""
    case_dir = os.path.join(ROOT, "cases", case)
    pending, metered, probed = [], [], True
    try:
        import case_state as cs
    except Exception as e:  # noqa: BLE001
        _log(f"  (hand-back skipped: case_state unavailable — {e})")
        return
    # Two independent probes, caught separately. `cold` is a SUBSTANTIVE claim — "the free search
    # is exhausted" — so it may only be made when the frontier was actually computed. A probe that
    # threw must not be reported as an empty frontier; that is how a silent failure becomes a
    # finding. When it fails we stay on awaiting-analyst and say the frontier is unknown.
    if stop not in ("failed", "backend-unavailable"):
        try:
            pending = _discover_new_seeds(case, seeds, max_new=25)
        except Exception as e:  # noqa: BLE001
            probed = False
            _log(f"  (frontier probe FAILED: {e} — frontier unknown, not assumed empty)")
        try:
            metered = (cs.frontier(case, max_new=25) or {}).get("metered_leads", [])
        except Exception as e:  # noqa: BLE001
            _log(f"  (metered-lead probe failed: {e})")

    status = _STOP_STATUS.get(stop, "expanding")
    if stop in ("depth-cap", "round-cap") and not pending:
        # The cap was never the binding constraint — unless we could not tell, in which case the
        # analyst gets asked rather than told.
        status = "cold" if probed else "awaiting-analyst"
    try:
        st = cs.load_state(case)
        st["status"] = status
        st["round"] = max(int(st.get("round") or 0), rounds)
        st["depth_limit"] = depth
        st["collected"] = sorted(cs.collected_hosts(case_dir))
        st["pending"] = pending
        st["metered_leads"] = metered
        st["history"].append({"round": st["round"], "collected": len(st["collected"]),
                              "verdict": stop, "driver": "orchestrator",
                              "ts": datetime.datetime.now(datetime.timezone.utc)
                              .strftime("%Y-%m-%dT%H:%M:%SZ")})
        cs.save_state(case, st)
    except Exception as e:  # noqa: BLE001
        _log(f"  (state.json not written: {e})")
        return

    _log(f"\n== case '{case}': status={status} · {len(st['collected'])} host(s) · "
         f"{st['round']} round(s) · stopped: {stop} ==")
    _log(f"   assessment: cases/{case}/SUMMARY.md   (snapshots: cases/{case}/assessments/)")
    if status == "awaiting-analyst":
        if pending:
            _log(f"   ⏸ {len(pending)} uncollected cluster peer(s) still on the free frontier: "
                 f"{', '.join(pending[:8])}{' …' if len(pending) > 8 else ''}")
        else:
            _log("   ⏸ frontier UNKNOWN — the peer probe failed, so this run cannot say whether "
                 "leads remain. Treat as unfinished, not as exhausted.")
        _log(f"   → CONTINUE:  ./intel continue {case} {' '.join(seeds[:2])}"
             f"{' …' if len(seeds) > 2 else ''}   (or: python3 tools/intel.py loop {case})")
    elif status == "converged":
        _log("   ✓ converged — the last rounds added no new hosts or indicators. "
             "Reopen only if new evidence lands:")
        _log(f"   → REOPEN:    python3 tools/case_state.py reopen {case} <new-seed>")
    elif status == "cold":
        _log("   ✗ no free frontier left (stopping is itself the finding — a keyless/free search "
             "is exhausted, which is NOT the same as 'nothing exists').")
        _log(f"   → REOPEN:    python3 tools/case_state.py reopen {case} <new-seed>")
    elif status == "awaiting-approval":
        _log("   ⏸ the cross-type loop needs YOUR approval for the pivots below "
             "(metered, oversized or of unknown size) — nothing was spent on them:")
        for line in P.render(P.load(ROOT, case) or {}).splitlines():
            _log("     " + line)
        _log(f"   → APPROVE:   ./intel approve {case} --only <id,id> (or --all), then "
             f"./intel continue {case}")
    if metered:
        _log(f"   ⚠ {len(metered)} metered lead(s) await YOUR approval (would spend FOFA / "
             f"WhoisXML / Censys credits — never auto-run):")
        for m in metered[:5]:
            _log(f"       · {m.get('service', '?')} {str(m.get('query', ''))[:60]} — "
                 f"{str(m.get('why', ''))[:70]}")
    _log(f"   state: cases/{case}/state.json   ·   ./intel status {case}")
    try:
        import next_actions
        next_actions.emit_or_prompt(case, pending=pending, metered=metered, status=status, seeds=seeds)
    except Exception as e:  # noqa: BLE001
        _log(f"  (next_actions prompt skipped: {e})")


async def run_case(seeds: list[str], case: str, *, hostile: bool, depth: int,
                   stale: int, max_new: int, collect_conc: int = 1,
                   resume: bool = False) -> Assessment | None:
    """One or more rounds of the cross-type loop. A round with new DOMAIN seeds runs
    Collect→Correlate→(Verify)→Assess and snapshots an immutable assessment; every round boundary
    then runs the cross-type step (_xtype_step: propose → PLAN → free pivots within auto_max run,
    the rest wait in proposal.json). Seeds of ANY type are accepted: a non-domain seed (email,
    phone, wallet, IP, hash, string, filename, telegram) enters the case's typed node registry
    and is pivoted on, never collected as a host. Stops on CONVERGED, the depth cap, an empty
    frontier, or awaiting-approval. collect_conc>1 fans collect out per seed (collect_fanout)."""
    import case_state as cs
    domains = cs.register_seed_nodes(case, seeds)
    _record_seeds(case, domains)
    P.set_loop_active(ROOT, case, True)
    approved_new, ran = _run_approved(case, hostile=hostile)
    resume = resume or ran            # a run that consumed an approval continues the case
    # The judged set always contains the analyst's seeds: on a resume the round's new hosts are
    # judged TOGETHER with the subject of the case, so no round can replace the case assessment
    # with a judgment about peripheral hosts alone (they are already collected — never re-fetched).
    current: list[str] = (sorted(_run_seeds(case) & {T._host(h) for h in _all_collected(case)})
                          if resume else [])
    fresh = approved_new + domains
    if resume:
        # Seedless `continue`: never re-collect / re-judge hosts the case already holds — only
        # what the approved pivots and the cross-type frontier surface from here on.
        have = set(_all_collected(case))
        fresh = [s for s in fresh if T._host(s) not in have]
    final, stop, rnd = None, "depth-cap", 0
    try:
        for rnd in range(1, depth + 1):
            fresh = [s for s in dict.fromkeys(fresh) if s not in current]
            # Consent to keyed collection is PER HOST (proposal.collect_free_only): the analyst's
            # own typed seeds (harness_seeds.json) collect with the keyed layers; every other host —
            # including ones an agent reaches inside round 1 — collects --free-only and earns keyed
            # enrichment only through an approved `enrich.host` item. The gate is on all run long.
            P.set_loop_active(ROOT, case, True)   # also renews the lease every round
            # Round 1 of a resume always re-judges the seed set (current), even with no new host:
            # typed pivots add evidence without adding hosts, and the case assessment must be a
            # judgment ABOUT THE SEEDS (never left as an earlier round's peripheral verdict).
            rejudge = rnd == 1 and resume and bool(current) and not fresh
            if fresh or rejudge:
                _record_hops(case, [T._host(s) for s in fresh if s not in domains], current)
                current = current + fresh
                _log(f"\n===== ROUND {rnd}/{depth} · {len(current)} seed(s): {', '.join(current)} =====")
                before = set(_all_collected(case))
                try:
                    final = await investigate(current, case, hostile=hostile, collect_conc=collect_conc)
                except backend_select.BackendUnavailable as e:
                    # Not a case failure: the backend stopped answering. Leave the case resumable
                    # and let harness/cli.py offer another backend.
                    _log(f"round {rnd} stopped: {e}")
                    _hand_back(case, "backend-unavailable", rounds=rnd, seeds=current, depth=depth)
                    raise
                except Exception as e:  # noqa: BLE001
                    _log(f"round {rnd} failed: {e}")
                    stop = "failed"
                    break
                _binary_round(case, hostile=hostile, free_only=False)
                await _leak_round(case, hostile=hostile)   # before any metered frontier pivot
                table_md = _domain_table(case)
                render.render_terminal(final, table_md=table_md)
                snap = _persist_assessment(final, case, table_md)
                _log(f" saved · {snap['snapshot_md']} (round {snap['round']}) · head {snap['summary']}")
                # A collect phase that wrote nothing for seeds it was given is a FAILED round, so
                # it can never read as convergence (zero growth because nothing ran).
                missing = [s for s in fresh if T._host(s) not in before]
                failed = ([f"collect wrote no raw for: {', '.join(missing[:5])}"]
                          if missing and not (set(_all_collected(case)) - before) else None)
                conv = _convergence_snapshot(case, failed=failed)
                if conv:
                    _log("convergence · " + conv.splitlines()[0])
                if depth == 1:
                    # The DEFAULT single-round `./intel open`: stopped because it was asked for one
                    # round — _hand_back decides between awaiting-analyst and cold.
                    stop = "round-cap"
                    break
                if _is_converged(case, stale) and not _xtype_pending(case):
                    _log(f"convergence: CONVERGED — last {stale} rounds added nothing new. Stopping.")
                    stop = "converged"
                    break
            else:
                _log(f"\n===== ROUND {rnd}/{depth} · cross-type pivots only (no new hosts to collect) =====")
                if rnd == 1:                # typed-only seeds (email / handle / phone): leak first
                    await _leak_round(case, hostile=hostile)
            P.set_loop_active(ROOT, case, True)   # the seed round is over: loop rules from here
            try:
                new, xstop = await _xtype_step(case, current, hostile=hostile, round_no=rnd,
                                               max_new=max_new, last_round=rnd == depth)
            except backend_select.BackendUnavailable as e:
                _log(f"round {rnd} plan stopped: {e}")
                _hand_back(case, "backend-unavailable", rounds=rnd, seeds=current, depth=depth)
                raise
            except Exception as e:  # noqa: BLE001 — planner REQUIRED: never pivot unplanned
                _log(f"round {rnd} cross-type step failed: {e}")
                stop = "failed"
                break
            fresh = new
            if xstop:
                stop = xstop
                break
            if new:
                _log(f"→ round {rnd + 1}: {len(new)} new host(s) to collect: {', '.join(new)}")
    finally:
        P.set_loop_active(ROOT, case, False)
    _hand_back(case, stop, rounds=rnd, seeds=current or list(seeds), depth=depth)
    if final is None and not resume and stop not in ("awaiting-approval", "no-frontier", "plan-veto"):
        raise RuntimeError("no assessment produced")
    return final


# ------------------------------------------------------- Phase 3: parallel + cluster-level judge
def _partition_components(case: str, domains: list[str]) -> list[list[str]]:
    """Partition the case's collected domains into same-operator clusters — one cluster == one unit
    of LLM judgment, so cost scales with cluster count, not domain count.

    The partition is the deterministic pipeline's own (`tools/intel.py clusters` → clusters.json:
    strong edges only, landlord IPs excluded, hosts at the expansion depth kept out as
    `related_hosts`), so what the harness judges is exactly what clusters.json — which house-report,
    build_report_data and the loop read — says. It used to partition in memory only, leaving
    clusters.json at an older round's view that disagreed with the judged head. A scratch KB
    (HARNESS_KB) or a failed run falls back to the raw KB component query, without persisting."""
    if os.path.realpath(os.path.join(ROOT, T.KB_DIR)) == os.path.realpath(os.path.join(ROOT, "knowledge")):
        r = T._run([sys.executable, os.path.join("tools", "intel.py"), "clusters", case], timeout=300)
        try:
            with open(os.path.join(ROOT, "cases", case, "clusters.json"), encoding="utf-8") as f:
                doc = json.load(f)
            comps = [list(c["domains"]) for c in doc.get("clusters") or [] if c.get("domains")]
        except (OSError, ValueError, KeyError, TypeError):
            doc, comps = {}, []
        if r.returncode == 0 and comps:
            if doc.get("related_hosts"):
                _log(f"  clusters.json: {len(doc['related_hosts'])} host(s) at the expansion depth kept "
                     f"out as related (not judged): {', '.join(doc['related_hosts'][:8])}")
            return comps
        _log("  clusters.json partition unavailable — falling back to the KB component query "
             "(clusters.json NOT refreshed)")
    hosts = sorted({T._host(d) for d in domains})
    r = T._run([sys.executable, os.path.join("tools", "kb", "query.py"),
                        "--kb", T.KB_DIR, "--components", "--domains", ",".join(hosts)], timeout=120)
    comps = []
    for line in (r.stdout or "").splitlines():
        if line.startswith("COMPONENT"):
            members = [d.strip() for d in line.partition("\t")[2].split(",") if d.strip()]
            if members:
                comps.append(members)
    return comps or [hosts]      # fallback: treat everything as one cluster if the KB/parse failed


def _compute_components(case: str, domains: list[str]) -> list[list[str]]:
    """The judged partition: clusters.json's (via _partition_components) minus every host the
    cross-type loop reached only through kit/neighbour rows — those are written to
    cases/<case>/tiers.json for assess/report and are never a same-operator cluster member."""
    comps = _partition_components(case, domains)
    tiers = _tier_hosts(case)
    if not tiers:
        return comps
    kept = [[m for m in c if T._host(m) not in tiers] for c in comps]
    kept = [c for c in kept if c]
    out = {"kit_siblings": sorted(h for h, t in tiers.items() if t == "kit"),
           "neighbours": sorted(h for h, t in tiers.items() if t == "neighbour"),
           "caveats": _TIER_CAVEAT}
    try:
        with open(os.path.join(ROOT, "cases", case, "tiers.json"), "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2)
    except OSError as e:
        _log(f"  (tiers.json not written: {e})")
    _log(f"  tiers: {len(out['kit_siblings'])} kit sibling(s), {len(out['neighbours'])} neighbour(s) "
         f"kept out of the judged clusters (cases/{case}/tiers.json)")
    return kept


def _persist_clusters(entries: list[tuple], case: str, table_md: str) -> dict:
    """Immutable snapshot per JUDGED cluster + a case roll-up SUMMARY.md listing every cluster.
    Each entry is (members, assessment_or_None, resolved_note_or_None, failure_reason_or_None): a
    judged cluster carries an Assessment; a cluster skipped because it was already attributed
    carries a resolved_note (its prior registry verdict — no LLM was spent); a failed judge
    carries neither an assessment nor a note, and a failure_reason instead (why it failed — a
    raised exception's message, or "assess produced no result" for a soft failure). `entries` MUST
    already be in the cluster's OWN original order (index i below IS that cluster's index — the
    caller is responsible for this, never success/resume order) so the `_cN` snapshot suffix
    always matches the cluster the analyst asked to judge. Returns {members_key: snapshot_base}
    for every judged cluster (the failover progress record)."""
    case_dir = os.path.join(ROOT, "cases", case)
    snap_dir = os.path.join(case_dir, "assessments")
    os.makedirs(snap_dir, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    roll = [f"<!-- {stamp} · parallel run · {len(entries)} cluster(s) -->",
            f"# Case roll-up — {case} — {len(entries)} cluster(s) · {stamp}\n"]
    changelog = []
    saved: dict = {}
    for i, (members, a, note, reason) in enumerate(entries, 1):
        base = f"{stamp}_c{i}"
        if a is None and note:            # already-attributed cluster — verdict from the registry, no LLM
            roll.append(f"## Cluster {i} — RESOLVED (prior attribution, not re-judged)\n{note}\n")
            changelog.append(f"- {stamp} · c{i} · RESOLVED · {len(members)} domains · {note[:100]}")
            continue
        if a is None:                     # judge failed (exception or soft no-result)
            why = f" — {reason}" if reason else ""
            roll.append(f"## Cluster {i} — JUDGMENT FAILED{why}\n  domains: {', '.join(members)}\n")
            changelog.append(f"- {stamp} · c{i} · FAILED · {len(members)} domains{why[:120]}")
            continue
        with open(os.path.join(snap_dir, base + ".md"), "w", encoding="utf-8") as f:
            f.write(render.render_markdown(a, table_md if i == 1 else ""))
        with open(os.path.join(snap_dir, base + ".json"), "w", encoding="utf-8") as f:
            f.write(a.model_dump_json(indent=2))
        saved[_members_key(members)] = base
        _render_deliverables(case, os.path.join(snap_dir, base + ".md"), a)  # figure built once, reused
        bluf = (a.bluf or "").replace("\n", " ")
        roll.append(f"## Cluster {i} — {a.attribution_level}/{a.confidence} "
                    f"({len(a.cluster or [])} domains) · [snapshot](assessments/{base}.md)\n{bluf}\n")
        changelog.append(f"- {stamp} · c{i} · {a.attribution_level}/{a.confidence} · "
                         f"{len(a.cluster or [])} in cluster · {bluf[:100]}")
    with open(os.path.join(case_dir, "SUMMARY.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(roll))
    with open(os.path.join(case_dir, "CHANGELOG.md"), "a", encoding="utf-8") as f:
        f.write("\n".join(changelog) + "\n")
    _log(f"\n saved · roll-up {case_dir}/SUMMARY.md ({len(entries)} clusters)")
    return saved


_HEAD_GENERATOR = "harness-parallel"
_LOOP_GENERATOR = "intel-loop"     # tools/intel.py's own assessment.json producer signature


def _write_head(entries: list[tuple], saved: dict, case: str, table_md: str, seeds: list[str]) -> str:
    """Refresh the case HEAD (assessment.json + assessment.md) from a parallel judgment, so
    house-report / build_report_data (which read the head) ship the judged verdict instead of the
    deterministic loop's earlier render. The PRIMARY cluster — the judged one holding the most
    original seeds (ties: lowest index) — becomes the head body; with several clusters, the head
    also lists every cluster's verdict/failure and its `_cN` snapshot.

    Ownership (AGENTS.md: never clobber an analyst assessment): assessment.json is replaced only
    when absent or engine-written (`_generator` = the loop or this function); assessment.md only
    when case_state.may_overwrite_assessment recognises the loop's or the harness's render.
    Returns the primary snapshot base, or "" when nothing was written."""
    judged = [(i, m, a) for i, (m, a, _n, _r) in enumerate(entries, 1)
              if a is not None and _members_key(m) in saved]
    if not judged:
        return ""
    seed_hosts = {T.collect_core.host_of(s).lower() for s in seeds}
    i0, m0, a0 = max(judged, key=lambda t: (len(seed_hosts & {h.lower() for h in t[1]}), -t[0]))
    base0 = saved[_members_key(m0)]
    index = []
    for i, (m, a, note, reason) in enumerate(entries, 1):
        row = {"index": i, "members": list(m)}
        if a is not None:
            row.update(attribution_level=a.attribution_level, confidence=a.confidence,
                       snapshot=f"assessments/{saved.get(_members_key(m), '')}.json")
        else:
            row.update(status="resolved" if note else "failed", note=note or reason)
        index.append(row)
    case_dir = os.path.join(ROOT, "cases", case)
    jpath, mpath = os.path.join(case_dir, "assessment.json"), os.path.join(case_dir, "assessment.md")
    try:
        with open(jpath, encoding="utf-8") as f:
            existing = json.load(f)
    except (OSError, ValueError):
        existing = None
    if os.path.exists(jpath) and (not isinstance(existing, dict)
                                  or existing.get("_generator") not in (_LOOP_GENERATOR, _HEAD_GENERATOR)):
        _log(" head · assessment.json is analyst-authored — not overwritten (verdicts stay in assessments/)")
        return ""
    head = json.loads(a0.model_dump_json())
    head.update(_generator=_HEAD_GENERATOR, _primary_cluster=i0,
                _snapshot=f"assessments/{base0}.json", clusters=index)
    with open(jpath, "w", encoding="utf-8") as f:
        json.dump(head, f, indent=2, ensure_ascii=False)
    import case_state as cs
    if cs.may_overwrite_assessment(mpath, cs.EVIDENCE_REPORT_MD + cs.HARNESS_RENDER_MD):
        md = render.render_markdown(a0, table_md)
        if len(entries) > 1:
            md += "\n\n## Other clusters in this case\n\n" + "\n".join(
                f"- **c{r['index']}** ({len(r['members'])} domains) — "
                + (f"{r['attribution_level']}/{r['confidence']} · [{r['snapshot']}]({r['snapshot']})"
                   if "snapshot" in r else f"{r['status'].upper()}: {r['note'] or ''}")
                for r in index if r["index"] != i0) + "\n"
        with open(mpath, "w", encoding="utf-8") as f:
            f.write(md)
    else:
        _log(" head · assessment.md is analyst-authored — not overwritten")
    _log(f" head · assessment.json/.md ← cluster c{i0} ({len(m0)} domains)"
         + (f"; {len(entries)} clusters indexed" if len(entries) > 1 else ""))
    return base0


def _all_collected(case: str) -> list[str]:
    raw = os.path.join(ROOT, "cases", case, "raw")
    return sorted(os.path.basename(p)[:-5] for p in glob.glob(os.path.join(raw, "*.json")))


def _record_hops(case: str, new: list[str], parents: list[str]) -> None:
    """Give each newly discovered seed a hop in state.json — the expansion anchor the loop's
    frontier, leaf rule and clusters.json all read. Without it the hosts this harness collected
    had NO hop, which in an anchored case means "leaf": the loop never expanded from them and
    clusters.json kept them out as related hosts. A subdomain of an apex the case holds inherits
    that apex's hop (same registration); any other host is one hop past the deepest parent this
    round expanded from (conservative: never closer to the seed than its origin). An existing hop
    is never raised. A legacy state with no hop map is left alone (nothing is a leaf there)."""
    try:
        import case_state as cs
        st = cs.load_state(case)
    except Exception as e:  # noqa: BLE001 — bookkeeping must never abort a collection round
        _log(f"  (hop bookkeeping skipped: {e})")
        return
    hops = st.get("hops") or {}
    if not hops:
        return
    depth = int(st.get("expansion_depth") or cs.DEFAULT_EXPANSION_DEPTH)
    parent_hops = [hops[p] for p in (T._host(x).lower() for x in parents) if p in hops]
    base = max(parent_hops) if parent_hops else max(hops.values())
    for h in (T._host(x).lower() for x in new):
        apex = cs._frontier_apex(h)
        if _is_ip(h):
            # a historical ORIGIN IP is an attribute of the host that resolved to it (same hop), so
            # its co-tenants land one hop further out — never a hop of its own
            hop = min(base, depth)
        else:
            hop = hops[apex] if apex in hops and apex != h else min(base + 1, depth)
        hops[h] = min(hop, hops.get(h, hop))
    # backfill: a host already collected without a hop (an earlier harness run) inherits its
    # apex's hop when the case holds that apex — same registration, no guess about distance
    for h in _all_collected(case):
        h = h.lower()
        apex = cs._frontier_apex(h)
        if h not in hops and apex in hops:
            hops[h] = hops[apex]
    st["hops"] = hops
    cs.save_state(case, st)


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(str(s or "").strip())
        return True
    except ValueError:
        return False


def _cluster_prior_verdict(members: list[str]) -> str | None:
    """If EVERY domain in the cluster is already attributed in the operator registry, return the
    combined verdict text (so we can skip re-judging it — a token saving). If any member is
    unattributed, return None (the cluster still needs LLM judgment)."""
    verdicts = []
    for d in members:
        r = T._run([sys.executable, os.path.join("tools", "kb", "operator_registry.py"),
                            "find", d], timeout=60)
        out = (r.stdout or "").strip()
        if not out or "not attributed" in out.lower():
            return None
        verdicts.append(out)
    return "; ".join(verdicts)


_CONF_RANK = {"low": 0, "moderate": 1, "high": 2}


def _no_owner_verdict(case: str, members: list[str]) -> Assessment | None:
    """A fixed `inconclusive` Assessment for a cluster with no owner evidence, so no LLM assess runs.

    Applies only when every member is an IP (or a provider hostname — wp_origin_history.
    is_provider_host), every IP classifies as one of no_owner_verdict.class_confidence's classes
    (cdn / parking / bogon / ad_edge / shared-hosting / platform — wp_origin_history.no_owner_class,
    reading the case's origin-history rows and the IP raw's own lookup), and no member's raw carries
    an owner-rung signal (wp_origin_history.owner_signal). Anything else — a domain, a small VPS, an
    unclassified or uncollected address, a cert / MX / distinctive PTR — returns None: the cluster
    goes to the LLM. Confidence is the lowest of the members' class confidences (references/
    origin_history.json no_owner_verdict)."""
    try:
        import case_state  # noqa: F401 — puts WebPivot/tools on sys.path
        import wp_origin_history as oh
    except Exception:  # noqa: BLE001 — no classifier, no shortcut: the LLM judges
        return None
    if not members or not any(_is_ip(m) for m in members):
        return None
    if not all(_is_ip(m) or oh.is_provider_host(m) for m in members):
        return None
    raw_dir = os.path.join(ROOT, "cases", case, "raw")

    def _load(path):
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except Exception:  # noqa: BLE001
            return None

    ips = {str(ipaddress.ip_address(m.strip())) for m in members if _is_ip(m)}
    history: dict[str, list] = {ip: [] for ip in ips}
    for path in sorted(glob.glob(os.path.join(raw_dir, "*.json"))):
        obj = _load(path)
        meta = (obj or {}).get("meta") or {}
        host = str(meta.get("host") or "").lower()
        if not obj or meta.get("kind") == "ip" or _is_ip(host):
            continue
        dp = next((p for p in obj.get("pivots") or [] if isinstance(p, dict) and p.get("kind") == "domain"), None)
        if not dp:
            continue
        for r in oh.block_for(dp.get("live_results") or {}, obj, host).get("ips") or []:
            if r.get("ip") in history:
                history[r["ip"]].append(r)
    parts, confs = [], []
    for m in members:
        obj = _load(os.path.join(raw_dir, f"{m}.json"))
        if obj and oh.owner_signal(obj):
            return None
        if not _is_ip(m):
            parts.append(f"{m} provider hostname")
            continue
        ip = str(ipaddress.ip_address(m.strip()))
        intel = ((obj or {}).get("artifacts") or {}).get("ip_intel") if obj else None
        got = oh.no_owner_class(ip, intel, history.get(ip) or ())
        if not got or got[0] not in oh.NO_OWNER_CONFIDENCE:
            return None
        parts.append(f"{m} {got[0]} ({got[1]})")
        confs.append(oh.NO_OWNER_CONFIDENCE[got[0]])
    conf = min(confs, key=lambda c: _CONF_RANK.get(c, 0))
    return Assessment(
        bluf="Inconclusive: every address in this cluster is shared provider infrastructure with no "
             "owner-rung evidence — it cannot attribute an operator.",
        cluster=[{"domain": m} for m in members],
        attribution_level="inconclusive",
        confidence=conf if conf in _CONF_RANK else "low",
        evidence=["Deterministic no-owner verdict (LLM assess skipped): " + "; ".join(parts)],
    )


async def run_case_parallel(seeds: list[str], case: str, *, hostile: bool, max_conc: int,
                            judge_conc: int, depth: int = 1, stale: int = 2, max_new: int = 8) -> list:
    """Phase 3 — scale. Collect concurrently (deterministic, no LLM). With depth>1 (--continue) keep
    expanding the frontier and re-collecting CHEAPLY until the case converges — judgment does NOT run
    per round. Then partition into same-operator clusters and judge each ONCE, in parallel; clusters
    already fully attributed skip the LLM entirely (their prior verdict is reused), and so do IP-only
    clusters with no owner evidence (_no_owner_verdict: a fixed inconclusive verdict)."""
    _log(f"\n===== PARALLEL CASE · {len(seeds)} seeds · collect≤{max_conc} · judge≤{judge_conc}"
         f"{' · continue depth ' + str(depth) if depth > 1 else ''} =====")
    import case_state as cs
    domains = cs.register_seed_nodes(case, seeds)       # non-domain seeds → typed nodes, never hosts
    _record_seeds(case, domains)
    P.set_loop_active(ROOT, case, True)
    approved_new, _ran = _run_approved(case, hostile=hostile)
    current, stop, rnd = list(dict.fromkeys(approved_new + domains)), "depth-cap", 0
    collected_before: list[str] = []
    try:
        for rnd in range(1, depth + 1):                                              # 1. expand-collect loop
            # Per-host consent (see run_case): typed seeds keyed, everything else free-only.
            P.set_loop_active(ROOT, case, True)
            if current:
                t0 = time.time()
                res = T.collect_many(current, case, hostile=hostile, max_workers=max_conc)
                ok = [r for r in res if r.get("ok")]
                fails = [r["host"] for r in res if not r.get("ok")]
                _log(f"round {rnd}: collected {len(ok)}/{len(res)} in {time.time() - t0:.0f}s "
                     f"({sum(1 for r in ok if r.get('reused'))} cached)"
                     + (f" · failures: {', '.join(fails)}" if fails else ""))
                for r in res:            # the REASON, not just the name — a 1 s 0/N round is a bug, not a proxy
                    if not r.get("ok"):
                        why = " ".join(str(r.get("error") or r.get("note") or "no reason recorded").split())
                        _log(f"    ✗ {r['host']}: {why[-200:]}")
                T.ingest(case)                                                       # ingest each round
                _binary_round(case, hostile=hostile, free_only=False)
                await _leak_round(case, hostile=hostile)   # before any metered frontier pivot
                conv = _convergence_snapshot(case, failed=fails)
                if conv:
                    _log("convergence · " + conv.splitlines()[0])
                if depth == 1:
                    stop = "round-cap"
                    break
                if _is_converged(case, stale) and not _xtype_pending(case):
                    _log(f"CONVERGED — last {stale} rounds added nothing. Stopping expansion.")
                    stop = "converged"
                    break
            elif rnd == 1:                  # typed-only seeds (email / handle / phone): leak first
                await _leak_round(case, hostile=hostile)
            collected_before = current
            P.set_loop_active(ROOT, case, True)   # the seed round is over: loop rules from here
            new, xstop = await _xtype_step(case, _all_collected(case), hostile=hostile,
                                           round_no=rnd, max_new=max_new, last_round=rnd == depth)
            if xstop:
                stop = xstop
                current = []
                break
            if new:
                _log(f"→ round {rnd + 1}: +{len(new)} new host(s): {', '.join(new)}")
                _record_hops(case, new, collected_before or _all_collected(case))
            current = new                                                            # only collect the frontier
    except backend_select.BackendUnavailable:
        _hand_back(case, "backend-unavailable", rounds=rnd, seeds=_all_collected(case), depth=depth)
        raise
    except Exception as e:  # noqa: BLE001 — planner REQUIRED: never pivot unplanned
        _log(f"round {rnd} cross-type step failed: {e}")
        stop = "failed"
    finally:
        P.set_loop_active(ROOT, case, False)

    _record_hops(case, [], current)          # backfill hops for the last round before partitioning
    if not _all_collected(case):
        # A non-domain seed whose pivots surfaced no host yet: nothing to cluster or judge.
        _hand_back(case, stop, rounds=rnd, seeds=list(seeds), depth=depth)
        return []
    clusters = _compute_components(case, _all_collected(case))                        # 2. cluster the whole graph
    # Clusters a PREVIOUS run already judged before its backend failed (see the progress file
    # written below) are reused as-is, so the fallback backend does not pay for them again.
    progress = _load_failover_progress(case)
    to_judge, resolved, reused, fixed = [], [], [], []
    for c in clusters:                                                               # 3. skip already-attributed
        v = _cluster_prior_verdict(c)
        prev = None if v else _reuse_judged(case, c, progress)
        # IP-only cluster on cdn / parking / ad-edge / shared-hosting / platform addresses with no
        # owner-rung signal: a fixed inconclusive verdict, never an LLM assess (references/
        # origin_history.json no_owner_verdict)
        det = None if (v or prev is not None) else _no_owner_verdict(case, c)
        if v:
            resolved.append((c, None, v))
        elif prev is not None:
            reused.append((c, prev, None))
        elif det is not None:
            fixed.append((c, det))
        else:
            to_judge.append(c)
    _log(f"{len(clusters)} cluster(s): {len(to_judge)} to judge, {len(resolved)} already attributed "
         f"(LLM skipped)" + (f", {len(reused)} reused from the run before the backend failover"
                              if reused else "")
         + (f", {len(fixed)} IP-only with no owner evidence (deterministic verdict)" if fixed else ""))
    for c, _a in fixed:
        _log(f"  no-owner verdict ({len(c)}): {', '.join(c[:8])}{' …' if len(c) > 8 else ''}")
    for i, c in enumerate(to_judge, 1):
        _log(f"  judge {i} ({len(c)}): {', '.join(c[:8])}{' …' if len(c) > 8 else ''}")

    sem = asyncio.Semaphore(judge_conc)                                              # 4. judge in parallel

    async def _judge_cluster(members):
        async with sem:
            a, ph = await _judge(members, case, members_only=True)
            return members, a, ph

    # return_exceptions: one cluster's backend failure must not discard the judgments that DID
    # finish — they are persisted and recorded before the failure is re-raised.
    outcomes = await asyncio.gather(*[_judge_cluster(c) for c in to_judge], return_exceptions=True)
    # Attribute every outcome to its OWN cluster by members-key (asyncio.gather preserves input
    # order even with return_exceptions=True, so zip(to_judge, outcomes) is exact) — never by
    # success order, which used to shift a later cluster's _cN suffix onto an earlier index
    # whenever a preceding cluster failed.
    allphases: dict = {}
    assessed: dict[str, Assessment] = {_members_key(c): a for c, a in fixed}
    reasons: dict[str, str] = {}
    for idx, (members, outcome) in enumerate(zip(to_judge, outcomes), 1):
        key = _members_key(members)
        if isinstance(outcome, BaseException):
            reasons[key] = str(outcome)[:300]
            continue
        _m, a, ph = outcome
        for k, v in ph.items():
            allphases[f"c{idx}:{k}"] = v
        if a is None:                      # soft failure — no exception, but no assessment either
            reasons[key] = "assess produced no result"
            continue
        assessed[key] = a

    table_md = _domain_table(case)                                                   # 5. persist + cost
    resolved_notes = {_members_key(c): v for c, _a, v in resolved}
    reused_assessments = {_members_key(c): a for c, a, _n in reused}

    def _outcome(c):
        key = _members_key(c)
        if key in resolved_notes:
            return (c, None, resolved_notes[key], None)
        if key in reused_assessments:
            return (c, reused_assessments[key], None, None)
        if key in assessed:
            return (c, assessed[key], None, None)
        return (c, None, None, reasons.get(key, "judgment failed"))

    entries = [_outcome(c) for c in clusters]                 # ALWAYS the cluster's own order
    saved = _persist_clusters(entries, case, table_md)
    _write_head(entries, saved, case, table_md, seeds)
    _report_cost(allphases, case=case)

    backend_errs = [o for o in outcomes if isinstance(o, backend_select.BackendUnavailable)]
    if backend_errs or reasons:
        # A resumed run must re-judge exactly the clusters recorded here as failed (never the ones
        # that succeeded, whether just now or in an earlier failed-over run) — `saved` (flat,
        # members_key -> snapshot base) is what `_reuse_judged` consults; `_FAILED_KEY` is a side
        # channel for the reason text (SUMMARY/log), never consulted as a reuse hit.
        merged = {**progress, **saved}
        if reasons:
            merged[_FAILED_KEY] = dict(reasons)
        else:
            merged.pop(_FAILED_KEY, None)
        _save_failover_progress(case, merged)
    else:
        _clear_failover_progress(case)
    if backend_errs:
        _log(f"  {len(saved)} cluster judgment(s) saved; {len(backend_errs)} stopped by the backend — "
             f"a resumed run reuses the saved ones")
        _hand_back(case, "backend-unavailable", rounds=rnd, seeds=_all_collected(case), depth=depth)
        raise backend_errs[0]              # the ONLY case that aborts the run — a systemic backend
                                            # outage, not a per-cluster judge failure (see below)
    if reasons:
        # A per-cluster judge failure (bad struct output, isolation breach, …) must NOT abort the
        # other clusters or discard their results — they are already persisted above. Log it,
        # keep the failed cluster(s) queued for the next resumed run, and let the caller decide the
        # exit code from `entries` (any 4th element set) rather than crashing the whole case.
        _log(f"  {len(reasons)} cluster(s) FAILED judgment (non-backend) — a resumed run re-judges "
             f"only them:")
        for key, reason in reasons.items():
            _log(f"    ✗ {key}: {reason[:200]}")
    _hand_back(case, stop, rounds=rnd, seeds=_all_collected(case), depth=depth)
    return entries


# --------------------------------------------------- failover progress (parallel judge)
def _members_key(members: list[str]) -> str:
    return ",".join(sorted(m.lower() for m in members))


# Reserved top-level key for cluster failure reasons, alongside the flat members_key -> snapshot
# base entries `_reuse_judged` consults. A real `_members_key(...)` can never collide with this
# (no domain is `__failed__`), so the progress file stays a plain flat dict for the judged half.
_FAILED_KEY = "__failed__"


def _progress_path(case: str) -> str:
    return os.path.join(ROOT, "cases", case, "failover_progress.json")


def _load_failover_progress(case: str) -> dict:
    try:
        with open(_progress_path(case), encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_failover_progress(case: str, mapping: dict) -> None:
    try:
        with open(_progress_path(case), "w", encoding="utf-8") as f:
            json.dump(mapping, f, indent=1)
    except OSError as e:
        _log(f"  (failover progress not saved: {e})")


def _clear_failover_progress(case: str) -> None:
    try:
        os.remove(_progress_path(case))
    except OSError:
        pass


def _reuse_judged(case: str, members: list[str], progress: dict):
    """The Assessment a failed-over run already produced for EXACTLY these members, else None. A
    changed member set (new collection since) is judged again — the old verdict no longer fits."""
    base = progress.get(_members_key(members))
    if not base:
        return None
    try:
        with open(os.path.join(ROOT, "cases", case, "assessments", base + ".json"), encoding="utf-8") as f:
            return Assessment.model_validate_json(f.read())
    except Exception:  # noqa: BLE001 — missing/corrupt snapshot → judge it again
        return None


def _pop_val(argv: list[str], name: str, default: str) -> str:
    if name in argv:
        i = argv.index(name)
        val = argv[i + 1]
        del argv[i:i + 2]
        return val
    return default


def _scope_from_argv(argv: list[str], case: str) -> dict:
    """Pull the intake flags off argv (mutating it) and resolve+persist this case's scope.

    Flags are optional by design — `policy.blocking` is false, so a run with none of them still
    starts, under `unknown` and saying so. What they buy is a posture the gate can enforce, an
    ownership rule the collectors obey, and a premise the assessment has to answer."""
    given: dict = {}
    for flag, field in (("--target-class", "target_class"), ("--purpose", "purpose"),
                        ("--claim", "claim"), ("--basis", "basis"), ("--brand", "brand"),
                        ("--how", "how_encountered"), ("--window", "time_window"),
                        ("--falsifier", "falsifier")):
        if flag in argv and argv.index(flag) == len(argv) - 1:
            _log(f"[scope] WARNING: {flag} given with no value — ignored.")
            argv.remove(flag)
            continue
        val = _pop_val(argv, flag, "")
        if val:
            given[field] = val
    for flag, field in (("--no-direct-contact", "no_direct_contact"), ("--no-spend", "no_spend")):
        if flag in argv:
            argv.remove(flag)
            given[field] = True
    path = _pop_val(argv, "--scope", "")
    if path:
        try:
            with open(path, encoding="utf-8") as f:
                given = {**json.load(f), **given}    # explicit flags still win over the file
        except Exception as e:  # noqa: BLE001 — a bad scope file must not kill the run
            _log(f"[scope] WARNING: --scope {path} unreadable ({e}); continuing without it.")
    return case_scope.resolve(case, **given)


def _main() -> None:
    import uuid
    os.environ.setdefault("INTEL_RUN_ID", uuid.uuid4().hex)   # wp_wayback_guard: one breaker per run
    # Every process this harness run spawns (SDK in-process tools, CLI-backend MCP servers, tool
    # subprocesses) inherits this marker: the `cti` driver/tool must never start a NESTED harness.
    os.environ["INTEL_IN_HARNESS"] = "1"
    argv = sys.argv[1:]
    hostile = "--hostile" in argv
    cont = "--continue" in argv
    parallel = "--parallel" in argv
    fanout = "--fanout" in argv
    if "--no-verify" in argv:
        globals()["VERIFY_ON"] = False   # per-run override of the adversarial-verify default
    argv = [a for a in argv
            if a not in ("--hostile", "--continue", "--parallel", "--fanout", "--no-verify")]
    depth = int(_pop_val(argv, "--depth", "4" if cont else "1"))
    stale = int(_pop_val(argv, "--stale", "2"))
    max_new = int(_pop_val(argv, "--max-new", "8"))
    collect_conc = int(_pop_val(argv, "--collect-conc", "8"))
    judge_conc = int(_pop_val(argv, "--judge-conc", "3"))
    if depth > 1:
        cont = True
    if len(argv) < 2 and not (cont and argv):
        sys.exit("usage: orchestrator.py <CASE-ID> [--hostile] [--no-verify] "
                 "[--fanout [--collect-conc N]] "
                 "[--continue [--depth N] [--stale N] [--max-new N]] "
                 "[--parallel [--collect-conc N] [--judge-conc N]] "
                 "[--target-class C] [--purpose P] [--claim TEXT] [--basis TEXT] [--brand NAME] "
                 "[--how TEXT] [--window TEXT] [--falsifier TEXT] [--no-direct-contact] "
                 "[--no-spend] [--scope FILE] <seed> ...   (a seed may be a domain/URL, email, "
                 "phone, IP, hash, wallet, telegram handle, filename or string)\n"
                 "  --continue CASE with no seeds resumes the case (e.g. after `intel approve`).\n"
                 "  intake flags are optional: an unscoped run proceeds as `unknown` and says so "
                 "(python3 harness/case_scope.py questions).")
    # INTAKE — resolved before anything is collected, and BEFORE the seed list is split off, since
    # the flags sit among the trailing arguments. It sets the posture (and, for a class that
    # forbids touching the target, the egress denial the tool gate enforces), the ownership rule
    # the collectors cluster by, and the premise the assessment must answer.
    case = argv[0]
    scope = _scope_from_argv(argv, case)
    seeds = argv[1:]
    resume = not seeds and cont
    if resume:
        # Resume (e.g. after `intel approve`): the case's ORIGINAL seeds only — hop-0 hosts from
        # the expansion anchor and hop-0 typed nodes. run_case(resume=True) never re-collects or
        # re-judges a host the case already holds; it continues from the approved pivots + frontier.
        import case_state as cs
        st = cs.load_state(case)
        hop0 = sorted(h for h, v in (st.get("hops") or {}).items() if v == 0)
        nodes0 = [n.get("selector") for n in (st.get("nodes") or {}).values()
                  if isinstance(n, dict) and n.get("hop") == 0 and n.get("selector")]
        recorded = sorted(_run_seeds(case))
        seeds = (list(dict.fromkeys(recorded + hop0 + nodes0))
                 or sorted(cs.collected_hosts(os.path.join(ROOT, "cases", case)))[:1])
    if not seeds:
        sys.exit(f"no seeds left after the intake flags — `{case}`'s scope was saved, but there is "
                 f"nothing to collect. Re-run with the seeds appended.")
    _SCOPE_CACHE[case] = scope
    _log(case_scope.banner(scope))
    hostile = case_scope.is_hostile(scope, explicit=hostile)
    if hostile and case_scope.posture(scope).get("fetch_posture") == case_scope.NO_TOUCH:
        _log(f"  posture `{case_scope.NO_TOUCH}` → outbound collection is DENIED by the gate; "
             f"passive sources and stored captures only.")
    # Auto-parallel for large seed sets (a single collect session would blow context/turns).
    auto_at = int(os.environ.get("HARNESS_PARALLEL_AT", "12"))
    if not parallel and len(seeds) >= auto_at:
        _log(f"auto-parallel: {len(seeds)} seeds ≥ {auto_at} (set HARNESS_PARALLEL_AT to change)")
        parallel = True
    try:
        if parallel:
            # --continue → cheap expand-collect until convergence, then judge once (depth from --depth).
            pdepth = depth if cont else 1
            entries = asyncio.run(run_case_parallel(seeds, case, hostile=hostile, max_conc=collect_conc,
                                                    judge_conc=judge_conc, depth=pdepth, stale=stale,
                                                    max_new=max_new))
            # A per-cluster judge failure does not raise (see run_case_parallel) — the other
            # clusters' results are already saved — but the run as a whole must still say so.
            if any(len(e) > 3 and e[3] for e in entries):
                sys.exit(1)
        else:
            # --fanout → one reactive collector agent per seed, concurrently (collect_conc); default
            # is the single sequential collect session. Judgment is unchanged.
            asyncio.run(run_case(seeds, case, hostile=hostile, depth=depth, stale=stale,
                                 max_new=max_new, collect_conc=collect_conc if fanout else 1,
                                 resume=resume))
    except backend_select.BackendUnavailable as e:
        _log(f"\n⚠ the {e.backend} backend stopped answering ({e.kind}): {e.reason}\n"
             f"   the case is intact — collected data is cached and re-running resumes it.")
        backend_select.write_failover(os.environ.get("HARNESS_FAILOVER_FILE"), e.backend, e.reason, e.kind)
        sys.exit(backend_select.FAILOVER_EXIT)


def _persist_assessment(assessment: Assessment, case: str, table_md: str) -> dict:
    """Snapshot + living head. Every run writes an IMMUTABLE, timestamped snapshot under
    assessments/ (append-only attribution history — nothing is ever overwritten), then refreshes
    SUMMARY.md (the current view) and appends one line to CHANGELOG.md. assessment.json is kept as
    a back-compat pointer to the latest. cases/ is git-ignored, so this IS the version history."""
    case_dir = os.path.join(ROOT, "cases", case)
    snap_dir = os.path.join(case_dir, "assessments")
    os.makedirs(snap_dir, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    rnd = len([f for f in os.listdir(snap_dir) if f.endswith(".json")]) + 1
    base = f"{stamp}_r{rnd}"
    md_body = render.render_markdown(assessment, table_md)
    js = assessment.model_dump_json(indent=2)

    # immutable snapshot — the audit trail
    snap_md = os.path.join(snap_dir, base + ".md")
    with open(snap_md, "w", encoding="utf-8") as f:
        f.write(md_body)
    with open(os.path.join(snap_dir, base + ".json"), "w", encoding="utf-8") as f:
        f.write(js)

    # living head — overwritten each run so "current" is always one file
    summary = os.path.join(case_dir, "SUMMARY.md")
    with open(summary, "w", encoding="utf-8") as f:
        f.write(f"<!-- round {rnd} · {stamp} · {assessment.attribution_level}/"
                f"{assessment.confidence} · snapshot assessments/{base}.md -->\n\n" + md_body)
    with open(os.path.join(case_dir, "assessment.json"), "w", encoding="utf-8") as f:
        f.write(js)  # back-compat pointer to the latest

    # changelog — one append-only line per round
    n_dom = len(assessment.cluster or [])
    bluf = (assessment.bluf or "").replace("\n", " ")[:140]
    changelog = os.path.join(case_dir, "CHANGELOG.md")
    with open(changelog, "a", encoding="utf-8") as f:
        f.write(f"- {stamp} · r{rnd} · {assessment.attribution_level}/{assessment.confidence} · "
                f"{n_dom} in cluster · {bluf}\n")
    deliv = _render_deliverables(case, snap_md, assessment)
    return {"round": rnd, "snapshot_md": snap_md, "summary": summary, "changelog": changelog, **deliv}


# --------------------------------------------------------------- deliverables (figure + PDF/DOCX)
# Node types pruned from a report figure so the meaningful nodes render large.
FIGURE_DROP_TYPES = ["nameserver", "registrar", "template", "theme", "email"]


def _write_figures_recipe(rep_dir: str, title: str) -> None:
    """At assess-time, drop a figures.json beside the report so a later
    `render_report.py` regenerates the chart from current raw data (IntelReport ⇄
    IntelGraph chain). Written only if absent — never clobbers a hand-curated recipe."""
    recipe = os.path.join(rep_dir, "figures.json")
    if os.path.exists(recipe):
        return
    spec = {"figures": [{
        "raw_glob": "../raw/*.json",          # picks up every domain collected into the case
        "graph": "case_graph.json", "stem": "case_diagram",
        "title": (title or "")[:80], "direction": "LR", "legend": True,
        "drop_types": FIGURE_DROP_TYPES,
    }]}
    try:
        with open(recipe, "w", encoding="utf-8") as f:
            json.dump(spec, f, indent=2)
        _log(f" deliverables: wrote figures.json ({recipe})")
    except OSError:
        pass


def _ensure_case_diagram(case: str, title: str) -> str | None:
    """Best-effort editable relationship diagram for the case. Builds
    cases/<case>/report/case_graph.json from the case's raw pivot JSON, then renders an
    editable Mermaid PNG/SVG via IntelGraph. Staleness-guarded so the parallel path doesn't
    rebuild it once per cluster. Returns the hi-res PNG path, or None if there's nothing to
    graph or the render is unavailable (no Node/Bun for Pele, or no SVG rasteriser). Never raises."""
    case_dir = os.path.join(ROOT, "cases", case)
    rep_dir = os.path.join(case_dir, "report")
    os.makedirs(rep_dir, exist_ok=True)
    _write_figures_recipe(rep_dir, title or case)   # wire the report⇄chart chain from assess-time
    fig = os.path.join(rep_dir, "case_diagram_hires.png")
    raw = glob.glob(os.path.join(case_dir, "raw", "*.json"))
    if not raw:
        return None
    # reuse if the figure is newer than the newest collected pivot
    if os.path.exists(fig) and os.path.getmtime(fig) >= max(os.path.getmtime(p) for p in raw):
        return fig
    graph_json = os.path.join(rep_dir, "case_graph.json")
    gb = T._run([sys.executable, os.path.join("WebPivot", "tools", "graph_build.py"),
                         *raw, "-o", graph_json], timeout=240)
    if gb.returncode != 0 or not os.path.exists(graph_json):
        _log(f" deliverables: graph build skipped ({(gb.stderr or gb.stdout or '').strip()[:120]})")
        return None
    gd = T._run([sys.executable, os.path.join("IntelGraph", "scripts", "graph_to_diagram.py"),
                         graph_json, os.path.join(rep_dir, "case_diagram"),
                         "--title", (title or case)[:80], "--legend",
                         "--drop-types", ",".join(FIGURE_DROP_TYPES)], timeout=180)
    if gd.returncode != 0 or not os.path.exists(fig):
        _log(f" deliverables: diagram skipped ({(gd.stderr or gd.stdout or '').strip()[:120]})")
        return None
    return fig


def _render_deliverables(case: str, snap_md: str, assessment: Assessment) -> dict:
    """After an assessment snapshot is written, auto-emit the case deliverables: an editable
    relationship diagram (PNG/SVG) and a polished PDF+DOCX (IntelReport). Best-effort — a
    missing diagram renderer (Pele) or pandoc only logs a warning; the case never fails on it. Set
    HARNESS_DELIVERABLES=0 to skip, HARNESS_TLP to set the classification (default TLP:AMBER)."""
    if os.environ.get("HARNESS_DELIVERABLES") == "0":
        return {}
    case_dir = os.path.join(ROOT, "cases", case)
    rep_dir = os.path.join(case_dir, "report")
    base = os.path.splitext(os.path.basename(snap_md))[0]
    title = (assessment.bluf or case).replace("\n", " ").strip()
    out: dict = {}

    fig = _ensure_case_diagram(case, title)
    if fig:
        out["diagram"] = fig

    # report markdown = frontmatter (title/case/classification) + assessment body + figure
    os.makedirs(rep_dir, exist_ok=True)
    report_md = os.path.join(rep_dir, base + ".md")
    tlp = os.environ.get("HARNESS_TLP", "TLP:AMBER")
    fm = ["---", 'title: "%s"' % title[:120].replace('"', "'"),
          "case_id: %s" % case, "classification: %s" % tlp, "---", ""]
    # Shareable output rule (SKILL §2.5): the operator's OWN selectors (the cluster's shared
    # artifacts, the estate's domains) stay in clear; every other e-mail / phone — a previous owner
    # cited in a REJECTED alternative, a registrar role mailbox — is masked, because a skim reader
    # or an IOC scraper keeps the value and drops the exculpatory framing. The snapshot under
    # assessments/ keeps the full values for the analyst.
    body = render.render_markdown(assessment, "")
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(ROOT), "scripts"))
        from cti_third_party_mask import mask_third_parties  # noqa: WPS433
        keep = {a for m in (assessment.cluster or []) for a in (m.shared_artifacts or [])}
        keep |= {a.split(":", 1)[1] for a in list(keep) if ":" in a}
        hosts = {m.domain for m in (assessment.cluster or [])}
        extra = []
        try:                                   # previous owners' NAMES (e-mails fall to the generic mask)
            import whois_eras  # noqa: WPS433 — WebPivot/tools is on sys.path via tools.py
            for rp in glob.glob(os.path.join(case_dir, "raw", "*.json")):
                w = ((json.load(open(rp, encoding="utf-8")).get("artifacts") or {}).get("whois")) or {}
                for kind in ("name", "org"):
                    for pv in whois_eras.prior_values(w, kind):
                        v = str(pv.get("value") or "").strip()
                        if len(v) >= 4 and v.lower() not in {k.lower() for k in keep} and v not in extra:
                            extra.append(v)
        except Exception as e:  # noqa: BLE001
            _log(f" deliverables: prior-owner name mask incomplete ({e!r})")
        body = mask_third_parties(body, keep=keep, hosts=hosts, extra=extra, current_case=case)
    except Exception as e:  # noqa: BLE001 — degrade loudly, never ship unmasked silently
        _log(f" deliverables: third-party mask unavailable ({e!r}) — report NOT masked; review before sharing")
    parts = ["\n".join(fm), body]
    if fig:
        parts += ["\n## Relationship graph\n",
                  "![%s — clustered relationship graph](%s)\n" % (case, os.path.basename(fig))]
    with open(report_md, "w", encoding="utf-8") as f:
        f.write("\n".join(parts) + "\n")

    stem = os.path.join(rep_dir, base)
    rr = T._run([sys.executable, os.path.join("IntelReport", "scripts", "render_report.py"),
                         report_md, stem, "--case-id", case], timeout=300)
    if rr.returncode == 0:
        for ext in ("pdf", "docx"):
            if os.path.exists(f"{stem}.{ext}"):
                out[ext] = f"{stem}.{ext}"
        _log(f" deliverables · {rep_dir}/{base}.pdf + .docx" + (" + diagram" if fig else " (no diagram)"))
    else:
        _log(f" deliverables: report skipped ({(rr.stderr or rr.stdout or '').strip()[:120]})")
    return out


if __name__ == "__main__":
    _main()
