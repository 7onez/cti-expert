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
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ResultMessage,
    ToolUseBlock,
    query,
)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import render  # noqa: E402
import tools as T  # noqa: E402
from schemas import Assessment  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))            # harness/
ROOT = os.path.dirname(HERE)                                  # repo root


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
    """Load a SKILL.md body to use as a phase system prompt (inlined for portability;
    the SDK can also auto-load skills from .claude/ via setting_sources)."""
    with open(os.path.join(ROOT, name, "SKILL.md"), encoding="utf-8") as f:
        return f.read()


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


def _domain_table(case: str) -> str:
    """Render the standard analyst Domain Summary table for the case's collected domains."""
    raw = os.path.join(ROOT, "cases", case, "raw")
    files = [os.path.join(raw, f) for f in os.listdir(raw)] if os.path.isdir(raw) else []
    if not files:
        return ""
    r = subprocess.run(
        [sys.executable, os.path.join("tools", "domain_table.py"), *files,
         "--case", case, "--kb", T.KB_DIR],
        cwd=ROOT, capture_output=True, text=True, timeout=180)
    return r.stdout if r.returncode == 0 else ""


def _prior_knowledge(seeds: list[str]) -> str:
    """Per-seed status so collect can skip re-work: already collected? already attributed?"""
    lines = []
    for s in seeds:
        host = T._host(s)
        collected = bool(T._find_cached_raw(host))
        op = subprocess.run(
            [sys.executable, os.path.join("tools", "kb", "operator_registry.py"), "find", host],
            cwd=ROOT, capture_output=True, text=True, timeout=60)
        first = (op.stdout or "").strip().splitlines()
        attributed = bool(first) and "not attributed" not in first[0].lower()
        tags = [t for t, on in (("already-collected", collected), ("attributed", attributed)) if on]
        note = f"  [{first[0]}]" if attributed else ""
        lines.append(f"- {host}: {', '.join(tags) if tags else 'NEW'}{note}")
    return "\n".join(lines)


async def _phase(prompt, *, label, system, tools, servers, resume=None,
                 model=None, effort=None, output_schema=None, hostile=False):
    T.POLICY["hostile"] = hostile
    t0 = time.time()
    _log(f"\n▶ {label}  ·  {model}/{effort}")
    opts = ClaudeAgentOptions(
        system_prompt=system,
        mcp_servers=servers,
        tools=[],             # remove ALL built-ins (Bash/Read/…) -> force the clean MCP tools,
        allowed_tools=tools,  #   not shell flailing over the skill prompt's bash instructions
        # headless: no approval prompts. The egress guardrail lives inside the tool;
        # for an interactive/safer harness use permission_mode="default" + can_use_tool.
        permission_mode="bypassPermissions",
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
    except Exception:  # query() raises AFTER yielding an error ResultMessage
        if result is None:
            raise
    cost = getattr(result, "total_cost_usd", None)
    _log(f"  ✓ {label} · {time.time() - t0:.0f}s"
         + (f" · ${cost:.4f}" if cost is not None else ""))
    return result


async def investigate(seeds: list[str], case: str, hostile: bool = False) -> Assessment:
    seed_lines = "\n".join(f"- {s}" for s in seeds)
    seed_csv = ", ".join(seeds)

    # PHASE 1 — COLLECT  (WebPivot brain, cheap model). Writes raw + ingests into the KB.
    prior = _prior_knowledge(seeds)
    _log("prior knowledge:\n" + prior)
    p1 = await _phase(
        _prompt(
            "collect",
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
    )
    # We do NOT resume the collect session into judgment. The facts now live in the KB,
    # which the judgment phases read via tools — carrying the (large) collect transcript
    # into every Opus turn was the main cost driver. Judgment runs in its own session.

    # PHASE 2+3 — judgment (Correlate → Assess) over the seeds, reading the ingested KB.
    assessment, jphases = await _judge(seeds, case)
    _report_cost({"collect": p1, **jphases}, case=case)
    if assessment is None:
        raise RuntimeError("assessment failed (correlate/assess produced nothing)")
    return assessment


async def _judge(domains: list[str], case: str) -> tuple[Assessment | None, dict]:
    """The judgment half — Correlate → Assess (+cascade) over `domains`, reusable per cluster. No
    collection; reads the already-ingested KB in its own fresh session. Returns (Assessment|None,
    phases_dict) so the caller aggregates cost across one or many clusters."""
    seed_csv = ", ".join(domains)
    # PHASE 2 — CORRELATE  (IntelAnalysis brain, judge model). Fresh session, reads the KB.
    p2 = await _phase(
        _prompt("correlate", case=case, seed_csv=seed_csv),
        label="correlate",
        system=_skill("IntelAnalysis"),
        tools=T.ANALYZE_TOOLS,
        servers={"analyze": T.ANALYZE_SERVER},
        model=JUDGE.model,
        effort=JUDGE.effort,
    )
    session = p2.session_id if p2 else None
    if not session:
        return None, {"correlate": p2}

    # PHASE 3 — ASSESS  (resume CORRELATE; schema-forced structured assessment)
    assess_prompt = _prompt("assess")
    assess_kw = dict(system=_skill("IntelAnalysis"), tools=T.ANALYZE_TOOLS,
                     servers={"analyze": T.ANALYZE_SERVER}, resume=session, output_schema=Assessment)
    p3 = await _phase(assess_prompt, label="assess", model=JUDGE.model, effort=JUDGE.effort, **assess_kw)
    phases = {"correlate": p2, "assess": p3}

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
    return assessment, phases


# --------------------------------------------------------------- convergence loop (--continue)
def _convergence_snapshot(case: str) -> str:
    """Record this round in cases/<case>/rounds.jsonl via the convergence tool (its own authority
    on what counts as a new host/indicator). Returns its one-line summary for the worklog."""
    r = subprocess.run([sys.executable, os.path.join("tools", "kb", "convergence.py"),
                        "snapshot", case], cwd=ROOT, capture_output=True, text=True, timeout=120)
    return (r.stdout or r.stderr or "").strip()


def _is_converged(case: str, stale: int) -> bool:
    """CONVERGED = the last `stale` snapshot rounds each added ZERO new hosts and indicators —
    the same rule convergence.py's `status` prints, read straight from rounds.jsonl."""
    p = os.path.join(ROOT, "cases", case, "rounds.jsonl")
    if not os.path.exists(p):
        return False
    rounds = [json.loads(l) for l in open(p, encoding="utf-8") if l.strip()]
    if len(rounds) < stale:
        return False
    return all(r["new_hosts"] == 0 and r["new_indicators"] == 0 for r in rounds[-stale:])


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
        r = subprocess.run([sys.executable, os.path.join("tools", "kb", "query.py"),
                            "--kb", T.KB_DIR, "--cluster", dom, "--strong"],
                           cwd=ROOT, capture_output=True, text=True, timeout=120)
        for line in (r.stdout or "").splitlines():
            m = re.match(r"^\s+(\S+)\s+via\s+(\d+)\s+shared", line)
            if not m:
                continue
            peer, nshared = m.group(1), int(m.group(2))
            if peer in known_hosts or T._host(peer) != peer or T._find_cached_raw(peer):
                continue
            scores[peer] = max(scores.get(peer, 0), nshared)
    return sorted(scores, key=lambda p: -scores[p])[:max_new]


async def run_case(seeds: list[str], case: str, *, hostile: bool, depth: int,
                   stale: int, max_new: int) -> Assessment:
    """One or more Collect→Correlate→Assess rounds. Each round snapshots an immutable assessment
    (r1, r2, …); between rounds it expands the seed set with newly-discovered cluster peers and
    stops when convergence.py reports CONVERGED, the depth cap is hit, or nothing new is found."""
    current, final = list(seeds), None
    for rnd in range(1, depth + 1):
        _log(f"\n===== ROUND {rnd}/{depth} · {len(current)} seed(s): {', '.join(current)} =====")
        try:
            final = await investigate(current, case, hostile=hostile)
        except Exception as e:  # noqa: BLE001
            _log(f"round {rnd} failed: {e}")
            break
        table_md = _domain_table(case)
        render.render_terminal(final, table_md=table_md)
        snap = _persist_assessment(final, case, table_md)
        _log(f" saved · {snap['snapshot_md']} (round {snap['round']}) · head {snap['summary']}")
        conv = _convergence_snapshot(case)
        if conv:
            _log("convergence · " + conv.splitlines()[0])
        if depth == 1:
            break
        if _is_converged(case, stale):
            _log(f"convergence: CONVERGED — last {stale} rounds added nothing new. Stopping.")
            break
        new = _discover_new_seeds(case, current, max_new)
        if not new:
            _log("no new uncollected cluster peers to pursue. Stopping.")
            break
        _log(f"→ round {rnd + 1}: expanding with {len(new)} new seed(s): {', '.join(new)}")
        current = current + new
    if final is None:
        raise RuntimeError("no assessment produced")
    return final


# ------------------------------------------------------- Phase 3: parallel + cluster-level judge
def _compute_components(case: str, domains: list[str]) -> list[list[str]]:
    """Partition the case's collected domains into same-operator clusters via the KB's STRONG
    connected components (boilerplate / benign / over-prevalent edges excluded). One cluster ==
    one unit of LLM judgment, so cost scales with cluster count, not domain count."""
    hosts = sorted({T._host(d) for d in domains})
    r = subprocess.run([sys.executable, os.path.join("tools", "kb", "query.py"),
                        "--kb", T.KB_DIR, "--components", "--domains", ",".join(hosts)],
                       cwd=ROOT, capture_output=True, text=True, timeout=120)
    comps = []
    for line in (r.stdout or "").splitlines():
        if line.startswith("COMPONENT"):
            members = [d.strip() for d in line.partition("\t")[2].split(",") if d.strip()]
            if members:
                comps.append(members)
    return comps or [hosts]      # fallback: treat everything as one cluster if the KB/parse failed


def _persist_clusters(entries: list[tuple], case: str, table_md: str) -> None:
    """Immutable snapshot per JUDGED cluster + a case roll-up SUMMARY.md listing every cluster.
    Each entry is (members, assessment_or_None, resolved_note_or_None): a judged cluster carries an
    Assessment; a cluster skipped because it was already attributed carries a resolved_note (its
    prior registry verdict — no LLM was spent); a failed judge carries neither."""
    case_dir = os.path.join(ROOT, "cases", case)
    snap_dir = os.path.join(case_dir, "assessments")
    os.makedirs(snap_dir, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    roll = [f"<!-- {stamp} · parallel run · {len(entries)} cluster(s) -->",
            f"# Case roll-up — {case} — {len(entries)} cluster(s) · {stamp}\n"]
    changelog = []
    for i, (members, a, note) in enumerate(entries, 1):
        base = f"{stamp}_c{i}"
        if a is None and note:            # already-attributed cluster — verdict from the registry, no LLM
            roll.append(f"## Cluster {i} — RESOLVED (prior attribution, not re-judged)\n{note}\n")
            changelog.append(f"- {stamp} · c{i} · RESOLVED · {len(members)} domains · {note[:100]}")
            continue
        if a is None:                     # judge failed
            roll.append(f"## Cluster {i} — JUDGMENT FAILED\n  domains: {', '.join(members)}\n")
            changelog.append(f"- {stamp} · c{i} · FAILED · {len(members)} domains")
            continue
        with open(os.path.join(snap_dir, base + ".md"), "w", encoding="utf-8") as f:
            f.write(render.render_markdown(a, table_md if i == 1 else ""))
        with open(os.path.join(snap_dir, base + ".json"), "w", encoding="utf-8") as f:
            f.write(a.model_dump_json(indent=2))
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


def _all_collected(case: str) -> list[str]:
    raw = os.path.join(ROOT, "cases", case, "raw")
    return sorted(os.path.basename(p)[:-5] for p in glob.glob(os.path.join(raw, "*.json")))


def _cluster_prior_verdict(members: list[str]) -> str | None:
    """If EVERY domain in the cluster is already attributed in the operator registry, return the
    combined verdict text (so we can skip re-judging it — a token saving). If any member is
    unattributed, return None (the cluster still needs LLM judgment)."""
    verdicts = []
    for d in members:
        r = subprocess.run([sys.executable, os.path.join("tools", "kb", "operator_registry.py"),
                            "find", d], cwd=ROOT, capture_output=True, text=True, timeout=60)
        out = (r.stdout or "").strip()
        if not out or "not attributed" in out.lower():
            return None
        verdicts.append(out)
    return "; ".join(verdicts)


async def run_case_parallel(seeds: list[str], case: str, *, hostile: bool, max_conc: int,
                            judge_conc: int, depth: int = 1, stale: int = 2, max_new: int = 8) -> list:
    """Phase 3 — scale. Collect concurrently (deterministic, no LLM). With depth>1 (--continue) keep
    expanding the frontier and re-collecting CHEAPLY until the case converges — judgment does NOT run
    per round. Then partition into same-operator clusters and judge each ONCE, in parallel; clusters
    already fully attributed skip the LLM entirely (their prior verdict is reused)."""
    _log(f"\n===== PARALLEL CASE · {len(seeds)} seeds · collect≤{max_conc} · judge≤{judge_conc}"
         f"{' · continue depth ' + str(depth) if depth > 1 else ''} =====")
    current = list(seeds)
    for rnd in range(1, depth + 1):                                                  # 1. expand-collect loop
        t0 = time.time()
        res = T.collect_many(current, case, hostile=hostile, max_workers=max_conc)
        ok = [r for r in res if r.get("ok")]
        fails = [r["host"] for r in res if not r.get("ok")]
        _log(f"round {rnd}: collected {len(ok)}/{len(res)} in {time.time() - t0:.0f}s "
             f"({sum(1 for r in ok if r.get('reused'))} cached)"
             + (f" · failures: {', '.join(fails)}" if fails else ""))
        T.ingest(case)                                                               # ingest each round
        conv = _convergence_snapshot(case)
        if conv:
            _log("convergence · " + conv.splitlines()[0])
        if depth == 1:
            break
        if _is_converged(case, stale):
            _log(f"CONVERGED — last {stale} rounds added nothing. Stopping expansion.")
            break
        new = _discover_new_seeds(case, _all_collected(case), max_new)
        if not new:
            _log("no new uncollected cluster peers. Stopping expansion.")
            break
        _log(f"→ round {rnd + 1}: +{len(new)} new seed(s): {', '.join(new)}")
        current = new                                                                # only collect the frontier

    clusters = _compute_components(case, _all_collected(case))                        # 2. cluster the whole graph
    to_judge, resolved = [], []
    for c in clusters:                                                               # 3. skip already-attributed
        v = _cluster_prior_verdict(c)
        (resolved.append((c, None, v)) if v else to_judge.append(c))
    _log(f"{len(clusters)} cluster(s): {len(to_judge)} to judge, {len(resolved)} already attributed "
         f"(LLM skipped)")
    for i, c in enumerate(to_judge, 1):
        _log(f"  judge {i} ({len(c)}): {', '.join(c[:8])}{' …' if len(c) > 8 else ''}")

    sem = asyncio.Semaphore(judge_conc)                                              # 4. judge in parallel

    async def _judge_cluster(members):
        async with sem:
            a, ph = await _judge(members, case)
            return members, a, ph

    outcomes = await asyncio.gather(*[_judge_cluster(c) for c in to_judge])
    table_md = _domain_table(case)                                                   # 5. persist + cost
    entries = [(m, a, None) for m, a, _ in outcomes] + resolved
    _persist_clusters(entries, case, table_md)
    allphases = {}
    for i, (_m, _a, ph) in enumerate(outcomes, 1):
        for k, v in ph.items():
            allphases[f"c{i}:{k}"] = v
    _report_cost(allphases, case=case)
    return entries


def _pop_val(argv: list[str], name: str, default: str) -> str:
    if name in argv:
        i = argv.index(name)
        val = argv[i + 1]
        del argv[i:i + 2]
        return val
    return default


def _main() -> None:
    argv = sys.argv[1:]
    hostile = "--hostile" in argv
    cont = "--continue" in argv
    parallel = "--parallel" in argv
    argv = [a for a in argv if a not in ("--hostile", "--continue", "--parallel")]
    depth = int(_pop_val(argv, "--depth", "4" if cont else "1"))
    stale = int(_pop_val(argv, "--stale", "2"))
    max_new = int(_pop_val(argv, "--max-new", "8"))
    collect_conc = int(_pop_val(argv, "--collect-conc", "8"))
    judge_conc = int(_pop_val(argv, "--judge-conc", "3"))
    if depth > 1:
        cont = True
    if len(argv) < 2:
        sys.exit("usage: orchestrator.py <CASE-ID> [--hostile] [--continue [--depth N] [--stale N] "
                 "[--max-new N]] [--parallel [--collect-conc N] [--judge-conc N]] <seed-url> ...")
    case, seeds = argv[0], argv[1:]
    # Auto-parallel for large seed sets (a single collect session would blow context/turns).
    auto_at = int(os.environ.get("HARNESS_PARALLEL_AT", "12"))
    if not parallel and len(seeds) >= auto_at:
        _log(f"auto-parallel: {len(seeds)} seeds ≥ {auto_at} (set HARNESS_PARALLEL_AT to change)")
        parallel = True
    if parallel:
        # --continue → cheap expand-collect until convergence, then judge once (depth from --depth).
        pdepth = depth if cont else 1
        asyncio.run(run_case_parallel(seeds, case, hostile=hostile, max_conc=collect_conc,
                                      judge_conc=judge_conc, depth=pdepth, stale=stale, max_new=max_new))
    else:
        asyncio.run(run_case(seeds, case, hostile=hostile, depth=depth, stale=stale, max_new=max_new))


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
    graph or the render is unavailable (missing mmdc/headless Chrome). Never raises."""
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
    gb = subprocess.run([sys.executable, os.path.join("WebPivot", "tools", "graph_build.py"),
                         *raw, "-o", graph_json], cwd=ROOT, capture_output=True, text=True, timeout=240)
    if gb.returncode != 0 or not os.path.exists(graph_json):
        _log(f" deliverables: graph build skipped ({(gb.stderr or gb.stdout or '').strip()[:120]})")
        return None
    gd = subprocess.run([sys.executable, os.path.join("IntelGraph", "scripts", "graph_to_diagram.py"),
                         graph_json, os.path.join(rep_dir, "case_diagram"),
                         "--title", (title or case)[:80], "--legend",
                         "--drop-types", ",".join(FIGURE_DROP_TYPES)],
                        cwd=ROOT, capture_output=True, text=True, timeout=180)
    if gd.returncode != 0 or not os.path.exists(fig):
        _log(f" deliverables: diagram skipped ({(gd.stderr or gd.stdout or '').strip()[:120]})")
        return None
    return fig


def _render_deliverables(case: str, snap_md: str, assessment: Assessment) -> dict:
    """After an assessment snapshot is written, auto-emit the case deliverables: an editable
    relationship diagram (PNG/SVG) and a polished PDF+DOCX (IntelReport). Best-effort — a
    missing browser (mmdc) or pandoc only logs a warning; the case never fails on it. Set
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
    parts = ["\n".join(fm), render.render_markdown(assessment, "")]
    if fig:
        parts += ["\n## Relationship graph\n",
                  "![%s — clustered relationship graph](%s)\n" % (case, os.path.basename(fig))]
    with open(report_md, "w", encoding="utf-8") as f:
        f.write("\n".join(parts) + "\n")

    stem = os.path.join(rep_dir, base)
    rr = subprocess.run([sys.executable, os.path.join("IntelReport", "scripts", "render_report.py"),
                         report_md, stem, "--case-id", case], cwd=ROOT, capture_output=True, text=True, timeout=300)
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
