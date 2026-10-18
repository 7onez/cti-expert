#!/usr/bin/env python3
"""Regression gate for a live --parallel run's harness bugs (A1):

  1. cli_backend._prepare_home wrote ONE mutable config.toml / mcp.json PER CASE, shared by every
     concurrent phase invocation (parallel cluster judges, struct-retry respawns). Concurrent
     phases raced on that one file: judge B's HARNESS_EMIT_OUT_FILE / HARNESS_PHASE / INTEL_CASE
     could land in judge A's process. Fixed by giving every call its OWN config directory, with
     only the resumable session store (codex's $CODEX_HOME/sessions/, omp's --session-dir) shared
     per (case, backend) so a judge chain's resume=<session_id> still finds its transcript.

  2. orchestrator.run_case_parallel assigned the persisted `_cN` snapshot suffix by SUCCESS order
     (position in the `done` list), not the cluster's own index in `_compute_components`'s output —
     a cluster that failed judgment silently vanished from the roll-up and the NEXT cluster's
     snapshot slid onto its index. Fixed by keeping `entries` in the cluster's OWN original order
     and recording a failure reason (SUMMARY.md + failover_progress.json) instead of dropping it.
     A per-cluster judge failure (not a backend outage) must not abort the other clusters or raise.

Offline: no CLI subprocess is spawned, no LLM is called — every seam is stubbed. Run standalone or
via run_eval.py. Needs claude_agent_sdk's backend-neutral surface only through the codex/omp shim
(HARNESS_BACKEND=codex avoids the real Anthropic SDK); if the harness modules themselves are not
importable in this environment, re-run under the harness venv:
  /root/.claude/skills/cti-expert/.venv/bin/python tools/eval/test_harness_phase_isolation.py
"""
import asyncio
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))            # intel_engine/tools/eval/
ENGINE = os.path.dirname(os.path.dirname(HERE))               # intel_engine/
HARNESS = os.path.join(ENGINE, "harness")


def check():
    out, passed, failed = [], 0, 0

    def ok(cond, label):
        nonlocal passed, failed
        passed, failed = (passed + 1, failed) if cond else (passed, failed + 1)
        out.append(("ok" if cond else "FAIL", label))

    try:
        sys.path.insert(0, HARNESS)
        os.environ.setdefault("HARNESS_BACKEND", "codex")   # cli_backend/orchestrator import without the real SDK
        import backend_select as bs
        bs.PROBE_CACHE = os.path.join(tempfile.mkdtemp(prefix="intel-probe-cache-"), "backend_probe.json")
        import cli_backend as cb
        import orchestrator as orch
    except ImportError as e:
        out.append(("skip", f"harness modules unavailable ({e}) — re-run under the harness venv "
                             "(/root/.claude/skills/cti-expert/.venv/bin/python)"))
        return passed, failed, out

    _t_prepare_home_codex_isolation(cb, ok)
    _t_prepare_home_omp_isolation(cb, ok)
    _t_run_case_parallel_partial_failure(orch, ok)
    _t_judge_rejects_out_of_scope_cluster(orch, ok)
    _t_record_hops(orch, ok)

    return passed, failed, out


def _t_prepare_home_codex_isolation(cb, ok):
    """Two overlapping codex phase preparations for the SAME case (two concurrent cluster judges,
    or a struct-retry respawn racing a sibling phase) must never share a mutable config.toml — but
    the resumable session store (codex reads $CODEX_HOME/sessions/) must be the SAME directory
    both times, or `codex exec resume <thread_id>` can't find a thread another call created."""
    tmp = tempfile.mkdtemp()
    saved_root = cb.ROOT
    try:
        cb.ROOT = tmp
        case = "CASE-0001"
        env_a = {"HARNESS_EMIT_OUT_FILE": os.path.join(tmp, "emit_A.json"), "HARNESS_PHASE": "correlate"}
        env_b = {"HARNESS_EMIT_OUT_FILE": os.path.join(tmp, "emit_B.json"), "HARNESS_PHASE": "assess"}
        cwd_a, extra_a, root_a, _sess_a = cb._prepare_home("codex", case, env_a)
        cwd_b, extra_b, root_b, _sess_b = cb._prepare_home("codex", case, env_b)

        ok(root_a != root_b, "two overlapping codex phases get DISTINCT config directories")
        ok(extra_a["CODEX_HOME"] != extra_b["CODEX_HOME"], "…and therefore distinct CODEX_HOMEs")
        cfg_a = open(os.path.join(extra_a["CODEX_HOME"], "config.toml"), encoding="utf-8").read()
        cfg_b = open(os.path.join(extra_b["CODEX_HOME"], "config.toml"), encoding="utf-8").read()
        ok("emit_A.json" in cfg_a and "emit_B.json" not in cfg_a,
           "phase A's config carries ONLY phase A's HARNESS_EMIT_OUT_FILE")
        ok("emit_B.json" in cfg_b and "emit_A.json" not in cfg_b,
           "phase B's config carries ONLY phase B's HARNESS_EMIT_OUT_FILE — no clobber")
        ok('HARNESS_PHASE = "correlate"' in cfg_a and 'HARNESS_PHASE = "assess"' in cfg_b,
           "each phase's own HARNESS_PHASE reaches its own config, never the other's")

        sessions_a = os.path.realpath(os.path.join(extra_a["CODEX_HOME"], "sessions"))
        sessions_b = os.path.realpath(os.path.join(extra_b["CODEX_HOME"], "sessions"))
        ok(sessions_a == sessions_b and os.path.isdir(sessions_a),
           "both isolated CODEX_HOMEs' sessions/ symlink resolves to the SAME shared per-case "
           "store — a judge chain's resume finds its thread regardless of which call created it")

        # cli_backend.query() removes a slot whose phase produced no session; either way the shared
        # session store must survive removal of any one config dir.
        shutil.rmtree(root_a, ignore_errors=True)
        ok(not os.path.exists(root_a), "the per-invocation config dir is independently removable")
        ok(os.path.isdir(sessions_a), "…without touching the shared sessions store")
    finally:
        cb.ROOT = saved_root


def _t_prepare_home_omp_isolation(cb, ok):
    """Same isolation property on the omp side, where the shared store is passed explicitly via
    --session-dir (omp's own supported flag) rather than a symlink inside the isolated dir."""
    tmp = tempfile.mkdtemp()
    saved_root = cb.ROOT
    try:
        cb.ROOT = tmp
        case = "CASE-0002"
        env_a = {"HARNESS_EMIT_OUT_FILE": os.path.join(tmp, "emit_A.json")}
        env_b = {"HARNESS_EMIT_OUT_FILE": os.path.join(tmp, "emit_B.json")}
        cwd_a, _extra_a, root_a, sess_a = cb._prepare_home("omp", case, env_a)
        cwd_b, _extra_b, root_b, sess_b = cb._prepare_home("omp", case, env_b)

        ok(cwd_a != cwd_b and root_a == cwd_a and root_b == cwd_b,
           "two overlapping omp phases get DISTINCT work dirs (each holds its own .omp/mcp.json)")
        mcp_a = json.load(open(os.path.join(cwd_a, ".omp", "mcp.json"), encoding="utf-8"))
        mcp_b = json.load(open(os.path.join(cwd_b, ".omp", "mcp.json"), encoding="utf-8"))
        ok(mcp_a["mcpServers"]["intel"]["env"]["HARNESS_EMIT_OUT_FILE"].endswith("emit_A.json"),
           "phase A's mcp.json carries phase A's emit file")
        ok(mcp_b["mcpServers"]["intel"]["env"]["HARNESS_EMIT_OUT_FILE"].endswith("emit_B.json"),
           "phase B's mcp.json carries phase B's emit file — no clobber, same case")
        ok(sess_a == sess_b and os.path.isdir(sess_a),
           "both calls report the SAME session_dir — the transcript store build_command passes as --session-dir")

        # omp binds a session to the directory it started in and refuses to resume it from anywhere
        # else (live run: 'Session … belongs to a directory that no longer exists'). A resumed phase
        # must therefore start in the slot that created its session, with ITS OWN config rewritten.
        cb.record_session_slot("omp", case, "S1", root_a)
        env_c = {"HARNESS_EMIT_OUT_FILE": os.path.join(tmp, "emit_C.json")}
        cwd_c, _extra_c, root_c, _sess_c = cb._prepare_home("omp", case, env_c, resume="S1")
        ok(os.path.realpath(cwd_c) == os.path.realpath(cwd_a),
           "resuming session S1 starts in the slot that created it (omp's session-directory binding)")
        mcp_c = json.load(open(os.path.join(cwd_c, ".omp", "mcp.json"), encoding="utf-8"))
        ok(mcp_c["mcpServers"]["intel"]["env"]["HARNESS_EMIT_OUT_FILE"].endswith("emit_C.json"),
           "the resumed phase's slot carries the NEW phase's emit file, not the one it was created with")
        mcp_b2 = json.load(open(os.path.join(cwd_b, ".omp", "mcp.json"), encoding="utf-8"))
        ok(mcp_b2["mcpServers"]["intel"]["env"]["HARNESS_EMIT_OUT_FILE"].endswith("emit_B.json"),
           "resuming one chain never rewrites a concurrent chain's config")
        cwd_d, *_ = cb._prepare_home("omp", case, env_c, resume="UNKNOWN")
        ok(cwd_d not in (cwd_a, cwd_b), "an unknown session id falls back to a fresh slot")

        cmd = cb.build_command("omp", model=None, resume="S1", session_dir=sess_a)
        ok("--session-dir" in cmd and sess_a in cmd, "build_command wires the shared session dir in")
    finally:
        cb.ROOT = saved_root


def _t_run_case_parallel_partial_failure(orch, ok):
    """Cluster 2's judge raises a plain (non-backend) RuntimeError. Clusters 1 and 3 must still be
    persisted under THEIR OWN _c1/_c3 suffixes (never shifted by success order), cluster 2 must be
    recorded as failed with its reason, and the run must NOT raise — a per-cluster judge failure is
    not a systemic backend outage."""
    from schemas import Assessment
    tmp = tempfile.mkdtemp()
    case = "CASE-0003"
    os.makedirs(os.path.join(tmp, "cases", case), exist_ok=True)
    A, B, C = ["a.example"], ["b.example"], ["c.example"]

    async def fake_judge(members, case_, members_only=False):
        if members == B:
            raise RuntimeError("phase assess failed (error): emit_path never appeared")
        return (Assessment(bluf=f"{members[0]} assessed", attribution_level="inconclusive",
                           confidence="low", cluster=[{"domain": members[0]}]), {})

    names = ("ROOT", "_judge", "_compute_components", "_cluster_prior_verdict", "_domain_table",
             "_render_deliverables", "_report_cost", "_hand_back", "_binary_round",
             "_convergence_snapshot", "_all_collected")
    saved = {n: getattr(orch, n) for n in names}
    saved_T = (orch.T.collect_many, orch.T.ingest)
    try:
        orch.ROOT = tmp
        orch._judge = fake_judge
        orch._compute_components = lambda case_, doms: [A, B, C]
        orch._cluster_prior_verdict = lambda members: None
        orch._domain_table = lambda case_: ""
        orch._render_deliverables = lambda *a, **k: {}
        orch._report_cost = lambda *a, **k: None
        orch._hand_back = lambda *a, **k: None
        orch._binary_round = lambda *a, **k: None
        orch._convergence_snapshot = lambda case_, **k: ""
        orch._all_collected = lambda case_: ["a.example", "b.example", "c.example"]
        orch.T.collect_many = lambda *a, **k: [{"host": h, "ok": True}
                                               for h in ("a.example", "b.example", "c.example")]
        orch.T.ingest = lambda case_: (True, "")

        entries = asyncio.run(orch.run_case_parallel(
            ["a.example", "b.example", "c.example"], case, hostile=False, max_conc=3, judge_conc=3))

        ok(len(entries) == 3, f"all three clusters are represented, in original order (got {len(entries)})")
        m1, a1, note1, reason1 = entries[0]
        m2, a2, note2, reason2 = entries[1]
        m3, a3, note3, reason3 = entries[2]
        ok(m1 == A and a1 is not None and reason1 is None, "cluster 1 persisted with its own assessment")
        ok(m2 == B and a2 is None and bool(reason2),
           f"cluster 2 recorded as FAILED with a reason (got {entries[1]!r})")
        ok(m3 == C and a3 is not None and reason3 is None,
           "cluster 3 STILL keeps its own assessment even though cluster 2 (before it) failed")

        snap_dir = os.path.join(tmp, "cases", case, "assessments")
        files = sorted(os.listdir(snap_dir))
        ok(any(f.endswith("_c1.json") for f in files), "cluster 1 snapshot uses suffix _c1")
        ok(not any(f.endswith("_c2.json") for f in files), "cluster 2 (failed) writes no snapshot file")
        ok(any(f.endswith("_c3.json") for f in files),
           "cluster 3 keeps ITS OWN index _c3 — not shifted to _c2 by success order (the A1 bug)")

        summ = open(os.path.join(tmp, "cases", case, "SUMMARY.md"), encoding="utf-8").read()
        ok("Cluster 2" in summ and "JUDGMENT FAILED" in summ and "emit_path never appeared" in summ,
           "the roll-up names cluster 2 as failed, with its reason")

        prog = orch._load_failover_progress(case)
        ok(orch._members_key(A) in prog and orch._members_key(C) in prog,
           "the two successful clusters are recorded (a resume reuses them, never re-judged)")
        ok(orch._members_key(B) not in prog, "the failed cluster is never a reuse hit")
        ok(orch._FAILED_KEY in prog and orch._members_key(B) in prog[orch._FAILED_KEY]
           and "emit_path" in prog[orch._FAILED_KEY][orch._members_key(B)],
           "the failed cluster's reason is recorded in failover_progress.json for the next resume")

        # HEAD: house-report / build_report_data read cases/<id>/assessment.json — the parallel
        # judgment must land there (it used to stay the loop's earlier render), with every cluster
        # indexed and the failed one named, never silently dropped.
        case_dir = os.path.join(tmp, "cases", case)
        head = json.load(open(os.path.join(case_dir, "assessment.json"), encoding="utf-8"))
        ok(head.get("_generator") == "harness-parallel" and head.get("_primary_cluster") == 1
           and head.get("bluf") == "a.example assessed",
           "the head carries the primary judged cluster's verdict (seed tie -> lowest index)")
        rows = {r["index"]: r for r in head.get("clusters") or []}
        ok(set(rows) == {1, 2, 3} and rows[2].get("status") == "failed"
           and "emit_path" in (rows[2].get("note") or "") and rows[3]["snapshot"].endswith("_c3.json"),
           "the head indexes every cluster: c2 as failed with its reason, c3 by its own snapshot")
        md = open(os.path.join(case_dir, "assessment.md"), encoding="utf-8").read()
        ok(md.startswith("# Assessment") and "Other clusters" in md, "assessment.md head is the harness render")
        prog_saved = {k: v for k, v in prog.items() if k != orch._FAILED_KEY}
        orch._write_head(entries, prog_saved, case, "", ["c.example"])
        head = json.load(open(os.path.join(case_dir, "assessment.json"), encoding="utf-8"))
        ok(head.get("_primary_cluster") == 3, "the cluster holding the case's seeds becomes the primary head")
        analyst = {"bluf": "analyst's own judgment", "attribution_level": "same-operator"}
        json.dump(analyst, open(os.path.join(case_dir, "assessment.json"), "w"))
        open(os.path.join(case_dir, "assessment.md"), "w").write("# My notes\nhand-written\n")
        orch._write_head(entries, prog_saved, case, "", ["a.example"])
        ok(json.load(open(os.path.join(case_dir, "assessment.json"))) == analyst,
           "an analyst-authored assessment.json (no engine _generator) is never overwritten")
        ok(open(os.path.join(case_dir, "assessment.md")).read() == "# My notes\nhand-written\n",
           "an analyst-authored assessment.md is never overwritten")
    finally:
        for n, v in saved.items():
            setattr(orch, n, v)
        orch.T.collect_many, orch.T.ingest = saved_T


def _t_record_hops(orch, ok):
    """Hosts the harness collects must enter the case's hop map. Live gap: 7 subdomains collected
    by a harness round had no hop, so the loop treated them as leaves and clusters.json kept them
    out — the judged head said 15 hosts, the cluster file 8."""
    import case_state as cs
    tmp = tempfile.mkdtemp()
    case = "CASE-0005"
    raw = os.path.join(tmp, "cases", case, "raw")
    os.makedirs(raw)
    for h in ("seed.example", "apex.example", "old.apex.example"):
        json.dump({"meta": {"host": h}, "pivots": []}, open(os.path.join(raw, h + ".json"), "w"))
    saved = (orch.ROOT, cs.ROOT)
    try:
        orch.ROOT = cs.ROOT = tmp
        st = cs.load_state(case)
        st.update(hops={"seed.example": 0, "apex.example": 1}, expansion_depth=2)
        cs.save_state(case, st)
        orch._record_hops(case, ["sub.apex.example", "other.example", "seed.example"], ["apex.example"])
        hops = cs.load_state(case)["hops"]
        ok(hops.get("sub.apex.example") == 1, "a new subdomain of a held apex inherits the apex's hop")
        ok(hops.get("other.example") == 2,
           "a new foreign apex is one hop past its deepest parent (capped at the depth -> a leaf)")
        ok(hops.get("seed.example") == 0, "an existing hop is never raised")
        ok(hops.get("old.apex.example") == 1,
           "an already-collected host with no hop is backfilled from its apex (same registration)")
        st = cs.load_state(case)
        st["hops"] = {}
        cs.save_state(case, st)
        orch._record_hops(case, ["x.example"], ["seed.example"])
        ok(cs.load_state(case).get("hops") in ({}, None), "a legacy state with no hop map is left alone")
    finally:
        orch.ROOT, cs.ROOT = saved


def _t_judge_rejects_out_of_scope_cluster(orch, ok):
    """Live run: the judge of a one-host cluster read the case-wide KB and returned the NEIGHBOURING
    estate as its `cluster`, which then shipped as that cluster's _cN verdict. The per-cluster judge
    must re-prompt once with the exact member list and refuse (raise) if the judge still names hosts
    outside its cluster; a judge that corrects itself is accepted. The single-judge path is untouched."""
    from types import SimpleNamespace as NS
    members = ["solo.example"]
    stray = {"bluf": "x", "attribution_level": "same-operator", "confidence": "moderate",
             "cluster": [{"domain": "other-a.example"}, {"domain": "other-b.example"}]}
    fixed = dict(stray, cluster=[{"domain": "solo.example"}])

    def run(assess_outputs, members_only=True):
        prompts, outs = [], list(assess_outputs)

        async def fake_phase(prompt, *, label, **kw):
            prompts.append((label, prompt))
            if label in ("correlate", "verify"):
                return NS(session_id="S", subtype="success", structured_output=None)
            return NS(session_id="S", subtype="success", structured_output=outs.pop(0))
        saved = (orch._phase, orch._scope, orch._skill, orch.ESCALATE_ON)
        orch._phase, orch._scope, orch._skill, orch.ESCALATE_ON = (
            fake_phase, (lambda case_: {}), (lambda name: ""), False)
        try:
            a, _ph = asyncio.run(orch._judge(members, "CASE-0004", members_only=members_only))
            return a, None, prompts
        except RuntimeError as e:
            return None, str(e), prompts
        finally:
            orch._phase, orch._scope, orch._skill, orch.ESCALATE_ON = saved

    a, err, prompts = run([stray, stray])
    ok(a is None and err and "out-of-scope" in err and "other-a.example" in err,
       "a judge that keeps naming hosts outside its cluster is refused, with the stray hosts named")
    ok(any(lbl == "assess-scope" for lbl, _p in prompts), "it was re-prompted once before being refused")
    ok(all("solo.example" in p for lbl, p in prompts if lbl in ("correlate", "assess", "assess-scope")),
       "correlate/assess/re-prompt state the exact member list")
    a, err, _p = run([stray, fixed])
    ok(a is not None and err is None and [c.domain for c in a.cluster] == ["solo.example"],
       "a judge that corrects its member list on the re-prompt is accepted")
    a, err, prompts = run([stray], members_only=False)
    ok(a is not None and not any(lbl == "assess-scope" for lbl, _p in prompts),
       "the single-judge investigate path (seeds grow into siblings) is not scope-restricted")

if __name__ == "__main__":
    p, f, lines = check()
    for status, label in lines:
        print(f"  [{status:4s}] {label}")
    print(f"\n{p} passed, {f} failed")
    raise SystemExit(bool(f))
