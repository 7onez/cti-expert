#!/usr/bin/env python3
"""Regression: the Codex/OMP CLI harness backend and the backend resolver.

Defends: (1) an unusable backend is a loud failure, never a ✓ phase; (2) the host agent this
process runs inside is preferred (inner-most marker first); (3) the phase judge fails a run in
which the host executed anything outside the `intel` MCP server (shell, another MCP server, a
built-in) or refused an MCP call at its own approval layer (gate bypass); (4) the phase context
(case/phase/hostile) bound by the orchestrator reaches the server process env and host-agent
markers do not; (5) the MCP server's emit_result path validates required keys and persists.
Offline: no CLI is spawned (subprocess seams stubbed)."""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
HARNESS = os.path.join(os.path.dirname(HERE), "harness")
sys.path.insert(0, HARNESS)
os.environ.setdefault("HARNESS_BACKEND", "codex")   # cli_backend must import without the SDK
import backend_select as bs  # noqa: E402

# Every test here runs isolated from the real probe cache: failover paths call bs.mark_failed(),
# which would otherwise tell the user's next real `harness open` to skip a backend for 10 minutes.
bs.PROBE_CACHE = os.path.join(tempfile.mkdtemp(prefix="intel-probe-cache-"), "backend_probe.json")
import cli_backend as cb  # noqa: E402
import audit  # noqa: E402

_LINES: list = []
_P = [0, 0]


def ok(cond, msg):
    _P[0 if cond else 1] += 1
    _LINES.append(f"  {'ok  ' if cond else 'FAIL'} {msg}")


def t_host_agent():
    ok(bs.host_agent({"CODEX_THREAD_ID": "x", "OMPCODE": "1", "CLAUDECODE": "1"}) == "codex",
       "inner-most host wins: codex marker beats inherited omp/claude markers")
    ok(bs.host_agent({"OMPCODE": "1", "CLAUDECODE": "1"}) == "omp", "omp beats inherited claude marker")
    ok(bs.host_agent({"CLAUDECODE": "1"}) == "claude", "claude marker alone → claude")
    ok(bs.host_agent({}) is None, "no marker → no host")
    ok(bs.candidates({"OMPCODE": "1"})[0] == "omp" and "codex" in bs.candidates({}),
       "the host agent is tried first, then the fixed order")


def t_resolve_fails_loudly():
    saved = dict(os.environ)
    try:
        os.environ["HARNESS_BACKEND"] = "auto"
        for k in ("CODEX_THREAD_ID", "CODEX_SESSION_ID", "OMPCODE", "CLAUDECODE", "ANTHROPIC_API_KEY",
                  "OPENAI_API_KEY", "DEEPSEEK_API_KEY", "MOONSHOT_API_KEY", "OPENAI_BASE_URL"):
            os.environ.pop(k, None)
        bs.available, _av = (lambda n: (False, f"{n} absent")), bs.available
        try:
            try:
                bs.resolve()
                ok(False, "resolve() raised when no backend is usable")
            except SystemExit as e:
                msg = str(e)
                ok("no usable LLM backend" in msg and "codex" in msg and "claude" in msg,
                   "the failure names every candidate and why")
        finally:
            bs.available = _av
        os.environ["HARNESS_BACKEND"] = "bogus"
        try:
            bs.resolve()
            ok(False, "unknown HARNESS_BACKEND rejected")
        except SystemExit:
            ok(True, "unknown HARNESS_BACKEND rejected")
    finally:
        os.environ.clear()
        os.environ.update(saved)


def t_judge():
    good = cb.parse_codex_events("\n".join(json.dumps(e) for e in [
        {"type": "thread.started", "thread_id": "T1"},
        {"type": "item.completed", "item": {"type": "mcp_tool_call", "server": "intel", "tool": "hash_id",
                                             "arguments": {"hashes": "x"}, "status": "completed"}},
        {"type": "item.completed", "item": {"type": "agent_message", "text": "DONE"}},
        {"type": "turn.completed", "usage": {"input_tokens": 1}}]))
    ok(good.session_id == "T1" and good.tool_calls == [("hash_id", {"hashes": "x"})] and cb.judge_events(good) is None,
       "codex: a clean MCP-only phase parses and passes")
    shell = cb.parse_codex_events(json.dumps({"type": "item.completed", "item": {
        "type": "command_execution", "command": "/bin/bash -lc 'gemini -y'"}}))
    ok("isolation contract" in (cb.judge_events(shell) or ""), "codex: a shell execution FAILS the phase")
    foreign = cb.parse_codex_events(json.dumps({"type": "item.completed", "item": {
        "type": "mcp_tool_call", "server": "ak-agent-runtime", "tool": "run", "arguments": {}, "status": "completed"}}))
    ok(cb.judge_events(foreign) is not None and not foreign.tool_calls,
       "codex: a call to ANOTHER MCP server is an isolation breach, not a tool call")
    refused = cb.parse_codex_events(json.dumps({"type": "item.completed", "item": {
        "type": "mcp_tool_call", "server": "intel", "tool": "pivot_extract", "arguments": {}, "status": "failed",
        "error": {"message": "MCP tool call requires approval, but approval policy is never"}}}))
    ok("gate bypassed" in (cb.judge_events(refused) or ""), "codex: host-level refusal is flagged (gate bypass)")
    omp_ok = cb.parse_omp_events("\n".join(json.dumps(e) for e in [
        {"type": "session", "id": "S1"},
        {"type": "tool_execution_start", "toolName": "mcp__intel_hash_id", "args": {"hashes": "x"}},
        {"type": "turn_end", "message": {"role": "assistant", "content": [{"type": "text", "text": "DONE"}],
                                         "usage": {"input": 1}}}]))
    ok(omp_ok.session_id == "S1" and omp_ok.tool_calls == [("hash_id", {"hashes": "x"})]
       and cb.judge_events(omp_ok) is None, "omp: a clean MCP-only phase parses and passes")
    omp_bad = cb.parse_omp_events(json.dumps({"type": "tool_execution_start", "toolName": "manage_skill", "args": {}}))
    ok(cb.judge_events(omp_bad) is not None, "omp: a surviving built-in tool call FAILS the phase")
    omp_foreign = cb.parse_omp_events(json.dumps({"type": "tool_execution_start", "toolName": "mcp__other_run", "args": {}}))
    ok(cb.judge_events(omp_foreign) is not None and not omp_foreign.tool_calls,
       "omp: another MCP server's tool is an isolation breach")


def t_context_and_env():
    captured = {}

    async def fake_run(cmd, *, cwd, env, timeout, stdin_text=None):
        captured["cmd"], captured["env"], captured["stdin"] = cmd, env, stdin_text
        # Read config.toml INSIDE the fake process call: cli_backend now removes the whole
        # per-invocation config dir once the phase ends (the isolation fix), so it must be
        # captured while the (fake) host process is still "running" against it.
        captured["cfg"] = open(os.path.join(env["CODEX_HOME"], "config.toml")).read()
        ev = [{"type": "thread.started", "thread_id": "T9"},
              {"type": "item.completed", "item": {"type": "mcp_tool_call", "server": "intel", "tool": "kb_entity",
                                                   "arguments": {"value": "a.example"}, "status": "completed"}},
              {"type": "item.completed", "item": {"type": "agent_message", "text": "DONE"}}]
        return 0, "\n".join(json.dumps(e) for e in ev), ""

    saved = dict(os.environ)
    _run, _home = cb._run_phase, cb._phase_home
    tmp = tempfile.mkdtemp()
    try:
        os.environ.update({"CLAUDECODE": "1", "OMPCODE": "1", "CODEX_THREAD_ID": "zz", "PI_SMOL_MODEL": "m",
                           "HARNESS_KB": "knowledge_scratch", "HARNESS_NO_ENRICH": "1",
                           "CTI_PROXIES": "http://u:p@203.0.113.9:80", "INTEL_VENDOR_TOKEN": "s3cret",
                           "HARNESS_API_KEY_X": "s3cret2", "FOFA_KEY": "s3cret3"})
        os.environ.pop("HARNESS_HOSTILE", None)
        cb._run_phase = fake_run
        cb._phase_home = lambda case: tmp
        cb.BACKEND = "codex"
        audit.set_context(case="CASE-0001", phase="collect", hostile=True, backend="codex")
        opts = cb.ClaudeAgentOptions(system_prompt="S" * 200_000, allowed_tools=["mcp__collect__kb_entity"])

        async def go():
            out = []
            async for m in cb.query(prompt="p", options=opts):
                out.append(m)
            return out

        msgs = asyncio.run(go())
        env = captured["env"]
        ok(env.get("CODEX_HOME", "").startswith(tmp), "codex runs in an isolated CODEX_HOME under the case")
        cfg = captured["cfg"]
        link = os.path.join(tmp, "codex_bysession", "T9")
        ok(os.path.isdir(link) and os.path.realpath(link) == os.path.realpath(env["CODEX_HOME"]),
           "the phase's slot is kept and linked to its session id, so a resume starts in the same home")
        ok("shell_tool = false" in cfg and 'default_tools_approval_mode = "approve"' in cfg
           and "[mcp_servers.intel]" in cfg, "codex config: no shell, intel MCP pre-approved")
        ok('HARNESS_HOSTILE = "1"' in cfg and 'HARNESS_PHASE = "collect"' in cfg and 'INTEL_CASE = "CASE-0001"' in cfg,
           "the phase's hostile/phase/case context reaches the MCP server env")
        ok('HARNESS_ALLOWED_TOOLS = "kb_entity"' in cfg, "the phase's allowed tools narrow the server")
        ok('HARNESS_KB = "knowledge_scratch"' in cfg and 'HARNESS_NO_ENRICH = "1"' in cfg,
           "operator knobs (HARNESS_KB / HARNESS_NO_ENRICH) reach the server — a no-spend smoke stays no-spend")
        ok("s3cret" not in cfg and "203.0.113.9" not in cfg and "CTI_PROXIES" not in cfg,
           "no proxy credential, key or token is ever written into the host config file")
        ok(not any(k in env for k in ("CLAUDECODE", "OMPCODE", "CODEX_THREAD_ID", "PI_SMOL_MODEL")),
           "host-agent markers are scrubbed from the child env")
        ok(captured["cmd"][-1] == "-" and captured["stdin"] and len(captured["stdin"]) > 200_000,
           "the prompt travels on stdin, not argv")
        res = [m for m in msgs if isinstance(m, cb.ResultMessage)][0]
        ok(res.subtype == "success" and res.session_id == "T9", "a clean phase yields success + session id")
        calls = [b.name for m in msgs if isinstance(m, cb.AssistantMessage) for b in m.content]
        ok(calls == ["kb_entity"], "tool calls surface to the worklog by bare name")
    finally:
        cb._run_phase, cb._phase_home = _run, _home
        os.environ.clear()
        os.environ.update(saved)


def t_emit_result_server():
    tmp = tempfile.mkdtemp()
    schema = os.path.join(tmp, "s.json")
    out = os.path.join(tmp, "o.json")
    json.dump({"type": "object", "required": ["bluf", "confidence"]}, open(schema, "w"))
    env = {**os.environ, "HARNESS_EMIT_SCHEMA_FILE": schema, "HARNESS_EMIT_OUT_FILE": out,
           "HARNESS_ALLOWED_TOOLS": "hash_id", "HARNESS_BACKEND": "codex"}
    reqs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "emit_result", "arguments": {"bluf": "x"}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
             "params": {"name": "emit_result", "arguments": {"bluf": "x", "confidence": "low"}}},
            {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "kb_entity", "arguments": {}}}]
    p = subprocess.Popen([sys.executable, os.path.join(HARNESS, "mcp_server.py")],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                         text=True, env=env, cwd=os.path.dirname(HERE))
    by_id = {}
    try:
        for r in reqs:                       # a real client keeps stdin open until it has its answers
            p.stdin.write(json.dumps(r) + "\n")
            p.stdin.flush()
            while True:
                line = p.stdout.readline()
                if not line:
                    break
                try:
                    m = json.loads(line)
                except ValueError:
                    continue
                if m.get("id") == r["id"]:
                    by_id[m["id"]] = m
                    break
    finally:
        p.stdin.close()
        p.wait(timeout=60)
    names = {t["name"] for t in by_id.get(2, {}).get("result", {}).get("tools", [])}
    ok(names == {"hash_id", "emit_result"}, f"tools/list is narrowed to the phase's tools + emit_result (got {sorted(names)})")
    r3 = by_id.get(3, {}).get("result", {})
    ok(r3.get("isError") is True and "confidence" in json.dumps(r3), "emit_result rejects a payload missing required keys")
    r4 = by_id.get(4, {}).get("result", {})
    ok(r4.get("isError") is False and json.load(open(out)) == {"bluf": "x", "confidence": "low"},
       "a complete emit_result payload is persisted for the backend to read")
    r5 = by_id.get(5, {}).get("result", {})
    ok(r5.get("isError") is True and "unknown tool" in json.dumps(r5), "a tool outside the phase allowlist is unknown")


def t_deliverable_mask():
    """A previous owner cited inside a REJECTED alternative must not reach the shareable report in
    clear (e-mail or personal name); the operator's own selector must stay readable."""
    import orchestrator as orch
    from schemas import Assessment
    tmp = tempfile.mkdtemp()
    case = "CASE-0001"
    cdir = os.path.join(tmp, "cases", case)
    os.makedirs(os.path.join(cdir, "raw"))
    json.dump({"meta": {"host": "site-a.example"}, "artifacts": {"whois": {
        "registrant_email": "owner@example.com", "created": "2025-08-01T00:00:00Z",
        "history": {"records": [
            {"email": "owner@example.com", "name": "Owner Current", "created": "2025-08-01T00:00:00Z"},
            {"email": "stranger@example.org", "name": "Prior Stranger", "created": "2017-06-20T00:00:00Z"}]}}}},
        open(os.path.join(cdir, "raw", "site-a.example.json"), "w"))
    a = Assessment(bluf="site-a.example is likely one operator", attribution_level="same-operator",
                   confidence="moderate",
                   cluster=[{"domain": "site-a.example", "shared_artifacts": ["email:owner@example.com"]}],
                   alternatives=[{"explanation": "Prior Stranger (stranger@example.org) is the operator",
                                  "status": "rejected", "why": "earlier registration era (2017)"}])
    captured = {}
    saved = (orch.ROOT, orch._ensure_case_diagram, orch.T._run)
    try:
        orch.ROOT = tmp
        orch._ensure_case_diagram = lambda *a, **k: None

        def fake_run(cmd, timeout=180):
            captured["md"] = open(cmd[2], encoding="utf-8").read()     # render_report.py <md> <stem>
            return subprocess.CompletedProcess(cmd, 1, "", "renderer stubbed")
        orch.T._run = fake_run
        orch._render_deliverables(case, os.path.join(cdir, "assessments", "x_r1.md"), a)
    finally:
        orch.ROOT, orch._ensure_case_diagram, orch.T._run = saved
    md = captured.get("md", "")
    ok("stranger@example.org" in md and "Prior Stranger" in md,
       "masking is disabled: a previous owner in a rejected alternative appears in plain text")
    ok("owner@example.com" in md, "the operator's own cluster selector stays in clear")


def t_failure_classification():
    c = bs.classify_failure
    ok(c("Your workspace is out of credits. Add credits to continue.") == "quota",
       "codex 'out of credits' is a backend (quota) failure")
    ok(c("Failed to authenticate: OAuth session expired and could not be refreshed") == "auth",
       "an expired OAuth session is a backend (auth) failure")
    ok(c("HTTP 429 Too Many Requests") == "rate", "a provider rate limit is a backend failure")
    ok(c("phase assess produced no emit_result") is None and c("pivot_extract raised KeyError") is None,
       "a tool or schema fault is NOT a backend failure (no backend switch)")
    ok(bs._said_ok("Working...\nOK") and not bs._said_ok("token budget exceeded") and not bs._said_ok(""),
       "the probe accepts an exact OK line only (no substring match on 'token')")


def t_failover_loop():
    """harness open: backend dies mid-run → next backend probed → asked → same command re-run on it."""
    import cli as hcli
    runs = []

    def fake_run(cmd, cwd=None, env=None):
        runs.append((list(cmd), env.get("HARNESS_BACKEND")))
        if len(runs) == 1:           # first attempt: codex runs out of credits mid-case
            bs.write_failover(env["HARNESS_FAILOVER_FILE"], "codex", "Your workspace is out of credits", "quota")
            return subprocess.CompletedProcess(cmd, bs.FAILOVER_EXIT)
        return subprocess.CompletedProcess(cmd, 0)

    saved = (hcli.subprocess.run, bs.resolve, hcli._confirm, dict(os.environ))
    seen_exclude = []
    try:
        hcli.subprocess.run = fake_run
        bs.resolve = lambda **kw: (seen_exclude.append(kw.get("exclude")), ("omp", "omp answered", []))[1]
        asked = []
        hcli._confirm = lambda q: (asked.append(q), True)[1]
        os.environ.pop("HARNESS_FAILOVER", None)
        rc = hcli._run_orchestrator(["CASE-0001", "https://site-a.example", "--failover", "ask"], cont=False)
        ok(rc == 0 and len(runs) == 2, "after a mid-run backend failure the case is re-run once and succeeds")
        ok(runs[1][1] == "omp" and seen_exclude and "codex" in seen_exclude[0],
           "the re-run uses the next backend, excluding the one that failed")
        ok(runs[0][0] == runs[1][0] and "--failover" not in runs[0][0],
           "the SAME orchestrator command is resumed; the --failover flag is not passed through")
        ok(asked and "omp" in asked[0], "mode ask: the user is asked before switching")

        runs.clear()
        hcli._confirm = lambda q: False
        rc = hcli._run_orchestrator(["CASE-0001", "https://site-a.example", "--failover", "ask"], cont=False)
        ok(rc == bs.FAILOVER_EXIT and len(runs) == 1, "a declined switch stops without re-running")

        runs.clear()
        rc = hcli._run_orchestrator(["CASE-0001", "https://site-a.example", "--failover", "off"], cont=False)
        ok(rc == bs.FAILOVER_EXIT and len(runs) == 1, "mode off (cron/CI): no switch, exit code says why")
    finally:
        hcli.subprocess.run, bs.resolve, hcli._confirm = saved[0], saved[1], saved[2]
        os.environ.clear()
        os.environ.update(saved[3])


def t_per_run_check_is_free():
    """A normal run must never send a model request to decide the backend; doctor does, and its
    answer is cached for the runs that follow."""
    tmp = tempfile.mkdtemp()
    saved = (bs._run, bs.PROBE_CACHE, bs.available, dict(os.environ))
    calls = []

    def fake_run(cmd, env=None, timeout=None, stdin_text=None):
        calls.append(list(cmd))
        if cmd[:3] == ["codex", "login", "status"]:
            return 0, "Logged in using ChatGPT"
        if cmd[:2] == ["codex", "exec"]:
            return 0, json.dumps({"type": "item.completed", "item": {"type": "agent_message", "text": "OK"}})
        return 1, "unexpected"
    try:
        bs._run = fake_run
        bs.PROBE_CACHE = os.path.join(tmp, "probe.json")
        bs.available = lambda n: (n == "codex", "present" if n == "codex" else "absent")
        for k in ("CODEX_THREAD_ID", "CODEX_SESSION_ID", "OMPCODE", "CLAUDECODE"):
            os.environ.pop(k, None)
        os.environ["HARNESS_BACKEND"] = "auto"
        name, why, _ = bs.resolve()
        ok(name == "codex" and not any(c[:2] == ["codex", "exec"] for c in calls),
           "a per-run resolve uses the free login-status check, never a model request")
        calls.clear()
        name, why, _ = bs.resolve(deep=True)
        ok(any(c[:2] == ["codex", "exec"] for c in calls), "doctor (deep) sends one real request")
        calls.clear()
        name, why, _ = bs.resolve()
        ok(name == "codex" and not calls and "min ago" in why,
           "the next run reuses doctor's cached answer — no subprocess at all")
        bs.mark_failed("codex", "Your workspace is out of credits")
        try:
            bs.resolve()
            ok(False, "a backend that failed mid-run is skipped by the next resolve")
        except SystemExit as e:
            ok("out of credits" in str(e), "a backend that failed mid-run is skipped by the next resolve")
    finally:
        bs._run, bs.PROBE_CACHE, bs.available = saved[0], saved[1], saved[2]
        os.environ.clear()
        os.environ.update(saved[3])


def t_parallel_resume_keeps_finished_clusters():
    """Parallel judge: cluster B's backend dies after cluster A finished. A is saved; the resumed
    run reuses A and judges only B."""
    import orchestrator as orch
    from schemas import Assessment
    tmp = tempfile.mkdtemp()
    case = "CASE-0001"
    os.makedirs(os.path.join(tmp, "cases", case), exist_ok=True)
    A, B = ["a.example"], ["b.example"]
    judged = []
    fail_b = {"on": True}

    async def fake_judge(members, case_, members_only=False):
        judged.append(tuple(members))
        if members == B and fail_b["on"]:
            raise bs.BackendUnavailable("codex", "Your workspace is out of credits", "quota")
        return Assessment(bluf=f"{members[0]} assessed", attribution_level="inconclusive",
                          confidence="low", cluster=[{"domain": members[0]}]), {}

    names = ("ROOT", "_judge", "_compute_components", "_cluster_prior_verdict", "_domain_table",
             "_render_deliverables", "_report_cost", "_hand_back", "_binary_round",
             "_convergence_snapshot", "_all_collected")
    saved = {n: getattr(orch, n) for n in names}
    saved_T = (orch.T.collect_many, orch.T.ingest)
    try:
        orch.ROOT = tmp
        orch._judge = fake_judge
        orch._compute_components = lambda case_, doms: [A, B]
        orch._cluster_prior_verdict = lambda members: None
        orch._domain_table = lambda case_: ""
        orch._render_deliverables = lambda *a, **k: {}
        orch._report_cost = lambda *a, **k: None
        orch._hand_back = lambda *a, **k: None
        orch._binary_round = lambda *a, **k: None
        orch._convergence_snapshot = lambda case_, **k: ""
        orch._all_collected = lambda case_: ["a.example", "b.example"]
        orch.T.collect_many = lambda *a, **k: [{"host": "a.example", "ok": True}, {"host": "b.example", "ok": True}]
        orch.T.ingest = lambda case_: (True, "")
        run = lambda: asyncio.run(orch.run_case_parallel(["a.example", "b.example"], case, hostile=False,
                                                         max_conc=2, judge_conc=2))
        try:
            run()
            ok(False, "the backend failure is re-raised after saving")
        except bs.BackendUnavailable:
            ok(True, "the backend failure is re-raised after saving")
        prog = orch._load_failover_progress(case)
        ok(orch._members_key(A) in prog and orch._members_key(B) not in prog,
           "the finished cluster's snapshot is recorded; the stopped one is not")
        judged.clear()
        fail_b["on"] = False
        run()
        ok(judged == [tuple(B)], f"the resumed run judges ONLY the unfinished cluster (judged {judged})")
        ok(not os.path.exists(orch._progress_path(case)), "a completed run clears the failover progress")
    finally:
        for n, v in saved.items():
            setattr(orch, n, v)
        orch.T.collect_many, orch.T.ingest = saved_T


def t_model_traffic_bypasses_research_proxy():
    """Model CLIs go direct; collectors keep the research proxy the dispatcher exported."""
    env = {"HTTPS_PROXY": "http://u:p@203.0.113.9:80", "NO_PROXY": "localhost,127.0.0.1"}
    bs.bypass_proxy_for_models(env)
    bs.bypass_proxy_for_models(env)          # idempotent: a second pass adds nothing
    hosts = env["NO_PROXY"].split(",")
    ok("api.anthropic.com" in hosts and ".openai.com" in hosts and "chatgpt.com" in hosts,
       "model-provider hosts are added to NO_PROXY")
    ok(hosts[:2] == ["localhost", "127.0.0.1"] and len(hosts) == len(set(hosts)),
       "existing NO_PROXY entries are kept and nothing is duplicated")
    ok(env["HTTPS_PROXY"] == "http://u:p@203.0.113.9:80", "the collector proxy itself is left in place")
    seen = {}
    real = bs.subprocess.run
    try:
        bs.subprocess.run = lambda cmd, **kw: (seen.update(kw.get("env") or {}),
                                               subprocess.CompletedProcess(cmd, 0, "OK", ""))[1]
        bs._run(["claude", "-p", "x"], env={"HTTPS_PROXY": "http://u:p@203.0.113.9:80"})
    finally:
        bs.subprocess.run = real
    ok("api.anthropic.com" in (seen.get("NO_PROXY") or ""), "every probe subprocess gets the model bypass")


def t_timeout_is_not_a_failure():
    """A probe that times out is not cached as 'failed' (it would skip a working backend for 10 min),
    and a phase process keeps the model bypass the orchestrator put in its env."""
    saved = (bs.probe, bs.available, bs.PROBE_CACHE, os.environ.get("NO_PROXY"))
    tmp = tempfile.mkdtemp()
    try:
        bs.PROBE_CACHE = os.path.join(tmp, "probe.json")
        bs.available = lambda n: (True, "present")
        bs.probe = lambda n: (False, f"{n} unusable: probe timed out after 90s")
        okv, why = bs.check("codex", deep=True)
        ok(not okv and "timed out" in why and not os.path.exists(bs.PROBE_CACHE),
           "a timed-out probe is reported as a timeout and never cached")
        bs.probe = lambda n: (False, f"{n} unusable: Your workspace is out of credits")
        bs.check("codex", deep=True)
        ok(bs._cache_get("codex") is not None and bs._cache_get("codex")[0] is False,
           "a real failure answer IS cached (so runs skip it)")
        os.environ["NO_PROXY"] = "localhost"
        bs.bypass_proxy_for_models(os.environ)
        child = cb._child_env({})
        ok("api.anthropic.com" in child.get("NO_PROXY", "") and ".chatgpt.com" in child.get("NO_PROXY", ""),
           "a codex/omp phase process inherits the model bypass (subscription hosts included)")
    finally:
        bs.probe, bs.available, bs.PROBE_CACHE = saved[0], saved[1], saved[2]
        if saved[3] is None:
            os.environ.pop("NO_PROXY", None)
        else:
            os.environ["NO_PROXY"] = saved[3]


_TESTS = [t_host_agent, t_resolve_fails_loudly, t_judge, t_context_and_env, t_emit_result_server,
          t_deliverable_mask, t_failure_classification, t_failover_loop, t_per_run_check_is_free,
          t_parallel_resume_keeps_finished_clusters,
          t_model_traffic_bypasses_research_proxy, t_timeout_is_not_a_failure]


def check():
    for t in _TESTS:
        try:
            t()
        except Exception as e:  # noqa: BLE001
            ok(False, f"{t.__name__} raised {e!r}")
    return _P[0], _P[1], list(_LINES)


if __name__ == "__main__":
    passed, failed, lines = check()
    print("\n".join(lines))
    print(f"\n{'PASS' if not failed else 'FAIL'} — {passed} passed, {failed} failed")
    raise SystemExit(bool(failed))
