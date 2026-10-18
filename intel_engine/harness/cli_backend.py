"""cli_backend.py — run the harness phases on the Codex or OMP CLI (the host's own login).

WHY
  On a VPS the Anthropic SDK path needs a Claude Code login or an API key. Codex and OMP users
  already have a subscription session on the box. This backend drives that CLI headlessly:
  every phase is one `codex exec --json` / `omp -p --mode json` process whose ONLY tools are the
  harness's own, served over stdio by harness/mcp_server.py — the same typed, audit-gated tool
  surface every other front-end uses (audit.gate runs inside the server on every call).

ISOLATION (the security property; see the failure mode this was designed against)
  A stock Codex session with a refused MCP call routed around the refusal: it read the user's
  skills and shelled out to ANOTHER agent to make the call. So each phase runs in an isolated
  home (CODEX_HOME / OMP profile dir under cases/<case>/harness_home/): no user skills, hooks,
  plugins or AGENTS.md; shell / exec / browser / web-search / multi-agent tools disabled; only
  the `intel` MCP server, with its tools pre-approved. The event stream is the judge, never the
  final text: a phase FAILS if any command/shell execution item appears, or if a tool call was
  refused by the host's approval layer (that means the gate was bypassed, not that the tool said
  no — a harness denial arrives as an isError tool RESULT, which the model is meant to read).

STRUCTURED OUTPUT
  Like openai_backend: the Assess phase gets an `emit_result` tool (served by the MCP server via
  HARNESS_EMIT_SCHEMA_FILE) and must call it; the server writes the payload to a file this backend
  reads back and validates against the required keys. Retries re-prompt in the same session.

SESSIONS
  `resume` maps to `codex exec resume <thread_id>` / `omp -p --resume <session_id>` so
  Correlate → Verify → Assess share one transcript, as on the SDK path.

CONFIG (env)
  HARNESS_BACKEND=codex|omp              the switch (backend_select exports it)
  HARNESS_CLI_MODEL_MAP                   JSON {tier: model-id} (e.g. {"haiku":"gpt-5-codex-mini"})
  HARNESS_CLI_TIMEOUT                     seconds per phase process (default 1800)
  HARNESS_CLI_BIN                         override the executable path
  INTEL_PY                                Python for the MCP server launcher (see harness/mcp-server)
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import audit  # noqa: E402 — the phase context the orchestrator bound (case/phase/hostile)
from openai_backend import (  # noqa: E402 — reuse the shim's SDK-shaped surface, one implementation
    AgentDefinition,
    AssistantMessage,
    ClaudeAgentOptions,
    HookMatcher,
    ResultMessage,
    SdkMcpServer,
    SdkMcpTool,
    TextBlock,
    ToolAnnotations,
    ToolUseBlock,
    _env_json,
    _missing_required,
    create_sdk_mcp_server,
    tool,
)

__all__ = ["AgentDefinition", "AssistantMessage", "ClaudeAgentOptions", "HookMatcher", "ResultMessage",
           "ToolAnnotations", "ToolUseBlock", "TextBlock", "SdkMcpServer", "SdkMcpTool",
           "create_sdk_mcp_server", "tool", "query", "PhaseRun", "parse_codex_events",
           "parse_omp_events", "judge_events", "codex_config", "omp_mcp_config", "build_command"]

BACKEND = (os.environ.get("HARNESS_BACKEND") or "codex").strip().lower()
PHASE_TIMEOUT = int(os.environ.get("HARNESS_CLI_TIMEOUT", "1800"))
STRUCT_RETRIES = int(os.environ.get("HARNESS_STRUCT_RETRIES", "3"))
EMIT_NAME = "emit_result"
SERVER_NAME = "intel"
MCP_LAUNCHER = os.path.join(HERE, "mcp-server")

# Tool-name normalisation: hosts prefix MCP tools differently (codex: server-qualified item
# fields; omp: `mcp__intel_<tool>`), the ledger/policy use the bare name.
_PREFIX_RE = re.compile(r"^(?:mcp__)?(?:%s)?[_:]*" % SERVER_NAME)


def _bare(name: str) -> str:
    n = (name or "").split("__")[-1]
    return _PREFIX_RE.sub("", n) if n.startswith(SERVER_NAME) else n


def _log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


# ---------------------------------------------------------------- host configs
def codex_config(*, mcp_launcher: str = MCP_LAUNCHER, timeout: int = PHASE_TIMEOUT,
                 env: Optional[dict] = None) -> str:
    """The whole config.toml for an isolated CODEX_HOME: MCP-only, no shell, tools pre-approved."""
    env_lines = "".join(f'{k} = "{v}"\n' for k, v in (env or {}).items())
    return (
        'approval_policy = "never"\n'
        'sandbox_mode = "read-only"\n'
        'web_search = "disabled"\n'
        "[features]\n"
        "shell_tool = false\nunified_exec = false\nmulti_agent = false\nbrowser_use = false\n"
        "computer_use = false\napps = false\nplugins = false\nimage_generation = false\n"
        "hooks = false\nskill_search = false\ntool_suggest = false\nview_image = false\n"
        "code_mode_host = true\n"
        f"[mcp_servers.{SERVER_NAME}]\n"
        f'command = "{mcp_launcher}"\n'
        f"tool_timeout_sec = {timeout}\nstartup_timeout_sec = 90\n"
        'default_tools_approval_mode = "approve"\n'
        + (f"[mcp_servers.{SERVER_NAME}.env]\n{env_lines}" if env_lines else "")
    )


def omp_mcp_config(*, mcp_launcher: str = MCP_LAUNCHER, timeout: int = PHASE_TIMEOUT,
                   env: Optional[dict] = None) -> dict:
    srv: dict = {"command": mcp_launcher, "timeout": timeout * 1000}
    if env:
        srv["env"] = dict(env)
    return {"mcpServers": {SERVER_NAME: srv}}


def _phase_home(case: Optional[str]) -> str:
    base = os.path.join(ROOT, "cases", case, "harness_home") if case else os.path.join(tempfile.gettempdir(), "intel-harness-home")
    os.makedirs(base, exist_ok=True)
    return base


def _session_link(base: str, backend: str, sid: str) -> str:
    return os.path.join(base, f"{backend}_bysession", sid)


def _prepare_home(backend: str, case: Optional[str], server_env: dict,
                  resume: Optional[str] = None) -> tuple[str, dict, str, Optional[str]]:
    """Write an ISOLATED host config for one phase; return (workdir, extra process env, slot,
    sessions_dir).

    A fresh phase gets its OWN new slot (a uuid dir under cases/<case>/harness_home/<backend>_runs/)
    holding config.toml / .omp/mcp.json, so concurrent phases (parallel cluster judges) never share
    a mutable config file and one phase's HARNESS_EMIT_OUT_FILE / HARNESS_PHASE / INTEL_CASE can
    never land in another's. A RESUMED phase (Correlate -> Verify -> Assess of one cluster) reuses
    the slot that created its session — the host CLIs bind a session to the directory it was started
    in (omp refuses to resume a session whose directory is gone) — and rewrites that slot's config
    for the new phase. That is race-free because one chain's phases run strictly in sequence; other
    chains resume their own slots. `record_session_slot` links a session id to its slot after the
    first call; `sessions_dir` (one per case+backend) is the transcript store omp is pointed at with
    --session-dir and codex reads through a `sessions` symlink in each CODEX_HOME."""
    base = _phase_home(case)
    sessions = os.path.join(base, f"{backend}_sessions")
    os.makedirs(sessions, exist_ok=True)
    slot = ""
    if resume:
        link = _session_link(base, backend, resume)
        if os.path.isdir(link):
            slot = os.path.realpath(link)
    if not slot:
        slot = os.path.join(base, f"{backend}_runs", uuid.uuid4().hex)
        os.makedirs(slot, exist_ok=True)
    if backend == "codex":
        with open(os.path.join(slot, "config.toml"), "w", encoding="utf-8") as f:
            f.write(codex_config(env=server_env))
        auth_src = os.path.join(os.environ.get("CODEX_HOME") or os.path.expanduser("~/.codex"), "auth.json")
        for src, name in ((auth_src, "auth.json"), (sessions, "sessions")):
            dst = os.path.join(slot, name)
            if os.path.exists(src) and not os.path.lexists(dst):
                try:
                    os.symlink(src, dst)  # reuse the login / shared transcript store, never copy
                except OSError:
                    pass
        work = os.path.join(slot, "work")
        os.makedirs(work, exist_ok=True)
        return work, {"CODEX_HOME": slot}, slot, None
    if backend == "omp":
        os.makedirs(os.path.join(slot, ".omp"), exist_ok=True)
        with open(os.path.join(slot, ".omp", "mcp.json"), "w", encoding="utf-8") as f:
            json.dump(omp_mcp_config(env=server_env), f, indent=1)
        return slot, {"OMP_MCP_TIMEOUT_MS": str(PHASE_TIMEOUT * 1000), "OMP_MCP_REQUIRE_READY": "1"}, slot, sessions
    raise SystemExit(f"cli_backend: unsupported backend {backend!r}")


def record_session_slot(backend: str, case: Optional[str], sid: str, slot: str) -> None:
    """Link `sid` to the slot it was created in, so a later resume of that session starts in the
    same directory. Per-session symlink = atomic, no shared map file for concurrent phases to race."""
    if not sid or not slot:
        return
    link = _session_link(_phase_home(case), backend, sid)
    os.makedirs(os.path.dirname(link), exist_ok=True)
    try:
        os.symlink(slot, link)
    except OSError:
        pass


def build_command(backend: str, *, model: Optional[str], resume: Optional[str],
                  session_dir: Optional[str] = None) -> list:
    """The host CLI invocation. The prompt is NOT an argument — it is piped on stdin (a phase's
    system prompt is a whole skill file; Linux caps one argv element at 128 KiB)."""
    exe = os.environ.get("HARNESS_CLI_BIN") or shutil.which(backend) or backend
    if backend == "codex":
        cmd = [exe, "exec", "--json", "--skip-git-repo-check"]
        if model:
            cmd += ["-m", model]
        if resume:
            cmd += ["resume", resume]
        return cmd + ["-"]
    if backend == "omp":
        cmd = [exe, "-p", "--mode", "json", "--no-tools", "--no-skills", "--no-rules",
               "--no-extensions", "--no-title", "--approval-mode", "yolo"]
        if session_dir:
            cmd += ["--session-dir", session_dir]
        if model:
            cmd += ["--model", model]
        if resume:
            cmd += ["--resume", resume]
        return cmd
    raise SystemExit(f"cli_backend: unsupported backend {backend!r}")


# ---------------------------------------------------------------- event parsing
@dataclass
class PhaseRun:
    session_id: str = ""
    tool_calls: list = field(default_factory=list)      # [(name, args)]
    refused: list = field(default_factory=list)         # host-level refusals (gate bypass risk)
    executions: list = field(default_factory=list)      # shell/command items — must be empty
    final_text: str = ""
    usage: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)


def _events(stream: str):
    for line in stream.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            yield json.loads(line)
        except ValueError:
            continue


def parse_codex_events(stream: str) -> PhaseRun:
    run = PhaseRun()
    for e in _events(stream):
        t = e.get("type")
        if t == "thread.started":
            run.session_id = e.get("thread_id") or ""
        elif t == "turn.completed":
            run.usage = e.get("usage") or {}
        elif t == "turn.failed":
            run.errors.append(str((e.get("error") or {}).get("message") or e))
        elif t == "item.completed":
            item = e.get("item") or {}
            it = item.get("type")
            if it == "mcp_tool_call":
                if (item.get("server") or SERVER_NAME) != SERVER_NAME:
                    run.executions.append(f"mcp:{item.get('server')}/{item.get('tool')}")
                    continue
                run.tool_calls.append((_bare(item.get("tool") or ""), item.get("arguments") or {}))
                err = item.get("error") or {}
                if item.get("status") == "failed" and "approval" in str(err.get("message", "")).lower():
                    run.refused.append(item.get("tool") or "")
            elif it in ("command_execution", "local_shell_call", "shell_call", "web_search",
                        "file_change", "collab_tool_call"):
                run.executions.append(item.get("command") or it)
            elif it == "agent_message":
                run.final_text = item.get("text") or run.final_text
            elif it == "error":
                msg = str(item.get("message") or "")
                if "skills context budget" not in msg.lower():
                    run.errors.append(msg)
    return run


def parse_omp_events(stream: str) -> PhaseRun:
    run = PhaseRun()
    for e in _events(stream):
        t = e.get("type")
        if t == "session":
            run.session_id = e.get("id") or ""
        elif t == "tool_execution_start":
            name = e.get("toolName") or ""
            if name.startswith(f"mcp__{SERVER_NAME}_"):
                run.tool_calls.append((_bare(name), e.get("args") or {}))
            else:                       # built-ins that survive --no-tools, or ANOTHER MCP server
                run.executions.append(name)
        elif t == "tool_execution_end":
            res = e.get("result") or {}
            txt = " ".join(b.get("text", "") for b in (res.get("content") or []) if isinstance(b, dict))
            if "requires approval" in txt.lower() or "approval denied" in txt.lower():
                run.refused.append(e.get("toolName") or "")
        elif t in ("message_end", "turn_end"):
            m = e.get("message") or {}
            if m.get("role") == "assistant":
                for b in m.get("content") or []:
                    if isinstance(b, dict) and b.get("type") == "text" and b.get("text"):
                        run.final_text = b["text"]
                u = m.get("usage")
                if isinstance(u, dict):
                    run.usage = u
        elif t == "error":
            run.errors.append(str(e.get("message") or e))
    return run


def judge_events(run: PhaseRun) -> Optional[str]:
    """None when the phase is acceptable; else the reason it must be treated as failed."""
    if run.executions:
        return ("host executed non-MCP tools (shell/command/web) — the isolation contract is broken: "
                + ", ".join(str(x)[:80] for x in run.executions[:3]))
    if run.refused:
        return "host approval layer refused MCP tool(s) (gate bypassed): " + ", ".join(run.refused[:3])
    if run.errors:
        return "; ".join(run.errors[:3])
    return None


# ---------------------------------------------------------------- the phase runner
def _model_for(tier: Optional[str]) -> Optional[str]:
    table = _env_json("HARNESS_CLI_MODEL_MAP")
    return table.get(tier or "") or None       # unmapped tier → the host's default model


def _emit_file(case: Optional[str]) -> str:
    return os.path.join(_phase_home(case), f"emit_{uuid.uuid4().hex}.json")


_SECRET_HINTS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "PROXY", "PROXIES", "AUTH", "COOKIE", "CREDENTIAL")


def _looks_secret(name: str) -> bool:
    """A conservative name test for values that must never be written into a host config file."""
    n = name.upper()
    return any(h in n for h in _SECRET_HINTS)


_HOST_MARKERS = ("CLAUDECODE", "OMPCODE", "CODEX_", "CLAUDE_CODE", "OMP_", "PI_")


def _child_env(extra: dict) -> dict:
    """The phase process env: the caller's, minus host-agent markers (a nested run must not think
    it is inside Codex/OMP/Claude Code and inherit their session/config), plus `extra`."""
    env = {k: v for k, v in os.environ.items()
           if not any(k == m or k.startswith(m) for m in _HOST_MARKERS)}
    env.update(extra)
    return env


async def _run_phase(cmd: list, *, cwd: str, env: dict, timeout: int,
                     stdin_text: Optional[str] = None) -> tuple[int, str, str]:
    def _go():
        p = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout,
                           input=stdin_text if stdin_text is not None else "",
                           **({} if stdin_text is not None else {"stdin": subprocess.DEVNULL}))
        return p.returncode, p.stdout or "", p.stderr or ""
    try:
        return await asyncio.to_thread(_go)
    except subprocess.TimeoutExpired as e:
        return 124, (e.stdout or "") if isinstance(e.stdout, str) else "", f"phase timed out after {timeout}s"


def _phase_context() -> tuple[Optional[str], str, bool]:
    """(case, phase, hostile) as the orchestrator bound them via audit.set_context — the SDK path
    closes over these in its PreToolUse hook; here they must travel to the server process."""
    try:
        ctx = audit._CTX.get() or {}
    except Exception:  # noqa: BLE001
        ctx = {}
    hostile = ctx.get("hostile")
    if hostile is None:
        hostile = os.environ.get("HARNESS_HOSTILE", "").strip().lower() in ("1", "true", "yes", "on")
    return ctx.get("case") or os.environ.get("INTEL_CASE") or None, str(ctx.get("phase") or "interactive"), bool(hostile)


async def query(*, prompt: str, options: ClaudeAgentOptions):
    """Async generator mirroring claude_agent_sdk.query on top of a host CLI process."""
    backend = BACKEND
    case, phase, hostile = _phase_context()
    want_struct = bool(options.output_format)
    schema = (options.output_format or {}).get("schema") or {} if want_struct else {}
    allowed = sorted({_bare(t) for t in (options.allowed_tools or [])})

    # The server process is the harness for this phase: the HARNESS_* / INTEL_* knobs the operator
    # set (HARNESS_KB scratch KB, HARNESS_NO_ENRICH no-credit smoke, HARNESS_FORCE, …) must reach
    # it, or a "no-spend smoke" spends. Phase-specific values are layered on top and win. NEVER a
    # secret: this dict is written in clear into the host's config file under the case dir, so
    # proxy URLs (CTI_PROXY/CTI_PROXIES carry user:pass@host), API keys and tokens stay out — the
    # collectors re-load keys and the proxy pool from the repo .env themselves. CTI_API_KEYS_ENV
    # (a PATH to that file) is the one CTI_* value forwarded.
    server_env = {k: v for k, v in os.environ.items()
                  if k.startswith(("HARNESS_", "INTEL_")) and k != "HARNESS_BACKEND"
                  and not _looks_secret(k)}
    if os.environ.get("CTI_API_KEYS_ENV"):
        server_env["CTI_API_KEYS_ENV"] = os.environ["CTI_API_KEYS_ENV"]
    server_env.update({
        "HARNESS_ALLOWED_TOOLS": ",".join(allowed),
        "HARNESS_HOSTILE": "1" if hostile else "",
        "HARNESS_PHASE": phase,
        "HARNESS_BACKEND": backend,
    })
    if case:
        server_env["INTEL_CASE"] = case
    emit_path = ""
    if want_struct:
        emit_path = _emit_file(case)
        with open(emit_path + "schema.json", "w", encoding="utf-8") as f:
            json.dump(schema, f)
        server_env["HARNESS_EMIT_SCHEMA_FILE"] = emit_path + "schema.json"
        server_env["HARNESS_EMIT_OUT_FILE"] = emit_path

    cwd, extra_env, slot, sessions_dir = _prepare_home(backend, case, server_env, resume=options.resume)
    env = _child_env(extra_env)
    session_dir = sessions_dir if backend == "omp" else None

    system = options.system_prompt or ""
    user = prompt
    if want_struct:
        user += ("\n\nWhen finished, call the `emit_result` tool exactly once with the final structured "
                 "result; it is the only accepted way to finish.")
    full_prompt = (f"<system>\n{system}\n</system>\n\n{user}" if system and not options.resume else user)
    full_prompt += ("\n\nRULES: use only the provided `intel` MCP tools; you have no shell, files or web "
                    "browsing, and must not try to obtain them.")

    model = _model_for(options.model)
    structured: Optional[dict] = None
    sid = options.resume or ""
    final_text = ""
    failure: Optional[str] = None
    usage: dict = {}
    tries = 0
    prompt_now = full_prompt
    while True:
        cmd = build_command(backend, model=model, resume=sid or None, session_dir=session_dir)
        rc, out, err = await _run_phase(cmd, cwd=cwd, env=env, timeout=PHASE_TIMEOUT, stdin_text=prompt_now)
        run = parse_codex_events(out) if backend == "codex" else parse_omp_events(out)
        sid = run.session_id or sid
        usage = run.usage or usage
        for name, args in run.tool_calls:
            yield AssistantMessage(content=[ToolUseBlock(name=name, input=args, id="")])
        failure = judge_events(run)
        if failure is None and rc != 0 and not run.tool_calls and not run.final_text:
            failure = f"{backend} exited {rc}: {(err or out).strip()[-300:]}"
        if failure is None and rc != 0 and "authenticat" in (err + out).lower():
            failure = f"{backend} auth failure: {(err or out).strip()[-200:]}"
        final_text = run.final_text or final_text
        if failure or not want_struct:
            break
        if os.path.exists(emit_path):
            try:
                structured = json.load(open(emit_path, encoding="utf-8"))
            except ValueError:
                structured = None
        if structured is not None and not _missing_required(schema, structured):
            break
        tries += 1
        if tries > STRUCT_RETRIES or not sid:
            break
        missing = _missing_required(schema, structured) if structured else ["<no emit_result call>"]
        prompt_now = ("Call the `emit_result` tool now with the COMPLETE final result matching the "
                      f"required schema. Missing: {', '.join(missing)}.")

    if failure:
        subtype = "error"
        final_text = failure        # the REASON, not the model's last message (that hid "out of credits")
        _log(f"    ✗ phase failed: {failure}")
    elif want_struct:
        subtype = "success" if structured is not None else "error"
    else:
        subtype = "success"
    if emit_path:
        for p in (emit_path, emit_path + "schema.json"):
            try:
                os.remove(p)
            except OSError:
                pass
    if sid:
        record_session_slot(backend, case, sid, slot)   # keep the slot: a later phase resumes here
    else:
        shutil.rmtree(slot, ignore_errors=True)         # no session to resume — config dir is spent
    yield ResultMessage(subtype=subtype, session_id=sid, total_cost_usd=None,
                        structured_output=structured, result=final_text)
