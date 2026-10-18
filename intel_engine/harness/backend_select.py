"""backend_select.py — pick the agent backend the harness runs its LLM phases on (stdlib only).

WHY
  The harness used to assume the Anthropic Agent SDK + a logged-in Claude Code CLI. On a VPS that
  is often false (no login, an expired OAuth session, root), and inside Codex or OMP the natural
  model is the host's own subscription. An unusable backend then surfaced as "every phase ✓ at
  $0.00, no assessment produced". This module decides ONCE, before sdk_compat is imported, and
  says why.

  HARNESS_BACKEND=claude|codex|omp|openai|deepseek|kimi|local   explicit — honoured as-is
  HARNESS_BACKEND unset / auto                                  resolve() below

  auto order: the host agent this process runs inside (CODEX_THREAD_ID → codex, OMPCODE → omp,
  CLAUDECODE → claude; inner host first because the markers are inherited), then claude, codex,
  omp, then an OpenAI-compatible key. Each candidate must pass `available()` (binary/module/key
  present, no model call) and `probe()` (auth actually works). Probes are cheap and cached in the
  environment (HARNESS_BACKEND is exported), so child processes never re-probe.

ROOT
  Claude Code refuses --dangerously-skip-permissions (the SDK's bypassPermissions) as euid 0 unless
  IS_SANDBOX=1. The harness never relies on that flag for safety — every tool call passes the
  PreToolUse gate (audit.gate) — so for euid 0 we set IS_SANDBOX=1 for the spawned CLI and say so.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

CLI_BACKENDS = ("codex", "omp")
OPENAI_BACKENDS = ("openai", "deepseek", "kimi", "moonshot", "local", "ollama", "vllm", "lmstudio")
KNOWN = ("claude",) + CLI_BACKENDS + OPENAI_BACKENDS
PROBE_TIMEOUT = int(os.environ.get("HARNESS_PROBE_TIMEOUT", "90"))


def _log(msg: str) -> None:
    print(f"[backend] {msg}", file=sys.stderr, flush=True)


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def ensure_root_sandbox_env() -> bool:
    """Set IS_SANDBOX=1 for euid 0 so the Claude CLI accepts bypassPermissions. Returns True when
    it set the variable (callers log it once)."""
    if is_root() and not os.environ.get("IS_SANDBOX"):
        os.environ["IS_SANDBOX"] = "1"
        return True
    return False


def host_agent(env=None) -> str | None:
    env = os.environ if env is None else env
    if env.get("CODEX_THREAD_ID") or env.get("CODEX_SESSION_ID"):
        return "codex"
    if env.get("OMPCODE"):
        return "omp"
    if env.get("CLAUDECODE"):
        return "claude"
    return None


def _openai_key(env=None) -> str:
    env = os.environ if env is None else env
    return env.get("OPENAI_API_KEY") or env.get("DEEPSEEK_API_KEY") or env.get("MOONSHOT_API_KEY") or ""


def available(name: str) -> tuple[bool, str]:
    """Cheap presence check — no model call."""
    if name == "claude":
        if importlib.util.find_spec("claude_agent_sdk") is None:
            return False, "claude_agent_sdk not installed in this Python"
        if os.environ.get("ANTHROPIC_API_KEY"):
            return True, "ANTHROPIC_API_KEY set"
        if shutil.which("claude"):
            return True, "claude CLI on PATH (subscription login)"
        return False, "no ANTHROPIC_API_KEY and no claude CLI"
    if name in CLI_BACKENDS:
        exe = shutil.which(name)
        return (True, f"{name} CLI at {exe}") if exe else (False, f"{name} CLI not on PATH")
    if name in OPENAI_BACKENDS:
        if name in ("local", "ollama", "vllm", "lmstudio"):
            return (bool(os.environ.get("OPENAI_BASE_URL")),
                    "OPENAI_BASE_URL set" if os.environ.get("OPENAI_BASE_URL") else "OPENAI_BASE_URL unset")
        return (True, "API key set") if _openai_key() else (False, "no OPENAI/DEEPSEEK/MOONSHOT key")
    return False, f"unknown backend {name!r}"


# Model-provider hosts reach the model DIRECTLY, never through the research proxy pool — see
# references/model_hosts.json. Fallback = the conservative core set (Anthropic + OpenAI).
_MODEL_HOSTS_FALLBACK = ["api.anthropic.com", ".anthropic.com", "claude.ai", ".claude.ai",
                         "api.openai.com", ".openai.com", "chatgpt.com", ".chatgpt.com"]


def _model_hosts() -> list:
    try:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "references",
                               "model_hosts.json"), encoding="utf-8") as f:
            hosts = json.load(f).get("no_proxy_hosts") or []
        return [h for h in hosts if isinstance(h, str) and h] or list(_MODEL_HOSTS_FALLBACK)
    except (OSError, ValueError):
        print("[backend] WARNING: references/model_hosts.json unreadable — using the core host list",
              file=sys.stderr)
        return list(_MODEL_HOSTS_FALLBACK)


MODEL_HOSTS = _model_hosts()


def bypass_proxy_for_models(env: dict) -> dict:
    """Append MODEL_HOSTS to NO_PROXY/no_proxy in `env` (in place; returned for chaining). Any
    HTTPS_PROXY the dispatcher exported for collectors stays set — only model hosts go direct."""
    for var in ("NO_PROXY", "no_proxy"):
        cur = [h.strip() for h in (env.get(var) or "").split(",") if h.strip()]
        env[var] = ",".join(cur + [h for h in MODEL_HOSTS if h not in cur])
    return env


def _run(cmd: list, *, env=None, timeout=PROBE_TIMEOUT, stdin_text: str | None = None) -> tuple[int, str]:
    try:
        # stdin is ALWAYS closed or fed: `claude -p` / `codex exec` wait on an inherited open pipe
        # (cron, CI, a backgrounded shell) until the timeout.
        env = bypass_proxy_for_models(dict(env if env is not None else os.environ))
        p = subprocess.run(cmd, input=stdin_text if stdin_text is not None else "", capture_output=True,
                           text=True, timeout=timeout, env=env, cwd=os.path.expanduser("~"))
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, f"probe timed out after {timeout}s"
    except OSError as e:
        return 127, str(e)


# --------------------------------------------------------------- failure classification
# A phase that dies on one of these is the BACKEND's problem (login, plan credits, provider rate
# limit), not the case's — so the run can resume on another backend with nothing lost. Anything
# else (a tool fault, a schema miss) is a real failure and must not trigger a backend switch.
_FAILURE_KINDS = (
    ("auth", re.compile(r"authenticat|oauth|not logged in|log ?in required|unauthori[sz]ed|\b401\b|"
                        r"invalid api key|api key (?:is )?(?:missing|invalid)|session expired", re.I)),
    ("quota", re.compile(r"out of credits|insufficient (?:credit|balance|quota|funds)|credit balance|"
                         r"quota|usage limit|billing|\b402\b|payment required|plan limit|add credits", re.I)),
    ("rate", re.compile(r"rate.?limit|\b429\b|too many requests|overloaded", re.I)),
)

# Exit code the orchestrator uses for "the backend became unusable mid-run" (EX_TEMPFAIL): the case
# is intact and resumable, so harness/cli.py may offer the next backend.
FAILOVER_EXIT = 75


class BackendUnavailable(RuntimeError):
    """The LLM backend itself stopped answering (auth / credits / rate limit)."""

    def __init__(self, backend: str, reason: str, kind: str = "unavailable"):
        super().__init__(f"{backend} unavailable ({kind}): {reason}")
        self.backend, self.reason, self.kind = backend, reason, kind


def classify_failure(text: str) -> str | None:
    """'auth' | 'quota' | 'rate' when `text` is a backend-level failure, else None."""
    for kind, rx in _FAILURE_KINDS:
        if rx.search(text or ""):
            return kind
    return None


def write_failover(path: str | None, backend: str, reason: str, kind: str) -> None:
    """Hand the failure to the parent (harness/cli.py) — a file, so the live log stays on the tty."""
    if not path:
        return
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"backend": backend, "reason": reason, "kind": kind}, f)
    except OSError:
        pass


def read_failover(path: str | None) -> dict:
    try:
        with open(path or "", encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _said_ok(text: str) -> bool:
    """The probe answer is exactly OK (a substring test would accept 'token' or 'look')."""
    lines = [ln.strip().strip(".!`*\"'").lower() for ln in (text or "").splitlines() if ln.strip()]
    return "ok" in lines          # a whole line, anywhere: CLIs print progress ("Working...") around it


def _codex_probe_home() -> str:
    """A throwaway CODEX_HOME for the probe: the user's login, none of their skills/MCP/hooks, no
    shell — so the probe is one small model turn, not a full agent session."""
    home = tempfile.mkdtemp(prefix="intel-codex-probe-")
    with open(os.path.join(home, "config.toml"), "w", encoding="utf-8") as f:
        f.write('approval_policy = "never"\nsandbox_mode = "read-only"\nweb_search = "disabled"\n'
                "[features]\nshell_tool = false\nunified_exec = false\nmulti_agent = false\n"
                "plugins = false\napps = false\nhooks = false\nbrowser_use = false\n")
    src = os.path.join(os.environ.get("CODEX_HOME") or os.path.expanduser("~/.codex"), "auth.json")
    if os.path.exists(src):
        os.symlink(src, os.path.join(home, "auth.json"))
    return home


def probe(name: str) -> tuple[bool, str]:
    """Does this backend actually ANSWER right now? One tiny real request per CLI — a login-status
    call is not enough: a logged-in account with no credits left passes it and dies mid-run."""
    if name == "claude":
        if os.environ.get("ANTHROPIC_API_KEY"):
            return True, "ANTHROPIC_API_KEY set (not probed)"
        env = dict(os.environ)
        if is_root():
            env.setdefault("IS_SANDBOX", "1")
        rc, out = _run(["claude", "-p", "Reply with exactly: OK", "--max-turns", "1",
                        "--output-format", "json"], env=env)
        try:
            data = json.loads(out.strip().splitlines()[-1]) if out.strip() else {}
        except (ValueError, IndexError):
            data = {}
        if rc == 0 and data and not data.get("is_error") and _said_ok(str(data.get("result") or "")):
            return True, "claude CLI answered"
        reason = (data.get("result") if isinstance(data, dict) else "") or out.strip()[-300:]
        return False, f"claude CLI unusable: {reason or f'exit {rc}'}"
    if name == "codex":
        rc, out = _run(["codex", "login", "status"], timeout=30)
        if rc != 0 or "not logged in" in out.lower():
            return False, f"codex not logged in ({out.strip()[-200:] or f'exit {rc}'})"
        home = _codex_probe_home()
        try:
            rc, out = _run(["codex", "exec", "--json", "--skip-git-repo-check", "-"],
                           env={**os.environ, "CODEX_HOME": home}, stdin_text="Reply with exactly: OK")
        finally:
            shutil.rmtree(home, ignore_errors=True)
        text, errs = "", []
        for line in out.splitlines():
            try:
                e = json.loads(line)
            except ValueError:
                continue
            item = e.get("item") or {}
            if e.get("type") == "turn.failed":
                errs.append(str((e.get("error") or {}).get("message") or e))
            elif item.get("type") == "agent_message":
                text = item.get("text") or text
            elif item.get("type") == "error" and "skills context budget" not in str(item.get("message", "")).lower():
                errs.append(str(item.get("message") or ""))
        if _said_ok(text) and not errs:
            return True, "codex answered"
        return False, f"codex unusable: {('; '.join(errs) or out.strip()[-200:] or f'exit {rc}')[:300]}"
    if name == "omp":
        rc, out = _run(["omp", "-p", "--no-tools", "--no-session", "--no-skills", "--no-rules",
                        "--no-extensions", "--no-title", "Reply with exactly: OK"])
        if rc == 0 and _said_ok(out):
            return True, "omp answered"
        return False, f"omp unusable: {out.strip()[-300:] or f'exit {rc}'}"
    if name in OPENAI_BACKENDS:
        return available(name)
    return False, f"unknown backend {name!r}"


def candidates(env=None) -> list:
    host = host_agent(env)
    order = ([host] if host else []) + ["claude", "codex", "omp", "openai"]
    seen, out = set(), []
    for n in order:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


# ------------------------------------------------------------ cheap checks + probe cache
# A per-run check must cost nothing: `harness open` runs often, and a real "reply OK" request is a
# whole agent turn (Codex: ~45k input tokens even in an isolated home). So a run uses each CLI's
# free login-PRESENCE command, which does not prove the login works (an expired session whose
# refresh fails may still read as logged in). The real request lives in `harness doctor`, whose
# result is cached so the next runs reuse it. Whatever the cheap check misses — a dead refresh,
# credits gone before or during the round — fails the first affected phase in seconds and becomes a
# failover (classify_failure → FAILOVER_EXIT → harness/cli.py).
PROBE_CACHE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "MEMORY", "backend_probe.json")          # engine MEMORY/ — gitignored
PASS_TTL = int(os.environ.get("HARNESS_PROBE_PASS_TTL") or 1800)   # a doctor "answered" is trusted 30 min
FAIL_TTL = int(os.environ.get("HARNESS_PROBE_FAIL_TTL") or 600)    # a failure is skipped for 10 min


def _cache_load() -> dict:
    try:
        with open(PROBE_CACHE, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _cache_put(name: str, ok: bool, why: str) -> None:
    d = _cache_load()
    d[name] = {"ok": bool(ok), "why": str(why)[:300], "ts": time.time()}
    try:
        os.makedirs(os.path.dirname(PROBE_CACHE), exist_ok=True)
        with open(PROBE_CACHE, "w", encoding="utf-8") as f:
            json.dump(d, f, indent=1)
    except OSError:
        pass


def _cache_get(name: str):
    e = _cache_load().get(name)
    if not isinstance(e, dict):
        return None
    age = time.time() - float(e.get("ts") or 0)
    if age < (PASS_TTL if e.get("ok") else FAIL_TTL):
        return bool(e.get("ok")), f"{e.get('why')} (checked {int(age // 60)} min ago)"
    return None


def mark_failed(name: str, why: str) -> None:
    """A backend that died mid-run is skipped by the next resolve (failover, next run) for FAIL_TTL."""
    _cache_put(name, False, f"failed mid-run: {why}")


def quick_check(name: str) -> tuple[bool, str]:
    """Free login-PRESENCE checks — no model request, no tokens. NOT a verification: it reads the
    stored login, so an expired OAuth session whose refresh will fail (the Claude case we hit) or an
    account with no credits can still pass. That is acceptable only because such a backend fails the
    FIRST phase within seconds, which classify_failure turns into a failover. `doctor` (deep=True)
    is the real check."""
    if name == "claude":
        if os.environ.get("ANTHROPIC_API_KEY"):
            return True, "ANTHROPIC_API_KEY set"
        rc, out = _run(["claude", "auth", "status"], timeout=30)
        try:
            data = json.loads(out[out.index("{"):]) if "{" in out else {}
        except ValueError:
            data = {}
        if rc == 0 and data.get("loggedIn"):
            return True, (f"claude has a stored login ({data.get('authMethod') or 'unknown method'}) "
                          f"— not verified; `harness doctor` tests it")
        return False, f"claude not logged in ({out.strip()[-160:] or f'exit {rc}'})"
    if name == "codex":
        rc, out = _run(["codex", "login", "status"], timeout=30)
        if rc == 0 and "not logged in" not in out.lower():
            return True, (f"codex has a stored login ({out.strip().splitlines()[-1][:60] if out.strip() else '?'}) "
                          f"— not verified; `harness doctor` tests it")
        return False, f"codex not logged in ({out.strip()[-160:] or f'exit {rc}'})"
    # omp has no status command; an unusable login fails the first phase in seconds → failover.
    return available(name)


def check(name: str, *, deep: bool = False) -> tuple[bool, str]:
    """deep=True (doctor): one real request, cached. deep=False (every run): a fresh cached result
    if there is one, else the free login-status check."""
    ok, why = available(name)
    if not ok:
        return ok, why
    if deep:
        ok, why = probe(name)
        if not ok and "timed out" in why:
            # A timeout says the PROBE did not finish (slow exit, network blip), not that the backend
            # failed — never cache it, or the next runs skip a backend that works.
            return False, f"{name} probe timed out — not cached; re-run `harness doctor` to retry"
        _cache_put(name, ok, why)
        return ok, why
    cached = _cache_get(name)
    return cached if cached is not None else quick_check(name)


def resolve(*, do_probe: bool = True, exclude=(), deep: bool = False) -> tuple[str, str, list]:
    """(backend, why, tried). Raises SystemExit with every candidate's reason when none works.
    `exclude` skips backends that already failed this run (failover); it also ignores a pinned
    HARNESS_BACKEND, since the pinned one is the backend that just failed. `deep` sends each
    candidate one real request (doctor); the default is the free per-run check."""
    explicit = (os.environ.get("HARNESS_BACKEND") or "").strip().lower()
    if explicit and explicit != "auto" and not exclude:
        if explicit not in KNOWN:
            raise SystemExit(f"HARNESS_BACKEND={explicit!r} is not one of {', '.join(KNOWN)} or auto")
        return explicit, "HARNESS_BACKEND set explicitly", []
    skip = {e.lower() for e in exclude}
    tried = []
    for name in candidates():
        if name in skip:
            continue
        ok, why = check(name, deep=deep) if do_probe else available(name)
        tried.append((name, ok, why))
        if ok:
            return name, why, tried
    lines = "\n".join(f"  - {n}: {w}" for n, _ok, w in tried)
    raise SystemExit(
        "no usable LLM backend for the harness:\n" + lines + "\n"
        "Fix one of: `claude /login` (or export ANTHROPIC_API_KEY) · `codex login` · configure omp "
        "(`omp` → /login) · export OPENAI_API_KEY/DEEPSEEK_API_KEY (+ OPENAI_BASE_URL). "
        "Or pin one with HARNESS_BACKEND=<name>.")


def ensure_env() -> str:
    """Resolve once and export HARNESS_BACKEND so sdk_compat (and every child process) agree."""
    # Model traffic direct, collector traffic still on the research pool: every model CLI this run
    # spawns (the SDK's claude, codex/omp phases) inherits this process env.
    bypass_proxy_for_models(os.environ)
    name, why, tried = resolve()
    for n, ok, w in tried:
        if not ok:
            _log(f"skip {n}: {w}")
    os.environ["HARNESS_BACKEND"] = name
    if name == "claude" and ensure_root_sandbox_env():
        _log("running as root: set IS_SANDBOX=1 so the Claude CLI accepts headless permissions "
             "(every tool call is still gated by audit.gate)")
    _log(f"using {name} — {why}")
    return name
