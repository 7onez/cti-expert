#!/usr/bin/env python3
"""
wp_timeouts.py — the ONE resolver for the per-call timeout CEILING (`CTI_CALL_TIMEOUT`), the
per-phase BUDGET (`HARNESS_PHASE_TIMEOUT` / `HARNESS_CLI_TIMEOUT`) and the PHASE-DEADLINE clamp.

POLICY
------
Every data-fetching / API / collector / renderer / subprocess "task call" in the engine runs up
to CALL_TIMEOUT seconds (default 18000 = 5 h), then times out and the run moves on. Shorter
per-call values written at a call site are FLOORED to the ceiling via `floor()`; only raw DNS /
TLS / JARM micro-probes (getaddrinfo, dig, nslookup, ping, handshake) keep their fail-fast bounds.

A call never outlives its harness phase: while a phase is active its deadline (epoch seconds) is
bound — in-process through `set_phase_deadline()` (a ContextVar, so concurrent phases never see
each other's), across processes through the HARNESS_PHASE_DEADLINE env var — and `floor()` /
`clamp()` cap every bound at `deadline - now - phase_deadline_margin` (minimum 1 s).

RESOLUTION ORDER (first hit wins) — the same for the ceiling and the phase budget
---------------------------------------------------------------------------------
  1. process env  <KEY>                     — an exported variable always wins
  2. .env files   <KEY>=<secs>              — the skill-root .env (the /apikeys store), then
                                              intel_engine/.env; the analyst's editable knob
  3. reference data                          — references/timeouts.json (RULE 3)
  4. embedded fallback                       — 18000

The resolved ceiling is EXPORTED back into os.environ so every child process this one spawns
inherits it without re-reading .env. Non-positive or garbage values fall through to the next
source. A running process keeps the value it started with — restart to apply a .env change.

Stdlib only. Importable standalone from any component (`sys.path.insert(0, <this dir>)`).
"""
from __future__ import annotations

import contextvars
import functools
import os
import time

__all__ = ["CALL_TIMEOUT", "ENV_KEY", "DEFAULT_CALL_TIMEOUT", "resolve_call_timeout", "floor",
           "PHASE_ENV_KEYS", "DEADLINE_ENV", "DEFAULT_PHASE_TIMEOUT", "DEFAULT_PHASE_MARGIN",
           "resolve_phase_timeout", "phase_margin", "set_phase_deadline", "reset_phase_deadline",
           "phase_deadline", "remaining", "clamp"]

ENV_KEY = "CTI_CALL_TIMEOUT"
DEFAULT_CALL_TIMEOUT = 18000
# Phase budget: the orchestrator reads HARNESS_PHASE_TIMEOUT first, the CLI backend
# HARNESS_CLI_TIMEOUT first; each falls back to the other so one setting governs both.
PHASE_ENV_KEYS = ("HARNESS_PHASE_TIMEOUT", "HARNESS_CLI_TIMEOUT")
DEFAULT_PHASE_TIMEOUT = 18000
DEFAULT_PHASE_MARGIN = 120
DEADLINE_ENV = "HARNESS_PHASE_DEADLINE"

_HERE = os.path.dirname(os.path.abspath(__file__))                       # WebPivot/tools
_ENGINE = os.path.dirname(os.path.dirname(_HERE))                        # intel_engine/
_SKILL = os.path.dirname(_ENGINE)                                        # cti-expert skill root
# Highest priority first: the skill-root .env is where /apikeys writes and where analysts edit.
DEFAULT_ENV_FILES = (
    os.environ.get("CTI_API_KEYS_ENV") or os.path.join(_SKILL, ".env"),
    os.path.join(_ENGINE, ".env"),
)


def _positive(v) -> int | None:
    """int(v) when it is a positive number, else None (garbage/blank/non-positive fall through)."""
    try:
        n = int(str(v).strip())
    except (TypeError, ValueError):
        return None
    return n if n > 0 else None


def _read_env_key(path: str, key: str) -> str | None:
    """Value of `key` from a KEY=VALUE .env file (comments/blanks ignored), or None."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith("#") or "=" not in s:
                    continue
                k, v = s.split("=", 1)
                if k.strip() == key:
                    return v.strip().strip('"').strip("'")
    except OSError:
        return None
    return None


def _reference_value(group: str, default: int) -> int | None:
    """`<group>.value` from references/timeouts.json via the RULE 3 loader (None when unavailable)."""
    try:
        import sys
        if _HERE not in sys.path:
            sys.path.insert(0, _HERE)
        from wp_refs import load_ref, ref_path  # noqa: E402
        ref = load_ref(ref_path(__file__, "timeouts.json"), {group: {"value": default}})
        node = ref.get(group)
        val = node.get("value") if isinstance(node, dict) else node
        return _positive(val)
    except Exception:  # noqa: BLE001 — a broken reference file must not take the engine down
        return None


def _reference_default() -> int | None:
    """call_timeout from references/timeouts.json (None when unavailable)."""
    return _reference_value("call_timeout", DEFAULT_CALL_TIMEOUT)


def _resolve(keys, files, group: str, default: int) -> int:
    """env (each key in order) → .env files (each file, each key in order) → reference → default."""
    for k in keys:
        v = _positive(os.environ.get(k))
        if v is not None:
            return v
    for p in files:
        for k in keys:
            v = _positive(_read_env_key(p, k))
            if v is not None:
                return v
    v = _reference_value(group, default)
    return default if v is None else v


def resolve_call_timeout(env_files=None, export: bool = True) -> int:
    """Resolve the ceiling per the order above. `env_files` overrides the .env search list (an
    empty tuple disables it — tests use this to assert the reference default); `export=False`
    leaves os.environ untouched."""
    files = DEFAULT_ENV_FILES if env_files is None else tuple(env_files)
    v = _resolve((ENV_KEY,), files, "call_timeout", DEFAULT_CALL_TIMEOUT)
    if export:
        os.environ[ENV_KEY] = str(v)
    return v


def resolve_phase_timeout(keys=PHASE_ENV_KEYS, env_files=None) -> int:
    """The wall-clock budget of one harness phase, per the order above. `keys` lists the env /
    .env keys in priority order (the CLI backend passes HARNESS_CLI_TIMEOUT first)."""
    files = DEFAULT_ENV_FILES if env_files is None else tuple(env_files)
    return _resolve(tuple(keys), files, "phase_timeout", DEFAULT_PHASE_TIMEOUT)


@functools.lru_cache(maxsize=1)
def phase_margin() -> int:
    """Seconds a call keeps in reserve before the phase deadline (references → 120); read once."""
    v = _reference_value("phase_deadline_margin", DEFAULT_PHASE_MARGIN)
    return DEFAULT_PHASE_MARGIN if v is None else v


# The active phase's deadline (epoch seconds). A ContextVar so concurrent in-process phases
# (collect fan-out, parallel cluster judges) each clamp to their OWN deadline; the env var
# carries it into child processes (the CLI backend's MCP server, collector subprocesses).
_DEADLINE: contextvars.ContextVar = contextvars.ContextVar("cti_phase_deadline", default=None)


def set_phase_deadline(deadline: float):
    """Bind the current context's phase deadline; returns the token for reset_phase_deadline."""
    return _DEADLINE.set(float(deadline))


def reset_phase_deadline(token) -> None:
    try:
        _DEADLINE.reset(token)
    except (ValueError, LookupError, RuntimeError):
        pass


def phase_deadline() -> float | None:
    """The active phase deadline: the in-process binding, else HARNESS_PHASE_DEADLINE, else None."""
    d = _DEADLINE.get()
    if d is not None:
        return d
    try:
        d = float(str(os.environ.get(DEADLINE_ENV) or "").strip())
    except ValueError:
        return None
    return d if d > 0 else None


def remaining(margin: float | None = None, now: float | None = None) -> float | None:
    """Seconds a call may still run inside the active phase (deadline - now - margin), or None
    when no phase deadline is bound."""
    d = phase_deadline()
    if d is None:
        return None
    return d - (time.time() if now is None else now) - (phase_margin() if margin is None else margin)


def clamp(timeout):
    """Cap `timeout` at the time left in the active phase (minimum 1 s); unchanged outside a phase."""
    left = remaining()
    if left is None:
        return timeout
    return max(1, min(int(timeout), int(left)))


CALL_TIMEOUT = resolve_call_timeout()


def floor(timeout) -> int:
    """Raise a per-call timeout to the ceiling — None/garbage → CALL_TIMEOUT, shorter → CALL_TIMEOUT,
    already longer → kept — then clamp it to the time left in the active phase. Use at every
    subprocess/HTTP task-call site that names its own bound."""
    t = CALL_TIMEOUT if not isinstance(timeout, (int, float)) else max(int(timeout), CALL_TIMEOUT)
    return clamp(t)
