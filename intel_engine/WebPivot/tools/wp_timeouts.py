#!/usr/bin/env python3
"""
wp_timeouts.py — the ONE resolver for the per-call timeout CEILING (`CTI_CALL_TIMEOUT`).

POLICY
------
Every data-fetching / API / collector / renderer / subprocess "task call" in the engine runs up
to CALL_TIMEOUT seconds (default 1800 = 30 min), then times out and the run moves on. Shorter
per-call values written at a call site are FLOORED to the ceiling via `floor()`; only raw DNS /
TLS / JARM micro-probes (getaddrinfo, dig, nslookup, ping, handshake) keep their fail-fast bounds.

RESOLUTION ORDER (first hit wins)
---------------------------------
  1. process env  CTI_CALL_TIMEOUT          — an exported variable always wins
  2. .env files   CTI_CALL_TIMEOUT=<secs>   — the skill-root .env (the /apikeys store), then
                                              intel_engine/.env; the analyst's editable knob
  3. reference data                          — references/timeouts.json → call_timeout (RULE 3)
  4. embedded fallback                       — 1800

The resolved value is EXPORTED back into os.environ so every child process this one spawns
(collector subprocesses, IntelGraph/IntelReport renderers, node/pandoc helpers) inherits the
same ceiling without re-reading .env. Non-positive or garbage values fall through to the next
source. A running process keeps the value it started with — restart to apply a .env change.

Stdlib only. Importable standalone from any component (`sys.path.insert(0, <this dir>)`).
"""
from __future__ import annotations

import os

__all__ = ["CALL_TIMEOUT", "ENV_KEY", "DEFAULT_CALL_TIMEOUT", "resolve_call_timeout", "floor"]

ENV_KEY = "CTI_CALL_TIMEOUT"
DEFAULT_CALL_TIMEOUT = 1800

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


def _reference_default() -> int | None:
    """call_timeout from references/timeouts.json via the RULE 3 loader (None when unavailable)."""
    try:
        import sys
        if _HERE not in sys.path:
            sys.path.insert(0, _HERE)
        from wp_refs import load_ref, ref_path  # noqa: E402
        ref = load_ref(ref_path(__file__, "timeouts.json"), {"call_timeout": DEFAULT_CALL_TIMEOUT})
        return _positive(ref.get("call_timeout"))
    except Exception:  # noqa: BLE001 — a broken reference file must not take the engine down
        return None


def resolve_call_timeout(env_files=None, export: bool = True) -> int:
    """Resolve the ceiling per the order above. `env_files` overrides the .env search list (an
    empty tuple disables it — tests use this to assert the reference default); `export=False`
    leaves os.environ untouched."""
    files = DEFAULT_ENV_FILES if env_files is None else tuple(env_files)
    v = _positive(os.environ.get(ENV_KEY))
    if v is None:
        for p in files:
            v = _positive(_read_env_key(p, ENV_KEY))
            if v is not None:
                break
    if v is None:
        v = _reference_default()
    if v is None:
        v = DEFAULT_CALL_TIMEOUT
    if export:
        os.environ[ENV_KEY] = str(v)
    return v


CALL_TIMEOUT = resolve_call_timeout()


def floor(timeout) -> int:
    """Raise a per-call timeout to the ceiling: None/garbage → CALL_TIMEOUT, shorter → CALL_TIMEOUT,
    already longer → kept. Use at every subprocess/HTTP task-call site that names its own bound."""
    return CALL_TIMEOUT if not isinstance(timeout, (int, float)) else max(int(timeout), CALL_TIMEOUT)
