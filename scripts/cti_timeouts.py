"""cti_timeouts — the root scripts' handle on the per-call timeout ceiling (CTI_CALL_TIMEOUT).

Re-exports the canonical resolver at ../intel_engine/WebPivot/tools/wp_timeouts.py (env →
skill-root .env → references/timeouts.json → 1800s; exports the value to os.environ so child
processes inherit it). A checkout without the engine subtree falls back to the same order minus
the reference file, so `uv run scripts/generate-cti-*.py` keeps working standalone.
"""
import os as _os
import sys as _sys

_ENGINE_TOOLS = _os.path.abspath(_os.path.join(_os.path.dirname(__file__), "..", "intel_engine",
                                                "WebPivot", "tools"))
try:
    if _ENGINE_TOOLS not in _sys.path:
        _sys.path.insert(0, _ENGINE_TOOLS)
    from wp_timeouts import CALL_TIMEOUT, floor  # noqa: F401
except Exception:  # noqa: BLE001 — engine absent: env → skill-root .env → 1800
    _SKILL_ENV = _os.environ.get("CTI_API_KEYS_ENV") or _os.path.join(
        _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), ".env")

    def _positive(v):
        try:
            n = int(str(v).strip())
        except (TypeError, ValueError):
            return None
        return n if n > 0 else None

    def _from_env_file():
        try:
            with open(_SKILL_ENV, encoding="utf-8") as f:
                for line in f:
                    s = line.strip()
                    if s.startswith("CTI_CALL_TIMEOUT="):
                        return s.split("=", 1)[1].strip().strip('"').strip("'")
        except OSError:
            pass
        return None

    CALL_TIMEOUT = _positive(_os.environ.get("CTI_CALL_TIMEOUT")) or _positive(_from_env_file()) or 1800
    _os.environ["CTI_CALL_TIMEOUT"] = str(CALL_TIMEOUT)

    def floor(timeout):
        return CALL_TIMEOUT if not isinstance(timeout, (int, float)) else max(int(timeout), CALL_TIMEOUT)

__all__ = ["CALL_TIMEOUT", "floor"]
