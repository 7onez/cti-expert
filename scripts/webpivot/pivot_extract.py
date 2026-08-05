"""De-duplicated shim — the canonical `pivot_extract` lives at ../../intel_engine/WebPivot/tools/pivot_extract.py
(single source of truth; no drift). This path used to hold a second, diverging copy — the
pre-split 2274-line monolith — while the canonical modular collector sat unused next to its
wp_* siblings. It now loads and re-exports the canonical so existing `import pivot_extract`
and CLI calls from here keep working, and the full upstream flag surface (--case, --report,
--archive-missing, --screenshot, --hunt-*, --free-only, --misp, --no-assets, --no-censys …)
reaches the collector instead of being dropped by the harness flag filter.

The canonical facade imports its wp_* siblings by bare name, so its own directory has to be on
sys.path before it is executed."""
import importlib.util as _u, os as _os, sys as _sys
_canon = _os.path.abspath(_os.path.join(_os.path.dirname(__file__), "..", "..",
                                        "intel_engine", "WebPivot", "tools", "pivot_extract.py"))
_pkg = _os.path.dirname(_canon)
if _pkg not in _sys.path:
    _sys.path.insert(0, _pkg)
_spec = _u.spec_from_file_location(__name__, _canon)
_mod = _u.module_from_spec(_spec)
_sys.modules[__name__] = _mod
_spec.loader.exec_module(_mod)
