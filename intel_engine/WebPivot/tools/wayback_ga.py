"""De-duplicated shim — the canonical `wayback_ga` lives at ../../scripts/webpivot/wayback_ga.py (single source
of truth; no drift). This path used to hold a second, diverging copy; it now loads and
re-exports the canonical so existing `import wayback_ga` and CLI calls from here keep working."""
import importlib.util as _u, os as _os, sys as _sys
_canon = _os.path.abspath(_os.path.join(_os.path.dirname(__file__), "..", "..", "..", "scripts", "webpivot", "wayback_ga.py"))
_spec = _u.spec_from_file_location(__name__, _canon)
_mod = _u.module_from_spec(_spec)
_sys.modules[__name__] = _mod
_spec.loader.exec_module(_mod)
