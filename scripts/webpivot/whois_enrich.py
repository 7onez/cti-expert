"""De-duplicated shim — the canonical `whois_enrich` lives at ../../WebPivot/tools/whois_enrich.py (single source
of truth; no drift). This path used to hold a second, diverging copy; it now loads and
re-exports the canonical so existing `import whois_enrich` and CLI calls from here keep working."""
import importlib.util as _u, os as _os, sys as _sys
_canon = _os.path.abspath(_os.path.join(_os.path.dirname(__file__), "..", "..", "intel_engine", "WebPivot", "tools", "whois_enrich.py"))
_spec = _u.spec_from_file_location(__name__, _canon)
_mod = _u.module_from_spec(_spec)
_sys.modules[__name__] = _mod
_spec.loader.exec_module(_mod)
