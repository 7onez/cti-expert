"""De-duplicated shim — the canonical `wp_subenum` (subdomain enumeration via installed subfinder /
amass / assetfinder / findomain, subfinder keyed from .env, DNS-verified, written to
cases/<id>/subenum/<apex>.json for the frontier) lives at ../../intel_engine/WebPivot/tools/wp_subenum.py.
Single source of truth; this path re-exports it (RULE 4)."""
import importlib.util as _u, os as _os, sys as _sys
_canon = _os.path.abspath(_os.path.join(_os.path.dirname(__file__), "..", "..",
                                        "intel_engine", "WebPivot", "tools", "wp_subenum.py"))
_pkg = _os.path.dirname(_canon)
if _pkg not in _sys.path:
    _sys.path.insert(0, _pkg)
_spec = _u.spec_from_file_location(__name__, _canon)
_mod = _u.module_from_spec(_spec)
_sys.modules[__name__] = _mod
_spec.loader.exec_module(_mod)
