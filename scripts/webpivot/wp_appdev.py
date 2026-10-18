"""De-duplicated shim — the canonical `wp_appdev` (keyless app-store developer lookup: Play package
→ developer name / legal name / email / website / other apps; App Store id or bundle id → iTunes
artistName / artistId / sellerName / other apps; developer website on a case domain = owner link)
lives at ../../intel_engine/WebPivot/tools/wp_appdev.py. Single source of truth; this path
re-exports it so `import wp_appdev` and CLI calls from the scripts/ layer keep working (RULE 4)."""
import importlib.util as _u, os as _os, sys as _sys
_canon = _os.path.abspath(_os.path.join(_os.path.dirname(__file__), "..", "..",
                                        "intel_engine", "WebPivot", "tools", "wp_appdev.py"))
_pkg = _os.path.dirname(_canon)
if _pkg not in _sys.path:
    _sys.path.insert(0, _pkg)
_spec = _u.spec_from_file_location(__name__, _canon)
_mod = _u.module_from_spec(_spec)
_sys.modules[__name__] = _mod
_spec.loader.exec_module(_mod)
