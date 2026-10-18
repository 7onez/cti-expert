#!/usr/bin/env python3
"""wp_browser — the ONE routing decision between the two browser engines, and the one place the
research-egress proxy is translated for them.

Engines:
  * Moli (wp_moli.py)   — DOM-first, ~1/7 of Chromium's memory. Plain DOM renders only.
  * Chromium (Playwright) — the pixel engine. Owns evidence screenshots, engage, and the
    Cloudflare-escalation retry.

`select_dom_engine()` rule, in order:
  1. A screenshot or an already-detected Cloudflare challenge needs Chromium — a Moli PNG is not
     what the victim saw, and a non-Chromium engine cannot clear a managed challenge. No Chromium
     → refuse (None), never a Moli substitute.
  2. CTI_BROWSER (else references/moli.json router.default_engine): `chromium` | `moli` | `auto`.
  3. Moli is used only when installed AND the egress proxy's scheme passed the Gate-0 probe
     (moli.json proxy.verified_schemes). `auto` then falls back to Chromium; `moli` refuses.

Returning None is the fail-closed outcome: the caller raises and records `live_error`, and the
collector falls through rendered → raw fetch → archive exactly as it does for a failed render.

Stdlib only; imports neither Playwright nor wp_common (no proxy-install side effect).
"""
from __future__ import annotations

import glob
import importlib.util
import os
import sys
from urllib.parse import unquote, urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wp_moli  # noqa: E402

ENGINES = ("chromium", "moli", "auto")
_CHROMIUM_HINT = "rerun the installer with --headless (Playwright + Chromium)"


def engine_setting() -> str:
    """CTI_BROWSER, else the reference default; an unknown value degrades to `chromium`."""
    v = (os.environ.get("CTI_BROWSER") or wp_moli.ROUTER.get("default_engine") or "chromium").strip().lower()
    return v if v in ENGINES else "chromium"


def resolve_proxy(proxy: str | None = None) -> str | None:
    """The egress proxy a render must use: the explicit one, else the process's proxy env — the
    same resolution the urllib path and cti_proxy.install() use (ALL_PROXY carries a SOCKS pool)."""
    p = (proxy or os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
         or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
         or os.environ.get("ALL_PROXY") or os.environ.get("all_proxy") or None)
    if not p:
        try:
            import wp_common  # noqa: F401 — walks parents to locate and install cti_proxy
            p = (os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
                 or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
                 or os.environ.get("ALL_PROXY") or os.environ.get("all_proxy") or None)
        except Exception:  # noqa: BLE001
            pass
    return p


def proxy_for_chromium(proxy: str | None = None) -> dict | None:
    """Chromium proxy config for Playwright, or None for a direct launch.

    Chromium ignores inline `user:pass@` credentials (the form the CTI proxy layer exports) and
    answers every navigation with a 407 and an empty document, so the credentials are handed over
    as Playwright's `username`/`password` fields."""
    raw = resolve_proxy(proxy)
    if not raw:
        return None
    u = urlparse(raw if "://" in raw else "http://" + raw)
    if not u.hostname:
        return None
    # Chromium knows http:// and socks5:// (it resolves through SOCKS anyway, so socks5h == socks5);
    # an https:// proxy URL in the pool means "HTTP proxy reached over TLS", which Chromium spells https://
    scheme = {"socks5h": "socks5", "socks4a": "socks4", "": "http"}.get(u.scheme.lower(), u.scheme.lower())
    cfg = {"server": f"{scheme}://{u.hostname}" + (f":{u.port}" if u.port else "")}
    if u.username:
        cfg["username"] = unquote(u.username)
        cfg["password"] = unquote(u.password or "")
    bypass = os.environ.get("NO_PROXY") or os.environ.get("no_proxy")
    if bypass:
        cfg["bypass"] = bypass
    return cfg


def chromium_launch_kwargs(proxy: str | None = None) -> dict:
    """`chromium.launch(**…)` arguments shared by every Chromium call site."""
    kw = {"headless": True}
    pcfg = proxy_for_chromium(proxy)
    if pcfg:
        kw["proxy"] = pcfg
    return kw


def _browsers_dirs() -> list[str]:
    env = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    if env and env != "0":
        return [env]
    home = os.path.expanduser("~")
    return [os.path.join(home, ".cache", "ms-playwright"),
            os.path.join(home, "Library", "Caches", "ms-playwright"),
            os.path.join(os.environ.get("LOCALAPPDATA", os.path.join(home, "AppData", "Local")), "ms-playwright")]


def _expected_chromium_dirs(pkg_dir: str) -> list[str] | None:
    """Browser-cache directory names this Playwright build launches for headless Chromium, from
    its own driver/package/browsers.json (headless launches use the headless shell), or None when
    the manifest is unreadable."""
    import json
    try:
        with open(os.path.join(pkg_dir, "driver", "package", "browsers.json"), encoding="utf-8") as fh:
            rev = {b.get("name"): b.get("revision") for b in json.load(fh).get("browsers", [])}
    except Exception:  # noqa: BLE001
        return None
    if rev.get("chromium-headless-shell"):
        return [f"chromium_headless_shell-{rev['chromium-headless-shell']}"]
    return [f"chromium-{rev['chromium']}"] if rev.get("chromium") else None


def chromium_available() -> bool:
    """Playwright importable AND the exact Chromium build it launches downloaded. The package
    alone is not enough — the installer can land it while the browser download is deferred — and
    neither is ANY cached Chromium: a Playwright upgrade wants a new revision and fails to launch."""
    try:
        spec = importlib.util.find_spec("playwright")
    except (ImportError, ValueError):
        return False
    if spec is None:
        return False
    if os.environ.get("PLAYWRIGHT_BROWSERS_PATH") == "0":     # browsers bundled inside the package
        return True
    pkg = next(iter(spec.submodule_search_locations or []), None)
    want = _expected_chromium_dirs(pkg) if pkg else None
    for d in _browsers_dirs():
        if want is None:
            if glob.glob(os.path.join(d, "chromium*")):
                return True
        elif any(os.path.isdir(os.path.join(d, w)) for w in want):
            return True
    return False


def chromium_missing_note(what: str = "evidence pixels") -> str:
    return f"Chromium is required for {what} — {_CHROMIUM_HINT}"


def select_dom_engine(proxy: str | None = None, *, cf_challenge: bool = False,
                      screenshot: bool = False) -> tuple[str | None, str]:
    """(engine, reason) for one render; engine None means refuse. See the module docstring."""
    if screenshot or cf_challenge:
        what = "a screenshot" if screenshot else "the Cloudflare-escalation render"
        if chromium_available():
            return "chromium", f"{what} always renders on Chromium"
        return None, chromium_missing_note(what)
    setting = engine_setting()
    if setting == "chromium":
        if chromium_available():
            return "chromium", "CTI_BROWSER=chromium"
        return None, f"CTI_BROWSER=chromium but Chromium is not installed — {_CHROMIUM_HINT}"
    px = resolve_proxy(proxy)
    if not wp_moli.moli_configured():
        blocker = "Moli is not installed"
    elif not wp_moli.proxy_supported(px):
        blocker = (f"proxy scheme '{urlparse(px if '://' in px else 'http://' + px).scheme}' is not "
                   f"verified for Moli")
    else:
        return "moli", f"CTI_BROWSER={setting}"
    if setting == "moli":
        return None, f"CTI_BROWSER=moli but {blocker}"
    if chromium_available():
        return "chromium", f"{blocker} — using Chromium"
    return None, f"no DOM renderer: {blocker}, and Chromium is not installed"


def chromium_renderer_tag(browser) -> str:
    try:
        return f"chromium {browser.version}"
    except Exception:  # noqa: BLE001
        return "chromium"
