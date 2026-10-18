#!/usr/bin/env python3
"""wp_moli — drive the Moli headless browser (github.com/lexmount/moli) through `moli fetch`.

Moli is a DOM-first engine: it runs the page's JavaScript against a native DOM and serializes the
result without building layout or paint, at a fraction of Chromium's memory. This module is the
ONE place that knows its command line. It renders DOM only — evidence pixels and the Cloudflare
escalation stay on Chromium (see wp_browser.py for the routing rule and references/moli.json for
why).

Contract (mirrors wp_net's Chromium render, which RAISES so the caller records a real
`live_error` instead of a silent passive fallback):
  * `fetch_dom()` returns {final_url, status, title, html, headers, redirect_chain, cookies,
    renderer} or raises MoliError — non-zero exit, proxy rejection (407), a raw non-HTML download,
    or a document shorter than `fetch.min_html_bytes`.
  * `eval_page()` returns the value of one JavaScript expression evaluated after page readiness,
    optionally with a document-start script installed before any page script runs.
  * The proxy travels in the child's ENVIRONMENT (http_proxy/https_proxy/all_proxy, both cases),
    never on the command line: /proc/<pid>/cmdline is world-readable, the environment is not.
    It is set ONLY when its scheme is in `proxy.verified_schemes`; anything else raises before a
    process is spawned, and inherited proxy variables are replaced, so an unverified proxy can
    never degrade to a direct egress. `proxy=None` means "the process's proxy env" (wp_browser).
  * The argv is built here from fixed options. Web Bot Auth (`--web-bot-auth-*`) — which announces
    a signed bot identity to the target — is never emitted: it is an attribution beacon.

Stdlib only; the binary is an optional runtime dependency (`moli_configured()`).

CLI:
    python3 wp_moli.py status [--json]
    python3 wp_moli.py fetch <url> [--proxy URL] [--ua UA] [--timeout S] [--json]
"""
from __future__ import annotations

import argparse
import functools
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wp_refs import load_ref, ref_path  # noqa: E402
from wp_timeouts import CALL_TIMEOUT  # noqa: E402

# Conservative minimum: the pin, ONE verified proxy scheme (plain HTTP), Chromium as the default
# engine and no downloadable assets — a missing reference file narrows Moli's reach, never widens it.
_MOLI_FALLBACK = {
    "release": {"version": "1.1.10", "base_url": "https://github.com/lexmount/moli/releases/download/v1.1.10"},
    "assets": {},
    "proxy": {"verified_schemes": ["http"]},
    "fetch": {"wait": "done", "min_timeout_seconds": 25, "min_html_bytes": 200},
    "router": {"default_engine": "chromium"},
}
_REF = load_ref(ref_path(__file__, "moli.json"), _MOLI_FALLBACK)
RELEASE = _REF["release"]
ASSETS = _REF["assets"]
PROXY = _REF["proxy"]
FETCH = _REF["fetch"]
ROUTER = _REF["router"]
PINNED_VERSION = str(RELEASE.get("version") or "")
VERIFIED_PROXY_SCHEMES = frozenset(s.lower() for s in PROXY.get("verified_schemes") or [])


class MoliError(RuntimeError):
    """A Moli render that produced no usable document."""


def moli_bin() -> str | None:
    """Path of the moli binary: $MOLI_BIN, then PATH, then the installers' default locations."""
    cands = [os.environ.get("MOLI_BIN"), shutil.which("moli"),
             os.path.expanduser("~/.local/bin/moli")]
    if os.name == "nt":
        cands.append(os.path.join(os.environ.get("LOCALAPPDATA", ""), "Moli", "bin", "moli.exe"))
    for c in cands:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


@functools.lru_cache(maxsize=4)
def _version_of(path: str) -> str | None:
    try:
        r = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=15)
    except Exception:  # noqa: BLE001
        return None
    m = re.search(r"(\d+\.\d+\.\d+\S*)", r.stdout or "")
    return m.group(1) if r.returncode == 0 and m else None


def version() -> str | None:
    """Installed Moli version (e.g. '1.1.10'), or None when absent or not runnable."""
    b = moli_bin()
    return _version_of(b) if b else None


def moli_configured() -> bool:
    """True when a runnable moli binary is present."""
    return version() is not None


def renderer_tag() -> str:
    """The `meta.renderer` stamp for artifacts this engine produced."""
    return f"moli {version() or 'unknown'}"


def _scheme(proxy: str) -> str:
    return (urlsplit(proxy if "://" in proxy else "http://" + proxy).scheme or "http").lower()


def proxy_supported(proxy: str | None) -> bool:
    """A direct fetch (no proxy) or a proxy whose scheme passed the Gate-0 egress probe."""
    return not proxy or _scheme(proxy) in VERIFIED_PROXY_SCHEMES


_PROXY_VARS = ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY")


def child_env(proxy: str | None) -> dict:
    """Environment for one moli process: inherited proxy variables replaced by exactly `proxy`
    (Gate 0 re-proved this route: good credentials egress, bad/dead proxies fail closed with no
    direct origin hit). Raises MoliError on an unverified scheme."""
    if proxy and not proxy_supported(proxy):
        raise MoliError(f"proxy scheme '{_scheme(proxy)}' is not verified for Moli "
                        f"(verified: {', '.join(sorted(VERIFIED_PROXY_SCHEMES)) or 'none'}) — refusing "
                        "rather than risk a direct egress")
    env = {k: v for k, v in os.environ.items() if k not in _PROXY_VARS}
    if proxy:
        env.update(dict.fromkeys(_PROXY_VARS, proxy if "://" in proxy else "http://" + proxy))
    return env


def _resolve_proxy(proxy: str | None) -> str | None:
    if proxy:
        return proxy
    import wp_browser                      # lazy: wp_browser imports this module
    return wp_browser.resolve_proxy(None)


def build_argv(url: str, *, timeout: int = 30, ua: str | None = None, wait: str | None = None,
               dump: str | None = "json", start_script_file: str | None = None,
               eval_file: str | None = None) -> list[str]:
    """The exact `moli fetch` command for one render (no proxy — see child_env)."""
    b = moli_bin()
    if not b:
        raise MoliError("moli binary not found (install it with scripts/install.sh, or set MOLI_BIN)")
    t_ms = max(int(timeout or 0), int(FETCH.get("min_timeout_seconds") or 25)) * 1000
    argv = [b, "fetch", "--wait", str(wait or FETCH.get("wait") or "done"), "-t", str(t_ms)]
    if eval_file:
        argv += ["--eval-file", eval_file]
    elif dump:
        argv += ["--dump", dump]
    if ua:
        argv += ["--user-agent", ua]
    if start_script_file:
        argv += ["--document-start-script-file", start_script_file]
    return argv + [url]


def _run(argv: list[str], timeout: int, env: dict) -> subprocess.CompletedProcess:
    # Readiness is bounded by -t inside Moli; the process ceiling is the engine-wide CALL_TIMEOUT.
    try:
        return subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace",
                              timeout=max(int(timeout or 0) + 60, CALL_TIMEOUT), env=env)
    except subprocess.TimeoutExpired as e:
        raise MoliError(f"moli fetch timed out after {e.timeout}s") from None
    except OSError as e:
        raise MoliError(f"moli fetch could not start: {e}") from None


def _err_tail(r: subprocess.CompletedProcess) -> str:
    lines = [ln.strip() for ln in (r.stderr or "").splitlines() if ln.strip()]
    return " | ".join(lines[-2:])[:300] or f"exit {r.returncode}"


def _cookies_from_headers(headers) -> list[dict]:
    """Set-Cookie headers -> [{name, value}] (the shape analyze() reads names from). Callers pass
    every redirect hop's headers too — a panel that sets its session on `/` and 302s to `/login`
    must yield the cookie. Cookies a page sets from JavaScript are not in the dump."""
    out = []
    for h in headers or []:
        if isinstance(h, dict) and str(h.get("name", "")).lower() == "set-cookie":
            first = str(h.get("value", "")).split(";", 1)[0]
            name, sep, val = first.partition("=")
            if sep and name.strip():
                out.append({"name": name.strip(), "value": val.strip()})
    return out


def fetch_dom(url: str, timeout: int = 30, ua: str | None = None, proxy: str | None = None,
              wait: str | None = None) -> dict:
    """Render `url` and return its post-JS DOM + response metadata. Raises MoliError."""
    env = child_env(_resolve_proxy(proxy))
    r = _run(build_argv(url, timeout=timeout, ua=ua, wait=wait), timeout, env)
    if r.returncode != 0:
        raise MoliError(f"moli render failed: {_err_tail(r)}")
    try:
        doc = json.loads(r.stdout)
    except ValueError:
        raise MoliError("moli render returned no JSON document") from None
    status = doc.get("status")
    if status == 407:
        raise MoliError("render: proxy rejected credentials (407)")
    html = doc.get("html")
    if html is None:
        raise MoliError(f"render: HTTP {status}, raw non-HTML response")
    if len(html) < int(FETCH.get("min_html_bytes") or 200):
        raise MoliError(f"render: HTTP {status}, {len(html)} bytes")
    chain = doc.get("redirect_chain") or []
    hop_headers = [h for hop in chain if isinstance(hop, dict) for h in hop.get("headers") or []]
    return {"final_url": doc.get("final_url") or url, "status": status, "title": doc.get("title"),
            "html": html, "headers": doc.get("headers") or [], "redirect_chain": chain,
            "cookies": _cookies_from_headers(hop_headers + (doc.get("headers") or [])),
            "renderer": renderer_tag()}


def eval_page(url: str, expression: str, *, timeout: int = 30, ua: str | None = None,
              proxy: str | None = None, start_script: str | None = None, wait: str | None = None):
    """Evaluate one JS expression on the rendered page; JSON values are decoded. Raises MoliError.
    `start_script` runs before any page script (instrumentation hooks such as a clipboard spy)."""
    env = child_env(_resolve_proxy(proxy))
    with tempfile.TemporaryDirectory(prefix="moli_") as td:
        ev = os.path.join(td, "eval.js")
        with open(ev, "w", encoding="utf-8") as fh:
            fh.write(expression)
        ss = None
        if start_script:
            ss = os.path.join(td, "start.js")
            with open(ss, "w", encoding="utf-8") as fh:
                fh.write(start_script)
        r = _run(build_argv(url, timeout=timeout, ua=ua, wait=wait, dump=None,
                            start_script_file=ss, eval_file=ev), timeout, env)
    if r.returncode != 0:
        raise MoliError(f"moli eval failed: {_err_tail(r)}")
    out = (r.stdout or "").strip()
    try:
        return json.loads(out)
    except ValueError:
        return out


def status() -> dict:
    b = moli_bin()
    v = version()
    return {"binary": b, "version": v, "pinned": PINNED_VERSION,
            "matches_pin": bool(v) and v == PINNED_VERSION,
            "verified_proxy_schemes": sorted(VERIFIED_PROXY_SCHEMES)}


def _cli(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Moli DOM renderer (DOM only; pixels stay on Chromium).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("status")
    s.add_argument("--json", action="store_true")
    f = sub.add_parser("fetch")
    f.add_argument("url")
    f.add_argument("--proxy")
    f.add_argument("--ua")
    f.add_argument("--timeout", type=int, default=30)
    f.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    if a.cmd == "status":
        st = status()
        if a.json:
            print(json.dumps(st, indent=1))
        else:
            print(f"moli: {st['version'] or 'NOT INSTALLED'} (pinned {st['pinned']}"
                  f"{'' if st['matches_pin'] or not st['version'] else ' — MISMATCH'}) at {st['binary'] or '-'}")
            print(f"verified proxy schemes: {', '.join(st['verified_proxy_schemes'])}")
        return 0 if st["version"] else 3
    try:
        d = fetch_dom(a.url, timeout=a.timeout, ua=a.ua, proxy=a.proxy)
    except MoliError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if a.json:
        print(json.dumps(d, indent=1))
    else:
        print(d["html"])
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
