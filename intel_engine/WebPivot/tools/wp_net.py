"""wp_net — HTTP fetch, Cloudflare handling, headless render, Wayback/urlscan retrieval."""
import sys
import os
import re
import json
import base64
import hashlib
import argparse
import collections
import functools
import gzip
import itertools
import zlib
import socket
import ssl
import datetime
import shutil
import subprocess
import concurrent.futures
from urllib.parse import urljoin, urlparse, urlencode, quote, parse_qsl, unquote
# ------------------------------------------------------------------ optional deps
try:
    import requests  # noqa
    HAVE_REQUESTS = True
except Exception:
    HAVE_REQUESTS = False

import urllib.request
import urllib.error
from wp_common import *  # noqa
try:
    import api_usage                      # licensed-API credit ledger
except Exception:
    api_usage = None
from wp_refs import ref_path, load_ref  # noqa — endpoint templates are reference DATA (RULE 3)

def _floor_to(t):
    """Raise a per-call timeout to CALL_TIMEOUT (the ceiling). Used on the requests/Playwright paths
    that bypass the process-wide urllib.request.urlopen floor installed in wp_common."""
    return CALL_TIMEOUT if not isinstance(t, (int, float)) else max(int(t), CALL_TIMEOUT)

# urlscan endpoint templates + hostname paging knobs — reference DATA (RULE 3). The fallback is the
# conservative MINIMUM that still walks the index correctly (hostname + cursor paths, A/NS eras, one
# page): a missing/bad reference file degrades to a narrower walk with a warning, never to a silently
# different one. tests/test_references.py asserts the loaded file is strictly richer than this.
_USCAN_FALLBACK = {
    "endpoints": {"hostname": "/api/v1/hostname/{host}?limit={limit}",
                  "hostname_page": "/api/v1/hostname/{host}?limit={limit}&pageState={page_state}"},
    "hostname": {"page_limit": 1000, "max_pages": 1, "era_types": ["A", "NS"],
                 "scan_prefix": "VIA-SCAN", "summary_seen_on": ["2100-01-01", "2200-01-01"],
                 "first_seen_sources": {"ct": "ct_first"}},
    "verdict": {"structural_labels": ["domain.apexdomain", "content.rootdir", "hosting.cdn"]},
    "dom_assets": {"max_resources": 10, "extensions": [".js", ".css"],
                   "mime_prefixes": ["javascript", "css"]},
}
_USCAN_REF = load_ref(ref_path(__file__, "urlscan_endpoints.json"), _USCAN_FALLBACK)
URLSCAN_ENDPOINTS = _USCAN_REF["endpoints"]
URLSCAN_HOSTNAME_CFG = _USCAN_REF["hostname"]
# result labels that describe structure/hosting class, never a finding — a verdict row is emitted
# only on signal (malicious / score>0 / brand / a label outside this set)
URLSCAN_STRUCTURAL_LABELS = frozenset((_USCAN_REF.get("verdict") or _USCAN_FALLBACK["verdict"])["structural_labels"])
# bounds for urlscan_dom_assets — see references/urlscan_endpoints.json -> dom_assets
URLSCAN_DOM_ASSETS_CFG = _USCAN_REF.get("dom_assets") or _USCAN_FALLBACK["dom_assets"]
URLSCAN_BASE = "https://urlscan.io"


class _RecordingRedirectHandler(urllib.request.HTTPRedirectHandler):
    """urllib redirect handler that records each hop (from-url, status, to-url)."""
    def __init__(self, sink):
        self._sink = sink

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self._sink.append({"from": req.full_url, "status": code, "to": newurl})
        return super().redirect_request(req, fp, code, msg, headers, newurl)

def fetch(url: str, timeout: int = 20, ua: str = DEFAULT_UA, proxy: str = None,
          redirects_out: list = None, origin: str = None, extra_headers: dict = None):
    """Return (final_url, status, headers_dict, body_bytes). Follows redirects.

    When `proxy` is given (e.g. 'http://10.0.0.5:8080'), the request is routed through it
    on both the requests and the urllib stdlib path. None → direct connection (unchanged).
    Sends a full browser header profile so basic bot filters don't reset the connection.
    If `redirects_out` (a list) is passed, each redirect hop is appended to it as
    {from,status,to}; callers that don't need the chain simply omit it (unchanged behavior).
    When `origin` is given, an `Origin:` request header is added — used to observe the
    server's CORS response (which origins/backends it trusts); None → omit it (unchanged).
    `extra_headers` override/extend the profile — an API `Accept:` or `Authorization:` for a
    vendor endpoint (never for the target).
    """
    timeout = _floor_to(timeout)   # requests path bypasses the urllib.request.urlopen floor
    reqh = _browser_headers(ua)
    if origin:
        reqh["Origin"] = origin
    if extra_headers:
        reqh.update(extra_headers)
    if HAVE_REQUESTS:
        proxies = {"http": proxy, "https": proxy} if proxy else None
        r = requests.get(url, headers=reqh, timeout=timeout,
                         allow_redirects=True, verify=True, proxies=proxies)
        if redirects_out is not None:
            for h in r.history:
                redirects_out.append({"from": h.url, "status": h.status_code,
                                      "to": h.headers.get("Location", "")})
        return r.url, r.status_code, {k.lower(): v for k, v in r.headers.items()}, r.content
    req = urllib.request.Request(url, headers=reqh)
    handlers = []
    if redirects_out is not None:
        handlers.append(_RecordingRedirectHandler(redirects_out))
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    opener = urllib.request.build_opener(*handlers).open if handlers else urllib.request.urlopen
    try:
        with opener(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            body = _decode_body(resp.read(), headers.get("content-encoding"))
            return resp.geturl(), resp.status, headers, body
    except urllib.error.HTTPError as e:
        eh = {k.lower(): v for k, v in (e.headers or {}).items()}
        return url, e.code, eh, _decode_body(e.read(), eh.get("content-encoding"))


# --- CORS configuration probe ------------------------------------------------------
# A site's CORS policy is a first-class OSINT pivot. When a browser sends a cross-origin
# request it includes an `Origin:` header; the server answers with `Access-Control-Allow-
# Origin` (ACAO) and friends, naming the origins it trusts. Three outcomes matter:
#   * ACAO is a LITERAL origin (e.g. https://api.backend.example) → that host is a pivot
#     (a backend/API/staging/sibling the app trusts) EVEN IF it never appears in the HTML.
#   * ACAO ECHOES back whatever Origin we send, +Allow-Credentials:true → a reflect-any
#     misconfig; names no host but confirms a live credential-bearing API worth probing.
#   * ACAO is "*" → public asset host, no operator pivot.
# We learn this by sending a foreign Origin on both a GET (simple request) and an OPTIONS
# preflight and reading what the server echoes. This routes through the same fetch path as
# everything else, so `--proxy` is honored (no IP leak — unlike the raw-socket TLS probe).
# ⚠️ Authorized OSINT only. The probe is a benign, standards-defined browser request.

_CORS_PROBE_ORIGIN = "https://osint-cors-probe.example"

def _cors_absorb(out: dict, headers: dict, probe_origin: str):
    """Fold one response's Access-Control-* headers into the running CORS summary `out`."""
    h = {k.lower(): v for k, v in (headers or {}).items()}
    acao = (h.get("access-control-allow-origin") or "").strip()
    if acao:
        out["acao"] = acao
        if acao == "*":
            out["wildcard"] = True
        elif acao.lower() == probe_origin.lower():
            out["reflects_origin"] = True
        else:
            for tok in re.split(r"[,\s]+", acao):
                if not tok:
                    continue
                host = strip_www(urlparse(tok).netloc if "://" in tok else tok).strip("/")
                if host and "." in host and host.lower() != probe_origin.split("//")[-1]:
                    out["allowed_origin_hosts"].append(host.lower())
    if str(h.get("access-control-allow-credentials", "")).strip().lower() == "true":
        out["credentials"] = True
    for key, hdr in (("methods", "access-control-allow-methods"),
                     ("request_headers", "access-control-allow-headers"),
                     ("expose_headers", "access-control-expose-headers"),
                     ("max_age", "access-control-max-age")):
        if h.get(hdr) and not out.get(key):
            out[key] = h[hdr]
    if "origin" in (h.get("vary", "").lower()):
        out["vary_origin"] = True
    out["allowed_origin_hosts"] = uniq(out["allowed_origin_hosts"])

def _cors_options(url: str, ua: str, proxy: str, timeout: int, origin: str):
    """Send a CORS preflight (OPTIONS + Origin + Access-Control-Request-*); return headers."""
    reqh = _browser_headers(ua)
    reqh["Origin"] = origin
    reqh["Access-Control-Request-Method"] = "GET"
    reqh["Access-Control-Request-Headers"] = "authorization,content-type"
    if HAVE_REQUESTS:
        proxies = {"http": proxy, "https": proxy} if proxy else None
        r = requests.options(url, headers=reqh, timeout=timeout, allow_redirects=True,
                             verify=True, proxies=proxies)
        return r.status_code, {k.lower(): v for k, v in r.headers.items()}
    handlers = [urllib.request.ProxyHandler({"http": proxy, "https": proxy})] if proxy else []
    opener = urllib.request.build_opener(*handlers).open if handlers else urllib.request.urlopen
    req = urllib.request.Request(url, headers=reqh, method="OPTIONS")
    try:
        with opener(req, timeout=timeout) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}

def probe_cors(url: str, ua: str = DEFAULT_UA, proxy: str = None, timeout: int = 12):
    """Actively probe a URL's CORS policy; return a structured summary or None.

    `allowed_origin_hosts` are the LITERAL origins the server named — the pivotable
    ones (backend/API/sibling hosts). `reflects_origin`+`credentials` flag the classic
    reflect-any credential misconfig. Returns None if the server exposes no CORS policy.
    """
    origin = _CORS_PROBE_ORIGIN
    out = {"probe_origin": origin, "preflight_status": None, "acao": None,
           "credentials": False, "wildcard": False, "reflects_origin": False,
           "vary_origin": False, "methods": None, "request_headers": None,
           "expose_headers": None, "max_age": None, "allowed_origin_hosts": []}
    saw = False
    try:
        st, ph = _cors_options(url, ua, proxy, timeout, origin)
        out["preflight_status"] = st
        _cors_absorb(out, ph, origin)
        saw = saw or any(k.lower().startswith("access-control-") for k in ph)
    except Exception:
        pass
    try:
        _, _, gh, _ = fetch(url, timeout=timeout, ua=ua, proxy=proxy, origin=origin)
        _cors_absorb(out, gh, origin)
        saw = saw or bool(out["acao"])
    except Exception:
        pass
    return out if saw else None

def extract_cors(headers: dict):
    """Passively read Access-Control-* already present on a normal response (no probe).

    Most servers only emit ACAO when an Origin is sent, so this is usually empty — but a
    site that returns ACAO:* or a literal origin unconditionally still gets captured.
    """
    out = {"probe_origin": None, "preflight_status": None, "acao": None,
           "credentials": False, "wildcard": False, "reflects_origin": False,
           "vary_origin": False, "methods": None, "request_headers": None,
           "expose_headers": None, "max_age": None, "allowed_origin_hosts": []}
    _cors_absorb(out, headers, "\x00none\x00")  # sentinel origin → nothing "reflects" it
    return out if out["acao"] or out["vary_origin"] else None

def merge_cors(passive, active):
    """Prefer the active-probe result (it carries the reflection verdict); fold in any
    unconditional ACAO the passive read saw. Either arg may be None."""
    if not active:
        return passive
    if not passive:
        return active
    active["allowed_origin_hosts"] = uniq(active["allowed_origin_hosts"]
                                          + passive.get("allowed_origin_hosts", []))
    if passive.get("acao") and not active.get("acao"):
        active["acao"] = passive["acao"]
    active["wildcard"] = active["wildcard"] or passive.get("wildcard", False)
    active["vary_origin"] = active["vary_origin"] or passive.get("vary_origin", False)
    return active


# --- Cloudflare challenge handling -------------------------------------------------
# A CF-fronted target returns a 403/503 challenge page instead of the site. Detecting it
# lets us (a) report it honestly (not as a generic error) and (b) ESCALATE: a plain UA
# swap does NOT beat CF's managed challenge / Turnstile — those require a JS-executing
# browser. The escalation ladder, weakest→strongest: full browser headers (always on) →
# UA rotation (--rotate-ua) → residential/rotating proxy (--proxy/--proxy-range; CF blocks
# datacenter IPs hardest) → a real browser that runs the challenge JS (--render) → a
# dedicated solver (FlareSolverr, --flaresolverr / --solve-cf).
# ⚠️ Authorized OSINT only — see EthicalFramework.md. Use non-attributable egress.

# DATA: references/fetch_profile.json -> cloudflare_body_markers
_CF_BODY_MARKERS = tuple(_FP_REF["cloudflare_body_markers"])

def detect_cloudflare_challenge(status: int, headers: dict, body: str):
    """Return a short label if this response is a Cloudflare interstitial, else None."""
    h = {k.lower(): str(v).lower() for k, v in (headers or {}).items()}
    server = h.get("server", "")
    cf = ("cloudflare" in server) or ("cf-ray" in h) or ("cf-mitigated" in h)
    low = (body or "")[:20000].lower()
    body_hit = any(m in low for m in _CF_BODY_MARKERS)
    if status in (403, 429, 503):
        if body_hit:
            # managed challenge / Turnstile pages are JS interstitials — need a real browser
            return "cloudflare_challenge"
        if cf:
            # CF-attributed hard denial with no interstitial body — includes a cf-ray 429
            # rate-limit that the old `(cf or body_hit) and body_hit` silently dropped.
            return "cloudflare_block"
    return None

def flaresolverr_get(url: str, endpoint: str, timeout: int = 60, proxy: str = None):
    """Solve a Cloudflare challenge via a FlareSolverr instance (open-source CF solver that
    drives a headless browser). Returns (final_url, html, cookies) or (None, None, None).

    Point --flaresolverr / $FLARESOLVERR_URL at a running instance
    (docker run ghcr.io/flaresolverr/flaresolverr, default http://localhost:8191). This is the
    proper way to collect a CF-walled page for authorized OSINT — it executes the challenge JS
    the same way a browser would; we never forge a Cloudflare clearance token ourselves.
    """
    timeout = _floor_to(timeout)   # lift the FlareSolverr maxTimeout budget (ms) to the ceiling too
    api = endpoint.rstrip("/")
    if not api.endswith("/v1"):
        api += "/v1"
    payload = {"cmd": "request.get", "url": url, "maxTimeout": int(timeout * 1000)}
    if proxy:
        payload["proxy"] = {"url": proxy}
    try:
        req = urllib.request.Request(
            api, data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=timeout + 10) as resp:
            data = json.loads(resp.read().decode("utf-8", "ignore"))
    except Exception as e:
        print(f"[!] flaresolverr error: {e}", file=sys.stderr)
        return None, None, None
    sol = data.get("solution") or {}
    html = sol.get("response")
    if not html:
        print(f"[!] flaresolverr: no solution ({data.get('message','')})", file=sys.stderr)
        return None, None, None
    cookies = [{"name": c.get("name"), "value": c.get("value")} for c in sol.get("cookies", [])]
    return sol.get("url") or url, html, cookies

class RenderChallenged(RuntimeError):
    """A render whose document is a Cloudflare interstitial, not the page. `label` is the
    detect_cloudflare_challenge() verdict the caller records as meta.cloudflare."""

    def __init__(self, label: str, renderer: str):
        super().__init__(f"{renderer} render served a Cloudflare challenge [{label}]")
        self.label = label


def render_dom(url: str, timeout: int = 30, ua: str = DEFAULT_UA, proxy: str = None,
               screenshot_path: str = None, cf_challenge: bool = False):
    """Return (final_url, post-JS html, cookies, renderer, response).

    `response` is {status, headers, redirect_chain} when the engine already has them (Moli) and
    None for Chromium, whose page.content() does not — the caller then does one plain fetch.
    A screenshot or `cf_challenge=True` always renders on Chromium. Raises on no usable engine,
    a proxy/HTTP failure, an empty document, or a Moli DOM that is a Cloudflare interstitial.
    """
    import wp_browser
    engine, why = wp_browser.select_dom_engine(proxy, cf_challenge=cf_challenge,
                                               screenshot=bool(screenshot_path))
    if engine is None:
        raise RuntimeError(f"render: {why}")
    if engine == "moli":
        import wp_moli
        d = wp_moli.fetch_dom(url, timeout=timeout, ua=ua, proxy=wp_browser.resolve_proxy(proxy))
        # Moli cannot clear a managed challenge, so a Moli DOM that IS the interstitial is not the
        # page: raise it as a challenge so the caller escalates (raw fetch → Chromium → archive).
        hdrs = {(h.get("name") or "").lower(): h.get("value", "")
                for h in d["headers"] if isinstance(h, dict) and h.get("name")}
        label = detect_cloudflare_challenge(d["status"] or 200, hdrs, d["html"])
        if label:
            raise RenderChallenged(label, d["renderer"])
        return (d["final_url"], d["html"], d["cookies"], d["renderer"],
                {"status": d["status"], "headers": hdrs, "redirect_chain": d["redirect_chain"]})
    return (*_render_chromium(url, timeout=timeout, ua=ua, proxy=proxy,
                              screenshot_path=screenshot_path), None)


def _render_chromium(url: str, timeout: int = 30, ua: str = DEFAULT_UA, proxy: str = None,
                     screenshot_path: str = None):
    """Playwright/Chromium render; `screenshot_path` saves a full-page PNG of the rendered page —
    an evidentiary capture of what the target actually served (phishing-kit evidence)."""
    import wp_browser
    timeout = _floor_to(timeout)   # Playwright ms path bypasses the urllib floor
    from playwright.sync_api import sync_playwright  # optional
    with sync_playwright() as p:
        launch_kwargs = wp_browser.chromium_launch_kwargs(proxy)
        pcfg = launch_kwargs.get("proxy")
        browser = p.chromium.launch(**launch_kwargs)
        try:
            ctx = browser.new_context(user_agent=ua)
            page = ctx.new_page()
            resp = page.goto(url, timeout=timeout * 1000, wait_until="networkidle")
            status = resp.status if resp else None
            html = page.content()
            final_url = page.url
            cookies = ctx.cookies()
            if status == 407:
                raise RuntimeError(f"render: proxy rejected credentials (407) via "
                                   f"{pcfg['server'] if pcfg else 'env proxy'}")
            if not html or len(html) < 200:
                raise RuntimeError(f"render: HTTP {status}, {len(html or '')} bytes")
            if screenshot_path:
                try:
                    os.makedirs(os.path.dirname(screenshot_path) or ".", exist_ok=True)
                    page.screenshot(path=screenshot_path, full_page=True)
                except Exception as e:
                    print(f"[!] screenshot failed: {e}", file=sys.stderr)
            renderer = wp_browser.chromium_renderer_tag(browser)
        finally:
            browser.close()
    return final_url, html, cookies, renderer


# ---------------------------------------------------------- passive fallback

_WB_SNAP = re.compile(r"^(https?://web\.archive\.org/web/)(\d{4,14})([a-z]{2}_)?/(.+)$", re.I)


def wayback_raw_url(snap_url: str) -> str:
    """The `id_` form of a Wayback snapshot URL — the ORIGINAL response bytes, without the
    archive toolbar, rewritten links or archive.org headers. Non-Wayback input returns unchanged."""
    m = _WB_SNAP.match(snap_url or "")
    if not m:
        return snap_url
    return f"https://web.archive.org/web/{m.group(2)}id_/{m.group(4)}"


def wayback_closest(url: str, ua: str = DEFAULT_UA):
    """Nearest available Wayback snapshot for a URL (the newest), or (None, None).

    Delegates to wp_wayback.closest — the id_ redirect resolver, then the availability API, then
    the index — every request paced and guarded by wp_wayback_guard (run breaker, egress pacer,
    429/refusal cooldown). An archive that did not answer prints its reason so it is never
    misread as 'not archived'."""
    import wp_wayback
    snap, ts, err = wp_wayback.closest(url, ua=ua)
    if err:
        print(f"[!] Wayback lookup for {url} not definitive: {err}", file=sys.stderr)
    return snap, ts

def urlscan_intel(host: str, ua: str = DEFAULT_UA, limit: int = 20,
                  max_pages: int = 1, page_size: int = 100, free_only: bool = False):
    """urlscan.io search for prior scans of a host: related domains/IPs/ASNs + every scan.

    Paginates with `search_after` (up to `max_pages` pages of `page_size`) so a host with
    hundreds of scans is not silently truncated to one page. `recent_scans` stays capped at
    `limit` for compact display; `all_scans` holds every scan found (used to fetch every
    cached DOM). Sends the API-Key header when URLSCAN_API_KEY is set (higher rate limits and
    access to results anonymous search omits); otherwise runs keyless.

    `free_only=True` FORBIDS spending the credential: urlscan is a metered index, so a
    free-only run stays analytically keyless — no API-Key, single anonymous page."""
    out = {"query": host, "total": 0, "related_domains": [], "ips": [], "asns": [],
           "servers": [], "recent_scans": [], "all_scans": [], "pages": 0}
    _uk = None if free_only else _secret("URLSCAN_API_KEY")
    if free_only:
        max_pages = 1            # keyless anonymous search returns a single page anyway
    doms, ips, asns, servers = set(), set(), set(), set()
    search_after = None
    size = max(1, min(int(page_size), 100))
    latest_uid = None
    for _page in range(max(1, int(max_pages))):
        api = f"https://urlscan.io/api/v1/search/?q=domain:{host}&size={size}"
        if search_after:
            api += f"&search_after={search_after}"
        req_headers = {"User-Agent": ua}
        if _uk:
            req_headers["API-Key"] = _uk
        _rem = _lim = None
        try:
            req = urllib.request.Request(api, headers=req_headers)
            with urllib.request.urlopen(req, timeout=30) as r:
                if api_usage:
                    _rem, _lim = api_usage.rl_headers(r)
                data = json.load(r)
        except Exception as e:
            if not out["all_scans"]:      # only the first page failing is an error
                out["error"] = str(e)
            if api_usage:
                api_usage.record("urlscan", "search", credits=0, query=f"domain:{host}", ok=False)
            break
        if api_usage:
            api_usage.record("urlscan", "search", credits=1, query=f"domain:{host}",
                             results=data.get("total"), remaining=_rem, limit=_lim)
        out["pages"] += 1
        out["total"] = data.get("total", out["total"])
        results = data.get("results", []) or []
        for res in results:
            p = res.get("page", {})
            if p.get("domain"):
                doms.add(p["domain"])
            if p.get("ip"):
                ips.add(p["ip"])
            if p.get("asn"):
                asns.add(f"{p.get('asn')} {p.get('asnname', '')}".strip())
            if p.get("server"):
                servers.add(p["server"])
            uid = res.get("_id")
            latest_uid = latest_uid or uid
            # page.domain/ip/asn per scan: the aggregate `ips` above mixes in pages that merely
            # LOADED the host, so wp_origin_history dates the host's own hosting from these rows
            # (page.domain == host) instead.
            out["all_scans"].append({
                "uuid": uid, "url": p.get("url"), "time": res.get("task", {}).get("time"),
                "result": f"https://urlscan.io/result/{uid}/",
                "domain": p.get("domain"), "ip": p.get("ip"),
                "asn": p.get("asn"), "asnname": p.get("asnname"),
            })
        # advance the cursor. urlscan's `has_more` is NOT trustworthy (measured 2026-09-28: false on
        # a full page of 100 while `total` was 248 and page 2 held 100 fresh scans), so stop on an
        # empty page or once `total` is listed — bounded by max_pages as before.
        tot = data.get("total")
        if not results or (isinstance(tot, int) and len(out["all_scans"]) >= tot) \
                or (not isinstance(tot, int) and not data.get("has_more")):
            break
        sortv = results[-1].get("sort")
        if not sortv:
            break
        search_after = ",".join(str(x) for x in sortv) if isinstance(sortv, list) else str(sortv)
    out["related_domains"] = sorted(doms)[:40]
    out["ips"] = sorted(ips)[:40]
    out["asns"] = sorted(asns)[:20]
    out["servers"] = sorted(servers)[:20]
    out["recent_scans"] = out["all_scans"][:limit]
    # urlscan verdict/brand → feeds risk_signals triage. The compact SEARCH hit omits verdicts;
    # they live in the full RESULT endpoint (works on a normal key). Fetch it for the latest scan.
    if _uk and latest_uid:
        v = urlscan_verdict(latest_uid, ua=ua)
        if v:
            out["verdict"] = v
    return out


def urlscan_quotas(ua: str = DEFAULT_UA, timeout: int = 20):
    """ENTITLEMENT probe — GET /api/v1/quotas (free, not counted against any quota). Measured live
    2026-09-04 on a Pro team key: `limits.products` lists the licensed products (`pro`, `livescan`),
    `limits.<scope>.day.{limit,used,remaining}` per scope (search / retrieve / private / …),
    `limits.maxSearchResults`. Returns {'tier': 'pro'|'free', 'products', 'features', 'search_day',
    'retrieve_day', 'max_search_results', 'scope'} | {'error'} | None (keyless). Never raises;
    never returns the key."""
    key = _secret("URLSCAN_API_KEY")
    if not key:
        return None
    try:
        req = urllib.request.Request(URLSCAN_BASE + URLSCAN_ENDPOINTS.get("quotas", "/api/v1/quotas/"),
                                     headers={"User-Agent": ua, "API-Key": key})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            d = json.load(r)
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}", "tier": "unknown"}
    except Exception as e:  # noqa: BLE001
        return {"error": str(e), "tier": "unknown"}
    lim = d.get("limits") if isinstance(d, dict) and isinstance(d.get("limits"), dict) else {}
    if not lim or not isinstance(lim.get("products"), list):
        # absence of a field is not a measurement — leave the tier unknown so the Pro call itself
        # stays the probe (a persisted `free` would switch those calls off for the whole case)
        return {"tier": "unknown", "error": "quotas response carried no limits.products", "scope": (d or {}).get("scope")}
    products = [str(p) for p in lim["products"] if p]

    def _day(scope):
        day = ((lim.get(scope) or {}).get("day") or {}) if isinstance(lim.get(scope), dict) else {}
        return {k: day.get(k) for k in ("limit", "used", "remaining") if k in day}
    return {"tier": "pro" if "pro" in products else "free", "products": products,
            "features": [str(f) for f in (lim.get("features") or []) if f],
            "search_day": _day("search"), "retrieve_day": _day("retrieve"),
            "max_search_results": lim.get("maxSearchResults"), "scope": d.get("scope")}



def urlscan_verdict(uuid: str, ua: str = DEFAULT_UA, timeout: int = 30):
    """Fetch urlscan's verdict/brand for a scan UUID from the RESULT endpoint (verdicts are NOT in
    the search hit). Returns {'score','malicious','brands','categories','tags','engines','labels',
    'result'} or None. Works on a normal key; a Pro key adds the engine verdicts (`verdicts.engines`
    — e.g. urlscan-ml score/100) and result `labels` (e.g. visual.brandai), which are evidence for the
    ledger at zero extra cost. NEVER raises."""
    headers = {"User-Agent": ua}
    key = _secret("URLSCAN_API_KEY")
    if key:
        headers["API-Key"] = key
    try:
        req = urllib.request.Request(f"https://urlscan.io/api/v1/result/{uuid}/", headers=headers)
        _rem = _lim = None
        with urllib.request.urlopen(req, timeout=timeout) as r:
            if api_usage:
                _rem, _lim = api_usage.rl_headers(r)
            data = json.load(r) or {}
            v = data.get("verdicts") or {}
    except Exception:
        if api_usage:
            api_usage.record("urlscan", "result", credits=0, query=uuid, ok=False)
        return None
    if api_usage:
        api_usage.record("urlscan", "result", credits=1, query=uuid, remaining=_rem, limit=_lim)
    ov = v.get("overall") or {}

    def _bn(b):
        return b.get("name") if isinstance(b, dict) else b
    brands = sorted({_bn(b) for b in ((ov.get("brands") or []) + ((v.get("urlscan") or {}).get("brands") or []))
                     if _bn(b)})
    # `verdicts.engines` shape measured live 2026-09-03: {score, malicious, enginesTotal,
    # maliciousTotal, benignTotal, maliciousVerdicts[], benignVerdicts[], hasVerdicts, tags[]};
    # score is -99 when no engine has looked at the scan — that is "no verdict", not a score.
    eng = v.get("engines") if isinstance(v.get("engines"), dict) else {}
    engines = None
    if eng and (eng.get("hasVerdicts") or (eng.get("enginesTotal") or 0) > 0):
        raw_score = eng.get("score")
        engines = {"score": raw_score if isinstance(raw_score, (int, float)) and raw_score >= 0 else None,
                   "malicious": bool(eng.get("malicious")),
                   "total": eng.get("enginesTotal"), "malicious_total": eng.get("maliciousTotal"),
                   "benign_total": eng.get("benignTotal"),
                   "malicious_verdicts": [str(x) for x in (eng.get("maliciousVerdicts") or []) if x][:8],
                   "tags": [str(x) for x in (eng.get("tags") or []) if x][:8]}
    labels = sorted({str(x) for x in (data.get("labels") or []) if x}) if isinstance(data.get("labels"), list) else []
    if not (ov or brands or engines or labels):
        return None
    return {"score": ov.get("score"), "malicious": ov.get("malicious"), "brands": brands,
            "categories": ov.get("categories") or [], "tags": ov.get("tags") or [],
            "engines": engines, "labels": labels,
            "result": f"https://urlscan.io/result/{uuid}/"}


def urlscan_hostname(host: str, ua: str = DEFAULT_UA, timeout: int = 30, max_pages: int = None,
                     free_only: bool = False):
    """urlscan **Pro** hostname lifecycle: every A/AAAA/NS/MX/SOA record, CT / zonefile / scan
    first-sighting and the scan history urlscan holds for `host`, folded into dated ERAS.

    The index is the previous-owner record: for a drop-catch host it shows the registrar-parking
    NS + A records years before the current registration, without rendering an archive. Returns

        {"host", "first_seen", "last_seen", "ct_first", "zonefile_first", "scan_first",
         "a_eras": [{"type","value","first_seen","last_seen","days","asn","first_seen_open"}, …],
         "ns_eras": [...], "mx": [...], "soa": [...],
         "scan_ips": [...], "records": <daily rows read>, "pages": n, "truncated": bool,
         "oldest_seen_on": "YYYY-MM-DD"}

    The index is PER-DAY rows (one per record per day, newest first), so rows are folded by
    `sub_id` into eras (min first_seen / max last_seen per type+value). When the walk stops at the
    page cap (`truncated`), every era whose first observation lies on/after the oldest day reached is
    LEFT-CENSORED: `first_seen_open=True` means "hosted since at least this date", not "hosting
    began here" — the timeline renders it as an open start, never as a dated beginning. Each page is
    one retrieve credit (any size), so pages are requested at the API maximum (`page_limit`, ref data,
    10 000 rows) to reach a drop-catch host's years-old parking era in few calls.

    Or {"skipped": …} (keyless / free_only / non-Pro) or {"error": …}. NEVER raises — enrich_live
    collects it through an executor whose result() re-raises, and one bad leg must not abort the
    whole pivot's enrichment."""
    if free_only:
        return {"skipped": "--free-only (urlscan Pro not spent)"}
    key = _secret("URLSCAN_API_KEY")
    if not key:
        return {"skipped": "no URLSCAN_API_KEY"}
    cfg, eps = URLSCAN_HOSTNAME_CFG, URLSCAN_ENDPOINTS
    pages_cap = int(max_pages if max_pages is not None else cfg.get("max_pages", 3))
    page_limit = max(10, min(10000, int(cfg.get("page_limit", 1000))))
    era_types = set(cfg.get("era_types") or [])
    summary_days = set(cfg.get("summary_seen_on") or [])
    first_map = dict(cfg.get("first_seen_sources") or {})
    scan_prefix = cfg.get("scan_prefix") or "VIA-SCAN"
    headers = {"User-Agent": ua, "API-Key": key}
    out = {"host": host, "first_seen": None, "last_seen": None, "ct_first": None,
           "zonefile_first": None, "scan_first": None, "a_eras": [], "ns_eras": [], "mx": [],
           "soa": [], "scan_ips": [], "records": 0, "pages": 0, "truncated": False,
           "oldest_seen_on": None}
    eras = {}                     # (type, value) -> {first_seen, last_seen, asn}
    scan_ips = set()
    page_state = None
    oldest_day = None             # the oldest daily row reached — the censoring boundary when truncated
    try:
        for _ in range(max(1, pages_cap)):
            path = (eps["hostname_page"].format(host=quote(host), limit=page_limit,
                                                page_state=quote(page_state, safe=""))
                    if page_state else eps["hostname"].format(host=quote(host), limit=page_limit))
            _rem = _lim = None
            try:
                req = urllib.request.Request(URLSCAN_BASE + path, headers=headers)
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    if api_usage:
                        _rem, _lim = api_usage.rl_headers(r)
                    data = json.load(r)
            except urllib.error.HTTPError as e:
                if api_usage:
                    api_usage.record("urlscan", "hostname", credits=0, query=host, ok=False)
                if e.code in (401, 402, 403):
                    if out["pages"]:
                        break             # keep what earlier pages gave us
                    return {"skipped": "urlscan hostname index needs a Pro key", "host": host}
                if out["pages"]:
                    break
                return {"error": f"HTTP {e.code}", "host": host}
            except Exception as e:  # noqa: BLE001 — transport fault: degrade, never raise
                if api_usage:
                    api_usage.record("urlscan", "hostname", credits=0, query=host, ok=False)
                if out["pages"]:
                    break
                return {"error": str(e), "host": host}
            rows = (data.get("results") or []) if isinstance(data, dict) else []
            if api_usage:
                api_usage.record("urlscan", "hostname", credits=1, query=host, results=len(rows),
                                 remaining=_rem, limit=_lim)
            out["pages"] += 1
            out["records"] += len(rows)
            for row in rows:
                if not isinstance(row, dict):
                    continue
                src = str(row.get("source") or "")
                sub = str(row.get("sub_id") or "")
                fs, ls = row.get("first_seen"), row.get("last_seen")
                if str(row.get("seen_on") or "") in summary_days or not sub:
                    # per-source rollup row: whole-index first/last for that source
                    fld = first_map.get(src)
                    if fld and fs and (out.get(fld) is None or fs < out[fld]):
                        out[fld] = fs
                    if src == "seenDates" and ls and (out["last_seen"] is None or ls > out["last_seen"]):
                        out["last_seen"] = ls
                    continue
                day = str(row.get("seen_on") or "")[:10]
                if day and (oldest_day is None or day < oldest_day):
                    oldest_day = day
                rtype, _, value = sub.partition("#")
                value = value.strip().rstrip(".").lower()
                if not value:
                    continue
                if rtype == scan_prefix:
                    scan_ips.add(value)
                    continue
                if rtype not in era_types:
                    continue
                slot = eras.setdefault((rtype, value), {"type": rtype, "value": value,
                                                       "first_seen": fs, "last_seen": ls, "asn": None})
                if fs and (slot["first_seen"] is None or fs < slot["first_seen"]):
                    slot["first_seen"] = fs
                if ls and (slot["last_seen"] is None or ls > slot["last_seen"]):
                    slot["last_seen"] = ls
                d = row.get("data") if isinstance(row.get("data"), dict) else {}
                asn = (d.get("asn") or {}).get("asn") if isinstance(d.get("asn"), dict) else None
                if asn and not slot["asn"]:
                    slot["asn"] = str(asn)
            page_state = data.get("pageState") if isinstance(data, dict) else None
            if not rows or not page_state:
                page_state = None
                break
        out["truncated"] = bool(page_state)
        out["oldest_seen_on"] = oldest_day
    except Exception as e:  # noqa: BLE001 — belt and braces: the contract is never-raise
        out["error"] = str(e)

    def _days(e):
        try:
            a = datetime.datetime.fromisoformat(str(e["first_seen"]).replace("Z", "+00:00"))
            b = datetime.datetime.fromisoformat(str(e["last_seen"] or e["first_seen"]).replace("Z", "+00:00"))
            return max(0, (b - a).days)
        except Exception:  # noqa: BLE001
            return None
    ordered = sorted(eras.values(), key=lambda e: (e["first_seen"] or "", e["type"], e["value"]))
    for e in ordered:
        e["days"] = _days(e)
        # left-censored: rows arrive newest-first, so an era whose EARLIEST row sits on the oldest
        # day the truncated walk reached may have older rows we never read — its start is unknown.
        # An era whose earliest row is later than that day genuinely began there (every newer row was read).
        e["first_seen_open"] = bool(out["truncated"] and oldest_day and e["first_seen"]
                                    and str(e["first_seen"])[:10] <= oldest_day)
        if e["type"] in ("A", "AAAA"):
            out["a_eras"].append(e)
        elif e["type"] == "NS":
            out["ns_eras"].append(e)
        elif e["type"] == "MX":
            out["mx"].append(e)
        elif e["type"] == "SOA":
            out["soa"].append(e)
        if e["first_seen"] and (out["first_seen"] is None or e["first_seen"] < out["first_seen"]):
            out["first_seen"] = e["first_seen"]
        if e["last_seen"] and (out["last_seen"] is None or e["last_seen"] > out["last_seen"]):
            out["last_seen"] = e["last_seen"]
    out["scan_ips"] = sorted(scan_ips)
    return out


_BINARY_JUNK_THRESHOLD = 0.05


def dom_is_binary_junk(html: str) -> bool:
    """True when decoded 'HTML' is actually undecoded binary — a heavy run of control bytes or
    the Unicode replacement character, the fingerprint of a gzip/deflate body decoded straight
    as UTF-8 because Content-Encoding lied or was missing (before _decode_body ran, or the
    store used a compression scheme that is neither gzip nor deflate)."""
    if not html:
        return False
    sample = html[:4000]
    bad = sum(1 for ch in sample if ch == "\ufffd" or (ord(ch) < 32 and ch not in "\t\n\r"))
    return (bad / max(len(sample), 1)) > _BINARY_JUNK_THRESHOLD


def urlscan_dom(intel: dict, ua: str = DEFAULT_UA, timeout: int = 30, free_only: bool = False):
    """Fetch the rendered DOM of the most recent urlscan scan for a host, so a dead /
    blocked target is still analyzable from a third-party capture. Returns (html, id)
    or ('', None). urlscan stores the DOM at /dom/<uuid>/ — which returns 403 without an
    API-Key, so the key (when set) is sent; keyless (or free_only) degrades to ('', None).
    The body is decoded per its actual Content-Encoding (_decode_body, gzip-magic-sniffing
    fallback included) before UTF-8 — a bare `.decode()` of a gzip body is binary junk."""
    _uk = None if free_only else _secret("URLSCAN_API_KEY")
    hdr = {"User-Agent": ua}
    if _uk:
        hdr["API-Key"] = _uk
    for scan in (intel or {}).get("recent_scans", []):
        res = scan.get("result") or ""
        m = re.search(r"/result/([0-9a-f\-]{16,})", res)
        if not m:
            continue
        uid = m.group(1)
        try:
            req = urllib.request.Request(f"https://urlscan.io/dom/{uid}/", headers=hdr)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
                enc = r.headers.get("Content-Encoding") if hasattr(r, "headers") else None
            html = _decode_body(raw, enc).decode("utf-8", "ignore")
            if html and len(html) > 200:
                return html, uid
        except Exception:
            continue
    return "", None

def urlscan_dom_all(intel: dict, ua: str = DEFAULT_UA, timeout: int = 15,
                    max_doms: int = 25, min_len: int = 200,
                    max_attempts: int = None, deadline: float = None, free_only: bool = False):
    """Fetch EVERY distinct cached DOM urlscan holds for a host (not just the newest, which
    urlscan_dom returns). Iterates `all_scans` (falls back to recent_scans), pulls
    /dom/<uuid>/ (sending the API-Key when set — the endpoint is 403 keyless), decodes each
    body per its Content-Encoding (_decode_body), and dedupes on the DECODED text's sha256.
    Returns [{'uuid','url','time','sha256','html'}], newest first, capped at max_doms distinct
    DOMs.

    BOUNDED so a host with hundreds of scans whose DOMs 404/time out cannot stall the caller:
    stops after `max_attempts` fetches (default max_doms*3+10) or when `deadline`
    (time.monotonic()) passes — whichever comes first."""
    import hashlib
    import time as _t
    scans = (intel or {}).get("all_scans") or (intel or {}).get("recent_scans") or []
    if max_attempts is None:
        max_attempts = max_doms * 3 + 10
    _uk = None if free_only else _secret("URLSCAN_API_KEY")   # /dom/ is 403 without a key
    hdr = {"User-Agent": ua}
    if _uk:
        hdr["API-Key"] = _uk
    seen_hashes: set[str] = set()
    out = []
    attempts = 0
    _rem = _lim = None
    for scan in scans:
        if len(out) >= max_doms or attempts >= max_attempts:
            break
        if deadline is not None and _t.monotonic() > deadline:
            break
        uid = scan.get("uuid")
        if not uid:
            m = re.search(r"/result/([0-9a-f\-]{16,})", scan.get("result") or "")
            uid = m.group(1) if m else None
        if not uid:
            continue
        attempts += 1
        try:
            req = urllib.request.Request(f"https://urlscan.io/dom/{uid}/", headers=hdr)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                if api_usage:
                    _rem, _lim = api_usage.rl_headers(r)
                raw = r.read()
                enc = r.headers.get("Content-Encoding") if hasattr(r, "headers") else None
            html = _decode_body(raw, enc).decode("utf-8", "ignore")
        except Exception:
            continue
        if not html or len(html) < min_len:
            continue
        h = hashlib.sha256(html.encode("utf-8", "ignore")).hexdigest()
        if h in seen_hashes:
            continue
        seen_hashes.add(h)
        out.append({"uuid": uid, "url": scan.get("url"), "time": scan.get("time"),
                    "sha256": h, "html": html})
    # metered: with the API-Key each /dom/ fetch is a licensed call — log the batch (RULE:
    # every metered third-party call lands in MEMORY/api_usage.jsonl). Keyless = 403, not billed.
    if api_usage and _uk and attempts:
        api_usage.record("urlscan", "dom", credits=attempts,
                         query=(intel or {}).get("query"), results=len(out),
                         remaining=_rem, limit=_lim)
    return out


def urlscan_result_requests(uuid: str, ua: str = DEFAULT_UA, timeout: int = 30):
    """The RESULT endpoint's `data.requests` list for a scan uuid — every HTTP transaction
    urlscan recorded during navigation; each response entry carries a sha256 `hash` urlscan
    stores verbatim at /responses/<hash>/. None on transport failure/bad JSON, else a list
    (possibly empty)."""
    headers = {"User-Agent": ua}
    key = _secret("URLSCAN_API_KEY")
    if key:
        headers["API-Key"] = key
    try:
        req = urllib.request.Request(f"{URLSCAN_BASE}/api/v1/result/{uuid}/", headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.load(r) or {}
        return (data.get("data") or {}).get("requests") or []
    except Exception:
        return None


def urlscan_response(sha256: str, ua: str = DEFAULT_UA, timeout: int = 20):
    """Fetch one stored HTTP response body by its urlscan sha256 (/responses/<hash>/), decoded
    per Content-Encoding (_decode_body, gzip-sniffing fallback included). '' on failure —
    never raises."""
    headers = {"User-Agent": ua}
    key = _secret("URLSCAN_API_KEY")
    if key:
        headers["API-Key"] = key
    try:
        req = urllib.request.Request(f"{URLSCAN_BASE}/responses/{sha256}/", headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            enc = r.headers.get("Content-Encoding") if hasattr(r, "headers") else None
        return _decode_body(raw, enc).decode("utf-8", "ignore")
    except Exception:
        return ""


def urlscan_dom_assets(uuid: str, ua: str = DEFAULT_UA, timeout: int = 20, free_only: bool = False):
    """For a page RECOVERED from a urlscan DOM capture (the live site cannot be fetched), pull
    that SAME scan's own stored JS/CSS responses (data.requests[].response.hash ->
    /responses/<sha256>/) so the existing asset layer (wp_assets.extract_api_endpoints /
    wp_extract.extract_app_downloads — API base, websocket host, download/app links) still has
    bundle text to read, instead of the empty result a same-origin fetch against a dead site
    would otherwise leave. Keyless/free_only -> '' (the /responses/ endpoint is licensed).
    Capped via references/urlscan_endpoints.json -> dom_assets.max_resources; every fetch is
    ledgered as one batch, like urlscan_dom_all. Returns the concatenated resource text."""
    if free_only or not _secret("URLSCAN_API_KEY"):
        return ""
    reqs = urlscan_result_requests(uuid, ua=ua, timeout=timeout)
    if not reqs:
        return ""
    cfg = URLSCAN_DOM_ASSETS_CFG
    exts = tuple(cfg.get("extensions") or (".js", ".css"))
    mimes = tuple(cfg.get("mime_prefixes") or ("javascript", "css"))
    cap = int(cfg.get("max_resources") or 10)
    seen, texts = set(), []
    for entry in reqs:
        if len(texts) >= cap:
            break
        resp = (entry or {}).get("response") or {}
        h = resp.get("hash")
        if not h or h in seen:
            continue
        meta = resp.get("response") or {}
        url = str(meta.get("url") or "")
        mime = str(meta.get("mimeType") or "").lower()
        if not (url.lower().endswith(exts) or any(m in mime for m in mimes)):
            continue
        seen.add(h)
        text = urlscan_response(h, ua=ua, timeout=timeout)
        if text:
            texts.append(text)
    if texts and api_usage:
        api_usage.record("urlscan", "responses", credits=len(texts), query=uuid, results=len(texts))
    return "\n".join(texts)

if HAVE_REQUESTS:
    class _UAScopedSession(requests.Session):
        """requests Session that re-scopes User-Agent on every redirect hop
        (wp_wayback_guard.ua_for): requests keeps a request's headers across redirects, which
        would carry the archive.org UA to whatever host the archive redirects to."""

        def __init__(self, base_ua: str):
            super().__init__()
            self._base_ua = base_ua

        def rebuild_auth(self, prepared_request, response):
            super().rebuild_auth(prepared_request, response)
            import wp_wayback_guard as wg
            prepared_request.headers["User-Agent"] = wg.ua_for(prepared_request.url, self._base_ua)

def wayback_save(url: str, ua: str = DEFAULT_UA, timeout: int = 40):
    """Submit a URL to the Wayback Machine's Save Page Now. Returns a dict with the
    archived snapshot URL (or an error). Passive-safe: it makes web.archive.org fetch the
    page, so the archive box (not you) touches the target from then on. Routed through
    wp_wayback_guard: a tripped run breaker or an egress cooldown returns a
    {"skipped": ..., "skipped_kind": "breaker"} dict without making a request; otherwise the
    request waits for its paced playback slot, and a 429 / refused connection arms the cooldown."""
    import wp_wayback_guard as wg
    reason = wg.admit("web.archive.org", "playback")
    if reason:
        return {"skipped": reason, "skipped_kind": "breaker"}
    timeout = _floor_to(timeout)   # requests path bypasses the urllib floor
    save_url = "https://web.archive.org/save/" + url
    # A REAL capture URL is /web/<14-digit-timestamp>/<original>. The bare /save/ endpoint URL
    # is NOT a snapshot — SPN returns it when it could not crawl the target (e.g. a CF wall).
    # Returning that as a "snapshot" makes the caller analyze archive.org's own wrapper page.
    _CAPTURE_RE = re.compile(r"https?://web\.archive\.org/web/\d{4,14}/")

    def _valid(snap):
        return bool(snap) and bool(_CAPTURE_RE.match(snap))
    try:
        # requests follows the redirect to the created snapshot; note Content-Location too
        if HAVE_REQUESTS:
            with _UAScopedSession(ua) as s:
                r = s.get(save_url, headers={"User-Agent": wg.ua_for(save_url, ua)},
                          timeout=timeout, allow_redirects=True)
            snap = r.headers.get("Content-Location") or ""
            if snap and not snap.startswith("http"):
                snap = "https://web.archive.org" + snap
            snap = snap or r.url
            if _valid(snap):
                wg.record(True, kind="save")
                wg.observe("web.archive.org", True)
                return {"snapshot": snap, "status": r.status_code}
            wg.record(not wg.is_failure(r.status_code), kind="save")
            wg.observe("web.archive.org", r.status_code, r.headers)
            return {"error": f"no capture created (status {r.status_code}) — target likely "
                             f"un-crawlable (Cloudflare/robots)", "status": r.status_code}
        req = wg.scope_ua(urllib.request.Request(save_url), ua)  # re-scoped per redirect hop
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            cl = resp.headers.get("Content-Location") or ""
            snap = ("https://web.archive.org" + cl) if cl else resp.geturl()
            if _valid(snap):
                wg.record(True, kind="save")
                wg.observe("web.archive.org", True)
                return {"snapshot": snap, "status": resp.status}
            wg.record(not wg.is_failure(resp.status), kind="save")
            return {"error": f"no capture created (status {resp.status})", "status": resp.status}
    except Exception as e:
        wg.record(not wg.is_failure(e), kind="save")
        wg.observe("web.archive.org", e, getattr(e, "headers", None))
        return {"error": str(e)}

def urlscan_submit(url: str, timeout: int = 30, visibility: str = None):
    """Submit a URL to urlscan.io for a fresh scan (needs URLSCAN_API_KEY). Returns the
    api/result URLs + scan UUID, or an error/'no key'. This actively enqueues a new scan
    (vs urlscan_search/urlscan_intel which only read existing scans).

    OPSEC: visibility defaults to `URLSCAN_VISIBILITY` env if set, else 'unlisted'. On a **Pro**
    key set `URLSCAN_VISIBILITY=private` — a private scan of hostile infra is team-only and never
    appears in the public feed, so the operator can't discover that you scanned them. (On the free
    tier 'private' is rejected; 'unlisted' is the safe default.)"""
    timeout = _floor_to(timeout)   # requests path bypasses the urllib floor
    key = _secret("URLSCAN_API_KEY")
    if not key:
        return {"skipped": "no URLSCAN_API_KEY"}
    if visibility is None:
        visibility = _secret("URLSCAN_VISIBILITY") or "unlisted"
    try:
        payload = json.dumps({"url": url, "visibility": visibility}).encode()
        if HAVE_REQUESTS:
            r = requests.post("https://urlscan.io/api/v1/scan/", data=payload, timeout=timeout,
                              headers={"API-Key": key, "Content-Type": "application/json"})
            j = r.json()
        else:
            req = urllib.request.Request("https://urlscan.io/api/v1/scan/", data=payload,
                                         headers={"API-Key": key, "Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                j = json.loads(resp.read().decode("utf-8", "ignore"))
        if j.get("uuid"):
            if api_usage:
                api_usage.record("urlscan", "scan", credits=1, query=url,
                                 results=j.get("visibility", visibility))
            return {"uuid": j["uuid"], "result": j.get("result"), "api": j.get("api"),
                    "visibility": j.get("visibility", visibility)}
        if api_usage:
            api_usage.record("urlscan", "scan", credits=0, query=url, ok=False)
        return {"error": j.get("message") or j.get("description") or str(j)[:200]}
    except Exception as e:
        return {"error": str(e)}


# --- tracking / analytics / ad IDs: (label, regex, pivot-hint)


__all__ = [_n for _n in dir() if not _n.startswith("__")]
