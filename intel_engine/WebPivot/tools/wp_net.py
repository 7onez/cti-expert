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

class _RecordingRedirectHandler(urllib.request.HTTPRedirectHandler):
    """urllib redirect handler that records each hop (from-url, status, to-url)."""
    def __init__(self, sink):
        self._sink = sink

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self._sink.append({"from": req.full_url, "status": code, "to": newurl})
        return super().redirect_request(req, fp, code, msg, headers, newurl)

def fetch(url: str, timeout: int = 20, ua: str = DEFAULT_UA, proxy: str = None,
          redirects_out: list = None, origin: str = None):
    """Return (final_url, status, headers_dict, body_bytes). Follows redirects.

    When `proxy` is given (e.g. 'http://10.0.0.5:8080'), the request is routed through it
    on both the requests and the urllib stdlib path. None → direct connection (unchanged).
    Sends a full browser header profile so basic bot filters don't reset the connection.
    If `redirects_out` (a list) is passed, each redirect hop is appended to it as
    {from,status,to}; callers that don't need the chain simply omit it (unchanged behavior).
    When `origin` is given, an `Origin:` request header is added — used to observe the
    server's CORS response (which origins/backends it trusts); None → omit it (unchanged).
    """
    reqh = _browser_headers(ua)
    if origin:
        reqh["Origin"] = origin
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

def render_dom(url: str, timeout: int = 30, ua: str = DEFAULT_UA, proxy: str = None,
               screenshot_path: str = None):
    """Return post-JS rendered HTML using Playwright (chromium). Requires playwright.

    `proxy` (if given) is passed to chromium so the rendered fetch egresses through it.
    `screenshot_path` (if given) saves a full-page PNG of the rendered page — an
    evidentiary capture of what the target actually served (phishing-kit evidence).
    """
    from playwright.sync_api import sync_playwright  # optional
    with sync_playwright() as p:
        launch_kwargs = {"headless": True}
        if proxy:
            launch_kwargs["proxy"] = {"server": proxy}
        browser = p.chromium.launch(**launch_kwargs)
        ctx = browser.new_context(user_agent=ua)
        page = ctx.new_page()
        page.goto(url, timeout=timeout * 1000, wait_until="networkidle")
        html = page.content()
        final_url = page.url
        cookies = ctx.cookies()
        if screenshot_path:
            try:
                os.makedirs(os.path.dirname(screenshot_path) or ".", exist_ok=True)
                page.screenshot(path=screenshot_path, full_page=True)
            except Exception as e:
                print(f"[!] screenshot failed: {e}", file=sys.stderr)
        browser.close()
    return final_url, html, cookies


# ---------------------------------------------------------- passive fallback

def wayback_closest(url: str, ua: str = DEFAULT_UA):
    """Nearest available Wayback snapshot for a URL, or (None, None).

    Tries the availability API, then the CDX API as a backup. Prints a distinct
    notice on HTTP 429 so callers don't misread throttling as 'not archived'.
    """
    import urllib.parse
    q = urllib.parse.quote(url, safe="")
    # 1) availability API (lightest)
    api = "http://archive.org/wayback/available?url=" + q
    try:
        req = urllib.request.Request(api, headers={"User-Agent": ua})
        with urllib.request.urlopen(req, timeout=25) as r:
            snap = json.load(r).get("archived_snapshots", {}).get("closest", {})
        if snap.get("available") and snap.get("url"):
            return snap["url"], snap.get("timestamp")
    except urllib.error.HTTPError as e:
        if e.code == 429:
            print("[!] archive.org rate-limited (429) — retry later or use a saved snapshot",
                  file=sys.stderr)
    except Exception:
        pass
    # 2) CDX backup — last 200 HTML capture
    host = urlparse(url if url.startswith("http") else "http://" + url).netloc or url
    cdx = (f"http://web.archive.org/cdx/search/cdx?url={host}&output=json"
           f"&filter=statuscode:200&limit=-1")
    try:
        req = urllib.request.Request(cdx, headers={"User-Agent": ua})
        with urllib.request.urlopen(req, timeout=30) as r:
            rows = json.load(r)
        if rows and len(rows) > 1:
            ts, orig = rows[-1][1], rows[-1][2]
            return f"https://web.archive.org/web/{ts}id_/{orig}", ts
    except Exception:
        pass
    return None, None

def urlscan_intel(host: str, ua: str = DEFAULT_UA, limit: int = 20):
    """urlscan.io search for prior scans of a host: related domains/IPs/ASNs.

    Sends the API-Key header when URLSCAN_API_KEY is set (higher rate limits and
    access to results anonymous search omits); otherwise runs keyless as before.
    """
    out = {"query": host, "total": 0, "related_domains": [], "ips": [], "asns": [],
           "servers": [], "recent_scans": []}
    try:
        api = f"https://urlscan.io/api/v1/search/?q=domain:{host}&size={limit}"
        req_headers = {"User-Agent": ua}
        _uk = _secret("URLSCAN_API_KEY")
        if _uk:
            req_headers["API-Key"] = _uk
        req = urllib.request.Request(api, headers=req_headers)
        _rem = _lim = None
        with urllib.request.urlopen(req, timeout=30) as r:
            if api_usage:
                _rem, _lim = api_usage.rl_headers(r)
            data = json.load(r)
    except Exception as e:
        out["error"] = str(e)
        if api_usage:
            api_usage.record("urlscan", "search", credits=0, query=f"domain:{host}", ok=False)
        return out
    if api_usage:
        api_usage.record("urlscan", "search", credits=1, query=f"domain:{host}",
                         results=data.get("total"), remaining=_rem, limit=_lim)
    out["total"] = data.get("total", 0)
    doms, ips, asns, servers = set(), set(), set(), set()
    for res in data.get("results", []):
        p = res.get("page", {})
        if p.get("domain"):
            doms.add(p["domain"])
        if p.get("ip"):
            ips.add(p["ip"])
        if p.get("asn"):
            asns.add(f"{p.get('asn')} {p.get('asnname', '')}".strip())
        if p.get("server"):
            servers.add(p["server"])
        out["recent_scans"].append({
            "url": p.get("url"), "time": res.get("task", {}).get("time"),
            "result": f"https://urlscan.io/result/{res.get('_id')}/",
        })
    out["related_domains"] = sorted(doms)[:40]
    out["ips"] = sorted(ips)[:40]
    out["asns"] = sorted(asns)[:20]
    out["servers"] = sorted(servers)[:20]
    out["recent_scans"] = out["recent_scans"][:limit]
    # urlscan verdict/brand → feeds risk_signals triage. The compact SEARCH hit omits verdicts;
    # they live in the full RESULT endpoint (works on a normal key). Fetch it for the latest scan.
    if _uk:
        uid = next((res.get("_id") for res in data.get("results", []) if res.get("_id")), None)
        if uid:
            v = urlscan_verdict(uid, ua=ua)
            if v:
                out["verdict"] = v
    return out


def urlscan_verdict(uuid: str, ua: str = DEFAULT_UA, timeout: int = 30):
    """Fetch urlscan's verdict/brand for a scan UUID from the RESULT endpoint (verdicts are NOT in
    the search hit). Returns {'score','malicious','brands','categories','tags','result'} or None.
    Works on a normal key; a Pro key just has richer engine/community verdicts."""
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
            v = (json.load(r).get("verdicts") or {})
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
    if not (ov or brands):
        return None
    return {"score": ov.get("score"), "malicious": ov.get("malicious"), "brands": brands,
            "categories": ov.get("categories") or [], "tags": ov.get("tags") or [],
            "result": f"https://urlscan.io/result/{uuid}/"}

def urlscan_dom(intel: dict, ua: str = DEFAULT_UA, timeout: int = 30):
    """Fetch the rendered DOM of the most recent urlscan scan for a host, so a dead /
    blocked target is still analyzable from a third-party capture. Returns (html, id)
    or ('', None). urlscan stores the DOM at /dom/<uuid>/."""
    for scan in (intel or {}).get("recent_scans", []):
        res = scan.get("result") or ""
        m = re.search(r"/result/([0-9a-f\-]{16,})", res)
        if not m:
            continue
        uid = m.group(1)
        try:
            req = urllib.request.Request(f"https://urlscan.io/dom/{uid}/",
                                         headers={"User-Agent": ua})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                html = r.read().decode("utf-8", "ignore")
            if html and len(html) > 200:
                return html, uid
        except Exception:
            continue
    return "", None

def wayback_save(url: str, ua: str = DEFAULT_UA, timeout: int = 40):
    """Submit a URL to the Wayback Machine's Save Page Now. Returns a dict with the
    archived snapshot URL (or an error). Passive-safe: it makes web.archive.org fetch the
    page, so the archive box (not you) touches the target from then on."""
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
            r = requests.get(save_url, headers={"User-Agent": ua}, timeout=timeout,
                             allow_redirects=True)
            snap = r.headers.get("Content-Location") or ""
            if snap and not snap.startswith("http"):
                snap = "https://web.archive.org" + snap
            snap = snap or r.url
            if _valid(snap):
                return {"snapshot": snap, "status": r.status_code}
            return {"error": f"no capture created (status {r.status_code}) — target likely "
                             f"un-crawlable (Cloudflare/robots)", "status": r.status_code}
        req = urllib.request.Request(save_url, headers={"User-Agent": ua})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            cl = resp.headers.get("Content-Location") or ""
            snap = ("https://web.archive.org" + cl) if cl else resp.geturl()
            if _valid(snap):
                return {"snapshot": snap, "status": resp.status}
            return {"error": f"no capture created (status {resp.status})", "status": resp.status}
    except Exception as e:
        return {"error": str(e)}

def urlscan_submit(url: str, timeout: int = 30, visibility: str = None):
    """Submit a URL to urlscan.io for a fresh scan (needs URLSCAN_API_KEY). Returns the
    api/result URLs + scan UUID, or an error/'no key'. This actively enqueues a new scan
    (vs urlscan_search/urlscan_intel which only read existing scans).

    OPSEC: visibility defaults to `URLSCAN_VISIBILITY` env if set, else 'unlisted'. On a **Pro**
    key set `URLSCAN_VISIBILITY=private` — a private scan of hostile infra is team-only and never
    appears in the public feed, so the operator can't discover that you scanned them. (On the free
    tier 'private' is rejected; 'unlisted' is the safe default.)"""
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
