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
}
_USCAN_REF = load_ref(ref_path(__file__, "urlscan_endpoints.json"), _USCAN_FALLBACK)
URLSCAN_ENDPOINTS = _USCAN_REF["endpoints"]
URLSCAN_HOSTNAME_CFG = _USCAN_REF["hostname"]
# result labels that describe structure/hosting class, never a finding — a verdict row is emitted
# only on signal (malicious / score>0 / brand / a label outside this set)
URLSCAN_STRUCTURAL_LABELS = frozenset((_USCAN_REF.get("verdict") or _USCAN_FALLBACK["verdict"])["structural_labels"])
URLSCAN_BASE = "https://urlscan.io"


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
            out["all_scans"].append({
                "uuid": uid, "url": p.get("url"), "time": res.get("task", {}).get("time"),
                "result": f"https://urlscan.io/result/{uid}/",
            })
        # advance the cursor; stop when the API says there is no more or a page came back empty
        if not results or not data.get("has_more"):
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


def urlscan_dom(intel: dict, ua: str = DEFAULT_UA, timeout: int = 30, free_only: bool = False):
    """Fetch the rendered DOM of the most recent urlscan scan for a host, so a dead /
    blocked target is still analyzable from a third-party capture. Returns (html, id)
    or ('', None). urlscan stores the DOM at /dom/<uuid>/ — which returns 403 without an
    API-Key, so the key (when set) is sent; keyless (or free_only) degrades to ('', None)."""
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
                html = r.read().decode("utf-8", "ignore")
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
    /dom/<uuid>/ (sending the API-Key when set — the endpoint is 403 keyless), and dedupes
    count once. Returns [{'uuid','url','time','sha256','html'}], newest first, capped at
    max_doms distinct DOMs.

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
                html = r.read().decode("utf-8", "ignore")
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
