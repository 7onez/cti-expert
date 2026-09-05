#!/usr/bin/env python3
# CTI Expert — ChongLuaDao (CLD) premium API client.
# First-party threat-intelligence connector for chongluadao.vn.
"""
cld_api.py — one stdlib client for both ChongLuaDao premium APIs:

  • Feeds API   (https://feeds.chongluadao.vn)   — URL/phone/whois/burner checks,
    denylist search, and the deep AI URL analyzer.
  • Threat-Intel API (https://api-ti.chongluadao.vn) — IoC analyzers (email,
    password, url, ip, phone, bank-account, hash, asn), the full Data-Leaks module
    (machines, stolen/exposed credentials, cookies, breaches, leaked-accounts +
    device inventory, exposure, full-export — with async job start→poll), Brand-
    Protection lookalikes, Threat-Feeds (CVE/KEV, actors, onion) and STIX/MISP feeds.

EGRESS / OPSEC — your client connects ONLY to ChongLuaDao (feeds./api-ti.), never
to the target. For `checkurl`, `analyze`, and `ioc url/ip`, CLD performs any target
fetch and scoring server-side, so the analyst's egress never touches hostile infra.
(The no-target-contact property is provable from this file: the only base URLs are
FEEDS and TI. That CLD then fetches the target server-side is inferred from the API.)

Auth: the key rides ONLY in the `X-API-Key` header and is never logged or printed.
Resolution: env var  >  skill-root .env  >  keyless (fails with exit 3).
Env vars (first hit wins): CHONGLUADAO_API_KEY, CLD_API_KEY, CHONGLUADAO_KEY, BURNER_API_KEY.

Timeouts: harness the data to the fullest — the default per-call ceiling is 1800s
(30 min) and async jobs poll up to that budget. A 403/404 returns immediately and is
treated as SKIP (exit 0), so a batch/pivot continues instead of hard-failing.

Output: a single JSON envelope on stdout —
  {"tool":"chongluadao","op":..,"input":..,"ok":bool,"status":int|null,
   "skipped":bool,"result":<raw response>,"error":str|null}
Exit codes: 0 ok OR skipped(403/404/unsupported) · 2 other error · 3 no key.

Usage (see `--help` on any subcommand):
  uv run cld_api.py route  https://scam-site.top          # auto-detect + best call
  uv run cld_api.py leaked-accounts user@example.com --type email   # async start→poll
  uv run cld_api.py full-export example.com               # async bulk export
  uv run cld_api.py feed stix2 --observed-after 2026-01-01
"""
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass

# --- egress proxy / rotation: route outbound HTTP through the /proxy pool ----
def _install_cti_proxy():
    import os as _o, sys as _s
    _b = _o.path.dirname(_o.path.abspath(__file__))
    for _ in range(6):
        _c = _o.path.join(_b, "proxy", "cti_proxy.py")
        if _o.path.isfile(_c):
            _s.path.insert(0, _o.path.dirname(_c))
            try:
                import cti_proxy
                cti_proxy.install()
            except Exception:
                pass
            return
        _p = _o.path.dirname(_b)
        if _p == _b:
            return
        _b = _p
_install_cti_proxy()

HERE = os.path.dirname(os.path.abspath(__file__))
FEEDS = "https://feeds.chongluadao.vn"
TI = "https://api-ti.chongluadao.vn"
UA = "cti-expert-cld/1.1"
DEFAULT_TIMEOUT = 1800          # 30-min ceiling per call (harness all the data)
STEP_TIMEOUT = 180              # per HTTP round-trip inside an async poll loop
POLL_INTERVAL = 5               # seconds between async polls
IOC_TYPES = ("email", "password", "url", "ip", "phone", "bank-account", "hash", "asn")

# reuse the canonical identifier classifier instead of duplicating it
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..")))
try:
    from pivot_orchestrator import classify as _classify  # type: ignore
except Exception:  # pragma: no cover - fallback keeps route usable standalone
    _classify = None


# ───────────────────────────────────────────────────────── key resolution
def _load_env():
    path = os.environ.get("CTI_API_KEYS_ENV") or os.path.normpath(
        os.path.join(HERE, "..", "..", ".env"))
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                k, v = k.strip(), v.strip().strip('"').strip("'")
                if k and k not in os.environ:
                    os.environ[k] = v
    except Exception:
        pass


def _api_key():
    _load_env()
    for n in ("CHONGLUADAO_API_KEY", "CLD_API_KEY", "CHONGLUADAO_KEY", "BURNER_API_KEY"):
        v = os.environ.get(n)
        if v and v.strip():
            return v.strip()
    return None


# ───────────────────────────────────────────────────────── HTTP core
def _request(method, base, path, api_key, params=None, body=None, timeout=DEFAULT_TIMEOUT):
    """Return (status, parsed_json_or_text, error). Key only in the header."""
    url = base + path
    if params:
        clean = {k: v for k, v in params.items() if v is not None}
        if clean:
            url += "?" + urllib.parse.urlencode(clean)
    headers = {"User-Agent": UA, "Accept": "application/json", "X-API-Key": api_key}
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw, status = r.read(), r.getcode()
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8", "replace")[:300]
        except Exception:
            pass
        return e.code, None, f"HTTP {e.code}{': ' + detail if detail else ''}"
    except Exception as e:  # network/timeout — never includes the key
        return None, None, f"{type(e).__name__}: {e}"
    text = raw.decode("utf-8", "replace")
    try:
        return status, json.loads(text), None
    except Exception:
        return status, text, None


def _run_job(base, start_path, start_body, poll_path, key, timeout, poll_kind):
    """Start an async job then poll to completion (or `timeout` budget).

    poll_kind: 'post_body' → POST poll_path {job_id}; 'get_path' → GET poll_path/{job_id}.
    Returns (status, result, error) of the terminal poll."""
    st, res, err = _request("POST", base, start_path, key, body=start_body, timeout=STEP_TIMEOUT)
    if err or not isinstance(res, dict):
        return st, res, err or "unexpected start response"
    job = res.get("job_id")
    if not job:
        return st, res, "no job_id in start response"
    deadline = time.time() + timeout
    pst, last = st, res
    while time.time() < deadline:
        if poll_kind == "get_path":
            pst, last, perr = _request("GET", base, poll_path + urllib.parse.quote(job, safe=""),
                                       key, timeout=STEP_TIMEOUT)
        else:
            pst, last, perr = _request("POST", base, poll_path, key,
                                       body={"job_id": job}, timeout=STEP_TIMEOUT)
        if perr:
            return pst, last, perr
        status = (last or {}).get("status")
        if status in ("done", "completed"):
            return pst, last, None
        if status in ("error", "failed"):
            return pst, last, (last or {}).get("error") or "job reported error"
        time.sleep(POLL_INTERVAL)
    return pst, last, f"job {job} still running after {timeout}s budget"


def _skipped(status):
    return status in (403, 404)


def _emit(op, inp, status, result, error, pretty, skipped=False, raw=False):
    skipped = skipped or _skipped(status)
    ok = (not skipped) and error is None and status is not None and 200 <= status < 300
    env = {"tool": "chongluadao", "op": op, "input": inp, "ok": ok,
           "status": status, "skipped": skipped, "result": result, "error": error}
    if raw:
        # emit ONLY the provider body (loadable STIX/MISP/JSON) on success; on
        # skip/error write nothing to stdout so a `> file` redirect stays empty.
        if ok:
            print(result if isinstance(result, str)
                  else json.dumps(result, indent=2 if pretty else None, ensure_ascii=False))
        else:
            print(json.dumps(env, ensure_ascii=False), file=sys.stderr)
        return 0 if (ok or skipped) else 2
    print(json.dumps(env, indent=2 if pretty else None, ensure_ascii=False))
    return 0 if (ok or skipped) else 2


# ───────────────────────────────────────────────────────── indicator routing
# classify() → the CLD IoC op that fits. Types with no CLD endpoint are absent on
# purpose: route SKIPS them rather than burning a metered ioc/url on a name/handle.
CLASS_TO_IOC = {"email": "email", "ipv4": "ip", "ipv6": "ip", "md5": "hash",
                "sha1": "hash", "cert_sha256": "hash", "asn": "asn",
                "domain": "url", "url": "url", "phone": "phone"}


def _classify_local(v):
    v = v.strip()
    if re.fullmatch(r"[^@\s]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", v):
        return "email"
    if re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|[0-9a-fA-F]{128}", v):
        return "md5"
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?", v):
        return "ipv4"
    if re.fullmatch(r"(as)?\d{1,10}", v.lower()) and (v.lower().startswith("as") or len(v) <= 6):
        return "asn"
    if re.fullmatch(r"\+?[\d\s\-()]{8,20}", v):
        return "phone"
    if re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}", v) or v.lower().startswith(("http://", "https://")):
        return "url" if "//" in v else "domain"
    return "unknown"


def op_route(k, a):
    t = a.target.strip()
    if re.fullmatch(r"(?i)cve-\d{4}-\d{4,}", t):
        a.cve = t
        return ("cve", op_vuln(k, a))
    if t.lower().endswith(".onion"):
        a.hostname = t
        return ("onion", op_onion(k, a))
    kind = (_classify(t) if _classify else _classify_local(t))
    ioc = CLASS_TO_IOC.get(kind)
    if not ioc:
        # no CLD IoC endpoint for this type — skip, never a blind metered ioc/url
        return (f"route/{kind}", (None, None,
                f"'{kind}' has no ChongLuaDao IoC endpoint — skipped (no metered call). "
                f"Use an explicit subcommand if this really is a checkable indicator.", True))
    a.type, a.value = ioc, t
    a.ai = getattr(a, "ai", False)
    return (f"ioc/{ioc}", op_ioc(k, a))


# ───────────────────────────────────────────────────────── Feeds ops
def op_checkurl(k, a):
    return _request("POST", FEEDS, "/external/checkurl", k, body={"url": a.url}, timeout=a.timeout)


def op_analyze(k, a):
    p = {"url": a.url, "lang": a.lang, "skip_cache": "true" if a.fresh else None}
    return _request("GET", FEEDS, "/api/v1/analyze-deep", k, params=p, timeout=a.timeout)


def op_denylist(k, a):
    p = {"search": a.search, "page": a.page, "limit": a.limit,
         "status": a.status, "url_type": a.type, "sort": a.sort}
    return _request("GET", FEEDS, "/external/denylists/search", k, params=p, timeout=a.timeout)


def op_checkphone(k, a):
    return _request("GET", FEEDS, "/external/checkphone", k, params={"q": a.q}, timeout=a.timeout)


def op_whois(k, a):
    return _request("GET", FEEDS, "/external/checkwhois", k, params={"q": a.q}, timeout=a.timeout)


def op_burner(k, a):
    return _request("GET", FEEDS, "/external/checkburneremail", k, params={"q": a.q}, timeout=a.timeout)


# ───────────────────────────────────────────────────────── TI: IoC ops
def op_ioc(k, a):
    field = {"bank-account": "account"}.get(a.type, a.type)
    body = {field: a.value}
    if a.type == "url" and getattr(a, "ai", False):
        body["ai_analysis"] = True
    return _request("POST", TI, f"/api/v1/ioc/external/{a.type}", k, body=body, timeout=a.timeout)


# ───────────────────────────────────────────────────────── TI: Data-Leaks ops
DL = "/api/v1/data-leaks/external"


def op_exposure(k, a):
    return _request("POST", TI, f"{DL}/leaked-accounts/exposure", k,
                    body={"value": a.value, "search_type": a.type}, timeout=a.timeout)


def op_leaks(k, a):
    return _request("POST", TI, f"{DL}/search", k,
                    body={"query": a.query, "input_type": a.input_type}, timeout=a.timeout)


def op_breaches(k, a):
    return _request("POST", TI, f"{DL}/breaches/search", k,
                    body={"query": a.query, "input_type": a.input_type, "limit": a.limit},
                    timeout=a.timeout)


def _dataset(k, a, name, extra=None):
    body = {"query": a.query, "input_type": a.input_type}
    if extra:
        body.update(extra)
    return _request("POST", TI, f"{DL}/{name}/search", k, body=body, timeout=a.timeout)


def op_machines(k, a):
    return _dataset(k, a, "machines", {"cursor": a.cursor})


def op_stolen(k, a):
    return _dataset(k, a, "stolen-credentials", {"limit": a.limit, "offset": a.offset})


def op_exposed(k, a):
    return _dataset(k, a, "exposed-credentials")


def op_cookies(k, a):
    return _dataset(k, a, "cookies", {"limit": a.limit, "offset": a.offset})


def op_leaked_accounts(k, a):
    body = {"query": a.query, "input_type": a.input_type, "limit": a.limit, "offset": a.offset}
    return _run_job(TI, f"{DL}/leaked-accounts/search/start", body,
                    f"{DL}/leaked-accounts/search/poll", k, a.timeout, "post_body")


def op_devices(k, a):
    body = {"query": a.query, "limit": a.limit, "offset": a.offset}
    return _run_job(TI, f"{DL}/leaked-accounts/devices/search/start", body,
                    f"{DL}/leaked-accounts/devices/search/poll", k, a.timeout, "post_body")


def op_device_detail(k, a):
    return _request("POST", TI, f"{DL}/leaked-accounts/devices/detail", k,
                    body={"device_id": a.device_id}, timeout=a.timeout)


def op_device_credentials(k, a):
    return _request("POST", TI, f"{DL}/leaked-accounts/devices/credentials", k,
                    body={"device_id": a.device_id, "limit": a.limit, "offset": a.offset},
                    timeout=a.timeout)


def op_full_export(k, a):
    return _run_job(TI, f"{DL}/full-export/start", {"query": a.query},
                    f"{DL}/full-export/poll/", k, a.timeout, "get_path")


# ───────────────────────────────────────────────────────── TI: Brand + Feeds
def op_brand_domains(k, a):
    return _request("POST", TI, "/api/v1/brand-protection/external/domains", k,
                    body={"limit": a.limit, "offset": a.offset}, timeout=a.timeout)


def op_vulns(k, a):
    p = {"severity": a.severity, "vendor": a.vendor, "product": a.product,
         "known_exploited": "true" if a.kev else None, "q": a.q,
         "limit": a.limit, "offset": a.offset}
    return _request("GET", TI, "/api/v1/threat-feeds/external/vulnerabilities", k, params=p,
                    timeout=a.timeout)


def op_vuln(k, a):
    return _request("GET", TI, "/api/v1/threat-feeds/external/vulnerabilities/"
                    + urllib.parse.quote(a.cve, safe=""), k, timeout=a.timeout)


def op_actors(k, a):
    p = {"q": a.q, "actor_type": a.type, "limit": a.limit, "offset": a.offset}
    return _request("GET", TI, "/api/v1/threat-feeds/external/threat-actors", k, params=p,
                    timeout=a.timeout)


def op_onion(k, a):
    return _request("GET", TI, "/api/v1/threat-feeds/external/onion-blocklist/check", k,
                    params={"hostname": a.hostname}, timeout=a.timeout)


def op_actor_usernames(k, a):
    # map a handle (a committer login, a Telegram/forum alias) to a tracked threat actor
    p = {"q": a.q, "limit": a.limit, "offset": a.offset}
    return _request("GET", TI, "/api/v1/threat-feeds/external/threat-actor-usernames", k,
                    params=p, timeout=a.timeout)


def op_incidents(k, a):
    p = {"q": a.q, "limit": a.limit, "offset": a.offset}
    return _request("GET", TI, "/api/v1/threat-feeds/external/incidents", k, params=p,
                    timeout=a.timeout)


def op_feed(k, a):
    path = {"stix2": "/api/v1/ioc/external/feeds/stix2",
            "misp": "/api/v1/ioc/external/feeds/misp",
            "stix1": "/api/v1/ioc/external/feeds/stix1"}[a.format]
    p = {"limit": a.limit, "type": a.type, "observed_after": a.observed_after}
    return _request("GET", TI, path, k, params=p, timeout=a.timeout)


def op_probe(k, a):
    st, res, err = _request("GET", FEEDS, "/external/checkburneremail", k,
                            params={"q": "mailinator.com"}, timeout=30)
    state = "valid" if (err is None and st == 200 and isinstance(res, dict)
                        and "is_burner_email" in res) else \
            ("invalid" if st in (401, 403) else "error")
    return st, {"probe": state, "detail": err or f"HTTP {st}"}, \
        (None if state == "valid" else (err or f"HTTP {st}"))


# ───────────────────────────────────────────────────────── CLI
def build_parser():
    ap = argparse.ArgumentParser(description="ChongLuaDao premium API client (/cld). "
                                 "Global flags --pretty/--timeout go AFTER the subcommand.")
    sub = ap.add_subparsers(dest="op", required=True)

    p = sub.add_parser("route", help="auto-detect indicator type and run the best call")
    p.add_argument("target"); p.add_argument("--ai", action="store_true")

    p = sub.add_parser("checkurl", help="Feeds: URL verdict vs CLD denylist/allowlist")
    p.add_argument("url")
    p = sub.add_parser("analyze", help="Feeds: deep AI URL analysis (risk 1-10 + findings)")
    p.add_argument("url"); p.add_argument("--lang", choices=["en", "vi"], default="en")
    p.add_argument("--fresh", action="store_true", help="skip cache, force fresh analysis")
    p = sub.add_parser("denylist", help="Feeds: search CLD denylist (campaign/brand clustering)")
    p.add_argument("search"); p.add_argument("--type", help='url_type, e.g. "2:PHISHING"')
    p.add_argument("--status", choices=["ONLINE", "OFFLINE"])
    p.add_argument("--page", type=int, default=1); p.add_argument("--limit", type=int, default=200)
    p.add_argument("--sort", default="created_at,DESC")
    for name, h in (("checkphone", "Feeds: VN phone scam-report verdict"),
                    ("whois", "Feeds: WHOIS registration lookup"),
                    ("burner", "Feeds: disposable/burner email check")):
        sp = sub.add_parser(name, help=h); sp.add_argument("q")

    p = sub.add_parser("ioc", help="TI: IoC analyzer — combined verdict + evidence")
    p.add_argument("type", choices=IOC_TYPES); p.add_argument("value")
    p.add_argument("--ai", action="store_true", help="url only: attach deep AI analysis")

    p = sub.add_parser("exposure", help="TI: data-leak exposure check")
    p.add_argument("value")
    p.add_argument("--type", required=True, choices=["username", "email", "password", "domain"])

    for name, h in (("leaks", "TI: live preview across all leak datasets"),
                    ("breaches", "TI: breach collections for a domain/account")):
        sp = sub.add_parser(name, help=h)
        sp.add_argument("query"); sp.add_argument("--input-type", dest="input_type", default="auto")
        if name == "breaches":
            sp.add_argument("--limit", type=int, default=50)

    # individual leak datasets
    p = sub.add_parser("machines", help="TI: affected-device (machine) records")
    p.add_argument("query"); p.add_argument("--input-type", dest="input_type", default="auto")
    p.add_argument("--cursor")
    for name, h in (("stolen-credentials", "TI: stolen login records"),
                    ("cookies", "TI: browser cookie records")):
        sp = sub.add_parser(name, help=h)
        sp.add_argument("query"); sp.add_argument("--input-type", dest="input_type", default="auto")
        sp.add_argument("--limit", type=int, default=100); sp.add_argument("--offset", type=int, default=0)
    p = sub.add_parser("exposed-credentials", help="TI: exposed username/password pairs")
    p.add_argument("query"); p.add_argument("--input-type", dest="input_type", default="auto")

    # async job endpoints (start → poll)
    p = sub.add_parser("leaked-accounts", help="TI: live CyberTrust leaked accounts (async job)")
    p.add_argument("query"); p.add_argument("--input-type", dest="input_type", default="auto")
    p.add_argument("--limit", type=int, default=100); p.add_argument("--offset", type=int, default=0)
    p = sub.add_parser("devices", help="TI: live CyberTrust device inventory (async job)")
    p.add_argument("query")
    p.add_argument("--limit", type=int, default=100); p.add_argument("--offset", type=int, default=0)
    p = sub.add_parser("device-detail", help="TI: one CyberTrust device detail")
    p.add_argument("device_id")
    p = sub.add_parser("device-credentials", help="TI: credentials from one device")
    p.add_argument("device_id")
    p.add_argument("--limit", type=int, default=100); p.add_argument("--offset", type=int, default=0)
    p = sub.add_parser("full-export", help="TI: bulk data-leak export (async job)")
    p.add_argument("query")

    p = sub.add_parser("brand-domains", help="TI: brand-protection lookalike domains")
    p.add_argument("--limit", type=int, default=50); p.add_argument("--offset", type=int, default=0)
    p = sub.add_parser("vulns", help="TI: threat-feed CVE/KEV list")
    p.add_argument("--severity"); p.add_argument("--vendor"); p.add_argument("--product")
    p.add_argument("--q"); p.add_argument("--kev", action="store_true")
    p.add_argument("--limit", type=int, default=50); p.add_argument("--offset", type=int, default=0)
    p = sub.add_parser("vuln", help="TI: one CVE by id"); p.add_argument("cve")
    p = sub.add_parser("actors", help="TI: threat-actor list")
    p.add_argument("--q"); p.add_argument("--type"); p.add_argument("--limit", type=int, default=50); p.add_argument("--offset", type=int, default=0)
    p = sub.add_parser("actor-usernames", help="TI: map a handle/alias to a tracked threat actor")
    p.add_argument("q"); p.add_argument("--limit", type=int, default=50); p.add_argument("--offset", type=int, default=0)
    p = sub.add_parser("incidents", help="TI: threat-feed incident records")
    p.add_argument("--q"); p.add_argument("--limit", type=int, default=50); p.add_argument("--offset", type=int, default=0)
    p = sub.add_parser("onion", help="TI: check an .onion against the abuse blocklist")
    p.add_argument("hostname")
    p = sub.add_parser("feed", help="TI: download indicator feed (STIX/MISP)")
    p.add_argument("format", choices=["stix2", "misp", "stix1"])
    p.add_argument("--limit", type=int, default=1000); p.add_argument("--type")
    p.add_argument("--observed-after", dest="observed_after", help="ISO date filter")

    sub.add_parser("probe", help="validate the configured key (fast)")
    for spx in sub.choices.values():          # flags accepted post-subcommand, no clobber
        spx.add_argument("--pretty", action="store_true", help="pretty-print JSON")
        spx.add_argument("--raw", action="store_true",
                         help="emit only the provider body (loadable STIX/MISP/JSON), no envelope")
        spx.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                         help="per-call / async-budget ceiling in seconds (default 1800 = 30 min)")
    return ap


DISPATCH = {
    "checkurl": op_checkurl, "analyze": op_analyze, "denylist": op_denylist,
    "checkphone": op_checkphone, "whois": op_whois, "burner": op_burner,
    "ioc": op_ioc, "exposure": op_exposure, "leaks": op_leaks, "breaches": op_breaches,
    "machines": op_machines, "stolen-credentials": op_stolen,
    "exposed-credentials": op_exposed, "cookies": op_cookies,
    "leaked-accounts": op_leaked_accounts, "devices": op_devices,
    "device-detail": op_device_detail, "device-credentials": op_device_credentials,
    "full-export": op_full_export, "brand-domains": op_brand_domains,
    "vulns": op_vulns, "vuln": op_vuln, "actors": op_actors,
    "actor-usernames": op_actor_usernames, "incidents": op_incidents, "onion": op_onion,
    "feed": op_feed, "probe": op_probe,
}


def _input_label(a):
    for attr in ("target", "url", "value", "search", "query", "q", "hostname", "cve", "device_id"):
        if getattr(a, attr, None) is not None:
            return getattr(a, attr)
    return None


def main():
    a = build_parser().parse_args()
    key = _api_key()
    if not key:
        print(json.dumps({"tool": "chongluadao", "op": a.op, "ok": False, "status": None,
                          "skipped": False, "result": None, "error": "no ChongLuaDao API key "
                          "(set CHONGLUADAO_API_KEY / CLD_API_KEY, or run /apikeys set chongluadao)"},
                         ensure_ascii=False))
        return 3
    if a.op == "route":
        op_name, tup = op_route(key, a)
        status, result, error = tup[0], tup[1], tup[2]
        skipped = tup[3] if len(tup) > 3 else False
        return _emit(op_name, a.target, status, result, error, a.pretty, skipped, a.raw)
    status, result, error = DISPATCH[a.op](key, a)
    return _emit(a.op, _input_label(a), status, result, error, a.pretty, raw=a.raw)


if __name__ == "__main__":
    sys.exit(main() or 0)
