#!/usr/bin/env python3
# CTI Expert — ChongLuaDao (CLD) premium API client.
# First-party threat-intelligence connector for chongluadao.vn.
"""
cld_api.py — one stdlib client for both ChongLuaDao premium APIs:

  • Feeds API   (https://feeds.chongluadao.vn)   — URL/phone/whois/burner checks,
    denylist search, and the deep AI URL analyzer.
  • Threat-Intel / Shield API (https://api-ti.chongluadao.vn) — IoC analyzers,
    Data-Leaks (dataset searches, internal-document leaks, bulk export), Brand-Protection,
    ransomware monitoring, ClickFix / PhaaS / Telegram, Threat-Feeds, TAXII and STIX/MISP feeds.
    Same key as Feeds. `route` calls both hosts so a miss on one is covered by the other.
    Endpoint contract: GET /api/v1/api-gateway/external/docs/<id>/openapi.json (verified 2026-10-20).

EGRESS / OPSEC — your client connects ONLY to ChongLuaDao (feeds./api-ti.), never
to the target. For `checkurl`, `analyze`, and `ioc url/ip`, CLD performs any target
fetch and scoring server-side, so the analyst's egress never touches hostile infra.
(The no-target-contact property is provable from this file: the only base URLs are
FEEDS and TI. That CLD then fetches the target server-side is inferred from the API.)

Auth: the key rides ONLY in the `X-API-Key` header and is never logged or printed.
Resolution: env var  >  skill-root .env  >  keyless (fails with exit 3).
Env vars (first hit wins): CHONGLUADAO_API_KEY, CLD_API_KEY, CHONGLUADAO_KEY, BURNER_API_KEY.

Timeouts: harness the data to the fullest — the default per-call ceiling is 5000s
(~83 min) and the bulk-export job polls up to that budget. A 403, and a 404 that names the
missing resource, returns immediately and is treated as SKIP (exit 0), so a batch/pivot continues
instead of hard-failing. A 404 whose body is exactly {"detail":"Not Found"} is a route that no
longer exists — that is an error (exit 2), never a silent skip.

Rate limits: no per-call credits, but every key is rate-limited (X-RateLimit-* headers; observed
TI 10/s · 100/min · 10,000/day, Feeds 60/s). A 429 inside a second/minute window is waited out and
retried within the call budget; a day-window 429 returns at once with its reset time. The envelope
`usage.rate_limit` carries the last window snapshot per tier.

Output: a single JSON envelope on stdout —
  {"tool":"chongluadao","op":..,"input":..,"ok":bool,"status":int|null,
   "skipped":bool,"result":<raw response>,"error":str|null,"usage":{..}}
Exit codes: 0 ok OR skipped(403/404/unsupported) · 2 other error · 3 no key.

Usage ledger: the CLI (and the MCP `cld` tool, which runs this CLI) records EVERY actual HTTP
request — each `route` leg, each async start AND status poll — to the shared api_usage ledger
(provider=chongluadao, action=<feeds|ti>:<endpoint>). Units per endpoint come from cld_usage.json
(an ESTIMATE: CLD publishes no pricing); a missing/broken file ledgers every call at 1 unit. No key
or a failed pre-flight sends nothing and ledgers nothing. Importers (wp_cld, reputation_check)
call `_request` directly and keep their own accounting: the ledger is off until `enable_ledger()`.

Usage (see `--help` on any subcommand):
  uv run cld_api.py route  https://scam-site.top          # Feeds + Shield together
  uv run cld_api.py route  bank:0123456789                # VN bank account → holder + bank name
  uv run cld_api.py leaks user@example.com                # all leak datasets, pending kinds settled
  uv run cld_api.py stolen-credentials example.com        # every page (default); --one-page for one
  uv run cld_api.py full-export example.com               # async bulk export (hours)
  uv run cld_api.py incident 1234                         # one incident: IOCs + MITRE ATT&CK
  uv run cld_api.py brand-domains --where assessment_result:eq:needs_attention --order-by first_seen_at:desc
  uv run cld_api.py feed stix2 --observed-after 2026-01-01 --all --raw > cld.stix.json
  uv run cld_api.py taxii2-objects indicators --added-after 2026-01-01T00:00:00Z --all
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
import threading
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
DEFAULT_TIMEOUT = 5000          # ~83-min ceiling per call (harness all the data)
STEP_TIMEOUT = 180              # per HTTP round-trip inside an async poll loop
POLL_INTERVAL = 5               # seconds between async polls
# A 429 is the vendor's own limit (TI: 10/s, 100/min, 10k/day per key; Feeds: 60/s). Wait out a
# second/minute window and retry; never sleep through a day window — that returns the 429.
RATE_WAIT_MAX = 65
RATE_RETRIES = 6
_TLS = threading.local()        # last response headers of this thread (X-Next, X-RateLimit-*)
IOC_TYPES = ("email", "password", "url", "ip", "phone", "bank-account", "hash", "asn")
LEAK_INPUT_TYPES = ("auto", "email", "domain", "ip", "username", "keyword", "password", "pc_name", "url")
TF = "/api/v1/threat-feeds/external"
# FastAPI's bare response for a path that does not exist, distinct from a resource miss
_ROUTE_GONE = 'HTTP 404: {"detail":"Not Found"}'

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


# ───────────────────────────────────────────────────────── usage ledger
_USAGE_REF = os.path.join(HERE, "references", "cld_usage.json")
_FALLBACK_UNITS = 1              # conservative: an unpriced call is never ledgered as free
_TIER_OF = {FEEDS: "feeds", TI: "ti"}
_LEDGER = None                   # None → off (library import); enable_ledger() turns it on


def _units(value, default=_FALLBACK_UNITS):
    ok = isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0
    return value if ok else default


def _load_usage():
    """cld_usage.json, or a fallback that prices every call at _FALLBACK_UNITS (with a warning)."""
    try:
        with open(_USAGE_REF, "r", encoding="utf-8") as f:
            ref = json.load(f)
        if not isinstance(ref, dict) or not isinstance(ref.get("tiers"), dict):
            raise ValueError("missing 'tiers' object")
        return ref
    except Exception as e:
        print(f"[cld_api] WARNING: {os.path.basename(_USAGE_REF)} unusable ({type(e).__name__}: "
              f"{e}); ledgering every ChongLuaDao call at {_FALLBACK_UNITS} unit.", file=sys.stderr)
        return {"pricing": {"published": False, "basis": "estimate"}, "tiers": {}}


def _path_matches(template, path):
    want, got = template.strip("/").split("/"), path.strip("/").split("/")
    return len(want) == len(got) and all(
        w == g or (w.startswith("{") and w.endswith("}") and g) for w, g in zip(want, got))


def _price(ref, base, path):
    """(tier, action, units, kind) for one request, from the usage reference."""
    tier = _TIER_OF.get(base, "unknown")
    spec_tier = ref["tiers"].get(tier)
    spec_tier = spec_tier if isinstance(spec_tier, dict) else {}
    default = _units(spec_tier.get("default_units"))
    endpoints = spec_tier.get("endpoints")
    for template, spec in (endpoints.items() if isinstance(endpoints, dict) else ()):
        if _path_matches(template, path):
            spec = spec if isinstance(spec, dict) else {}
            return (tier, str(spec.get("action") or template), _units(spec.get("units"), default),
                    str(spec.get("kind") or "request"))
    return tier, path, default, "request"


def enable_ledger(sink, query=None):
    """Ledger every subsequent `_request` of this process. `sink` is the api_usage module (or any
    object with its `record` signature); None still counts calls for the envelope `usage` block."""
    global _LEDGER
    _LEDGER = {"sink": sink, "query": query, "ref": _load_usage(),
               "calls": 0, "polls": 0, "units": 0, "by_tier": {}, "rate_limit": {}}


def usage_summary():
    """The envelope `usage` block: what this process actually sent. None while the ledger is off."""
    if _LEDGER is None:
        return None
    pricing = _LEDGER["ref"].get("pricing") or {}
    return {"calls": _LEDGER["calls"], "polls": _LEDGER["polls"],
            "billable_units": _LEDGER["units"], "by_tier": _LEDGER["by_tier"],
            "basis": pricing.get("basis") or "estimate",
            "published_pricing": bool(pricing.get("published")),
            "ledgered": _LEDGER["sink"] is not None,
            "rate_limit": _LEDGER["rate_limit"]}


def _ledger(base, path, status, error):
    if _LEDGER is None:
        return
    tier, action, units, kind = _price(_LEDGER["ref"], base, path)
    ok = error is None and isinstance(status, int) and 200 <= status < 300
    billed = units if ok else 0
    _LEDGER["calls"] += 1
    _LEDGER["polls"] += 1 if kind == "poll" else 0
    _LEDGER["units"] += billed
    row = _LEDGER["by_tier"].setdefault(tier, {"calls": 0, "billable_units": 0})
    row["calls"] += 1
    row["billable_units"] += billed
    if _LEDGER["sink"] is not None:
        try:
            _LEDGER["sink"].record("chongluadao", f"{tier}:{action}", credits=units,
                                   query=_LEDGER["query"], ok=ok)
        except Exception as e:  # a ledger fault must never lose the vendor answer
            print(f"[cld_api] WARNING: usage ledger write failed ({type(e).__name__})",
                  file=sys.stderr)


# ───────────────────────────────────────────────────────── HTTP core
def _header(name):
    """A header of this thread's last response (lower-cased name), or None."""
    return (getattr(_TLS, "headers", None) or {}).get(name.lower())


def _rate_snapshot():
    """{window: {limit, remaining, reset_s}} from the last response's X-RateLimit-* headers."""
    out = {}
    for window in ("second", "minute", "day"):
        row = {}
        for field, out_name in (("limit", "limit"), ("remaining", "remaining"), ("reset", "reset_s")):
            v = _header(f"x-ratelimit-{window}-{field}")
            if v is not None and str(v).strip().isdigit():
                row[out_name] = int(v)
        if row:
            out[window] = row
    return out


def _rate_wait(status):
    """Seconds to wait before retrying a 429, or None when the call must not be retried here.
    Retry-After wins; otherwise the longest reset among exhausted windows; unknown → 2s."""
    if status != 429:
        return None
    ra = _header("retry-after")
    if ra is not None and str(ra).strip().isdigit():
        wait = int(ra)
    else:
        exhausted = [w["reset_s"] for w in _rate_snapshot().values()
                     if w.get("remaining") == 0 and "reset_s" in w]
        wait = max(exhausted) if exhausted else 2
    return wait if wait <= RATE_WAIT_MAX else None


def _request(method, base, path, api_key, params=None, body=None, timeout=DEFAULT_TIMEOUT):
    """Return (status, parsed_json_or_text, error). Key only in the header. With the ledger on,
    every attempted request is ledgered exactly once (a rejected one with ok=false, 0 credits).
    A 429 inside a second/minute window is waited out and retried within `timeout`."""
    deadline = time.time() + timeout
    for _attempt in range(RATE_RETRIES + 1):
        _TLS.headers = {}
        status, result, error = _http(method, base, path, api_key, params, body,
                                      max(1, min(timeout, deadline - time.time())))
        _ledger(base, path, status, error)
        snap = _rate_snapshot()
        if snap and _LEDGER is not None:
            _LEDGER["rate_limit"][_TIER_OF.get(base, "unknown")] = snap
        wait = _rate_wait(status)
        if wait is None or time.time() + wait >= deadline:
            break
        time.sleep(wait)
    if status == 429:
        spent = [f"{w} resets in {v['reset_s']}s" for w, v in _rate_snapshot().items()
                 if v.get("remaining") == 0 and "reset_s" in v]
        if spent:
            error = f"{error} (ChongLuaDao rate limit: {', '.join(spent)})"
    return status, result, error


def _http(method, base, path, api_key, params, body, timeout):
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
            _TLS.headers = {k.lower(): v for k, v in r.headers.items()}
            raw, status = r.read(), r.getcode()
    except urllib.error.HTTPError as e:
        _TLS.headers = {k.lower(): v for k, v in (e.headers or {}).items()}
        detail = ""
        try:
            detail = e.read().decode("utf-8", "replace")[:300]
        except Exception:
            pass
        return e.code, None, f"HTTP {e.code}{': ' + detail if detail else ''}"
    except Exception as e:  # network/timeout — never includes the key
        return None, None, f"{type(e).__name__}: {e}"
    if not raw:
        return status, None, None          # 204 (webhook delete)
    text = raw.decode("utf-8", "replace")
    try:
        return status, json.loads(text), None
    except Exception:
        return status, text, None


def _skipped(status, error=None):
    if status == 403:
        return True
    # a missing resource ("Victim not found.") is a skip; a removed route is not
    return status == 404 and error != _ROUTE_GONE


_EXTRA = {}                     # envelope-level fields an op adds (e.g. the feed's X-Next cursor)


def _emit(op, inp, status, result, error, pretty, skipped=False, raw=False, usage=None):
    skipped = skipped or _skipped(status, error)
    ok = (not skipped) and error is None and status is not None and 200 <= status < 300
    env = {"tool": "chongluadao", "op": op, "input": inp, "ok": ok,
           "status": status, "skipped": skipped, "result": result, "error": error}
    env.update(_EXTRA)
    if usage is not None:
        env["usage"] = usage
    if raw and ok and _EXTRA:
        # a raw body must stay loadable, so the cursor goes to stderr
        print(json.dumps(_EXTRA, ensure_ascii=False), file=sys.stderr)
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


def _host_of(value):
    v = str(value or "").strip().lower()
    v = v.split("://", 1)[-1].split("/")[0].split(":")[0].rstrip(".")
    if v.startswith("www."):
        v = v[4:]
    return v


def filter_host_hits(result, host):
    """Keep only rows whose website/domain/url host is the target or its subdomain.
    A free-text `q` hit is not a verdict. Returns (filtered, matched_count)."""
    if not isinstance(result, dict):
        return result, 0
    want = _host_of(host)
    key = next((k for k in ("items", "data", "results", "victims")
                if isinstance(result.get(k), list)), None)
    if not key or not want:
        out = dict(result)
        out["matched"] = 0
        return out, 0
    matched = []
    for row in result[key]:
        if not isinstance(row, dict):
            continue
        hosts = [_host_of(row.get(k)) for k in ("website", "domain", "url", "host", "hostname")]
        if any(h == want or h.endswith("." + want) for h in hosts if h):
            matched.append(row)
    out = dict(result)
    out[key] = matched
    out["count"] = len(matched)
    out["total"] = len(matched)
    out["matched"] = len(matched)
    out["unfiltered"] = len(result[key])
    return out, len(matched)


_WHOIS_SIGNAL_KEY_RE = re.compile(
    r"registrar|registrant|regist(?:ered|ration)|creat(?:ed|ion)|expir|updat(?:ed)?|"
    r"organi[sz]ation|\bowner\b|name.?server|\bns\d*\b|domain.?status", re.I)


def _collect_whois_signal_values(node, out):
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(v, (dict, list)):
                _collect_whois_signal_values(v, out)
            elif _WHOIS_SIGNAL_KEY_RE.search(str(k)):
                out.append(v)
    elif isinstance(node, list):
        for item in node:
            _collect_whois_signal_values(item, out)


def whois_has_signal(body) -> bool:
    """True when a CLD checkwhois body carries at least one non-empty registrar/date/owner/name-
    server field, anywhere in the structure. False only for an ALL-NULL body (registrar, dates,
    owner and name servers all empty) — that is a MISS, not an answer, and the caller (wp_cld,
    whois_enrich's `.vn` fallback chain) must treat it as such and fall back to RDAP/port-43 WHOIS.
    An unrecognised shape (no signal-named key found at all, e.g. the API changed its field names)
    returns True — this never GUESSES a miss out of a shape it has not seen before."""
    if not isinstance(body, dict) or body.get("error"):
        return True
    values = []
    _collect_whois_signal_values(body, values)
    if not values:
        return True
    return any(v not in (None, "", [], {}) for v in values)


def _side(status, result, error, host=None):
    side = {"status": status,
            "ok": error is None and isinstance(status, int) and 200 <= status < 300,
            "result": result, "error": error, "hit": False, "matched": 0}
    if host and side["ok"]:
        filtered, n = filter_host_hits(result, host)
        side["result"] = filtered
        side["matched"] = n
        side["hit"] = n > 0
    return side


def _search_side(status, result, error):
    """A search-scoped list. The row url is where the document was found, not the target."""
    side = _side(status, result, error)
    if side["ok"] and isinstance(result, dict):
        n = next((len(result[k]) for k in ("items", "data", "results")
                  if isinstance(result.get(k), list)), 0)
        side["matched"] = n
        side["hit"] = n > 0
        if isinstance(side["result"], dict):
            side["result"] = dict(side["result"])
            side["result"]["matched"] = n
    return side


def _telegram_handle(value):
    m = re.search(r"(?:t\.me/|telegram\.me/)([A-Za-z0-9_]{4,})", value, re.I)
    if m:
        return m.group(1)
    if re.fullmatch(r"@[A-Za-z0-9_]{4,}", value):
        return value[1:]
    return None


_BANK_PREFIX = re.compile(r"(?i)^(?:bank|stk|account):\s*([\d\s\-]{8,40})$")


def op_route(k, a):
    """One indicator, both APIs, only the endpoints that match its type.
    A list endpoint is a hit only when a row's host is the target, not a substring.
    A bank account is all digits like a phone, so it routes only with an explicit
    `bank:` (or `stk:`) prefix."""
    t = a.target.strip()
    bank = _BANK_PREFIX.match(t)
    if bank:
        a.type, a.value = "bank-account", re.sub(r"[\s\-]", "", bank.group(1))
        return ("route/bank-account", op_ioc(k, a))
    handle = _telegram_handle(t)
    if handle:
        a.handle = handle
        a.q = handle
        sides = {"shield_telegram": _search_side(*op_catalog(k, a, "telegram")),
                 "shield_actor_channels": _search_side(*op_catalog(k, a, "actor-channels"))}
        ok = any(s["ok"] for s in sides.values())
        statuses = [s["status"] for s in sides.values() if s["status"] is not None]
        return ("telegram", (200 if ok else (statuses[0] if statuses else None),
                             {"kind": "telegram", "sides": sides},
                             None if ok else "; ".join(s["error"] for s in sides.values() if s["error"]) or None,
                             (not ok) and bool(statuses) and all(_skipped(s["status"], s["error"]) for s in statuses)))
    if re.fullmatch(r"(?i)cve-\d{4}-\d{4,}", t):
        a.cve = t
        return ("cve", op_catalog(k, a, "vuln"))
    if t.lower().endswith(".onion"):
        a.hostname = t
        return ("onion", op_catalog(k, a, "onion"))
    kind = (_classify(t) if _classify else _classify_local(t))
    ioc = CLASS_TO_IOC.get(kind)
    sides = {}
    if kind in ("url", "domain"):
        a.url = t if "://" in t else "https://" + t
        host = t.split("://", 1)[-1].split("/")[0]
        sides["feeds_checkurl"] = _side(*op_checkurl(k, a))
        a.q = host
        a.search = host
        sides["shield_ransomware"] = _side(*op_catalog(k, a, "ransomware"), host=host)
        sides["shield_clickfix"] = _side(*op_catalog(k, a, "clickfix"), host=host)
        sides["shield_phaas"] = _side(*op_catalog(k, a, "phaas"), host=host)
        sides["shield_internal_leaks"] = _search_side(*op_catalog(k, a, "internal-leaks"))
        sides["shield_defacements"] = _side(*op_catalog(k, a, "defacements"), host=host)
        sides["shield_underground"] = _side(*op_catalog(k, a, "underground"), host=host)
    elif kind == "email":
        a.q = t.split("@", 1)[-1]
        sides["feeds_burner"] = _side(*op_burner(k, a))
    elif kind == "phone":
        a.q = t
        sides["feeds_checkphone"] = _side(*op_checkphone(k, a))
    if ioc:
        a.type, a.value = ioc, t
        a.ai = getattr(a, "ai", False)
        sides["shield_ioc"] = _side(*op_ioc(k, a))
    if not sides:
        return (f"route/{kind}", (None, None,
                f"'{kind}' has no ChongLuaDao endpoint on either API — skipped "
                f"(no metered call).", True))
    ok = any(s["ok"] for s in sides.values())
    statuses = [s["status"] for s in sides.values() if s["status"] is not None]
    status = 200 if ok else (statuses[0] if statuses else None)
    err = None if ok else "; ".join(s["error"] for s in sides.values() if s["error"]) or None
    skipped = (not ok) and bool(statuses) and all(_skipped(s["status"], s["error"]) for s in statuses)
    return (f"route/{kind}", (status, {"kind": kind, "sides": sides}, err, skipped))


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


def _leak_body(a, page=None):
    """The documented dataset body: query + input_type, limit, and the opaque `next` cursor.
    `offset` and `cursor` were removed by the API and are now rejected."""
    body = {"query": a.query, "input_type": getattr(a, "input_type", "auto")}
    limit = getattr(a, "limit", None)
    # the aggregate /search takes no limit — it always returns 3 examples per dataset
    if limit and getattr(a, "op", "") != "leaks":
        body["limit"] = min(int(limit), 100)
    if page:
        body["next"] = page
    return body

def _leak_search(k, a, dataset, follow=False, wait_pending=True):
    """One dataset page, or every page when follow=True. A `pending` block is re-asked until it
    settles or the call budget runs out — repeating a search resumes it, it does not restart."""
    path = f"{DL}/{dataset}/search" if dataset else f"{DL}/search"
    deadline = time.time() + a.timeout
    page, pages, first = getattr(a, "page", None) or None, [], None
    status = result = None
    while time.time() < deadline:
        status, result, error = _request("POST", TI, path, k, body=_leak_body(a, page),
                                         timeout=min(STEP_TIMEOUT, max(1, deadline - time.time())))
        if error or not isinstance(result, dict):
            return status, result, error
        blocks = [b for b in (result.get("results") or []) if isinstance(b, dict)]
        if first is None:
            first = result
        # a pending page is unfinished: repeat the same cursor, never store it
        if wait_pending and any(b.get("status") == "pending" for b in blocks):
            time.sleep(POLL_INTERVAL)
            continue
        if not follow:
            return status, result, None
        pages.extend(blocks)
        nxt = next((b.get("next") for b in blocks if b.get("next")), None)
        if nxt and nxt != page:
            page = nxt
            continue
        out = dict(first)
        out["results"] = pages
        return status, out, None
    return status, result, f"leak search still pending after {a.timeout}s budget"


def op_leaks(k, a):
    """The aggregate preview (≈20 s server wait). A kind still `pending` there is resolved the way
    the API documents it — on that kind's own endpoint, which waits for the search to settle —
    and its block replaces the pending one. A kind that cannot be settled keeps its pending block,
    tagged `settle_error`, and the call returns an error naming it: partial totals are never `ok`."""
    status, result, error = _leak_search(k, a, "", wait_pending=False)
    if error or not isinstance(result, dict):
        return status, result, error
    blocks, unsettled = [], []
    for block in result.get("results") or []:
        kind = block.get("kind") if isinstance(block, dict) else None
        if kind and block.get("status") == "pending":
            sub = argparse.Namespace(**vars(a))
            sub.op, sub.limit, sub.page = kind, 3, None
            _st, res, err = _leak_search(k, sub, kind)
            settled = next((b for b in (res or {}).get("results") or [] if isinstance(b, dict)),
                           None) if not err and isinstance(res, dict) else None
            if settled and settled.get("status") != "pending":
                block = settled
            else:
                reason = err or "still pending"
                block = dict(block, settle_error=reason)
                unsettled.append(f"{kind} ({reason})")
        blocks.append(block)
    out = dict(result)
    out["results"] = blocks
    if unsettled:
        return status, out, "leak kind(s) not settled, totals are partial: " + "; ".join(unsettled)
    return status, out, None

def _follow_pages(a):
    """Page through a dataset unless the caller asked for one page. Following is the default."""
    return not getattr(a, "one_page", False)


def op_breaches(k, a):
    return _leak_search(k, a, "breaches", follow=_follow_pages(a))


def op_machines(k, a):
    return _leak_search(k, a, "machines", follow=_follow_pages(a))


def op_stolen(k, a):
    return _leak_search(k, a, "stolen-credentials", follow=_follow_pages(a))


def op_exposed(k, a):
    return _leak_search(k, a, "exposed-credentials", follow=_follow_pages(a))


def op_cookies(k, a):
    return _leak_search(k, a, "cookies", follow=_follow_pages(a))



def op_full_export(k, a):
    """Start the exhaustive export and poll it. The API asks for one poll a minute, and a broad
    query takes hours, so the interval is 60s rather than the 5s used for interactive lookups."""
    status, result, error = _request("POST", TI, f"{DL}/full-export/start", k,
                                     body={"query": a.query}, timeout=STEP_TIMEOUT)
    job = (result or {}).get("job_id") if isinstance(result, dict) else None
    if error or not job:
        return status, result, error or "no job_id in start response"
    deadline = time.time() + a.timeout
    while time.time() < deadline:
        status, result, error = _request(
            "GET", TI, f"{DL}/full-export/poll/{urllib.parse.quote(job, safe='')}",
            k, timeout=STEP_TIMEOUT)
        if error:
            return status, result, error
        state = (result or {}).get("status")
        if state == "completed":
            return status, result, None
        if state == "failed":
            return status, result, (result or {}).get("error") or "export failed"
        time.sleep(60)
    return status, result, f"export {job} still running after {a.timeout}s budget"


# ───────────────────────────────────────────────────────── TI: GET catalog
# One row per documented GET endpoint: name → (path, [(flag, param, kind)]), parity with the
# OpenAPI contract named in the module docstring. A {token} in the path is a positional argument;
# kind "pos" is a positional query parameter; "str"/"int"/"bool" are optional --flags.
RW = "/api/v1/ransomware/external"
TX = "/api/v1/ioc/external"
_LO = [("limit", "limit", "int"), ("offset", "offset", "int")]
_SORT = [("sort", "sort", "str")]
_PAGE = [("page", "page", "int"), ("page-size", "page_size", "int")]
_TAXII_PAGE = [("limit", "limit", "int"), ("next", "next", "str"), ("type", "type", "str")]
_CATALOG = {
    # Threat Feeds
    "vulns": (TF + "/vulnerabilities", [("q", "q", "str"), ("severity", "severity", "str"),
                                        ("vendor", "vendor", "str"), ("product", "product", "str"),
                                        ("kev", "known_exploited", "bool"), ("since", "since", "str"),
                                        ("until", "until", "str")] + _SORT + _LO),
    "vuln": (TF + "/vulnerabilities/{cve}", []),
    "actors": (TF + "/threat-actors", [("q", "q", "str"), ("type", "actor_type", "str"),
                                       ("attack-type", "attack_type", "str"),
                                       ("channel-platform", "channel_platform", "str")] + _SORT + _LO),
    "actor": (TF + "/threat-actors/{actor_id}", []),
    "actor-usernames": (TF + "/threat-actor-usernames",
                        [("q", "q", "pos"), ("forum", "forum", "str")] + _SORT + _LO),
    "actor-channels": (TF + "/actor-channels", [("q", "q", "str"), ("platform", "platform", "str"),
                                                ("status", "status", "str")] + _SORT + _LO),
    "c2": (TF + "/c2-frameworks", [("q", "q", "str")] + _SORT + _LO),
    "c2-get": (TF + "/c2-frameworks/{framework_id}", []),
    "lolbin": (TF + "/living-off-the-land", [("q", "q", "str"), ("platform", "platform", "str"),
                                             ("category", "category", "str")] + _SORT + _LO),
    "lolbin-get": (TF + "/living-off-the-land/{entry_id}", []),
    "defacements": (TF + "/defacements", [("q", "q", "str"), ("country", "country", "str"),
                                          ("since", "since", "str"), ("until", "until", "str")]
                    + _SORT + _LO),
    "defacement": (TF + "/defacements/{defacement_id}", []),
    "underground": (TF + "/underground-directory", [("q", "q", "str"), ("category", "category", "str"),
                                                    ("subcategory", "subcategory", "str"),
                                                    ("tld", "tld", "str")] + _SORT + _LO),
    "underground-categories": (TF + "/underground-directory/categories", []),
    "onion": (TF + "/onion-blocklist/check", [("hostname", "hostname", "pos")]),
    "incidents": (TF + "/incidents", [("q", "q", "str"), ("category", "category", "str"),
                                      ("severity", "severity", "str"), ("country", "country", "str"),
                                      ("actor", "actor", "str"), ("network", "network", "str"),
                                      ("since", "since", "str"), ("until", "until", "str")]
                  + _SORT + _LO),
    "incident": (TF + "/incidents/{incident_id}", []),
    "clickfix": (TF + "/clickfix", [("q", "q", "str"), ("country", "country", "str"),
                                    ("status", "status", "str")] + _SORT + _LO),
    "clickfix-get": (TF + "/clickfix/{site_id}", []),
    "phaas": (TF + "/phaas", [("q", "q", "str"), ("country", "country", "str"),
                              ("family", "family", "str"), ("tag", "tag", "str")] + _SORT + _LO),
    "phaas-get": (TF + "/phaas/{site_id}", []),
    "seized-markets": (TF + "/seized-markets", [("q", "q", "str")] + _SORT + _LO),
    "telegram": (TF + "/telegram/posts", [("q", "q", "str"), ("handle", "handle", "str"),
                                          ("channel-id", "channel_id", "str")] + _SORT + _LO),
    "telegram-channels": (TF + "/telegram/channels", [("limit", "limit", "int")]),
    "tf-stats": (TF + "/stats/{view}", [("limit", "limit", "int"), ("days", "days", "int")]),
    # Ransomware Monitoring (page / page_size pagination)
    "ransomware": (RW + "/victims", [("q", "q", "pos"), ("group", "group", "str"),
                                     ("country", "country", "str"), ("sector", "sector", "str"),
                                     ("year", "year", "int"), ("month", "month", "int")]
                   + _SORT + [("order", "order", "str")] + _PAGE),
    "ransomware-victim": (RW + "/victims/{victim_id}", []),
    "ransomware-stats": (RW + "/statistics", [("country", "country", "str")]),
    "ransomware-monthly": (RW + "/statistics/monthly",
                           [("group", "group", "str"), ("country", "country", "str"),
                            ("year-from", "year_from", "int"), ("year-to", "year_to", "int")]),
    "ransomware-by-country": (RW + "/statistics/by-country", []),
    "ransomware-by-sector": (RW + "/statistics/by-sector",
                             [("country", "country", "str"), ("group", "group", "str")]),
    "ransomware-by-group": (RW + "/statistics/by-group", [("country", "country", "str")]),
    "ransomware-groups": (RW + "/groups", [("q", "q", "str")] + _SORT + [("order", "order", "str")]
                          + _PAGE),
    "ransomware-group": (RW + "/groups/{name}", []),
    "ransomware-press": (RW + "/press", [("q", "q", "str"), ("country", "country", "str"),
                                         ("year", "year", "int"), ("month", "month", "int")] + _PAGE),
    "sec-filings": (RW + "/sec-filings", [("q", "q", "str"), ("ticker", "stock_ticker", "str"),
                                          ("year", "year", "int"), ("month", "month", "int")] + _PAGE),
    "decryptors": (RW + "/decryptors", [("q", "q", "str"), ("group", "group", "str")] + _PAGE),
    # Data Leaks / Brand Protection (single records)
    "internal-leaks": (DL + "/internal-leaks", [("search", "search", "pos"),
                                                ("severity", "severity", "str")] + _LO),
    "internal-leak": (DL + "/internal-leaks/{leak_id}", []),
    "brand-domain": ("/api/v1/brand-protection/external/domains/{domain_id}", []),
    # TAXII 2.1 / 1.x (the only collection is `indicators`)
    "taxii2": (TX + "/taxii2", []),
    "taxii2-root": (TX + "/taxii2/default", []),
    "taxii2-collections": (TX + "/taxii2/default/collections", []),
    "taxii2-collection": (TX + "/taxii2/default/collections/{collection_id}", []),
    "taxii2-objects": (TX + "/taxii2/default/collections/{collection_id}/objects",
                       _TAXII_PAGE + [("added-after", "added_after", "str")]),
    "taxii2-manifest": (TX + "/taxii2/default/collections/{collection_id}/manifest",
                        _TAXII_PAGE + [("added-after", "added_after", "str")]),
    "taxii1": (TX + "/taxii1/discovery", []),
    "taxii1-poll": (TX + "/taxii1/poll/{collection_id}",
                    _TAXII_PAGE + [("observed-after", "observed_after", "str")]),
    # Webhooks (read side; writes are the webhook-* ops below)
    "webhooks": ("/api/v1/webhooks", [("module", "module", "str")]),
    "webhook": ("/api/v1/webhooks/{subscription_id}", []),
    "webhook-deliveries": ("/api/v1/webhooks/{subscription_id}/deliveries", [("limit", "limit", "int")]),
}
# positional path tokens that are a fixed set of multi-segment sub-paths
_POS_CHOICES = {"view": ("summary", "vulnerabilities/by-severity", "vulnerabilities/top-vendors",
                         "vulnerabilities/timeline", "defacements/monthly", "defacements/by-country",
                         "actors/by-type")}
# whole-corpus lists: refuse to run them without at least one filter (an unfiltered list is not a lookup)
_NEEDS_FILTER = {"clickfix", "phaas", "telegram", "defacements", "underground", "seized-markets",
                 "actor-channels", "ransomware-groups", "ransomware-press", "sec-filings", "decryptors"}
_PAGING_PARAMS = {"limit", "offset", "page", "page_size", "sort", "order"}
# TAXII envelopes carry `more` + `next`; --all follows them
_FOLLOW_NEXT = {"taxii2-objects", "taxii2-manifest"}


def _has_filter(a, name):
    return any(getattr(a, flag.replace("-", "_"), None) not in (None, False, "")
               for flag, param, _kind in _CATALOG[name][1] if param not in _PAGING_PARAMS)


def op_catalog(k, a, name=None):
    name = name or a.op
    path, flags = _CATALOG[name]
    for token in re.findall(r"\{(\w+)\}", path):
        safe = "/" if token in _POS_CHOICES else ""
        path = path.replace("{" + token + "}", urllib.parse.quote(str(getattr(a, token)), safe=safe))
    params = {}
    for flag, param, kind in flags:
        value = getattr(a, flag.replace("-", "_"), None)
        if value is None or (kind == "bool" and not value):
            continue
        params[param] = "true" if kind == "bool" else value
    if name in _FOLLOW_NEXT and getattr(a, "all", False):
        return _follow_envelope(k, path, params, a.timeout)
    return _request("GET", TI, path, k, params=params or None, timeout=a.timeout)


def _merge_rows(into, rows, seen, key):
    for row in rows or []:
        rid = row.get(key) if isinstance(row, dict) else None
        if rid is not None:
            if rid in seen:
                continue
            seen.add(rid)
        into.append(row)


def _follow_envelope(k, path, params, timeout):
    """Follow a TAXII envelope's `next` while `more` is true and merge its `objects`."""
    deadline = time.time() + timeout
    objects, seen, first = [], set(), None
    while True:
        st, res, err = _request("GET", TI, path, k, params=params or None,
                                timeout=max(1, deadline - time.time()))
        if err or not isinstance(res, dict):
            return st, res, err
        first = first or res
        _merge_rows(objects, res.get("objects"), seen, "id")
        nxt = res.get("next")
        if not (res.get("more") and nxt) or nxt == params.get("next"):
            break
        params = dict(params, next=nxt)
        if time.time() >= deadline:
            out = dict(first, objects=objects, more=True, next=nxt)
            return st, out, f"stopped after {timeout}s budget; resume with --next {nxt}"
    return st, dict(first, objects=objects, more=False, next=None), None


# ───────────────────────────────────────────────────────── TI: feeds, brand, webhooks
_FEED_PATHS = {"stix2": TX + "/feeds/stix2", "misp": TX + "/feeds/misp", "stix1": TX + "/feeds/stix1"}


def _feed_rows(fmt, body):
    """(container, list key, dedupe key) holding a feed page's indicators."""
    if fmt == "stix2":
        return body, "objects", "id"
    event = body.get("Event") if isinstance(body.get("Event"), dict) else {}
    return event, "Attribute", "uuid"


def op_feed(k, a):
    """One feed page, or every page with --all (the cursor is the X-Next response header). The
    next cursor lands in the envelope as `next` (stderr under --raw, so the body stays loadable)."""
    if a.all and a.format == "stix1":
        return None, None, "--all merges JSON pages only; page STIX 1.x with --next"
    params = {"limit": a.limit, "type": a.type, "observed_after": a.observed_after, "next": a.next,
              "correlate": "true" if a.format == "misp" and a.correlate else None}
    deadline = time.time() + a.timeout
    merged, rows, seen = None, [], set()
    while True:
        st, res, err = _request("GET", TI, _FEED_PATHS[a.format], k, params=params,
                                timeout=max(1, deadline - time.time()))
        nxt = _header("x-next")
        if err or not isinstance(res, dict):
            if nxt and not err:
                _EXTRA["next"] = nxt
            return st, merged or res, err
        merged = merged or res
        container, list_key, id_key = _feed_rows(a.format, res)
        _merge_rows(rows, container.get(list_key), seen, id_key)
        if not (a.all and nxt) or nxt == params.get("next") or time.time() >= deadline:
            break
        params = dict(params, next=nxt)
    container, list_key, _ = _feed_rows(a.format, merged)
    container[list_key] = rows
    if nxt:
        _EXTRA["next"] = nxt
    if a.all and nxt:
        return st, merged, f"feed stopped after {a.timeout}s budget; resume with --next {nxt}"
    return st, merged, None


def _scalar(value):
    return int(value) if re.fullmatch(r"-?\d+", value) else value


def op_brand_domains(k, a):
    """The SQL-like brand-protection query. --where field:operator:value (repeatable, AND-ed;
    `in` takes a comma list, is_empty/is_not_empty take no value), --order-by field[:asc|desc]."""
    where = []
    for clause in a.where or []:
        field, _, rest = clause.partition(":")
        operator, _, value = rest.partition(":")
        operator = operator or "eq"
        item = {"field": field, "operator": operator}
        if operator not in ("is_empty", "is_not_empty"):
            item["value"] = [_scalar(v) for v in value.split(",")] if operator == "in" else _scalar(value)
        where.append(item)
    order_by = []
    for spec in a.order_by or []:
        field, _, direction = spec.partition(":")
        order_by.append({"field": field, "dir": direction or "asc"})
    body = {"fields": a.field, "where": where or None, "group_by": a.group_by,
            "order_by": order_by or None, "limit": a.limit, "offset": a.offset}
    return _request("POST", TI, "/api/v1/brand-protection/external/domains", k,
                    body={key: v for key, v in body.items() if v is not None}, timeout=a.timeout)


WH = "/api/v1/webhooks"


def _wh_path(a, suffix=""):
    return f"{WH}/{urllib.parse.quote(str(a.subscription_id), safe='')}{suffix}"


def _wh_body(a):
    body = {"url": a.url, "name": a.name, "modules": a.module, "secret": a.secret,
            "is_active": getattr(a, "active", None)}
    return {key: v for key, v in body.items() if v is not None}


def op_webhook_create(k, a):
    return _request("POST", TI, WH, k, body=_wh_body(a), timeout=a.timeout)


def op_webhook_update(k, a):
    body = _wh_body(a)
    if not body:
        return None, None, "nothing to update: pass --url/--name/--module/--secret/--active/--paused"
    return _request("PATCH", TI, _wh_path(a), k, body=body, timeout=a.timeout)


def op_webhook_delete(k, a):
    return _request("DELETE", TI, _wh_path(a), k, timeout=a.timeout)


def op_webhook_test(k, a):
    body = {"simulate_event": bool(a.simulate)}
    if a.event_type:
        body["event_type"] = a.event_type
    if a.payload:
        try:
            body["custom_payload"] = json.loads(a.payload)
        except ValueError as e:
            return None, None, f"--payload is not JSON: {e}"
    return _request("POST", TI, _wh_path(a, "/test"), k, body=body, timeout=a.timeout)


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

    p = sub.add_parser("route", help="both APIs: Feeds check + Shield IoC (and ransomware/ClickFix for a domain)")
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

    def _leak_parser(name, help_text):
        sp = sub.add_parser(name, help=help_text)
        sp.add_argument("query")
        sp.add_argument("--input-type", dest="input_type", choices=LEAK_INPUT_TYPES, default="auto")
        sp.add_argument("--limit", type=int, default=25)
        sp.add_argument("--page", help="opaque `next` cursor to start from; later pages still follow")
        sp.add_argument("--one-page", action="store_true",
                        help="return only this page; the default follows `next` until the dataset ends")
        sp.add_argument("--all", action="store_true",
                        help="accepted, no effect: following every page is already the default")
        return sp

    _leak_parser("leaks", "TI: one preview across every leak dataset (3 examples each)")
    for name, h in (("breaches", "TI: breach collections for a domain/account"),
                    ("machines", "TI: infected devices (IP, hostname, malware family, credentials)"),
                    ("stolen-credentials", "TI: stolen login records"),
                    ("cookies", "TI: browser cookie records"),
                    ("exposed-credentials", "TI: exposed username/password pairs")):
        _leak_parser(name, h)
    sub.add_parser("full-export", help="TI: exhaustive leak export, polled once a minute (hours)").add_argument("query")

    p = sub.add_parser("brand-domains", help="TI: brand-protection lookalike domains (SQL-like query)")
    p.add_argument("--where", action="append", metavar="FIELD:OP:VALUE",
                   help="filter, repeatable (AND). OP: eq ne gt gte lt lte in contains starts_with "
                        "ends_with is_empty is_not_empty; `in` takes a comma list")
    p.add_argument("--field", action="append", help="field to return (repeatable)")
    p.add_argument("--group-by", dest="group_by", action="append", help="group field (repeatable)")
    p.add_argument("--order-by", dest="order_by", action="append", metavar="FIELD[:asc|desc]")
    p.add_argument("--limit", type=int); p.add_argument("--offset", type=int)
    p = sub.add_parser("feed", help="TI: indicator feed (STIX 2.1 / MISP / STIX 1.x)")
    p.add_argument("format", choices=sorted(_FEED_PATHS))
    p.add_argument("--limit", type=int, default=1000, help="indicators per page (max 1000)")
    p.add_argument("--type", help="one indicator type: asn cidr cve domain email hostname ip "
                                  "ip:port ja3 md5 sha1 sha256 ssl_fingerprint url")
    p.add_argument("--observed-after", dest="observed_after", help="ISO date filter")
    p.add_argument("--next", help="X-Next cursor from a previous page")
    p.add_argument("--correlate", action="store_true", help="misp only: allow MISP correlation")
    p.add_argument("--all", action="store_true", help="follow X-Next and merge every page (JSON formats)")

    p = sub.add_parser("webhook-create", help="TI: register an HTTPS webhook (POST /api/v1/webhooks)")
    p.add_argument("url"); p.add_argument("--name"); p.add_argument("--secret")
    p.add_argument("--module", action="append",
                   help="module or alias, repeatable (data-leaks, impersonation-watch, threat-feeds, "
                        "ransomware-monitoring); omitted = every enabled module")
    p = sub.add_parser("webhook-update", help="TI: update a webhook (PATCH, only given fields)")
    p.add_argument("subscription_id"); p.add_argument("--url"); p.add_argument("--name")
    p.add_argument("--secret"); p.add_argument("--module", action="append")
    state = p.add_mutually_exclusive_group()
    state.add_argument("--active", dest="active", action="store_const", const=True)
    state.add_argument("--paused", dest="active", action="store_const", const=False)
    p = sub.add_parser("webhook-delete", help="TI: permanently delete a webhook subscription")
    p.add_argument("subscription_id")
    p = sub.add_parser("webhook-test", help="TI: send a test delivery to a webhook")
    p.add_argument("subscription_id")
    p.add_argument("--simulate", action="store_true", help="send a realistic finding, not a ping")
    p.add_argument("--event-type", dest="event_type", help="e.g. threat_feeds.cve_published")
    p.add_argument("--payload", help="custom JSON payload")

    sub.add_parser("probe", help="validate the configured key (fast)")
    for name, (path, flags) in _CATALOG.items():
        sp = sub.add_parser(name, help="TI: GET " + path)
        for token in re.findall(r"\{(\w+)\}", path):
            sp.add_argument(token, choices=_POS_CHOICES.get(token))
        for flag, _param, kind in flags:
            if kind == "pos":
                sp.add_argument(flag)
            else:
                extra = {"help": "sort column; descending is --sort=-<column> (with '=')"} \
                    if flag == "sort" and name not in ("ransomware", "ransomware-groups") else {}
                sp.add_argument("--" + flag, **({"action": "store_true"} if kind == "bool"
                                                else {"type": int} if kind == "int" else extra))
        if name in _FOLLOW_NEXT:
            sp.add_argument("--all", action="store_true", help="follow `next` and merge every page")
    for spx in sub.choices.values():          # flags accepted post-subcommand, no clobber
        spx.add_argument("--pretty", action="store_true", help="pretty-print JSON")
        spx.add_argument("--raw", action="store_true",
                         help="emit only the provider body (loadable STIX/MISP/JSON), no envelope")
        spx.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                         help="per-call / async-budget ceiling in seconds (default 5000 ≈ 83 min)")
    return ap


DISPATCH = {
    "checkurl": op_checkurl, "analyze": op_analyze, "denylist": op_denylist,
    "checkphone": op_checkphone, "whois": op_whois, "burner": op_burner,
    "ioc": op_ioc, "leaks": op_leaks, "breaches": op_breaches,
    "machines": op_machines, "stolen-credentials": op_stolen,
    "exposed-credentials": op_exposed, "cookies": op_cookies,
    "full-export": op_full_export, "brand-domains": op_brand_domains,
    "feed": op_feed, "probe": op_probe,
    "webhook-create": op_webhook_create, "webhook-update": op_webhook_update,
    "webhook-delete": op_webhook_delete, "webhook-test": op_webhook_test,
}
DISPATCH.update({name: (lambda k, a, n=name: op_catalog(k, a, n)) for name in _CATALOG})


def _input_label(a):
    for attr in ("target", "url", "value", "search", "query", "q", "hostname", "cve",
                 "view", "name", "actor_id", "framework_id", "entry_id", "defacement_id",
                 "incident_id", "site_id", "victim_id", "leak_id", "domain_id", "collection_id",
                 "subscription_id", "format"):
        if getattr(a, attr, None) is not None:
            return getattr(a, attr)
    return None


def _usage_sink():
    """The shared api_usage module, case-tagged from $WP_CASE_DIR; None (with a warning) if absent."""
    tools = os.path.normpath(os.path.join(HERE, "..", "..", "intel_engine", "WebPivot", "tools"))
    if tools not in sys.path:
        sys.path.insert(0, tools)
    try:
        import api_usage  # type: ignore
    except Exception as e:
        print(f"[cld_api] WARNING: api_usage ledger unavailable ({type(e).__name__}); "
              "calls are counted in the envelope only.", file=sys.stderr)
        return None
    case_dir = os.environ.get("WP_CASE_DIR")
    api_usage.set_context(case=os.path.basename(os.path.normpath(case_dir)) if case_dir else None,
                          skill="cld")
    return api_usage


def main(argv=None):
    a = build_parser().parse_args(argv)
    key = _api_key()
    if not key:
        print(json.dumps({"tool": "chongluadao", "op": a.op, "ok": False, "status": None,
                          "skipped": False, "result": None, "error": "no ChongLuaDao API key "
                          "(set CHONGLUADAO_API_KEY / CLD_API_KEY, or run /apikeys set chongluadao)"},
                         ensure_ascii=False))
        return 3
    if a.op in _NEEDS_FILTER and not _has_filter(a, a.op):
        filters = [f"--{flag}" for flag, param, _k in _CATALOG[a.op][1] if param not in _PAGING_PARAMS]
        print(json.dumps({"tool": "chongluadao", "op": a.op, "ok": False,
                          "error": f"requires a filter ({' / '.join(filters)}). "
                                   "An unfiltered list is not a lookup."}))
        return 2
    # pre-flight passed: from here every HTTP request this process sends is ledgered
    enable_ledger(_usage_sink(), query=_input_label(a))
    if a.op == "route":
        op_name, tup = op_route(key, a)
        status, result, error = tup[0], tup[1], tup[2]
        skipped = tup[3] if len(tup) > 3 else False
        return _emit(op_name, a.target, status, result, error, a.pretty, skipped, a.raw,
                     usage=usage_summary())
    status, result, error = DISPATCH[a.op](key, a)
    return _emit(a.op, _input_label(a), status, result, error, a.pretty, raw=a.raw,
                 usage=usage_summary())


if __name__ == "__main__":
    sys.exit(main() or 0)
