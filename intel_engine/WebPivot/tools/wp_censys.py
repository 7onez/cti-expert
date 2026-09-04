#!/usr/bin/env python3
"""wp_censys — Censys **Platform** API client + CenQL query builder for WebPivot.

WHAT CENSYS ADDS THAT THE OTHER ENGINES DON'T
---------------------------------------------
FOFA/urlscan index what a page LOOKS like; Censys indexes what the SERVER presents. Three of its
views are pivots nothing else in WebPivot gives you cleanly:

  - **certificate lookup by SHA-256** -> `names`: every hostname Censys has ever seen on that exact
    leaf certificate. crt.sh gives you name overlap; this gives you the cert's own name list, which
    is the cleanest cross-brand "one operator, many apexes" link there is.
  - **web property** (`hostname:port`) -> the operator's TLS cert, favicon hashes, body hash,
    software stack and labels for the hostname the victim actually typed — not for an IP.
  - **host** (`ip`) -> ASN/WHOIS org, forward+reverse DNS names, every open port and its banner.

THE FREE PLAN IS THE CONSTRAINT — READ THIS BEFORE ADDING A CALL
----------------------------------------------------------------
A Censys **Free** account can call ONLY the lookup endpoints. `POST /v3/global/search/query`
answers 403 — searching by favicon hash / body keyword / JARM is Starter and above. So:

  - every function here that needs search **degrades to `{"skipped": ...}` with the reason**, and
  - **every** Censys pivot also emits a `platform.censys.io/search?q=` URL, because a free analyst
    CAN run the exact same CenQL by hand in the web UI (1 page of 100 results, 5 credits).

CREDITS ARE THE REAL CONSTRAINT — 100 A MONTH, NO ROLLOVER
-----------------------------------------------------------
Censys meters everything in **credits**: a lookup is 1, a search is 5 (8 with regex), and a Free
account gets **100 a month that do not roll over**. Twenty searches empty the month — and the month
is per ACCOUNT, so a careless batch does not just spoil its own run, it takes Censys away from every
later case until the 1st. This is the tightest budget in the toolkit and is treated accordingly:

  - **spend is tracked and capped BEFORE the call** (`budget_status` / `_budget_block`), summed from
    `MEMORY/api_usage.jsonl` across every case, with a per-run blast-radius cap and a reserve that
    keeps the cheap 1-credit lookups affordable when a 5-credit search would empty the balance.
    Over budget -> the same `{"skipped": reason}` degradation as a plan 403, never a 402 surprise;
  - the **UI link is not free either** — running the emitted CenQL in the web console costs the same
    5 credits, so every UI entry states its price rather than reading as a free escape hatch;
  - Censys is **skipped under `--free-only`**, disabled by `--no-censys`, memoised per process, and
    every call is logged via `api_usage.record`.

Thresholds are DATA (`references/censys_queries.json` -> `credit_budget`), overridable per run with
`CENSYS_MONTHLY_CREDITS` / `CENSYS_MAX_CREDITS_PER_RUN`.

CENQL, NOT LEGACY SEARCH SYNTAX
--------------------------------
Censys replaced the Legacy Search language with CenQL, which namespaces every field under `host.` /
`web.` / `cert.`. A Censys query copied from an older write-up (`services.tls.certificates.leaf_data
.fingerprint_sha256:...`) does not run on the Platform. The current field names are DATA in
`references/censys_queries.json` — when Censys renames one, edit the JSON, not this file.

Auth: `CENSYS_PAT` (a Personal Access Token from the Platform web console -> user icon -> API
Access -> Create New Token), optionally `CENSYS_ORG_ID`. No token -> every network function returns
None and the query BUILDER still works, keyless, exactly like the rest of WebPivot.

CLI:
  python3 wp_censys.py host 1.2.3.4
  python3 wp_censys.py webproperty example.com[:443]
  python3 wp_censys.py cert <sha256>
  python3 wp_censys.py search 'web.hostname="example.com"' [--page-size 50]
  python3 wp_censys.py query favicon_hash <md5>        # offline — builds CenQL + UI URL, no key
  python3 wp_censys.py budget                          # offline — this month's credit balance
"""
import argparse
import copy
import datetime
import json
import os
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request

from wp_common import *  # noqa — DEFAULT_UA, _secret, uniq
from wp_refs import ref_path, load_ref  # noqa — reference DATA lives in references/*.json
import wp_plans as _plans               # per-case on-disk entitlement store (the search is the probe)

try:
    import api_usage                      # licensed-API credit ledger
except Exception:
    api_usage = None

API_BASE = "https://api.platform.censys.io"
UI_SEARCH = "https://platform.censys.io/search?q="

# --- reference DATA (RULE 3): field names, prices and entitlements are Censys product constants
#     that change without our code changing. The fallbacks below are the bare minimum that keeps
#     a favicon/cert pivot working if the JSON goes missing — load_ref warns loudly when it does.
_CENSYS_FALLBACK = {
    "cenql_templates": {
        "favicon_md5": ["web.endpoints.http.favicons.hash_md5={value}"],
        "tls_fingerprint_sha256": ["cert.fingerprint_sha256={value}"],
        "hostname": ['web.hostname="{value}"'],
        "ip": ["host.ip={value}"],
    },
    "pivot_kind_map": {
        "favicon_hash": "favicon_md5",
        "tls_cert:fingerprint_sha256": "tls_fingerprint_sha256",
        "domain": "hostname",
        "ip": "ip",
    },
    "credit_costs": {"entity_lookup": 1, "standard_query": 5, "advanced_query": 8,
                     "free_monthly_credits": 100},
    # Deliberately the CONSERVATIVE minimum: if the data file is unreadable the guard must still
    # refuse to overspend. The two thresholds not listed here fall back to the stricter of the
    # defaults at their call sites, so a broken file cannot silently unlock a bigger spend.
    "credit_budget": {"monthly_credits": 100, "max_credits_per_run": 20,
                      "block_when_exhausted": True},
    "plan_capabilities": {"free": {"api_search": False}},
    "endpoints": {"lookup_host": "/v3/global/asset/host/{id}",
                  "search_query": "/v3/global/search/query"},
}
_REFS = load_ref(ref_path(__file__, "censys_queries.json"), _CENSYS_FALLBACK)
CENQL_TEMPLATES = _REFS["cenql_templates"]
PIVOT_KIND_MAP = _REFS["pivot_kind_map"]
CREDIT_COSTS = _REFS["credit_costs"]
CREDIT_BUDGET = _REFS["credit_budget"]
PLAN_CAPABILITIES = _REFS["plan_capabilities"]
ENDPOINTS = _REFS["endpoints"]

# One process = one case. The free tier grants 100 credits a MONTH, so paying twice for the same
# IP inside a single run is a real cost, not a style point. Memoised per (kind, id).
_MEMO = {}
_MEMO_LOCK = threading.Lock()


# --------------------------------------------------------------------------- auth / transport
def censys_token():
    """The Personal Access Token, or None. `CENSYS_PAT` is the documented name; the aliases are
    what analysts who came from the legacy API tend to export."""
    return _secret("CENSYS_PAT", "CENSYS_API_KEY", "CENSYS_TOKEN")


# Master off switch, flipped by `pivot_extract --no-censys`. Only the NETWORK calls honour it —
# the CenQL builder is offline and free, so it keeps emitting queries either way.
ENABLED = True


def censys_configured() -> bool:
    """True when a PAT is available and Censys isn't switched off — the gate every caller checks
    before spending a credit."""
    return ENABLED and bool(censys_token())


def _headers():
    h = {"User-Agent": DEFAULT_UA, "Accept": "application/json"}
    tok = censys_token()
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    org = _secret("CENSYS_ORG_ID", "CENSYS_ORGANIZATION_ID")
    if org:
        h["X-Organization-ID"] = org
    return h


# HTTP status -> the analyst-readable reason. The whole point is that a Free-plan 403 on
# /search/query reads as "your plan can't do this, here is the UI link" and NOT as a bare error.
_STATUS_REASON = {
    401: "Censys rejected the token (CENSYS_PAT missing, expired, or lacking the API Access role)",
    402: "Censys credits exhausted — a Free account gets %s per month and they do not roll over"
         % CREDIT_COSTS.get("free_monthly_credits", 100),
    403: "your Censys plan does not allow this endpoint — the FREE plan exposes ONLY the lookup "
         "endpoints (host / web property / certificate); search needs Starter or above",
    404: "not in the Censys dataset",
    429: "Censys rate limit — Free/Starter allow 1 concurrent action",
}


def _call(path: str, *, method: str = "GET", body: dict = None, timeout: int = 30):
    """One Platform API call -> (data, error_dict). Never raises.

    `error_dict` is `{"skipped": reason}` for the plan/credit/auth conditions the caller is
    expected to survive, and `{"error": ...}` for anything genuinely unexpected."""
    if not censys_configured():
        return None, {"skipped": "no CENSYS_PAT configured"}
    url = API_BASE + path
    data = json.dumps(body).encode() if body is not None else None
    headers = _headers()
    if data:
        headers["Content-Type"] = "application/json"
    try:
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r), None
    except urllib.error.HTTPError as e:
        reason = _STATUS_REASON.get(e.code)
        detail = ""
        try:
            detail = (json.loads(e.read().decode()).get("error") or {}).get("message") or ""
        except Exception:
            pass
        msg = f"HTTP {e.code}" + (f" — {reason}" if reason else "") + (f" ({detail})" if detail else "")
        # 404 is a fact about the target, not a failure of ours; the rest are conditions the
        # caller degrades around. Only a 5xx/unknown code is an actual error.
        if e.code in _STATUS_REASON:
            return None, {"skipped": msg, "http": e.code}
        return None, {"error": msg, "http": e.code}
    except Exception as e:                              # network/timeout/parse
        return None, {"error": str(e)}


def _record(action: str, credits: int, query: str, results=None, ok: bool = True):
    if credits:
        _spend(credits)
    if api_usage:
        api_usage.record("censys", action, credits=credits, query=query, results=results, ok=ok)


# --------------------------------------------------------------------------- credit BUDGET guard
# The free plan grants 100 credits a MONTH and they do not roll over. Four searches a day empties
# it, and the failure mode is nasty: the month dies silently mid-case and every LATER case loses
# Censys too. So the spend is tracked against the ledger and capped BEFORE the call, rather than
# discovered as an HTTP 402 halfway through a batch. Thresholds are DATA (references/censys_queries
# .json → credit_budget); the env overrides exist for the analyst who bought credits today and does
# not want to edit a tracked file for one run.
_RUN_SPENT = 0
_MONTH_SPENT = None          # summed from the ledger once per process
_WARNED = set()
_BUDGET_LOCK = threading.Lock()


def _budget(key: str, env: str = None, default=0):
    if env:
        raw = _secret(env)
        if raw:
            try:
                return int(float(raw))
            except ValueError:
                print(f"[censys] WARNING: {env}={raw!r} is not a number; using the reference value.",
                      file=sys.stderr)
    return CREDIT_BUDGET.get(key, default)


def _ledger_path():
    if api_usage:
        return api_usage._log_path()
    return _secret("API_USAGE_LOG") or os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "MEMORY", "api_usage.jsonl")


def month_spent(refresh: bool = False) -> int:
    """Censys credits already spent this UTC month, read from the api_usage ledger.

    The ledger is the same file `api_usage.record` appends to, so this counts every Censys call
    made by ANY tool or case this month — which is the number that matters, since the quota is per
    account, not per case. Unreadable ledger -> 0 (never block work because a log is missing)."""
    global _MONTH_SPENT
    with _BUDGET_LOCK:
        if _MONTH_SPENT is not None and not refresh:
            return _MONTH_SPENT
    month = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m")
    total = 0
    try:
        with open(_ledger_path(), encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or '"censys"' not in line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                if rec.get("provider") == "censys" and (rec.get("ts") or "").startswith(month):
                    total += rec.get("credits") or 0
    except FileNotFoundError:
        total = 0
    except Exception as exc:
        print(f"[censys] WARNING: could not read the credit ledger ({exc}); the monthly budget "
              f"guard is running on this process's spend only.", file=sys.stderr)
        total = 0
    with _BUDGET_LOCK:
        _MONTH_SPENT = total
    return total


def _spend(credits: int) -> None:
    global _RUN_SPENT, _MONTH_SPENT
    with _BUDGET_LOCK:
        _RUN_SPENT += credits
        if _MONTH_SPENT is not None:
            _MONTH_SPENT += credits


def budget_status() -> dict:
    """Where the month's Censys credits stand — the number to quote when reporting cost."""
    limit = _budget("monthly_credits", "CENSYS_MONTHLY_CREDITS", 100)
    run_cap = _budget("max_credits_per_run", "CENSYS_MAX_CREDITS_PER_RUN", 20)
    spent = month_spent()
    return {"monthly_credits": limit, "spent_this_month": spent,
            "remaining_this_month": max(0, limit - spent),
            "spent_this_run": _RUN_SPENT, "max_credits_per_run": run_cap,
            "reserve_for_lookups": _budget("reserve_for_lookups", default=10),
            "ledger": _ledger_path(), "month": datetime.datetime.now(
                datetime.timezone.utc).strftime("%Y-%m")}


def _budget_block(cost: int, action: str, is_search: bool = False):
    """None when `cost` credits may be spent, else the analyst-readable reason not to.

    Returned as a `skipped` reason, never an exception: a Censys call that cannot be afforded is
    the same class of outcome as one the plan does not allow — the CenQL query and its UI link are
    still the deliverable."""
    b = budget_status()
    if not CREDIT_BUDGET.get("block_when_exhausted", True):
        return None
    if b["spent_this_run"] + cost > b["max_credits_per_run"]:
        return (f"per-run Censys credit cap reached ({b['spent_this_run']}/"
                f"{b['max_credits_per_run']} credits spent this run; {action} needs {cost}). "
                f"Raise CENSYS_MAX_CREDITS_PER_RUN for a run that genuinely needs it, or run the "
                f"emitted CenQL in the Censys web UI instead.")
    remaining = b["remaining_this_month"]
    if cost > remaining:
        return (f"monthly Censys credit budget exhausted ({b['spent_this_month']}/"
                f"{b['monthly_credits']} spent in {b['month']}; {action} needs {cost}). Credits do "
                f"not roll over — the balance resets on the 1st. Raise CENSYS_MONTHLY_CREDITS if "
                f"you bought more.")
    # The cheap cert/host/webproperty lookups are the free plan's whole value; a 5-credit search
    # must not eat the last of the month and leave them unaffordable.
    reserve = b["reserve_for_lookups"]
    if is_search and reserve and remaining - cost < reserve:
        return (f"a {cost}-credit search would leave {remaining - cost} credits, below the "
                f"{reserve} reserved for 1-credit lookups (cert/host/webproperty — the highest-"
                f"value calls on a free plan). Run this CenQL in the Censys web UI instead.")
    if remaining <= _budget("warn_at_remaining", default=30) and action not in _WARNED:
        _WARNED.add(action)
        print(f"[censys] ⚠ {remaining} of {b['monthly_credits']} monthly credits left "
              f"({b['spent_this_month']} spent in {b['month']}, no rollover). Spending {cost} on "
              f"{action}.", file=sys.stderr)
    return None


def _memoised(kind: str, ident: str, fn):
    """Run `fn()` once per (kind, ident) per process and hand back a private copy."""
    key = (kind, ident)
    with _MEMO_LOCK:
        if key in _MEMO:
            return copy.deepcopy(_MEMO[key])
    val = fn()
    with _MEMO_LOCK:
        _MEMO[key] = val
    return copy.deepcopy(val)


# --------------------------------------------------------------------------- summarisers
# A raw Censys host record is tens of kilobytes of per-protocol detail. Case JSON is evidence an
# analyst reads, so we keep only the fields that can actually drive a pivot.
def _svc_summary(svc: dict) -> dict:
    out = {"port": svc.get("port"), "protocol": svc.get("protocol")}
    prods = [s.get("product") for s in (svc.get("software") or []) if isinstance(s, dict) and s.get("product")]
    if prods:
        out["software"] = uniq(prods)
    cert = (svc.get("cert") or {}).get("fingerprint_sha256")
    if cert:
        out["cert_fingerprint_sha256"] = cert
    jarm = (svc.get("jarm") or {}).get("fingerprint")
    if jarm:
        out["jarm"] = jarm
    bh = (svc.get("banner_hash_sha256"))
    if bh:
        out["banner_hash_sha256"] = bh
    return out


def summarise_host(res: dict) -> dict:
    """Censys Host resource -> the pivot-relevant subset."""
    if not isinstance(res, dict):
        return {}
    asys = res.get("autonomous_system") or {}
    dns = res.get("dns") or {}
    names = []
    for side in ("forward", "reverse"):
        node = dns.get(side) or dns.get(side + "_resolution") or {}
        if isinstance(node, dict):
            names += [n for n in (node.get("names") or []) if isinstance(n, str)]
    names += [n for n in (dns.get("names") or []) if isinstance(n, str)]
    services = [_svc_summary(s) for s in (res.get("services") or []) if isinstance(s, dict)]
    out = {
        "ip": res.get("ip"),
        "asn": asys.get("asn"), "asn_name": asys.get("name") or asys.get("description"),
        "asn_country": asys.get("country_code"), "bgp_prefix": asys.get("bgp_prefix"),
        "whois_org": ((res.get("whois") or {}).get("organization") or {}).get("name"),
        "country": (res.get("location") or {}).get("country"),
        "dns_names": uniq(names)[:50],
        "ports": sorted({str(s["port"]) for s in services if s.get("port")},
                        key=lambda p: int(p) if p.isdigit() else 0),
        "services": services[:40],
        "cert_fingerprints": uniq([s["cert_fingerprint_sha256"] for s in services
                                   if s.get("cert_fingerprint_sha256")]),
        "labels": uniq([l.get("value") for l in (res.get("labels") or [])
                        if isinstance(l, dict) and l.get("value")]),
    }
    return {k: v for k, v in out.items() if v not in (None, [], "")}


def summarise_webproperty(res: dict) -> dict:
    """Censys Web Property (hostname:port) resource -> the pivot-relevant subset."""
    if not isinstance(res, dict):
        return {}
    cert = res.get("cert") or {}
    favicons, body_hashes = [], []
    for ep in (res.get("endpoints") or []):
        http = (ep or {}).get("http") or {}
        for f in (http.get("favicons") or []):
            if isinstance(f, dict) and (f.get("hash_md5") or f.get("hash_sha256")):
                favicons.append({k: f.get(k) for k in ("hash_md5", "hash_sha256", "size") if f.get(k)})
        if http.get("body_hash_sha256"):
            body_hashes.append(http["body_hash_sha256"])
    out = {
        "hostname": res.get("hostname"), "port": res.get("port"),
        "cert_fingerprint_sha256": cert.get("fingerprint_sha256"),
        "cert_names": uniq(cert.get("names") or [])[:60],
        "jarm": (res.get("jarm") or {}).get("fingerprint"),
        "favicons": favicons[:5],
        "body_hash_sha256": uniq(body_hashes)[:5],
        "software": uniq([s.get("product") for s in (res.get("software") or [])
                          if isinstance(s, dict) and s.get("product")]),
        "labels": uniq([l.get("value") for l in (res.get("labels") or [])
                        if isinstance(l, dict) and l.get("value")]),
        "threats": uniq([t.get("name") for t in (res.get("threats") or [])
                         if isinstance(t, dict) and t.get("name")]),
        "scan_time": res.get("scan_time"),
    }
    return {k: v for k, v in out.items() if v not in (None, [], "")}


def summarise_certificate(res: dict) -> dict:
    """Censys Certificate resource -> the pivot-relevant subset. `names` is the payload: every
    hostname on this exact leaf cert, i.e. the operator's own apex list."""
    if not isinstance(res, dict):
        return {}
    parsed = res.get("parsed") or {}
    subj, iss = parsed.get("subject") or {}, parsed.get("issuer") or {}
    out = {
        "fingerprint_sha256": res.get("fingerprint_sha256"),
        "fingerprint_sha1": res.get("fingerprint_sha1"),
        "names": uniq(res.get("names") or [])[:200],
        "subject_cn": subj.get("common_name") if isinstance(subj.get("common_name"), str)
        else (subj.get("common_name") or [None])[0] if isinstance(subj.get("common_name"), list) else None,
        "subject_org": subj.get("organization"),
        "issuer_org": iss.get("organization"),
        "added_at": res.get("added_at"), "validated_at": res.get("validated_at"),
        "ever_seen_in_scan": res.get("ever_seen_in_scan"),
        "validation_level": res.get("validation_level"),
    }
    return {k: v for k, v in out.items() if v not in (None, [], "")}


# --------------------------------------------------------------------------- lookups (FREE tier)
def _lookup(kind: str, ident: str, path: str, summarise, timeout: int = 30):
    """Shared body of the three single-entity lookups. 1 credit each, available on every plan."""
    cost = CREDIT_COSTS.get("entity_lookup", 1)

    def run():
        blocked = _budget_block(cost, f"{kind} lookup")
        if blocked:
            return {"skipped": blocked, "id": ident, "budget": budget_status()}
        data, err = _call(path.replace("{id}", urllib.parse.quote(ident, safe="")), timeout=timeout)
        if err:
            _record(f"lookup_{kind}", 0, ident, ok=False)
            return dict(err, id=ident)
        res = ((data or {}).get("result") or {}).get("resource") or {}
        _record(f"lookup_{kind}", cost, ident, results=1)
        return summarise(res)
    return _memoised(kind, ident, run)


def censys_host(ip: str, timeout: int = 30):
    """Censys host lookup by IP -> summarised host record. 1 credit. Available on the FREE plan.
    Returns None with no PAT, `{"skipped": ...}` when Censys declines."""
    if not censys_configured():
        return None
    return _lookup("host", ip, ENDPOINTS.get("lookup_host", "/v3/global/asset/host/{id}"),
                   summarise_host, timeout)


def webproperty_id(host: str, port: int = 443) -> str:
    """`hostname:port` — Censys's web-property identifier. Accepts a bare host, a `host:port`, or a
    URL, so callers can pass whatever the case has."""
    h = (host or "").strip()
    if "://" in h:
        u = urllib.parse.urlparse(h)
        h, port = u.hostname or "", (u.port or (80 if u.scheme == "http" else 443))
    h = h.strip("/").lower()
    if ":" in h:
        base, _, p = h.rpartition(":")
        if p.isdigit():
            return f"{strip_www(base)}:{p}"
    return f"{strip_www(h)}:{int(port)}"


def censys_webproperty(host: str, port: int = 443, timeout: int = 30):
    """Censys web-property lookup for `hostname:port` -> cert, favicons, body hash, software,
    labels, threats. 1 credit. Available on the FREE plan."""
    if not censys_configured():
        return None
    return _lookup("webproperty", webproperty_id(host, port),
                   ENDPOINTS.get("lookup_webproperty", "/v3/global/asset/webproperty/{id}"),
                   summarise_webproperty, timeout)


def censys_certificate(sha256: str, timeout: int = 30):
    """Censys certificate lookup by leaf SHA-256 -> its full `names` list (every hostname on that
    exact cert). 1 credit. Available on the FREE plan. The strongest cross-brand link Censys gives
    a free account, because it needs no search entitlement."""
    if not censys_configured():
        return None
    return _lookup("certificate", (sha256 or "").strip().lower(),
                   ENDPOINTS.get("lookup_certificate", "/v3/global/asset/certificate/{id}"),
                   summarise_certificate, timeout)


def _bulk(kind: str, ids: list, path: str, field: str, summarise, cap: int, timeout: int = 45):
    """Bulk lookup. Censys charges 1 credit PER RESULT RETURNED, so this is a latency win, not a
    price win — the cap is Censys's own per-call maximum."""
    ids = [i for i in uniq(ids or []) if i][:cap]
    if not ids:
        return []
    if not censys_configured():
        return None
    # Censys charges 1 credit per RESULT, so the worst case is one per id asked for — budget
    # against that, not against the single HTTP call.
    blocked = _budget_block(CREDIT_COSTS.get("entity_lookup", 1) * len(ids),
                            f"bulk {kind} lookup ({len(ids)} ids)")
    if blocked:
        return {"skipped": blocked, "ids": ids, "budget": budget_status()}
    data, err = _call(path, method="POST", body={field: ids}, timeout=timeout)
    if err:
        _record(f"lookup_{kind}_bulk", 0, ",".join(ids)[:200], ok=False)
        return dict(err, ids=ids)
    rows = [summarise((r or {}).get("resource") or {}) for r in ((data or {}).get("result") or [])]
    rows = [r for r in rows if r]
    _record(f"lookup_{kind}_bulk", CREDIT_COSTS.get("entity_lookup", 1) * len(rows),
            ",".join(ids)[:200], results=len(rows))
    return rows


def censys_hosts(ips: list, timeout: int = 45):
    """Bulk host lookup (<=100 per call). 1 credit per host returned."""
    return _bulk("host", ips, ENDPOINTS.get("lookup_host_bulk", "/v3/global/asset/host"),
                 "host_ids", summarise_host, 100, timeout)


def censys_certificates(fingerprints: list, timeout: int = 45):
    """Bulk certificate lookup (<=1000 per call). 1 credit per certificate returned."""
    return _bulk("certificate", [f.strip().lower() for f in (fingerprints or []) if f],
                 ENDPOINTS.get("lookup_certificate_bulk", "/v3/global/asset/certificate"),
                 "certificate_ids", summarise_certificate, 1000, timeout)


def censys_webproperties(ids: list, timeout: int = 45):
    """Bulk web-property lookup (<=100 per call). 1 credit per property returned."""
    return _bulk("webproperty", [webproperty_id(i) for i in (ids or []) if i],
                 ENDPOINTS.get("lookup_webproperty_bulk", "/v3/global/asset/webproperty"),
                 "webproperty_ids", summarise_webproperty, 100, timeout)


# --------------------------------------------------------------------------- search (STARTER+)
def _hit_identity(hit: dict) -> dict:
    """One search hit -> {kind, id, ...} regardless of which dataset matched."""
    if hit.get("webproperty_v1"):
        r = summarise_webproperty((hit["webproperty_v1"] or {}).get("resource") or hit["webproperty_v1"])
        return dict(r, kind="webproperty")
    if hit.get("host_v1"):
        r = summarise_host((hit["host_v1"] or {}).get("resource") or hit["host_v1"])
        return dict(r, kind="host")
    if hit.get("certificate_v1"):
        r = summarise_certificate((hit["certificate_v1"] or {}).get("resource") or hit["certificate_v1"])
        return dict(r, kind="certificate")
    return {}


def censys_search(query: str, page_size: int = 100, pages: int = 1, timeout: int = 45):
    """Run a CenQL query -> {'query','total','hits':[...],'hostnames':[...],'ips':[...]}.

    **Starter and above.** On a FREE plan Censys answers 403 and this returns
    `{"skipped": ..., "ui_url": ...}` — the analyst runs the identical CenQL in the web UI. That is
    a degradation, not a failure: the query string is the deliverable either way.

    5 credits for the query plus 5 for each extra page, so `pages` defaults to 1."""
    if not censys_configured():
        return None
    q = (query or "").strip()
    if not q:
        return {"error": "empty query"}
    # THE SEARCH IS THE PROBE (red-team H0). It is never gated on a plan only it can discover; the
    # one thing that stops it is a `free` verdict ALREADY RECORDED for this case by an earlier
    # process's 403 (wp_plans: cases/<id>/capability_plans.json) — the per-process memo cannot
    # carry that across cmd_open / loop rounds / per-host collector subprocesses.
    if _plans.get("censys") == "free":
        return {"skipped": "Censys search skipped — this case already recorded the plan as FREE "
                           "(search needs Starter+); run the CenQL in the web UI",
                "query": q, "ui_url": censys_ui_url(q), "plan": "free"}
    cost = CREDIT_COSTS.get("advanced_query", 8) if "=~" in q else CREDIT_COSTS.get("standard_query", 5)
    # A search is 5x a lookup and each extra page costs the same again — the single easiest way to
    # burn a month. Budget the WHOLE requested paging run up front.
    blocked = _budget_block(cost * max(1, pages), f"search ({max(1, pages)} page(s))", is_search=True)
    if blocked:
        return {"skipped": blocked, "query": q, "ui_url": censys_ui_url(q),
                "budget": budget_status()}
    hits, token, spent, total = [], None, 0, None
    for _ in range(max(1, pages)):
        body = {"query": q, "page_size": max(1, min(100, page_size))}
        if token:
            body["page_token"] = token
        data, err = _call(ENDPOINTS.get("search_query", "/v3/global/search/query"),
                          method="POST", body=body, timeout=timeout)
        if err:
            _record("search", spent, q, results=len(hits), ok=bool(hits))
            if err.get("http") == 403 and not hits:
                _plans.record("censys", "free", why="search/query answered 403 (Free plan: lookups only)")
                err = dict(err, plan="free")
            if hits:
                break                                   # keep the pages already paid for
            return dict(err, query=q, ui_url=censys_ui_url(q))
        if spent == 0 and _plans.get("censys") != "paid":
            _plans.record("censys", "paid", why="search/query answered 200 (Starter or above)")
        spent += cost
        res = (data or {}).get("result") or {}
        total = res.get("total_hits", total)
        hits += [h for h in (_hit_identity(h) for h in (res.get("hits") or [])) if h]
        token = res.get("next_page_token")
        if not token:
            break
    _record("search", spent, q, results=len(hits))
    return {"query": q, "ui_url": censys_ui_url(q),
            "total": total if total is not None else len(hits),
            "hits": hits,
            "hostnames": uniq([h.get("hostname") for h in hits if h.get("hostname")]
                              + [n for h in hits for n in (h.get("names") or h.get("dns_names") or [])]),
            "ips": uniq([h.get("ip") for h in hits if h.get("ip")])}


# --------------------------------------------------------------------------- query BUILDER (keyless)
def censys_ui_url(cenql: str) -> str:
    """The Platform web-UI URL for a CenQL query — what a FREE-plan analyst clicks, since the
    search API is Starter+ but the UI search is not."""
    tpl = ENDPOINTS.get("ui_search") or (UI_SEARCH + "{q}")
    return tpl.replace("{q}", urllib.parse.quote(cenql or "", safe=""))


def template_for(kind: str):
    """WebPivot pivot `kind` -> the cenql_templates key, honouring the `prefix:` entries in
    pivot_kind_map (so `tracker:ga4` resolves via `tracker:`). None when Censys can't reverse it."""
    if not kind:
        return None
    if kind in PIVOT_KIND_MAP:
        return PIVOT_KIND_MAP[kind]
    for pref, tpl in PIVOT_KIND_MAP.items():
        if pref.endswith(":") and kind.startswith(pref):
            return tpl
    return None


def cenql_for(kind: str, value, **extra) -> list:
    """Raw CenQL string(s) for a pivot kind + value. [] when Censys does not index the artifact.

    NOTE for `favicon_hash`: pass the favicon's **MD5**, not the Shodan mmh3 — Censys is the one
    engine in the matrix that hashes favicons with MD5/SHA-256 rather than mmh3."""
    tpl_key = template_for(kind)
    if not tpl_key:
        return []
    subs = {"value": str(value).replace('"', r"\""), **{k: str(v) for k, v in extra.items()}}
    out = []
    for t in (CENQL_TEMPLATES.get(tpl_key) or []):
        try:
            out.append(t.format(**subs))
        except KeyError:                 # template wants a placeholder the caller didn't supply
            continue
    return out


def censys_queries(kind: str, value, ui: bool = True, forms: int = None, **extra) -> list:
    """Ready-to-run Censys entries for a pivot's `queries` list: the CenQL plus, when `ui`, the
    Platform web-UI URL that runs it without a search entitlement. [] when Censys can't reverse it.

    `forms` caps how many CenQL variants to emit (the same fact lives under `web.` and `host.`);
    the bulk-attach pass uses forms=1 so a 30-pivot result doesn't triple in size."""
    qs = cenql_for(kind, value, **extra)
    if not qs:
        return []
    if forms:
        qs = qs[:max(1, forms)]
    out = [{"service": "Censys", "query": qs[0]}]
    for q in qs[1:]:
        out.append({"service": "Censys (host view)" if q.startswith("host.") else "Censys (alt)",
                    "query": q})
    if ui:
        # Say the price on the link itself. The UI search is the free plan's only way to run a
        # CenQL query — but it is NOT free: it spends 5 of the account's 100 monthly credits, the
        # same pool the cert/host lookups draw on. An analyst clicking six of these has spent a
        # third of the month without ever calling the API.
        out.append({"service": f"Censys UI (works without a search entitlement — costs "
                               f"{CREDIT_COSTS.get('standard_query', 5)} of your "
                               f"{CREDIT_BUDGET.get('monthly_credits', 100)} monthly credits)",
                    "query": censys_ui_url(qs[0])})
    return out


def attach_censys_queries(pivots: list, forms: int = 1) -> list:
    """Append a Censys CenQL query (+ the UI URL) to every pivot whose kind Censys can reverse.

    Done as ONE pass over the finished pivot list rather than at 19 `add(...)` call sites: the
    pivot_kind_map in `references/censys_queries.json` is then the single place an analyst edits to
    teach WebPivot a new Censys field, and no call site can be forgotten. Pivots that already carry
    a hand-written Censys entry (favicon, which needs the MD5 rather than the pivot's mmh3 value)
    are left alone. Mutates and returns `pivots`."""
    for piv in pivots or []:
        if any("Censys" in (q.get("service") or "") for q in (piv.get("queries") or [])):
            continue
        qs = censys_queries(piv.get("kind"), piv.get("value"), forms=forms)
        if qs:
            piv.setdefault("queries", []).extend(qs)
    return pivots


def certs_search_once(sha256_list, case_budget: int = 1, case_dir=None, timeout: int = 45):
    """ONE case-level Censys search over the estate's deduped leaf-certificate SHA-256s — `cert.
    fingerprint_sha256=<a> or cert.fingerprint_sha256=<b> …` — bounded to `case_budget` query
    call(s) per case (5 credits each), so an estate of 30 hosts costs one search, not thirty.

    THE SEARCH IS THE PROBE: it runs unless this case already recorded Censys as `free` (wp_plans);
    censys_search itself records `free` on the first 403 / `paid` on a 200. Returns
    {queries:[…], hostnames:[…], ips:[…], hits:n, skipped?:reason, plan?:…} — never raises; every
    outcome is a dict the caller can persist (cases/<id>/censys_search.json) and the frontier can
    merge on exact-cert match (an owner link — the same standard as censys_cert names)."""
    fps = sorted({str(f or "").strip().lower() for f in (sha256_list or []) if f and len(str(f).strip()) == 64})
    out = {"fingerprints": fps, "queries": [], "hostnames": [], "ips": [], "hits": 0}
    if not fps:
        out["skipped"] = "no leaf-certificate fingerprints collected"
        return out
    if not censys_configured():
        out["skipped"] = "no CENSYS_PAT"
        return out
    if _plans.get("censys", case_dir=case_dir) == "free":
        out["skipped"] = "this case recorded the Censys plan as FREE (lookups only) — search not attempted"
        out["plan"] = "free"
        out["ui_urls"] = [censys_ui_url(f"cert.fingerprint_sha256={f}") for f in fps[:6]]
        return out
    tpl = (CENQL_TEMPLATES.get("tls_fingerprint_sha256") or ["cert.fingerprint_sha256={value}"])[0]
    # OR the fingerprints into as few queries as the budget allows (Censys accepts long disjunctions)
    per_query = max(1, -(-len(fps) // max(1, case_budget)))
    hostnames, ips = [], []
    for i in range(0, len(fps), per_query):
        if len(out["queries"]) >= max(1, case_budget):
            out["truncated"] = True
            break
        q = " or ".join(tpl.replace("{value}", f) for f in fps[i:i + per_query])
        res = censys_search(q, page_size=100, pages=1, timeout=timeout)
        qrow = {"query": q, "fingerprints": fps[i:i + per_query],
                "result": {k: v for k, v in (res or {}).items() if k not in ("hits", "hostnames", "ips")}}
        out["queries"].append(qrow)
        if not isinstance(res, dict):
            continue
        if res.get("error"):
            # TRANSPORT failure: distinct from `skipped` so the caller's idempotence check retries it
            # next run instead of freezing the case on one timeout.
            out["error"] = res["error"]
            break
        if res.get("skipped"):
            out["skipped"] = res["skipped"]
            if res.get("plan"):
                out["plan"] = res["plan"]
            out["ui_url"] = res.get("ui_url")
            break
        # per-QUERY hostnames stay attributable to their fingerprint chunk, so a shared CDN cert in one
        # chunk cannot poison a genuine one in another (the frontier guards fan-out per query)
        qrow["hostnames"] = uniq(list(res.get("hostnames") or []))
        qrow["ips"] = uniq(list(res.get("ips") or []))
        qrow["total"] = int(res.get("total") or 0)
        hostnames += qrow["hostnames"]
        ips += qrow["ips"]
        out["hits"] += qrow["total"]
    out["hostnames"] = uniq(hostnames)
    out["ips"] = uniq(ips)
    return out


__all__ = ["censys_configured", "censys_token", "censys_host", "censys_webproperty",
           "censys_certificate", "censys_hosts", "censys_certificates", "censys_webproperties",
           "censys_search", "certs_search_once", "censys_queries", "attach_censys_queries", "cenql_for", "template_for",
           "censys_ui_url", "budget_status", "month_spent",
           "webproperty_id", "summarise_host", "summarise_webproperty", "summarise_certificate",
           "CENQL_TEMPLATES", "PIVOT_KIND_MAP", "CREDIT_COSTS", "CREDIT_BUDGET",
           "PLAN_CAPABILITIES", "ENDPOINTS"]


def main():
    ap = argparse.ArgumentParser(description="Censys Platform lookups + CenQL query builder")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("host", help="host lookup by IP (1 credit, FREE plan OK)")
    p.add_argument("ip")
    p = sub.add_parser("webproperty", help="web-property lookup for host[:port] (1 credit, FREE plan OK)")
    p.add_argument("host")
    p.add_argument("--port", type=int, default=443)
    p = sub.add_parser("cert", help="certificate lookup by leaf SHA-256 (1 credit, FREE plan OK)")
    p.add_argument("sha256")
    p = sub.add_parser("search", help="run a CenQL query (5 credits, Starter+)")
    p.add_argument("query")
    p.add_argument("--page-size", type=int, default=100)
    p.add_argument("--pages", type=int, default=1)
    p = sub.add_parser("query", help="OFFLINE: build the CenQL + UI URL for a pivot kind (no key)")
    p.add_argument("kind", help="WebPivot pivot kind, e.g. favicon_hash, tls_cert:fingerprint_sha256")
    p.add_argument("value")
    sub.add_parser("budget", help="OFFLINE: this month's Censys credit balance (no key, no spend)")
    args = ap.parse_args()

    if args.cmd == "query":
        out = {"kind": args.kind, "template": template_for(args.kind),
               "queries": censys_queries(args.kind, args.value)}
        if not out["queries"]:
            out["note"] = ("Censys does not index this artifact — reverse it on FOFA body= / "
                           "PublicWWW / a search engine instead.")
    elif args.cmd == "budget":
        out = budget_status()
        out["note"] = (f"A lookup costs {CREDIT_COSTS.get('entity_lookup', 1)}, a search "
                       f"{CREDIT_COSTS.get('standard_query', 5)} (also charged when you run the "
                       f"CenQL in the web UI). Credits do NOT roll over.")
    elif not censys_configured():
        # Keyless is a supported mode, not an error — say exactly what is and is not available so
        # nobody reads an absent Censys section as "Censys found nothing".
        print(
            "CENSYS: KEYLESS — no CENSYS_PAT configured.\n"
            "  UNAVAILABLE (needs a free key): the certificate lookup (every hostname on a leaf\n"
            "    cert — the strongest cross-brand link a free plan gives), the host lookup\n"
            "    (ASN/DNS/ports/banners) and the web-property lookup. Nothing was queried, so\n"
            "    nothing being reported is NOT a finding about the target.\n"
            "  STILL AVAILABLE, keyless and free: the `query` subcommand builds the exact CenQL\n"
            "    plus a platform.censys.io UI link for any pivot artifact. Every pivot_extract\n"
            f"    run already carries those. Running one in the UI costs "
            f"{CREDIT_COSTS.get('standard_query', 5)} of the account's\n"
            f"    {CREDIT_BUDGET.get('monthly_credits', 100)} monthly credits — it is a deliberate "
            "move, not a default one.\n"
            "  Get a free key (no card): https://platform.censys.io/ → user icon → API Access →\n"
            "    Create New Token, then `printf 'CENSYS_PAT=…\\n' >> .env && chmod 600 .env`.\n"
            "  Detail: WebPivot/references/Setup.md",
            file=sys.stderr)
        return 2
    elif args.cmd == "host":
        out = censys_host(args.ip)
    elif args.cmd == "webproperty":
        out = censys_webproperty(args.host, args.port)
    elif args.cmd == "cert":
        out = censys_certificate(args.sha256)
    else:
        out = censys_search(args.query, page_size=args.page_size, pages=args.pages)
    print(json.dumps(out, indent=2, ensure_ascii=False))
    if args.cmd not in ("query", "budget"):
        b = budget_status()
        print(f"[censys] spent {b['spent_this_run']} credit(s) this run · "
              f"{b['remaining_this_month']}/{b['monthly_credits']} left for {b['month']} "
              f"(no rollover)", file=sys.stderr)
    if api_usage:
        api_usage.print_session_summary()
    return 0


if __name__ == "__main__":
    sys.exit(main())
