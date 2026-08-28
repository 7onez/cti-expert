#!/usr/bin/env python3
"""wp_validin — Validin (app.validin.com) infra-pivot REST client + normaliser.

Validin gives DNS + certificates + favicon + response-body hashes in ONE graph on a FREE
Community key. This client is the SCRIPTED integration (the skill previously only emitted
Validin as a manual query string). It mirrors wp_hunterhow / wp_censys:

  * `import wp_common` FIRST — installs the cti-proxy opener as an import side effect, so every
    urlopen here egresses through /cti-proxy. NEVER build a custom opener or use `requests`.
  * Keyless-safe: no key -> every lookup returns None; nothing errors, nothing egresses.
  * Tri-state per call: a normalised dict on success, `{"skipped": reason}` for auth/quota/tier
    conditions the caller degrades around, `{"error": reason}` for transport faults. Never raises.
  * QUOTA-GOVERNED (Community = 10/day, 50/mo): a per-domain call cap + a remaining-quota gate
    short-circuit BEFORE any HTTP call, so one /cti run never empties a small key.

Verified endpoints/shapes (2026-08-27, live): base https://app.validin.com, Bearer auth.
Free tier covers passive DNS + subdomains + hash/cert/favicon reverse + reputation + lookalike;
WHOIS/RDAP registration + reverse-WHOIS are paid (403) — WhoisXML keeps that role.
"""
import json
import os
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wp_common import _secret, DEFAULT_UA  # noqa: E402 — shared .env loader + UA + proxy install

try:                                        # reference-file loader (optional; degrade to fallback)
    from wp_refs import load_ref, ref_path  # noqa: E402
except Exception:                           # noqa: BLE001
    def load_ref(path, fallback):
        return dict(fallback)

    def ref_path(module_file, name):
        return os.path.normpath(os.path.join(os.path.dirname(module_file), os.pardir,
                                             "references", name))

try:
    import api_usage                         # licensed-API credit ledger (optional)
except Exception:                            # noqa: BLE001
    api_usage = None

BASE = "https://app.validin.com"

# DATA: endpoint path templates + caps + quota thresholds. Overridable via
# references/validin_endpoints.json; the fallback keeps a keyless/file-less run working.
_VALIDIN_FALLBACK = {
    "endpoints": {
        "usage": "/api/profile/usage",
        "paths": "/api/paths",
        "combined_domain": "/api/v2/domain/combined/connections/{q}",
        "subdomains": "/api/axon/domain/subdomains/{q}",
        "certificates": "/api/axon/domain/certificates/{q}",
        "domain_reputation": "/api/axon/domain/reputation/quick/{q}",
        "ip_reputation": "/api/axon/ip/reputation/quick/{q}",
        "hash_pivots": "/api/axon/hash/pivots/{q}",
        "ip_dns_history": "/api/axon/ip/dns/history/{q}",
        "ip_pivots": "/api/axon/ip/pivots/{q}",
        "lookalike": "/api/lookalike/domain/{q}",
        "bulk_osint": "/api/axon/bulk/osint/context",
    },
    "budget": {"max_calls_per_domain": 2, "max_calls_per_run": 40, "min_remaining": 3},
}
_REFS = load_ref(ref_path(__file__, "validin_endpoints.json"), _VALIDIN_FALLBACK)
EP = _REFS["endpoints"]
_BUDGET = _REFS["budget"]

# Master off switch, flipped by callers (e.g. pivot_extract --no-validin). Only NETWORK calls
# honour it — the keyless query-string path other modules emit is unaffected.
ENABLED = True

# Quota/cap state (one process = one case). Env overrides for the analyst who bought a bigger key.
_MAX_PER_DOMAIN = int(os.environ.get("VALIDIN_MAX_CALLS_PER_DOMAIN", _BUDGET["max_calls_per_domain"]))
_MAX_PER_RUN = int(os.environ.get("VALIDIN_MAX_CALLS_PER_RUN", _BUDGET["max_calls_per_run"]))
_MIN_REMAINING = int(os.environ.get("VALIDIN_MIN_REMAINING", _BUDGET["min_remaining"]))
_RUN_CALLS = 0
_DOMAIN_CALLS = {}
_USAGE = None                                # cached {"daily_remaining", "monthly_remaining"} or None
_LOCK = threading.Lock()

_STATUS_REASON = {
    401: "Validin rejected the key (VALIDIN_API_KEY missing/expired)",
    402: "Validin quota exhausted — Community is 10/day, 50/month; upgrade or wait for reset",
    403: "your Validin plan does not allow this endpoint (WHOIS/RDAP history + Bulk/Live-scan "
         "are paid tiers)",
    404: "not in the Validin dataset",
    429: "Validin rate limit — slow down",
}


def validin_key():
    """The Validin API key, or None."""
    return _secret("VALIDIN_API_KEY", "VALIDIN_API_KEY_FALLBACK")


def validin_configured() -> bool:
    """True when a key is available and Validin isn't switched off — the gate every caller checks."""
    return ENABLED and bool(validin_key())


def _headers():
    return {"User-Agent": DEFAULT_UA, "Accept": "application/json",
            "Authorization": "Bearer %s" % (validin_key() or "")}


def _record(action, results, ok=True):
    if api_usage:
        try:
            api_usage.record("validin", action, credits=1, query=action, results=results, ok=ok)
        except Exception:                    # noqa: BLE001
            pass


def usage(timeout=15):
    """Remaining Community quota from /api/profile/usage, cached per process. Never raises;
    returns None on any failure (unknown quota => the gate allows, never blocks on ignorance)."""
    global _USAGE
    if _USAGE is not None:
        return _USAGE
    if not validin_configured():
        return None
    data, _err = _get(EP["usage"], timeout=timeout)
    if isinstance(data, dict):
        rem = data.get("remaining") or {}
        _USAGE = {"daily_remaining": rem.get("daily"), "monthly_remaining": rem.get("monthly")}
        return _USAGE
    return None


def can_spend(n=1) -> bool:
    """False when cached quota shows fewer than the safety margin remaining. Reads the CACHE only
    (no network) so it is safe to call in the pre-flight gate and easy to stub in tests."""
    u = _USAGE
    if not u:
        return True                          # unknown quota -> allow (do not block on ignorance)
    for k in ("daily_remaining", "monthly_remaining"):
        v = u.get(k)
        if isinstance(v, int) and v < max(n, _MIN_REMAINING):
            return False
    return True


def permitted_paths(timeout=15):
    """The set of API path templates this key may call (/api/paths). Capability is derived at
    runtime, never assumed from the tier. Returns a set (empty on failure)."""
    data, _err = _get(EP["paths"], timeout=timeout)
    return set(data.keys()) if isinstance(data, dict) else set()


def _allow(bucket):
    """Per-domain cap + per-run ceiling + quota gate, all BEFORE any HTTP call. Increments the
    counters when it allows. `bucket` is the domain/IP the call is attributed to."""
    global _RUN_CALLS
    if _USAGE is None:
        usage()                              # prime the quota cache ONCE per run so can_spend() is live
    with _LOCK:
        if _RUN_CALLS >= _MAX_PER_RUN:
            return False
        if _DOMAIN_CALLS.get(bucket, 0) >= _MAX_PER_DOMAIN:
            return False
        if not can_spend(1):
            return False
        _RUN_CALLS += 1
        _DOMAIN_CALLS[bucket] = _DOMAIN_CALLS.get(bucket, 0) + 1
        return True


def _get(path, *, timeout=25, body=None):
    """One API call -> (data, error_dict). Never raises. Meta calls (usage/paths) call this
    directly, bypassing the per-run cap that _allow enforces for the typed lookups."""
    if not validin_configured():
        return None, {"skipped": "no VALIDIN_API_KEY configured"}
    url = BASE + path
    data = json.dumps(body).encode() if body is not None else None
    headers = _headers()
    if data:
        headers["Content-Type"] = "application/json"
    try:
        req = urllib.request.Request(url, data=data, headers=headers,
                                     method="POST" if body is not None else "GET")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r), None
    except urllib.error.HTTPError as e:
        reason = _STATUS_REASON.get(e.code)
        msg = "HTTP %d%s" % (e.code, (" — %s" % reason) if reason else "")
        return None, ({"skipped": msg} if e.code in _STATUS_REASON else {"error": msg})
    except Exception as e:                    # noqa: BLE001 — network/timeout/parse
        return None, {"error": str(e)}


# --------------------------------------------------------------------------- normalisers
def _rows(data, *keys):
    """Flatten Validin's records-of-lists shape into a single row list. `data.records` is a dict
    of category -> [rows]; if `keys` given, only those categories (prefix match) are taken."""
    recs = (data or {}).get("records") if isinstance(data, dict) else None
    out = []
    if isinstance(recs, dict):
        for cat, rows in recs.items():
            if keys and not any(str(cat).startswith(k) for k in keys):
                continue
            if isinstance(rows, list):
                out.extend(rows)
    elif isinstance(recs, list):
        out = recs
    return out


def _uniq(seq):
    seen, out = set(), []
    for x in seq:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _wrap(err_or_none, payload):
    """Return payload on success, else the tri-state error dict."""
    return err_or_none if err_or_none else payload


# --------------------------------------------------------------------------- typed lookups
def domain_lookup(domain, timeout=25):
    """Primary per-domain call: v2 combined connections (passive DNS + co-hosted) in ONE query.
    -> {"total", "dns":[{rrname,rrtype,rdata,first,last}], "hosts":[co-hosted domains]} | tri-state."""
    if not validin_configured():
        return None
    if not _allow(domain):
        return {"skipped": "quota"}
    data, err = _get(EP["combined_domain"].format(q=urllib.parse.quote(domain, safe="")), timeout=timeout)
    if err:
        return err
    dns = data.get("dns") if isinstance(data, dict) else None
    dns = dns if isinstance(dns, list) else []
    hosts = _uniq(r.get("rrname") for r in dns
                  if isinstance(r, dict) and r.get("rrname") and r.get("rrname") != domain)
    _record("combined", len(dns))
    return {"total": len(dns),
            "dns": [{"rrname": r.get("rrname"), "rrtype": r.get("rrtype"), "rdata": r.get("rdata"),
                     "first": r.get("time_first"), "last": r.get("time_last")}
                    for r in dns if isinstance(r, dict)],
            "hosts": hosts}


def subdomains(domain, timeout=25):
    """Enumerate one apex's subdomains -> {"total","hosts":[...]} | tri-state."""
    if not validin_configured():
        return None
    if not _allow(domain):
        return {"skipped": "quota"}
    data, err = _get(EP["subdomains"].format(q=urllib.parse.quote(domain, safe="")), timeout=timeout)
    if err:
        return err
    subs = ((data or {}).get("records") or {}).get("subdomains") or []
    hosts = _uniq(s.get("value") for s in subs if isinstance(s, dict))
    _record("subdomains", len(hosts))
    return {"total": len(hosts), "hosts": hosts}


def certificates(domain, timeout=25):
    """Historic CT certificates for a domain -> {"total","certs":[...]} | tri-state."""
    if not validin_configured():
        return None
    if not _allow(domain):
        return {"skipped": "quota"}
    data, err = _get(EP["certificates"].format(q=urllib.parse.quote(domain, safe="")), timeout=timeout)
    if err:
        return err
    certs = _rows(data)
    _record("certificates", len(certs))
    return {"total": len(certs), "certs": certs}


def reputation(domain, timeout=25):
    """Quick reputation verdict -> {"annotations":[...]} | tri-state. A CORROBORATING signal only."""
    if not validin_configured():
        return None
    if not _allow(domain):
        return {"skipped": "quota"}
    data, err = _get(EP["domain_reputation"].format(q=urllib.parse.quote(domain, safe="")), timeout=timeout)
    if err:
        return err
    anns = (data or {}).get("annotations") or []
    _record("reputation", len(anns))
    return {"annotations": anns}


def ip_reputation(ip, timeout=25):
    if not validin_configured():
        return None
    if not _allow(ip):
        return {"skipped": "quota"}
    data, err = _get(EP["ip_reputation"].format(q=urllib.parse.quote(ip, safe="")), timeout=timeout)
    if err:
        return err
    return {"annotations": (data or {}).get("annotations") or []}


def _hash_hosts(sha1, category, bucket, timeout):
    if not validin_configured():
        return None
    if not _allow(bucket):
        return {"skipped": "quota"}
    data, err = _get(EP["hash_pivots"].format(q=urllib.parse.quote(sha1, safe="")), timeout=timeout)
    if err:
        return err
    rows = _rows(data, category)
    hosts = _uniq(r.get("value") for r in rows if isinstance(r, dict))
    _record("hash_pivots", len(hosts))
    return {"total": len(hosts), "hosts": hosts}


def cert_hosts(sha1, timeout=25):
    """Hosts serving the exact cert fingerprint (SHA1) -> {"total","hosts":[ip...]} | tri-state."""
    return _hash_hosts(sha1, "CERT_FINGERPRINT", "hash:" + str(sha1), timeout)


def favicon_hosts(sha1, timeout=25):
    """Hosts serving the exact favicon (SHA1) -> {"total","hosts":[...]} | tri-state."""
    return _hash_hosts(sha1, "FAVICON_HASH", "hash:" + str(sha1), timeout)


def ip_lookup(ip, timeout=25):
    """Reverse-IP: domains observed on the IP -> {"total","domains":[...]} | tri-state."""
    if not validin_configured():
        return None
    if not _allow(ip):
        return {"skipped": "quota"}
    data, err = _get(EP["ip_dns_history"].format(q=urllib.parse.quote(ip, safe="")), timeout=timeout)
    if err:
        return err
    rows = _rows(data)
    domains = _uniq(r.get("value") or r.get("key") for r in rows
                    if isinstance(r, dict) and (r.get("value_type") == "dom" or r.get("value")))
    _record("ip_dns_history", len(domains))
    return {"total": len(domains), "domains": domains}


def lookalikes(domain, timeout=25):
    """Newly-observed Levenshtein<=2 lookalikes -> {"total","records":[...]} | tri-state."""
    if not validin_configured():
        return None
    if not _allow(domain):
        return {"skipped": "quota"}
    data, err = _get(EP["lookalike"].format(q=urllib.parse.quote(domain, safe="")), timeout=timeout)
    if err:
        return err
    recs = (data or {}).get("records") or []
    out = [{"domain": r.get("key"), "similarity": r.get("similarity"), "keyword": r.get("keyword"),
            "first_seen": r.get("first_seen"), "registrar": r.get("rar"),
            "registered": r.get("reg"), "recent_dns": r.get("recent_dns")}
           for r in recs if isinstance(r, dict)]
    _record("lookalike", len(out))
    return {"total": len(out), "records": out}


def bulk_osint(indicators, timeout=25):
    """Batch verdicts (POST). BULK IS PROFESSIONAL+ — only call when permitted_paths() confirms it.
    -> {"records": {...}} | tri-state."""
    if not validin_configured():
        return None
    if EP["bulk_osint"] not in permitted_paths():
        return {"skipped": "bulk/osint/context not permitted on this key (Professional+ only)"}
    if not _allow("bulk"):
        return {"skipped": "quota"}
    data, err = _get(EP["bulk_osint"], timeout=timeout, body={"indicators": list(indicators)})
    if err:
        return err
    return {"records": (data or {}).get("records") or {}}


__all__ = ["validin_key", "validin_configured", "usage", "can_spend", "permitted_paths",
           "domain_lookup", "subdomains", "certificates", "reputation", "ip_reputation",
           "cert_hosts", "favicon_hosts", "ip_lookup", "lookalikes", "bulk_osint",
           "ENABLED", "BASE"]


def main(argv):
    if not argv:
        print("usage: wp_validin.py <domain> [--json]", file=sys.stderr)
        return 2
    domain = argv[0]
    out = {"configured": validin_configured(), "usage": usage(),
           "domain": domain_lookup(domain), "subdomains": subdomains(domain),
           "reputation": reputation(domain), "lookalikes": lookalikes(domain)}
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
