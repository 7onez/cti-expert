#!/usr/bin/env python3
"""wp_securitytrails — SecurityTrails (api.securitytrails.com) DNS-history + subdomain REST
client + normaliser.

SecurityTrails gives current subdomain enumeration and historical DNS-record snapshots on a
FREEMIUM key (50 calls/MONTH total, no daily reset — every credit matters). This client mirrors
wp_validin / wp_hunterhow:

  * `import wp_common` FIRST — installs the cti-proxy opener as an import side effect, so every
    urlopen here egresses through /cti-proxy. NEVER build a custom opener or use `requests`.
  * Keyless-safe: no key -> every lookup returns None; nothing errors, nothing egresses.
  * Tri-state per call: a normalised dict on success, `{"skipped": reason}` for auth/quota/tier
    conditions the caller degrades around, `{"error": reason}` for transport faults. Never raises.
  * METERED (Free = 50 calls/MONTH — no daily reset disclosed): a per-run call cap PLUS a live
    /account/usage check gate BEFORE every typed lookup, so one /cti run never empties the key.
    The orchestrator additionally gates this engine `and not free_only` at the call site, same as
    every other paid/metered WebPivot tool.

Verified endpoints/shapes (2026-08-28, live against the real SECURITYTRAILS_API_KEY in .env):
  * base https://api.securitytrails.com/v1, auth via the `APIKEY` HTTP header
    (https://docs.securitytrails.com/docs/authentication — the query-string `?apikey=` fallback
    exists but is NOT used here: header keeps the key out of proxy/access logs).
  * GET /account/usage                 -> {"current_monthly_usage","allowed_monthly_usage"}
    (free — verified NOT metered: calling it twice left current_monthly_usage unchanged).
  * GET /domain/{hostname}/subdomains  -> {"subdomains":[...]}  bare labels, not FQDNs (free tier
    caps large domains with `meta.limit_reached: true`, e.g. github.com truncates).
  * GET /history/{hostname}/dns/{type} -> {"type","records":[{"values":[{"ip",...}],...}]},
    type in a/aaaa/mx/ns/soa/txt (free).
  * GET /ips/nearby/{ip} ("Explore IPs" — the reverse-IP/neighbours op) -> live-tested and
    returned HTTP 200 with a Recorded Future upsell body: {"message": "This feature is not
    available for your subscription package. Consider upgrading your package or contact
    asi-support@recordedfuture.com"} — a PAID add-on on this Free key, and the call was NOT
    deducted from current_monthly_usage. Per the plan's own "omit, don't fake" instruction this
    client does NOT expose a reverse_ip()/neighbours() function — there is nothing free-tier to
    wire. WhoisXML/Validin already cover reverse-IP for this skill.
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

try:
    import api_usage                         # licensed-API credit ledger (optional)
except Exception:                            # noqa: BLE001
    api_usage = None

BASE = "https://api.securitytrails.com/v1"
DNS_RECORD_TYPES = ("a", "aaaa", "mx", "ns", "soa", "txt")

# Master off switch, flipped by callers (e.g. pivot_extract --no-securitytrails).
ENABLED = True

# Quota/cap state (one process = one case). The Free key is 50/MONTH total, so the default cap
# is deliberately small; env overrides let an analyst with a bigger key raise it.
_MAX_PER_RUN = int(os.environ.get("SECURITYTRAILS_MAX_CALLS_PER_RUN", 5))
_MIN_REMAINING = int(os.environ.get("SECURITYTRAILS_MIN_REMAINING", 2))
_RUN_CALLS = 0
_USAGE = None                                # cached {"used","allowed"} or None
_LOCK = threading.Lock()

_STATUS_REASON = {
    401: "SecurityTrails rejected the key (SECURITYTRAILS_API_KEY missing/expired)",
    403: "your SecurityTrails plan does not allow this endpoint (paid Recorded Future add-on)",
    429: "SecurityTrails rate limit — slow down",
}


def securitytrails_key():
    """The SecurityTrails API key, or None."""
    return _secret("SECURITYTRAILS_API_KEY", "SECURITYTRAILS_API_KEY_FALLBACK")


def securitytrails_configured() -> bool:
    """True when a key is available and SecurityTrails isn't switched off — the gate every
    caller checks before spending the 50/month Free quota."""
    return ENABLED and bool(securitytrails_key())


def _headers():
    return {"User-Agent": DEFAULT_UA, "Accept": "application/json",
            "APIKEY": securitytrails_key() or ""}


def _record(action, results, ok=True):
    if api_usage:
        try:
            api_usage.record("securitytrails", action, credits=1, query=action,
                              results=results, ok=ok)
        except Exception:                    # noqa: BLE001
            pass


def usage(timeout=15):
    """Remaining Free-tier quota from /account/usage, cached per process. Verified NOT itself
    metered. Never raises; returns None on any failure (unknown quota => the gate allows, never
    blocks on ignorance)."""
    global _USAGE
    if _USAGE is not None:
        return _USAGE
    if not securitytrails_configured():
        return None
    data, _err = _get_raw("/account/usage", timeout=timeout)
    if isinstance(data, dict) and "allowed_monthly_usage" in data:
        _USAGE = {"used": data.get("current_monthly_usage"),
                   "allowed": data.get("allowed_monthly_usage")}
        return _USAGE
    return None


def can_spend(n=1) -> bool:
    """False when cached quota shows fewer than the safety margin remaining THIS MONTH. Reads
    the CACHE only (no network) so it is safe to call in the pre-flight gate."""
    u = _USAGE
    if not u or u.get("used") is None or u.get("allowed") is None:
        return True                          # unknown quota -> allow (do not block on ignorance)
    return (u["allowed"] - u["used"]) >= max(n, _MIN_REMAINING)


def _allow():
    """Per-run ceiling + live monthly-quota gate, BEFORE any HTTP call. Increments the run
    counter when it allows."""
    global _RUN_CALLS
    if _USAGE is None:
        usage()                              # prime the quota cache ONCE per run
    with _LOCK:
        if _RUN_CALLS >= _MAX_PER_RUN:
            return False
        if not can_spend(1):
            return False
        _RUN_CALLS += 1
        return True


def _get_raw(path, *, params=None, timeout=25):
    """One API call -> (data, error_dict). Never raises. usage() calls this directly, bypassing
    the per-run cap _allow() enforces for the typed lookups."""
    if not securitytrails_configured():
        return None, {"skipped": "no SECURITYTRAILS_API_KEY configured"}
    url = BASE + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    try:
        req = urllib.request.Request(url, headers=_headers(), method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r), None
    except urllib.error.HTTPError as e:
        reason = _STATUS_REASON.get(e.code)
        msg = "HTTP %d%s" % (e.code, (" — %s" % reason) if reason else "")
        return None, ({"skipped": msg} if e.code in _STATUS_REASON else {"error": msg})
    except Exception as e:                    # noqa: BLE001 — network/timeout/parse
        return None, {"error": str(e)}


def _get(path, *, params=None, timeout=25):
    """Typed-lookup call: applies the per-run cap + live quota gate before _get_raw."""
    if not securitytrails_configured():
        return None, {"skipped": "no SECURITYTRAILS_API_KEY configured"}
    if not _allow():
        return None, {"skipped": "SecurityTrails per-run cap or monthly quota exhausted"}
    return _get_raw(path, params=params, timeout=timeout)


def _uniq(seq):
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


# --------------------------------------------------------------------------- typed lookups
def subdomains(domain, timeout=25):
    """Enumerate one apex's subdomains -> {"total","hosts":[...]} | tri-state | None (keyless).
    The API returns bare labels (e.g. "www", "gist"), not FQDNs — this normaliser joins each to
    `domain` so callers get the same full-hostname shape as every other WebPivot host lookup.
    Free tier caps large domains (response carries `meta.limit_reached: true`, silently)."""
    if not securitytrails_configured():
        return None
    data, err = _get("/domain/%s/subdomains" % urllib.parse.quote(domain), timeout=timeout)
    if err:
        _record("subdomains:" + domain, 0, ok=False)
        return err
    subs = (data or {}).get("subdomains") or []
    apex = domain.strip(".").lower()
    hosts = [apex if not (s or "").strip(".") else "%s.%s" % ((s or "").strip(".").lower(), apex)
             for s in subs]
    hosts = _uniq(hosts)
    _record("subdomains:" + domain, len(hosts))
    return {"total": len(hosts), "hosts": hosts}


def dns_history(domain, record_type="a", timeout=25):
    """Historical DNS records for one host -> {"total","ips":[...]} for a/aaaa record types, or
    {"total","records":[...]} (raw) for mx/ns/soa/txt -> tri-state | None (keyless)."""
    if not securitytrails_configured():
        return None
    rt = (record_type or "a").lower()
    if rt not in DNS_RECORD_TYPES:
        return {"error": "unsupported DNS record type %r (allowed: %s)"
                          % (record_type, ", ".join(DNS_RECORD_TYPES))}
    data, err = _get("/history/%s/dns/%s" % (urllib.parse.quote(domain), rt), timeout=timeout)
    if err:
        _record("dns_history:" + domain, 0, ok=False)
        return err
    records = (data or {}).get("records") or []
    if rt in ("a", "aaaa"):
        ips = _uniq([v.get("ip") for rec in records for v in (rec.get("values") or [])
                     if v.get("ip")])
        _record("dns_history:" + domain, len(ips))
        return {"total": len(ips), "ips": ips}
    _record("dns_history:" + domain, len(records))
    return {"total": len(records), "records": records}


__all__ = ["securitytrails_key", "securitytrails_configured", "usage", "can_spend",
           "subdomains", "dns_history", "DNS_RECORD_TYPES", "ENABLED", "BASE"]


def main(argv):
    if not argv:
        print("usage: wp_securitytrails.py <domain>", file=sys.stderr)
        return 2
    domain = argv[0]
    if not securitytrails_configured():
        print(json.dumps({"configured": False, "domain": domain}))
        return 0
    out = {"configured": True, "domain": domain,
           "usage": usage(),
           "subdomains": subdomains(domain),
           "dns_history": dns_history(domain)}
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
