#!/usr/bin/env python3
"""wp_dnslytics — DNSLytics (api.dnslytics.net) reverse Ad-tracker + reverse-IP REST client +
normaliser.

DNSLytics' unique value for WebPivot (see registry.json's "unlocks") is reversing a Google
AdSense (ca-pub-/pub-) or Google Analytics/Tag (UA-/G-/GTM-/AW-/DC-/GT-) ID into every domain
CURRENTLY carrying that tracker — the classic "find every other site the same operator runs"
pivot the skill previously only emitted as a manual query string. This client is the SCRIPTED
integration. Mirrors wp_validin / wp_hunterhow:

  * `import wp_common` FIRST — installs the cti-proxy opener as an import side effect, so every
    urlopen here egresses through /cti-proxy. NEVER build a custom opener or use `requests`.
  * Keyless-safe: no key -> every lookup returns None; nothing errors, nothing egresses.
  * Tri-state per call: a normalised dict on success, `{"skipped": reason}` for auth/quota/
    rate-limit conditions the caller degrades around, `{"error": reason}` for a malformed
    caller-supplied tracker id or a transport fault. Never raises.
  * CREDIT-METERED (pay-as-you-go prepaid balance; checked once per process via the FREE
    accountinfo call): a per-run call cap + a remaining-credit gate short-circuit BEFORE any
    billable HTTP call, so one /cti run never empties a small key.

Verified endpoints/shapes (2026-08-28, live, api v1): base https://api.dnslytics.net/v1,
`apikey` travels as a query-string param (not a header). `accountinfo` is free and confirms the
prepaid balance. `reverseadsense`/`reverseganalytics` (6 credits each) return CURRENT sibling
domains for a tracker id — verified live against omgubuntu.co.uk's real ads.txt AdSense pub-id
(-> omgubuntu.co.uk + omgchrome.com, a real sibling network) and dnslytics.com's own live G- GA4
tag. `reverseip` (5 credits) returns CURRENT co-hosted domains for an IP; it is NOT free like
Validin's reverse-IP, but is included as a corroborating premium alternative since it works
under the same paid key and is gated identically to the two reverse-tracker calls. All three
premium calls 400 with `{"status":"error","data":"<message>"}` on a bad/expired key or malformed
upstream id, and 403/429/503 on rate limits — every non-"succeed" response degrades to
`{"skipped": ...}`, never raised.
"""
import json
import os
import re
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
        return os.path.normpath(os.path.join(
            os.path.dirname(os.path.abspath(module_file)), os.pardir, "references", name))

try:
    import api_usage                         # licensed-API credit ledger (optional)
except Exception:                            # noqa: BLE001
    api_usage = None

BASE = "https://api.dnslytics.net/v1"

# DATA: endpoint path templates + per-call credit cost + budget caps. Overridable via
# references/dnslytics_endpoints.json; the fallback keeps a keyless/file-less run working.
_DNSLYTICS_FALLBACK = {
    "endpoints": {
        "accountinfo": "/accountinfo",
        "reverseadsense": "/reverseadsense/{q}",
        "reverseganalytics": "/reverseganalytics/{q}",
        "reverseip": "/reverseip/{q}",
    },
    "credits": {"reverseadsense": 6, "reverseganalytics": 6, "reverseip": 5},
    "budget": {"max_calls_per_run": 15, "min_remaining": 5},
}
_REFS = load_ref(ref_path(__file__, "dnslytics_endpoints.json"), _DNSLYTICS_FALLBACK)
EP = _REFS["endpoints"]
_CREDITS = _REFS["credits"]
_BUDGET = _REFS["budget"]

# Master off switch, flipped by callers (e.g. pivot_extract --no-dnslytics). Only NETWORK calls
# honour it — id classification stays free and offline either way.
ENABLED = True

# Credit-budget state (one process = one case). Env overrides for the analyst who bought a
# bigger credit block.
_MAX_PER_RUN = int(os.environ.get("DNSLYTICS_MAX_CALLS_PER_RUN", _BUDGET["max_calls_per_run"]))
_MIN_REMAINING = int(os.environ.get("DNSLYTICS_MIN_REMAINING", _BUDGET["min_remaining"]))
_RUN_CALLS = 0
_USAGE = None                                # cached {"credits","daily_limit","calls_today"} or None
_LOCK = threading.Lock()


def dnslytics_key():
    """The DNSLytics API key, or None."""
    return _secret("DNSLYTICS_API_KEY", "DNSLYTICS_API_KEY_FALLBACK")


def dnslytics_configured() -> bool:
    """True when a key is available and DNSLytics isn't switched off — the gate every caller
    checks before spending credits."""
    return ENABLED and bool(dnslytics_key())


def _record(action, query, results, ok=True):
    if api_usage:
        try:
            api_usage.record("dnslytics", action, credits=_CREDITS.get(action, 1),
                             query=query, results=results,
                             remaining=(_USAGE or {}).get("credits"), ok=ok)
        except Exception:                    # noqa: BLE001
            pass


def usage(timeout=15):
    """Current prepaid balance from the FREE /accountinfo call, cached per process ->
    {"credits","daily_limit","calls_today"} | None. Never raises; never counted against the
    per-run BILLABLE cap (this endpoint itself costs 0 credits)."""
    global _USAGE
    if _USAGE is not None:
        return _USAGE
    if not dnslytics_configured():
        return None
    data, _err = _get(EP["accountinfo"], {}, timeout=timeout)
    d = (data or {}).get("data") if isinstance(data, dict) else None
    if isinstance(d, dict):
        _USAGE = {"credits": d.get("apicredits"), "daily_limit": d.get("apilimits"),
                  "calls_today": d.get("apicalls")}
        return _USAGE
    return None


def can_spend(n=1) -> bool:
    """False when the cached balance shows fewer credits than the safety margin. Reads the
    CACHE only (no network) so it is safe in the pre-flight gate. Unknown balance -> allow (do
    not block on ignorance; DNSLytics itself 400s a truly-exhausted key, which degrades to
    'skipped' below)."""
    u = _USAGE
    if not u or not isinstance(u.get("credits"), int):
        return True
    return (u["credits"] - n) >= _MIN_REMAINING


def _allow(cost):
    """Per-run ceiling + cached-balance gate, BEFORE any billable HTTP call. Increments the
    run counter when it allows."""
    global _RUN_CALLS
    if _USAGE is None:
        usage()                              # prime the balance cache ONCE per run
    with _LOCK:
        if _RUN_CALLS >= _MAX_PER_RUN:
            return False
        if not can_spend(cost):
            return False
        _RUN_CALLS += 1
        return True


def _classify(msg, code):
    """An API-level `{"status":"error","data":<msg>}` (DNSLytics uses HTTP 400 for a bad key or
    malformed upstream id, 403/429 for daily/minute rate limits, 503 for a global outage) ->
    the tri-state 'skipped' dict. Never a fatal 'error' — that's reserved for transport faults
    (see `_get`'s except branch)."""
    return {"skipped": "DNSLytics: %s (HTTP %d)" % (msg, code)}


def _get(path, params, timeout=25):
    """One API call -> (parsed-JSON-response-body, error_dict). Never raises. `usage()` calls
    this directly, bypassing the per-run cap that `_allow` enforces for the billable lookups."""
    if not dnslytics_configured():
        return None, {"skipped": "no DNSLYTICS_API_KEY configured"}
    q = dict(params)
    q["apikey"] = dnslytics_key()
    url = BASE + path + "?" + urllib.parse.urlencode(q)
    headers = {"User-Agent": DEFAULT_UA, "Accept": "application/json"}
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = json.load(r)
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode("utf-8", "replace"))
        except Exception:                    # noqa: BLE001 — non-JSON error body
            return None, {"error": "HTTP %d" % e.code}
        if isinstance(body, dict) and body.get("status") == "error":
            return None, _classify(body.get("data") or "unknown error", e.code)
        return None, {"error": "HTTP %d" % e.code}
    except Exception as e:                    # noqa: BLE001 — network/timeout/parse
        return None, {"error": str(e)}
    if isinstance(body, dict) and body.get("status") == "error":
        return None, _classify(body.get("data") or "unknown error", 200)
    return body, None


# --------------------------------------------------------------------------- id normalisation
_ADSENSE_RE = re.compile(r"^(?:ca-)?pub-(\d+)$", re.I)
_ANALYTICS_RE = re.compile(r"^(ua|g|gtm|aw|dc|gt)-[a-z0-9-]+$", re.I)


def classify_tracker_id(raw):
    """A raw tracker id (`ca-pub-XXXX`, `pub-XXXX`, `UA-`/`G-`/`GTM-`/`AW-`/`DC-`/`GT-XXXX`) ->
    (kind, normalised) where kind is 'adsense' | 'analytics' | None (unrecognised — no network
    spent). DNSLytics' own API rejects the `ca-` prefix (wants bare `pub-XXXX`), so `ca-pub-`
    is stripped here before the id ever reaches `_get`."""
    s = (raw or "").strip()
    m = _ADSENSE_RE.match(s)
    if m:
        return "adsense", "pub-" + m.group(1)
    if _ANALYTICS_RE.match(s):
        return "analytics", s.lower()
    return None, s


# --------------------------------------------------------------------------- typed lookups
def _domains_from_body(body):
    """DNSLytics' `{"status":"succeed","data":{"ndomains":N,"domains":[...]}}` shape -> a
    deduped list of plain hostnames + the reported total. `domains` entries are either bare
    strings (reverseip) or `{"domain","firstseen","lastseen"}` objects (reverse* trackers)."""
    d = (body or {}).get("data") or {}
    out = []
    for r in d.get("domains") or []:
        if isinstance(r, str) and r:
            out.append(r)
        elif isinstance(r, dict) and r.get("domain"):
            out.append(r["domain"])
    seen, uniq = set(), []
    for x in out:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    total = d.get("ndomains") if isinstance(d.get("ndomains"), int) else len(uniq)
    return uniq, total


def reverse_adsense(pub_id, page=1, timeout=25):
    """Domains CURRENTLY serving this Google AdSense publisher id -> {"total","domains":[...]}
    | tri-state. Accepts `ca-pub-XXXX` or `pub-XXXX`; normalised before the network call."""
    if not dnslytics_configured():
        return None
    kind, norm = classify_tracker_id(pub_id)
    if kind != "adsense":
        return {"error": "not an AdSense id (expected ca-pub-XXXX or pub-XXXX): %r" % pub_id}
    if not _allow(_CREDITS.get("reverseadsense", 6)):
        return {"skipped": "per-run call cap or credit balance reached"}
    body, err = _get(EP["reverseadsense"].format(q=urllib.parse.quote(norm, safe="")),
                     {"page": max(1, min(int(page or 1), 40))}, timeout=timeout)
    if err:
        _record("reverseadsense", norm, 0, ok=False)
        return err
    domains, total = _domains_from_body(body)
    _record("reverseadsense", norm, total, ok=True)
    return {"total": total, "domains": domains}


def reverse_analytics(tracker_id, page=1, timeout=25):
    """Domains CURRENTLY carrying this Google Analytics/Tag id (UA-/G-/GTM-/AW-/DC-/GT-) ->
    {"total","domains":[...]} | tri-state."""
    if not dnslytics_configured():
        return None
    kind, norm = classify_tracker_id(tracker_id)
    if kind != "analytics":
        return {"error": "not a Google Analytics/Tag id (expected UA-/G-/GTM-/AW-/DC-/GT-"
                          "XXXX): %r" % tracker_id}
    if not _allow(_CREDITS.get("reverseganalytics", 6)):
        return {"skipped": "per-run call cap or credit balance reached"}
    body, err = _get(EP["reverseganalytics"].format(q=urllib.parse.quote(norm, safe="")),
                     {"page": max(1, min(int(page or 1), 40))}, timeout=timeout)
    if err:
        _record("reverseganalytics", norm, 0, ok=False)
        return err
    domains, total = _domains_from_body(body)
    _record("reverseganalytics", norm, total, ok=True)
    return {"total": total, "domains": domains}


def ga_adsense_siblings(tracker_id, page=1, timeout=25):
    """THE primary WebPivot entry point: any Google AdSense OR Analytics/Tag id -> sibling
    domains currently carrying it, auto-routed to the right endpoint ->
    {"total","domains":[...],"kind":"adsense"|"analytics"} | tri-state (no "kind" key on
    skip/error)."""
    if not dnslytics_configured():
        return None
    kind, norm = classify_tracker_id(tracker_id)
    if kind == "adsense":
        out = reverse_adsense(norm, page=page, timeout=timeout)
    elif kind == "analytics":
        out = reverse_analytics(norm, page=page, timeout=timeout)
    else:
        return {"error": "unrecognised tracker id format (expected pub-/ca-pub-/UA-/G-/GTM-/"
                          "AW-/DC-/GT-): %r" % tracker_id}
    if isinstance(out, dict) and "total" in out:
        out["kind"] = kind
    return out


def reverse_ip(ip, page=1, timeout=25):
    """Domains CURRENTLY hosted on this IP (or the first IPv4 a hostname resolves to) ->
    {"total","domains":[...]} | tri-state. NOT free (5 credits) — a premium corroborating
    alternative to Validin's free reverse-IP; gated by the same per-run cap / credit-balance
    guard as the tracker lookups above."""
    if not dnslytics_configured():
        return None
    # 5 credits per call and every estate host resolves to the same origin: bought ONCE per case
    try:
        import wp_casememo
        cached = wp_casememo.get("dnslytics", f"reverseip|{ip}|{page}")
    except Exception:  # noqa: BLE001
        wp_casememo, cached = None, None
    if cached is not None:
        return dict(cached, memo="case cache")
    if not _allow(_CREDITS.get("reverseip", 5)):
        return {"skipped": "per-run call cap or credit balance reached"}
    body, err = _get(EP["reverseip"].format(q=urllib.parse.quote(ip, safe="")),
                     {"page": max(1, min(int(page or 1), 40))}, timeout=timeout)
    if err:
        _record("reverseip", ip, 0, ok=False)
        return err
    domains, total = _domains_from_body(body)
    _record("reverseip", ip, total, ok=True)
    out = {"total": total, "domains": domains}
    if wp_casememo is not None:
        wp_casememo.put("dnslytics", f"reverseip|{ip}|{page}", out)
    return out


__all__ = ["dnslytics_key", "dnslytics_configured", "usage", "can_spend",
          "classify_tracker_id", "reverse_adsense", "reverse_analytics",
          "ga_adsense_siblings", "reverse_ip", "ENABLED", "BASE"]


def main(argv):
    if not argv:
        print("usage: wp_dnslytics.py <adsense-or-analytics-tracker-id-or-ip>", file=sys.stderr)
        return 2
    val = argv[0]
    out = {"configured": dnslytics_configured(), "usage": usage()}
    kind, _norm = classify_tracker_id(val)
    if kind:
        out["ga_adsense_siblings"] = ga_adsense_siblings(val)
    else:
        out["reverse_ip"] = reverse_ip(val)
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
