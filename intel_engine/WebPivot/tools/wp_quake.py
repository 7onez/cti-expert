#!/usr/bin/env python3
"""wp_quake — Quake (360, quake.360.net) favicon-reverse cyberspace-search client for WebPivot.

Quake is 360's internet-wide asset index — an independent, CN-dense peer to FOFA/Hunter.how. The
one pivot wired here is the highest-value cross-operator reverse a favicon gives: every host 360
has seen serving the same favicon mmh3 hash. That surfaces re-skinned siblings of a kit that share
one icon across rotating hosts.

API facts (verified against the published v3 API, 2026):
  * POST https://quake.360.net/api/v3/search/quake_service
  * auth via header `X-QuakeToken: <QUAKE_API_KEY>`; a bad/absent token -> a non-zero `code`
    (e.g. q2001/q3005) or HTTP 401/403 — never an exception here.
  * body {"query": "favicon.hash:\"<mmh3>\"", "start": 0, "size": N, "latest": true}
  * response {"code": 0, "message": "Successful.", "data": [{"ip","domain","service":{"http":{"host"}}}]}
    — `code == 0` is success; any other code is an API-level error carried in `message`.

Metered: Quake bills in points, so it is gated `and not free_only` by the caller (wp_analyze) like
FOFA/Hunter.how. The keyless query STRING is still emitted elsewhere at zero cost. Proxy-safe:
imports wp_common (which installs a global proxy opener) and uses urllib.request.urlopen directly —
never a custom opener, which would bypass the proxy.
"""
import argparse
import json
import os
import sys
import threading
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wp_common import _secret, DEFAULT_UA  # noqa: E402 — shared .env loader + UA + proxy install

try:                                        # reference-file loader (optional; degrade to fallback)
    from wp_refs import load_ref, ref_path  # noqa: E402
except Exception:                           # noqa: BLE001
    def load_ref(path, fallback):
        try:
            with open(path, encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            return fallback

    def ref_path(module_file, name):
        return os.path.abspath(os.path.join(
            os.path.dirname(os.path.abspath(module_file)), os.pardir, "references", name))

try:
    import api_usage                         # licensed-API credit ledger (optional)
except Exception:                            # noqa: BLE001
    api_usage = None

BASE = "https://quake.360.net"

# DATA: endpoint path templates + per-run budget. Overridable via references/quake_endpoints.json;
# the fallback keeps a keyless/file-less run working.
_QUAKE_FALLBACK = {
    "endpoints": {"search": "/api/v3/search/quake_service"},
    "budget": {"max_calls_per_run": 15, "min_remaining": 0, "page_size": 50},
}
_REFS = load_ref(ref_path(__file__, "quake_endpoints.json"), _QUAKE_FALLBACK)
EP = _REFS["endpoints"]
_BUDGET = _REFS["budget"]

# Master off switch, flipped by callers (e.g. pivot_extract --no-quake). Only the NETWORK call
# honours it — the offline query string other modules emit is unaffected.
ENABLED = True

_MAX_PER_RUN = int(os.environ.get("QUAKE_MAX_CALLS_PER_RUN", _BUDGET["max_calls_per_run"]))
_PAGE_SIZE = int(os.environ.get("QUAKE_PAGE_SIZE", _BUDGET.get("page_size", 50)))
_RUN_CALLS = 0
_LOCK = threading.Lock()


def quake_key():
    """The Quake API token, or None."""
    return _secret("QUAKE_API_KEY", "QUAKE_API_KEY_FALLBACK", "QUAKE_TOKEN")


def quake_configured() -> bool:
    """True when a token is available and Quake isn't switched off — the gate every caller checks
    before spending points."""
    return ENABLED and bool(quake_key())


def _record(action, results, ok=True):
    if api_usage:
        try:
            api_usage.record("quake", action, credits=1, query=None, results=results, ok=ok)
        except Exception:
            pass


def _allow():
    """Per-run ceiling, BEFORE any billable HTTP call. Increments the counter under lock."""
    global _RUN_CALLS
    with _LOCK:
        if _RUN_CALLS >= _MAX_PER_RUN:
            return False
        _RUN_CALLS += 1
        return True


def _post(path, body, timeout=25):
    """One API call -> (parsed-JSON, error_dict). Never raises."""
    url = BASE + path
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "User-Agent": DEFAULT_UA, "Accept": "application/json",
        "Content-Type": "application/json", "X-QuakeToken": quake_key() or ""})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — proxy-safe global opener
            return json.loads(resp.read().decode("utf-8", "replace")), None
    except urllib.error.HTTPError as e:
        return None, {"error": "Quake HTTP %d" % e.code}
    except Exception as e:                   # noqa: BLE001
        return None, {"error": str(e)}


def _hosts_from_data(rows):
    """Quake service rows -> a deduped list of bare hostnames (domain / http host), IPs dropped in
    favour of names when a name is present."""
    seen, out = set(), []
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        host = (r.get("domain") or (((r.get("service") or {}).get("http") or {}).get("host"))
                or r.get("hostname") or "")
        host = str(host).strip().lower().rstrip(".")
        if host and host not in seen:
            seen.add(host)
            out.append(host)
    return out


def favicon_reverse(mmh3, timeout=25):
    """Hosts 360 has seen serving this favicon mmh3 hash -> {"total","hosts":[...]} | tri-state.
    None when not configured; {"skipped"} on quota; {"error"} on an API/transport failure."""
    if not quake_configured():
        return None
    if mmh3 in (None, ""):
        return None
    if not _allow():
        return {"skipped": "Quake per-run cap reached"}
    body = {"query": 'favicon.hash:"%s"' % mmh3, "start": 0, "size": _PAGE_SIZE, "latest": True}
    data, err = _post(EP["search"], body, timeout=timeout)
    if err:
        _record("favicon", 0, ok=False)
        return err
    code = (data or {}).get("code")
    if code not in (0, "0"):                 # API-level error (bad token, no points, etc.)
        return {"skipped": "Quake: %s (code %s)" % ((data or {}).get("message") or "error", code)}
    hosts = _hosts_from_data((data or {}).get("data") or [])
    _record("favicon", len(hosts), ok=True)
    return {"total": len(hosts), "hosts": hosts}


__all__ = ["quake_key", "quake_configured", "favicon_reverse", "ENABLED", "BASE"]


def main(argv):
    ap = argparse.ArgumentParser(description="Quake (360) favicon-hash reverse search")
    ap.add_argument("mmh3", help="favicon mmh3 hash (as emitted by the favicon_hash pivot)")
    args = ap.parse_args(argv)
    print(json.dumps(favicon_reverse(args.mmh3), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
