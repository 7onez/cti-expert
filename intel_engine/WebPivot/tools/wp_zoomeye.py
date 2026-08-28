#!/usr/bin/env python3
"""wp_zoomeye — ZoomEye (api.zoomeye.ai v2) favicon-reverse cyberspace-search client for WebPivot.

ZoomEye is Knownsec's internet-wide asset index — an independent FOFA/Hunter.how peer. The one
pivot wired here is the highest-value cross-operator reverse a favicon gives: every host ZoomEye
has seen serving the same favicon mmh3 hash, surfacing re-skinned siblings that share one icon
across rotating hosts.

API facts (verified against the v2 API + official ZoomEye-python SDK, 2026):
  * POST https://api.zoomeye.ai/v2/search
  * auth via header `API-KEY: <ZOOMEYE_API_KEY>` (the key never expires; reset in the profile).
  * body {"qbase64": base64("iconhash=\"<mmh3>\""), "page": 1, "pagesize": N}
    — ZoomEye's `iconhash:` filter takes an mmh3 OR md5 favicon hash.
  * response {"code": 60000, "data": [{"url","domain","ip","hostname",...}]}
    — `code == 60000` is success; any other code is an API-level error carried in `message`.

Metered: ZoomEye bills query quota, so it is gated `and not free_only` by the caller (wp_analyze)
like FOFA/Hunter.how. The keyless query STRING is still emitted elsewhere at zero cost. Proxy-safe:
imports wp_common (which installs a global proxy opener) and uses urllib.request.urlopen directly —
never a custom opener, which would bypass the proxy.
"""
import argparse
import base64
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

BASE = "https://api.zoomeye.ai"

# DATA: endpoint path templates + per-run budget. Overridable via references/zoomeye_endpoints.json;
# the fallback keeps a keyless/file-less run working.
_ZOOMEYE_FALLBACK = {
    "endpoints": {"search": "/v2/search"},
    "budget": {"max_calls_per_run": 15, "min_remaining": 0, "page_size": 50},
}
_REFS = load_ref(ref_path(__file__, "zoomeye_endpoints.json"), _ZOOMEYE_FALLBACK)
EP = _REFS["endpoints"]
_BUDGET = _REFS["budget"]

# Master off switch, flipped by callers (e.g. pivot_extract --no-zoomeye). Only the NETWORK call
# honours it — the offline query string other modules emit is unaffected.
ENABLED = True

_MAX_PER_RUN = int(os.environ.get("ZOOMEYE_MAX_CALLS_PER_RUN", _BUDGET["max_calls_per_run"]))
_PAGE_SIZE = int(os.environ.get("ZOOMEYE_PAGE_SIZE", _BUDGET.get("page_size", 50)))
_RUN_CALLS = 0
_LOCK = threading.Lock()

_SUCCESS_CODE = 60000                        # ZoomEye v2 success code


def zoomeye_key():
    """The ZoomEye API key, or None."""
    return _secret("ZOOMEYE_API_KEY", "ZOOMEYE_API_KEY_FALLBACK", "ZOOMEYE_KEY")


def zoomeye_configured() -> bool:
    """True when a key is available and ZoomEye isn't switched off — the gate every caller checks
    before spending quota."""
    return ENABLED and bool(zoomeye_key())


def _record(action, results, ok=True):
    if api_usage:
        try:
            api_usage.record("zoomeye", action, credits=1, query=None, results=results, ok=ok)
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
        "Content-Type": "application/json", "API-KEY": zoomeye_key() or ""})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — proxy-safe global opener
            return json.loads(resp.read().decode("utf-8", "replace")), None
    except urllib.error.HTTPError as e:
        return None, {"error": "ZoomEye HTTP %d" % e.code}
    except Exception as e:                   # noqa: BLE001
        return None, {"error": str(e)}


def _hosts_from_data(rows):
    """ZoomEye v2 rows -> a deduped list of bare hostnames (domain / hostname / host-of-url)."""
    seen, out = set(), []
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        host = r.get("domain") or r.get("hostname") or ""
        if not host and r.get("url"):        # fall back to the host part of a URL
            host = str(r["url"]).split("//")[-1].split("/")[0].split(":")[0]
        host = str(host).strip().lower().rstrip(".")
        if host and host not in seen:
            seen.add(host)
            out.append(host)
    return out


def favicon_reverse(mmh3, timeout=25):
    """Hosts ZoomEye has seen serving this favicon mmh3 hash -> {"total","hosts":[...]} | tri-state.
    None when not configured; {"skipped"} on quota; {"error"} on an API/transport failure."""
    if not zoomeye_configured():
        return None
    if mmh3 in (None, ""):
        return None
    if not _allow():
        return {"skipped": "ZoomEye per-run cap reached"}
    q = 'iconhash="%s"' % mmh3
    body = {"qbase64": base64.b64encode(q.encode("utf-8")).decode("ascii"),
            "page": 1, "pagesize": _PAGE_SIZE}
    data, err = _post(EP["search"], body, timeout=timeout)
    if err:
        _record("favicon", 0, ok=False)
        return err
    code = (data or {}).get("code")
    if code not in (_SUCCESS_CODE, str(_SUCCESS_CODE)):
        return {"skipped": "ZoomEye: %s (code %s)" % ((data or {}).get("message") or "error", code)}
    hosts = _hosts_from_data((data or {}).get("data") or [])
    _record("favicon", len(hosts), ok=True)
    return {"total": len(hosts), "hosts": hosts}


__all__ = ["zoomeye_key", "zoomeye_configured", "favicon_reverse", "ENABLED", "BASE"]


def main(argv):
    ap = argparse.ArgumentParser(description="ZoomEye (v2) favicon-hash reverse search")
    ap.add_argument("mmh3", help="favicon mmh3 hash (as emitted by the favicon_hash pivot)")
    args = ap.parse_args(argv)
    print(json.dumps(favicon_reverse(args.mmh3), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
