#!/usr/bin/env python3
"""wp_hunterhow — Hunter.how (api.hunter.how) reverse cyberspace-search client + query builder.

Hunter.how is an independent, CN-dense internet-asset index — a FOFA/Quake/ZoomEye peer. It
reverses a favicon mmh3 hash, a body string, a server header, a domain or an IP to the hosts that
carry it, which is a same-operator pivot (priority ladder rungs 4/7/8). This tool:

  * executes a search when HUNTERHOW_API_KEY is set (METERED — a free account has a small quota;
    every call is logged to the api_usage ledger), and
  * ALWAYS builds the ready-to-run query keyless, so an analyst with no key can run it by hand.

API facts verified live against api.hunter.how (2026-08):
  * auth via the `api-key` query param;
  * `query` is base64 of a hunter.how expression (hunter.how/guide);
  * the API REQUIRES `fields=ip,port,domain`, a `page_size` in {10,20,50,100,1000}, and a
    `start_time`/`end_time` window no wider than one year;
  * the HTTP status is ALWAYS 200 — the real status is the JSON `code` (200 = results,
    440 = a note such as "no results" or an invalid-query hint), so callers must read `code`.

Only field expressions verified against the live API are emitted by the builder; an unknown pivot
kind yields no query rather than a guess the API would reject.
"""
import argparse
import base64
import datetime
import json
import os
import sys
import urllib.parse
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wp_common import _secret, DEFAULT_UA  # noqa: E402 — shared skill-root .env loader + UA

try:
    import api_usage                        # licensed-API credit ledger (optional)
except Exception:
    api_usage = None

API_URL = "https://api.hunter.how/search"
UI_URL = "https://hunter.how/list?searchVal="
PAGE_SIZES = (10, 20, 50, 100, 1000)

# Master off switch, flipped by callers (e.g. --no-hunterhow). Only the NETWORK call honours it —
# the query builder is offline and free, so it keeps emitting queries either way.
ENABLED = True


def hunterhow_key():
    """The Hunter.how API key, or None."""
    return _secret("HUNTERHOW_API_KEY", "HUNTER_HOW_API_KEY", "HUNTERHOW_KEY")


def hunterhow_configured():
    """True when a key is available and Hunter.how isn't switched off — the gate every caller
    checks before spending quota."""
    return ENABLED and bool(hunterhow_key())


def query_for(kind, value):
    """A WebPivot pivot `kind` + value -> a hunter.how field expression, or None when Hunter.how
    cannot reverse that artifact. Fields are the ones verified against the live API."""
    if value in (None, ""):
        return None
    v = str(value).replace('"', '\\"')
    k = (kind or "").lower()
    if k in ("favicon", "favicon_mmh3", "favicon_hash", "icon_hash"):
        return f'favicon_hash="{v}"'
    if k in ("domain", "apex", "hostname"):
        return f'domain="{v}"'
    if k in ("ip", "ipv4", "origin_ip"):
        return f'ip="{v}"'
    if k in ("html_string", "body", "web_body", "source_string"):
        return f'web.body="{v}"'
    if k in ("server_header", "server"):
        return f'header.server="{v}"'
    if k in ("cert", "cert_sha256", "cert_serial"):
        return f'cert="{v}"'
    return None


def ui_url(query):
    """The hunter.how web-UI URL for a query — what a keyless analyst clicks."""
    return UI_URL + urllib.parse.quote(query or "", safe="")


def _window(days):
    """A recent [start, end] date window <= 365 days, as the API requires."""
    days = max(1, min(int(days), 365))
    end = datetime.date.today()
    return (end - datetime.timedelta(days=days)).isoformat(), end.isoformat()


def _record(query, results, ok=True):
    if api_usage:
        try:
            api_usage.record("hunterhow", "search", credits=1, query=query,
                             results=results, ok=ok)
        except Exception:
            pass


def search(query, page=1, page_size=10, days=180, fields="ip,port,domain", timeout=25):
    """Run a hunter.how query -> a dict with {query, ui, code, total, results_count,
    query_count, query_limit, hosts:[{domain,ip,port}]}; {'skipped':...} keyless; {'error':...}
    on transport failure. Never raises."""
    out = {"query": query, "ui": ui_url(query)}
    if page_size not in PAGE_SIZES:
        page_size = 10
    if not hunterhow_configured():
        out["skipped"] = "no HUNTERHOW_API_KEY configured — run the query in the web UI (see 'ui')"
        return out
    start, end = _window(days)
    q64 = base64.b64encode(query.encode("utf-8")).decode("ascii")
    params = urllib.parse.urlencode({
        "api-key": hunterhow_key(), "query": q64, "page": page, "page_size": page_size,
        "fields": fields, "start_time": start, "end_time": end})
    try:
        req = urllib.request.Request(API_URL + "?" + params,
                                     headers={"User-Agent": DEFAULT_UA,
                                              "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = json.load(r)
    except urllib.error.HTTPError as e:
        out["error"] = f"HTTP {e.code}"
        return out
    except Exception as e:
        out["error"] = str(e)
        return out
    code = body.get("code")
    out["code"] = code
    data = body.get("data") or {}
    if code == 200 and data:
        hosts = [{"domain": x.get("domain"), "ip": x.get("ip"), "port": x.get("port")}
                 for x in (data.get("list") or [])]
        out.update({"total": data.get("total"), "results_count": data.get("results_count"),
                    "query_count": data.get("query_count"),
                    "query_limit": data.get("query_limit"), "hosts": hosts})
        _record(query, len(hosts), ok=True)
    else:
        out["message"] = body.get("message")
        out["hosts"] = []
        _record(query, 0, ok=(code in (200, 440)))
    return out


def hunterhow_queries(kind, value, ui=True):
    """Ready-to-run Hunter.how entries for a pivot's `queries` list: the expression plus, when
    `ui`, the web-UI link that runs it keyless. [] when Hunter.how can't reverse the kind."""
    q = query_for(kind, value)
    if not q:
        return []
    out = [{"service": "Hunter.how", "query": q}]
    if ui:
        out.append({"service": "Hunter.how UI", "query": ui_url(q)})
    return out


def attach_hunterhow_queries(pivots):
    """Append a Hunter.how query (+ UI URL) to every pivot whose kind Hunter.how can reverse.
    One pass over the finished pivot list, mirroring attach_censys_queries — so the keyless run
    still hands the analyst a runnable Hunter.how query for every reversible artifact. Mutates
    and returns `pivots`."""
    for piv in pivots or []:
        if any("Hunter.how" in (qq.get("service") or "") for qq in (piv.get("queries") or [])):
            continue
        qs = hunterhow_queries(piv.get("kind"), piv.get("value"))
        if qs:
            piv.setdefault("queries", []).extend(qs)
    return pivots


__all__ = ["hunterhow_key", "hunterhow_configured", "query_for", "search", "ui_url",
           "hunterhow_queries", "attach_hunterhow_queries"]


def main():
    ap = argparse.ArgumentParser(
        description="Hunter.how reverse cyberspace search + keyless query builder")
    ap.add_argument("value", help="a raw hunter.how query, OR the pivot value when --kind is set")
    ap.add_argument("--kind",
                    help="pivot kind (favicon_hash|domain|ip|web_body|server_header|cert) "
                         "-> builds the query from `value`")
    ap.add_argument("--page", type=int, default=1)
    ap.add_argument("--page-size", type=int, default=10, choices=PAGE_SIZES)
    ap.add_argument("--days", type=int, default=180, help="lookback window in days (<=365)")
    ap.add_argument("--build-only", action="store_true",
                    help="print the query + UI link only; never call the API (keyless)")
    args = ap.parse_args()
    query = query_for(args.kind, args.value) if args.kind else args.value
    if not query:
        print(json.dumps({"error": f"no hunter.how query for kind={args.kind!r}"}),
              file=sys.stderr)
        return 2
    if args.build_only:
        print(json.dumps({"query": query, "ui": ui_url(query)}, ensure_ascii=False, indent=2))
        return 0
    print(json.dumps(search(query, page=args.page, page_size=args.page_size, days=args.days),
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
