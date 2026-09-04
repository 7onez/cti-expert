#!/usr/bin/env python3
"""wp_netlas — Netlas (app.netlas.io) internet-scan / DNS / WHOIS / certificate index client.

Netlas is an independent internet-asset index (a Shodan/FOFA/Censys peer) with FOUR searchable
collections behind one Bearer key. What each is worth to an estate investigation was measured live
against a 32-domain brand-impersonation case (2026-09-02):

  * `domains`  — the DNS index. `a:<origin-ip>` reverse-IP on a NON-CDN origin (the mail server the
                 estate shares) returned 32 apexes of which 15 were estate members and the rest were
                 same-MO siblings under OTHER registrant personas — the best cheap "who else uses this
                 operator's infrastructure" pivot of the three vendors tested. `ns:` and
                 `txt:*_spf.<provider>*` reverse the provider, which is rung-10 noise (hundreds of
                 unrelated tenants) — emitted as a COUNT, never as leads.
  * `whois_domains` — thin: one record per registrant term for a 32-domain estate. Not a reverse-WHOIS
                 source; kept for the per-domain registrar/created cross-check only.
  * `responses` — the HTTP scan index. It had NOT indexed any estate host (small VN doorway sites), so
                 title/body/favicon pivots return nothing for this class of case; `ip:<origin>` and the
                 `responses_facet` on http.title still describe the shared host (webmail banner).
  * `certs`     — 3 requests/minute; searched last and only by exact SAN.

The Non-profit / paid plans have unlimited requests (`requests_left.limit == -1`) and a coin balance;
Free plans are metered. Every call is logged to the api_usage ledger regardless. Netlas fronts the API
with Cloudflare: a request without a browser User-Agent is refused with error 1010, so the client
always sends DEFAULT_UA. Rate limit: 60/min (certs 3/min); 429 carries Retry-After.

Keyless the tool still emits the ready-to-run query strings + web-UI links (RULE: an analyst with no
key can run the same pivot by hand).
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wp_common import _secret, DEFAULT_UA  # noqa: E402

try:
    import api_usage
except Exception:  # noqa: BLE001
    api_usage = None

BASE = "https://app.netlas.io"
UI = {"domains": BASE + "/domains/?q=", "responses": BASE + "/responses/?q=", "whois_domains": BASE + "/whois/domains/?q=",
      "certs": BASE + "/certs/?q=", "whois_ip": BASE + "/whois/ip/?q="}
COLLECTIONS = ("responses", "domains", "whois_ip", "whois_domains", "certs")
PAGE = 20                 # fixed by the API
MAX_START = 9980          # the API exposes the first 10 000 hits only

ENABLED = True            # master off switch (--no-netlas)


def netlas_key():
    return _secret("NETLAS_API_KEY", "NETLAS_KEY")


def netlas_configured():
    return ENABLED and bool(netlas_key())


def _record(action, query, results, ok=True, credits=1):
    if api_usage:
        try:
            api_usage.record("netlas", action, credits=credits, query=query, results=results, ok=ok)
        except Exception:  # noqa: BLE001
            pass


def _get(path, params=None, timeout=45, retries=2):
    """GET with Bearer auth + browser UA; honours 429 Retry-After once. (status, json|text)."""
    url = BASE + path + (("?" + urllib.parse.urlencode(params, doseq=True)) if params else "")
    hdr = {"Authorization": "Bearer " + (netlas_key() or ""), "User-Agent": DEFAULT_UA, "Accept": "application/json"}
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=hdr), timeout=timeout) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < retries:
                time.sleep(min(int(e.headers.get("Retry-After") or "5"), 30))
                continue
            return e.code, e.read()[:300].decode("utf-8", "replace")
        except Exception as e:  # noqa: BLE001
            return None, str(e)[:160]
    return None, "retries exhausted"


# --------------------------------------------------------------------------- query builder (keyless)
def query_for(kind, value):
    """(collection, query) for a pivot kind, or None when Netlas has no useful field for it.
    Only expressions verified live are emitted."""
    v = str(value).strip()
    if kind in ("ip", "origin_ip"):
        return "domains", f"a:{v}"
    if kind == "ns":
        return "domains", f"ns:{v}"
    if kind in ("spf_include", "spf"):
        return "domains", f"txt:*{v}*"
    if kind == "domain":
        return "domains", f"domain:{v}"
    if kind == "registrant_email":
        return "whois_domains", f'registrant.email:"{v}"'
    if kind == "registrant_phone":
        return "whois_domains", f"registrant.phone:*{v.lstrip('+').replace('.', '')}*"
    if kind in ("san", "cert_name"):
        return "certs", f"certificate.names:{v}"
    if kind == "title":
        return "responses", f'http.title:"{v}"'
    return None


def ui_url(collection, q):
    return UI.get(collection, BASE + "/") + urllib.parse.quote(q, safe="")


# --------------------------------------------------------------------------- calls
def count(collection, q, timeout=45):
    """{'count': int} | {'error': str}. Exact under 1 000, else ±3 %."""
    if not netlas_configured():
        return {"skipped": "no NETLAS_API_KEY", "query": q, "ui": ui_url(collection, q)}
    s, d = _get(f"/api/{collection}_count/", {"q": q}, timeout)
    ok = isinstance(d, dict) and "count" in d
    _record(f"{collection}_count", q, d.get("count") if ok else 0, ok=ok)
    return {"count": d["count"], "query": q, "ui": ui_url(collection, q)} if ok else {"error": f"{s} {str(d)[:120]}", "query": q}


def search(collection, q, fields="*", max_results=200, timeout=45):
    """Paged search -> {query, ui, total, items:[data…]} | {'error'} | {'skipped'}. `fields` is a
    comma list (include); pages of 20 up to max_results or the 10 000-hit API ceiling."""
    if not netlas_configured():
        return {"skipped": "no NETLAS_API_KEY", "query": q, "ui": ui_url(collection, q)}
    items, total = [], None
    for start in range(0, min(max_results, MAX_START + PAGE), PAGE):
        s, d = _get(f"/api/{collection}/", {"q": q, "fields": fields, "source_type": "include", "start": start}, timeout)
        if not isinstance(d, dict):
            _record(f"{collection}_search", q, len(items), ok=False)
            return {"error": f"{s} {str(d)[:120]}", "query": q, "items": items}
        page = [it.get("data", it) for it in d.get("items") or []]
        items += page
        total = d.get("total", total)
        if len(page) < PAGE:
            break
    _record(f"{collection}_search", q, len(items))
    return {"query": q, "ui": ui_url(collection, q), "total": total, "items": items[:max_results]}


def facet(collection, q, field, size=50, timeout=45):
    if not netlas_configured():
        return {"skipped": "no NETLAS_API_KEY", "query": q}
    s, d = _get(f"/api/{collection}_facet/", {"q": q, "facets": field, "size": size}, timeout)
    ok = isinstance(d, dict) and "aggregations" in d
    _record(f"{collection}_facet", q, len(d.get("aggregations", [])) if ok else 0, ok=ok)
    return {"query": q, "field": field, "buckets": [(a.get("key"), a.get("doc_count")) for a in d["aggregations"]]} if ok else {"error": f"{s} {str(d)[:120]}"}


def _apex(host):
    p = host.lower().split(".")
    return ".".join(p[-3:]) if len(p) >= 3 and p[-2] in ("com", "co", "net", "org", "edu", "gov") and len(p[-1]) == 2 else ".".join(p[-2:])


def reverse_ip(ip, max_results=400):
    """Apexes whose DNS points at `ip` (domains index) — the MO-neighbour pivot. Run it on a NON-CDN
    origin (mail server, shared host); on a CDN edge it is meaningless and the caller must not ask.
    -> {query, ui, total, hosts:[…], apexes:[…]}."""
    r = search("domains", f"a:{ip}", fields="domain,a,mx,ns", max_results=max_results)
    if "items" not in r:
        return r
    hosts = sorted({it.get("domain", "").lower() for it in r["items"] if it.get("domain")})
    r["hosts"] = hosts
    r["apexes"] = sorted({_apex(h) for h in hosts})
    # `total` counts DOCUMENTS (one per record type), hosts are deduped — judge truncation against
    # the rows actually returned, never against the deduped host list.
    r["truncated"] = isinstance(r.get("total"), int) and r["total"] > len(r["items"])
    return r


def whois_domain(domain):
    """The Netlas Domain-WHOIS record (registrar, created, registrant contact when the index has it)."""
    r = search("whois_domains", f"domain:{domain}", fields="domain,created_date,expiration_date,registrar.name,registrant.email,registrant.name,registrant.phone,name_servers", max_results=1)
    return (r.get("items") or [None])[0] if "items" in r else r


def plan():
    """Account plan + counters (entitlement discovery). Never returns the key."""
    s, d = _get("/api/users/current/")
    p = (d.get("plan") or {}) if isinstance(d, dict) else {}
    s2, c = _get("/api/users/profile_data/")
    c = c if isinstance(c, dict) else {}
    return {"plan": p.get("name"), "is_free": p.get("is_free"), "active_until": p.get("active_until"),
            "requests_limit": (c.get("requests_left") or {}).get("limit"),
            "coins_left": (c.get("coins") or {}).get("left"), "scanner": p.get("is_scanner_available")}


def _main():
    ap = argparse.ArgumentParser(description="Netlas search client / query builder")
    ap.add_argument("kind", choices=["ip", "ns", "spf", "domain", "registrant_email", "registrant_phone", "san", "title", "plan", "raw"])
    ap.add_argument("value", nargs="?")
    ap.add_argument("--collection", default="domains", help="with kind=raw")
    ap.add_argument("--count", action="store_true", help="count only")
    ap.add_argument("--fields", default="*")
    ap.add_argument("--max", type=int, default=200)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    if a.kind == "plan":
        out = plan()
    else:
        if a.kind == "raw":
            coll, q = a.collection, a.value
        else:
            cq = query_for(a.kind, a.value)
            if not cq:
                sys.exit(f"no Netlas expression for kind={a.kind}")
            coll, q = cq
        out = count(coll, q) if a.count else (reverse_ip(a.value, a.max) if a.kind == "ip" else search(coll, q, a.fields, a.max))
    print(json.dumps(out, ensure_ascii=False, indent=2 if a.json else None)[:20000])


if __name__ == "__main__":
    _main()
