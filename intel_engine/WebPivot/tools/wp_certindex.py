#!/usr/bin/env python3
"""wp_certindex — CertIndex (api.ctindex.io) CT lookups, an optional keyed backup for wp_ct.

FREE TIER: personal / non-commercial use only; 10 full-domain lookups per hour ACCOUNT-WIDE (each
page is one lookup), 10 000 a month; currently valid certificates only (~1 year).

Quota is never waited on: `usage()` reads GET /v1/usage — free, not a lookup — and a domain fetch
uses at most min(max_pages, remaining this hour) pages. No lookups left → `skipped-quota`; an HTTP
429 mid-walk → `partial` (or `skipped-quota` on the first page), with the server's retry_after in
the note. A new domain's first query is partial while CertIndex backfills it — `coverage.basis` not
yet `domain_backfill_completed…` or `total_is_lower_bound` — and is reported `partial`, so a later
call asks again. Recorded to the usage ledger at 0 credits (quota, not money) for visibility.
"""
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wp_common import DEFAULT_UA, _secret  # noqa: E402
from wp_refs import ref_path, load_ref  # noqa: E402

try:
    import api_usage
except Exception:  # noqa: BLE001
    api_usage = None

_FALLBACK = {"certindex": {"base_url": "https://api.ctindex.io", "page_size": 100, "max_pages": 1,
                           "request_timeout_seconds": 60}}
CFG = load_ref(ref_path(__file__, "ct_sources.json"), _FALLBACK)["certindex"]


def certindex_key():
    return _secret("CERTINDEX_API_KEY", "CTINDEX_API_KEY")


def certindex_configured():
    return bool(certindex_key())


def _get(path, params=None):
    """GET → (status, json|text). Never raises."""
    url = CFG["base_url"] + path + ("?" + urllib.parse.urlencode(params) if params else "")
    req = urllib.request.Request(url, headers={"X-API-Key": certindex_key() or "",
                                               "User-Agent": DEFAULT_UA, "Accept": "application/json"})
    opener = getattr(urllib.request.urlopen, "_cti_orig", urllib.request.urlopen)
    try:
        with opener(req, timeout=CFG["request_timeout_seconds"]) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        body = e.read()[:400].decode("utf-8", "replace")
        try:
            return e.code, json.loads(body)
        except ValueError:
            return e.code, body
    except Exception as e:  # noqa: BLE001
        return None, f"{type(e).__name__}: {e}"[:160]


def usage():
    """{'tier','commercial_use_allowed','full_domain_left','monthly_left','resets_at'} | {'error'}.
    Free — reading the quota is not a lookup."""
    if not certindex_configured():
        return {"error": "no CERTINDEX_API_KEY"}
    s, d = _get("/v1/usage")
    if s != 200 or not isinstance(d, dict):
        return {"error": f"usage HTTP {s}: {str(d)[:120]}"}
    rem = d.get("remaining") or {}
    return {"tier": d.get("tier"), "commercial_use_allowed": d.get("commercial_use_allowed"),
            "full_domain_left": rem.get("full_domain_per_hr"), "monthly_left": rem.get("monthly"),
            "resets_at": (d.get("billing_period") or {}).get("resets_at")}


def _coverage_gap(page):
    """None when CertIndex says its inventory for the domain is complete, else its own basis."""
    cov = page.get("coverage") or {}
    basis = str(cov.get("basis") or "unknown")
    lower = page.get("total_is_lower_bound") or cov.get("total_is_lower_bound")
    if basis.startswith("domain_backfill_completed") and not lower:
        return None
    return basis + (" (total is a lower bound)" if lower else "")


def certindex_fetch(domain):
    """CertIndex certificates for `domain` → wp_ct source result. Never raises."""
    import wp_ct  # noqa: PLC0415 — avoid an import cycle with wp_ct
    out = {"source": "certindex", "window": wp_ct.WINDOWS.get("certindex"), "rows": [], "errors": []}
    if not certindex_configured():
        out.update(status="skipped-no-key", n=0)
        return out
    u = usage()
    if u.get("error"):
        out["errors"].append(u["error"])
        out.update(status="failed", n=0)
        return out
    left = min(int(u.get("full_domain_left") or 0), int(u.get("monthly_left") or 0))
    if left <= 0:
        out["note"] = "no CertIndex lookups left this hour/month (quota resets; not waited on)"
        out.update(status="skipped-quota", n=0)
        return out
    budget = min(int(CFG["max_pages"]), left)
    page, status, gap = 1, None, None
    while page <= budget:
        s, d = _get(f"/v1/domains/{urllib.parse.quote(domain)}/certificates",
                    {"limit": int(CFG["page_size"]), "page": page})
        if s != 200 or not isinstance(d, dict):
            retry = d.get("retry_after") if isinstance(d, dict) else None
            out["errors"].append(f"page {page}: HTTP {s}" + (f" (retry_after {retry}s)" if retry else ""))
            status = ("skipped-quota" if s == 429 else "failed") if page == 1 else "partial"
            break
        gap = gap or _coverage_gap(d)
        for r in d.get("results") or []:
            out["rows"].append(wp_ct._cert(
                "certindex", sha256=r.get("sha256"), issuer=r.get("issuer_cn") or r.get("issuer_o"),
                common_name=r.get("subject_cn"), names=r.get("sans") or [],
                not_before=r.get("not_before"), not_after=r.get("not_after")))
        if not d.get("has_more"):
            status = "complete"
            break
        page += 1
    pages = min(page, budget)
    status = status or "capped"
    if status in ("complete", "capped") and gap:
        status = "partial"
        out["note"] = f"CertIndex coverage: {gap}"
    out.update(status=status, pages=pages, n=len(wp_ct.dedup_certs(out["rows"])))
    if api_usage:
        api_usage.record("certindex", "domain_certificates", credits=0, query=domain,
                         results=out["n"], ok=status not in ("failed", "skipped-quota"))
    return out


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "usage":
        print(json.dumps(usage(), indent=2))
    else:
        r = certindex_fetch(sys.argv[1] if len(sys.argv) > 1 else "example.com")
        print(json.dumps({k: v for k, v in r.items() if k != "rows"}, indent=2))
