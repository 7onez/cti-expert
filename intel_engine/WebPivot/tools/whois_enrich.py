#!/usr/bin/env python3
"""
whois_enrich.py — WhoisXML API enrichment for WebPivot.

Adds registration-based pivots to the DOM/infra pivots from pivot_extract.py:
  * current WHOIS       — registrant email/name/org, registrar, dates, name servers
  * WHOIS history       — every registrant email/name/registrar ever seen (catches
                          pre-privacy records that name the real owner)
  * reverse WHOIS       — other domains sharing a registrant email / name

Registrant email + name are top-tier same-operator artifacts — they cluster
infrastructure the way a shared GA4 ID or favicon does, and history often exposes
an owner who later hid behind WHOIS privacy.

Keys: reads WHOISXML_API_KEY from the environment first, then the chmod-600
customization .env (env wins). No key -> every call is a no-op (returns None).

Usage:
  python3 whois_enrich.py example.com                    # current + history summary
  python3 whois_enrich.py example.com --history-mode purchase   # full history records
  python3 whois_enrich.py --reverse-email owner@x.com    # reverse WHOIS by email
  python3 whois_enrich.py --reverse-name "Some Org" --search-type historic
  python3 whois_enrich.py example.com --json             # raw JSON
"""

import os
import sys
import json
import argparse
import concurrent.futures
import urllib.request
import urllib.error
from urllib.parse import urlencode
try:
    import api_usage                      # licensed-API credit ledger
except Exception:
    api_usage = None

DEFAULT_UA = "WebPivot-whois/1.0"
_CUSTOMIZATION_ENV = os.path.expanduser(
    "~/.claude/PAI/USER/SKILLCUSTOMIZATIONS/WebPivot/.env")

WHOIS_CURRENT_URL = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
WHOIS_HISTORY_URL = "https://whois-history.whoisxmlapi.com/api/v1"
REVERSE_WHOIS_URL = "https://reverse-whois.whoisxmlapi.com/api/v2"


def _load_customization_env(path=_CUSTOMIZATION_ENV):
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
    except FileNotFoundError:
        pass
    except Exception:
        pass


_load_customization_env()


def _key():
    for n in ("WHOISXML_API_KEY", "WHOISXMLAPI_KEY", "WHOIS_API_KEY"):
        v = os.environ.get(n)
        if v and v.strip():
            return v.strip()
    return None


# Privacy-proxy / registrar-role markers — these are NOT the real owner and must
# never become a same-operator hub or trigger a reverse-WHOIS (which would return
# thousands of unrelated domains and waste credits).
_PRIVACY_MARKERS = (
    "privacy", "redacted", "whoisguard", "data protected", "withheld", "not disclosed",
    "domains by proxy", "domainsbyproxy", "registration private", "private by design",
    "identity protect", "contact privacy", "perfect privacy", "gdpr masked", "statutory masking")
_ROLE_PREFIXES = ("abuse@", "hostmaster@", "noc@", "registrar-abuse@", "postmaster@")
_PROXY_DOMAINS = ("porkbun.com", "godaddy.com", "namecheap.com", "domainsbyproxy.com",
                  "withheldforprivacy.com", "privacyprotect.org", "1and1.com",
                  "contactprivacy.com", "whoisprivacyprotect.com", "privacyguardian.org")


def is_privacy(value):
    """True if a registrant value is a privacy proxy / registrar role / non-identifying."""
    if not value:
        return True
    s = str(value).strip().lower()
    if s.startswith("http"):
        return True  # a URL placeholder, not a real contact
    if any(m in s for m in _PRIVACY_MARKERS):
        return True
    if any(s.startswith(p) for p in _ROLE_PREFIXES):
        return True
    if "@" in s and s.split("@", 1)[1] in _PROXY_DOMAINS:
        return True
    return False


def _wx_action(url):
    """WhoisXML endpoint → billable action label for the usage ledger (each charges credits)."""
    if url == WHOIS_HISTORY_URL:
        return "whois-history"
    if url == REVERSE_WHOIS_URL:
        return "reverse-whois"
    return "whois"


def _get_json(url, params, timeout=30):
    full = url + "?" + urlencode(params)
    req = urllib.request.Request(full, headers={"User-Agent": DEFAULT_UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        out = json.load(r)
    if api_usage:
        api_usage.record("whoisxml", _wx_action(url), credits=1,
                         query=params.get("domainName") or params.get("terms") or params.get("q"))
    return out


def _post_json(url, payload, timeout=30):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"User-Agent": DEFAULT_UA,
                                          "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        out = json.load(r)
    if api_usage:
        api_usage.record("whoisxml", _wx_action(url), credits=1)
    return out


def _contact(rec, *keys):
    """Pull the first present nested contact block from a WHOIS record."""
    for k in keys:
        c = rec.get(k)
        if isinstance(c, dict) and c:
            return c
    return {}


def _phone(contact):
    """Normalized registrant phone (digits/+ only, keep extension marker)."""
    raw = (contact.get("telephone") or contact.get("phone") or "").strip()
    return raw or None


def _address(contact):
    """Single-line street/city/state/postal/country address, pivot-ready."""
    parts = [contact.get(k) for k in
             ("street1", "street2", "city", "state", "postalCode", "country")]
    parts = [str(p).strip() for p in parts if p and str(p).strip()]
    return ", ".join(parts) or None


def whois_current(domain, timeout=30, keep_raw=True):
    """Current WHOIS for a domain. Returns a normalized dict or {'error':...} / None.

    With keep_raw (default), the FULL unmodified WhoisXML response is retained under
    the '_raw' key so the complete record is archived for later reference, not just
    the normalized fields we happen to surface today."""
    key = _key()
    if not key:
        return None
    try:
        data = _get_json(WHOIS_CURRENT_URL,
                         {"apiKey": key, "domainName": domain,
                          "outputFormat": "JSON"}, timeout=timeout)
    except Exception as e:
        return {"error": str(e), "domain": domain}
    rec = data.get("WhoisRecord") or {}
    if not rec:
        return {"error": "no WhoisRecord", "domain": domain, "_raw": data if keep_raw else None}
    # Many registrars (e.g. Hostinger/thin registries) populate dates + name servers
    # ONLY under the nested registryData, leaving the top-level fields empty. Read
    # each field from rec, then fall back to registryData so they aren't dropped.
    reg_data = rec.get("registryData") or {}
    def _f(*keys):
        for src in (rec, reg_data):
            for k in keys:
                v = src.get(k)
                if v:
                    return v
        return None
    reg = _contact(rec, "registrantContact", "registrant") \
        or _contact(reg_data, "registrantContact", "registrant") or {}
    ns = ((rec.get("nameServers") or {}).get("hostNames")
          or (reg_data.get("nameServers") or {}).get("hostNames") or [])
    res = {
        "domain": domain,
        "registrant_email": (reg.get("email") or rec.get("contactEmail")
                             or reg_data.get("contactEmail") or "").lower() or None,
        "registrant_name": reg.get("name") or None,
        "registrant_org": reg.get("organization") or None,
        "registrant_country": reg.get("country") or reg.get("countryCode") or None,
        "registrant_phone": _phone(reg),
        "registrant_address": _address(reg),
        "registrar": _f("registrarName"),
        "created": _f("createdDateNormalized", "createdDate"),
        "updated": _f("updatedDateNormalized", "updatedDate"),
        "expires": _f("expiresDateNormalized", "expiresDate"),
        "name_servers": sorted({n.lower() for n in ns if n}),
    }
    if keep_raw:
        res["_raw"] = data   # full unmodified WhoisXML record, archived for later ref
    return res


def whois_history(domain, mode="purchase", timeout=40, keep_raw=True):
    """Historical WHOIS records. mode=preview (count only) or purchase (full).

    Returns {'count','registrant_emails','registrant_names','registrars','records'}.
    With keep_raw (default), the full unmodified history response is kept under '_raw'.
    """
    key = _key()
    if not key:
        return None
    try:
        data = _get_json(WHOIS_HISTORY_URL,
                         {"apiKey": key, "domainName": domain,
                          "mode": mode, "outputFormat": "JSON"}, timeout=timeout)
    except Exception as e:
        return {"error": str(e), "domain": domain}
    recs = data.get("records") or []
    emails, names, registrars, phones, addresses, out = set(), set(), set(), set(), set(), []
    for rec in recs:
        reg = _contact(rec, "registrantContact", "registrant")
        em = (reg.get("email") or "").lower().strip()
        nm = (reg.get("name") or reg.get("organization") or "").strip()
        rg = (rec.get("registrarName") or "").strip()
        ph = _phone(reg)
        ad = _address(reg)
        if nm and any(0x80 <= ord(c) <= 0x9f for c in nm):
            nm = ""  # drop C1-mojibake-corrupted names (double-encoding artifacts)
        if em:
            emails.add(em)
        if nm:
            names.add(nm)
        if rg:
            registrars.add(rg)
        if ph:
            phones.add(ph)
        if ad:
            addresses.add(ad)
        out.append({
            "email": em or None, "name": nm or None, "registrar": rg or None,
            "phone": ph, "address": ad,
            "created": rec.get("createdDateNormalized") or rec.get("createdDateISO8601"),
            "updated": rec.get("updatedDateNormalized"),
            "expires": rec.get("expiresDateNormalized"),
        })
    res = {
        "count": data.get("recordsCount", len(recs)),
        "registrant_emails": sorted(emails),
        "registrant_names": sorted(names),
        "registrant_phones": sorted(phones),
        "registrant_addresses": sorted(addresses),
        "registrars": sorted(registrars),
        "records": out if mode == "purchase" else [],
    }
    if keep_raw:
        res["_raw"] = data   # full unmodified history response, archived for later ref
    return res


def reverse_whois(term, kind="email", search_type="current", mode="purchase", timeout=40):
    """Domains sharing a registrant term. kind: email|name|org. search_type: current|historic.

    mode=preview returns {'count'} only (cheap); purchase returns {'count','domains'}.
    """
    key = _key()
    if not key or not term:
        return None
    payload = {
        "apiKey": key,
        "searchType": search_type,
        "mode": mode,
        "punycode": True,
        "basicSearchTerms": {"include": [term]},
    }
    try:
        data = _post_json(REVERSE_WHOIS_URL, payload, timeout=timeout)
    except urllib.error.HTTPError as e:
        try:
            body = json.load(e)
            return {"error": body.get("messages") or str(e), "term": term}
        except Exception:
            return {"error": str(e), "term": term}
    except Exception as e:
        return {"error": str(e), "term": term}
    domains = [d.get("domainName") if isinstance(d, dict) else d
               for d in (data.get("domainsList") or [])]
    return {"term": term, "kind": kind, "search_type": search_type,
            "count": data.get("domainsCount", len(domains)),
            "domains": [d for d in domains if d][:200]}


def whois_summary(domain, history_mode="purchase", timeout=40, keep_raw=True):
    """Combined current + history block, ready to attach to a pivot_extract result.

    Always fetches the FULL current + history WHOIS. With keep_raw (default) the
    complete unmodified API responses are archived under out['raw'] = {current, history}
    so later analysis can mine fields we don't normalize today."""
    if not _key():
        return None
    # current + history are two INDEPENDENT WhoisXML calls (the long pole of enrichment). Run them
    # concurrently to ~halve WHOIS latency per host. Same two API calls, same credits/egress — only
    # concurrency changes; api_usage.record's single-line append is atomic, so it's ledger-safe.
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as _ex:
        _f_cur = _ex.submit(whois_current, domain, timeout=timeout, keep_raw=keep_raw)
        _f_hist = _ex.submit(whois_history, domain, mode=history_mode, timeout=timeout, keep_raw=keep_raw)
        cur = _f_cur.result() or {}
        hist = _f_hist.result() or {}
    cur_raw = cur.pop("_raw", None)
    hist_raw = hist.pop("_raw", None)
    out = dict(cur)
    out["history"] = {k: hist.get(k) for k in
                      ("count", "registrant_emails", "registrant_names",
                       "registrant_phones", "registrant_addresses", "registrars")}
    if hist.get("error"):
        out["history"]["error"] = hist["error"]
    if keep_raw:
        out["raw"] = {"current": cur_raw, "history": hist_raw}
    return out


# ----------------------------------------------------------------- CLI
def main():
    ap = argparse.ArgumentParser(description="WhoisXML enrichment for WebPivot.")
    ap.add_argument("domain", nargs="?", help="domain to look up (current + history)")
    ap.add_argument("--history-mode", choices=["preview", "purchase"], default="purchase")
    ap.add_argument("--reverse-email", help="reverse WHOIS by registrant email")
    ap.add_argument("--reverse-name", help="reverse WHOIS by registrant name/org")
    ap.add_argument("--reverse-phone", help="reverse WHOIS by registrant phone (bulk = registrar noise)")
    ap.add_argument("--search-type", choices=["current", "historic"], default="current")
    ap.add_argument("--reverse-mode", choices=["preview", "purchase"], default="purchase")
    ap.add_argument("--json", action="store_true", help="raw JSON output")
    args = ap.parse_args()

    if not _key():
        print("[!] no WHOISXML_API_KEY set (env or customization .env). Nothing to do.",
              file=sys.stderr)
        sys.exit(2)

    out = {}
    if args.reverse_email:
        out["reverse_email"] = reverse_whois(args.reverse_email, "email",
                                             args.search_type, args.reverse_mode)
    if args.reverse_name:
        out["reverse_name"] = reverse_whois(args.reverse_name, "name",
                                            args.search_type, args.reverse_mode)
    if args.reverse_phone:
        out["reverse_phone"] = reverse_whois(args.reverse_phone, "phone",
                                             args.search_type, args.reverse_mode)
    if args.domain:
        out["whois"] = whois_summary(args.domain, history_mode=args.history_mode)

    if not out:
        ap.error("give a domain and/or --reverse-email/--reverse-name")

    if args.json:
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return
    # human-readable
    w = out.get("whois")
    if w:
        print(f"# WHOIS — {w.get('domain')}")
        for k in ("registrant_email", "registrant_name", "registrant_org",
                  "registrant_phone", "registrant_address",
                  "registrar", "created", "updated", "expires"):
            if w.get(k):
                print(f"  {k:18} {w[k]}")
        if w.get("name_servers"):
            print(f"  name_servers       {', '.join(w['name_servers'])}")
        h = w.get("history") or {}
        if h.get("count"):
            print(f"  history: {h['count']} records")
            if h.get("registrant_emails"):
                print(f"    emails:    {', '.join(h['registrant_emails'])}")
            if h.get("registrant_names"):
                print(f"    names:     {', '.join(h['registrant_names'])}")
            if h.get("registrant_phones"):
                print(f"    phones:    {', '.join(h['registrant_phones'])}")
            if h.get("registrant_addresses"):
                print(f"    addresses: {', '.join(h['registrant_addresses'])}")
    for key in ("reverse_email", "reverse_name"):
        r = out.get(key)
        if r:
            if r.get("error"):
                print(f"# {key}: error — {r['error']}")
            else:
                print(f"# {key} '{r['term']}' ({r['search_type']}): {r['count']} domains")
                for d in r.get("domains", [])[:50]:
                    print(f"    {d}")


if __name__ == "__main__":
    main()
