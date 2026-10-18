#!/usr/bin/env python3
"""wp_quarry_reuse — skip a metered vendor call when this case already holds the equivalent
Quarry result.

Quarry and this skill spend the same vendor accounts. After a Quarry import, `quarry_bridge`
writes `cases/<case>/quarry/covered.json`. Each vendor client asks `get(key)` before it opens
a connection. A hit returns the stored marker and does not spend. A miss — a query Quarry did
not run, a different selector, no case dir — returns None and the call proceeds.

Equivalence is the query, not the vendor name. A FOFA `domain="host"` result does not cover
`icon_hash="…"`. A Censys certificate lookup does not cover a web-property lookup.
"""
import json
import os
import re

CASE_DIR_ENV = "WP_CASE_DIR"


def norm_query(query: str) -> str:
    """Case-fold and drop whitespace so `domain="Host"` and `domain="host"` are one query."""
    return re.sub(r"\s+", "", str(query or "").strip().lower())


def fofa_key(query: str) -> str:
    return "fofa:" + norm_query(query)


def urlscan_key(query: str) -> str:
    return "urlscan:" + norm_query(query)


def censys_cert_key(sha256: str) -> str:
    return "censys:cert:" + str(sha256 or "").strip().lower()


def censys_webproperty_key(ident: str) -> str:
    return "censys:webproperty:" + str(ident or "").strip().lower()


def whois_history_key(domain: str) -> str:
    return "whoisxml:history:" + str(domain or "").strip().lower()


def securitytrails_key(domain: str, record_type: str) -> str:
    return "securitytrails:dns:%s:%s" % (
        str(record_type or "").strip().lower(), str(domain or "").strip().lower())


def ipinfo_key(ip: str) -> str:
    return "ipinfo:" + str(ip or "").strip()


def shodan_key(query: str) -> str:
    return "shodan:" + norm_query(query)


def hunterhow_key(query: str) -> str:
    return "hunterhow:" + norm_query(query)


def _load():
    cdir = os.environ.get(CASE_DIR_ENV) or ""
    if not cdir:
        return {}
    try:
        with open(os.path.join(cdir, "quarry", "covered.json"), encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return {}
    queries = doc.get("queries") if isinstance(doc, dict) else None
    return queries if isinstance(queries, dict) else {}


def get(key: str):
    """The stored Quarry result for this exact query, or None. Never raises, never calls out."""
    hit = _load().get(key)
    if not isinstance(hit, dict):
        return None
    out = {"reused": "quarry", "query": key}
    for k, v in hit.items():
        if k != "vendor":
            out[k] = v
    return out


def _host_row(row: dict) -> dict:
    """Quarry FOFA host -> the `{host,ip,domain,title}` row `fofa_search` returns."""
    host = str(row.get("host") or row.get("domain") or "").strip()
    domain = str(row.get("domain") or "").strip()
    if not domain and host and "." in host and not host.replace(".", "").isdigit():
        domain = host.split(":")[0]
    return {
        "host": host, "ip": str(row.get("ip") or "").strip(), "domain": domain,
        "title": row.get("title") or "", "server": row.get("server") or "",
        "port": row.get("port") or "", "protocol": row.get("protocol") or "",
    }


def _whois_records(history) -> list:
    """Quarry WHOIS eras -> the `records` list `whois_history` splits into owner eras."""
    out = []
    for era in history or []:
        if not isinstance(era, dict):
            continue
        reg = era.get("registrant") if isinstance(era.get("registrant"), dict) else {}
        name = reg.get("name") or reg.get("organization") or era.get("registrant_name") or ""
        email = reg.get("email") or era.get("registrant_email") or ""
        out.append({
            "email": str(email).lower().strip() or None,
            "name": str(name).strip() or None,
            "registrar": str(era.get("registrar") or "").strip() or None,
            "phone": str(reg.get("phone") or era.get("registrant_phone") or "").strip() or None,
            "address": str(reg.get("address") or "").strip() or None,
            "country": reg.get("country") or era.get("country") or None,
            "created": era.get("created_date") or era.get("created") or None,
            "updated": era.get("updated_date") or era.get("timestamp") or None,
            "expires": era.get("expires_date") or era.get("expires") or None,
        })
    return out


def build_coverage(bundle, domain: str) -> dict:
    """Equivalent query keys from a Quarry export + overview. Each key carries the payload the
    matching vendor function returns — co-hosts, certificate names, WHOIS records — not a flag.
    A vendor block that is null, empty, or a different query is not covered."""
    export = (bundle or {}).get("export") or {}
    content = export.get("content") if isinstance(export.get("content"), dict) else export
    if not isinstance(content, dict):
        content = {}
    domain = str(domain or "").strip().lower()
    queries = {}

    def put(key, vendor, **extra):
        if key:
            row = {"vendor": vendor, "stored": True}
            row.update(extra)
            queries[key] = row

    fofa = content.get("fofa") or {}
    if isinstance(fofa, dict):
        hosts = [_host_row(h) for h in (fofa.get("hosts") or []) if isinstance(h, dict)]
        for q in fofa.get("queries") or []:
            put(fofa_key(q), "fofa", query=str(q), total=len(hosts), results=hosts)
    censys = content.get("censys") or {}
    if isinstance(censys, dict):
        for cert in censys.get("certs") or []:
            if not isinstance(cert, dict):
                continue
            fp = cert.get("fingerprint_sha256") or cert.get("fingerprint") or ""
            names = cert.get("names") or cert.get("sans") or cert.get("dns_names") or []
            if isinstance(names, str):
                names = [names]
            put(censys_cert_key(fp), "censys",
                fingerprint_sha256=str(fp).strip().lower(),
                names=[str(n).strip() for n in names if n],
                subject_cn=cert.get("subject_cn") or "",
                issuer=cert.get("issuer") or "")
        # hosts[] are IP host lookups, not hostname:443 web properties — do not cover those.
    whois = content.get("whois") or {}
    if isinstance(whois, dict):
        records = _whois_records(whois.get("whois_history"))
        if records:
            put(whois_history_key(domain), "whoisxml", records=records, count=len(records))
        for rtype, field in (("ns", "ns_history"), ("mx", "mx_history"),
                             ("soa", "soa_history"), ("txt", "txt_history")):
            rows = [r for r in (whois.get(field) or []) if isinstance(r, dict)]
            if rows:
                put(securitytrails_key(domain, rtype), "securitytrails",
                    total=len(rows), records=rows)
    ip_whois = content.get("ip_whois") or {}
    if isinstance(ip_whois, dict):
        for row in ip_whois.get("results") or []:
            if not isinstance(row, dict) or not row.get("ip"):
                continue
            provider = str(row.get("provider") or "").lower()
            sources = [str(s).lower() for s in (row.get("sources") or [])]
            if "ipinfo" in provider or "ipinfo" in sources:
                put(ipinfo_key(row["ip"]), "ipinfo",
                    ip=row.get("ip"), asn=row.get("asn") or "",
                    org_name=row.get("org_name") or row.get("org") or "",
                    hostname=row.get("hostname") or "",
                    city=row.get("city") or "", region=row.get("region") or "",
                    country=row.get("country") or row.get("country_code") or "")
    overview = (bundle or {}).get("overview") or {}
    vendor = overview.get("vendor_intel") if isinstance(overview, dict) else None
    if isinstance(vendor, dict) and vendor.get("webamon"):
        put("webamon:domain:" + domain, "webamon", webamon=vendor.get("webamon"))
    return {"domain": domain, "queries": queries}


def write_coverage(case_dir: str, bundle, domain: str) -> str:
    doc = build_coverage(bundle, domain)
    d = os.path.join(case_dir, "quarry")
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, "covered.json")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)
    os.replace(tmp, path)
    return path


__all__ = ["get", "build_coverage", "write_coverage", "fofa_key", "urlscan_key",
           "censys_cert_key", "censys_webproperty_key", "whois_history_key",
           "securitytrails_key", "ipinfo_key", "shodan_key", "hunterhow_key"]
