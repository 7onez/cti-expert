#!/usr/bin/env python3
"""
house_report_dossier.py — Appendix C domain dossiers (Rule 17) and Appendix E glossary (Rule 23)
for the deterministic house report: one Field · Value table per domain in scope, and a Term · plain
meaning table containing ONLY the terms the composed report actually uses. Stdlib only; the WHOIS
country reconcile reuses the collector's helper when it is importable.
"""
from __future__ import annotations

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
WP_TOOLS = os.path.join(ROOT, "WebPivot", "tools")


# --------------------------------------------------------------------------- domain dossiers
def _live_results(raw: dict) -> dict:
    for p in raw.get("pivots") or []:
        lr = p.get("live_results") if isinstance(p, dict) else None
        if isinstance(lr, dict) and ("dns" in lr or "passivedns" in lr or "ipinfo" in lr):
            return lr
    return {}


def _hosting(raw: dict) -> str:
    lr = _live_results(raw)
    dns = lr.get("dns") or {}
    ipinfo = lr.get("ipinfo") or {}
    parts = []
    for cl in dns.get("ip_classification") or [{"ip": ip} for ip in dns.get("ips") or []]:
        ip = cl.get("ip")
        asn = (ipinfo.get(ip) or {}).get("asn")
        tag = f"{cl.get('provider')} edge" if cl.get("cdn") else "origin"
        parts.append(f"`{ip}`" + (f" ({asn}, {tag})" if asn else f" ({tag})"))
    pd = lr.get("passivedns") or {}
    cdn_ips = {cl.get("ip") for cl in dns.get("ip_classification") or [] if cl.get("cdn")}
    origins = [h for h in pd.get("hosts") or [] if h.get("ip") and h["ip"] not in cdn_ips and h["ip"] not in (dns.get("ips") or [])]
    if origins:
        parts.append("behind the edge (passive DNS): " + ", ".join(f"`{h['host']}` → `{h['ip']}`" for h in origins[:3]))
    return "; ".join(parts) or "—"


def registrant_country(w: dict) -> str:
    """ISO country for the WHOIS registrant, or '' when only a registrar placeholder ('NA'/'NAMIBIA',
    the not-available token WhoisXML maps to Namibia) is on record. Records enriched after the
    country reconcile carry the corrected code; older sidecars are reconciled here from the raw
    contact (phone prefix / address fields) with the same helper the collector uses."""
    cc = (w.get("registrant_country") or "").strip()
    try:
        sys.path.insert(0, WP_TOOLS)
        import whois_enrich  # noqa: E402
        placeholders = whois_enrich._PLACEHOLDER_COUNTRIES
        if cc.upper() in placeholders or not cc:
            # whois_current() keeps the raw record at top-level `_raw`; whois_summary() (the
            # sidecar's shape once history is requested) nests it at raw.current — read both.
            raw_rec = w.get("_raw") or ((w.get("raw") or {}).get("current")) or {}
            # Same contact resolution as the collector: WhoisXML's primary key is `registrantContact`
            # (legacy `registrant`), with `registryData` as the fallback record.
            rec = (raw_rec.get("WhoisRecord") or {})
            contact = (whois_enrich._contact(rec, "registrantContact", "registrant")
                       or whois_enrich._contact(rec.get("registryData") or {}, "registrantContact", "registrant")
                       or {})
            fixed = whois_enrich._reconcile_country(contact) if contact else None
            return fixed or ""
    except Exception:  # noqa: BLE001 — helper unavailable: drop anything that is not a clean code
        if cc.upper() in ("NA", "NAMIBIA", "N/A", "NONE", "REDACTED"):
            return ""
    return cc if re.fullmatch(r"[A-Z]{2}", cc) else ""


def domain_profiles_md(c: dict, load_json, escape) -> str:
    """Rule 17: one Field · Value dossier per domain in scope."""
    L = []
    for h in c["hosts"]:
        w = c["whois"].get(h, {})
        raw = next((load_json(p, {}) for p in c["raw"] if os.path.basename(p)[:-5].lower() == h), {}) or {}
        a = raw.get("artifacts") or {}
        meta = raw.get("meta") or {}
        http = a.get("http") or {}
        status = http.get("status")
        live = (f"live (HTTP {status})" if status else "not reached") + (f", final URL `{meta['final_url']}`" if meta.get("final_url") and meta["final_url"].rstrip("/") != f"https://{h}" else "")
        if meta.get("archived_via_wayback"):
            live += " — content from web archive"
        reg = " / ".join(x for x in (w.get("registrant_name"), w.get("registrant_email"), w.get("registrant_phone")) if x) or "privacy-redacted"
        cc = registrant_country(w)
        if cc:
            reg += f" ({cc})"
        tls = a.get("tls_cert") or {}
        tls_s = "—"
        if tls.get("fingerprint_sha256"):
            tls_s = (f"issuer {escape(tls.get('issuer') or '—')}; valid from "
                     f"{escape(' '.join((tls.get('not_before') or '—').split()))}; SHA-256 `{tls['fingerprint_sha256']}`")
        mail = a.get("mail") or {}
        mail_s = []
        if mail.get("mx_hosts"):
            mail_s.append("MX " + ", ".join(f"`{m}`" for m in mail["mx_hosts"][:2]))
        spf = (mail.get("spf") or {}).get("includes") or []
        if spf:
            mail_s.append("SPF includes " + ", ".join(f"`{s}`" for s in spf[:3]))
        tech = list(a.get("tech_fingerprint") or []) + [f"theme:{t}" for t in a.get("wp_themes") or []]
        distinct = []
        if a.get("title"):
            distinct.append(f"title \u201c{escape(str(a['title'])[:60])}\u201d")
        fav = a.get("favicon")
        if isinstance(fav, dict) and fav.get("mmh3") is not None:
            distinct.append(f"favicon mmh3 `{fav['mmh3']}`")
        if a.get("dom_skeleton_sha1"):
            distinct.append(f"DOM skeleton `{a['dom_skeleton_sha1']}`")
        for kind, ids in ((a.get("trackers") or {}).items()):
            for i in (ids if isinstance(ids, list) else [ids])[:2]:
                distinct.append(f"{kind} `{i}`")
        rows = [f"### {h} {{.unnumbered .unlisted}}", "", "| Field | Value |", "|:----------|:----------------------------------|",
                f"| Status | {escape(live)} |",
                f"| Registrar · created | {escape(w.get('registrar') or '—')} · {(w.get('created') or '—')[:10]} |",
                f"| Expires | {(w.get('expires') or '—')[:10]} |",
                f"| Registrant (WHOIS) | {escape(reg)} |",
                f"| Nameservers | {escape(', '.join(w.get('name_servers') or []) or '—')} |",
                f"| Hosting | {_hosting(raw)} |",
                f"| TLS | {tls_s} |",
                f"| Mail | {'; '.join(mail_s) or '—'} |",
                f"| Tech stack | {escape(', '.join(tech) or '—')} |",
                f"| Distinctive artifacts | {'; '.join(distinct) or '—'} |", ""]
        L += rows
    return "\n".join(L)


# --------------------------------------------------------------------------- glossary
# (term, detection regex, plain-English meaning). Only terms the composed report actually uses print.
GLOSSARY = [
    ("WHOIS / RDAP", r"\bWHOIS\b|\bRDAP\b", "The public registration record of a domain: who registered it (name, e-mail, phone — often masked by a privacy service), through which registrar, and when it was created, updated and expires."),
    ("Reverse WHOIS", r"reverse[- ]WHOIS", "Searching registration records backwards — from a registrant e-mail or phone to every domain that carries it."),
    ("Registrar", r"\bregistrar\b", "The company a domain is bought through. It holds the registration record and receives abuse referrals for it."),
    ("Registrant", r"\bregistrant\b", "The person or organisation named in a domain's registration record."),
    ("Registrant persona", r"\bpersona\b", "The name / e-mail / phone triple a registrant typed in. It identifies one account, not necessarily a real person."),
    ("Nameserver", r"\bnameservers?\b", "The DNS servers a domain delegates to. Managed providers (e.g. a CDN) give many unrelated customers the same names, so a shared nameserver is weak evidence."),
    ("Passive DNS", r"passive DNS", "Historical records of which IP addresses a hostname resolved to and when, collected by resolvers rather than by contacting the site."),
    ("Origin IP / hosting", r"\borigin\b|\bhosting\b", "The server that actually holds the site. When a CDN fronts the site, the visible address belongs to the CDN and the origin sits behind it."),
    ("CDN / edge", r"\bCDN\b|\bedge\b|cloudflare", "A content-delivery network: shared front-end servers that many unrelated sites sit behind, so their IP addresses do not link sites to each other."),
    ("ASN", r"\bAS\d{3,6}\b|\bASN\b", "Autonomous System Number — the identifier of the network operator that announces an IP address range."),
    ("TLS certificate", r"\bTLS\b|certificate", "The certificate a site presents for HTTPS. Its issuer, validity dates and SHA-256 fingerprint are recorded in public logs."),
    ("Certificate transparency", r"certificate[- ]transparency|\bCT\b", "Public, append-only logs of every certificate issued, which let anyone see when a hostname first received a certificate."),
    ("SAN", r"\bSANs?\b", "Subject Alternative Name — the list of hostnames one certificate covers; two domains on one certificate were provisioned together."),
    ("SHA-256 / SHA-1", r"SHA-?256|SHA-?1\b|sha256|sha1", "A cryptographic fingerprint of a file or certificate. Quoted in full so anyone holding the same bytes can re-verify it."),
    ("Favicon hash (mmh3)", r"favicon|mmh3", "A numeric fingerprint of a site's tab icon. Sites built from the same kit share it; so do sites using a common stock icon, which is why it is checked for prevalence."),
    ("DOM skeleton", r"DOM skeleton|dom_skeleton", "A fingerprint of a page's HTML structure with the text removed. Pages generated by the same template share it."),
    ("JARM", r"\bJARM\b", "A fingerprint of how a server answers a TLS handshake; two servers configured the same way share it."),
    ("SPF / DMARC / MX", r"\bSPF\b|\bDMARC\b|\bMX\b", "Mail-routing DNS records: MX names the mail server, SPF lists who may send for the domain, DMARC says what to do with failures. Shared values show shared mail provisioning."),
    ("Typosquat / impersonation domain", r"typosquat|impersonat", "A domain name chosen to look like a genuine brand's name, to borrow its credibility."),
    ("SEO doorway / link farm", r"doorway|link farm|\bSEO\b", "A site with no product of its own, built to rank in search results and pass visitors or ranking value on to other sites."),
    ("Drop-catching", r"drop-?catch", "Registering a domain the moment its previous owner lets it expire, to inherit its history and search reputation."),
    ("Web archive", r"web archive|Wayback|archived", "A public, dated copy of a page (e.g. the Internet Archive), cited so a reader can see what the site showed at a given time."),
    ("Web-scan data", r"web-scan|urlscan", "Public services that fetch and record web pages on request, giving dated third-party snapshots of a site's content and behaviour."),
    ("Infostealer / stealer log", r"infostealer|stealer[- ]log", "Credentials and browser data taken from an infected computer and traded in bulk; a hit ties a machine to an account."),
    ("Leak corpus", r"leak[- ]corpus|breach", "Aggregated data from past breaches, searched to see whether an e-mail or phone appears in other contexts."),
    ("Same-operator estate", r"same-operator|estate", "A set of domains assessed to be controlled by one party."),
    ("Pivot ladder / rung", r"\brung\b|pivot ladder", "The ranking of link types by strength: rung 1 is a registrant record the operator typed in; high rungs are shared providers many strangers also share."),
    ("Rung 1 (registrant record)", r"rung 1", "The strongest link class — the same registrant e-mail or phone on two domains, an owner-controlled value."),
    ("BLUF", r"\bBLUF\b", "Bottom Line Up Front — the conclusion stated before the evidence."),
    ("NATO Admiralty code", r"Admiralty|\b[A-F][1-6]\b", "A two-part grade for each piece of evidence: source reliability A (completely reliable) to F (cannot be judged) × information credibility 1 (confirmed) to 6 (cannot be judged)."),
    ("ICD-203 estimative words", r"ICD[- ]203|almost certain|very likely|\blikely\b|roughly even chance|very unlikely", "The fixed probability vocabulary of US intelligence standard ICD 203: almost no chance (1–5%), very unlikely (5–20), unlikely (20–45), roughly even chance (45–55), likely (55–80), very likely (80–95), almost certain (95–99)."),
    ("Confidence (low / moderate / high)", r"\bconfidence\b", "How well the evidence supports a judgment — distinct from the probability word, which says how likely the judgment is to be true."),
    ("Assessed / observed", r"\bassessed\b|\bobserved\b", "'Observed' is a fact we saw directly; 'assessed' is a conclusion we drew from facts."),
    ("Alternative analysis", r"Alternative analysis|Alternative explanation", "Listing the innocent explanations for the evidence and stating which were ruled out and why (analysis of competing hypotheses)."),
    ("TLP", r"\bTLP:?\s?(CLEAR|GREEN|AMBER|RED)", "Traffic Light Protocol — the sharing marking. CLEAR: may be published; GREEN: community; AMBER: recipients' organisations only; RED: named recipients only."),
    ("Headless browser", r"headless", "A real web browser run without a window, used to render a page exactly as a visitor would see it and save the result."),
]


def glossary_md(report_md: str) -> str:
    rows = ["| Term | Plain-English meaning |", "|:------------|:--------------------------------------|"]
    for term, rx, meaning in GLOSSARY:
        if re.search(rx, report_md, re.I):
            rows.append(f"| {term} | {meaning} |")
    return "\n".join(rows)
