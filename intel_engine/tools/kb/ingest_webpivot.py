#!/usr/bin/env python3
"""
ingest_webpivot.py — adapter: pivot_extract.py JSON  ->  attributed facts in the KB.

Turns one WebPivot collection into atomic, provenance-carrying facts and edges:
  * each shared artifact (favicon, GA4/GTM, verification token, registrant, name
    server) becomes an `indicator`/`email`/`person` entity, and the domain gets an
    attributed edge to it. Domains that share an indicator are thus auto-linked.
  * FOFA / urlscan / reverse-WHOIS live_results become edges from the DISCOVERED
    sibling domains to the same indicator, sourced to the engine that found them.
  * the raw pivot_extract JSON is copied to evidence/ so every fact is re-openable.

Idempotent: re-ingesting the same collection updates rather than duplicates.

Usage:
  python3 ingest_webpivot.py --kb knowledge cases/<case>/raw/*.json
"""
import os
import re
import sys
import json
import hashlib
import argparse
import ipaddress
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from knowledge_base import KB  # noqa: E402
from noise_filters import is_managed_dns, is_parking_favicon, is_noise_email  # noqa: E402

# reuse the collector's checksum validator so bad wallets can't enter via a stale raw file either
try:
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))), "WebPivot", "tools"))
    from pivot_extract import valid_crypto_address as _valid_wallet  # noqa: E402
except Exception:
    def _valid_wallet(label, value):   # fail-open if collector not importable
        return True

# CDN/cloud classifier — a domain's Cloudflare/Fastly edge IP is NOT its operator host, so a
# `hosted_on` edge to it would be noise. Reused from WebPivot; fail-open (treat unknown as origin —
# --strong prevalence gating still drops any IP shared by too many domains).
try:
    from wp_analyze import classify_ip as _classify_ip  # noqa: E402
except Exception:
    def _classify_ip(ip):
        return {"ip": ip, "cdn": None, "provider": None, "kind": "unknown"}


def _is_ipaddr(s):
    """True only for a real IPv4/IPv6 literal — guards against pdns records whose A/AAAA rdata is a
    hostname (CNAME chains / mislabeled rrtype), which must never become an `ip:<domain>` node."""
    try:
        ipaddress.ip_address((s or "").strip())
        return True
    except ValueError:
        return False


def _ip_is_cdn(ip):
    try:
        return _classify_ip(ip).get("cdn") is True
    except Exception:
        return False


def _epoch_day(v):
    """A passive-DNS time_first/time_last → 'YYYY-MM-DD'. Accepts unix epoch (int/str) or ISO."""
    if v is None or v == "":
        return None
    try:
        return datetime.fromtimestamp(int(float(v)), timezone.utc).strftime("%Y-%m-%d")
    except (ValueError, TypeError, OSError):
        return str(v)[:10] or None

COLLECTOR = "webpivot/pivot_extract"

_IP_HOST_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?:[:_]\d+)?$")
# corporate suffixes → the registrant is an ORG, not a natural person (route to type 'org')
_ORG_SUFFIX = (" ltd", " ltd.", " llc", " inc", " inc.", " co.", " corp", " gmbh", " pty",
               " limited", " group", " s.r.o", " pte", " b.v", " co ltd", " company",
               " technologies", " technology", " systems", " media", " holdings", " sarl")
# WHOIS field-label / status junk mis-captured as a registrant name
_NAME_JUNK = ("registrant state", "registrant province", "registrant country", "registrant city",
              "registrant_", "state/province", "reactivation period", "pending delete",
              "redemption period", "pending renewal", "on behalf of", "domain buyer")


def _is_ip_host(host):
    return bool(_IP_HOST_RE.match((host or "").strip()))


def _name_kind(nm):
    """Classify a registrant name → 'org' | 'person' | None(junk)."""
    s = (nm or "").strip().lower()
    if not s or any(j in s for j in _NAME_JUNK):
        return None
    if any(suf in " " + s for suf in _ORG_SUFFIX):
        return "org"
    return "person"

# artifact class -> (relationship, confidence)  — encodes attribution weight
REL = {
    "google_analytics_ga4": ("uses_analytics", "high"),
    "google_analytics_ua":  ("uses_analytics", "high"),   # Universal Analytics (historical, owner-tied)
    "google_tag_manager":   ("uses_analytics", "high"),
    "adsense":              ("uses_adsense",   "high"),
    "facebook_pixel":       ("uses_pixel",     "high"),
    "yandex_metrica":       ("uses_analytics", "high"),
}
_PRIV = ("privacy", "redacted", "whoisguard", "data protected", "withheld",
         "not disclosed", "domains by proxy", "domainsbyproxy", "registration private",
         "private by design", "identity protect", "contact privacy", "perfect privacy")
_PROXY_DOM = ("porkbun.com", "godaddy.com", "namecheap.com", "domainsbyproxy.com",
              "withheldforprivacy.com", "privacyprotect.org", "contactprivacy.com")

# Generic registrant ROLE placeholders. Distinct from _PRIV, which matches privacy-SIGNALLING
# words ("privacy", "redacted", "withheld"). These strings contain no such word, so _PRIV misses
# them — yet they are boilerplate emitted by registrars in place of a registrant, shared across
# unrelated customers. Left unfiltered, `Domain Admin` becomes a high-confidence
# `registered_by -> person` edge and merges every domain whose registrar used that placeholder.
#
# Matched on the NORMALISED form (lowercased, punctuation stripped, whitespace collapsed) and
# EXACTLY, never as a substring — a substring rule would eat legitimate registrant orgs such as
# "Admin Solutions GmbH" or "Domain Manager Services Ltd". Exactness is the safety property here:
# over-filtering silently destroys real attribution, which is the costlier direction.
_ROLE_NAME_PLACEHOLDERS = frozenset({
    "domain admin", "domain admins", "domain administrator", "domain administrators",
    "domainadmin", "domain manager", "domain name administrator", "domain owner",
    "domain registrant", "registrant", "dns admin", "dns administrator",
    "admin", "administrator", "hostmaster", "postmaster", "webmaster",
    "statutory masking enabled", "non public data", "nonpublic data",
    "not available", "not applicable", "na", "n a", "none", "null", "unknown",
    "no name", "anonymous", "customer", "client", "owner", "registry",
})


def _norm_name(v):
    """Lowercase, drop punctuation, collapse whitespace — so 'Domain Admin.', 'DOMAIN  ADMIN'
    and 'domain-admin' all normalise to 'domain admin'."""
    s = (v or "").lower()
    s = "".join(c if (c.isalnum() or c.isspace()) else " " for c in s)
    return " ".join(s.split())


def _is_role_placeholder(v):
    """True if a WHOIS registrant NAME is a generic role/boilerplate placeholder rather than an
    identity. Such a name must never become a `registered_by` clustering edge."""
    return _norm_name(v) in _ROLE_NAME_PLACEHOLDERS


def _is_privacy(v):
    s = (v or "").strip().lower()
    if not s or s.startswith("http"):
        return True
    if any(m in s for m in _PRIV):
        return True
    if s.startswith(("abuse@", "hostmaster@", "noc@", "postmaster@")):
        return True
    if "@" in s and s.split("@", 1)[1] in _PROXY_DOM:
        return True
    if any(0x80 <= ord(c) <= 0x9f for c in s):  # mojibake
        return True
    return False


def _day(iso):
    return (iso or "")[:10] or datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _resolved_ip_edges(kb, host, lr, observed, ev):
    """Emit `domain host --hosted_on--> indicator ip:<ip>` for the domain's resolved IPs, so a
    domain graph-links to the IP box (and thus to its co-tenants). Carries the hosting time window
    when passive DNS supplies it. CDN/cloud edge IPs are dropped (not the operator's host). Merges
    live-DNS ('now') and CIRCL passive-DNS (historical, time-windowed) into one edge per IP.

    `lr` is the `domain` pivot's live_results: dns.ips (+ip_classification), pdns.records
    (rrtype/rdata/time_first/time_last), passivedns.ips."""
    today = (observed or "")[:10]
    ips = {}   # ip -> {first, last, via:set}

    def _note(ip, first, last, via):
        m = ips.setdefault(ip, {"first": None, "last": None, "via": set()})
        for f in (first,):
            if f and (m["first"] is None or f < m["first"]):
                m["first"] = f
        for l in (last,):
            if l and (m["last"] is None or l > m["last"]):
                m["last"] = l
        m["via"].add(via)

    # live A/AAAA records — classification already computed by enrich_live
    dns = lr.get("dns") or {}
    cls = {c.get("ip"): c for c in (dns.get("ip_classification") or [])}
    for ip in dns.get("ips") or []:
        ip = (ip or "").strip()
        if not _is_ipaddr(ip) or (cls.get(ip) or {}).get("cdn") is True:
            continue
        _note(ip, today, today, "live_dns")

    # CIRCL passive DNS — historical hosting with a real time window
    for rec in ((lr.get("pdns") or {}).get("records") or []):
        if rec.get("rrtype") not in ("A", "AAAA"):
            continue
        ip = (rec.get("rdata") or "").strip()
        if not _is_ipaddr(ip) or _ip_is_cdn(ip):   # A/AAAA rdata can still be a CNAME target — reject non-IPs
            continue
        _note(ip, _epoch_day(rec.get("time_first")) or today,
              _epoch_day(rec.get("time_last")) or today, "pdns")

    # HackerTarget passive DNS — origin IPs, no timing
    for ip in ((lr.get("passivedns") or {}).get("ips") or []):
        ip = (ip or "").strip()
        if not _is_ipaddr(ip) or _ip_is_cdn(ip):
            continue
        _note(ip, today, today, "passivedns")

    n = 0
    for ip, m in ips.items():
        attrs = {"first_seen": m["first"] or today, "last_seen": m["last"] or today,
                 "via": ",".join(sorted(m["via"]))}
        kb.add_edge("domain", host, "hosted_on", "indicator", f"ip:{ip}",
                    "webpivot", "webpivot/dns", observed, "medium", ev, attrs=attrs)
        n += 1
    return n


def _norm_domain(hd):
    """Normalize a co-tenant host to a bare registrable-ish domain: drop scheme/port/path/www."""
    hd = (hd or "").strip().lower()
    hd = re.sub(r"^[a-z]+://", "", hd).split("/")[0].split(":")[0]
    return hd[4:] if hd.startswith("www.") else hd


def _ingest_ip(kb, d, meta, ip, observed, day):
    """Ingest an IPPivot result (meta.kind=='ip'). The IP becomes an `indicator` node `ip:<ip>`;
    co-hosted domains get a `hosted_on` edge to it, so domains sharing an origin IP auto-cluster
    exactly like a shared favicon (union-find keys on domain→indicator edges). For a NOISE provider
    (shared CDN/cloud/hosting) co-tenancy is NOT ownership, so those are recorded as facts only —
    never clustering edges. ASN/org/ports/PTR/git-servers/provenance are attached as facts."""
    art = (d.get("artifacts") or {}).get("ip_intel") or {}
    ev = kb.save_evidence("webpivot-ip", ip, d, day)
    ind = f"ip:{ip}"
    kb.touch("indicator", ind, observed)
    n = 1

    ii = art.get("ipinfo") or {}
    for attr, val, conf in (("asn", ii.get("asn"), "high"), ("org", ii.get("org_name"), "high"),
                            ("ptr", art.get("ptr"), "medium"),
                            ("ports", ",".join(art.get("ports") or []), "medium"),
                            ("services", ", ".join(art.get("services") or []), "low")):
        if val:
            kb.add_fact("indicator", ind, attr, val, "webpivot", COLLECTOR, observed, conf, ev)
            n += 1
    if meta.get("provenance"):
        kb.add_fact("indicator", ind, "provenance", meta["provenance"][:400],
                    "webpivot", COLLECTOR, observed, "high", ev)
        n += 1
    # exposed operator git servers (case-specific, high attribution value)
    for label, g in (art.get("git_servers") or {}).items():
        detail = " ".join(x for x in (g.get("url"),
                          ("%s/%s" % (g.get("owner"), g.get("repo"))) if g.get("repo") else None,
                          ("fronted_by=%s" % g["fronted_by"]) if g.get("fronted_by") else None) if x)
        kb.add_fact("indicator", ind, f"git_server:{label}", detail,
                    "webpivot", COLLECTOR, observed, "high", ev)
        n += 1

    noise = bool(art.get("noise"))
    # co-hosted / historical co-tenant domains (FOFA reverse + urlscan history)
    cohosts, seen = [], set()
    for hd in (list(art.get("co_hosted_domains") or []) + list(art.get("urlscan_cotenants") or [])):
        nd = _norm_domain(hd)
        if nd and not _is_ip_host(nd) and nd not in seen:
            seen.add(nd)
            cohosts.append(nd)
    for nd in cohosts:
        if noise:
            # shared provider — co-tenancy is not ownership; keep as a fact, never a cluster edge
            kb.add_fact("indicator", ind, "co_tenant", nd, "webpivot", COLLECTOR, observed, "low", ev)
        else:
            # origin box — domains here are same-operator leads; cluster them on the ip: indicator
            kb.add_edge("domain", nd, "hosted_on", "indicator", ind,
                        "fofa/urlscan", "webpivot/ip", observed, "medium", ev)
        n += 1

    # self-hosted mail domain (managed providers already filtered out in build_ip_result)
    mail = art.get("mail") or {}
    if mail and mail.get("mx") and not mail.get("managed"):
        for md in mail.get("mail_domains") or []:
            nd = _norm_domain(md)
            if nd and not _is_ip_host(nd):
                kb.add_edge("domain", nd, "hosted_on", "indicator", ind,
                            "webpivot", COLLECTOR, observed, "medium", ev)
                n += 1
    return n


def ingest_file(kb, path):
    d = json.load(open(path, encoding="utf-8"))
    meta = d.get("meta") or {}
    host = meta.get("host")
    if not host:
        return 0
    # observed_at: file mtime as ISO (collections don't carry their own timestamp)
    observed = datetime.fromtimestamp(os.path.getmtime(path), timezone.utc).isoformat()
    day = _day(observed)
    # IPPivot result → IP-shaped ingest (co-hosted domains cluster on the ip: indicator)
    if meta.get("kind") == "ip" or _is_ip_host(host):
        return _ingest_ip(kb, d, meta, host, observed, day)
    art = d.get("artifacts") or {}
    ev = kb.save_evidence("webpivot", host, d, day)
    n = 0

    kb.touch("domain", host, observed)
    if art.get("title"):
        kb.add_fact("domain", host, "title", art["title"], "webpivot", COLLECTOR, observed, "high", ev)
        n += 1
    for tf in art.get("tech_fingerprint") or []:
        kb.add_fact("domain", host, "tech", tf, "webpivot", COLLECTOR, observed, "medium", ev)
        n += 1

    # --- trackers -> indicators ---
    for label, vals in (art.get("trackers") or {}).items():
        rel, conf = REL.get(label, ("uses_tracker", "medium"))
        for v in vals:
            kb.add_edge("domain", host, rel, "indicator", f"{label}:{v}",
                        "webpivot", COLLECTOR, observed, conf, ev)
            kb.add_fact("indicator", f"{label}:{v}", "kind", label, "webpivot", COLLECTOR, observed, conf, ev)
            n += 1
    # --- CSS / template indicators (same-kit) ---
    for theme in art.get("wp_themes") or []:
        kb.add_edge("domain", host, "uses_theme", "indicator", f"wp_theme:{theme}",
                    "webpivot", COLLECTOR, observed, "medium", ev)
        n += 1
    for h in art.get("inline_style_sha256") or []:
        kb.add_edge("domain", host, "same_inline_css", "indicator", f"css_hash:{h[:16]}",
                    "webpivot", COLLECTOR, observed, "medium", ev)
        n += 1
    if art.get("dom_skeleton_sha1"):
        kb.add_edge("domain", host, "same_template", "indicator",
                    f"dom_skeleton:{art['dom_skeleton_sha1'][:16]}",
                    "webpivot", COLLECTOR, observed, "medium", ev)
        n += 1
    # distinctive HTML comments (shared builder tell — boilerplate filtered)
    _BOILER = ("litespeed", "wordpress", "wp rocket", "yoast", "google tag manager",
               "wayback", "archived", "page optimized", "quic.cloud", "elementor",
               "cache", "w3tc", "autoptimize", "begin", "end", "if lt ie", "supported by")
    for c in art.get("html_comments") or []:
        cl = " ".join((c or "").split()).lower()
        if len(cl) < 14 or any(b in cl for b in _BOILER):
            continue
        ch = hashlib.sha1(cl.encode("utf-8", "ignore")).hexdigest()[:16]
        kb.add_edge("domain", host, "same_comment", "indicator", f"comment:{ch}",
                    "webpivot", COLLECTOR, observed, "medium", ev)
        n += 1

    # --- favicon ---
    fav = art.get("favicon") or {}
    if fav.get("shodan_mmh3") is not None:
        if is_parking_favicon(fav["shodan_mmh3"]):
            # parking/for-sale favicon — record as a fact, but never as a clustering hub
            kb.add_fact("domain", host, "parking_favicon", str(fav["shodan_mmh3"]),
                        "webpivot", COLLECTOR, observed, "low", ev)
            n += 1
        else:
            ind = f"favicon:{fav['shodan_mmh3']}"
            kb.add_edge("domain", host, "uses_favicon", "indicator", ind, "webpivot", COLLECTOR, observed, "high", ev)
            kb.add_fact("indicator", ind, "md5", fav.get("md5"), "webpivot", COLLECTOR, observed, "high", ev)
            n += 1
    # --- verification tokens (owner-tied) ---
    for label, tok in (art.get("verifications") or {}).items():
        ind = f"verification:{label}:{tok}"
        kb.add_edge("domain", host, "uses_verification", "indicator", ind, "webpivot", COLLECTOR, observed, "high", ev)
        n += 1
    # --- socials ---
    for net, handles in (art.get("socials") or {}).items():
        for h in handles:
            ind = f"social:{net}:{h.rstrip('/').split('/')[-1]}"
            kb.add_edge("domain", host, "uses_contact", "indicator", ind, "webpivot", COLLECTOR, observed, "medium", ev)
            n += 1

    # --- money trail: crypto wallets (attribution-grade — a reused wallet = the same payee) ---
    crypto = art.get("crypto") or {}
    for kind, vals in crypto.items():
        for v in (vals if isinstance(vals, list) else [vals]):
            if not v or not _valid_wallet(kind, v):   # checksum-reject md5/hash false-positives
                continue
            ind = f"wallet:{kind}:{v}"
            kb.add_edge("domain", host, "uses_wallet", "indicator", ind, "webpivot", COLLECTOR, observed, "high", ev)
            kb.add_fact("indicator", ind, "kind", f"wallet_{kind}", "webpivot", COLLECTOR, observed, "high", ev)
            n += 1
    # --- money trail: on-page contact emails (how the operator gets reached to close the fraud) ---
    _GENERIC_EMAIL = ("support@", "info@", "admin@", "contact@", "hello@", "sales@",
                      "noreply@", "no-reply@", "office@")
    for em in (art.get("emails") or []):
        em = (em or "").strip().lower()
        if not em or "@" not in em or _is_privacy(em):
            continue
        conf = "low" if em.startswith(_GENERIC_EMAIL) else "medium"
        kb.add_edge("domain", host, "shows_email", "email", em, "webpivot", COLLECTOR, observed, conf, ev)
        n += 1

    # --- SaaS / no-code operator tokens (GHL location, backend Sheet, automation webhooks) ---
    # attribution-grade: a private, owner-controlled account/automation id. Same token = same operator.
    _SAAS_IND = {"gohighlevel_location": "ghl_location", "google_sheet": "google_sheet",
                 "make_webhook": "webhook", "integromat_webhook": "webhook",
                 "zapier_webhook": "webhook", "apps_script": "webhook"}
    for label, vals in (art.get("saas_ids") or {}).items():
        if label == "trustedform":   # lead-gen tell, not an operator id
            for v in vals:
                kb.add_fact("domain", host, "tech", f"trustedform:{v}", "webpivot", COLLECTOR, observed, "low", ev)
                n += 1
            continue
        pref = _SAAS_IND.get(label)
        if not pref:
            continue
        for v in vals:
            ind = f"{pref}:{v}"
            kb.add_edge("domain", host, "uses_saas", "indicator", ind, "webpivot", COLLECTOR, observed, "high", ev)
            kb.add_fact("indicator", ind, "kind", label, "webpivot", COLLECTOR, observed, "high", ev)
            n += 1

    # --- WHOIS ---
    wh = art.get("whois") or {}
    if wh:
        for k in ("registrar", "created", "updated", "expires"):
            if wh.get(k) and not _is_privacy(wh[k]):
                kb.add_fact("domain", host, f"whois_{k}", wh[k], "whoisxml", "webpivot/whois_enrich", observed, "high", ev)
                n += 1
        emails = ([wh.get("registrant_email")] +
                  ((wh.get("history") or {}).get("registrant_emails") or []))
        for em in emails:
            if em and not _is_privacy(em) and not is_noise_email(em):
                kb.add_edge("domain", host, "registered_by", "email", em.lower(),
                            "whoisxml", "webpivot/whois_enrich", observed, "high", ev)
                n += 1
            elif em and is_noise_email(em):   # registrar/abuse role email — keep as fact only
                kb.add_fact("domain", host, "whois_role_email", em.lower(),
                            "whoisxml", "webpivot/whois_enrich", observed, "low", ev)
                n += 1
        names = ([wh.get("registrant_name") or wh.get("registrant_org")] +
                 ((wh.get("history") or {}).get("registrant_names") or []))
        for nm in names:
            if nm and not _is_privacy(nm) and not _is_role_placeholder(nm):
                kind = _name_kind(nm)          # org / person / None(junk label — skip)
                if not kind:
                    continue
                kb.add_edge("domain", host, "registered_by", kind, nm.strip(),
                            "whoisxml", "webpivot/whois_enrich", observed, "high", ev)
                n += 1
            elif nm and _is_role_placeholder(nm):   # generic role boilerplate — fact, never an edge
                kb.add_fact("domain", host, "whois_role_name", nm.strip(),
                            "whoisxml", "webpivot/whois_enrich", observed, "low", ev)
                n += 1
        for ns in wh.get("name_servers") or []:
            if is_managed_dns(ns):
                # managed/registrar/parking DNS (Cloudflare, NameSilo, GoDaddy…) — shared by
                # millions of unrelated domains. Record as a fact, never a clustering edge.
                kb.add_fact("domain", host, "nameserver", ns.lower(),
                            "whoisxml", "webpivot/whois_enrich", observed, "low", ev)
            else:
                kb.add_edge("domain", host, "uses_nameserver", "indicator", f"ns:{ns.lower()}",
                            "whoisxml", "webpivot/whois_enrich", observed, "low", ev)
            n += 1

    # --- externally-discovered siblings (FOFA / urlscan / reverse-WHOIS) ---
    for piv in d.get("pivots") or []:
        lr = piv.get("live_results") or {}
        kind = piv.get("kind", "")
        # map the pivot back to the indicator id used above
        ind = None
        if kind == "favicon_hash":
            ind = f"favicon:{piv['value']}"
        elif kind.startswith("tracker:"):
            ind = f"{kind.split(':',1)[1]}:{piv['value']}"
        elif kind.startswith("verification:"):
            ind = f"verification:{kind.split(':',1)[1]}:{piv['value']}"
        # FOFA / urlscan hits
        for engine, block in (("fofa", lr.get("fofa")), ("urlscan", lr.get("urlscan"))):
            if not block or block.get("error") or not ind:
                continue
            hits = [r.get("domain") or r.get("host") for r in block.get("results", [])] \
                if engine == "fofa" else block.get("domains", [])
            rel = ("uses_favicon" if kind == "favicon_hash"
                   else "uses_verification" if kind.startswith("verification:")
                   else "uses_analytics")
            for hd in filter(None, hits):
                if hd == host or _is_ip_host(hd):   # FOFA indexes IP:port — not a domain entity
                    continue
                kb.add_edge("domain", hd, rel, "indicator", ind, engine, f"webpivot/{engine}",
                            observed, "medium", ev)
                n += 1
        # reverse-WHOIS hits (share a registrant)
        if kind == "whois:registrant_email":
            for stk in ("reverse_whois_current", "reverse_whois_historic"):
                blk = lr.get(stk) or {}
                for hd in blk.get("domains", []) or []:
                    if hd and hd != host and not _is_ip_host(hd):
                        kb.add_edge("domain", hd, "registered_by", "email", piv["value"].lower(),
                                    "whoisxml", "webpivot/whois_enrich", observed, "medium", ev)
                        n += 1

    # --- resolved IPs: domain hosted_on ip:<ip> (+ hosting time window) — links domain ↔ IP box ---
    for piv in d.get("pivots") or []:
        if piv.get("kind") == "domain":
            lr = piv.get("live_results") or {}
            n += _resolved_ip_edges(kb, host, lr, observed, ev)
            # urlscan Pro structure-similarity → cluster re-skinned kits on a structure:<host> anchor
            sim = (lr.get("urlscan_similar") or {}).get("similar_domains") or []
            if sim:
                ind = f"structure:{host}"
                kb.add_edge("domain", host, "similar_structure", "indicator", ind,
                            "urlscan", "webpivot/urlscan", observed, "medium", ev)
                for sd in sim:
                    nd = _norm_domain(sd)
                    if nd and nd != host and not _is_ip_host(nd):
                        kb.add_edge("domain", nd, "similar_structure", "indicator", ind,
                                    "urlscan", "webpivot/urlscan", observed, "medium", ev)
                        n += 1
            break
    return n


def main():
    ap = argparse.ArgumentParser(description="Ingest WebPivot JSON into the knowledge base.")
    ap.add_argument("--kb", required=True, help="knowledge/ directory")
    ap.add_argument("inputs", nargs="+", help="pivot_extract JSON files")
    args = ap.parse_args()
    kb = KB(args.kb)
    total = 0
    for p in args.inputs:
        try:
            c = ingest_file(kb, p)
            total += c
            print(f"  [{c:3d} facts] {p}")
        except Exception as e:
            print(f"  [skip] {p}: {e}", file=sys.stderr)
    print(f"ingested {total} facts/edges from {len(args.inputs)} collection(s) -> {args.kb}")


if __name__ == "__main__":
    main()
