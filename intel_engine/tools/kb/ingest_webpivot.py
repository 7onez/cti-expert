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
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kb_refs  # noqa: E402 — reference DATA lives in references/*.json (RULE 3)
from knowledge_base import KB  # noqa: E402
from noise_filters import (is_managed_dns, is_parking_favicon, is_noise_email,  # noqa: E402
                           is_noise_indicator, is_noise_tracker, is_saturated_reverse,
                           is_noise_social_handle, is_bulk_registrant, is_noise_phone,
                           is_boilerplate_comment, DOM_SKELETON_MIN_TAGS)

# reuse the collector's checksum validator so bad wallets can't enter via a stale raw file either
try:
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))), "WebPivot", "tools"))
    from pivot_extract import valid_crypto_address as _valid_wallet  # noqa: E402
except Exception:
    def _valid_wallet(label, value):   # fail-open if collector not importable
        return True

# The document/image metadata base-rate filter, reused from the collector so BOTH paths agree on
# what is a tool and what is an operator. It must be re-applied here and not merely trusted from
# the pivot list, because ingest reads the raw `artifacts.docmeta` block directly: without it a PDF
# whose Producer is "Microsoft Word" would edge together every unrelated domain that ever hosted a
# Word-made document — the exact false-cluster class this repo's noise layer exists to prevent.
# Fails CLOSED (drop the value) rather than open: a missed edge costs a lead, a false edge costs
# an investigation.
try:
    from wp_docmeta import is_generic as _doc_generic  # noqa: E402
except Exception:
    def _doc_generic(key, value):
        print("[ingest] WARNING: wp_docmeta not importable — document/image metadata will NOT be "
              "ingested (cannot tell a tool string from an operator).", file=sys.stderr)
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

# ---------------------------------------------------------------- reference data (RULE 3)
# Every registrant-noise denylist below is DATA in references/registrant_noise.json — the SAME
# file clean_kb.py, hypothesize.py and ingest_report.py read. Before it existed these lists were
# pasted into each of those modules and drifted, so a proxy one module knew about kept slipping
# through another. Add a value there; never re-paste a list into a module.
_RN_FALLBACK = {
    "org_suffixes": (" ltd", " llc", " inc", " corp", " gmbh", " limited", " group", " company"),
    "name_junk": ("registrant state", "registrant country", "reactivation period",
                  "pending delete", "redemption period"),
    "role_name_placeholders": ("domain admin", "domain administrator", "registrant", "admin",
                               "administrator", "hostmaster", "not available", "unknown"),
    "privacy_markers": ("privacy", "redacted", "whoisguard", "data protected", "withheld",
                        "not disclosed", "domains by proxy"),
    "proxy_email_domains": ("godaddy.com", "namecheap.com", "domainsbyproxy.com",
                            "withheldforprivacy.com", "privacyprotect.org"),
}
_RN = kb_refs.load_ref(kb_refs.ref_path(__file__, "registrant_noise.json"), _RN_FALLBACK)

# corporate suffixes → the registrant is an ORG, not a natural person (route to type 'org')
_ORG_SUFFIX = tuple(_RN["org_suffixes"])
# WHOIS field-label / status junk mis-captured as a registrant name
_NAME_JUNK = tuple(_RN["name_junk"])


def _is_ip_host(host):
    return bool(_IP_HOST_RE.match((host or "").strip()))


def _host_of(url):
    """Bare lowercase hostname of a URL (asset-layer backends arrive as full URLs).
    Tolerates protocol-relative '//host/path' and a bare host with no scheme."""
    u = (url or "").strip()
    if not u:
        return ""
    if u.startswith("//"):
        u = "https:" + u
    elif "://" not in u:
        u = "https://" + u
    try:
        netloc = urlparse(u).netloc
    except Exception:
        return ""
    host = netloc.split("@")[-1].split(":")[0].strip().lower().rstrip(".")
    return host[4:] if host.startswith("www.") else host


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
# DATA: references/registrant_noise.json -> privacy_markers / proxy_email_domains
_PRIV = tuple(_RN["privacy_markers"])
_PROXY_DOM = tuple(_RN["proxy_email_domains"])

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
# DATA: references/registrant_noise.json -> role_name_placeholders
_ROLE_NAME_PLACEHOLDERS = frozenset(_RN["role_name_placeholders"])


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


def _ingest_paths(kb, d, meta, host, observed, ev):
    """The URL PATH as a clustering indicator — `path_kit:<kit>`.

    Standard clustering hangs off the hostname. An operator who has noticed that buys a pool of
    disposable hosts and selects which branded template a victim sees by the URL PATH instead:
    `host-a/<kit>/`, `host-b/<kit>/`, `host-c/<kit>/`. Nothing at host level connects those, so
    without this edge they ingest as three unrelated one-domain cases. With it they land in one
    cluster keyed on the kit directory — the one string the operator cannot randomise without
    rebuilding their own routing.

    Weight is deliberately MEDIUM and the relation is `serves_kit`, not `same_operator`: a shared
    kit directory is SAME-KIT evidence, exactly like a shared white-label platform artifact. Two
    resellers of one kit have the same directory names. It is a strong collection lead; the
    operator claim needs a second, independent artifact class.

    A generic path emits nothing — `wp_paths.kit_segment()` applies the base-rate denylist, so
    `/login` and `/assets` never become an edge. That guard is the whole reason this is safe."""
    kit = (meta.get("kit") or "").strip().lower()
    if not kit:
        return 0
    ind = f"path_kit:{kit}"
    kb.touch("indicator", ind, observed)
    kb.add_fact("indicator", ind, "kind", "url_path_kit", "webpivot", COLLECTOR, observed,
                "high", ev)
    kb.touch("domain", host, observed)
    kb.add_edge("domain", host, "serves_kit", "indicator", ind, "webpivot", COLLECTOR,
                observed, "medium", ev)
    n = 1
    # The full path is a FACT on the domain, not an edge: two hosts serving the same kit at
    # different depths are still the same kit, and clustering on the deep path would split them.
    if meta.get("url_path"):
        kb.add_fact("domain", host, "url_path", meta["url_path"], "webpivot", COLLECTOR,
                    observed, "high", ev)
    if meta.get("path_template"):
        kb.add_fact("domain", host, "path_template", meta["path_template"], "webpivot",
                    COLLECTOR, observed, "medium", ev)
    # Which market the template was localised for — target-selection evidence, never a cluster key
    # (every kit in a country shares its locale segment).
    if meta.get("locale"):
        kb.add_fact("domain", host, "path_locale", meta["locale"], "webpivot", COLLECTOR,
                    observed, "low", ev)
    return n


def _ingest_ads(kb, d, meta, host, observed, ev):
    """The ADVERTISING layer as clustering indicators — `ads_advertiser:<AR…>`, `ads_campaign:<id>`.

    An advertiser id is the only artifact in this collector that identifies a PAYER. To run Google
    ads the operator passed identity verification and put a card on file, so `ads_advertiser:` is a
    verified, billed account — and unlike a favicon or a template, it is not something a second
    operator can copy off the first. Every domain that account advertised gets an edge to the same
    indicator, which is what makes them cluster.

    Two guards, both of which fail toward LOSING a link rather than inventing one:

      - `agency_shaped` (from `clustering_policy.agency_domain_threshold`) marks an advertiser whose
        creatives point at many unrelated domains. That is a media buyer or affiliate network buying
        traffic FOR others, and fusing its clients into one operator would be the same mistake as
        clustering on a shared white-label platform. Those co-advertised domains are recorded as
        FACTS on the indicator, never as edges, so they stay visible as leads without joining a
        cluster.
      - the campaign OBJECT ids (`campaignid`/`adgroupid`/`creative`) are short integers, so they get
        the medium weight their base rate deserves.

    Cloaking is deliberately NOT an indicator. It is a property of one page — this host serves paid
    clicks a different page than everyone else — so it lands as a high-confidence FACT on the domain.
    It is evidence of intent, not of identity, and an indicator would cluster every cloaking site on
    the internet into one operator."""
    n = 0
    adv_block = d.get("advertising") or {}
    for adv in adv_block.get("advertisers") or []:
        aid = (adv.get("advertiser_id") or "").strip()
        if not aid:
            continue
        agency = bool(adv.get("agency_shaped"))
        ind = f"ads_advertiser:{aid}"
        kb.touch("indicator", ind, observed)
        kb.add_fact("indicator", ind, "kind", "google_ads_advertiser", "webpivot", COLLECTOR,
                    observed, "high", ev)
        if adv.get("advertiser"):
            # The verified legal name — the string that takes this out of infrastructure and into a
            # corporate registry. Kept on the indicator so every domain in the cluster inherits it.
            kb.add_fact("indicator", ind, "funded_by", adv["advertiser"], "webpivot", COLLECTOR,
                        observed, "high", ev)
        for k in ("first_shown", "last_shown"):
            if adv.get(k):
                kb.add_fact("indicator", ind, k, adv[k], "webpivot", COLLECTOR, observed,
                            "medium", ev)
        kb.add_edge("domain", host, "advertised_by", "indicator", ind, "webpivot", COLLECTOR,
                    observed, "medium" if agency else "high", ev)
        n += 1
        if agency:
            kb.add_fact("indicator", ind, "agency_shaped",
                        adv.get("agency_note") or "many unrelated target domains", "webpivot",
                        COLLECTOR, observed, "high", ev)
        for peer in adv.get("target_domains") or []:
            peer = _norm_domain(peer)
            if not peer or peer == host or _is_ip_host(peer):
                continue
            if agency:
                kb.add_fact("indicator", ind, "co_advertised", peer, "webpivot", COLLECTOR,
                            observed, "low", ev)
            else:
                kb.touch("domain", peer, observed)
                kb.add_edge("domain", peer, "advertised_by", "indicator", ind, "webpivot",
                            COLLECTOR, observed, "medium", ev)
            n += 1

    # Campaign object ids come through as pivots (`ads:campaignid` and friends) rather than as a
    # block, because they are read off the URL and exist even when no key resolved an advertiser.
    for piv in d.get("pivots") or []:
        # str(): a pivot value is not always a string (favicon_hash is an int), and this loop sees
        # every pivot before it filters down to the `ads:` ones.
        kind, val = (piv.get("kind") or ""), str(piv.get("value") or "").strip()
        if not val or not kind.startswith("ads:") or kind in ("ads:paid_arrival", "ads:cloaking",
                                                              "ads:advertiser", "ads:advertiser_id",
                                                              "ads:co_advertised_domain"):
            continue
        ind = f"ads_campaign:{kind.split(':', 1)[1]}={val}"
        kb.touch("indicator", ind, observed)
        kb.add_fact("indicator", ind, "kind", "google_ads_campaign_object", "webpivot", COLLECTOR,
                    observed, "medium", ev)
        kb.add_edge("domain", host, "ran_campaign", "indicator", ind, "webpivot", COLLECTOR,
                    observed, "medium", ev)
        n += 1

    cloak = (meta.get("cloaking") or {})
    if cloak.get("verdict") == "divergent":
        kb.add_fact("domain", host, "cloaking", "click_keyed: serves paid-click traffic different "
                    "content than plain visitors", "webpivot", COLLECTOR, observed, "high", ev)
        if cloak.get("unlock_url"):
            kb.add_fact("domain", host, "cloaking_unlock_url", cloak["unlock_url"], "webpivot",
                        COLLECTOR, observed, "high", ev)
        n += 1
    elif cloak.get("verdict") in ("dynamic", "identical"):
        # Recorded so a later reader knows the probe RAN and what it found — an absent fact and a
        # negative result must not look the same.
        kb.add_fact("domain", host, "cloaking_probe", cloak["verdict"], "webpivot", COLLECTOR,
                    observed, "medium", ev)
        n += 1
    return n


def _ingest_impersonation(kb, d, meta, host, observed, day):
    """Ingest an ImpersonationHunt result (meta.kind=='impersonation'). The seed's brand keyword
    becomes an `indicator brand:<label>`; the seed and every CONFIRMED lookalike get an edge to it,
    so a brand and its typosquats/TLD-swaps cluster together (union-find keys on domain→indicator
    edges, exactly like a shared favicon). Resolved lookalikes also get a `hosted_on` edge to their
    IP indicator, reusing the same IP-clustering IPPivot uses. The unregistered watchlist is NOT
    ingested — non-existent NRDs aren't infrastructure yet, so they'd only add noise nodes."""
    art = (d.get("artifacts") or {}).get("impersonation") or {}
    label = art.get("brand_label")
    if not label:
        return 0
    ev = kb.save_evidence("webpivot", host, d, day)
    ind = f"brand:{label}"
    kb.touch("indicator", ind, observed)
    kb.add_fact("indicator", ind, "kind", "brand_keyword", "webpivot", COLLECTOR, observed, "high", ev)
    # the seed anchors the brand indicator
    kb.touch("domain", host, observed)
    kb.add_edge("domain", host, "is_brand", "indicator", ind, "webpivot", COLLECTOR, observed, "high", ev)
    n = 1
    for p in d.get("pivots") or []:
        if p.get("kind") != "impersonation:candidate":
            continue
        look = _norm_domain(p.get("value"))
        if not look or _is_ip_host(look):
            continue
        kb.touch("domain", look, observed)
        kb.add_edge("domain", look, "impersonates", "indicator", ind,
                    "webpivot", COLLECTOR, observed, p.get("confidence", "low"), ev)
        n += 1
        for ip in ((p.get("live_results") or {}).get("resolves") or []):
            kb.add_edge("domain", look, "hosted_on", "indicator", f"ip:{ip}",
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
    # URL-path kit FIRST: on a path-routed estate this is the only edge that survives the host
    # rotation, so it must land even if the rest of the page yielded nothing clusterable.
    n += _ingest_paths(kb, d, meta, host, observed, ev)
    # The advertising layer next, for the same reason: an advertiser account is the one artifact
    # here that identifies a PAYER rather than a configuration, and it survives the re-skin that
    # invalidates the favicon and DOM facts collected below.
    n += _ingest_ads(kb, d, meta, host, observed, ev)
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
            if is_noise_tracker(v):
                # the hosting platform's own ID on its parking/default page — record it as a fact
                # about this domain, but never as a clustering hub (mirrors parking_favicon)
                kb.add_fact("domain", host, "platform_tracker", str(v),
                            "webpivot", COLLECTOR, observed, "low", ev)
                n += 1
                continue
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
    # distinctive HTML comments (shared builder tell — boilerplate filtered).
    # DATA: references/noise_filters.json -> comment_boilerplate / comment_min_length
    for c in art.get("html_comments") or []:
        cl = " ".join((c or "").split()).lower()
        if is_boilerplate_comment(cl):
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
            leaf = h.rstrip("/").split("/")[-1]
            if is_noise_social_handle(leaf):
                continue        # a share icon or a bundle's `{u}` placeholder is nobody's account
            ind = f"social:{net}:{leaf}"
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

    # --- ASSET LAYER (wp_assets): JS bundles, source maps, build config, policy files ---
    # These are the artifacts that survive a re-skin. The front end is rebuilt per brand; the
    # backend host, the build-time tenant token, the developer's machine and the operator's
    # monetization account behind it are not. A shared-platform backend is filtered by the one
    # noise policy (is_noise_indicator) so a white-label BaaS never becomes a same-operator edge.
    assets = art.get("assets") or {}
    _api = assets.get("api") or {}

    for base in (_api.get("api_bases") or [])[:10]:
        bh = _host_of(base)
        if not bh or _is_ip_host(bh):
            continue
        ind = f"api_endpoint:{bh}"
        if is_noise_indicator(ind):
            kb.add_fact("domain", host, "backend_platform", bh,
                        "webpivot", COLLECTOR, observed, "low", ev)
            n += 1
            continue
        kb.add_edge("domain", host, "uses_backend", "indicator", ind,
                    "webpivot", COLLECTOR, observed, "high", ev)
        kb.add_fact("indicator", ind, "kind", "api_endpoint", "webpivot", COLLECTOR,
                    observed, "high", ev)
        n += 1

    for ws in (_api.get("websockets") or [])[:6]:
        wh_host = _host_of(ws)
        if not wh_host or _is_ip_host(wh_host):
            continue
        ind = f"websocket:{wh_host}"
        if is_noise_indicator(ind):
            continue
        kb.add_edge("domain", host, "uses_backend", "indicator", ind,
                    "webpivot", COLLECTOR, observed, "medium", ev)
        kb.add_fact("indicator", ind, "kind", "websocket", "webpivot", COLLECTOR,
                    observed, "medium", ev)
        n += 1

    # Build-time tenant/brand tokens. Clustering keys on KEY *and* value: the same KEY with a
    # DIFFERENT value means the same white-label PLATFORM (a same-kit link), not one operator.
    _BRANDY = ("BRAND", "TENANT", "SITE", "NAME", "PROJECT", "CLIENT", "MERCHANT",
               "PLATFORM", "COMPANY", "AGENT", "CHANNEL")
    for key, vals in list((_api.get("build_env") or {}).items())[:20]:
        if not any(b in key.upper() for b in _BRANDY):
            continue
        for v in vals[:3]:
            ind = f"build_tenant:{key}={v}"
            kb.add_edge("domain", host, "same_build_tenant", "indicator", ind,
                        "webpivot", COLLECTOR, observed, "high", ev)
            kb.add_fact("indicator", ind, "kind", "build_env", "webpivot", COLLECTOR,
                        observed, "high", ev)
            n += 1

    # A compiled bundle digest — same build artifact deployed twice. Same KIT; only an operator
    # link once corroborated, so it lands at medium like the other template/DOM hashes.
    for f in (assets.get("collected") or [])[:8]:
        if f.get("sha256"):
            ind = f"js_bundle:{f['sha256'][:32]}"
            kb.add_edge("domain", host, "same_bundle", "indicator", ind,
                        "webpivot", COLLECTOR, observed, "medium", ev)
            n += 1

    # --- DOCUMENT / IMAGE METADATA (artifacts.docmeta) -------------------------------------
    # What is embedded in the files the site HOSTS. wp_docmeta already dropped the generic
    # values (Word / Photoshop / "Windows User"), so anything reaching here is non-generic —
    # but the EDGE STRENGTH still differs by what the value actually identifies:
    #   author / copyright / GPS / XMP DocumentID  -> a PERSON or one specific source file (high)
    #   producer / editing software / camera / file hash -> the SHOP or the KIT (medium), which
    #   only becomes same-operator once an owner-tied artifact corroborates it.
    for f in (art.get("docmeta") or {}).get("files", [])[:12]:
        fm = f.get("meta") or {}
        for key, prefix, rel, conf in (
                ("author", "doc_author", "authored_by", "high"),
                ("artist", "doc_author", "authored_by", "high"),
                ("xp_author", "doc_author", "authored_by", "high"),
                ("last_modified_by", "doc_author", "authored_by", "high"),
                ("company", "doc_company", "names_company", "high"),
                ("manager", "doc_company", "names_company", "high"),
                ("copyright", "doc_copyright", "claims_copyright", "high"),
                ("xmp_document_id", "doc_xmp_docid", "same_source_document", "high"),
                ("gps", "doc_gps", "photographed_at", "high"),
                ("producer", "doc_producer", "same_document_shop", "medium"),
                ("creator_tool", "doc_producer", "same_document_shop", "medium"),
                ("software", "doc_software", "same_editor", "medium")):
            val = str(fm.get(key) or "").strip()
            if not val or len(val) < 3 or _doc_generic(key, val):
                continue
            ind = f"{prefix}:{val.lower()[:120]}"
            kb.add_edge("domain", host, rel, "indicator", ind,
                        "webpivot", COLLECTOR, observed, conf, ev)
            kb.add_fact("indicator", ind, "kind", prefix, "webpivot", COLLECTOR,
                        observed, conf, ev)
            n += 1
        cam = " ".join(str(fm.get(k) or "").strip()
                       for k in ("camera_make", "camera_model")).strip()
        if len(cam) > 3:
            ind = f"doc_camera:{cam.lower()[:80]}"
            kb.add_edge("domain", host, "shot_with", "indicator", ind,
                        "webpivot", COLLECTOR, observed, "medium", ev)
            kb.add_fact("indicator", ind, "kind", "doc_camera", "webpivot", COLLECTOR,
                        observed, "medium", ev)
            n += 1
        # Only a SAME-SITE file: a third-party image the page hot-links is the other site's
        # asset, and hashing it would cluster on someone else's stock photo.
        if f.get("sha256") and f.get("same_site"):
            ind = f"media:{f['sha256'][:32]}"
            kb.add_edge("domain", host, "serves_file", "indicator", ind,
                        "webpivot", COLLECTOR, observed, "medium", ev)
            n += 1

    for sm in (assets.get("source_maps") or [])[:4]:
        for user in (sm.get("usernames") or [])[:4]:
            ind = f"dev_user:{user.lower()}"
            kb.add_edge("domain", host, "built_by", "indicator", ind,
                        "webpivot", COLLECTOR, observed, "high", ev)
            kb.add_fact("indicator", ind, "kind", "dev_username", "webpivot", COLLECTOR,
                        observed, "high", ev)
            n += 1
        for root in (sm.get("project_roots") or [])[:5]:
            ind = f"dev_project:{root.lower()}"
            kb.add_edge("domain", host, "same_codebase", "indicator", ind,
                        "webpivot", COLLECTOR, observed, "high", ev)
            kb.add_fact("indicator", ind, "kind", "dev_project", "webpivot", COLLECTOR,
                        observed, "high", ev)
            n += 1

    # SPA route inventory. The signature is a same-KIT edge (medium, like the DOM/template
    # hashes): an identical compiled routing table survives a cosmetic re-skin, but a shared
    # white-label platform gives every tenant the same routes — so it clusters the KIT, and
    # only an owner-tied artifact promotes that to same-OPERATOR.
    _routes = assets.get("routes") or {}
    if _routes.get("signature"):
        ind = f"spa_routes:{_routes['signature'][:32]}"
        kb.add_edge("domain", host, "same_route_table", "indicator", ind,
                    "webpivot", COLLECTOR, observed, "medium", ev)
        kb.add_fact("indicator", ind, "kind", "spa_route_signature", "webpivot", COLLECTOR,
                    observed, "medium", ev)
        kb.add_fact("domain", host, "spa_router", str(_routes.get("router") or "unknown"),
                    "webpivot", COLLECTOR, observed, "low", ev)
        kb.add_fact("domain", host, "spa_route_count", str(_routes.get("count") or 0),
                    "webpivot", COLLECTOR, observed, "low", ev)
        n += 3
    # Admin/funnel routes are recorded as FACTS about this domain, never as clustering edges:
    # '/admin' is universal and would false-cluster the entire internet.
    for _r in (_routes.get("admin_routes") or [])[:12]:
        kb.add_fact("domain", host, "admin_route", _r, "webpivot", COLLECTOR, observed, "low", ev)
        n += 1
    for _r in (_routes.get("funnel_routes") or [])[:12]:
        kb.add_fact("domain", host, "funnel_route", _r, "webpivot", COLLECTOR, observed, "low", ev)
        n += 1

    # ads.txt / app-ads.txt publisher accounts — owner-registered monetization ids. A stranger
    # cannot declare your publisher id on their own domain, so this is Tier-A like a GSC token.
    _wk = assets.get("well_known") or {}
    for _which in ("ads_txt", "app_ads_txt"):
        for pub in ((_wk.get(_which) or {}).get("publishers") or [])[:15]:
            pid = pub.get("publisher_id")
            if not pid:
                continue
            ind = f"adstxt_pub:{pub.get('exchange', '')}:{pid}"
            kb.add_edge("domain", host, "uses_publisher_account", "indicator", ind,
                        "webpivot", COLLECTOR, observed, "high", ev)
            kb.add_fact("indicator", ind, "kind", "adstxt_publisher", "webpivot", COLLECTOR,
                        observed, "high", ev)
            n += 1

    _aasa = _wk.get("apple_app_site_association") or {}
    for team in (_aasa.get("team_ids") or [])[:5]:
        ind = f"apple_team:{team}"
        kb.add_edge("domain", host, "signed_by", "indicator", ind,
                    "webpivot", COLLECTOR, observed, "high", ev)
        kb.add_fact("indicator", ind, "kind", "apple_team_id", "webpivot", COLLECTOR,
                    observed, "high", ev)
        n += 1
    for bid in (_aasa.get("bundle_ids") or [])[:6]:
        ind = f"ios_bundle:{bid.lower()}"
        kb.add_edge("domain", host, "ships_app", "indicator", ind,
                    "webpivot", COLLECTOR, observed, "high", ev)
        kb.add_fact("indicator", ind, "kind", "ios_bundle_id", "webpivot", COLLECTOR,
                    observed, "high", ev)
        n += 1

    for contact in ((_wk.get("security_txt") or {}).get("contacts") or [])[:4]:
        if "@" in contact and not is_noise_email(contact):
            kb.add_edge("domain", host, "shows_email", "email", contact.lower(),
                        "webpivot", COLLECTOR, observed, "medium", ev)
            n += 1

    # --- WHOIS ---
    wh = art.get("whois") or {}
    if wh:
        for k in ("registrar", "created", "updated", "expires", "registrant_country"):
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
        # Registrant PHONE — a strong correlatable selector (like email), so it must be a
        # queryable KB entity, not just a per-domain fact. Digits-only normalisation matches the
        # orchestrator's reverse-WHOIS key. Gated by is_noise_phone: a privacy/proxy provider
        # publishes ONE phone across every domain it fronts, so an unfiltered edge would merge
        # thousands of unrelated domains (see noise_filters.json §registrant-phone).
        phones = ([wh.get("registrant_phone")] +
                  ((wh.get("history") or {}).get("registrant_phones") or []))
        _seen_ph = set()
        for ph in phones:
            if not ph:
                continue
            digits = "".join(c for c in str(ph) if c.isdigit())
            if len(digits) < 7 or digits in _seen_ph:
                continue
            _seen_ph.add(digits)
            if is_noise_phone(ph, wh.get("registrant_email"), wh.get("registrant_org")):
                kb.add_fact("domain", host, "whois_role_phone", digits,
                            "whoisxml", "webpivot/whois_enrich", observed, "low", ev)
            else:
                kb.add_edge("domain", host, "registered_by", "phone", digits,
                            "whoisxml", "webpivot/whois_enrich", observed, "high", ev)
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
        # The noise checks must be repeated HERE, not only at the seed's own artifact above: this
        # loop turns a reverse-search result set into one edge per hit, so a platform artifact
        # (a parking favicon, a host's own analytics ID) lands thousands of unrelated domains on a
        # single indicator and makes it the largest cluster in the KB.
        ind = None
        if kind == "favicon_hash":
            if is_parking_favicon(piv["value"]):
                continue
            ind = f"favicon:{piv['value']}"
        elif kind.startswith("tracker:"):
            if is_noise_tracker(piv["value"]):
                continue
            ind = f"{kind.split(':',1)[1]}:{piv['value']}"
        elif kind.startswith("verification:"):
            ind = f"verification:{kind.split(':',1)[1]}:{piv['value']}"
        # FOFA / urlscan hits
        for engine, block in (("fofa", lr.get("fofa")), ("urlscan", lr.get("urlscan"))):
            if not block or block.get("error") or not ind:
                continue
            # BASE RATE: an artifact this widely carried is shared infrastructure, and fanning its
            # hits out into edges is what makes a hosted platform's default favicon the largest
            # "cluster" in the KB. The seed's own artifact is still recorded above; only the
            # reverse-search fan-out is suppressed. Catches values no denylist has enumerated.
            if is_saturated_reverse(block.get("total")):
                kb.add_fact("domain", host, "saturated_indicator",
                            f"{ind} ({engine}: {block.get('total')} hits)",
                            engine, f"webpivot/{engine}", observed, "low", ev)
                n += 1
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
        # The collector already refuses to emit a privacy-proxied registrant, but this ingest is
        # also fed by older raw files and by other collectors, and one registrar role mailbox
        # reversed here writes a `registered_by` edge per hit — hundreds of unrelated domains on
        # a shared abuse address. Re-check here, and apply the same base-rate cap as above.
        if kind == "whois:registrant_email" and not is_noise_email(piv.get("value") or ""):
            for stk in ("reverse_whois_current", "reverse_whois_historic"):
                blk = lr.get(stk) or {}
                # A registrant CONTACT gets the tighter bulk-registrant bound, not the artifact
                # cap: it is a much weaker hub, and this is the same number ingest_reverse_whois
                # enforces — they used to disagree (200 vs 500) and a reseller fell between them.
                _cnt = blk.get("count") or blk.get("total")
                if is_bulk_registrant(_cnt):
                    kb.add_fact("domain", host, "bulk_registrant",
                                f"registrant {piv.get('value')} ({stk}: {_cnt} domains) "
                                f"— shared registration service, not an owner",
                                "whoisxml", "webpivot/whois_enrich", observed, "low", ev)
                    n += 1
                    continue
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
