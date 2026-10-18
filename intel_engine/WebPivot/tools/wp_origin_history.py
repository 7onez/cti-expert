#!/usr/bin/env python3
"""wp_origin_history — every address a host has EVER resolved to: merged, classified, dated, ranked.

WHY
---
A host fronted by a CDN today was usually served straight from the operator's own box before it
was fronted (or still is, on a forgotten subdomain). Seven different collectors already record
pieces of that history on the domain pivot — CIRCL/COF passive DNS, HackerTarget, SecurityTrails
history, Validin, urlscan's hostname index, Webamon's servers index, passive-SSL cert->IP — plus the
keyless urlscan scan list. Each wrote its own shape and nothing joined them, classified them, or
chased them: every IP follow-up ran on the first LIVE non-CDN address only, so a CDN-fronted host
got no IP pivot at all.

This module is the single join. `build()` folds all of them into one per-IP record
  {ip, status, provider, why, sources[], first_seen, last_seen, live, asn, org, names[]}
where `status` is
  origin     a plausible operator box — the loop/harness collect it as an IP seed (IPPivot)
  ambiguous  a DDoS-protection network that also rents servers (DDoS-Guard, StackPath) — collected
             like an origin, but its co-tenants are always held as leads and it never clusters
  cdn        a shared CDN / WAF / DDoS-scrubbing edge (CIDR index, or the ASN/org the source named)
  parking    a parking / aftermarket farm
  bogon      non-routable (127.0.0.1 parking answers, RFC1918 leaks)
  undetermined  CDN range cache unavailable and no ASN/org verdict — never collected
  invalid    not an address
and `era()` dates an origin against the host's registration and today:
  current         the host resolves there now
  recent          seen within sweep_policy.recent_tenancy_days
  historical      older than that
  undated         no source gave a date (HackerTarget, passive-SSL)
  previous_owner  last seen BEFORE the current registration — someone else's era, never collected

ATTRIBUTION RAILS (SKILL.md RULE 5)
-----------------------------------
An origin IP is collected so its own evidence (ASN, abuse contact, ports/banners, PTR, certificates,
self-hosted mail) is read; its CO-TENANTS stay neighbour-rung and pass the shared-hosting guard.
A `historical`/`undated` origin's current co-tenants may have arrived after our host left, so
`origin_context()` marks it stale and the frontier/ingest hold those co-tenants back as leads.

Stdlib only; reads nothing from the network. Policy lives in references/origin_history.json.
"""
from __future__ import annotations

import datetime
import functools
import glob
import ipaddress
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
from wp_refs import ref_path, load_ref  # noqa: E402

# Conservative minimum (RULE 3): a broken data file narrows the sweep and the edge lists — it never
# widens what is collected.
_ORIGIN_FALLBACK = {
    "edge_asns": {"AS13335": "cloudflare", "AS54113": "fastly", "AS20940": "akamai"},
    "edge_org_markers": ["cloudflare", "fastly"],
    "parking_markers": ["sedo"],
    "ambiguous_asns": {"AS57724": "ddos_guard"},
    "ambiguous_org_markers": ["ddos-guard"],
    "sweep_policy": {"max_ips_per_host": 3, "max_ip_seeds_per_round": 4, "recent_tenancy_days": 90,
                     "vps_auto_max_cotenants": 5},
    # ad-edge fallback: the three busiest regions only — a broken file still catches the obvious pool
    "ad_edge": {"provider": "aws_ad_edge", "asns": ["AS16509"], "min_ips": 6, "min_regions": 3,
                "window_days": 30,
                "region_cidrs": {"us-east-1": ["3.80.0.0/12"], "us-west-2": ["34.208.0.0/12"],
                                 "eu-west-1": ["34.240.0.0/13"]}},
    # no-owner verdict fallback: edge/parking/bogon only — every other class goes to the LLM
    "no_owner_verdict": {"class_confidence": {"cdn": "high", "parking": "high", "bogon": "high"},
                         "provider_host_suffixes": ["amazonaws.com", "cloudfront.net"],
                         "benign_ip_pivot_kinds": ["ip:information", "ip:asn"],
                         "owner_pivot_prefixes": ["tracker:", "whois:registrant_email",
                                                  "whois:registrant_phone", "tls_cert:fingerprint",
                                                  "token", "crypto", "wallet", "ip:mx", "ip:misconfig"]},
}
_REF = load_ref(ref_path(__file__, "origin_history.json"), _ORIGIN_FALLBACK)
EDGE_ASNS = {str(k).upper(): str(v) for k, v in dict(_REF["edge_asns"]).items()}
EDGE_ORG_MARKERS = tuple(str(m).lower() for m in _REF["edge_org_markers"])
PARKING_MARKERS = tuple(str(m).lower() for m in _REF["parking_markers"])
AMBIGUOUS_ASNS = {str(k).upper(): str(v) for k, v in dict(_REF["ambiguous_asns"]).items()}
AMBIGUOUS_ORG_MARKERS = tuple(str(m).lower() for m in _REF["ambiguous_org_markers"])
SWEEP_POLICY = dict(_REF["sweep_policy"])
MAX_IPS_PER_HOST = int(SWEEP_POLICY.get("max_ips_per_host", 3))
MAX_IP_SEEDS_PER_ROUND = int(SWEEP_POLICY.get("max_ip_seeds_per_round", 4))
RECENT_TENANCY_DAYS = int(SWEEP_POLICY.get("recent_tenancy_days", 90))
VPS_AUTO_MAX_COTENANTS = int(SWEEP_POLICY.get("vps_auto_max_cotenants", 5))
AD_EDGE = dict(_REF["ad_edge"])
AD_EDGE_PROVIDER = str(AD_EDGE.get("provider") or "aws_ad_edge")
AD_EDGE_ASNS = tuple(str(a).upper() for a in AD_EDGE.get("asns") or ())
AD_EDGE_MIN_IPS = int(AD_EDGE.get("min_ips", 6))
AD_EDGE_MIN_REGIONS = int(AD_EDGE.get("min_regions", 3))
AD_EDGE_WINDOW_DAYS = int(AD_EDGE.get("window_days", 30))
AD_EDGE_REGION_CIDRS = {str(r): [ipaddress.ip_network(str(c), strict=False) for c in cidrs or ()]
                        for r, cidrs in dict(AD_EDGE.get("region_cidrs") or {}).items()}
NO_OWNER = dict(_REF["no_owner_verdict"])
NO_OWNER_CONFIDENCE = {str(k): str(v) for k, v in dict(NO_OWNER.get("class_confidence") or {}).items()}
PROVIDER_HOST_SUFFIXES = tuple(str(s).lower().strip(".") for s in NO_OWNER.get("provider_host_suffixes") or ())
BENIGN_IP_PIVOT_KINDS = frozenset(str(k) for k in NO_OWNER.get("benign_ip_pivot_kinds") or ())
OWNER_PIVOT_PREFIXES = tuple(str(p) for p in NO_OWNER.get("owner_pivot_prefixes") or ())
#: statuses the loop/harness COLLECT as IP seeds (everything else is a recorded, uncollected row)
COLLECTABLE = ("origin", "ambiguous")

#: live_results / result keys read, in the order they are reported (`sources_read`).
SOURCES = ("live_dns", "pdns", "passivedns", "securitytrails_dns_history", "validin",
           "urlscan_hostname", "webamon_servers", "passive_ssl", "urlscan_scans")
#: eras whose CURRENT co-tenants may be seeded; every other era holds them back as leads.
SEEDABLE_COTENANT_ERAS = ("current", "recent")
_ERA_RANK = {"current": 0, "recent": 1, "historical": 2, "undated": 3, "previous_owner": 4}


# --------------------------------------------------------------------------- helpers
def _day(v):
    """YYYY-MM-DD from an ISO string, 'YYYY-MM-DD HH:MM:SS', a Wayback-free epoch (int/str), or None."""
    if v in (None, "", 0, "0"):
        return None
    if isinstance(v, (int, float)) or (isinstance(v, str) and v.strip().isdigit() and len(v.strip()) >= 9):
        try:
            return datetime.datetime.fromtimestamp(int(float(v)), datetime.timezone.utc).strftime("%Y-%m-%d")
        except (OverflowError, OSError, ValueError):
            return None
    m = re.match(r"\s*(\d{4}-\d{2}-\d{2})", str(v))
    return m.group(1) if m else None


def _ip(v):
    try:
        return str(ipaddress.ip_address(str(v or "").strip()))
    except ValueError:
        return None


def _asn(v):
    s = str(v or "").strip().upper()
    if not s:
        return None
    s = s.split()[0]
    if s.startswith("AS"):
        s = s[2:]
    return f"AS{s}" if s.isdigit() else None


@functools.lru_cache(maxsize=1)
def _cdn():
    """(cdn_ranges module, index) — (None, None) when the CIDR cache is unavailable."""
    try:
        import cdn_ranges  # noqa: WPS433
    except Exception:  # noqa: BLE001
        return None, None
    try:
        return cdn_ranges, cdn_ranges.load_ranges()
    except Exception:  # noqa: BLE001
        return cdn_ranges, None


def classify(ip, asn=None, org=None):
    """{'status','provider','why'} for one address. Order: invalid → bogon → CIDR edge → edge ASN →
    edge org marker → parking marker → origin. CIDR wins over everything an ASN/org row claims.
    Bogon is cdn_ranges.is_bogon (the system-wide definition), stdlib flags when it is unavailable."""
    norm = _ip(ip)
    if not norm:
        return {"status": "invalid", "provider": None, "why": "not an IP address"}
    mod, idx = _cdn()
    addr = ipaddress.ip_address(norm)
    bogon = (mod.is_bogon(norm) if mod is not None and hasattr(mod, "is_bogon") else
             (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast
              or addr.is_unspecified or addr.is_reserved))
    if bogon:
        return {"status": "bogon", "provider": None,
                "why": "non-routable address (loopback / private / reserved) — a parking or sinkhole answer"}
    if idx is None:
        # No CIDR index → a Cloudflare edge with no ASN/org on its row would read as an origin. Without
        # the index the address is UNDETERMINED (never collected) unless the source's own ASN/org says.
        c = None
    else:
        c = mod.classify(norm, idx)
        # Customer GCE ranges are rented VMs — real origins (the co-host count guard still applies);
        # every other published range (CDN edges, Google's own front ends) is a shared edge.
        if c.get("cdn") is True and not is_rentable_cloud(c):
            return {"status": "cdn", "provider": c.get("provider"),
                    "why": f"published {c.get('provider')} edge range ({c.get('kind')})"}
    a = _asn(asn)
    if a and a in EDGE_ASNS:
        return {"status": "cdn", "provider": EDGE_ASNS[a], "why": f"{a} is an edge-only network ({EDGE_ASNS[a]})"}
    o = str(org or "").lower()
    for m in EDGE_ORG_MARKERS:
        if _has_marker(o, m):
            return {"status": "cdn", "provider": m, "why": f"network '{org}' is an edge/WAF provider"}
    if a and a in AMBIGUOUS_ASNS:
        return {"status": "ambiguous", "provider": AMBIGUOUS_ASNS[a],
                "why": f"{a} ({AMBIGUOUS_ASNS[a]}) sells DDoS proxying AND servers — collected, co-tenants held"}
    for m in AMBIGUOUS_ORG_MARKERS:
        if _has_marker(o, m):
            return {"status": "ambiguous", "provider": m,
                    "why": f"network '{org}' sells DDoS proxying AND servers — collected, co-tenants held"}
    for m in PARKING_MARKERS:
        if _has_marker(o, m):
            return {"status": "parking", "provider": m, "why": f"network '{org}' is a parking farm"}
    if idx is None:
        return {"status": "undetermined", "provider": None,
                "why": "CDN range cache unavailable — cannot rule out a shared edge; not collected"}
    return {"status": "origin", "provider": c.get("provider") if c.get("cdn") else None,
            "why": ("customer cloud VM range (google_cloud) — a rented origin" if c.get("cdn")
                    else "not a known CDN / WAF / parking edge")}


def is_rentable_cloud(c):
    """True for a cdn_ranges verdict that is customer cloud COMPUTE (GCE VMs a tenant rents — a real
    origin, co-host count guard applies) rather than a shared edge. The ONE place this is decided:
    case_state's co-host guard reads it too, so the frontier and the classifier cannot disagree."""
    return bool(c) and c.get("kind") == "cloud" and c.get("provider") == "google_cloud"


def _has_marker(org_lower, marker):
    """Whole-word match: 'sedo' hits 'Sedo GmbH', never 'Sedona Hosting'."""
    return bool(marker) and re.search(r"(?<![a-z0-9])" + re.escape(marker) + r"(?![a-z0-9])", org_lower) is not None


def collected_verdict(ip, ip_intel):
    """classify() again, with the network the IP LOOKUP reported (IPPivot `ip_intel.ipinfo`). Most
    history sources carry no ASN, so an edge or proxy-or-host box is often queued as `origin`; the
    frontier and KB ingest read this before seeding / linking the box's co-tenants."""
    info = (ip_intel or {}).get("ipinfo") or {}
    return classify(ip, info.get("asn"), info.get("org_name"))


def is_vps_origin(ip, ip_intel):
    """True for a collected IP the classifier keeps as an ORIGIN while the IP lookup flags its network
    as hosting/noise (cloud or VPS — Google Cloud, DigitalOcean, OVH, Hetzner, Vultr …). Its co-tenants
    are auto-linked only up to VPS_AUTO_MAX_COTENANTS; beyond that they need analyst approval."""
    return bool((ip_intel or {}).get("noise")) and collected_verdict(ip, ip_intel).get("status") == "origin"


@functools.lru_cache(maxsize=1)
def _saas_suffixes():
    """noise_filters.SAAS_TENANT_SUFFIXES — the SAME platform list case_state._frontier_apex uses
    (tools/kb is a sibling of WebPivot in the engine). Empty when the KB toolkit is unavailable."""
    try:
        kb_tools = os.path.normpath(os.path.join(HERE, os.pardir, os.pardir, "tools", "kb"))
        if kb_tools not in sys.path:
            sys.path.append(kb_tools)
        from noise_filters import SAAS_TENANT_SUFFIXES  # noqa: WPS433
        return tuple(sorted(SAAS_TENANT_SUFFIXES, key=len, reverse=True))
    except Exception:  # noqa: BLE001
        return ()


def _apex(host):
    """The registrable unit of a co-tenant — the ONE reduction the approval record, the frontier,
    ingest and the partition share. A shared-platform tenant (`kit.pages.dev`) keeps its tenant label,
    exactly like case_state._frontier_apex: reducing it to `pages.dev` would make one approval cover
    every tenant of the platform on that box."""
    h = str(host or "").strip().lower().rstrip(".")
    for s in _saas_suffixes():
        if h == s:
            return s
        if h.endswith("." + s):
            label = h[:-(len(s) + 1)].rsplit(".", 1)[-1]
            return f"{label}.{s}" if label else s
    try:
        from wp_common import _registrable  # noqa: WPS433 — lazy: keeps this module import-light
        return _registrable(h) or ""
    except Exception:  # noqa: BLE001
        parts = h.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else ""


def cotenant_count(ip_intel, names, exclude=(), is_noise=None):
    """(apexes, count) — the ONE count the frontier and KB ingest compare against
    VPS_AUTO_MAX_COTENANTS, so they always reach the same decision. `apexes` = registrable apexes of
    `names` minus `exclude` (the case hosts that resolved to the box) and anything `is_noise` calls
    shared infrastructure. `count` also honours the reverse index's own total (`cohost_total`), so a
    truncated list on a box that answers for hundreds of sites never reads as a small VPS."""
    excl = {_apex(h) for h in exclude or ()} - {""}
    allx = {_apex(n) for n in names or ()} - {""}
    apexes = {a for a in allx - excl if not (is_noise and is_noise(a))}
    try:
        total = int((ip_intel or {}).get("cohost_total") or 0)
    except (TypeError, ValueError):
        total = 0
    return apexes, max(len(apexes), total - len(allx & excl))


def approved_cohosts(case_dir):
    """{ip: {"domains": {apex…}, "hosts": {host…}}} — the co-tenants the analyst APPROVED, per domain
    (state.json `approved_cohosts`, written by case_state.record_approved_cohost for the items that
    actually ran: a harness approval or `approve-cohost`). `hosts` are the case hosts that resolved to
    the box when it was approved. Approval is the evidence, but ONLY for these domains: the frontier
    seeds them, ingest links them, and the partition lets their `hosted_on` edges (and the case
    hosts') bind past the VPS / shared-hosting bounds. Every other site on the box keeps the rules."""
    try:
        with open(os.path.join(case_dir, "state.json"), encoding="utf-8") as fh:
            st = json.load(fh) or {}
    except Exception:  # noqa: BLE001
        return {}
    out = {}
    for ip, rec in (st.get("approved_cohosts") or {}).items():
        if isinstance(rec, dict):
            out[str(ip)] = {"domains": {str(d).lower() for d in rec.get("domains") or [] if d},
                            "hosts": {str(h).lower() for h in rec.get("hosts") or [] if h}}
    return out


def approval_allows(approved, src, ip):
    """True when a `domain src --hosted_on--> ip` edge is covered by an approval: src is an approved
    co-tenant (by registrable apex) or one of the case hosts that resolved to the box."""
    rec = (approved or {}).get(str(ip).removeprefix("ip:"))
    if not rec:
        return False
    s = str(src or "").lower().rstrip(".")
    return s in rec["hosts"] or _apex(s) in rec["domains"]


# --------------------------------------------------------------------------- observations
def _observations(lr, result=None, host=None):
    """Yield (ip, source, first, last, asn, org, name) from every history block on a domain pivot."""
    lr = lr if isinstance(lr, dict) else {}
    h = str(host or "").lower().rstrip(".")
    dns = lr.get("dns") if isinstance(lr.get("dns"), dict) else {}
    for ip in dns.get("ips") or []:
        yield ip, "live_dns", None, None, None, None, h or None
    pdns = lr.get("pdns") if isinstance(lr.get("pdns"), dict) else {}
    for rec in pdns.get("records") or []:
        if isinstance(rec, dict) and str(rec.get("rrtype", "")).upper() in ("A", "AAAA"):
            yield (rec.get("rdata"), "pdns", rec.get("time_first"), rec.get("time_last"), None, None,
                   str(rec.get("rrname") or "").rstrip(".").lower() or None)
    ht = lr.get("passivedns") if isinstance(lr.get("passivedns"), dict) else {}
    for row in ht.get("hosts") or []:
        if isinstance(row, dict):
            yield row.get("ip"), "passivedns", None, None, None, None, row.get("host")
    st = lr.get("securitytrails_dns_history") if isinstance(lr.get("securitytrails_dns_history"), dict) else {}
    for e in st.get("eras") or []:
        if isinstance(e, dict):
            yield e.get("ip"), "securitytrails_dns_history", e.get("first_seen"), e.get("last_seen"), None, e.get("org"), h or None
    va = lr.get("validin") if isinstance(lr.get("validin"), dict) else {}
    for rec in va.get("dns") or []:
        if isinstance(rec, dict) and str(rec.get("rrtype", "")).upper() in ("A", "AAAA"):
            yield (rec.get("rdata"), "validin", rec.get("first"), rec.get("last"), None, None,
                   str(rec.get("rrname") or "").rstrip(".").lower() or None)
    us = lr.get("urlscan_hostname") if isinstance(lr.get("urlscan_hostname"), dict) else {}
    for e in us.get("a_eras") or []:
        if isinstance(e, dict):
            yield e.get("value"), "urlscan_hostname", e.get("first_seen"), e.get("last_seen"), e.get("asn"), None, h or None
    wa = lr.get("webamon_servers") if isinstance(lr.get("webamon_servers"), dict) else {}
    for s in wa.get("servers") or []:
        if isinstance(s, dict):
            yield s.get("ip"), "webamon_servers", s.get("first_seen"), s.get("last_seen"), s.get("asn"), s.get("asn_name"), h or None
    ps = lr.get("pssl") if isinstance(lr.get("pssl"), dict) else {}
    # a non-clusterable cert (served on > max_ips_per_cert addresses, or a CDN / default subject) lists
    # OTHER customers' servers — never this host's history
    if ps.get("clusterable"):
        for ip in ps.get("all_ips") or []:
            yield ip, "passive_ssl", None, None, None, None, h or None
    # keyless urlscan scan list (pivot_extract's related_urlscan): only scans whose PAGE was this host
    rel = (result or {}).get("related_urlscan") if isinstance(result, dict) else None
    scans = rel.get("all_scans") or [] if isinstance(rel, dict) else []
    for sc in scans:
        if isinstance(sc, dict) and sc.get("ip") and h and str(sc.get("domain") or "").lower() == h:
            yield sc["ip"], "urlscan_scans", sc.get("time"), sc.get("time"), sc.get("asn"), sc.get("asnname"), h


def _rank_key(row):
    """origin first, live first, most corroborated, most recently seen (undated last), then IP."""
    last = row.get("last_seen") or ""
    return (0 if row["status"] in COLLECTABLE else 1, 0 if row["live"] else 1, -len(row["sources"]),
            1 if not last else 0, "".join(chr(255 - ord(c)) for c in last), row["ip"])


def build(lr, result=None, host=None):
    """The `origin_history` block for one domain pivot (pure; no network)."""
    agg = {}
    live = set()
    read = set()
    for ip, src, first, last, asn, org, name in _observations(lr, result, host):
        norm = _ip(ip)
        if not norm:
            continue
        read.add(src)
        a = agg.setdefault(norm, {"sources": set(), "first": None, "last": None, "asn": None,
                                  "org": None, "names": set()})
        a["sources"].add(src)
        if src == "live_dns":
            live.add(norm)
        f, l = _day(first), _day(last)
        if f and (a["first"] is None or f < a["first"]):
            a["first"] = f
        if l and (a["last"] is None or l > a["last"]):
            a["last"] = l
        a["asn"] = a["asn"] or _asn(asn)
        a["org"] = a["org"] or (str(org).strip() if org else None)
        if name:
            a["names"].add(str(name).lower().rstrip("."))
    rows = []
    for ip, a in agg.items():
        c = classify(ip, a["asn"], a["org"])
        rows.append({"ip": ip, "status": c["status"], "provider": c["provider"], "why": c["why"],
                     "sources": sorted(a["sources"]), "first_seen": a["first"], "last_seen": a["last"],
                     "live": ip in live, "asn": a["asn"], "org": a["org"],
                     "names": sorted(a["names"])[:8]})
    rows = mark_ad_edges(rows)
    return _finish({"sources_read": [s for s in SOURCES if s in read]}, rows)


def _finish(blk, rows, sort=True):
    """`blk` with `rows` (ranked unless `sort` is False) counted and its collectable origin list rebuilt."""
    rows = sorted(rows, key=_rank_key) if sort else list(rows)
    counts = {}
    for r in rows:
        counts[r.get("status")] = counts.get(r.get("status"), 0) + 1
    return {**blk, "ips": rows, "origin_candidates": [r.get("ip") for r in rows if r.get("status") in COLLECTABLE],
            "counts": counts}


def block_for(lr, result=None, host=None):
    """The stored block when the collector wrote one, else computed from the raw blocks (older raws).
    A stored block gets the ad-edge rule re-applied, so a raw collected before it existed (or under
    an older reference) still never binds two publishers through an ad network's edge pool."""
    blk = (lr or {}).get("origin_history") if isinstance(lr, dict) else None
    if isinstance(blk, dict) and isinstance(blk.get("ips"), list):
        rows = [r for r in blk["ips"] if isinstance(r, dict)]
        marked = mark_ad_edges(rows)
        return _finish(blk, marked, sort=False) if marked != rows else blk
    return build(lr, result, host)


# --------------------------------------------------------------------------- ad-network edge
def aws_region(ip):
    """The ad_edge.region_cidrs region holding `ip`, else None."""
    norm = _ip(ip)
    if not norm:
        return None
    addr = ipaddress.ip_address(norm)
    for region, nets in AD_EDGE_REGION_CIDRS.items():
        if any(addr.version == n.version and addr in n for n in nets):
            return region
    return None


def mark_ad_edges(rows, today=None):
    """Reclassify one host's ad-network edge pool as `cdn` (references/origin_history.json ad_edge).

    A host answering, within ad_edge.window_days of its latest sighting, on >= min_ips addresses of
    an ad_edge ASN (or region CIDR) spread across >= min_regions regions is on an ad network's
    hyperscaler edge — every publisher on that network shares the pool, so the rows must never seed
    an IP pivot or write a hosted_on edge. Returns a NEW list (rows unchanged when the rule does not
    fire); undated rows of the pool are swept along, rows outside the window keep their verdict."""
    pool = []
    for r in rows or []:
        if r.get("status") not in ("origin", "undetermined"):
            continue
        region = aws_region(r.get("ip"))
        if region or (_asn(r.get("asn")) in AD_EDGE_ASNS):
            pool.append((r, region))
    if len(pool) < AD_EDGE_MIN_IPS:
        return list(rows or [])
    now = today or _today()
    ends = {id(r): (now if r.get("live") else _day(r.get("last_seen"))) for r, _ in pool}
    dated = [e for e in ends.values() if e]
    if not dated:
        return list(rows or [])
    try:
        floor = (datetime.date.fromisoformat(max(dated))
                 - datetime.timedelta(days=AD_EDGE_WINDOW_DAYS)).isoformat()
    except ValueError:
        return list(rows or [])
    in_window = [(r, g) for r, g in pool if ends[id(r)] and ends[id(r)] >= floor]
    regions = {g for _r, g in in_window if g}
    if len(in_window) < AD_EDGE_MIN_IPS or len(regions) < AD_EDGE_MIN_REGIONS:
        return list(rows or [])
    hit = {id(r) for r, _g in in_window} | {id(r) for r, _g in pool if not ends[id(r)]}
    why = (f"ad-network edge pool: {len(in_window)} {'/'.join(AD_EDGE_ASNS) or 'hyperscaler'} addresses "
           f"across {len(regions)} regions within {AD_EDGE_WINDOW_DAYS} days — shared by every "
           f"publisher on the network, never an operator origin")
    return [dict(r, status="cdn", provider=AD_EDGE_PROVIDER, why=why) if id(r) in hit else r
            for r in rows or []]


# --------------------------------------------------------------------------- no-owner verdict
def is_provider_host(host):
    """True for a hostname under no_owner_verdict.provider_host_suffixes (a provider's own name)."""
    h = str(host or "").strip().lower().rstrip(".")
    return bool(h) and any(h == s or h.endswith("." + s) for s in PROVIDER_HOST_SUFFIXES)


def owner_signal(obj):
    """The first owner-rung signal on a collected raw (IP or provider hostname), else None.
    IP raw: any pivot kind outside benign_ip_pivot_kinds (a cert, self-hosted MX, misconfig leak,
    distinctive PTR …) except an ip:ptr under a provider suffix. Hostname raw: any pivot whose kind
    starts with an owner_pivot_prefixes entry."""
    meta = (obj or {}).get("meta") or {}
    is_ip = meta.get("kind") == "ip" or bool(_ip(meta.get("host")))
    for p in (obj or {}).get("pivots") or []:
        if not isinstance(p, dict):
            continue
        kind = str(p.get("kind") or "")
        if is_ip:
            if kind in BENIGN_IP_PIVOT_KINDS:
                continue
            if kind == "ip:ptr" and is_provider_host(p.get("value")):
                continue
            return f"{kind} {p.get('value') or ''}".strip()
        if any(kind.startswith(px) for px in OWNER_PIVOT_PREFIXES):
            return f"{kind} {p.get('value') or ''}".strip()
    return None


@functools.lru_cache(maxsize=1)
def _shared_hosting_max():
    """noise_filters.SHARED_HOSTING_MAX_COHOSTS (the landlord bound ingest and the frontier use);
    None when the KB toolkit is unavailable — then no address is called shared-hosting."""
    try:
        _saas_suffixes()                     # puts tools/kb on sys.path
        from noise_filters import SHARED_HOSTING_MAX_COHOSTS  # noqa: WPS433
        return int(SHARED_HOSTING_MAX_COHOSTS)
    except Exception:  # noqa: BLE001
        return None


def no_owner_class(ip, ip_intel=None, history=()):
    """(class, label) when `ip` is provably not an operator box, else None.

    `history`: the case's origin-history rows for this address (any domain raw). A row the history
    classed cdn / parking / bogon (incl. the ad-edge pool) decides first; then the IP lookup's own
    network (collected_verdict); then the box's co-tenant count: above the shared-hosting bound it
    is `shared-hosting`, on a noise-flagged hosting network above the VPS bound it is `platform`.
    A small VPS, an ambiguous proxy-or-host network or an unclassifiable address returns None —
    those may be the operator's own box and go to the LLM."""
    info = (ip_intel or {}).get("ipinfo") or {}
    for r in history or ():
        st = r.get("status")
        if st in ("cdn", "parking", "bogon"):
            cls = "ad_edge" if r.get("provider") == AD_EDGE_PROVIDER else st
            asn = r.get("asn") or info.get("asn")
            org = r.get("org") or info.get("org_name")
            return cls, " ".join(x for x in (asn, org or r.get("provider")) if x) or st
    if ip_intel is None:
        return None
    v = collected_verdict(ip, ip_intel)
    label = " ".join(x for x in (info.get("asn"), info.get("org_name")) if x)
    if v.get("status") in ("cdn", "parking", "bogon"):
        return v["status"], label or str(v.get("provider") or v["status"])
    if v.get("status") != "origin":
        return None
    try:
        total = int((ip_intel or {}).get("cohost_total") or 0)
    except (TypeError, ValueError):
        total = 0
    total = max(total, len((ip_intel or {}).get("co_hosted_domains") or []))
    bound = _shared_hosting_max()
    if bound is not None and total > bound:
        return "shared-hosting", f"{label or 'unknown network'}, {total} co-hosted sites"
    if is_vps_origin(ip, ip_intel) and total > VPS_AUTO_MAX_COTENANTS:
        return "platform", f"{label or 'hosting network'}, {total} co-hosted sites"
    return None


# --------------------------------------------------------------------------- eras
def _today():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")


def era(row, registered_on=None, today=None, recent_days=None):
    """Tenancy era of one origin row (see module docstring)."""
    if row.get("live"):
        return "current"
    last = row.get("last_seen")
    reg = _day(registered_on)
    if reg and last and last < reg:
        return "previous_owner"
    if not last:
        return "undated"
    days = RECENT_TENANCY_DAYS if recent_days is None else int(recent_days)
    try:
        age = (datetime.date.fromisoformat(today or _today()) - datetime.date.fromisoformat(last)).days
    except ValueError:
        return "undated"
    return "recent" if age <= days else "historical"


def host_origins(obj, today=None):
    """(host, registered_on, [collectable rows (origin + ambiguous) + 'era']) for a DOMAIN raw
    pivot_extract object; ('', None, []) for an IP raw or a raw without a domain pivot."""
    meta = (obj or {}).get("meta") or {}
    host = str(meta.get("host") or "").lower()
    if meta.get("kind") == "ip" or _ip(host):
        return host, None, []
    dp = next((p for p in (obj.get("pivots") or []) if isinstance(p, dict) and p.get("kind") == "domain"), None)
    if not dp:
        return host, None, []
    reg = ((obj.get("artifacts") or {}).get("whois") or {}).get("created")
    blk = block_for(dp.get("live_results") or {}, obj, host)
    rows = []
    for r in blk.get("ips") or []:
        if r.get("status") not in COLLECTABLE:
            continue
        rows.append(dict(r, era=era(r, reg, today)))
    return host, reg, rows


def origin_context(case_dir, ip, today=None):
    """Why the case holds this IP: every collected DOMAIN raw whose origin history names it. Returns
    {hosts, sources, first_seen, last_seen, live, era, stale, ambiguous, hold_cotenants} or None when
    no case host ever used it. `hold_cotenants` (stale tenancy OR an ambiguous proxy-or-host network)
    is the one flag the frontier and KB ingest read before seeding / clustering the box's co-tenants."""
    target = _ip(ip)
    if not (case_dir and target):
        return None
    hosts, sources, first, last, live, best, ambiguous = set(), set(), None, None, False, None, False
    for path in sorted(glob.glob(os.path.join(case_dir, "raw", "*.json"))):
        try:
            with open(path, encoding="utf-8") as fh:
                obj = json.load(fh)
        except Exception:  # noqa: BLE001
            continue
        host, _reg, rows = host_origins(obj, today)
        for r in rows:
            if r["ip"] != target:
                continue
            hosts.add(host)
            sources.update(r.get("sources") or ())
            if r.get("first_seen") and (first is None or r["first_seen"] < first):
                first = r["first_seen"]
            if r.get("last_seen") and (last is None or r["last_seen"] > last):
                last = r["last_seen"]
            live = live or bool(r.get("live"))
            ambiguous = ambiguous or r.get("status") == "ambiguous"
            if best is None or _ERA_RANK[r["era"]] < _ERA_RANK[best]:
                best = r["era"]
    if not hosts:
        return None
    stale = best not in SEEDABLE_COTENANT_ERAS
    return {"hosts": sorted(hosts), "sources": sorted(sources), "first_seen": first, "last_seen": last,
            "live": live, "era": best, "stale": stale, "ambiguous": ambiguous,
            "hold_cotenants": stale or ambiguous}


def hold_cotenants(ctx):
    """True when an IP raw's origin_context says its co-tenants must not seed / cluster (older stamps
    carry only `stale`)."""
    ctx = ctx or {}
    return bool(ctx.get("hold_cotenants", ctx.get("stale")) or ctx.get("ambiguous"))


def _overlap(a, b):
    """Tenancy overlap of two rows {first_seen,last_seen,live}: ('overlapping', 'YYYY-MM..YYYY-MM'),
    ('disjoint', 'gap N days') or ('undated', '')."""
    def _span(r):
        f = r.get("first_seen")
        l = _today() if r.get("live") else r.get("last_seen")
        return (f or l, l or f)
    (af, al), (bf, bl) = _span(a), _span(b)
    if not (af and al and bf and bl):
        return "undated", ""
    lo, hi = max(af, bf), min(al, bl)
    if lo <= hi:
        return "overlapping", f"{lo[:7]}..{hi[:7]}"
    gap = (datetime.date.fromisoformat(lo) - datetime.date.fromisoformat(hi)).days
    return "disjoint", f"gap {gap} days"


def case_summary(case_dir, host=None, today=None):
    """Every DOMAIN raw's merged origin history in a case (or one host): the collectable rows with
    their era, the counts of suppressed edge/parking/bogon rows, and whether each origin IP was
    collected yet. Offline — reads cases/<id>/raw only."""
    raw_dir = os.path.join(case_dir, "raw")
    collected = {os.path.basename(p)[:-5] for p in glob.glob(os.path.join(raw_dir, "*.json"))}
    out = []
    for path in sorted(glob.glob(os.path.join(raw_dir, "*.json"))):
        try:
            with open(path, encoding="utf-8") as fh:
                obj = json.load(fh)
        except Exception:  # noqa: BLE001
            continue
        h, reg, rows = host_origins(obj, today)
        if not h or _ip(h) or (host and h != str(host).lower()):
            continue
        dp = next((p for p in obj.get("pivots") or [] if isinstance(p, dict) and p.get("kind") == "domain"), None)
        if not dp:
            continue
        blk = block_for(dp.get("live_results") or {}, obj, h)
        out.append({"host": h, "registered_on": reg, "counts": blk.get("counts") or {},
                    "sources_read": blk.get("sources_read") or [], "error": blk.get("error"),
                    "origins": [dict(r, collected=r["ip"] in collected) for r in rows]})
    return out


__all__ = ["build", "block_for", "classify", "collected_verdict", "is_vps_origin", "cotenant_count",
           "approved_cohosts", "approval_allows", "era", "host_origins", "origin_context", "hold_cotenants",
           "case_summary", "is_rentable_cloud", "EDGE_ASNS", "EDGE_ORG_MARKERS", "PARKING_MARKERS",
           "AMBIGUOUS_ASNS", "AMBIGUOUS_ORG_MARKERS", "COLLECTABLE", "MAX_IPS_PER_HOST",
           "MAX_IP_SEEDS_PER_ROUND", "RECENT_TENANCY_DAYS", "VPS_AUTO_MAX_COTENANTS",
           "SEEDABLE_COTENANT_ERAS", "SOURCES", "mark_ad_edges", "aws_region", "is_provider_host",
           "owner_signal", "no_owner_class", "AD_EDGE_ASNS", "AD_EDGE_REGION_CIDRS", "AD_EDGE_PROVIDER",
           "NO_OWNER_CONFIDENCE", "PROVIDER_HOST_SUFFIXES"]


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Historical origin IPs of a case's collected hosts (offline).")
    ap.add_argument("case", help="case ID (under this engine's cases/) or a case directory path")
    ap.add_argument("--host", help="only this collected host")
    a = ap.parse_args()
    _c = a.case
    if not (os.path.isabs(_c) or os.sep in _c):
        # same rule as case_state._case_dir: a bare ID is this engine's cases/<id> — so origin-history
        # reads exactly the store approve-cohost / frontier write
        _c = os.path.join(os.path.dirname(os.path.dirname(HERE)), "cases", _c)
    if not os.path.isdir(os.path.join(_c, "raw")):
        sys.exit(f"no collected raws under {_c}/raw")
    print(json.dumps(case_summary(_c, a.host), indent=2, ensure_ascii=False))
