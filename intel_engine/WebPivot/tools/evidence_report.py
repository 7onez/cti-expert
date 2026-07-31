"""evidence_report — finished-intelligence reporting + a master evidence ledger for WebPivot.

Two independent capabilities, both operating on a `pivot_extract.py` result dict:

  render_cia_report(result, ...)   -> str   (Markdown intelligence assessment)
  append_master(result, path, ...) -> dict  (append this run's pivots to a master ledger)

REPORTING — US IC analytic tradecraft (ICD 203 "Analytic Standards" + CIA/ODNI style):
  * a classification banner (top and bottom of every product),
  * BLUF (Bottom Line Up Front),
  * Key Judgments, each carrying a word of estimative probability AND a calibrated
    analytic confidence level (high / moderate / low),
  * a clean split between REPORTED FACT (collected) and ANALYTIC ASSESSMENT (judged),
  * a source / collection summary,
  * neutral, precise, active-voice prose — no marketing adjectives, no hype.

LEDGER — one row per pivot, appended to a single master file so runs accumulate into a
  court-ready exhibit register. CSV by default (stdlib only); XLSX when the path ends in
  .xlsx and openpyxl is installed. Rows dedupe on a stable evidence_id, so re-running a
  host UPDATES its rows instead of duplicating them, and existing rows are never dropped.

Stdlib-only for the CSV path — consistent with the WebPivot "core needs nothing beyond
the Python 3 stdlib" contract. openpyxl is an optional accelerator for .xlsx output.
"""
from __future__ import annotations

import csv
import datetime
import hashlib
import ipaddress
import os
import sys
from typing import Optional

# Standardized analyst Domain Summary table (domains/status/WHOIS/attribution) —
# auto-prepended to every assessment. Lives at the project-root tools/ dir.
try:
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))), "tools"))
    from domain_table import render_domain_table  # type: ignore
except Exception:                                  # degrade gracefully if unavailable
    render_domain_table = None

# CDN/cloud classifier — so the origin-IP section can label a shared edge (Cloudflare, CloudFront,
# GCP LB) and never call it a high-value origin. Fail-open (unknown) if unavailable.
try:
    from wp_analyze import classify_ip as _classify_ip  # type: ignore
except Exception:
    def _classify_ip(ip):
        return {"ip": ip, "cdn": None, "provider": None, "kind": "unknown"}

# --------------------------------------------------------------------------- estimative language
# ICD 203 mandates a standard lexicon for likelihood ("words of estimative probability")
# and requires it be kept distinct from analytic CONFIDENCE (how solid the sourcing is).
# We map the extractor's internal pivot confidence (high/medium/low) to both.

# Likelihood that the pivot reflects a real, actionable infrastructure/ownership link.
_ESTIMATIVE = {
    "high":   "very likely",
    "medium": "likely",
    "low":    "roughly even chance",
}
# Analytic confidence = quality/corroboration of the underlying reporting.
_CONFIDENCE = {
    "high":   "high confidence",
    "medium": "moderate confidence",
    "low":    "low confidence",
}
# The full ICD 203 estimative scale, low→high, for reference and for the up-grade step.
_SCALE = ["remote", "very unlikely", "unlikely", "roughly even chance",
          "likely", "very likely", "almost certainly"]
# Analytic-confidence scale, low→high — same "bump one notch" idiom as _SCALE.
_CONF_SCALE = ["low confidence", "moderate confidence", "high confidence"]


def _bump(scale: list, value: str) -> str:
    """Climb one rung up an ordered term scale (capped at the top)."""
    idx = scale.index(value) if value in scale else 0
    return scale[min(idx + 1, len(scale) - 1)]


def estimative_terms(confidence: str, live_corroborated: bool = False) -> dict:
    """Return {'likelihood', 'confidence'} in ICD 203 language for a pivot.

    Live corroboration (an independent source returned hits for the pivot) bumps the
    likelihood one notch up the estimative scale and lifts analytic confidence — this
    is the tradecraft rule that multiple independent sources raise confidence.
    """
    conf = (confidence or "low").lower()
    likelihood = _ESTIMATIVE.get(conf, "roughly even chance")
    analytic = _CONFIDENCE.get(conf, "low confidence")
    if live_corroborated:
        likelihood = _bump(_SCALE, likelihood)
        analytic = _bump(_CONF_SCALE, analytic)
    return {"likelihood": likelihood, "confidence": analytic}


# --------------------------------------------------------------------------- shared helpers
def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _live_hits(pivot: dict) -> list:
    """Human-readable one-liners for whatever independent sources corroborated a pivot."""
    lr = pivot.get("live_results") or {}
    out = []
    dns = lr.get("dns") or {}
    if dns.get("ips"):
        out.append("live DNS: " + ", ".join(dns["ips"]))
    for key, label in (("fofa", "FOFA"), ("urlscan", "urlscan"),
                       ("crtsh", "crt.sh"), ("passivedns", "passive DNS"),
                       ("pdns", "PDNS"), ("fofa_ip_reverse", "FOFA reverse-IP"),
                       ("pdns_ip_reverse", "PDNS reverse-IP")):
        blk = lr.get(key) or {}
        total = blk.get("total")
        if total:
            out.append(f"{label}: {total} hits")
    for stk in ("reverse_whois_current", "reverse_whois_historic"):
        rw = lr.get(stk) or {}
        if rw.get("count"):
            out.append(f"{stk}: {rw['count']} domains")
    return out


def _evidence_id(host: str, kind: str, value: str, case: str = "") -> str:
    """Stable 12-char id for a single artifact — the dedupe/merge key for the ledger.

    `case` is folded in so one shared master file can hold multiple cases without the
    same host+artifact in two cases colliding onto (and overwriting) one row.
    """
    raw = f"{(case or '').lower()}|{(host or '').lower()}|{(kind or '').lower()}|{str(value).strip().lower()}"
    return hashlib.sha256(raw.encode("utf-8", "ignore")).hexdigest()[:12]


# =========================================================================== 1. CIA-standard report
def render_cia_report(result: dict,
                      case: Optional[str] = None,
                      classification: str = "UNCLASSIFIED//FOR OFFICIAL USE ONLY",
                      analyst: Optional[str] = None) -> str:
    """Render a pivot-extract `result` as a finished-intelligence assessment (Markdown).

    Tone and structure follow ICD 203 / CIA analytic tradecraft: banner, BLUF, Key
    Judgments with estimative language and calibrated confidence, a fact/assessment
    split, and a collection summary. Facts are what collection returned; judgments are
    clearly labelled as analysis.
    """
    m = result.get("meta", {})
    art = result.get("artifacts", {})
    pivots = result.get("pivots", []) or []
    host = m.get("host") or m.get("source") or "unknown target"
    final_url = m.get("final_url") or m.get("source") or ""

    # Walk each pivot's live_results exactly once; everything below reads these.
    pivot_hits = [(p, _live_hits(p)) for p in pivots]

    L: list = []
    banner = classification.strip().upper()
    L.append(banner)
    L.append("")
    L.append(f"# Intelligence Assessment — {host}")
    subject = [f"**Subject:** {final_url or host}"]
    if case:
        subject.append(f"**Case:** {case}")
    subject.append(f"**Date (UTC):** {_utc_now()}")
    # OPSEC: the analyst name is deliberately NOT stamped on the deliverable (attribution leak).
    L.append("  |  ".join(subject))
    L.append("")

    # ---- Noise suppression (Gap #3/#5): registrar-privacy emails, CDN edge IPs and
    # boilerplate must NEVER earn a Key Judgment. Split signal vs suppressed up front. ----
    signal = [(p, h) for (p, h) in pivot_hits
              if not _is_noise_value(p.get("kind", ""), p.get("value"))]
    suppressed = [p for (p, _h) in pivot_hits
                  if _is_noise_value(p.get("kind", ""), p.get("value"))]
    cdn_providers = set()
    for p, _h in pivot_hits:
        if p.get("kind") == "domain":
            for c in ((p.get("live_results") or {}).get("dns") or {}).get("ip_classification") or []:
                if c.get("cdn") is True and c.get("provider"):
                    cdn_providers.add(c["provider"])

    # ---- BLUF ---------------------------------------------------------------
    high = [p for (p, _h) in signal if (p.get("confidence") or "").lower() == "high"]
    corr = [p for (p, hits) in signal if hits]
    L.append("## Bottom Line Up Front")
    if signal:
        lead, lead_hits = next(((p, h) for p, h in signal
                                if (p.get("confidence") or "").lower() == "high"), signal[0])
        terms = estimative_terms(lead.get("confidence"), bool(lead_hits))
        L.append(
            f"Collection against {host} yielded {len(signal)} pivot artifact(s) of analytic value"
            + (f" ({len(suppressed)} suppressed as registrar/CDN boilerplate)" if suppressed else "")
            + f", of which {len(high)} carry high extraction confidence and {len(corr)} were "
            f"independently corroborated by live sourcing. We assess with {terms['confidence']} that "
            f"the strongest indicator — {lead.get('kind')} `{lead.get('value')}` — {terms['likelihood']} "
            f"reflects a genuine, pivotable link to the operator's wider infrastructure."
        )
    else:
        L.append(
            f"Collection against {host} returned no high-value pivot artifacts"
            + (f" ({len(suppressed)} registrar/CDN boilerplate item(s) suppressed)" if suppressed else "")
            + ". We are unable to assess operator infrastructure from this collection alone; "
            "additional collection is required."
        )
    if cdn_providers:
        L.append(f"_The host is fronted by a shared CDN/cloud edge ({', '.join(sorted(cdn_providers))}); "
                 f"its hosting IP carries low attribution value and is excluded from judgments._")
    if m.get("redirect_destination"):
        L.append(f"The subject redirects to **{m['redirect_destination']}**, which we assess "
                 f"is the operative destination and should anchor further collection.")
    if m.get("live_error"):
        L.append(f"_Collection note: the live target was unreachable ({m['live_error']}); "
                 f"findings rest on {m.get('recovered_via') or 'passive sourcing'}._")
    L.append("")

    # ---- Domain Summary (standardized table: status / WHOIS / attribution) ---
    if render_domain_table is not None:
        try:
            tbl = render_domain_table([result], case=case)
            if tbl:
                L += [tbl, ""]
        except Exception:
            pass

    # ---- Key Judgments ------------------------------------------------------
    L.append("## Key Judgments")
    L.append("")
    L.append("_Estimative language and confidence per ICD 203. Likelihood describes whether the "
             "link is real; confidence describes the strength of the underlying sourcing._")
    L.append("")
    if signal:
        for i, (p, hits) in enumerate(signal[:15], 1):
            terms = estimative_terms(p.get("confidence"), bool(hits))
            L.append(f"- **KJ-{i}.** The {p.get('kind')} artifact `{p.get('value')}` "
                     f"**{terms['likelihood']}** links the subject to related infrastructure "
                     f"(*{terms['confidence']}*).")
            if p.get("note"):
                L.append(f"    - Basis: {p['note']}")
            L.append(f"    - Corroboration: {'; '.join(hits)}." if hits
                     else "    - Corroboration: none returned this collection; single-source.")
        if len(signal) > 15:
            L.append(f"- _({len(signal) - 15} additional lower-priority artifacts recorded in "
                     f"the evidence ledger.)_")
    else:
        L.append("- No judgments supported by current collection.")
    if suppressed:
        L.append(f"- _Suppressed as noise (not judged): {len(suppressed)} registrar-privacy / CDN / "
                 f"boilerplate artifact(s) — e.g. {', '.join(str(p.get('value'))[:40] for p in suppressed[:3])}._")
    L.append("")

    # ---- Reported facts (collected, not judged) -----------------------------
    L.append("## Reported Facts (Collection)")
    L.append("")
    L.append(f"- Target host: `{host}`")
    if final_url:
        L.append(f"- Final URL observed: {final_url}")
    if art.get("title"):
        L.append(f"- Page title: \"{art['title']}\"")
    fav = art.get("favicon") or {}
    if fav.get("shodan_mmh3") is not None:
        L.append(f"- Favicon MurmurHash3 (Shodan): `{fav['shodan_mmh3']}`")
    if art.get("emails"):
        L.append(f"- Email address(es) observed: {', '.join(art['emails'][:10])}")
    if art.get("crypto"):
        flat = [f"{k}: {v}" for k, vs in art["crypto"].items() for v in (vs if isinstance(vs, list) else [vs])]
        L.append(f"- Cryptocurrency address(es): {', '.join(flat[:8])}")
    tp = art.get("third_party_hosts") or []
    if tp:
        L.append(f"- Third-party infrastructure hosts: {', '.join(tp[:10])}")
    if m.get("crawled"):
        L.append(f"- Pages collected in this run: {len(m['crawled'])}")
    L.append("")

    # ---- Registrant identity (WHOIS) ---------------------------------------
    w = art.get("whois") or {}
    if w and not w.get("error"):
        L.append("## Registrant Identity (WHOIS — Reported)")
        L.append("")
        for label, key in (("Registrant email", "registrant_email"),
                           ("Registrant name", "registrant_name"),
                           ("Registrant org", "registrant_org"),
                           ("Registrant country", "registrant_country"),
                           ("Registrant phone", "registrant_phone"),
                           ("Registrant address", "registrant_address"),
                           ("Registrar", "registrar")):
            if w.get(key):
                L.append(f"- {label}: {w[key]}")
        hist = w.get("history") or {}
        if hist.get("registrant_emails"):
            L.append(f"- Historical registrant email(s): {', '.join(hist['registrant_emails'][:8])}")
        if hist.get("registrant_names"):
            L.append(f"- Historical registrant name(s): {', '.join(hist['registrant_names'][:8])}")
        L.append("")

    # ---- Source / collection summary ---------------------------------------
    L.append("## Source & Collection Summary")
    L.append("")
    L.append(f"- Collection method: {m.get('fetched_with', 'unknown')}"
             + (" (rendered DOM)" if m.get('rendered') else ""))
    if m.get("enriched_with"):
        L.append(f"- Enrichment sources queried: {', '.join(m['enriched_with'])}")
    if m.get("archived_via_wayback"):
        L.append("- Recovered from Internet Archive (Wayback) — historical snapshot.")
    L.append(f"- Independently corroborated artifacts: {len(corr)} of {len(signal)} "
             f"(after suppressing {len(suppressed)} registrar/CDN/boilerplate item(s)).")
    L.append("- Confidence handling: single-source artifacts are reported as such; "
             "confidence is raised only where an independent source corroborates.")
    L.append("")

    # ---- Analyst comment / next collection ---------------------------------
    L.append("## Intelligence Gaps & Recommended Collection")
    L.append("")
    if high:
        L.append(f"- Run reverse lookups on the {len(high)} high-confidence artifact(s) to "
                 f"enumerate the operator's wider domain set.")
    if any((p.get("kind") or "").startswith("whois") for p in pivots):
        L.append("- Pull WHOIS history (registrant phone + address) for reverse-WHOIS pivots.")
    L.append("- Corroborate single-source judgments with a second independent collection pass.")
    L.append("")

    L.append(banner)
    return "\n".join(L)


# =========================================================================== 1b. Cluster report
# Registrant/contact emails that are registrar-privacy or abuse boilerplate, NOT the operator.
# A shared value from this set is noise — it must never drive a same-operator judgment.
_NOISE_EMAIL_SUBSTR = (
    "contact.gandi.net", "@gandi.net", "whoisguard", "whoisprivacy", "privacyprotect",
    "domainsbyproxy", "withheldforprivacy", "perfectprivacy", "privacy-protect",
    "redacted", "abuse@", "tucows.com", "namecheap", "proxy@", "identity-protect",
    "data-protected", "privacydotlink", "privacyservice",
)
# Registrant-name placeholders that registrar privacy proxies emit — not real people.
_NOISE_NAME_SUBSTR = (
    "redacted", "privacy", "domain admin", "whois", "proxy", "not disclosed",
    "withheld", "reactivation period", "c/o id#", "data protected", "statutory masking",
)


def _norm(v) -> str:
    return "" if v is None else str(v).strip().lower()


# Managed-DNS nameserver domains + verification-token shapes that appear in passive DNS
# but are NOT operator infrastructure — keep them out of Discovered Infrastructure.
_NS_NOISE = ("ns.cloudflare.com", "dns.cloudflare.com", "awsdns", "domaincontrol.com",
             "registrar-servers.com", "nsone.net", "dnspod.net", "googledomains.com",
             "azure-dns.", "ns.buddyns.com", "name.com", "dnsowl.com", "he.net")


def _is_infra_noise_host(h: str) -> bool:
    """True for a discovered host that is DNS-provider plumbing or a verification token,
    not a pivotable operator asset."""
    h = _norm(h)
    if not h or "_" in h:                       # verification tokens (mandrill_verify.*, etc.)
        return True
    return any(ns in h for ns in _NS_NOISE)


def _is_identity_pivot(kind: str) -> bool:
    """Kinds that, when shared across hosts, indicate common OPERATOR control —
    the backbone of a same-operator cluster (favicon, analytics/verif/SaaS tokens,
    exact TLS cert). Excludes co_san (handled separately) and low-value hosts/emails."""
    return (kind in ("favicon_hash", "tls_cert:fingerprint_sha256")
            or kind.startswith(("tracker:", "verification:", "saas:")))


def _is_noise_value(kind: str, value: str) -> bool:
    """True if a shared artifact is registrar/CDN/privacy boilerplate, not operator signal."""
    v = _norm(value)
    if not v:
        return True
    if kind == "email" or kind.endswith("registrant_email"):
        return any(s in v for s in _NOISE_EMAIL_SUBSTR)
    if kind.endswith("registrant_name") or kind == "person":
        return any(s in v for s in _NOISE_NAME_SUBSTR)
    return False


def _cluster_confidence(n_types: int, live_corroborated: bool) -> str:
    """Analytic confidence for a same-operator sub-cluster (ICD 203).

    Independent artifact TYPES that co-occur across the same hosts are themselves
    independent sources — a favicon AND a GSC token AND a GA4 ID shared by the same
    domains corroborate each other. So >=3 independent types => high confidence even
    without a live reverse-lookup; 2 types => high only if also live-corroborated,
    else moderate; a single shared artifact => low (or moderate if live-corroborated)."""
    if n_types >= 3 or (n_types >= 2 and live_corroborated):
        return "high confidence"
    if n_types >= 2:
        return "moderate confidence"
    return "moderate confidence" if live_corroborated else "low confidence"


class _UF:
    """Tiny union-find to group hosts that share any backbone artifact into sub-clusters."""
    def __init__(self, items):
        self.p = {x: x for x in items}

    def find(self, x):
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        self.p[self.find(a)] = self.find(b)

    def groups(self):
        g: dict = {}
        for x in self.p:
            g.setdefault(self.find(x), []).append(x)
        return list(g.values())


def _is_ipaddr(s):
    try:
        ipaddress.ip_address((s or "").strip())
        return True
    except ValueError:
        return False


def _epoch_day(v):
    """passive-DNS time_first/time_last -> 'YYYY-MM-DD' (unix epoch int/str, or ISO)."""
    if v in (None, ""):
        return None
    try:
        return datetime.datetime.fromtimestamp(int(float(v)), datetime.timezone.utc).strftime("%Y-%m-%d")
    except (ValueError, TypeError, OSError):
        return str(v)[:10] or None


def _origin_ip_groups(results):
    """Group case domains by the ORIGIN IP they resolve to (CDN/cloud edges excluded), reading only
    collected data — no live calls. Returns (groups, tenant_total, ip_meta):
      groups[ip]       = {host: hosting_window_str}   (only IPs with >= 2 case hosts)
      tenant_total[ip] = FOFA ip= reverse count (dedicated box vs shared hosting)
      ip_meta[ip]      = {'asn','org'} when an IPPivot result for that IP is in the set."""
    ip_hosts, tenant_total, ip_meta = {}, {}, {}
    for r in results:
        meta = r.get("meta") or {}
        host = _norm(meta.get("host") or "")
        if meta.get("kind") == "ip":                       # IPPivot result → ASN/org for that IP
            ii = ((r.get("artifacts") or {}).get("ip_intel") or {}).get("ipinfo") or {}
            if _is_ipaddr(host):
                ip_meta[host] = {"asn": ii.get("asn"), "org": ii.get("org_name")}
            continue
        dp = next((p for p in r.get("pivots") or [] if p.get("kind") == "domain"), None)
        if not dp:
            continue
        lr = dp.get("live_results") or {}
        dns = lr.get("dns") or {}
        cls = {c.get("ip"): c for c in dns.get("ip_classification") or []}
        win = {}
        for rec in (lr.get("pdns") or {}).get("records") or []:
            if rec.get("rrtype") in ("A", "AAAA") and _is_ipaddr(rec.get("rdata")):
                win[rec["rdata"].strip()] = (_epoch_day(rec.get("time_first")),
                                             _epoch_day(rec.get("time_last")))
        for ip in dns.get("ips") or []:
            ip = (ip or "").strip()
            if not _is_ipaddr(ip) or (cls.get(ip) or {}).get("cdn") is True:
                continue
            w = win.get(ip)
            ip_hosts.setdefault(ip, {})[host] = (
                f"{w[0]}..{w[1]}" if w and w[0] and w[1] else "current (live DNS)")
        fr = lr.get("fofa_ip_reverse") or {}
        q = fr.get("query") or ""
        if 'ip="' in q and fr.get("total") is not None:
            fip = q.split('ip="', 1)[1].split('"', 1)[0]
            if _is_ipaddr(fip):
                tenant_total[fip] = max(tenant_total.get(fip, 0), fr.get("total") or 0)
    groups = {ip: hosts for ip, hosts in ip_hosts.items() if len(hosts) >= 2}
    return groups, tenant_total, ip_meta


def _origin_ip_section(results):
    """Markdown for the origin-IP shared-hosting sub-clusters, gated by tenant count."""
    groups, tenant_total, ip_meta = _origin_ip_groups(results)
    if not groups:
        return []
    L = ["## Shared-Hosting (Origin-IP) Sub-Clusters", "",
         "Case domains resolving to the same **origin IP** (CDN/cloud edges excluded). A "
         "**dedicated** box (few other tenants) is a strong same-operator/deployment link; a "
         "**shared** IP (many tenants) is common hosting — shown for completeness, low attribution "
         "value. Hosting window from passive DNS when available.", ""]

    def _rank(ip):
        t = tenant_total.get(ip)
        return (t if t is not None else 10 ** 9, -len(groups[ip]))

    for ip in sorted(groups, key=_rank):
        t = tenant_total.get(ip)
        m = ip_meta.get(ip) or {}
        cl = _classify_ip(ip) or {}
        prov = cl.get("provider") or (m.get("org") if m.get("asn") else None)
        asn = f" · {m['asn']} {m.get('org') or ''}".rstrip() if m.get("asn") else (
            f" · {prov}" if prov else "")
        # A CDN/managed-edge or known cloud provider IP is NOT the operator's origin — never "strong",
        # regardless of how few tenants FOFA happens to index for it.
        if cl.get("cdn") is True or cl.get("kind") in ("cdn", "cloud"):
            note = (f"shared CDN/cloud edge ({prov or cl.get('kind')}) → NOT an origin, low "
                    f"attribution" + (f"; ~{t:,} tenants" if t else ""))
        elif t is None:
            note = "tenant count not collected — reverse `ip=\"%s\"` to judge dedicated vs shared" % ip
        elif t <= 25:
            note = f"**dedicated** (~{t} tenants) → strong same-operator link"
        elif t <= 250:
            note = f"small shared host (~{t} tenants) → moderate, corroborate"
        else:
            note = f"shared hosting (~{t:,} tenants) → low attribution / likely noise"
        L.append(f"### {ip} — {len(groups[ip])} case domains{asn}")
        L.append(f"_{note}_")
        for host, w in sorted(groups[ip].items()):
            L.append(f"- `{host}`  (hosted: {w})")
        L.append("")
    return L


def render_cluster_report(results: list,
                          case: Optional[str] = None,
                          classification: str = "UNCLASSIFIED//FOR OFFICIAL USE ONLY",
                          analyst: Optional[str] = None,
                          graph: Optional[dict] = None) -> str:
    """Render ONE ICD-203 assessment across a whole case (many pivot_extract results).

    Rolls per-host artifacts up into cluster-level Key Judgments: hosts sharing >=2
    INDEPENDENT identity artifacts (favicon / analytics / SaaS token / exact TLS cert)
    are assessed 'almost certainly one operator' (high confidence); one shared artifact
    is 'likely' (moderate). Registrar-privacy emails, CDN edge IPs, and privacy-proxy
    registrant placeholders are filtered out FIRST and disclosed in a transparency
    section, so boilerplate never earns an estimative judgment. Also surfaces
    infrastructure DISCOVERED via origin-IP reverse (hosts not in the input set)."""
    results = [r for r in results if (r.get("meta") or {}).get("host")]
    case_hosts = {(_norm(r["meta"]["host"])) for r in results}
    live = [r for r in results if (r.get("meta") or {}).get("host")]
    n_total = len(results)

    # --- 1. aggregate backbone artifacts across hosts ------------------------
    shared: dict = {}        # (kind, value) -> set(hosts)
    corroborated: set = set()
    suppressed_emails: set = set()
    suppressed_ips: dict = {}   # ip -> provider (CDN edge = noise)
    discovered: dict = {}       # external host -> how found
    per_host: dict = {}         # host -> {status, ipclass, top}

    for r in results:
        host = _norm(r["meta"]["host"])
        top_art = None
        ipclass = None
        for p in r.get("pivots", []) or []:
            kind, val = p.get("kind", ""), p.get("value")
            # registrant/email noise -> suppress + record for transparency
            if _is_noise_value(kind, val):
                if kind == "email" or kind.endswith("registrant_email"):
                    suppressed_emails.add(_norm(val))
                continue
            # CDN-edge IPs from the domain pivot's classification = noise
            if kind == "domain":
                dns = ((p.get("live_results") or {}).get("dns") or {})
                for c in dns.get("ip_classification") or []:
                    if c.get("cdn") is True:
                        suppressed_ips[c["ip"]] = c.get("provider") or "cdn"
                # discovered infra from origin-IP reverse (only ran on origin candidates)
                for lr_key in ("fofa_ip_reverse", "fofa", "urlscan", "pdns", "pdns_ip_reverse"):
                    blk = (p.get("live_results") or {}).get(lr_key) or {}
                    for h in (blk.get("results") or blk.get("domains") or []):
                        hh = _norm(h.get("domain") or h.get("host") if isinstance(h, dict) else h)
                        hh = hh.split("//")[-1].split("/")[0]
                        if (hh and hh not in case_hosts and "." in hh
                                and not hh.replace(".", "").isdigit()
                                and not _is_infra_noise_host(hh)):
                            discovered.setdefault(hh, f"{lr_key} on {host}")
            if _is_identity_pivot(kind) and val is not None:
                key = (kind, _norm(val))
                shared.setdefault(key, set()).add(host)
                if _live_hits(p):
                    corroborated.add(key)
                if top_art is None:
                    top_art = f"{kind}={val}"
        # IP class summary for the host
        for p in r.get("pivots", []) or []:
            if p.get("kind") == "domain":
                ic = ((p.get("live_results") or {}).get("dns") or {}).get("ip_classification")
                if ic:
                    ipclass = ",".join(sorted({c.get("provider") or c.get("kind") for c in ic}))
        per_host[host] = {"top": top_art, "ipclass": ipclass}

    backbone = {k: hosts for k, hosts in shared.items() if len(hosts) >= 2}

    # --- 2. group hosts into sub-clusters via shared backbone ---------------
    uf = _UF(case_hosts)
    for (kind, val), hosts in backbone.items():
        hl = list(hosts)
        for h in hl[1:]:
            uf.union(hl[0], h)
    subclusters = []
    for grp in uf.groups():
        arts = [(k, v, hosts) for (k, v), hosts in backbone.items()
                if hosts & set(grp)]
        if len(grp) < 2 or not arts:
            continue
        kinds = {k.split(":")[0] for (k, v, _h) in arts}   # distinct artifact TYPES
        subclusters.append({"hosts": sorted(grp), "arts": arts, "types": kinds,
                            "corr": any((k, v) in corroborated for (k, v, _h) in arts)})
    subclusters.sort(key=lambda c: (-len(c["types"]), -len(c["hosts"])))

    # --- 3. render ----------------------------------------------------------
    banner = classification.strip().upper()
    L = [banner, "", f"# Cluster Intelligence Assessment — {case or 'case'}"]
    subj = [f"**Domains assessed:** {n_total}"]
    if case:
        subj.append(f"**Case:** {case}")
    subj.append(f"**Date (UTC):** {_utc_now()}")
    # OPSEC: the analyst name is deliberately NOT stamped on the deliverable (attribution leak).
    L += ["  |  ".join(subj), ""]

    confirmed = [c for c in subclusters if len(c["types"]) >= 2]
    L.append("## Bottom Line Up Front")
    if confirmed:
        big = confirmed[0]
        L.append(
            f"Collection covered {n_total} domain(s). We assess with high confidence that "
            f"{sum(len(c['hosts']) for c in confirmed)} of them resolve to common operator "
            f"control, on the basis of {len(confirmed)} sub-cluster(s) each sharing two or more "
            f"independent identity artifacts. The strongest — {', '.join(big['hosts'])} — "
            f"almost certainly share a single operator "
            f"(shared {', '.join(sorted(big['types']))}).")
    elif backbone:
        L.append(f"Collection covered {n_total} domain(s). We assess with moderate confidence "
                 f"that subsets are commonly operated, but no subset yet meets the two-independent-"
                 f"artifact threshold for high confidence; corroboration is recommended.")
    else:
        L.append(f"Collection covered {n_total} domain(s) but surfaced no shared identity "
                 f"artifact across two or more hosts; common control is not established from "
                 f"this collection.")
    if discovered:
        L.append(f"Origin-IP reverse lookups surfaced **{len(discovered)}** external host(s) not "
                 f"in the input set — candidate additional infrastructure (see Discovered Infrastructure).")
    L.append("")

    # Domain Summary table — standardized at-a-glance grid (status / WHOIS dates /
    # registrar+NS / registrant / IP·ASN / attribution / analyst context) so the
    # analyst can judge the whole cluster before reading the narrative.
    if render_domain_table is not None:
        try:
            tbl = render_domain_table(results, case=case)
            if tbl:
                L += [tbl, ""]
        except Exception:
            pass

    # Key Judgments
    L += ["## Key Judgments", "",
          "_ICD 203: likelihood = whether the link is real; confidence = strength of sourcing. "
          "Two or more independent shared artifacts raise both._", ""]
    if confirmed or subclusters:
        for i, c in enumerate(subclusters[:12], 1):
            two = len(c["types"]) >= 2
            like = "almost certainly" if two else "likely"
            conf = _cluster_confidence(len(c["types"]), c["corr"])
            arts_str = "; ".join(f"{k}=`{v}` [{len(h)} hosts]" for (k, v, h) in c["arts"][:4])
            L.append(f"- **KJ-{i}.** {', '.join(c['hosts'])} — **{like}** one operator "
                     f"(*{conf}*); shared: {arts_str}.")
    else:
        L.append("- No cluster-level judgment supported by shared artifacts this collection.")
    L.append("")

    # Confirmed sub-clusters table
    if subclusters:
        L += ["## Confirmed Sub-Clusters", "",
              "| Domains | Shared identity artifacts | Independent types | Verdict |",
              "|---|---|---|---|"]
        for c in subclusters:
            conf = _cluster_confidence(len(c["types"]), c["corr"])
            verdict = {"high confidence": "**one operator** (high)",
                       "moderate confidence": "one operator (moderate)",
                       "low confidence": "possible link (low)"}[conf]
            arts_str = "<br>".join(f"{k}=`{v}`" for (k, v, _h) in c["arts"][:5])
            L.append(f"| {', '.join(c['hosts'])} | {arts_str} | {len(c['types'])} | {verdict} |")
        L.append("")

    # Shared-hosting (origin-IP) sub-clusters — domains on the same origin box, tenant-count gated
    L += _origin_ip_section(results)

    # Discovered infrastructure
    if discovered:
        L += ["## Discovered Infrastructure (origin-IP reverse — not in input set)", ""]
        for h, how in sorted(discovered.items()):
            L.append(f"- `{h}` — via {how}")
        L.append("")

    # Per-host reported facts
    L += ["## Reported Facts — Per Host (Collection)", "",
          "| Host | Live | IP class | Top identity artifact |", "|---|---|---|---|"]
    for r in results:
        host = _norm(r["meta"]["host"])
        ph = per_host.get(host, {})
        L.append(f"| {host} | yes | {ph.get('ipclass') or '—'} | {ph.get('top') or '—'} |")
    L.append("")

    # Suppressed-noise transparency
    if suppressed_emails or suppressed_ips:
        L += ["## Suppressed as Noise (transparency — excluded from judgments)", ""]
        if suppressed_emails:
            L.append(f"- {len(suppressed_emails)} registrar-privacy/abuse email(s): "
                     f"{', '.join(sorted(suppressed_emails)[:6])}"
                     + (" …" if len(suppressed_emails) > 6 else ""))
        if suppressed_ips:
            L.append(f"- {len(suppressed_ips)} shared CDN/cloud edge IP(s) (low attribution value): "
                     + ", ".join(f"{ip} ({prov})" for ip, prov in list(suppressed_ips.items())[:6]))
        L.append("")

    # Gaps
    L += ["## Intelligence Gaps & Recommended Collection", ""]
    if discovered:
        L.append(f"- Pivot the {len(discovered)} discovered host(s) as new seeds.")
    if any(len(c["types"]) < 2 for c in subclusters):
        L.append("- Corroborate single-artifact sub-clusters with a second independent artifact.")
    L.append("- Passive-source (urlscan / Wayback) any input domain that failed live collection.")
    L.append("")
    L.append(banner)
    return "\n".join(L)


# =========================================================================== 2. Master evidence ledger
# Fixed column order — a stable schema the user can hand to a court/evidence workflow.
MASTER_COLUMNS = [
    "evidence_id", "first_collected", "last_collected", "case", "host", "final_url",
    "pivot_kind", "pivot_value", "extraction_confidence",
    "estimative_likelihood", "analytic_confidence",
    "corroborated", "live_hits", "note", "source_file",
]


def _rows_from_result(result: dict, case: Optional[str], source_file: Optional[str]) -> list:
    """Flatten a result into one ledger row per pivot (first/last collected both = now;
    append_master carries the earlier first_collected forward on an update)."""
    m = result.get("meta", {})
    host = m.get("host") or ""
    final_url = m.get("final_url") or m.get("source") or ""
    now = _utc_now()
    rows = []
    for p in result.get("pivots", []) or []:
        kind = p.get("kind", "")
        value = "" if p.get("value") is None else str(p.get("value"))
        hits = _live_hits(p)
        corr = bool(hits)
        terms = estimative_terms(p.get("confidence"), corr)
        rows.append({
            "evidence_id": _evidence_id(host, kind, value, case or ""),
            "first_collected": now,
            "last_collected": now,
            "case": case or "",
            "host": host,
            "final_url": final_url,
            "pivot_kind": kind,
            "pivot_value": value,
            "extraction_confidence": (p.get("confidence") or "").lower(),
            "estimative_likelihood": terms["likelihood"],
            "analytic_confidence": terms["confidence"],
            "corroborated": "yes" if corr else "no",
            "live_hits": " | ".join(hits),
            "note": (p.get("note") or "").replace("\n", " ").strip(),
            "source_file": source_file or "",
        })
    return rows


def _read_existing_csv(path: str) -> "dict[str, dict]":
    existing = {}
    if not os.path.isfile(path):
        return existing
    with open(path, "r", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            eid = row.get("evidence_id")
            if eid:
                existing[eid] = row
    return existing


def _write_csv(path: str, rows_by_id: "dict[str, dict]") -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        # extrasaction="ignore" drops stray keys; restval="" fills any missing column.
        writer = csv.DictWriter(f, fieldnames=MASTER_COLUMNS, extrasaction="ignore",
                                restval="")
        writer.writeheader()
        for row in rows_by_id.values():
            writer.writerow(row)
    os.replace(tmp, path)  # atomic — never leave a half-written ledger


def _write_xlsx(path: str, rows_by_id: "dict[str, dict]") -> bool:
    try:
        from openpyxl import Workbook
    except Exception:
        return False
    wb = Workbook()
    ws = wb.active
    ws.title = "evidence"
    ws.append(MASTER_COLUMNS)
    for row in rows_by_id.values():
        ws.append([row.get(c, "") for c in MASTER_COLUMNS])
    ws.freeze_panes = "A2"
    wb.save(path)
    return True


def append_master(result: dict,
                  path: str = "evidence/master_pivots.csv",
                  case: Optional[str] = None,
                  source_file: Optional[str] = None) -> dict:
    """Append this run's pivots to a master evidence ledger, deduping on evidence_id.

    - Existing rows are read, merged with this run's rows (this run wins on collision so
      the latest collection state is reflected), and the whole file is rewritten. No row
      is ever silently dropped.
    - CSV via stdlib. If `path` ends in .xlsx and openpyxl is installed, an XLSX is
      written (a sibling .csv is always maintained too, so the ledger survives without
      openpyxl). Returns a small summary dict.
    """
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)

    new_rows = _rows_from_result(result, case, source_file)
    new_by_id = {r["evidence_id"]: r for r in new_rows}

    want_xlsx = path.lower().endswith(".xlsx")
    csv_path = (path[:-5] + ".csv") if want_xlsx else path

    merged = _read_existing_csv(csv_path)
    added = sum(1 for k in new_by_id if k not in merged)
    updated = sum(1 for k in new_by_id if k in merged)
    # This run's state wins on a repeat artifact, but preserve the ORIGINAL first_collected
    # (chain-of-custody: when the artifact was first observed) — only last_collected moves.
    for eid, row in new_by_id.items():
        prior = merged.get(eid)
        if prior and prior.get("first_collected"):
            row["first_collected"] = prior["first_collected"]
    merged.update(new_by_id)

    _write_csv(csv_path, merged)

    xlsx_written = False
    xlsx_path = None
    if want_xlsx:
        xlsx_written = _write_xlsx(path, merged)
        if xlsx_written:
            xlsx_path = path

    return {
        "csv": csv_path,
        "xlsx": xlsx_path,
        "xlsx_written": xlsx_written,
        "xlsx_requested": want_xlsx,
        "rows_added": added,
        "rows_updated": updated,
        "rows_total": len(merged),
    }


# =========================================================================== 3. MISP IOC bundle
_MISP_IDS_TYPES = {"domain", "ip-dst", "url", "x509-fingerprint-sha256", "btc", "xmr", "email-src"}


def render_misp_event(results, event_info: Optional[str] = None) -> dict:
    """Build a shareable MISP-event IOC bundle from one or many pivot_extract results.

    Maps artifacts to MISP attribute types (domain / ip-dst / x509-fingerprint-sha256 /
    btc / email-src / text / link), deduped, with registrar-privacy/boilerplate noise
    filtered out. Importable into MISP or convertible to STIX by MISP's own exporters."""
    if isinstance(results, dict):
        results = [results]
    attrs, seen = [], set()

    def add(t, v, cat, comment=""):
        v = str(v).strip().rstrip(".")
        if not v:
            return
        k = (t, v.lower())
        if k in seen:
            return
        seen.add(k)
        attrs.append({"type": t, "category": cat, "value": v,
                      "to_ids": t in _MISP_IDS_TYPES, "comment": comment})

    for r in results:
        host = (r.get("meta") or {}).get("host") or ""
        for p in r.get("pivots", []) or []:
            kind, val = p.get("kind", ""), p.get("value")
            if val is None or _is_noise_value(kind, val):
                continue
            if kind in ("domain", "urlscan_related_domain"):
                add("domain", val, "Network activity", f"{kind} ({host})")
            elif kind in ("urlscan_ip", "ip"):
                add("ip-dst", val, "Network activity", f"{kind} ({host})")
            elif kind == "tls_cert:fingerprint_sha256":
                add("x509-fingerprint-sha256", val, "Network activity", f"TLS cert ({host})")
            elif kind == "tls_cert:co_san":
                for apex in str(val).split(","):
                    add("domain", apex.strip(), "Network activity", f"co-SAN with {host}")
            elif kind == "favicon_hash":
                add("other", f"favicon-mmh3:{val}", "Payload delivery", f"favicon mmh3 ({host})")
            elif kind.startswith(("tracker:", "verification:", "saas:")):
                add("text", str(val), "External analysis", f"{kind} ({host})")
            elif kind.startswith("crypto:"):
                coin = kind.split(":", 1)[1]
                add({"btc": "btc", "xmr": "xmr"}.get(coin, "other"), val, "Financial fraud",
                    f"{kind} ({host})")
            elif kind == "email":
                add("email-src", val, "Payload delivery", f"contact/registrant ({host})")
            elif kind == "app:apk":
                add("url", val, "Payload delivery", f"APK download ({host})")
            elif kind == "app:signing_sha256":
                add("x509-fingerprint-sha256", val, "Payload delivery", f"APK signing cert ({host})")
            elif kind in ("app:android_package", "app:ios_app_id"):
                add("text", val, "Payload delivery", f"{kind} ({host})")
            elif kind.startswith("social:"):
                add("link", val, "External analysis", f"{kind} ({host})")

    hosts = sorted({(r.get("meta") or {}).get("host") for r in results
                    if (r.get("meta") or {}).get("host")})
    info = event_info or ("WebPivot IOCs — " + ", ".join(hosts[:5])
                          + (" …" if len(hosts) > 5 else ""))
    return {"Event": {"info": info, "date": _utc_now()[:10], "threat_level_id": "2",
                      "analysis": "2", "distribution": "0",
                      "Tag": [{"name": "source:WebPivot"}], "Attribute": attrs}}


# =========================================================================== CLI
def main():
    import argparse
    import glob
    import json
    import sys
    ap = argparse.ArgumentParser(
        description="Render an ICD-203 intelligence assessment from saved pivot_extract JSON.")
    ap.add_argument("json", nargs="+",
                    help="one host JSON (single-host report) or many/globbed JSONs (cluster report)")
    ap.add_argument("--cluster", action="store_true",
                    help="force the cluster report even for one file")
    ap.add_argument("--misp", metavar="PATH",
                    help="write a MISP-event IOC bundle (JSON) instead of a Markdown report")
    ap.add_argument("--case", default=None)
    ap.add_argument("--analyst", default=None,
                    help="accepted for backward compat but IGNORED — the analyst name is never "
                         "stamped on a deliverable (opsec / attribution leak)")
    ap.add_argument("--classification", default="UNCLASSIFIED//FOR OFFICIAL USE ONLY")
    ap.add_argument("-o", "--out", help="write the Markdown assessment here (else stdout)")
    a = ap.parse_args()

    paths = []
    for p in a.json:
        paths.extend(sorted(glob.glob(p)) if any(c in p for c in "*?[") else [p])
    results = []
    for p in paths:
        try:
            results.append(json.load(open(p, encoding="utf-8")))
        except Exception as e:
            print(f"[!] skip {p}: {e}", file=sys.stderr)
    if not results:
        sys.exit("no readable JSON inputs")

    if a.misp:
        event = render_misp_event(results, event_info=(f"WebPivot IOCs — {a.case}" if a.case else None))
        with open(a.misp, "w", encoding="utf-8") as f:
            json.dump(event, f, indent=2, ensure_ascii=False)
        print(f"[+] wrote MISP IOC bundle ({len(event['Event']['Attribute'])} attributes) -> {a.misp}",
              file=sys.stderr)
        return

    if a.cluster or len(results) > 1:
        md = render_cluster_report(results, case=a.case, classification=a.classification,
                                   analyst=a.analyst)
    else:
        md = render_cia_report(results[0], case=a.case, classification=a.classification,
                               analyst=a.analyst)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(md)
        print(f"[+] wrote assessment -> {a.out}", file=sys.stderr)
    else:
        print(md)


if __name__ == "__main__":
    main()
