#!/usr/bin/env python3
"""
case_timeline.py — the TEMPORAL view of a case: when each domain was registered, who held
it, which IPs hosted it when, which certificates covered it, and when it was observed alive.

WHY THIS EXISTS
---------------
A shared artifact only links two hosts if both carried it AT THE SAME TIME. A shared IP with
non-overlapping tenancy is a recycled address, not co-tenancy; a tracker id seen on one site in
2023 and another in 2026 is a resold kit, not one operator. Every same-operator claim is really
a claim about intervals, and intervals are what this tool extracts, draws and cross-checks:

  * registration span      created -> expires, per domain (WHOIS/RDAP)
  * registrant eras        who the record named, and between which dates (WHOIS history)
  * hosting windows        which IP served the name, time_first -> time_last (passive DNS)
  * certificate windows    not_before -> not_after, per logged cert (CT / live TLS)
  * archive visibility     first -> last Wayback capture, and per-artifact presence windows
  * point observations     WHOIS updates, urlscan scans, recovered snapshots, collection date

It then derives the correlations an analyst would otherwise eyeball: registration cohorts,
EXPIRY/renewal cohorts (the billing-account tell), certificate issuance batches, IP-tenancy
overlaps, and shared-artifact window overlaps.

EVIDENCE, NOT FILE PATHS
------------------------
Every emitted row carries `when` (UTC), `source`, an Admiralty grade and an ONLINE permalink —
Wayback snapshot, urlscan result, crt.sh cert id, RDAP record, BGP — minted from
`IntelGraph/references/evidence_sources.json`. A local `cases/<case>/out/*.json` path is our
collection record, never the citation: a reader must be able to re-check the claim without our
disk. Where no public link exists yet, archive the page first (`pivot_extract --archive-missing`)
and re-run.

USAGE
-----
  python3 case_timeline.py CASE/out/*.json --stem CASE/timeline \\
      --title "Infrastructure lifecycle — <n> domains" \\
      [--history CASE/out/wayback_*.json] [--markdown CASE/timeline.md] \\
      [--lang vi] [--source "..."] [--grading B2] [--no-figure]

Writes  <stem>_hires.png / <stem>.svg / <stem>_thumb.png   (figure, needs matplotlib)
        <stem>_events.json                                 (evidence ledger + correlations)
        <stem>.md  (with --markdown)                       (paste-ready evidence table)
"""
import argparse
import json
import os
import re
import sys
import urllib.parse
from collections import defaultdict
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ig_refs import load_ref, ref_path                       # noqa: E402

# Minimal embedded fallback — the real, extensible data lives in
# references/evidence_sources.json (contributor RULE 3). If you are reading THIS list in
# production output, the JSON failed to load and citations are degraded.
_EV_FALLBACK = {
    "permalink_templates": {
        "wayback_snapshot": {"label": "Wayback Machine snapshot",
                             "url": "https://web.archive.org/web/{timestamp}/{url}"},
        "urlscan_result": {"label": "urlscan.io scan result",
                           "url": "https://urlscan.io/result/{uuid}/"},
        "crtsh_cert": {"label": "crt.sh certificate", "url": "https://crt.sh/?id={cert_id}"},
        "rdap_domain": {"label": "RDAP domain record", "url": "https://rdap.org/domain/{host}"},
    },
    "source_grading": {"rdap": "A1", "certificate_transparency": "A1",
                       "passive_dns": "B2", "wayback": "B2"},
    "staleness": {"present_tense_max_age_days": 30, "recent_days": 90,
                  "cohort_window_hours": 24, "min_overlap_days": 7},
}
_EV = load_ref(ref_path(__file__, "evidence_sources.json"), _EV_FALLBACK)
TEMPLATES = _EV["permalink_templates"]
GRADING = _EV["source_grading"]
STALENESS = _EV["staleness"]

# figure track order (top to bottom inside one host lane) + house colours
TRACKS = ["registration", "registrant_era", "hosting", "cert", "archive_span", "artifact_window"]
TRACK_LABEL = {
    "registration": "registration (created → expires)",
    "registrant_era": "registrant era (WHOIS history)",
    "hosting": "hosting window (passive DNS)",
    "cert": "certificate validity (CT)",
    "archive_span": "archive visibility (Wayback)",
    "artifact_window": "artifact present (Wayback)",
}
TRACK_LABEL_VI = {
    "registration": "đăng ký tên miền (tạo → hết hạn)",
    "registrant_era": "giai đoạn chủ thể đăng ký (lịch sử WHOIS)",
    "hosting": "khoảng thời gian lưu trữ (passive DNS)",
    "cert": "hiệu lực chứng chỉ số (CT)",
    "archive_span": "phạm vi lưu trữ (Wayback)",
    "artifact_window": "dấu vết hiện diện trên trang (Wayback)",
}
OBSERVATION_LABEL = {"en": "observation (WHOIS update, capture, scan)",
                     "vi": "quan sát (cập nhật WHOIS, ảnh lưu trữ, lượt quét)"}
# archive visibility is a WEAKER kind of span than the others (a crawl schedule, not a record of
# control), so it is hatched rather than solid — the two pale tracks stay tellable apart in print.
HATCH = {"archive_span": "///"}
POINT_LABEL = {
    "whois_updated": "WHOIS updated",
    "wayback_capture": "archived capture",
    "urlscan_scan": "urlscan scan",
    "content_updated": "page self-declared update",
    "collection": "our collection",
    "expired": "registration lapsed",
}


# --------------------------------------------------------------------- time parsing
_MONTHS = {m: i + 1 for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"])}


def parse_dt(value):
    """Any timestamp this repo's collectors emit -> aware UTC datetime, or None.

    Handles ISO (with/without T, Z or offset), 'Jun  1 00:00:00 2026 GMT' (getpeercert),
    Wayback 14-digit stamps, plain YYYY-MM-DD, and epoch seconds (passive DNS COF).
    """
    if value in (None, "", "0"):
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    s = str(value).strip()
    if not s:
        return None
    if re.fullmatch(r"\d{9,13}", s):                      # epoch (s or ms)
        v = int(s)
        return parse_dt(v / 1000 if v > 10_000_000_000 else v)
    if re.fullmatch(r"\d{14}", s):                        # Wayback 20230225133742
        s = f"{s[:4]}-{s[4:6]}-{s[6:8]}T{s[8:10]}:{s[10:12]}:{s[12:14]}"
    if re.fullmatch(r"\d{8}", s):                         # Wayback day precision
        s = f"{s[:4]}-{s[4:6]}-{s[6:8]}"
    m = re.fullmatch(r"([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})\s*\w*", s)
    if m:                                                 # 'Jun  1 00:00:00 2026 GMT'
        mon = _MONTHS.get(m.group(1).lower())
        if mon:
            return datetime(int(m.group(6)), mon, int(m.group(2)), int(m.group(3)),
                            int(m.group(4)), int(m.group(5)), tzinfo=timezone.utc)
    s = s.replace("Z", "+00:00").replace(" UTC", "").replace(" GMT", "")
    try:
        dt = datetime.fromisoformat(s.replace(" ", "T", 1) if " " in s[:11] else s)
    except ValueError:
        try:
            dt = datetime.strptime(s[:10], "%Y-%m-%d")
        except ValueError:
            return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def iso(dt, day=False):
    if not dt:
        return None
    return dt.strftime("%Y-%m-%d") if day else dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------- permalinks
def permalink(key, **kw):
    """Mint an ONLINE evidence link from references/evidence_sources.json. None if the
    template is unknown or a placeholder is missing — never invent a link shape."""
    tpl = TEMPLATES.get(key)
    if not isinstance(tpl, dict) or not tpl.get("url"):
        return None
    safe = dict(kw)
    for k in ("url", "query"):
        if k in safe and safe[k]:
            safe[k] = urllib.parse.quote(str(safe[k]), safe=":/?&=%") if k == "url" \
                else urllib.parse.quote(str(safe[k]), safe="")
    try:
        return tpl["url"].format(**safe)
    except (KeyError, IndexError):
        return None


def grade(source_key):
    return GRADING.get(source_key, "F6")


# Where an evidence link points, for the ledger's link text. Keyed on the service host so a
# link minted anywhere (template, urlscan's own `result` field, a Wayback save) labels itself.
_LINK_NAMES = [("web.archive.org", "Wayback"), ("archive.ph", "archive.today"),
               ("urlscan.io", "urlscan"), ("crt.sh", "crt.sh"), ("rdap.org", "RDAP"),
               ("bgp.he.net", "BGP"), ("censys.io", "Censys"), ("shodan.io", "Shodan"),
               ("securitytrails.com", "SecurityTrails"), ("viewdns.info", "ViewDNS"),
               ("publicwww.com", "PublicWWW"), ("chainabuse.com", "Chainabuse")]


def link_name(url):
    netloc = urllib.parse.urlparse(url or "").netloc.lower()
    for needle, label in _LINK_NAMES:
        if needle in netloc:
            return label
    return netloc or "open"


def strip_www(host):
    """'www.example.com' -> 'example.com'. NOT lstrip('www.') — that eats leading w/./ chars
    off legitimate names ('world.example' -> 'orld.example')."""
    h = (host or "").strip().lower().rstrip(".")
    return h[4:] if h.startswith("www.") else h


def _ev(host, kind, start, end=None, label="", detail="", source="", url=None, value=None):
    """One timeline row. `start`/`end` are datetimes; `end=None` means a point event."""
    if not start:
        return None
    return {"host": host, "kind": kind, "start": iso(start), "end": iso(end),
            "_start": start, "_end": end, "label": label, "detail": detail,
            "source": source, "grading": grade(source), "url": url, "value": value}


# --------------------------------------------------------------------- extraction
def _host_of(analysis):
    meta = analysis.get("meta") or {}
    host = meta.get("host")
    if not host:
        src = meta.get("final_url") or meta.get("source") or ""
        host = urllib.parse.urlparse(src if "://" in src else "http://" + src).netloc
    return strip_www(host) or "unknown"


def _domain_pivot_results(analysis):
    """live_results blocks attached to the `domain` pivots of a pivot_extract result."""
    for piv in analysis.get("pivots") or []:
        if piv.get("kind") == "domain" and isinstance(piv.get("live_results"), dict):
            yield piv.get("value"), piv["live_results"]


def whois_events(host, whois, out):
    if not isinstance(whois, dict):
        return
    rdap = permalink("rdap_domain", host=host)
    created, expires = parse_dt(whois.get("created")), parse_dt(whois.get("expires"))
    if created:
        out.append(_ev(host, "registration", created, expires,
                       label="registered" + (f" · {whois['registrar']}" if whois.get("registrar") else ""),
                       detail=f"created {iso(created, day=True)}"
                              + (f" → expires {iso(expires, day=True)}" if expires else ""),
                       source="whois_registrar", url=rdap,
                       value={"registrar": whois.get("registrar"),
                              "term_days": (expires - created).days if expires else None}))
    if expires and expires < datetime.now(timezone.utc):
        out.append(_ev(host, "expired", expires, label="registration lapsed",
                       detail="expiry date passed with no later record — nobody renewed",
                       source="whois_registrar", url=rdap))
    upd = parse_dt(whois.get("updated"))
    if upd:
        out.append(_ev(host, "whois_updated", upd, label="WHOIS updated",
                       detail="registrar/registry record changed (NS, privacy, renewal…)",
                       source="whois_registrar", url=rdap,
                       value={"registrar": whois.get("registrar")}))

    # registrant eras from WHOIS history: each record's `updated` (else `created`) is when that
    # record was observed; the era runs to the next record's date. Day-precision at best — the
    # history API gives us record snapshots, not the moment of change.
    recs = []
    for r in ((whois.get("history") or {}).get("records") or []):
        when = parse_dt(r.get("updated")) or parse_dt(r.get("created"))
        if when:
            recs.append((when, r))
    recs.sort(key=lambda t: t[0])
    for i, (when, r) in enumerate(recs):
        ident = r.get("email") or r.get("name") or r.get("registrar")
        if not ident:
            continue
        if i and (recs[i - 1][1].get("email") or recs[i - 1][1].get("name")
                  or recs[i - 1][1].get("registrar")) == ident:
            continue                                   # same persona as the previous record
        nxt = next((recs[j][0] for j in range(i + 1, len(recs))
                    if (recs[j][1].get("email") or recs[j][1].get("name")
                        or recs[j][1].get("registrar")) != ident), None)
        out.append(_ev(host, "registrant_era", when, nxt or parse_dt(whois.get("expires")),
                       label=f"registrant: {ident}",
                       detail="self-declared registrant identity in the WHOIS record of the day"
                              " — a clustering key, not proof of ownership",
                       source="whois_history", url=rdap,
                       value={"identity": ident, "registrar": r.get("registrar")}))


def cert_events(host, analysis, out, max_certs=12):
    """CT-logged certificates + the live TLS cert. Returns the number dropped by max_certs."""
    dropped = 0
    seen = set()
    for _, lr in _domain_pivot_results(analysis):
        certs = ((lr.get("crtsh") or {}).get("certs")) or []
        for c in certs[:max_certs]:
            nb, na = parse_dt(c.get("not_before")), parse_dt(c.get("not_after"))
            if not nb:
                continue
            key = (c.get("id"), iso(nb))
            if key in seen:
                continue
            seen.add(key)
            issuer = (c.get("issuer") or "").replace("C=US, O=", "").split(",")[0].strip()
            names = c.get("names") or []
            out.append(_ev(host, "cert", nb, na,
                           label=f"cert [{issuer or 'unknown CA'}]",
                           detail=f"{len(names)} name(s): {', '.join(names[:4])}"
                                  + ("…" if len(names) > 4 else ""),
                           source="certificate_transparency",
                           url=permalink("crtsh_cert", cert_id=c["id"]) if c.get("id")
                               else permalink("crtsh_domain", query=host),
                           value={"issuer": issuer, "names": names, "serial": c.get("serial"),
                                  "crtsh_id": c.get("id")}))
        dropped += max(0, len(certs) - max_certs)
    tls = (analysis.get("artifacts") or {}).get("tls_cert")
    if isinstance(tls, dict) and not tls.get("error"):
        nb, na = parse_dt(tls.get("not_before")), parse_dt(tls.get("not_after"))
        fp = tls.get("fingerprint_sha256")
        if nb:
            out.append(_ev(host, "cert", nb, na,
                           label=f"live cert [{tls.get('issuer') or 'unknown CA'}]",
                           detail="certificate served by the host at collection time"
                                  + ("" if tls.get("validated") else " (did NOT validate)"),
                           source="tls_handshake",
                           url=permalink("crtsh_cert_sha256", sha256=fp) if fp else None,
                           value={"issuer": tls.get("issuer"), "fingerprint_sha256": fp,
                                  "sans": tls.get("sans")}))
    return dropped


def hosting_events(host, analysis, out):
    """Which IP served the name, and between which dates (passive-DNS COF records)."""
    for _, lr in _domain_pivot_results(analysis):
        for rec in ((lr.get("pdns") or {}).get("records") or []):
            if str(rec.get("rrtype", "")).upper() not in ("A", "AAAA"):
                continue
            rrname = str(rec.get("rrname") or "").rstrip(".").lower()
            rdata = str(rec.get("rdata") or "").rstrip(".").lower()
            # COF instances differ on which side holds the IP — route by shape, not field.
            ip = next((v for v in (rdata, rrname) if _looks_ip(v)), None)
            name = next((v for v in (rrname, rdata) if v and not _looks_ip(v)), host)
            first, last = parse_dt(rec.get("time_first")), parse_dt(rec.get("time_last"))
            if not (ip and first):
                continue
            out.append(_ev(name or host, "hosting", first, last,
                           label=f"hosted at {ip}",
                           detail=f"passive DNS: {rec.get('count') or '?'} observation(s)"
                                  f" {iso(first, day=True)} → {iso(last, day=True) if last else 'open'}",
                           source="passive_dns", url=permalink("bgp_he_ip", ip=ip),
                           value={"ip": ip, "rrtype": str(rec.get("rrtype")).upper()}))


def _looks_ip(v):
    return bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", v or "")) or (
        bool(v) and ":" in v and " " not in v)


def observation_events(host, analysis, out, observed, hosts):
    """Point observations: recovered snapshots, urlscan scans, self-declared page dates, us."""
    meta = analysis.get("meta") or {}
    src_url = meta.get("final_url") or meta.get("source") or f"https://{host}/"

    rec = str(meta.get("recovered_via") or "")
    m = re.match(r"wayback:(\d{8,14})", rec)
    if m:
        ts = m.group(1)
        out.append(_ev(host, "wayback_capture", parse_dt(ts),
                       label="page recovered from archive",
                       detail="the live site did not serve us this content — every artifact "
                              "extracted from it is dated to the CAPTURE, not to today",
                       source="wayback",
                       url=permalink("wayback_snapshot", timestamp=ts, url=src_url)))
    snap = ((analysis.get("archives") or {}).get("wayback") or {}).get("snapshot")
    if snap:
        ts = (re.search(r"/web/(\d{8,14})", snap) or [None, None])[1]
        out.append(_ev(host, "wayback_capture", parse_dt(ts) or observed,
                       label="snapshot we created",
                       detail="page archived on demand so the claim stays checkable after takedown",
                       source="wayback", url=snap))

    for scan in ((analysis.get("related_urlscan") or {}).get("recent_scans") or []):
        when = parse_dt(scan.get("time"))
        shost = strip_www(urllib.parse.urlparse(scan.get("url") or "").netloc)
        if not when or (shost and shost not in hosts):
            continue                                   # keep lanes to the case's own hosts
        out.append(_ev(shost or host, "urlscan_scan", when,
                       label="urlscan scan",
                       detail="third-party capture with the resolved IP + TLS chain of that day; "
                              "scan cadence reflects who submitted, not site activity",
                       source="urlscan", url=scan.get("result")))

    pmeta = (analysis.get("artifacts") or {}).get("meta") or {}
    for key in ("og:updated_time", "article:modified_time", "article:published_time"):
        when = parse_dt(pmeta.get(key))
        if when:
            out.append(_ev(host, "content_updated", when, label=f"page {key}",
                           detail="self-declared by the page itself — trivially forged, use only "
                                  "to date content relative to the site's own claims",
                           source="page_self_declared_date", url=src_url))
    out.append(_ev(host, "collection", observed, label="collected by us",
                   detail="when this host's artifacts were captured into the case",
                   source="live_dns", url=permalink("urlscan_domain", host=host)))


def history_events(hist, out):
    """wayback_ga.py output → archive-visibility span + per-artifact presence windows."""
    host = strip_www(hist.get("domain"))
    if not host:
        return
    span = hist.get("span") or []
    if len(span) == 2 and span[0]:
        first, last = parse_dt(span[0]), parse_dt(span[1])
        out.append(_ev(host, "archive_span", first, last,
                       label=f"archived {hist.get('snapshots_total', 0)}×",
                       detail="first → last Wayback capture. A gap is a CRAWL gap: absence of a "
                              "capture is not evidence the site was down",
                       source="wayback", url=permalink("wayback_calendar", host=host)))
    for rec in hist.get("pivots") or hist.get("historical_ids") or []:
        first = parse_dt(rec.get("first_seen") or rec.get("first"))
        last = parse_dt(rec.get("last_seen") or rec.get("last"))
        val = rec.get("value")
        if not (first and val):
            continue
        out.append(_ev(host, "artifact_window", first, last,
                       label=f"{rec.get('kind')} = {val}",
                       detail=f"present in {rec.get('hits')} capture(s) — the window in which this "
                              "artifact could have linked this host to another",
                       source="wayback", url=permalink("wayback_calendar", host=host),
                       value={"kind": rec.get("kind"), "value": val}))


# --------------------------------------------------------------------- correlation
def _day(e, field="_start"):
    return e[field].strftime("%Y-%m-%d") if e.get(field) else None


def correlate(events):
    """The temporal reads an analyst would otherwise do by eye. Every entry names the hosts,
    the dates and the caveat that could kill it — a cohort is a LEAD until the caveat is closed."""
    out = {}
    reg = [e for e in events if e["kind"] == "registration"]

    # 1) registration cohorts — one provisioning sitting
    by_created = defaultdict(list)
    for e in reg:
        by_created[_day(e)].append(e)
    out["registration_cohorts"] = [
        {"date": d, "hosts": sorted({e["host"] for e in g}),
         "registrars": sorted({(e.get("value") or {}).get("registrar") or "?" for e in g}),
         "reading": "registered on one day = one sitting; strongest when the set is small and "
                    "thematically coherent, weakest when a registrar bulk promo explains it"}
        for d, g in sorted(by_created.items()) if d and len({e["host"] for e in g}) > 1]

    # 2) expiry cohorts — the billing-account tell. Same expiry from DIFFERENT creation days is
    #    a deliberate renewal alignment (someone consolidated the bill); same expiry because the
    #    domains were created the same day is ONE fact restated, not a second signal.
    by_exp = defaultdict(list)
    for e in reg:
        if e.get("_end"):
            by_exp[_day(e, "_end")].append(e)
    cohorts = []
    for d, g in sorted(by_exp.items()):
        hosts = sorted({e["host"] for e in g})
        if len(hosts) < 2:
            continue
        created = {_day(e) for e in g}
        terms = {(e.get("value") or {}).get("term_days") for e in g}
        cohorts.append({
            "expires": d, "hosts": hosts, "distinct_creation_days": sorted(x for x in created if x),
            "independent_signal": len(created) > 1,
            "term_days": sorted(t for t in terms if t),
            "reading": ("expiry aligned across DIFFERENT registration dates — a renewal decision "
                        "made once, for all of them, by one payer") if len(created) > 1 else
                       ("same expiry only because they share a creation date + term — this is the "
                        "registration cohort restated, do not count it twice")})
    out["expiry_cohorts"] = cohorts

    # 3) WHOIS-update cohorts — one config change… unless one registrar did it to its whole book
    by_upd = defaultdict(list)
    for e in events:
        if e["kind"] == "whois_updated":
            by_upd[_day(e)].append(e)
    out["whois_update_cohorts"] = [
        {"date": d, "hosts": sorted({e["host"] for e in g}),
         "registrars": sorted({(e.get("value") or {}).get("registrar") or "?" for e in g}),
         "reading": "same-day WHOIS update across DIFFERENT registrars is an operator action; "
                    "across ONE registrar it is more likely a registrar-side event (system "
                    "migration, DNSSEC, bulk privacy toggle) — discount it"}
        for d, g in sorted(by_upd.items()) if d and len({e["host"] for e in g}) > 1]

    # 4) certificate issuance batches — one ACME run provisions a fleet in minutes
    window = timedelta(hours=float(STALENESS.get("cohort_window_hours", 24)))
    certs = sorted([e for e in events if e["kind"] == "cert"], key=lambda e: e["_start"])
    batches, cur = [], []
    for e in certs:
        if cur and e["_start"] - cur[0]["_start"] > window:
            batches.append(cur)
            cur = []
        cur.append(e)
    if cur:
        batches.append(cur)
    out["cert_batches"] = [
        {"from": iso(b[0]["_start"]), "to": iso(b[-1]["_start"]),
         "hosts": sorted({e["host"] for e in b}),
         "issuers": sorted({(e.get("value") or {}).get("issuer") or "?" for e in b}),
         "links": [e["url"] for e in b if e.get("url")][:6],
         "reading": "certificates issued inside one window across several hosts = one "
                    "provisioning run on one machine; check the issuer/profile matches before "
                    "asserting — a shared CA with 90-day auto-renewal syncs unrelated sites too"}
        for b in batches if len({e["host"] for e in b}) > 1]

    # 5) IP tenancy — co-tenancy is an OVERLAP claim, not a shared-value claim
    by_ip = defaultdict(list)
    for e in events:
        if e["kind"] == "hosting" and (e.get("value") or {}).get("ip"):
            by_ip[e["value"]["ip"]].append(e)
    min_overlap = timedelta(days=float(STALENESS.get("min_overlap_days", 7)))
    tenancy = []
    for ip, g in sorted(by_ip.items()):
        hosts = sorted({e["host"] for e in g})
        if len(hosts) < 2:
            continue
        pairs = []
        for i in range(len(g)):
            for j in range(i + 1, len(g)):
                a, b = g[i], g[j]
                if a["host"] == b["host"]:
                    continue
                lo = max(a["_start"], b["_start"])
                hi = min(a["_end"] or a["_start"], b["_end"] or b["_start"])
                days = (hi - lo).days
                pairs.append({"hosts": [a["host"], b["host"]],
                              "overlap_days": days if days > 0 else 0,
                              "overlap": [iso(lo, day=True), iso(hi, day=True)] if days > 0 else None,
                              "verdict": "co-tenant" if timedelta(days=max(days, 0)) >= min_overlap
                                         else ("brief overlap" if days > 0 else
                                               "sequential tenancy — NOT co-tenancy")})
        tenancy.append({
            "ip": ip, "hosts": hosts, "link": permalink("bgp_he_ip", ip=ip), "pairs": pairs,
            "reading": "two names on one IP only co-tenant if their windows OVERLAP; sequential "
                       "tenancy means the address was recycled. And even a real overlap is noise "
                       "on a CDN edge or shared-host IP — classify the IP before you assert"})
    out["ip_tenancy"] = tenancy

    # 6) shared artifacts — did the two hosts carry it AT THE SAME TIME?
    by_val = defaultdict(list)
    for e in events:
        if e["kind"] == "artifact_window":
            by_val[(e["value"]["kind"], e["value"]["value"])].append(e)
    shared = []
    for (kind, val), g in sorted(by_val.items(), key=lambda kv: str(kv[0])):
        hosts = sorted({e["host"] for e in g})
        if len(hosts) < 2:
            continue
        lo = max(e["_start"] for e in g)
        hi = min((e["_end"] or e["_start"]) for e in g)
        days = (hi - lo).days
        shared.append({"artifact": f"{kind}={val}", "hosts": hosts,
                       "contemporaneous": days > 0,
                       "overlap": [iso(lo, day=True), iso(hi, day=True)] if days > 0 else None,
                       "overlap_days": max(days, 0),
                       "reading": "the artifact was on both hosts at once — the link is "
                                  "contemporaneous" if days > 0 else
                                  "the windows do NOT overlap — consistent with a resold/copied "
                                  "kit or a recycled account, not with one live operator"})
    out["shared_artifact_windows"] = shared

    # 7) abandonment — a fleet that stops being paid for on the same date
    lapses = defaultdict(list)
    for e in events:
        if e["kind"] == "expired":
            lapses[_day(e)].append(e["host"])
    out["lapse_cohorts"] = [
        {"date": d, "hosts": sorted(set(h)),
         "reading": "registrations lapsed together = one payer stopped paying; this dates the END "
                    "of the campaign as precisely as a registration cohort dates its start"}
        for d, h in sorted(lapses.items()) if d and len(set(h)) > 1]
    return out


# --------------------------------------------------------------------- outputs
def markdown(events, corr, title, observed):
    """Paste-ready evidence table: when · host · what · source · ONLINE link."""
    L = [f"# {title}", "",
         f"_Timeline compiled {iso(observed, day=True)} (UTC). Every row is cited to a public "
         "source; links resolve without access to the case store._", "",
         "## Evidence ledger", "",
         "| When (UTC) | Host | What | Source (Admiralty) | Evidence link |",
         "|---|---|---|---|---|"]
    for e in sorted(events, key=lambda x: x["_start"]):
        when = iso(e["_start"], day=True) + (f" → {iso(e['_end'], day=True)}" if e.get("_end") else "")
        link = f"[{link_name(e['url'])}]({e['url']})" if e.get("url") else "—"
        what = e["label"] + (f" — {e['detail']}" if e.get("detail") else "")
        L.append(f"| {when} | `{e['host']}` | {what} | {e['source']} ({e['grading']}) | {link} |")

    L += ["", "## Temporal correlations", ""]
    labels = {"registration_cohorts": "Registration cohorts (one provisioning sitting)",
              "expiry_cohorts": "Expiry / renewal cohorts (one payer)",
              "whois_update_cohorts": "Same-day WHOIS updates",
              "cert_batches": "Certificate issuance batches",
              "ip_tenancy": "IP tenancy overlap",
              "shared_artifact_windows": "Shared artifacts — contemporaneous?",
              "lapse_cohorts": "Abandonment cohorts"}
    for key, heading in labels.items():
        rows = corr.get(key) or []
        L.append(f"### {heading}")
        if not rows:
            L += ["", "_Nothing found. That is a finding only if the inputs carried the dates to "
                  "find it in — check the ledger above before reading this as a negative._", ""]
            continue
        L.append("")
        for r in rows:
            head = r.get("date") or r.get("expires") or r.get("ip") or r.get("artifact") or \
                r.get("from") or "—"
            L.append(f"- **{head}** — {', '.join(r.get('hosts', []))}")
            for k in ("overlap", "overlap_days", "contemporaneous", "independent_signal",
                      "distinct_creation_days", "registrars", "issuers", "term_days", "verdict"):
                if k in r and r[k] not in (None, [], ""):
                    L.append(f"  - {k}: {r[k]}")
            for p in r.get("pairs", []):
                L.append(f"  - {' ↔ '.join(p['hosts'])}: {p['verdict']}"
                         + (f" ({p['overlap_days']}d, {p['overlap'][0]} → {p['overlap'][1]})"
                            if p.get("overlap") else ""))
            if r.get("link"):
                L.append(f"  - link: {r['link']}")
            L.append(f"  - _{r['reading']}_")
        L.append("")
    return "\n".join(L)


def render(events, stem, title, subtitle=None, lang="en", source="", grading="", date="",
           max_lanes=24):
    """Swimlane: one lane per host, one sub-track per interval kind, markers for point events."""
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    from matplotlib.patches import Patch
    from matplotlib.lines import Line2D
    from theme import apply_theme, PALETTE, caption, save_dual, title_block
    apply_theme(lang=lang)

    colors = {"registration": PALETTE["sand"], "registrant_era": PALETTE["ochre"],
              "hosting": PALETTE["primary"], "cert": PALETTE["olive"],
              "archive_span": PALETTE["grid"], "artifact_window": PALETTE["slate"]}
    first_seen = {}
    for e in events:
        first_seen.setdefault(e["host"], e["_start"])
        first_seen[e["host"]] = min(first_seen[e["host"]], e["_start"])
    hosts = sorted(first_seen, key=lambda h: first_seen[h])
    dropped_lanes = hosts[max_lanes:]
    hosts = hosts[:max_lanes]
    lane = {h: i for i, h in enumerate(reversed(hosts))}

    present = [k for k in TRACKS if any(e["kind"] == k for e in events)]
    offs = {k: 0.34 - i * (0.68 / max(len(present) - 1, 1)) for i, k in enumerate(present)} \
        if len(present) > 1 else {k: 0.0 for k in present}
    height = min(0.5, 0.62 / max(len(present), 1))

    lane_h = 0.16 * len(present) + 0.30          # taller lanes when more tracks are stacked
    fig, ax = plt.subplots(figsize=(12.5, max(3.4, lane_h * len(hosts) + 2.4)))
    ax.grid(axis="x")
    ax.grid(axis="y", visible=False)
    now = datetime.now(timezone.utc)
    for e in events:
        if e["host"] not in lane:
            continue
        y = lane[e["host"]] + offs.get(e["kind"], 0.0)
        if e["kind"] in colors:
            start = mdates.date2num(e["_start"])
            end = mdates.date2num(e["_end"] or e["_start"] + timedelta(days=1))
            ax.barh(y, max(end - start, 0.75), left=start, height=height,
                    color=colors[e["kind"]], edgecolor=PALETTE["slate"], linewidth=0.4,
                    hatch=HATCH.get(e["kind"]),
                    alpha=0.95 if e["kind"] != "archive_span" else 0.8)
        else:                                     # point observation — its own strip under the bars
            ax.plot(mdates.date2num(e["_start"]), lane[e["host"]] - 0.45, marker="d",
                    markersize=5, color=PALETTE["brick"], zorder=5)
    ax.axvline(mdates.date2num(now), color=PALETTE["muted"], linewidth=0.9, linestyle=":", zorder=1)
    ax.text(mdates.date2num(now), len(hosts) - 0.4, " bây giờ" if lang == "vi" else " now",
            fontsize=8, color=PALETTE["muted"], va="top")

    ax.set_yticks(range(len(hosts)))
    ax.set_yticklabels([h for h in reversed(hosts)], fontsize=9)
    ax.set_ylim(-0.7, len(hosts) - 0.3)
    ax.xaxis_date()
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m"))
    fig.autofmt_xdate(rotation=30, ha="right")
    names = TRACK_LABEL_VI if lang == "vi" else TRACK_LABEL
    handles = [Patch(facecolor=colors[k], edgecolor=PALETTE["slate"], hatch=HATCH.get(k),
                     label=names.get(k, TRACK_LABEL[k])) for k in present]
    if any(e["kind"] not in colors for e in events):
        handles.append(Line2D([], [], marker="d", linestyle="none", color=PALETTE["brick"],
                              label=OBSERVATION_LABEL.get(lang, OBSERVATION_LABEL["en"])))
    # legend below the rotated date axis — the offset scales with figure height so it clears the
    # tick labels on a 2-lane figure and does not float away on a 20-lane one
    gap = -min(0.30, 1.25 / fig.get_figheight())
    ax.legend(handles=handles, loc="upper left", bbox_to_anchor=(0, gap), ncol=2,
              frameon=False, fontsize=8.5)
    title_block(ax, title, subtitle)
    caption(fig, source, grading, date or iso(now, day=True), lang)
    outs = save_dual(fig, stem)
    plt.close(fig)
    return outs, dropped_lanes


# --------------------------------------------------------------------- CLI
def main():
    ap = argparse.ArgumentParser(
        description="Build the temporal view of a case from pivot_extract JSON: registration, "
                    "registrant eras, hosting windows, certificate validity, archive visibility "
                    "— with an online-cited evidence ledger and the derived cohorts/overlaps.")
    ap.add_argument("inputs", nargs="+", help="pivot_extract JSON files (out/*.json)")
    ap.add_argument("--stem", required=True, help="output path without extension")
    ap.add_argument("--history", nargs="*", default=[],
                    help="wayback_ga.py JSON — adds archive spans + artifact presence windows")
    ap.add_argument("--title", default="Infrastructure lifecycle")
    ap.add_argument("--subtitle", default=None)
    ap.add_argument("--markdown", nargs="?", const="", default=None,
                    help="also write the evidence table as markdown (default <stem>.md)")
    ap.add_argument("--observed", help="collection date YYYY-MM-DD (default: input file mtime)")
    ap.add_argument("--max-certs", type=int, default=12,
                    help="newest N certs per host (default 12); the rest are counted, not hidden")
    ap.add_argument("--max-lanes", type=int, default=24, help="hosts drawn in the figure")
    ap.add_argument("--lang", default="en", choices=["en", "vi"])
    ap.add_argument("--source", default="", help="caption source line")
    ap.add_argument("--grading", default="", help="caption Admiralty grading")
    ap.add_argument("--no-figure", action="store_true", help="ledger + correlations only")
    args = ap.parse_args()

    analyses, hosts = [], set()
    for p in args.inputs:
        try:
            d = json.load(open(p, encoding="utf-8"))
        except Exception as exc:
            print(f"  skip {p}: {exc}", file=sys.stderr)
            continue
        for a in (d if isinstance(d, list) else [d]):
            if isinstance(a, dict) and (a.get("artifacts") or a.get("pivots")):
                a["_mtime"] = os.path.getmtime(p)
                analyses.append(a)
                hosts.add(_host_of(a))
    if not analyses:
        print("no pivot_extract JSON could be read — nothing to time", file=sys.stderr)
        return 2

    events, dropped_certs = [], 0
    for a in analyses:
        host = _host_of(a)
        observed = parse_dt(args.observed) or datetime.fromtimestamp(a["_mtime"], tz=timezone.utc)
        whois_events(host, (a.get("artifacts") or {}).get("whois"), events)
        dropped_certs += cert_events(host, a, events, max_certs=args.max_certs)
        hosting_events(host, a, events)
        observation_events(host, a, events, observed, hosts)
    for p in args.history:
        try:
            h = json.load(open(p, encoding="utf-8"))
        except Exception as exc:
            print(f"  history skipped {p}: {exc}", file=sys.stderr)
            continue
        for rec in (h if isinstance(h, list) else [h]):
            history_events(rec, events)
    events = [e for e in events if e]
    if not events:
        print("no dated facts in these inputs — collect WHOIS/CT/passive DNS first "
              "(pivot_extract --whois; a keyless run still yields RDAP dates + CT)", file=sys.stderr)
        return 3

    corr = correlate(events)
    observed_now = datetime.now(timezone.utc)

    outs = []
    dropped_lanes = []
    if not args.no_figure:
        try:
            outs, dropped_lanes = render(events, args.stem, args.title, args.subtitle,
                                         lang=args.lang, source=args.source,
                                         grading=args.grading, max_lanes=args.max_lanes)
        except ImportError as exc:
            print(f"[figure skipped] matplotlib unavailable ({exc}) — ledger still written",
                  file=sys.stderr)

    ledger = os.path.abspath(args.stem) + "_events.json"
    os.makedirs(os.path.dirname(ledger), exist_ok=True)
    payload = {
        "meta": {"title": args.title, "compiled": iso(observed_now),
                 "hosts": sorted(hosts), "events": len(events),
                 "certs_omitted_by_max_certs": dropped_certs,
                 "hosts_omitted_from_figure": dropped_lanes,
                 "collection_record": [os.path.basename(p) for p in args.inputs],
                 "citation_rule": "every event carries an online source link; local case-store "
                                  "paths are collection provenance, never the citation"},
        "events": [{k: v for k, v in e.items() if not k.startswith("_")}
                   for e in sorted(events, key=lambda x: x["_start"])],
        "correlations": corr,
    }
    with open(ledger, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    outs.append(ledger)

    if args.markdown is not None:
        md_path = args.markdown or (args.stem + ".md")
        with open(md_path, "w", encoding="utf-8") as fh:
            fh.write(markdown(events, corr, args.title, observed_now))
        outs.append(md_path)

    print(f"timeline: {len(events)} dated facts across {len(hosts)} host(s)", file=sys.stderr)
    for key, rows in corr.items():
        if rows:
            print(f"  {key}: {len(rows)}", file=sys.stderr)
    if dropped_certs:
        print(f"  note: {dropped_certs} older cert(s) omitted by --max-certs "
              f"{args.max_certs} (raise it to see the full issuance chain)", file=sys.stderr)
    if dropped_lanes:
        print(f"  note: {len(dropped_lanes)} host(s) not drawn (--max-lanes): "
              f"{', '.join(dropped_lanes[:6])}…", file=sys.stderr)
    for o in outs:
        print(o)
    return 0


if __name__ == "__main__":
    sys.exit(main())
