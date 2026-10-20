#!/usr/bin/env python3
"""wp_related — the reporting contract for certificate-transparency status and pivot hits, shared
by every renderer (evidence_report, house_report, build_report_data) so they cannot drift apart.

CT STATUS
---------
`ct_of(raw)` pulls the CT block a collection recorded (the domain pivot's `live_results.crtsh`, or
`meta.capability.ct`) and `ct_md(...)` renders it: one completeness line plus each source's status
and observation window. A collection made before per-source status existed reads as "CT status not
recorded" — never as "no certificates". A degraded CT with no rows is never "no certificates".

RELATED HOSTS (UNVERIFIED)
--------------------------
`related_hosts(raw)` turns every artifact-reverse hit (a host sharing a certificate fingerprint,
favicon hash or tracking ID with the target, found by FOFA / Shodan / urlscan / Validin / Hunter.how
/ Quake / ZoomEye / DNSLytics / Censys) into a row: host, IP, engine, the SHARED value, the scan date,
and which origin checks passed:
  (1) host_header — the IP serves the target's content for `Host: <target>` (same body hash); an
      active request, so only /cert-pivot's live run fills it; otherwise `not run`
  (2) cert_san    — the shared value is the target's own leaf certificate, it is not CDN-managed and
      its SANs include the target
  (3) history     — the target's own passive DNS / passive SSL / DNS history shows it on that IP
  (4) non_cdn     — the IP is outside CDN / WAF / parking ranges
One agreeing check = LOW lead, two = MEDIUM probable origin, three or more = HIGH. A related host is
NEVER rendered under hosting and never becomes an abuse / takedown recipient: hosting and abuse come
only from the target's own resolution and origin history (evidence_report / house_report sections).
IP-reverse co-hosting (neighbours) is not a pivot hit and is not listed here.
"""
import ipaddress
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wp_refs import ref_path, load_ref  # noqa: E402

_FALLBACK = {"related_hosts": {
    "rungs": ["related (unverified)", "lead (LOW)", "probable origin (MEDIUM)", "origin (HIGH)",
              "origin (HIGH)"],
    "cdn_cert_issuer_markers": ["cloudflare"], "max_rows": 40, "probe_max_ips": 5,
    "probe_timeout_seconds": 15,
    "edge_rung": "edge / non-routable address (CDN, WAF, parking, bogon) — not an origin"}}
CFG = load_ref(ref_path(__file__, "ct_sources.json"), _FALLBACK)["related_hosts"]

CHECKS = ("host_header", "cert_san", "history", "non_cdn")
CHECK_LABELS = {"host_header": "(1) serves target for Host header", "cert_san": "(2) non-CDN cert names target",
                "history": "(3) target's pDNS/pSSL history", "non_cdn": "(4) outside CDN ranges"}

# live_results key → engine label. Artifact reverses only: an IP reverse on the domain pivot is
# co-tenancy (neighbours), and JARM hits are a shared TLS stack — neither is a shared VALUE.
_HIT_KEYS = {"fofa": "FOFA", "hunterhow": "Hunter.how", "quake": "Quake", "zoomeye": "ZoomEye",
             "urlscan": "urlscan", "validin_cert": "Validin", "validin_favicon": "Validin",
             "shodan_search": "Shodan", "censys_cert": "Censys (co-listed names)",
             "dnslytics": "DNSLytics"}
_DATE_KEYS = ("timestamp", "time", "updated_at", "update_time", "last_seen", "first_seen", "date",
              "scan_date", "seen")


# ------------------------------------------------------------------ CT status
def ct_of(raw):
    """The CT block of one collection: the domain pivot's live crtsh result, else the
    meta.capability.ct summary, else None (CT never ran or pre-dates per-source status)."""
    for p in (raw or {}).get("pivots") or []:
        if isinstance(p, dict) and p.get("kind") == "domain":
            c = (p.get("live_results") or {}).get("crtsh")
            if isinstance(c, dict) and c:
                return c
    cap = (((raw or {}).get("meta") or {}).get("capability") or {}).get("ct")
    return cap if isinstance(cap, dict) and cap else None


def ct_summary(ct):
    """→ {completeness, completeness_line, sources{src:{status,window,n}}, cert_total, truncated}
    for a CT block, or a `not recorded` stub for a pre-contract collection."""
    if not ct:
        return None
    st = ct.get("ct_status") or ct.get("sources") or {}
    if not isinstance(st, dict) or not st:
        return {"completeness": "unknown", "sources": {},
                "cert_total": ct.get("cert_total", ct.get("cert_count")),
                "completeness_line": ("CT source status not recorded — completeness unknown, "
                                      "not 'no certificates'")}
    return {"completeness": ct.get("completeness"), "completeness_line": ct.get("completeness_line"),
            "sources": {s: {"status": v.get("status"), "window": v.get("window"), "n": v.get("n", 0)}
                        for s, v in st.items()},
            "cert_total": ct.get("cert_total"), "truncated": bool(ct.get("truncated"))}


def ct_md(summaries):
    """{host: ct_summary} → markdown lines: one completeness line per host, and a per-source table
    for every host whose history is not complete (a full crt.sh answer needs no table)."""
    rows = [(h, s) for h, s in sorted(summaries.items()) if s]
    if not rows:
        return []
    out = ["| Host | Certificates | Completeness |", "|:--|--:|:--|"]
    for h, s in rows:
        n = s.get("cert_total")
        out.append(f"| `{h}` | {n if n is not None else '—'} | {s.get('completeness_line') or '—'} |")
    out.append("")
    gaps = [(h, s) for h, s in rows if s.get("completeness") not in ("full", None) and s.get("sources")]
    for h, s in gaps:
        out += [f"Per-source status — `{h}`:", "",
                "| Source | Status | Certificates | Observation window |", "|:--|:--|--:|:--|"]
        for src, v in s["sources"].items():
            out.append(f"| {src} | {v.get('status')} | {v.get('n', 0)} | {v.get('window') or '—'} |")
        out.append("")
    return out


def ct_gap_lines(summaries):
    """One intelligence-gap sentence per host whose CT history is incomplete or unrecorded."""
    out = []
    for h, s in sorted(summaries.items()):
        if s and s.get("completeness") not in ("full", None):
            unq = sorted(k for k, v in (s.get("sources") or {}).items()
                         if str(v.get("status")).startswith("skipped")
                         or v.get("status") in ("failed", "degraded"))
            out.append(f"Certificate history for {h}: {s.get('completeness_line')}"
                       + (f" (unqueried / failed: {', '.join(unq)})" if unq else "") + ".")
    return out


# ------------------------------------------------------------------ related hosts
def _date(row):
    if isinstance(row, dict):
        for k in _DATE_KEYS:
            v = row.get(k)
            if v:
                return str(v)[:10]
        task = row.get("task") if isinstance(row.get("task"), dict) else {}
        if task.get("time"):
            return str(task["time"])[:10]
    return None


def _host_ip(key, row):
    """(host, ip) from one engine row, whatever its shape."""
    if isinstance(row, (list, tuple)):          # FOFA: [host, ip, domain, title, …]
        host = (row[2] if len(row) > 2 and row[2] else row[0]) if row else ""
        ip = row[1] if len(row) > 1 else None
    elif isinstance(row, dict):
        page = row.get("page") if isinstance(row.get("page"), dict) else {}
        hn = row.get("hostnames")
        host = (page.get("domain") or row.get("domain") or row.get("host") or row.get("name")
                or row.get("value") or (hn[0] if isinstance(hn, list) and hn else ""))
        ip = page.get("ip") or row.get("ip") or row.get("ip_str")
    else:
        host, ip = str(row or ""), None
    host = str(host or "").lower().split("//")[-1].split("/")[0].strip(".")
    try:                                         # a bare IP in a hostname slot is an IP row
        return None, str(ipaddress.ip_address(host.strip("[]")))
    except ValueError:
        pass
    if host.count(":") == 1:                      # host:port
        host = host.split(":")[0]
    return host, (str(ip) if ip else None)


def _rows_of(key, blk):
    if key == "censys_cert":
        return [n for n in blk.get("names") or [] if n]
    return blk.get("results") or blk.get("hosts") or blk.get("matches") or blk.get("domains") or []


def _cdn_cert(issuer):
    s = str(issuer or "").lower()
    return any(m in s for m in CFG["cdn_cert_issuer_markers"])


def _classify(ip):
    try:
        import wp_origin_history as OH  # noqa: PLC0415
        return OH.classify(ip).get("status")
    except Exception:  # noqa: BLE001
        return None


def _history_ips(raw):
    try:
        import wp_origin_history as OH  # noqa: PLC0415
        _h, _r, rows = OH.host_origins(raw)
    except Exception:  # noqa: BLE001
        return {}
    return {r["ip"]: sorted(r.get("sources") or []) for r in rows if r.get("ip")}


def _san_covers(san, host):
    """A SAN names `host` exactly, or is a wildcard one label above it."""
    s = str(san or "").lower().rstrip(".")
    if s.startswith("*."):
        rest = host.split(".", 1)
        return len(rest) == 2 and rest[1] == s[2:]
    return s == host


def grade(checks):
    """checks{name: 'pass'|'fail'|'not run'|'n/a'} → (passed[], rung label). An address check (4)
    classifies as a CDN / WAF / parking edge is never an origin, however many other checks agree: an
    edge serves the target's content and certificate by design."""
    passed = [c for c in CHECKS if checks.get(c) == "pass"]
    if checks.get("non_cdn") == "fail":
        return passed, CFG["edge_rung"]
    rungs = CFG["rungs"]
    return passed, rungs[min(len(passed), len(rungs) - 1)]


def related_hosts(raw, case_hosts=(), skip=None):
    """Every artifact-reverse hit in one pivot_extract collection → graded related-host rows.
    `case_hosts` (and the target itself) are excluded; `skip(host)` drops infra noise."""
    meta = (raw or {}).get("meta") or {}
    target = str(meta.get("host") or "").lower()
    art = (raw or {}).get("artifacts") or {}
    leaf = art.get("tls_cert") if isinstance(art.get("tls_cert"), dict) else {}
    leaf_fps = {str(leaf.get(k) or "").lower() for k in ("fingerprint_sha256", "fingerprint_sha1")} - {""}
    leaf_ok = (bool(leaf_fps) and not _cdn_cert(leaf.get("issuer"))
               and any(_san_covers(n, target) for n in leaf.get("sans") or []))
    history = _history_ips(raw)
    excluded = {str(h).lower() for h in case_hosts} | {target}
    rows, seen = [], {}
    for p in (raw or {}).get("pivots") or []:
        if not isinstance(p, dict) or p.get("kind") == "domain":
            continue
        kind, value = str(p.get("kind") or ""), p.get("value")
        if "jarm" in kind.lower():
            continue
        lr = p.get("live_results") or {}
        probe = lr.get("origin_probe") if isinstance(lr.get("origin_probe"), dict) else {}
        is_leaf = str(value or "").lower() in leaf_fps
        for key, engine in _HIT_KEYS.items():
            blk = lr.get(key)
            if not isinstance(blk, dict):
                continue
            if key == "shodan_search" and "cert" not in kind.lower():
                continue
            for row in _rows_of(key, blk):
                host, ip = _host_ip(key, row)
                if (not (host or ip) or host in excluded or (host and host.endswith("." + target))
                        or (skip and host and skip(host))):
                    continue                     # the target's own names are its estate, not related
                ident = (host or ip, ip, kind, str(value))
                if ident in seen:
                    seen[ident]["engines"].add(engine)
                    continue
                checks = {c: "n/a" for c in CHECKS}
                if ip:
                    pr = probe.get(ip) or {}
                    checks["host_header"] = ("pass" if pr.get("match") else
                                             "fail" if pr.get("ran") else "not run")
                    if "cert" in kind.lower():
                        checks["cert_san"] = "pass" if (is_leaf and leaf_ok) else "fail"
                    checks["history"] = "pass" if ip in history else "fail"
                    cls = _classify(ip)
                    checks["non_cdn"] = ("pass" if cls == "origin" else "fail" if cls else "not run")
                passed, rung = grade(checks)
                r = {"host": host or None, "ip": ip, "target": target, "engines": {engine},
                     "shared_kind": kind, "shared_value": value, "scan_date": _date(row),
                     "checks": checks, "passed": passed, "rung": rung,
                     "history_sources": history.get(ip, []) if ip else []}
                seen[ident] = r
                rows.append(r)
    for r in rows:
        r["engines"] = sorted(r["engines"])
    rows.sort(key=lambda r: (-len(r["passed"]), r["host"] or "", r["ip"] or ""))
    return rows


def related_md(rows, max_rows=None):
    """Graded related-host rows → the "Related hosts (unverified)" markdown section body."""
    if not rows:
        return []
    cap = int(max_rows or CFG["max_rows"])
    out = ["Hosts that share a value with the target. A shared value makes a host RELATED, not the "
           "target's server or its origin: only agreeing origin checks promote one, and none of these "
           "addresses is a hosting provider or takedown recipient for the target.", "",
           "| Host | IP | Shares with | Shared value | Engine | Scan date | Origin checks passed | Rung |",
           "|:--|:--|:--|:--|:--|:--|:--|:--|"]
    for r in rows[:cap]:
        val = str(r.get("shared_value") or "")
        val = val if len(val) <= 24 else val[:20] + "…"
        passed = "; ".join(CHECK_LABELS[c] for c in r["passed"]) or "none"
        out.append(f"| {('`' + r['host'] + '`') if r.get('host') else '—'} | {r.get('ip') or '—'} | "
                   f"`{r.get('target') or '—'}` | {r.get('shared_kind')} `{val}` | "
                   f"{', '.join(r['engines'])} | {r.get('scan_date') or 'undated'} | {passed} | "
                   f"{r['rung']} |")
    if len(rows) > cap:
        out.append(f"| … | | | | | | | {len(rows) - cap} more in the JSON |")
    out.append("")
    return out
