#!/usr/bin/env python3
"""
wp_takedown.py — TAKEDOWN / RELOCATION WATCH: was this domain held, suspended or deleted, and
where did the kit move to?

WHAT IT DOES
------------
For each domain (or every collected apex of a case, read-only from cases/<id>/raw/*.json):

  1. **RDAP status** (keyless, whois_enrich.rdap_lookup) — the EPP status set. clientHold /
     serverHold = held (the name is pulled from the zone); redemptionPeriod / pendingDelete =
     deleted; serverDeleteProhibited & friends count only AFTER a hold (the takedown lock).
     `held_since` comes from the RDAP events (basis reported beside the date — RDAP has no
     dedicated hold event, so it is usually `last changed`).
  2. **DNS** — NXDOMAIN, no NS delegation, or a sinkhole / registry-hold nameserver.
  3. **Successor hunt** (held / suspended / deleted, or `--hunt`) — the last known origin IPs
     (case origin history → HackerTarget hostsearch → live A), CDN / parking / bogon edges
     skipped, keyless HackerTarget reverse-IP for the co-tenants, then each co-tenant's live
     page compared with the held domain's LAST CAPTURE (case raw, else Wayback): favicon mmh3,
     DOM skeleton ("body") and distinctive <title>.

RULE 5 — every successor is a LEAD. A shared IP alone is co-tenancy (`rung: lead`); a content
match raises it only to a KIT sibling (`rung: kit`) — same kit, never the same owner, never a KB
edge. Patterns, limits and caveat text: WebPivot/references/takedown.json.

Tri-state, never raises: each step yields a dict, None (not applicable) or {"error"|"skipped"}.

CLI:
    python3 WebPivot/tools/wp_takedown.py <domain> [more ...] [--case ID] [--ip IP ...]
        [--hunt] [--no-wayback] [--no-fetch] [--timeout N] [--proxy URL] [--json]
"""
from __future__ import annotations

import glob
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from urllib.parse import urljoin

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
from wp_refs import ref_path, load_ref  # noqa: E402

ENGINE = os.path.dirname(os.path.dirname(HERE))

_TAKEDOWN_FALLBACK = {
    "epp_status": {"held": ["clienthold", "serverhold"], "suspended": [],
                   "deleted": ["redemptionperiod", "pendingdelete"]},
    "lock_after_hold": {"values": ["serverdeleteprohibited"]},
    "held_since_events": {"values": ["last changed"]},
    "sinkhole_ns": {"suffixes": [], "substrings": ["sinkhole"]},
    "skip_reverse_ip_status": {"values": ["cdn", "parking", "bogon", "invalid"]},
    "limits": {"max_ips": 2, "max_candidates": 10, "max_cotenant_list": 30, "http_timeout": 15},
    "caveats": {
        "co_tenant": "Shared IP only — co-tenancy, not an operator link (RULE 5).",
        "kit": "Same {match} as the held domain's last capture — kit sibling, not owner (RULE 5)."},
}
_REF = load_ref(ref_path(__file__, "takedown.json"), _TAKEDOWN_FALLBACK)


def _vals(key):
    v = _REF.get(key) or {}
    return [str(x).lower() for x in (v.get("values") if isinstance(v, dict) else v) or []]


EPP = {k: {str(x).lower() for x in (_REF.get("epp_status") or {}).get(k) or []}
       for k in ("held", "suspended", "deleted")}
LOCK_AFTER_HOLD = set(_vals("lock_after_hold"))
HELD_SINCE_EVENTS = _vals("held_since_events")
_SINK = _REF.get("sinkhole_ns") or {}
SINK_SUFFIXES = [str(x).lower().strip(".") for x in _SINK.get("suffixes") or []]
SINK_SUBSTRINGS = [str(x).lower() for x in _SINK.get("substrings") or []]
SKIP_IP_STATUS = set(_vals("skip_reverse_ip_status"))
LIMITS = dict(_TAKEDOWN_FALLBACK["limits"], **(_REF.get("limits") or {}))
CAVEATS = dict(_TAKEDOWN_FALLBACK["caveats"], **(_REF.get("caveats") or {}))
TAKEDOWN_STATES = ("held", "suspended", "deleted")
_MATCH_RANK = ("favicon", "body", "title")      # strongest first


def _norm_status(s):
    return re.sub(r"[\s_\-]+", "", str(s or "")).lower()


# ------------------------------------------------------------------ network indirections
# Module-level so a smoke run can stub them; each returns dict | None | {"error"}.
def _rdap(domain):
    try:
        import whois_enrich
        return whois_enrich.rdap_lookup(domain, keep_raw=True)
    except Exception as e:  # noqa: BLE001
        return {"error": f"{type(e).__name__}: {e}", "source": "rdap"}


def _dns(domain):
    """{'rcode','ns','a'} via dig (rcode NOERROR/NXDOMAIN/SERVFAIL…), socket fallback without dig."""
    out = {"rcode": None, "ns": [], "a": []}
    if shutil.which("dig"):
        try:
            r = subprocess.run(["dig", "+time=5", "+tries=1", "NS", domain],
                               capture_output=True, text=True, timeout=15)
            m = re.search(r"status:\s*([A-Z]+)", r.stdout or "")
            out["rcode"] = m.group(1) if m else None
            for ln in (r.stdout or "").splitlines():
                p = ln.split()
                if len(p) >= 5 and not ln.startswith(";") and p[3].upper() == "NS":
                    out["ns"].append(p[4].rstrip(".").lower())
        except Exception as e:  # noqa: BLE001
            out["error"] = f"dig: {e}"
    try:
        out["a"] = sorted(set(socket.gethostbyname_ex(domain)[2]))
        out["rcode"] = out["rcode"] or "NOERROR"
    except socket.gaierror as e:
        if out["rcode"] is None and e.errno in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", -5)):
            out["rcode"] = "NXDOMAIN"
    except Exception:  # noqa: BLE001
        pass
    out["ns"] = sorted(set(out["ns"]))
    return out


def _hostsearch(domain):
    try:
        from wp_recon import passivedns_search
        return passivedns_search(domain)
    except Exception as e:  # noqa: BLE001
        return {"error": f"{type(e).__name__}: {e}"}


def _reverse_ip(ip):
    try:
        from wp_recon import reverseip_search
        return reverseip_search(ip)
    except Exception as e:  # noqa: BLE001
        return {"error": f"{type(e).__name__}: {e}"}


def _ip_class(ip):
    try:
        import wp_origin_history
        return wp_origin_history.classify(ip)
    except Exception as e:  # noqa: BLE001
        return {"status": "undetermined", "why": f"{type(e).__name__}: {e}"}


def _apex(host):
    try:
        import wp_origin_history
        return wp_origin_history._apex(host) or ""
    except Exception:  # noqa: BLE001
        p = str(host or "").lower().strip(".").split(".")
        return ".".join(p[-2:]) if len(p) >= 2 else ""


def _fingerprint(html, base_host=None):
    """title (distinctive only) + DOM skeleton sha1 of an HTML document."""
    try:
        from wp_extract import TITLE_RE, dom_skeleton_hash
        from wp_pivots import _distinctive_title
    except Exception as e:  # noqa: BLE001
        return {"error": f"{type(e).__name__}: {e}"}
    m = TITLE_RE.search(html or "")
    raw_title = re.sub(r"\s+", " ", m.group(1)).strip() if m else None
    return {"title": raw_title,
            "title_distinctive": _distinctive_title(raw_title, base_host) if raw_title else None,
            "dom_skeleton_sha1": dom_skeleton_hash(html or "")}


def _favicon_mmh3(fav_url, proxy=None, timeout=None):
    try:
        from wp_net import fetch
        from wp_hash import shodan_favicon_hash
        _, status, headers, raw = fetch(fav_url, timeout=timeout or LIMITS["http_timeout"], proxy=proxy)
    except Exception:  # noqa: BLE001
        return None
    ctype = str((headers or {}).get("content-type") or "").lower()
    if status != 200 or not raw or "html" in ctype:
        return None
    return shodan_favicon_hash(raw)


def _favicon_href(html):
    try:
        from wp_extract import FAVICON_RE, HREF_IN_TAG_RE
    except Exception:  # noqa: BLE001
        return None
    m = FAVICON_RE.search(html or "")
    h = HREF_IN_TAG_RE.search(m.group(0)) if m else None
    return h.group(1) if h else None


def _page(host, proxy=None, timeout=None):
    """Live homepage fingerprint {url,title,title_distinctive,dom_skeleton_sha1,favicon_mmh3}."""
    try:
        from wp_net import fetch
    except Exception as e:  # noqa: BLE001
        return {"error": f"{type(e).__name__}: {e}"}
    last = None
    for scheme in ("https", "http"):
        try:
            final, status, _h, body = fetch(f"{scheme}://{host}/", timeout=timeout or LIMITS["http_timeout"],
                                            proxy=proxy)
        except Exception as e:  # noqa: BLE001
            last = f"{type(e).__name__}: {e}"
            continue
        html = body.decode("utf-8", "ignore") if isinstance(body, (bytes, bytearray)) else str(body or "")
        if not html.strip():
            last = f"HTTP {status} empty body"
            continue
        fp = _fingerprint(html, host)
        if fp.get("error"):
            return fp
        fp["url"], fp["http_status"] = final, status
        fp["favicon_mmh3"] = _favicon_mmh3(urljoin(final, _favicon_href(html) or "/favicon.ico"),
                                           proxy=proxy, timeout=timeout)
        return fp
    return {"error": last or "no response"}


def _wayback_baseline(domain, proxy=None, timeout=None):
    """Last Wayback capture of the homepage → fingerprint, or None (never archived) / {'error'}."""
    try:
        import wp_wayback
        from wp_net import fetch, wayback_raw_url
        snap, ts, err = wp_wayback.closest(f"http://{domain}/")
    except Exception as e:  # noqa: BLE001
        return {"error": f"{type(e).__name__}: {e}"}
    if err:
        return {"error": f"wayback: {err}"}
    if not snap:
        return None
    try:
        _, status, _h, body = fetch(wayback_raw_url(snap), timeout=timeout or 30, proxy=proxy)
    except Exception as e:  # noqa: BLE001
        return {"error": f"wayback fetch: {e}"}
    html = body.decode("utf-8", "ignore") if isinstance(body, (bytes, bytearray)) else str(body or "")
    if status != 200 or not html.strip():
        return {"error": f"wayback capture HTTP {status}"}
    fp = _fingerprint(html, domain)
    if fp.get("error"):
        return fp
    m = re.search(r"/web/\d+[a-z_]*/(.+)$", snap)
    orig = m.group(1) if m else f"http://{domain}/"
    fav = urljoin(orig, _favicon_href(html) or "/favicon.ico")
    fp["favicon_mmh3"] = _favicon_mmh3(f"https://web.archive.org/web/{ts}id_/{fav}", proxy=proxy,
                                       timeout=timeout)
    fp.update(source="wayback", captured_at=str(ts), snapshot=snap)
    return fp


# ------------------------------------------------------------------ status
def _held_since(raw_rdap):
    ev = {}
    for e in (raw_rdap or {}).get("events") or []:
        if isinstance(e, dict) and e.get("eventDate"):
            ev[str(e.get("eventAction") or "").lower()] = e["eventDate"]
    for act in HELD_SINCE_EVENTS:
        if ev.get(act):
            return ev[act], f"rdap_event:{act}"
    return None, None


def _sinkhole(ns):
    hits = []
    for n in ns or []:
        n = n.lower().rstrip(".")
        if any(n == s or n.endswith("." + s) for s in SINK_SUFFIXES) or any(s in n for s in SINK_SUBSTRINGS):
            hits.append(n)
    return hits


def assess_status(domain, rdap, dns):
    """(status, signals[], held_since, held_since_basis, epp_status[]) from an RDAP dict and a DNS dict."""
    signals, states = [], set()
    epp = list((rdap or {}).get("status") or []) if isinstance(rdap, dict) and not rdap.get("error") else []
    norm = {_norm_status(s): s for s in epp}
    for state in ("held", "suspended", "deleted"):
        for n, orig in norm.items():
            if n in EPP[state]:
                states.add(state)
                signals.append(f"epp:{orig}")
    if "held" in states or "suspended" in states:
        signals += [f"epp_lock_after_hold:{norm[n]}" for n in norm if n in LOCK_AFTER_HOLD]
    rdap_missing = False
    if isinstance(rdap, dict) and rdap.get("error"):
        err = str(rdap["error"])
        rdap_missing = "404" in err or "not found" in err.lower()
        signals.append("rdap:not_found" if rdap_missing else f"rdap:error:{err[:80]}")
    dns = dns if isinstance(dns, dict) else {}
    rcode, ns = dns.get("rcode"), dns.get("ns") or []
    if rcode == "NXDOMAIN":
        signals.append("dns:nxdomain")
    elif rcode and rcode != "NOERROR":
        signals.append(f"dns:{rcode.lower()}")
    if rcode == "NOERROR" and not ns:
        signals.append("dns:no_ns")
    sink = _sinkhole(ns)
    if sink:
        states.add("suspended")
        signals += [f"ns:sinkhole:{n}" for n in sink]
    if "deleted" in states or (rdap_missing and rcode == "NXDOMAIN"):
        status = "deleted"
    elif "suspended" in states:
        status = "suspended"
    elif "held" in states:
        status = "held"
    elif isinstance(rdap, dict) and not rdap.get("error") and rcode == "NOERROR" and ns:
        status = "active"
    else:
        status = "unknown"
    held_since = basis = None
    if status in TAKEDOWN_STATES and isinstance(rdap, dict):
        held_since, basis = _held_since(rdap.get("_raw"))
    return status, signals, held_since, basis, epp


# ------------------------------------------------------------------ case input (read-only)
def _case_dir(case_id):
    return os.path.join(os.environ.get("INTEL_HOME") or ENGINE, "cases", case_id)


def case_apexes(case_dir):
    """{apex: {'ips': [rows], 'baseline': dict|None}} from a case's domain raws (read-only)."""
    try:
        import wp_origin_history
    except Exception:  # noqa: BLE001
        wp_origin_history = None
    out = {}
    for path in sorted(glob.glob(os.path.join(case_dir, "raw", "*.json"))):
        try:
            with open(path, encoding="utf-8") as fh:
                obj = json.load(fh)
        except Exception:  # noqa: BLE001
            continue
        meta = obj.get("meta") or {}
        host = str(meta.get("host") or "").lower().strip(".")
        if not host or meta.get("kind") == "ip" or re.fullmatch(r"[\d.]+|[0-9a-f:]+", host):
            continue
        apex = _apex(host)
        if not apex:
            continue
        slot = out.setdefault(apex, {"ips": [], "baseline": None, "_hosts": set()})
        slot["_hosts"].add(host)
        if wp_origin_history is not None:
            try:
                _h, _reg, rows = wp_origin_history.host_origins(obj)
            except Exception:  # noqa: BLE001
                rows = []
            for r in rows:
                slot["ips"].append({"ip": r.get("ip"), "source": "case:" + ",".join(r.get("sources") or []),
                                    "first_seen": r.get("first_seen"), "last_seen": r.get("last_seen"),
                                    "live": bool(r.get("live"))})
        art = obj.get("artifacts") or {}
        fav = art.get("favicon") if isinstance(art.get("favicon"), dict) else {}
        base = {"source": "case_raw", "host": host, "captured_at": meta.get("collected_at"),
                "title": art.get("title") or None, "dom_skeleton_sha1": art.get("dom_skeleton_sha1"),
                "favicon_mmh3": fav.get("shodan_mmh3")}
        try:
            from wp_pivots import _distinctive_title
            base["title_distinctive"] = _distinctive_title(base["title"], host) if base["title"] else None
        except Exception:  # noqa: BLE001
            base["title_distinctive"] = None
        has = any(base.get(k) is not None for k in ("title_distinctive", "dom_skeleton_sha1", "favicon_mmh3"))
        prev = slot["baseline"]
        if has and (prev is None or host in (apex, "www." + apex)):
            slot["baseline"] = base
    for slot in out.values():
        slot.pop("_hosts", None)
    return out


# ------------------------------------------------------------------ successor hunt
def _last_ips(domain, dns, case_rows, extra_ips):
    rows, seen = [], set()

    def add(ip, source, **kw):
        if ip and ip not in seen:
            seen.add(ip)
            rows.append(dict({"ip": ip, "source": source}, **kw))

    for ip in extra_ips or []:
        add(ip, "analyst")
    newest = sorted(case_rows or [], key=lambda r: str(r.get("last_seen") or ""), reverse=True)
    for r in sorted(newest, key=lambda r: not r.get("live")):          # live first, then newest
        add(r.get("ip"), r.get("source") or "case", first_seen=r.get("first_seen"),
            last_seen=r.get("last_seen"))
    for ip in (dns or {}).get("a") or []:
        add(ip, "live_dns")
    if len(rows) < LIMITS["max_ips"]:
        hs = _hostsearch(domain)
        if isinstance(hs, dict) and not hs.get("error"):
            for h in hs.get("hosts") or []:
                if str(h.get("host") or "").lower().strip(".") in (domain, "www." + domain):
                    add(h.get("ip"), "hackertarget_hostsearch")
    return rows[:int(LIMITS["max_ips"])]


def _compare(base, cand):
    matches = []
    if not (isinstance(base, dict) and isinstance(cand, dict)) or cand.get("error"):
        return matches
    try:
        from wp_extract import BOILERPLATE_FAVICON_MMH3
    except Exception:  # noqa: BLE001
        BOILERPLATE_FAVICON_MMH3 = set()
    bf, cf = base.get("favicon_mmh3"), cand.get("favicon_mmh3")
    if bf is not None and bf == cf and int(bf) not in BOILERPLATE_FAVICON_MMH3:
        matches.append("favicon")
    if base.get("dom_skeleton_sha1") and base["dom_skeleton_sha1"] == cand.get("dom_skeleton_sha1"):
        matches.append("body")
    bt, ct = base.get("title_distinctive"), cand.get("title_distinctive")
    if bt and ct and bt.casefold() == ct.casefold():
        matches.append("title")
    return [m for m in _MATCH_RANK if m in matches]


def hunt_successors(domain, ips, baseline, fetch_pages=True, proxy=None, timeout=None):
    """(successors[], ip_report[]) — co-tenants on the last known IPs, content-compared to baseline."""
    held_apex = _apex(domain) or domain
    ip_report, cands = [], {}
    for row in ips:
        ip = row["ip"]
        cls = _ip_class(ip) or {}
        rep = dict(row, ip_class=cls.get("status"), ip_class_why=cls.get("why"))
        if cls.get("status") in SKIP_IP_STATUS:
            rep["reverse_ip"] = {"skipped": f"{cls.get('status')} address — co-tenants are strangers"}
            ip_report.append(rep)
            continue
        rv = _reverse_ip(ip)
        if not isinstance(rv, dict) or rv.get("error"):
            rep["reverse_ip"] = {"error": (rv or {}).get("error", "no answer")}
            ip_report.append(rep)
            continue
        rep["reverse_ip"] = {"source": "hackertarget", "total": rv.get("total", len(rv.get("domains") or []))}
        ip_report.append(rep)
        for name in rv.get("domains") or []:
            ap = _apex(name)
            if not ap or ap == held_apex:
                continue
            cands.setdefault(ap, {"hosts": set(), "ips": set()})
            cands[ap]["hosts"].add(name)
            cands[ap]["ips"].add(ip)
    base_ok = isinstance(baseline, dict) and not baseline.get("error") and any(
        baseline.get(k) is not None for k in ("favicon_mmh3", "dom_skeleton_sha1", "title_distinctive"))
    successors = []
    for i, ap in enumerate(sorted(cands)):
        if i >= int(LIMITS["max_cotenant_list"]):
            break
        c = cands[ap]
        s = {"domain": ap, "shared_ip": sorted(c["ips"])[0], "shared_ips": sorted(c["ips"]),
             "hosts_seen": sorted(c["hosts"])[:5], "content_match": "none", "content_matches": [],
             "checked": False, "first_seen": None, "first_seen_basis": "undated (reverse-IP carries no date)"}
        if fetch_pages and base_ok and i < int(LIMITS["max_candidates"]):
            host = ap if ap in c["hosts"] or not c["hosts"] else sorted(c["hosts"])[0]
            page = _page(host, proxy=proxy, timeout=timeout)
            s["checked"] = True
            if isinstance(page, dict) and page.get("error"):
                s["fetch_error"] = page["error"]
            ms = _compare(baseline, page)
            if ms:
                s["content_match"], s["content_matches"] = ms[0], ms
        elif not base_ok:
            s["not_checked_reason"] = "no last-capture fingerprint for the held domain"
        if s["content_match"] != "none":
            s.update(rung="kit", relation="kit_sibling",
                     caveat=CAVEATS["kit"].format(match=s["content_match"]))
            rd = _rdap(ap)
            if isinstance(rd, dict) and not rd.get("error") and rd.get("created"):
                s["first_seen"], s["first_seen_basis"] = rd["created"], "rdap_registration"
        else:
            s.update(rung="lead", relation="co_tenant", caveat=CAVEATS["co_tenant"])
        successors.append(s)
    successors.sort(key=lambda s: (s["rung"] != "kit", s["domain"]))
    return successors, ip_report


# ------------------------------------------------------------------ driver
def watch(domain, *, case_slot=None, extra_ips=None, hunt=False, wayback=True, fetch_pages=True,
          proxy=None, timeout=None):
    domain = str(domain or "").strip().lower().strip(".")
    if "://" in domain:
        domain = domain.split("://", 1)[1]
    domain = domain.split("/", 1)[0]
    rdap = _rdap(domain)
    dns = _dns(domain)
    status, signals, held_since, basis, epp = assess_status(domain, rdap, dns)
    row = {"domain": domain, "status": status, "signals": signals, "held_since": held_since,
           "held_since_basis": basis, "epp_status": epp,
           "nameservers": (dns or {}).get("ns") or [], "dns_rcode": (dns or {}).get("rcode"),
           "registrar": rdap.get("registrar") if isinstance(rdap, dict) else None,
           "successors": [], "last_ips": [], "baseline": None}
    if not (hunt or status in TAKEDOWN_STATES):
        row["successor_hunt"] = {"skipped": f"status {status} — pass --hunt to look anyway"}
        return row
    baseline = (case_slot or {}).get("baseline")
    if baseline is None and wayback:
        baseline = _wayback_baseline(domain, proxy=proxy, timeout=timeout)
    row["baseline"] = baseline
    ips = _last_ips(domain, dns, (case_slot or {}).get("ips"), extra_ips)
    if not ips:
        row["successor_hunt"] = {"skipped": "no last known IP (case history, hostsearch, live DNS all empty)"}
        return row
    row["successors"], row["last_ips"] = hunt_successors(domain, ips, baseline, fetch_pages=fetch_pages,
                                                         proxy=proxy, timeout=timeout)
    row["successor_hunt"] = {"candidates": len(row["successors"]),
                             "kit_siblings": sum(1 for s in row["successors"] if s["rung"] == "kit")}
    return row


def run(domains=(), case=None, **kw):
    slots, case_dir = {}, None
    if case:
        case_dir = _case_dir(case) if not os.path.isdir(case) else case
        if not os.path.isdir(case_dir):
            return {"tool": "takedown_watch", "case": case, "error": f"case directory not found: {case_dir}"}
        slots = case_apexes(case_dir)
    targets = list(dict.fromkeys([str(d).strip().lower() for d in domains if str(d).strip()] + sorted(slots)))
    if not targets:
        return {"tool": "takedown_watch", "case": case, "error": "no domains given and none collected in the case"}
    rows = [watch(d, case_slot=slots.get(_apex(d) or d) or slots.get(d), **kw) for d in targets]
    return {"tool": "takedown_watch", "case": case, "domains": rows,
            "summary": {s: sum(1 for r in rows if r["status"] == s)
                        for s in ("active", "held", "suspended", "deleted", "unknown")},
            "caveat": "Status is registry/DNS fact. Successors are LEADS (RULE 5): shared IP = co-tenancy; "
                      "content match = kit sibling only — never an owner edge or operator attribution."}


def _main():
    import argparse
    ap = argparse.ArgumentParser(description="Takedown / relocation watch: RDAP hold status, DNS sinkhole/"
                                             "NXDOMAIN, and successor domains on the last known IPs.")
    ap.add_argument("domains", nargs="*", help="domain(s) to check")
    ap.add_argument("--case", default=None, help="case id (or path): check every collected apex, read-only")
    ap.add_argument("--ip", action="append", default=[], help="extra last-known IP to reverse (repeatable)")
    ap.add_argument("--hunt", action="store_true", help="hunt successors even when the domain is active")
    ap.add_argument("--no-wayback", action="store_true", help="no Wayback baseline when the case has none")
    ap.add_argument("--no-fetch", action="store_true", help="list co-tenants without fetching their pages")
    ap.add_argument("--timeout", type=int, default=None)
    ap.add_argument("--proxy", default=None)
    ap.add_argument("--json", action="store_true", help="emit JSON")
    a = ap.parse_args()
    out = run(a.domains, case=a.case, extra_ips=a.ip, hunt=a.hunt, wayback=not a.no_wayback,
              fetch_pages=not a.no_fetch, proxy=a.proxy, timeout=a.timeout)
    if a.json or out.get("error"):
        print(json.dumps(out, indent=2, ensure_ascii=False, default=str))
        return
    for r in out["domains"]:
        print(f"\n{r['domain']}  →  {r['status'].upper()}"
              + (f"  (since {r['held_since']} · {r['held_since_basis']})" if r["held_since"] else ""))
        print(f"  signals : {', '.join(r['signals']) or '-'}")
        print(f"  ns      : {', '.join(r['nameservers']) or '-'}  ·  rcode {r['dns_rcode']}")
        for ipr in r["last_ips"]:
            print(f"  ip      : {ipr['ip']} [{ipr.get('ip_class')}] via {ipr['source']} → {ipr.get('reverse_ip')}")
        for s in r["successors"]:
            print(f"  {s['rung']:<4}    : {s['domain']} on {s['shared_ip']} match={s['content_match']}")
        if r.get("successor_hunt", {}).get("skipped"):
            print(f"  hunt    : skipped — {r['successor_hunt']['skipped']}")
    print(f"\n{out['caveat']}")


if __name__ == "__main__":
    _main()
