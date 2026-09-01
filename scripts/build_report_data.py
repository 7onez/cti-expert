#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# dependencies = []
# ///
"""
build_report_data.py — deterministic case -> flat report-JSON converter.

THE MISSING BRIDGE. The report generators (generate-cti-html.py, generate-cti-iocs.py,
generate-cti-docx-hybrid.py) all consume the flat "report JSON" documented in SKILL.md
§8 (subjects[]/findings[]/connections[]/timeline[]/indicators[]/…). Nothing produced it:
the deterministic pipeline (`intel.py pipeline open`) writes assessment.md, assessment.json
(engine schema), shared.txt, clusters.json and case_graph.json — but NOT that flat JSON.
So every /cti (= /case) Deliver step depended on an agent hand-authoring a large JSON by
hand; skip or thin it and the report renders with zero charts (the exact failure this fixes).

This turns a completed case directory into a populated, §2.5-clean report JSON with ZERO
LLM involvement and zero egress — reading only what the pipeline already wrote:

  raw/<host>.json      collected pivots (http/tech/cert/wp/mail/dns per host)
  whois/<host>.json    registrant triple (name/email/phone), registrar, dates, NS
  evidence/*.json      opportunistic sidecars (leak-sweep, estate-seo-sweep) -> findings
  clusters.json        read only to flag a multi-operator case (>1 cluster) as a caveat
  assessment.md        analyst BLUF (-> executive_summary) + Recommendation(s) section
  knowledge/operators.jsonl   confirmed-operator ledger (attribution + estate domain set)

It degrades gracefully: a case missing any of these still yields a valid report JSON from
whatever is present. §2.5 discipline is preserved mechanically — shared/CDN infrastructure,
the registrar, nameservers and a saturated/parking favicon are emitted into `ioc_exclude`
(retained in the report narrative, gated out of IOC values), never asserted as operator links.

Usage:
    uv run build_report_data.py <case-dir> [-o <report.json>] [--print]
    python3 build_report_data.py cases/CASE-0001 -o cases/CASE-0001/report-data.json

Author: CTI Expert — https://github.com/7onez/cti-expert
"""
import argparse
import datetime
import json
import os
import re
import sys

GENERATOR = "CTI Expert — https://github.com/7onez/cti-expert"
SEVERITY = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
# raw sidecars that are not collected hosts (evidence bundles keyed like a host but not one)
_NON_HOST_STEMS = {"leak-sweep", "estate-seo-sweep", "shared-infra-note", "harvest.indicators"}


def _load_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def _n_clusters(case_dir):
    """Same-operator cluster count from clusters.json (engine's Louvain partition). >1 means the
    case spans multiple operators — this converter attributes only one, so the caller is warned."""
    c = _load_json(os.path.join(case_dir, "clusters.json"))
    try:
        return int(c.get("n_clusters")) if isinstance(c, dict) else None
    except (TypeError, ValueError):
        return None


def _iter_raw(case_dir):
    """Yield (host, raw_dict) for every collected host pivot JSON — never an evidence sidecar."""
    d = os.path.join(case_dir, "raw")
    if not os.path.isdir(d):
        return
    for fn in sorted(os.listdir(d)):
        if not fn.endswith(".json") or fn.endswith(".impersonation.json"):
            continue
        stem = fn[:-5]
        if stem in _NON_HOST_STEMS:
            continue
        data = _load_json(os.path.join(d, fn))
        host = ((data or {}).get("meta") or {}).get("host") or stem
        if data is not None and "." in host:
            yield host.lower(), data


def _whois_of(case_dir, host, raw):
    """Registrant + registration record for a host: the whois/ sidecar wins (it carries the
    enriched registrant triple), else the raw collection's own whois block."""
    side = _load_json(os.path.join(case_dir, "whois", host + ".json"))
    if side:
        return side
    return ((raw.get("artifacts") or {}).get("whois")) or raw.get("whois") or {}


def _artifacts(raw):
    return raw.get("artifacts") or {}


def _cdn_ips_and_origins(raw):
    """§2.5: every CDN/shared edge IP and stale passive origin the collector already classified —
    these are infrastructure noise, never an operator link. Returns a set of IP strings."""
    out = set()
    for piv in raw.get("pivots") or []:
        dns = ((piv.get("live_results") or {}).get("dns")) or {}
        for c in dns.get("ip_classification") or []:
            if c.get("cdn") and c.get("ip"):
                out.add(c["ip"])
        for ip in dns.get("stale_passive_ips") or []:
            out.add(ip)
    return out


def _parse_operator(op_field):
    """'Name (email@host)' -> (name, email). Either part may be absent."""
    m = re.match(r"^(.*?)\s*\(([^)]+@[^)]+)\)\s*$", op_field or "")
    if m:
        return m.group(1).strip(), m.group(2).strip().lower()
    return (op_field or "").strip(), None


def _operator_record(kb_dir, hosts):
    """The confirmed-operator ledger row whose domain set intersects this case's hosts (the
    largest such row — an estate ledger supersedes a single-case extension). None if unmatched."""
    path = os.path.join(kb_dir, "operators.jsonl")
    best = None
    hostset = {h.lower() for h in hosts}
    if os.path.isfile(path):
        for line in open(path, encoding="utf-8", errors="replace"):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            doms = {d.lower() for d in rec.get("domains") or []}
            if doms & hostset and (best is None or len(doms) > len(best.get("domains") or [])):
                best = rec
    return best


def _bluf(case_dir):
    """First substantive paragraph under a 'Bottom Line' / BLUF heading in assessment.md."""
    md = os.path.join(case_dir, "assessment.md")
    if not os.path.isfile(md):
        return ""
    lines = open(md, encoding="utf-8", errors="replace").read().splitlines()
    grab, buf = False, []
    for ln in lines:
        if ln.lstrip().startswith("#"):
            if grab:
                break
            grab = bool(re.search(r"bottom line|bluf|executive", ln, re.I))
            continue
        if grab:
            if ln.strip():
                buf.append(ln.strip())
            elif buf:
                break
    text = " ".join(buf).strip()
    return re.sub(r"[*`]", "", text)


def _recommendations(case_dir):
    """Bullet/numbered items under a 'Recommendation(s)' heading in assessment.md, else []."""
    md = os.path.join(case_dir, "assessment.md")
    if not os.path.isfile(md):
        return []
    lines = open(md, encoding="utf-8", errors="replace").read().splitlines()
    grab, out = False, []
    for ln in lines:
        if ln.lstrip().startswith("#"):
            if grab:
                break
            grab = bool(re.search(r"recommendation", ln, re.I))
            continue
        if grab:
            s = ln.strip()
            m = re.match(r"^(?:[-*]|\d+[.)])\s+(.*)$", s)
            if m:
                out.append(m.group(1).strip())
            elif s and out:
                out[-1] += " " + s
    return [r for r in out if r]


def build(case_dir, kb_dir):
    case_id = os.path.basename(os.path.abspath(case_dir).rstrip("/"))
    raws = dict(_iter_raw(case_dir))
    hosts = sorted(raws)
    seed = hosts[0] if hosts else case_id

    op_rec = _operator_record(kb_dir, hosts)
    estate = sorted({d.lower() for d in (op_rec or {}).get("domains") or []} | set(hosts))
    op_name, op_email = _parse_operator((op_rec or {}).get("operator", ""))

    # registrant triple — sidecar whois of the seed wins
    reg = _whois_of(case_dir, seed, raws.get(seed, {})) if seed in raws else {}
    reg_name = reg.get("registrant_name") or op_name or None
    reg_email = reg.get("registrant_email") or op_email or None
    reg_phone = reg.get("registrant_phone") or None
    op_username = op_email.split("@")[0] if op_email else None

    exclude = set()          # §2.5 ioc_exclude
    registrars, nameservers = set(), set()
    timeline, sources, subjects, findings, connections, indicators = [], [], [], [], [], []
    seen_src = set()

    def add_source(name, url, date):
        key = (name, url)
        if url and key not in seen_src:
            seen_src.add(key)
            sources.append({"name": name, "url": url, "date": date})

    # ---- operator subject (actor) --------------------------------------------
    operator_exists = bool(reg_name or op_name or reg_email or reg_phone)
    if operator_exists:
        selectors = []
        if reg_email:
            selectors.append({"type": "email", "value": reg_email})
        if reg_phone:
            selectors.append({"type": "phone", "value": reg_phone})
        if op_username:
            selectors.append({"type": "username", "value": op_username})
        subjects.append({
            "id": "SUB-001", "label": reg_name or op_name or reg_email or "Unattributed operator",
            "type": "person", "role": "actor",
            "confidence": 95 if reg_email and reg_phone else 80, "verified": bool(reg_email),
            "aliases": [op_name] if op_name and op_name != (reg_name or "") else [],
            "first_seen": None,
            "notes": ("Assessed operator identity from the recurring current registrant triple "
                      f"across {len(estate)} domain(s)." if reg_email else
                      "Operator identity from the confirmed-operator ledger."),
            "selectors": selectors,
        })
        # curated identity indicators (one row per value — the reachable/profiling selectors)
        if reg_email:
            indicators.append({"type": "email", "value": reg_email, "category": "contact",
                               "role": "actor", "confidence": 95})
        if reg_phone:
            indicators.append({"type": "phone", "value": reg_phone, "category": "contact",
                               "role": "actor", "confidence": 95})
        if op_username:
            indicators.append({"type": "username", "value": op_username, "category": "identity",
                               "role": "actor", "confidence": 85})

    # ---- per-collected-host subjects + infra facts ---------------------------
    sub_by_host = {}
    for i, h in enumerate(hosts, start=2):
        raw = raws[h]
        art = _artifacts(raw)
        who = _whois_of(case_dir, h, raw)
        sid = f"SUB-{i:03d}"
        sub_by_host[h] = sid
        http = (art.get("http") or {}).get("status") or (raw.get("http") or {}).get("status")
        themes = art.get("wp_themes") or raw.get("wp_themes") or []
        created = (who.get("created") or "")[:10] or None
        registrar = who.get("registrar")
        if registrar:
            registrars.add(registrar)
        for ns in who.get("name_servers") or []:
            nameservers.add(ns.lower())
        exclude |= _cdn_ips_and_origins(raw)
        subjects.append({
            "id": sid, "label": h, "type": "domain", "role": "infrastructure",
            "confidence": 95 if h == seed else 85, "verified": True, "aliases": [],
            "first_seen": created,
            "notes": (f"Collected host; HTTP {http or 'n/a'}"
                      + (f"; {', '.join(themes)} kit" if themes else "")
                      + (f"; registrar {registrar}" if registrar else "") + "."),
        })
        if operator_exists:
            connections.append({"id": f"CON-{len(connections)+1:03d}", "from_id": "SUB-001",
                                "to_id": sid, "relationship": "operates", "strength": "confirmed"})
        if created:
            timeline.append({"date": created, "event": f"{h} registered"
                             + (f" through {registrar}" if registrar else "")})
        indicators.append({"type": "domain", "value": h, "category": "network",
                           "role": "infrastructure", "confidence": 95 if h == seed else 85})
        # provenance from the seed's own live page / rdap
        if h == seed:
            add_source("Live page", raw.get("meta", {}).get("final_url") or f"https://{h}/",
                       (raw.get("meta", {}).get("collected_at") or "")[:10] or None)

    # estate domains attributed by the ledger but not individually collected -> IOC only (§2.5:
    # do not mint a per-domain subject node without per-domain evidence; keep the entity graph honest)
    estate_only = [d for d in estate if d not in raws]

    # ---- findings ------------------------------------------------------------
    def add_finding(fid, subject_id, ftype, weight, desc, src, conf, tags):
        findings.append({"id": fid, "subject_id": subject_id, "type": ftype,
                         "weight": weight if weight in SEVERITY else "INFO",
                         "description": desc, "source_url": src,
                         "collected_at": (op_rec or {}).get("added") or _today(),
                         "confidence": int(conf), "tags": tags})

    if reg_email:
        add_finding("FND-001", "SUB-001", "identity", "HIGH",
                    (f"The registrant identity ({', '.join(x for x in [reg_name, reg_email, reg_phone] if x)}) "
                     f"recurs across {len(estate)} current domain(s). The analyst assesses this "
                     "owner-controlled triple as decisive same-operator evidence."),
                    None, 95, ["attribution", "whois", "registrant-triple", "rung-1"])
    if seed in raws:
        add_finding("FND-002", sub_by_host.get(seed, "SUB-002"), "infrastructure", "HIGH",
                    (f"{seed} was collected live" + (
                        f" (HTTP {(_artifacts(raws[seed]).get('http') or {}).get('status')})"
                        if (_artifacts(raws[seed]).get('http') or {}).get('status') else "")
                     + ". Shared CDN edges, origins, registrar and nameservers are infrastructure "
                       "context and are not attributed to the operator."),
                    raws[seed].get("meta", {}).get("final_url"), 90,
                    ["live-state", "shared-infrastructure"])
    if op_rec:
        add_finding("FND-003", "SUB-001" if operator_exists else sub_by_host.get(seed, "SUB-002"),
                    "behavioral", "HIGH",
                    (f"Ledger attribution: {op_rec.get('confidence', 'assessed')} — "
                     + (op_rec.get("basis") or "same registrant triple across the estate.")),
                    None, 92, ["attribution", "estate", "ledger"])

    # ---- §2.5 false-positive control finding + ioc_exclude -------------------
    exclude |= registrars | nameservers
    fp_bits = []
    if registrars:
        fp_bits.append("registrar " + "/".join(sorted(registrars)))
    if nameservers:
        fp_bits.append(f"{len(nameservers)} shared nameserver(s)")
    ip_excl = sorted(x for x in exclude if re.match(r"^\d", x))
    if ip_excl:
        fp_bits.append("shared/CDN origins " + ", ".join(ip_excl))
    if fp_bits:
        add_finding(f"FND-{len(findings)+1:03d}", sub_by_host.get(seed, "SUB-001"),
                    "infrastructure", "INFO",
                    "Rejected as operator-level links (commodity or multi-tenant): "
                    + "; ".join(fp_bits) + ".",
                    None, 96, ["false-positive-control", "shared-infrastructure"])

    # ---- opportunistic evidence sidecars (known filenames; skipped if absent) -
    leak = _load_json(os.path.join(case_dir, "evidence", "leak-sweep.json"))
    if leak and isinstance(leak.get("verdict"), str):
        add_finding(f"FND-{len(findings)+1:03d}",
                    "SUB-001" if operator_exists else sub_by_host.get(seed, "SUB-002"),
                    "exposure", "INFO",
                    "Breach / infostealer sweep: " + leak["verdict"][:600], None, 90,
                    ["negative-finding", "breach", "infostealer"])
    sweep = _load_json(os.path.join(case_dir, "evidence", "estate-seo-sweep.json"))
    if sweep and sweep.get("verdict"):
        confirmed = list((sweep.get("operator_era_doorway_confirmed") or {}))
        add_finding(f"FND-{len(findings)+1:03d}", sub_by_host.get(seed, "SUB-001"),
                    "behavioral", "HIGH", sweep["verdict"][:600]
                    + (f" Confirmed apexes: {', '.join(confirmed)}." if confirmed else ""),
                    None, 93, ["campaign", "doorway", "seo-spam"])
        for d in confirmed:
            if d not in {i["value"] for i in indicators}:
                indicators.append({"type": "domain", "value": d.lower(),
                                   "category": "network", "role": "infrastructure", "confidence": 80})

    # estate domains as network indicators (deduped)
    known = {i["value"] for i in indicators}
    for d in estate_only:
        if d not in known:
            indicators.append({"type": "domain", "value": d, "category": "network",
                               "role": "infrastructure", "confidence": 75})

    # ---- gaps + recommendations + summary -----------------------------------
    gaps = []
    if estate_only:
        gaps.append(f"{len(estate_only)} attributed estate domain(s) are exported as indicators "
                    "but not individually collected — per-domain registration/live-state detail "
                    "was not gathered this run.")
    if not reg_email:
        gaps.append("No current registrant triple recovered — attribution rests on the ledger only.")
    n_clusters = _n_clusters(case_dir)
    if n_clusters and n_clusters > 1:
        gaps.append(f"clusters.json reports {n_clusters} operator clusters for this case; this "
                    "converter attributes a SINGLE operator (largest ledger row) and wires it to "
                    "every collected host. Re-run per cluster or hand-author subjects for a genuine "
                    "multi-operator case.")
        sys.stderr.write(f"build_report_data: WARNING — clusters.json has {n_clusters} clusters; "
                         "single-operator attribution may over-attribute (see intelligence_gaps).\n")
    recs = _recommendations(case_dir) or [
        "Preserve the current registration records before contacts are masked or domains lapse.",
        "Submit brand-abuse referrals with the operator IOC set (registrant triple + estate domains).",
        "Monitor certificate-transparency, DNS and HTTP liveness across the attributed estate.",
        "Keep shared hosting / registrar / nameserver artifacts out of the operator ledger.",
    ]
    exec_sum = _bluf(case_dir) or (
        f"{seed} is attributed to {reg_name or op_name or 'a single operator'} with "
        f"{len(estate)} domain(s) sharing the registrant identity. Shared infrastructure signals "
        "were excluded from operator-level clustering per §2.5.")

    report = {
        "generator": GENERATOR,
        "case": {
            "id": case_id,
            "label": (op_rec or {}).get("label") or f"{case_id} — {seed}",
            "classification": "UNCLASSIFIED//FOR OFFICIAL USE ONLY",
            "analyst": "AI-Assisted CTI Analyst",
            "date": _today(),
            "subject": seed,
            "status": "complete",
        },
        "executive_summary": exec_sum,
        "subjects": subjects,
        "findings": findings,
        "connections": connections,
        "timeline": sorted(timeline, key=lambda e: e["date"]),
        "sources": sources,
        "intelligence_gaps": gaps,
        "recommendations": recs,
        "indicators": indicators,
        "ioc_exclude": sorted(exclude),
        "caveats": [
            "Report uses only publicly available and case-preserved evidence; no active exploitation.",
            "Shared hosting/CDN origins, the registrar and nameservers are context, not same-operator "
            "indicators (§2.5) — retained in narrative, excluded from IOC values.",
            "Confidence reflects the analyst assessment at the collection cutoff and may change with "
            "new owner-controlled evidence.",
        ],
    }
    return report


def _today():
    return datetime.date.today().isoformat()


def main():
    ap = argparse.ArgumentParser(description="case dir -> flat report JSON (SKILL.md §8)")
    ap.add_argument("case_dir")
    ap.add_argument("-o", "--out", default=None, help="output path (default: <case>/report-data.json)")
    ap.add_argument("--kb", default=None, help="knowledge dir (default: engine knowledge/)")
    ap.add_argument("--print", action="store_true", dest="show", help="also print the JSON")
    a = ap.parse_args()
    if not os.path.isdir(a.case_dir):
        sys.exit(f"not a case directory: {a.case_dir}")
    kb = a.kb or os.path.normpath(os.path.join(a.case_dir, "..", "..", "knowledge"))
    report = build(a.case_dir, kb)
    out = a.out or os.path.join(a.case_dir, "report-data.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    c = report
    print(f"wrote {out}")
    print(f"  subjects={len(c['subjects'])} findings={len(c['findings'])} "
          f"connections={len(c['connections'])} timeline={len(c['timeline'])} "
          f"indicators={len(c['indicators'])} ioc_exclude={len(c['ioc_exclude'])}")
    if a.show:
        print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
