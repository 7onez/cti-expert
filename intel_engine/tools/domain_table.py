#!/usr/bin/env python3
"""Standardized analyst **Domain Summary** table — one shape, every output.

Every WebPivot / IntelAnalysis deliverable should open with the same at-a-glance
table so an analyst can judge a cluster without digging through raw JSON. This is
the single renderer for it; `evidence_report.py` (per-host `--report` and the
whole-case rollup) calls `render_domain_table()` so the table + WHOIS is
auto-prepended to every run — no extra command.

Columns (fixed):
  Domain | Status | Registered | Expires | Registrar | Nameservers |
  Registrant | IP · ASN | Attribution | Analyst context

Data sources, all best-effort (a missing source degrades to "—", never raises):
  * WHOIS (registrar / created / expires / registrant / NS) — WhoisXML, reusing
    WebPivot/tools/whois_enrich.whois_current; cached under cases/<case>/whois/.
  * Status + hosting IP — derived from the pivot_extract raw JSON (live DNS,
    recovered_via, parked-page title); falls back to a live DNS probe.
  * ASN / org for the hosting IP — keyless ip-api.com lookup (cached).
  * Attribution (operator + confidence + reason) — knowledge/operators.jsonl.
  * Analyst context — free-text per-domain note from an optional sidecar
    (cases/<case>/notes.json : {"domain": "note", ...}); this column is where the
    analyst records the judgement the automated columns can't.

CLI:
  python3 tools/domain_table.py cases/<case>/raw/*.json --case <case> --kb knowledge
  python3 tools/domain_table.py --domains a.com,b.com --kb knowledge -o table.md
"""
from __future__ import annotations
import argparse, glob, json, os, socket, sys, urllib.parse, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# reuse the WebPivot WHOIS client (WhoisXML) without duplicating it
sys.path.insert(0, os.path.join(ROOT, "WebPivot", "tools"))
try:
    from whois_enrich import whois_current, is_privacy  # type: ignore
except Exception:                                        # pragma: no cover - degrade gracefully
    whois_current = None
    def is_privacy(v):  # noqa
        return False

PARKED_MARKERS = ("parked domain name", "domain is parked", "buy this domain",
                  "dns-parking.com")


# ---------------------------------------------------------------- data gathering
def _short_date(v):
    """'2026-07-15T14:25:31Z' -> '2026-07-15'; passthrough anything else."""
    if not v:
        return "—"
    return str(v)[:10]


def _resolve(domain):
    try:
        _, _, ips = socket.gethostbyname_ex(domain)
        return ips
    except Exception:
        return []


def _asn_for_ip(ip, cache, timeout=8):
    """Keyless ASN/org lookup via ip-api.com. Cached per IP. '—' on failure."""
    if not ip:
        return "—"
    if ip in cache:
        return cache[ip]
    try:
        url = "http://ip-api.com/json/" + urllib.parse.quote(ip) + "?fields=as,org,countryCode"
        with urllib.request.urlopen(url, timeout=timeout) as r:
            d = json.load(r)
        asn = (d.get("as") or "").split()[0] if d.get("as") else ""      # 'AS47583'
        org = d.get("org") or (d.get("as") or "").split(" ", 1)[-1] or ""
        cc = d.get("countryCode") or ""
        out = " ".join(x for x in (asn, org and f"({org}{', '+cc if cc else ''})") if x) or "—"
    except Exception:
        out = "—"
    cache[ip] = out
    return out


def _status_from_result(result):
    """Derive (status, hosting_ip) from a pivot_extract raw JSON dict."""
    meta = result.get("meta", {}) or {}
    arts = result.get("artifacts", {}) or {}
    title = (arts.get("title") or "").lower()
    # live IP from the domain pivot's live DNS (ground truth), else the raw DOM title
    ips = []
    for p in result.get("pivots", []):
        if p.get("kind") == "domain":
            ips = ((p.get("live_results", {}) or {}).get("dns", {}) or {}).get("ips", []) or []
            break
    if any(m in title for m in PARKED_MARKERS):
        return "parked", (ips[0] if ips else "")
    if ips:
        return "live", ips[0]
    err = str(meta.get("live_error") or "").lower()
    if any(s in err for s in ("nodename nor servname", "not known", "nxdomain",
                              "name or service not known", "no address associated")):
        return "dead/pulled", ""          # DNS no longer resolves → taken down / rotated
    if err or meta.get("recovered_via"):
        return "unreachable", ""          # firewalled / CF-walled / archive-only
    return "unknown", (ips[0] if ips else "")


def _status_from_live(domain):
    """Status for a domain with no raw JSON: live DNS + a quick page peek."""
    ips = _resolve(domain)
    if not ips:
        return "dead/pulled", ""
    try:
        req = urllib.request.Request("https://" + domain + "/",
                                     headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=12) as r:
            body = r.read(20000).decode("utf-8", "ignore").lower()
        if any(m in body for m in PARKED_MARKERS):
            return "parked", ips[0]
        return "live", ips[0]
    except Exception:
        return "resolves", ips[0]         # DNS resolves but no clean HTTP read


def _attribution(domain, registry_recs):
    for r in registry_recs:
        if domain in [d.lower() for d in r.get("domains", [])]:
            conf = (r.get("confidence") or "?")
            reason = r.get("basis") or r.get("operator") or ""
            mark = {"assessed": "🟢 confirmed", "likely": "🟡 likely",
                    "possible": "🟡 possible"}.get(conf, conf)
            return f"{mark} — {reason}" if reason else mark
    return "—"


def _load_registry(kb):
    path = os.path.join(kb, "operators.jsonl") if kb else ""
    recs = []
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        recs.append(json.loads(line))
                    except Exception:
                        pass
    return recs


def _whois_cached(domain, case_dir):
    """WHOIS via WhoisXML, cached to cases/<case>/whois/<domain>.json."""
    cache = os.path.join(case_dir, "whois", domain + ".json") if case_dir else ""
    if cache and os.path.exists(cache):
        try:
            return json.load(open(cache, encoding="utf-8"))
        except Exception:
            pass
    if whois_current is None:
        return {}
    try:
        w = whois_current(domain) or {}
    except Exception:
        w = {}
    if cache and w:
        os.makedirs(os.path.dirname(cache), exist_ok=True)
        try:
            json.dump(w, open(cache, "w", encoding="utf-8"), indent=2)
        except Exception:
            pass
    return w


def _fmt_registrant(w):
    email = w.get("registrant_email")
    name = w.get("registrant_name")
    org = w.get("registrant_org")
    val = org or name or email or "—"
    if val != "—" and (is_privacy(val) or (email and is_privacy(email))):
        return f"priv: {email or val}"
    parts = [x for x in (org, name) if x]
    if email:
        parts.append(email)
    return " / ".join(parts) if parts else "—"


def _ns_short(w):
    ns = w.get("name_servers") or w.get("nameServers") or []
    if isinstance(ns, dict):
        ns = ns.get("hostNames") or []
    if not ns:
        return "—"
    # collapse to the registrable NS provider when they share one (…dns-parking.com)
    apexes = sorted({".".join(h.lower().split(".")[-2:]) for h in ns if h})
    return ", ".join(apexes[:2]) + (" …" if len(ns) > 2 else "")


# ---------------------------------------------------------------- rendering
def gather_rows(domains_results, case_dir, kb, notes):
    """domains_results: list of (domain, result_dict_or_None). Returns row dicts."""
    registry = _load_registry(kb)
    asn_cache = {}
    rows = []
    for domain, result in domains_results:
        domain = domain.lower().strip()
        if result is not None:
            status, ip = _status_from_result(result)
        else:
            status, ip = _status_from_live(domain)
        w = _whois_cached(domain, case_dir)
        rows.append({
            "domain": domain,
            "status": status,
            "registered": _short_date(w.get("created")),
            "expires": _short_date(w.get("expires")),
            "registrar": (w.get("registrar") or "—").replace(", ", " ").split(" operations")[0],
            "nameservers": _ns_short(w),
            "registrant": _fmt_registrant(w),
            "ip_asn": (f"{ip} · {_asn_for_ip(ip, asn_cache)}" if ip else "—"),
            "attribution": _attribution(domain, registry),
            "context": (notes or {}).get(domain, "—"),
        })
    rows.sort(key=lambda r: (r["registered"] == "—", r["registered"]))
    return rows


_COLS = [("domain", "Domain"), ("status", "Status"), ("registered", "Registered"),
         ("expires", "Expires"), ("registrar", "Registrar"), ("nameservers", "Nameservers"),
         ("registrant", "Registrant"), ("ip_asn", "IP · ASN"),
         ("attribution", "Attribution"), ("context", "Analyst context")]


def rows_to_markdown(rows, title="Domain Summary"):
    if not rows:
        return ""
    def esc(v):
        return str(v).replace("|", "\\|").replace("\n", " ")
    out = [f"## {title}", ""]
    out.append("| " + " | ".join(h for _, h in _COLS) + " |")
    out.append("|" + "|".join("---" for _ in _COLS) + "|")
    for r in rows:
        out.append("| " + " | ".join(esc(r.get(k, "—")) for k, _ in _COLS) + " |")
    out += ["", "_WHOIS via WhoisXML; status/IP from live DNS + pivot capture; "
            "ASN via ip-api; attribution from operators.jsonl. '—' = not available._", ""]
    return "\n".join(out)


def render_domain_table(results, case=None, kb="knowledge", notes=None, title="Domain Summary"):
    """Convenience entry point for report renderers.

    `results` is a list of pivot_extract raw-JSON dicts (each with meta.host).
    Returns a ready-to-embed markdown string (or '' if nothing usable).
    """
    case_dir = os.path.join(ROOT, "cases", case) if case else None
    if notes is None and case_dir:
        npath = os.path.join(case_dir, "notes.json")
        if os.path.exists(npath):
            try:
                notes = json.load(open(npath, encoding="utf-8"))
            except Exception:
                notes = {}
    pairs = []
    for res in results:
        host = (res.get("meta", {}) or {}).get("host")
        if host:
            pairs.append((host, res))
    rows = gather_rows(pairs, case_dir, os.path.join(ROOT, kb) if kb and not os.path.isabs(kb) else kb, notes or {})
    return rows_to_markdown(rows, title=title)


# ---------------------------------------------------------------- CLI
def main():
    ap = argparse.ArgumentParser(description="Standardized analyst Domain Summary table.")
    ap.add_argument("raw", nargs="*", help="pivot_extract raw JSON files (cases/<case>/raw/*.json)")
    ap.add_argument("--domains", help="comma-separated domains with no raw JSON (live-probed)")
    ap.add_argument("--case", help="case name (for WHOIS cache + notes.json sidecar)")
    ap.add_argument("--kb", default="knowledge", help="KB dir holding operators.jsonl")
    ap.add_argument("--notes", help="JSON sidecar {domain: analyst-note}")
    ap.add_argument("-o", "--out", help="write markdown here instead of stdout")
    a = ap.parse_args()

    pairs = []
    for path in a.raw:
        for fp in glob.glob(path):
            try:
                res = json.load(open(fp, encoding="utf-8"))
                host = (res.get("meta", {}) or {}).get("host") or os.path.basename(fp)[:-5]
                pairs.append((host, res))
            except Exception as e:
                print(f"[!] skip {fp}: {e}", file=sys.stderr)
    for d in (a.domains.split(",") if a.domains else []):
        if d.strip():
            pairs.append((d.strip(), None))
    if not pairs:
        ap.error("no domains — pass raw JSON files and/or --domains")

    case_dir = os.path.join(ROOT, "cases", a.case) if a.case else None
    notes = {}
    if a.notes and os.path.exists(a.notes):
        notes = json.load(open(a.notes, encoding="utf-8"))
    elif case_dir and os.path.exists(os.path.join(case_dir, "notes.json")):
        notes = json.load(open(os.path.join(case_dir, "notes.json"), encoding="utf-8"))

    kb = a.kb if os.path.isabs(a.kb) else os.path.join(ROOT, a.kb)
    rows = gather_rows(pairs, case_dir, kb, notes)
    md = rows_to_markdown(rows)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(md + "\n")
        print(f"[+] wrote {a.out} ({len(rows)} domains)")
    else:
        print(md)


if __name__ == "__main__":
    main()
