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

Two layouts (`--layout`, or `layout=` on render_domain_table):
  * `wide` (default) — every column in one grid, unchanged. Right for terminal and
    for the markdown an analyst reads on screen.
  * `compact` — for any PDF/DOCX deliverable. Drops `Analyst context` out of the
    grid into prose below it, shortens the registrar to its d/b/a trading name, and
    omits a column that is "—" for every row. A multi-sentence note inside a
    ten-column portrait A4 table gets ~1.5cm of width, wraps to one word per line
    and makes a single domain span a whole page; the house LaTeX header already
    sets tables to \footnotesize, so type size is not the lever — column budget is.

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
  python3 tools/domain_table.py --domains a.com,b.com --layout compact -o table.md
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

# Liveness is decided by wp_liveness (reads the PAGE, not just the status code) so a parking
# page / server default page / soft-404 stops being reported as "live", and a 404 or 403 stops
# being reported as dead. See WebPivot/tools/wp_liveness.py + references/liveness.json.
try:
    import wp_liveness                                     # type: ignore
except Exception:                                          # pragma: no cover — degrade, don't block
    wp_liveness = None
    print("[domain_table] WARNING: wp_liveness unavailable; falling back to the old "
          "status-code-only liveness check, which mislabels parked/suspended/default pages as "
          "live and 404/403 as dead.", file=sys.stderr)

PARKED_MARKERS = ("parked domain name", "domain is parked", "buy this domain",
                  "dns-parking.com")

# Managed-DNS classification + the display-only generic NS labels come from tools/kb (RULE 3:
# one group, one owner — do not re-paste the provider list here). Degrade to a minimal local
# behaviour if tools/kb is not importable, so this module still renders a table standalone.
try:
    sys.path.insert(0, os.path.join(ROOT, "tools", "kb"))
    from noise_filters import (is_managed_dns as _nf_is_managed_dns,      # type: ignore
                               GENERIC_NAMESERVER_LABELS as _GENERIC_NS_LABELS)
except Exception:                                          # pragma: no cover — degrade, don't block
    _GENERIC_NS_LABELS = frozenset(
        ["ns", "nameserver", "nsbak", "dns"]
        + [f"ns{i}" for i in range(10)] + [f"dns{i}" for i in range(10)])
    def _nf_is_managed_dns(h):                             # noqa: D401
        h = str(h or "").lower()
        return any(t in h for t in ("cloudflare.com", "awsdns", "domaincontrol.com",
                                    "registrar-servers.com", "azure-dns.", "dns-parking.com"))
    print("[domain_table] WARNING: tools/kb/noise_filters not importable; nameserver labels fall "
          "back to a minimal embedded list.", file=sys.stderr)


def _fmt_status(v: dict) -> str:
    """Verdict dict -> the Status cell. `†` marks a name that is STILL CONTROLLED and can be
    re-pointed to live content later (parked / suspended / default page / 404 / blocked) — those
    belong on a re-check list, not in the discard pile. `?` marks an unconfident verdict.

    The mark is `†`, not a rotate-arrow glyph, on purpose: U+27F2 (⟲) is absent from ordinary text
    families — on a full macOS only Apple Symbols / STIX Two Math carried it — so it rendered as a
    tofu box in the PDF deliverable. An unreadable Status column is a correctness problem, not a
    cosmetic one, and a portable skill cannot depend on a platform symbol font. `†` is present in
    every text family and is the conventional table footnote mark. (wp_liveness still prints the
    arrow in its own terminal output, where the shell's font fallback handles it.)"""
    s = v.get("state", "unknown")
    if v.get("reuse_watch") and s != "live":
        s += " †"
    if not v.get("confident", True):
        s += "?"
    return s


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
    """ASN / org / country for an address. IPinfo first, keyless ip-api as the fallback.

    IPinfo is preferred whenever it is reachable because it carries what ip-api does not: the
    abuse contact, and the hosting/proxy/VPN privacy flags. Those change how a row READS — an
    address flagged `vpn` is not the same finding as a datacentre one — so the flags are appended
    to the cell rather than dropped. ip-api stays as the keyless fallback so a machine with no
    IPinfo token still fills the column instead of printing '—' across the whole table."""
    if not ip:
        return "—"
    if ip in cache:
        return cache[ip]
    try:
        import sys as _sys
        _wp = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "WebPivot", "tools")
        if _wp not in _sys.path:
            _sys.path.append(_wp)
        from wp_ippivot import ipinfo_lookup
        d = ipinfo_lookup(ip, timeout=timeout)
        if not d.get("error") and (d.get("asn") or d.get("org_name") or d.get("country")):
            who = " ".join(x for x in (d.get("asn"), d.get("org_name")) if x)
            cc = d.get("country") or ""
            cell = (f"{who} ({cc})" if who and cc else who or cc)
            if d.get("privacy_flags"):
                cell += " · " + "/".join(d["privacy_flags"])
            cache[ip] = cell or "—"
            return cache[ip]
    except Exception:                       # noqa: BLE001 — fall through to the keyless path
        pass
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
    """Derive (status, hosting_ip) from a pivot_extract raw JSON dict — offline, no new request.

    Classification is delegated to wp_liveness, which reads the captured DOM rather than the
    title alone: a parking page's title is frequently just the bare domain, so a title-only
    check saw nothing and reported the site as live."""
    ips = []
    for p in result.get("pivots", []):
        if p.get("kind") == "domain":
            ips = ((p.get("live_results", {}) or {}).get("dns", {}) or {}).get("ips", []) or []
            break
    if wp_liveness is not None:
        v = wp_liveness.from_pivot_result(result)
        return _fmt_status(v), (ips[0] if ips else "")
    return _legacy_status_from_result(result, ips)


def _legacy_status_from_result(result, ips):
    """Pre-wp_liveness behaviour, kept only for the degraded import path above."""
    meta = result.get("meta", {}) or {}
    title = ((result.get("artifacts", {}) or {}).get("title") or "").lower()
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
    """Status for a domain with no raw JSON: DNS + one bounded page READ.

    The read happens for every status code — the body of a 404 is what separates "this path is
    gone" from "this host is a parking page that answers 404 for everything", and the old
    version threw that body away inside a bare `except`."""
    if wp_liveness is not None:
        v = wp_liveness.probe(domain)
        ips = v.get("ips") or []
        return _fmt_status(v), (ips[0] if ips else "")
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


# A sequence-numbered nameserver label identifies nothing, and providers write the number in
# several shapes: ns1, ns-1234 (Route 53), dns03, pdns6. The exact-match list in
# noise_filters.json cannot enumerate them, so the numeric forms are matched by pattern here and
# the JSON list carries the WORD-shaped labels an analyst might want to add (nsbak, master, hidden).
_SEQ_LABEL_RE = __import__("re").compile(r"^(?:ns|dns|pdns|sdns|udns)[-_]?\d+$")

# Two-label public suffixes, so `ns-789.awsdns-12.co.uk` yields the apex `awsdns-12.co.uk` and not
# the meaningless `co.uk` (which then renders as the brand "co"). DISPLAY-only and deliberately not
# a reference JSON file: it is an inert technical constant used to pick a label for one table cell,
# never matched against to include or exclude evidence. Extend inline if a ccTLD shows up wrong.
_TWO_LABEL_SUFFIXES = frozenset((
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "com.au", "net.au", "org.au", "co.nz",
    "com.br", "com.cn", "net.cn", "org.cn", "com.vn", "net.vn", "org.vn", "gov.vn", "edu.vn",
    "co.jp", "or.jp", "ne.jp", "co.kr", "or.kr", "com.tw", "com.hk", "com.sg", "com.my",
    "co.in", "co.id", "co.th", "com.tr", "com.mx", "com.ar", "co.za", "com.ua", "com.pl",
))


def _ns_apex(host):
    """Registrable apex of a nameserver hostname, public-suffix aware for the common ccTLD forms."""
    bits = host.split(".")
    if len(bits) >= 3 and ".".join(bits[-2:]) in _TWO_LABEL_SUFFIXES:
        return ".".join(bits[-3:])
    return ".".join(bits[-2:]) if len(bits) >= 2 else host


def _ns_short(w):
    """The Nameservers cell — provider apex, but KEEP the account-assigned labels.

    Collapsing `hope.ns.cloudflare.com` + `rick.ns.cloudflare.com` to `cloudflare.com` threw away
    the only part that discriminates: the apex is shared by millions of unrelated domains, whereas
    the LABEL PAIR is assigned per Cloudflare account, so two domains on hope+rick are in the same
    account. That pair is routinely a corroborating artifact in a cluster, and the old cell hid it —
    the analyst had to go back to the raw WHOIS to see what the table already had.

    So: on a managed provider (`noise_filters.is_managed_dns`) render `cloudflare: hope/rick`; on
    anything else the apex IS the identity, so render the apex. Sequence-number labels (`ns1`,
    `dns2`, `nsbak`) distinguish nothing and are suppressed as data —
    `noise_filters.GENERIC_NAMESERVER_LABELS`, tunable in noise_filters.json.

    ⚠️ Display only. A shared NS pair is a LEAD, never proof of common control: Cloudflare reuses a
    finite set of label pairs across accounts, so the pair's base rate is high. The clustering
    decision stays with managed_dns_suffixes, which correctly treats managed DNS as noise."""
    ns = w.get("name_servers") or w.get("nameServers") or []
    if isinstance(ns, dict):
        ns = ns.get("hostNames") or []
    hosts = [str(h).strip().lower().rstrip(".") for h in ns if h]
    if not hosts:
        return "—"
    groups = {}
    for h in hosts:
        apex = _ns_apex(h)
        rest = h[: -(len(apex) + 1)] if h.endswith("." + apex) else ""
        groups.setdefault(apex, []).append(rest.split(".")[0] if rest else "")
    parts = []
    for apex in sorted(groups):
        managed = any(_nf_is_managed_dns(h) for h in hosts if h.endswith(apex))
        labels = sorted({l for l in groups[apex]
                         if l and l not in _GENERIC_NS_LABELS
                         and not _SEQ_LABEL_RE.match(l)})
        if managed and labels:
            brand = apex.split(".")[0]
            parts.append("%s: %s%s" % (brand, "/".join(labels[:2]),
                                       "…" if len(labels) > 2 else ""))
        else:
            parts.append(apex)
    return ", ".join(parts[:2]) + (" …" if len(parts) > 2 else "")


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


def _short_registrar(v):
    """'CSL Computer Service Langenbach GmbH d/b/a Joker.com' -> 'Joker.com'.

    The d/b/a is the registrar's TRADING name — the same company, under the name an analyst
    recognises and an abuse report is addressed to. Full legal names run to 50+ characters and,
    in a portrait table, wrap to eight lines and blow the row height. Only applied in the
    compact layout; `wide` keeps the legal name verbatim."""
    t = str(v or "").strip()
    for sep in (" d/b/a ", " D/B/A ", " dba ", " DBA "):
        if sep in t:
            return t.split(sep, 1)[1].strip() or t
    if t.upper().startswith("DBA "):
        return t[4:].strip() or t
    return t


def _compact_registrant(v):
    """Narrow the Registrant cell so it stops overflowing into the next column.

    Two problems, both about UNBREAKABLE tokens. (1) A privacy-masked row carries the registrar's
    ROLE MAILBOX (`priv: abuse@joker.com`) — 17+ characters with no break opportunity (LaTeX will
    not break at `@` or `.`), so it runs straight over the IP column. It also carries no
    attribution whatsoever: it is denylisted registrant noise, and the Registrar column already
    names the company. So render it as `(privacy)`. (2) A REAL registrant email is evidence and
    must stay, so it is wrapped in backticks — the house header routes inline code through
    \\seqsplit, which may break anywhere, so the address wraps inside the cell instead of over it.
    """
    t = str(v or "").strip()
    if not t or t == "—":
        return "—"
    if t.lower().startswith("priv:"):
        return "(privacy)"
    out = []
    for part in t.split(" / "):
        p = part.strip()
        out.append("`%s`" % p if "@" in p and not p.startswith("`") else p)
    return " / ".join(out)


def _compact_ip_asn(v):
    """'172.67.158.152 · AS13335 Cloudflare, Inc. (US)' -> '... · AS13335 Cloudflare (US)'.

    The corporate suffix is pure width: it never distinguishes two ASNs, and the four characters it
    costs are what push the country code onto its own line."""
    t = str(v or "").strip()
    for suf in (", Inc.", ", Inc", ", LLC", ", L.L.C.", ", Ltd.", ", Ltd", ", GmbH", ", S.A.",
                ", B.V.", ", Corp.", ", Co., Ltd."):
        t = t.replace(suf, "")
    return t or "—"


def rows_to_markdown(rows, title="Domain Summary", layout="wide"):
    """Render the rows as markdown.

    layout='wide' (default) keeps every column in one grid, including the
    free-text `Analyst context`.

    layout='compact' DROPS `Analyst context` from the grid and emits it below as
    one short prose block per domain. Use it for any PDF/DOCX deliverable: a
    per-domain note runs to several sentences, and in a 10-column portrait A4
    table that single cell is allocated ~1.5cm, so it wraps to one word per line
    and a single domain can span a whole page. Shrinking the table font does not
    fix that (the house header already applies \\footnotesize) — the column
    budget is what's exhausted, so the prose has to leave the grid.
    """
    if not rows:
        return ""
    def esc(v):
        return str(v).replace("|", "\\|").replace("\n", " ")
    compact = str(layout).lower() == "compact"
    rows = [dict(r) for r in rows]                       # don't mutate the caller's rows
    if compact:
        for r in rows:
            r["registrar"] = _short_registrar(r.get("registrar"))
            r["registrant"] = _compact_registrant(r.get("registrant"))
            r["ip_asn"] = _compact_ip_asn(r.get("ip_asn"))
    cols = [c for c in _COLS if not (compact and c[0] == "context")]
    if compact:
        # Drop a column that is empty for EVERY row (commonly Attribution, when
        # operators.jsonl has no entry yet). A column of dashes costs width that the
        # populated columns need, and its absence is not a loss of information.
        cols = [c for c in cols
                if c[0] == "domain"
                or any(str(r.get(c[0], "—")).strip() not in ("", "—") for r in rows)]
    out = [f"## {title}", ""]
    out.append("| " + " | ".join(h for _, h in cols) + " |")
    out.append("|" + "|".join("---" for _ in cols) + "|")
    for r in rows:
        out.append("| " + " | ".join(esc(r.get(k, "—")) for k, _ in cols) + " |")
    if compact:
        noted = [r for r in rows
                 if str(r.get("context", "—")).strip() not in ("", "—")]
        if noted:
            out += ["", "### Analyst context", ""]
            for r in noted:
                out += ["**%s** — %s" % (r.get("domain", "?"),
                                         str(r["context"]).replace("\n", " ").strip()), ""]
    # The legend names DATA SOURCES in both layouts, but only `wide` names the internal modules
    # and stores. `compact` is what gets rendered into a PDF/DOCX that leaves the team, and an
    # internal module name, KB filename or case path in a shared deliverable is an OPSEC leak that
    # also ties the document back to the case store the external report reference exists to hide.
    if compact:
        out += ["", "_Registration data from WHOIS/RDAP. Status is judged from the page CONTENT "
                "plus DNS, never the HTTP status code alone. IP and ASN/country from live DNS and "
                "IP-geolocation lookup — a `hosting`/`proxy`/`vpn`/`tor` suffix is the provider's "
                "privacy classification for that address. `†` = the name is still registered and "
                "controlled and can be re-pointed to live content later, so it stays on the "
                "re-check list; `?` = the verdict rests on a single signal. '—' = not "
                "available._", ""]
    else:
        out += ["", "_WHOIS via WhoisXML; status from wp_liveness (the page CONTENT plus DNS, not "
                "the HTTP status code alone) and IP from live DNS + pivot capture; ASN/country via "
                "IPinfo (keyless ip-api as fallback) — a `hosting`/`proxy`/`vpn`/`tor` suffix is "
                "IPinfo's privacy flag for that address; "
                "attribution from operators.jsonl. `†` = the name is still controlled and can be "
                "re-pointed to live content later — keep it on the re-check list; `?` = the verdict "
                "rests on a single signal. '—' = not available._", ""]
    return "\n".join(out)


def render_domain_table(results, case=None, kb="knowledge", notes=None, title="Domain Summary",
                        layout="wide"):
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
    return rows_to_markdown(rows, title=title, layout=layout)


# ---------------------------------------------------------------- CLI
def main():
    ap = argparse.ArgumentParser(description="Standardized analyst Domain Summary table.")
    ap.add_argument("raw", nargs="*", help="pivot_extract raw JSON files (cases/<case>/raw/*.json)")
    ap.add_argument("--domains", help="comma-separated domains with no raw JSON (live-probed)")
    ap.add_argument("--case", help="case name (for WHOIS cache + notes.json sidecar)")
    ap.add_argument("--kb", default="knowledge", help="KB dir holding operators.jsonl")
    ap.add_argument("--notes", help="JSON sidecar {domain: analyst-note}")
    ap.add_argument("-o", "--out", help="write markdown here instead of stdout")
    ap.add_argument("--layout", choices=("wide", "compact"), default="wide",
                    help="wide (default): every column in one grid, incl. Analyst context. "
                         "compact: drop Analyst context from the grid and emit it as prose "
                         "below — USE THIS for PDF/DOCX, where a multi-sentence note in a "
                         "10-column portrait table wraps to one word per line")
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
    md = rows_to_markdown(rows, layout=a.layout)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(md + "\n")
        print(f"[+] wrote {a.out} ({len(rows)} domains)")
    else:
        print(md)


if __name__ == "__main__":
    main()
