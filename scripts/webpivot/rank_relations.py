#!/usr/bin/env python3
# cti-expert skill — ported/adapted from the Quarry OSINT toolkit
# (github.com/7onez/quarry): urlscan_relation_ranker.py.
"""rank_relations.py — score and rank same-operator relations between the pages in a
case, mechanizing the "confirm a cluster with >=2 independent artifacts" rule that
techniques/web-pivot.md states as guidance.

Feed it the per-page JSON that pivot_extract.py already writes into a case
(``<case>/raw/*.json``). For every pair of analyzed hosts it sums the weighted
strength of the artifacts they share (shared tracker ID, favicon hash, wallet,
registrant email, origin IP, cert, DOM template, ...), drops ubiquitous CDN/
analytics/font infrastructure via an editable noise denylist FIRST, and ranks the
survivors. A single shared artifact is a lead; two independent ones is a cluster.

Usage:
  uv run rank_relations.py <case>/raw/*.json --pretty -o <case>/relations.json
  uv run rank_relations.py a.json b.json c.json --md          # markdown table, high->low
  uv run rank_relations.py raw/*.json --min-strength 8         # only strong links
  CTI_PIVOT_NOISE_DISABLE=1 uv run rank_relations.py raw/*.json # keep noise (debug)

Pure post-processing — no network. Each input JSON must carry ``meta.host`` (real-URL
pivot_extract runs set it) plus the ``artifacts`` block.
"""
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
import sys
import os
import json
import argparse
from itertools import combinations
from pathlib import Path

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

# Optional CDN/cloud classifier — a shared *origin* IP is attribution-grade; a shared
# *CDN edge* IP is noise. Degrades cleanly if the range cache is missing.
try:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import cdn_ranges as _cdn
    _CDN_IDX = _cdn.load_ranges()
except Exception:
    _cdn, _CDN_IDX = None, None

_DENYLIST_PATH = Path(__file__).parent / "data" / "pivot-noise-denylist.txt"

# Strength-signal weights (tunable). A relation's `relation_strength` is the sum of the
# weights of its DISTINCT matched signals. Operator-grade private artifacts weigh most;
# reusable kit templates medium; shared infrastructure least (unless it is an origin).
SIGNAL_WEIGHTS: dict[str, int] = {
    "registrant_email": 5,  # WHOIS registrant email — operator-grade private identifier
    "wallet":           5,  # same crypto address on both pages — operator-grade
    "tracking_id":      5,  # exact analytics/ads ID shared (GA/GTM/AdSense/pixel)
    "verification":     5,  # site-verification token (google/bing/fb domain-verify)
    "favicon":          4,  # identical favicon hash (kit reuse / shared origin)
    "shared_cert":      4,  # same TLS cert fingerprint (cert-sibling)
    "same_origin_ip":   4,  # co-hosted on a non-CDN origin IP
    "registrant_name":  3,  # shared WHOIS registrant name/org
    "social":           3,  # same social handle linked from both
    "redirect_chain":   3,  # one host appears in the other's redirect chain
    "dom_skeleton":     3,  # identical DOM-skeleton hash (same template/kit)
    "same_ip":          2,  # shared IP of unknown class (not proven CDN, not proven origin)
    "wp_theme":         2,  # shared CMS theme slug
    "nameserver":       2,  # shared authoritative name server
    "reg_batch":        2,  # registered on the same day (batch registration)
    "email":            2,  # same on-page contact email
    "page_link":        1,  # one page hyperlinks the other
}

# WHOIS privacy / proxy / role markers — never treat these as a real shared identity.
_PRIV_MARK = (
    "privacy", "redacted", "whoisguard", "data protected", "withheld", "not disclosed",
    "domains by proxy", "domainsbyproxy", "registration private", "private by design",
    "identity protect", "contact privacy", "perfect privacy", "statutory masking",
    "masking enabled", "registry registrant id", "not available from registry",
    "registrant country", "registrant state", "registrant city", "whois agent",
    "redemption", "pending delete", "reactivation", "domain expired",
)
_PROXY_DOM = (
    "porkbun.com", "godaddy.com", "namecheap.com", "domainsbyproxy.com",
    "withheldforprivacy.com", "privacyprotect.org", "contactprivacy.com",
    "onamae.com", "tenten.vn", "inet.vn", "gname.com", "sav.com", "enom.com",
)
_ROLE_LOCAL = (
    "abuse@", "hostmaster@", "noc@", "postmaster@", "registrar@", "complaint@",
    "proxy@", "protected@", "dataprotected@", "info@", "sales@", "support@",
    "contact@", "noreply@", "no-reply@", "admin@",
)


# --------------------------------------------------------------------------- denylist
def load_denylist(path=None) -> frozenset:
    """Load apex-domain noise entries. Empty set on any failure (graceful)."""
    p = Path(path) if path else _DENYLIST_PATH
    try:
        out = set()
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            out.add(line.lower().rstrip("."))
        return frozenset(out)
    except Exception:
        return frozenset()


def denylist_disabled() -> bool:
    for var in ("CTI_PIVOT_NOISE_DISABLE", "URLSCAN_NOISE_DENYLIST_DISABLE"):
        if os.getenv(var, "").strip().lower() in {"1", "true", "yes", "on"}:
            return True
    return False


def is_noise(host: str, denylist: frozenset) -> bool:
    """True if `host` matches a denylist entry (exact apex OR subdomain suffix)."""
    if not host:
        return True
    d = host.strip().lower().rstrip(".")
    return any(d == e or d.endswith("." + e) for e in denylist)


# ------------------------------------------------------------------------- helpers
def _norm_host(h) -> str:
    return (h or "").strip().lower().rstrip(".")


def _priv(s: str) -> bool:
    """True when a WHOIS value is a privacy/proxy/role placeholder, not a real identity."""
    s = (s or "").strip().lower()
    if not s or s.startswith("http"):
        return True
    if any(m in s for m in _PRIV_MARK):
        return True
    if s.startswith(_ROLE_LOCAL):
        return True
    if "@" in s and s.split("@", 1)[1] in _PROXY_DOM:
        return True
    return False


def _host_of(url: str) -> str:
    """Best-effort host extraction from a URL string (stdlib urlsplit)."""
    from urllib.parse import urlsplit
    try:
        net = urlsplit(url if "//" in url else "//" + url).netloc
        return _norm_host(net.split("@")[-1].split(":")[0])
    except Exception:
        return ""


def load_analyses(paths):
    """Load pivot_extract JSONs; each may be a dict or a list of dicts."""
    out = []
    for p in paths:
        try:
            d = json.load(open(p, encoding="utf-8"))
        except Exception as e:
            print(f"  skip {p}: {e}", file=sys.stderr)
            continue
        out.extend(d if isinstance(d, list) else [d])
    return out


# ---------------------------------------------------- artifact -> signal extraction
def extract_signals(analysis, denylist):
    """Return {signal_type: set(values)} of pivot artifacts for one analyzed host.

    Values are the shareable keys (a tracker id, a favicon hash, a wallet, ...); two
    hosts that produce the same (signal_type, value) share that signal.
    """
    art = analysis.get("artifacts") or {}
    meta = analysis.get("meta") or {}
    sig: dict[str, set] = {}

    def add(kind, value):
        v = str(value).strip()
        if v:
            sig.setdefault(kind, set()).add(v)

    for _label, vals in (art.get("trackers") or {}).items():
        for v in vals:
            add("tracking_id", v)
    fav = art.get("favicon") or {}
    for k in ("shodan_mmh3", "md5", "sha256"):
        if fav.get(k) is not None:
            add("favicon", f"{k}:{fav[k]}")
    for _coin, vals in (art.get("crypto") or {}).items():
        for v in vals:
            add("wallet", v)
    for _label, tok in (art.get("verifications") or {}).items():
        add("verification", tok)
    for _net, handles in (art.get("socials") or {}).items():
        for h in handles:
            add("social", h)
    for e in (art.get("emails") or []):
        add("email", e.lower())
    if art.get("dom_skeleton_sha1"):
        add("dom_skeleton", art["dom_skeleton_sha1"])
    for th in (art.get("wp_themes") or []):
        add("wp_theme", th)
    # TLS cert fingerprint if pivot_extract captured one (optional field)
    for cert_field in ("cert_sha256", "cert_fingerprint_sha256", "tls_fingerprint"):
        if art.get(cert_field):
            add("shared_cert", art[cert_field])

    # WHOIS operator glue (privacy/proxy filtered)
    wh = art.get("whois") or {}
    hist = wh.get("history") or {}
    for em in ([wh.get("registrant_email")] + (hist.get("registrant_emails") or [])):
        em = _norm_host(em)
        if em and not _priv(em):
            add("registrant_email", em)
    for nm in ([wh.get("registrant_name") or wh.get("registrant_org")]
               + (hist.get("registrant_names") or [])):
        nm = (nm or "").strip().lower()
        if nm and not _priv(nm):
            add("registrant_name", nm)
    for ns in (wh.get("name_servers") or []):
        ns = _norm_host(ns)
        if ns and not is_noise(ns, denylist):
            add("nameserver", ns)
    created = wh.get("created")
    if isinstance(created, str) and len(created) >= 10:
        add("reg_batch", created[:10])

    # IPs (urlscan/passive) — classify CDN(noise) vs origin(attribution-grade)
    us = analysis.get("related_urlscan") or {}
    for ip in (us.get("ips") or []):
        ip = str(ip).strip()
        if not ip:
            continue
        cls = _cdn.classify(ip, _CDN_IDX) if _CDN_IDX else None
        if cls and cls.get("cdn") is True:
            continue  # shared CDN edge IP — noise, never an operator hub
        if cls and cls.get("cdn") is False:
            add("same_origin_ip", ip)
        else:
            add("same_ip", ip)  # unknown class — weak co-hosting signal

    return sig, meta


def redirect_hosts(analysis):
    """Hosts that appear in this page's redirect chain (for the redirect_chain signal)."""
    meta = analysis.get("meta") or {}
    hosts = set()
    for u in (meta.get("redirect_chain") or []):
        h = _host_of(u)
        if h:
            hosts.add(h)
    return hosts


def page_link_hosts(analysis):
    """Third-party hosts this page hyperlinks (for the page_link signal)."""
    art = analysis.get("artifacts") or {}
    return {_host_of(h) for h in (art.get("third_party_hosts") or []) if h}


# --------------------------------------------------------------------------- ranking
def _assess(strength, signals):
    """Map a scored relation to a plain-language confidence assessment."""
    strong = [s for s in signals if SIGNAL_WEIGHTS.get(s, 0) >= 4]
    if len(signals) >= 2 and strong:
        return "same_operator_likely"      # >=2 independent artifacts, >=1 strong
    if strength >= 8 or len(signals) >= 3:
        return "same_operator_likely"
    if strength >= 4:
        return "related_probable"
    return "weak_lead"


class _UF:
    """Union-find for clustering hosts over corroborated edges."""
    def __init__(self):
        self.p = {}

    def find(self, x):
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[ra] = rb


def rank(analyses, denylist, min_strength=1, include_weak=False):
    hosts = {}          # host -> {signal_type: set(values)}
    redirects = {}      # host -> set(hosts in its redirect chain)
    links = {}          # host -> set(hosts it links to)

    for a in analyses:
        sig, meta = extract_signals(a, denylist)
        host = _norm_host(meta.get("host"))
        if not host or is_noise(host, denylist):
            continue
        # merge if the same host appears in multiple inputs (e.g. crawl pages)
        h = hosts.setdefault(host, {})
        for k, vs in sig.items():
            h.setdefault(k, set()).update(vs)
        redirects.setdefault(host, set()).update(redirect_hosts(a))
        links.setdefault(host, set()).update(page_link_hosts(a))

    host_list = sorted(hosts)
    relations = []
    for a, b in combinations(host_list, 2):
        matched: dict[str, list] = {}   # signal_type -> shared values
        for stype in set(hosts[a]) & set(hosts[b]):
            shared = sorted(hosts[a][stype] & hosts[b][stype])
            if shared:
                matched[stype] = shared
        # relational (non-artifact) signals
        if b in redirects.get(a, ()) or a in redirects.get(b, ()):
            matched["redirect_chain"] = ["redirect chain"]
        if b in links.get(a, ()) or a in links.get(b, ()):
            matched.setdefault("page_link", ["hyperlink"])

        if not matched:
            continue
        signals = sorted(matched, key=lambda s: -SIGNAL_WEIGHTS.get(s, 0))
        strength = sum(SIGNAL_WEIGHTS.get(s, 0) for s in signals)
        assessment = _assess(strength, signals)
        if strength < min_strength:
            continue
        if assessment == "weak_lead" and not include_weak:
            continue
        relations.append({
            "a": a, "b": b,
            "relation_strength": strength,
            "signals": signals,
            "assessment": assessment,
            "shared": {s: matched[s][:8] for s in signals},
        })

    relations.sort(key=lambda r: (-r["relation_strength"], r["a"], r["b"]))

    # per-domain strongest siblings
    by_domain: dict[str, list] = {}
    for r in relations:
        for x, y in ((r["a"], r["b"]), (r["b"], r["a"])):
            by_domain.setdefault(x, []).append(
                {"domain": y, "relation_strength": r["relation_strength"],
                 "signals": r["signals"], "assessment": r["assessment"]})
    for x in by_domain:
        by_domain[x].sort(key=lambda d: -d["relation_strength"])

    # clusters over corroborated (non-weak) edges
    uf = _UF()
    for h in host_list:
        uf.find(h)
    for r in relations:
        if r["assessment"] != "weak_lead":
            uf.union(r["a"], r["b"])
    groups: dict[str, list] = {}
    for h in host_list:
        groups.setdefault(uf.find(h), []).append(h)
    clusters = sorted(
        (sorted(g) for g in groups.values() if len(g) >= 2),
        key=lambda g: -len(g),
    )

    return {
        "meta": {
            "inputs": len(analyses), "hosts": len(host_list),
            "relations": len(relations), "clusters": len(clusters),
            "denylist_entries": len(denylist), "denylist_disabled": denylist_disabled(),
        },
        "relations": relations,
        "by_domain": by_domain,
        "clusters": clusters,
    }


def to_markdown(result):
    lines = ["| A | B | strength | assessment | shared signals |",
             "|---|---|---:|---|---|"]
    for r in result["relations"]:
        sig = ", ".join(f"{s}(+{SIGNAL_WEIGHTS.get(s,0)})" for s in r["signals"])
        lines.append(f"| {r['a']} | {r['b']} | {r['relation_strength']} "
                     f"| {r['assessment']} | {sig} |")
    if result["clusters"]:
        lines.append("")
        lines.append("**Clusters (corroborated same-operator groups):**")
        for i, c in enumerate(result["clusters"], 1):
            lines.append(f"- Cluster {i}: {', '.join(c)}")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(
        description="Rank same-operator relations between analyzed pages (noise-filtered).")
    ap.add_argument("inputs", nargs="+", help="pivot_extract JSON files (e.g. <case>/raw/*.json)")
    ap.add_argument("--min-strength", type=int, default=1,
                    help="drop relations weaker than this summed strength (default 1)")
    ap.add_argument("--include-weak", action="store_true",
                    help="keep single-weak-signal 'weak_lead' relations")
    ap.add_argument("--denylist", help="override path to the noise denylist file")
    ap.add_argument("--md", action="store_true", help="print a ranked markdown table instead of JSON")
    ap.add_argument("--pretty", action="store_true", help="pretty-print JSON")
    ap.add_argument("-o", "--out", help="write JSON to file")
    args = ap.parse_args()

    denylist = frozenset() if denylist_disabled() else load_denylist(args.denylist)
    analyses = load_analyses(args.inputs)
    result = rank(analyses, denylist,
                  min_strength=args.min_strength, include_weak=args.include_weak)

    m = result["meta"]
    print(f"ranked {m['relations']} relation(s) across {m['hosts']} host(s); "
          f"{m['clusters']} cluster(s); denylist={m['denylist_entries']} entries"
          f"{' (DISABLED)' if m['denylist_disabled'] else ''}", file=sys.stderr)

    if args.md:
        print(to_markdown(result))
        return
    text = json.dumps(result, ensure_ascii=False, indent=2 if args.pretty else None)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        print(text)


if __name__ == "__main__":
    main()
