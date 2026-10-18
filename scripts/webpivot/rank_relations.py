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

# Ownership-era + noise classification — single source of truth with the ingester/KB (see
# whois_eras.py's module docstring): only the CURRENT owner's WHOIS values may score a
# same-operator signal; a previous owner from a drop-catch/resale never contributes here.
try:
    _ENGINE_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    sys.path.insert(0, os.path.join(_ENGINE_ROOT, "intel_engine", "WebPivot", "tools"))
    sys.path.insert(0, os.path.join(_ENGINE_ROOT, "intel_engine", "tools", "kb"))
    from whois_eras import owner_values as _owner_values
    from whois_enrich import is_privacy as _is_privacy
    from noise_filters import (is_noise_email as _is_noise_email, is_managed_dns as _is_managed_dns,
                               is_noise_indicator as _is_noise_indicator)
except Exception:
    def _owner_values(wh, kind):
        live = (wh or {}).get({"email": "registrant_email", "name": "registrant_name",
                               "phone": "registrant_phone", "org": "registrant_org"}[kind])
        return [live] if live else []
    def _is_privacy(v):
        return False
    def _is_noise_email(v):
        return False
    def _is_managed_dns(ns):
        return False
    def _is_noise_indicator(v):
        return False

_DENYLIST_PATH = Path(__file__).parent / "data" / "pivot-noise-denylist.txt"

# Strength-signal weights (tunable). A relation's `relation_strength` is the sum of the
# weights of its DISTINCT matched signals. Operator-grade private artifacts weigh most;
# reusable kit templates medium; shared infrastructure least (unless it is an origin).
SIGNAL_WEIGHTS: dict[str, int] = {
    "registrant_email": 5,  # WHOIS registrant email — operator-grade private identifier
    "registrant_phone": 5,  # WHOIS registrant phone — operator-grade private identifier
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
    "mail":             3,  # shared M365 tenant / custom MX host / SPF single-host IP — ONE family
                            # (an M365 tenant and its MX host are one fact); 3 so it never links alone
    "same_ip":          2,  # shared IP of unknown class (not proven CDN, not proven origin)
    "wp_theme":         2,  # shared CMS theme slug
    "nameserver":       2,  # shared authoritative name server (managed-DNS providers excluded)
    "reg_batch":        2,  # registered on the same day (batch registration)
    "email":            2,  # same on-page contact email
    "page_link":        1,  # one page hyperlinks the other
}


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

    # WHOIS operator glue — CURRENT owner only (whois_eras.py contract): a previous owner's
    # WHOIS-of-the-day value must never score a same-operator relation.
    wh = art.get("whois") or {}
    for em in _owner_values(wh, "email"):
        em = _norm_host(em)
        if em and not _is_privacy(em) and not _is_noise_email(em):
            add("registrant_email", em)
    for nm in _owner_values(wh, "name") + _owner_values(wh, "org"):
        nm = (nm or "").strip().lower()
        if nm and not _is_privacy(nm) and not _is_noise_email(nm):
            add("registrant_name", nm)
    for ph in _owner_values(wh, "phone"):
        digits = "".join(c for c in str(ph) if c.isdigit())
        if len(digits) >= 7:
            add("registrant_phone", digits)
    for ns in (wh.get("name_servers") or []):
        ns = _norm_host(ns)
        if ns and not is_noise(ns, denylist) and not _is_managed_dns(ns):
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

    # Mail infrastructure (wp_recon.detect_mail_provider → artifacts.mail). Managed providers are
    # already classified out there; shared-infra MX apexes are dropped here via noise_filters. All
    # three kinds share the ONE `mail` signal so they never corroborate each other.
    mail = art.get("mail") or {}
    if mail.get("m365_tenant"):
        add("mail", f"m365:{str(mail['m365_tenant']).strip().lower()}")
    for ex in (mail.get("custom_mx_hosts") or []):
        ex = _norm_host(ex)
        if ex and not is_noise(ex, denylist) and not _is_noise_indicator(f"mail:mx:{ex}"):
            add("mail", f"mx:{ex}")
    spf = mail.get("spf") or {}
    for sip in (spf.get("ip4") or []) + (spf.get("ip6") or []):
        sip = str(sip).strip()
        if "/" in sip and sip.split("/")[-1] not in ("32", "128"):
            continue  # a whole netblock in SPF is an ESP range, not one sending box
        ip = sip.split("/")[0]
        cls = _cdn.classify(ip, _CDN_IDX) if (_CDN_IDX and ip) else None
        if ip and not (cls and cls.get("cdn") is True):
            add("mail", f"spf_ip:{ip}")

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
