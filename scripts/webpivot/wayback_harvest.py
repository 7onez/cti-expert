#!/usr/bin/env python3
# Part of the WebPivot toolkit by Zeroska — https://github.com/Zeroska
# Adapted for the cti-expert skill by Hieu Ngo (chongluadao.vn).
"""
wayback_harvest.py — full-IOC harvest across a domain's ENTIRE archive history.

The gap this closes
  `pivot_extract.py` extracts the full artifact set (emails, trackers, wallets,
  SaaS/operator IDs, socials, verification IDs) — but only from ONE live/representative
  capture. `wayback_ga.py` walks the whole Wayback timeline but only harvests
  *tracker/verification IDs*. So an email, phone, or wallet that appeared in a 2022
  snapshot and was later scrubbed is never collected by default. This tool runs the
  FULL extractor over every sampled snapshot and merges results across time with
  first-seen / last-seen — turning "grabbed the caches" into "harvested every
  historical selector from them." It also extracts PHONES, which `analyze()` omits.

  Optionally folds in urlscan.io prior-scan intel (related domains/IPs/ASNs) when
  URLSCAN_API_KEY is set — the "Wayback + urlscan" corpus in one pass.

  Output can be emitted as case-schema `indicators[]` (--indicators), which
  generate-cti-iocs.py already ingests — so harvested selectors roll straight into
  the /case IOC bundle with no manual step.

Usage
  python3 wayback_harvest.py suspect.example --timeline
  python3 wayback_harvest.py suspect.example --max 20 --from 2019 --urlscan
  python3 wayback_harvest.py suspect.example --indicators -o "<case>/harvest.indicators.json"
  python3 wayback_harvest.py -f domains.txt --json --pretty

Passive by construction: only touches web.archive.org (+ urlscan.io if keyed),
never the target. FOR AUTHORIZED INVESTIGATIONS ONLY.
"""
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///

import sys
import os
import re
import json
import argparse

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# Reuse the CDX/sampling/fetch plumbing and the full extractor set.
from wayback_ga import cdx_snapshots, sample_evenly, fetch_raw  # noqa: E402
from pivot_extract import (  # noqa: E402
    DEFAULT_UA, EMAIL_RE, LINK_HREF_RE, BOILERPLATE_EMAIL_HOSTS,
    VERIFICATION_META, extract_trackers, extract_meta, extract_saas,
    extract_crypto, extract_socials, extract_phones, uniq,
)

try:
    from pivot_extract import urlscan_intel  # optional; needs URLSCAN_API_KEY
except Exception:
    urlscan_intel = None


# ----------------------------------------------------------------------------- extraction

_IMG_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico")


def clean_emails(html):
    out = []
    for e in uniq(EMAIL_RE.findall(html)):
        el = e.lower()
        if el.endswith(_IMG_EXT):
            continue
        if el.split("@")[-1].endswith(BOILERPLATE_EMAIL_HOSTS):
            continue
        out.append(e)
    return out[:40]


def harvest_html(html):
    """Return {kind: [values]} for one snapshot's HTML."""
    found = {}

    def put(kind, values):
        if values:
            found.setdefault(kind, [])
            for v in values:
                if v and v not in found[kind]:
                    found[kind].append(v)

    put("email", clean_emails(html))
    put("phone", extract_phones(html))

    crypto = extract_crypto(html)  # {"btc":[...], "eth":[...], ...}
    for chain, addrs in (crypto or {}).items():
        put(f"wallet:{chain}", addrs)

    for label, vals in (extract_trackers(html) or {}).items():
        put(f"tracker:{label}", vals)

    meta = extract_meta(html)
    for mk, label in VERIFICATION_META.items():
        if mk in meta:
            put(f"verification:{label}", [meta[mk]])

    for label, vals in (extract_saas(html) or {}).items():
        put(f"saas:{label}", vals if isinstance(vals, list) else [vals])

    hrefs = uniq(LINK_HREF_RE.findall(html))
    socials = extract_socials(hrefs)  # {network: [handles/urls]}
    for net, handles in (socials or {}).items():
        put(f"social:{net}", handles if isinstance(handles, list) else [handles])

    title = meta.get("_title")
    if title:
        put("title", [re.sub(r"\s+", " ", title).strip()[:160]])

    return found


# ----------------------------------------------------------------------------- merge

def analyze_domain(domain, max_snaps=15, year_from=None, year_to=None, with_urlscan=False,
                   root_only=False, include_assets=True, limit_scan=2000, urlscan_pages=3,
                   deadline=None, fetch_budget=None):
    snaps = cdx_snapshots(domain, year_from, year_to, limit_scan=limit_scan,
                          root_only=root_only, include_assets=include_assets)
    picked = sample_evenly(snaps, max_snaps)
    # `fetch_budget` (seconds) bounds only the snapshot-FETCH loop, started AFTER the CDX
    # enumeration above returns — so a slow enumeration on a heavily-archived domain cannot
    # consume the whole slice and leave zero snapshots fetched. `deadline` (absolute) still
    # applies if given; the earlier of the two wins.
    import time as _t
    if fetch_budget is not None:
        fb = _t.monotonic() + max(5, fetch_budget)
        deadline = fb if deadline is None else min(deadline, fb)

    # (kind, value) -> record
    ids = {}

    def note(kind, value, ts, url):
        key = (kind, value)
        rec = ids.get(key)
        if rec is None:
            ids[key] = {"kind": kind, "value": value, "first": ts, "last": ts,
                        "hits": 1, "seen": [ts], "first_url": url}
        else:
            rec["hits"] += 1
            if ts not in rec["seen"]:
                rec["seen"].append(ts)
            if ts < rec["first"]:
                rec["first"], rec["first_url"] = ts, url
            rec["last"] = max(rec["last"], ts)

    scanned = 0
    for ts, original in picked:
        if deadline is not None and _t.monotonic() > deadline:
            break            # phase budget spent — leave time for the other corpora
        html = fetch_raw(ts, original)
        if not html or (len(html) < 400 and "<title" not in html.lower()):
            continue
        scanned += 1
        snap_url = f"https://web.archive.org/web/{ts}id_/{original}"
        for kind, values in harvest_html(html).items():
            for v in values:
                note(kind, v, ts, snap_url)

    records = sorted(ids.values(), key=lambda r: (r["kind"], -r["hits"], r["value"]))

    result = {
        "domain": domain,
        "snapshots_total": len(snaps),
        "snapshots_scanned": scanned,
        "span": [snaps[0][0], snaps[-1][0]] if snaps else None,
        "records": records,
    }

    if with_urlscan and urlscan_intel is not None:
        try:
            host = re.sub(r"^https?://", "", domain).split("/")[0]
            # paginate so a host with hundreds of scans is not truncated to one page
            try:
                us = urlscan_intel(host, max_pages=urlscan_pages)
            except TypeError:
                us = urlscan_intel(host)   # older signature without pagination
            result["urlscan"] = us
        except Exception as e:
            result["urlscan"] = {"error": str(e)}

    result["indicators"] = build_indicators(result)
    return result


# ----------------------------------------------------------------------------- indicators

# kind -> (IOC category, IOC type). Categories match generate-cti-iocs.py buckets:
# network, contact, identity, social, messaging, financial, geo.
def _map_kind(kind, value):
    if kind == "email":
        return "contact", "email"
    if kind == "phone":
        return "contact", "phone"
    if kind.startswith("wallet:"):
        chain = kind.split(":", 1)[1]
        return "financial", f"{chain}-wallet"
    if kind.startswith("social:"):
        return "social", kind.split(":", 1)[1]
    if kind.startswith("tracker:"):
        return "network", "tracker-" + kind.split(":", 1)[1]
    if kind.startswith("verification:"):
        return "network", "verification-" + kind.split(":", 1)[1]
    if kind.startswith("saas:"):
        return "network", "saas-" + kind.split(":", 1)[1]
    return None, None  # title etc. — not an IOC


def build_indicators(result):
    inds = []
    for r in result.get("records", []):
        cat, typ = _map_kind(r["kind"], r["value"])
        if not cat:
            continue
        conf = min(90, 50 + r["hits"] * 5)  # more captures = higher confidence
        inds.append({
            "category": cat,
            "type": typ,
            "value": r["value"],
            "role": "unknown",
            "confidence": conf,
            "source_url": r["first_url"],
            "first_seen": r["first"],
            "last_seen": r["last"],
            "note": f"wayback-harvest {result['domain']} ({r['hits']}× captures)",
        })
    # urlscan related domains/IPs → network indicators
    us = result.get("urlscan") or {}
    scans = us.get("recent_scans") or []
    us_src = scans[0].get("result") if scans else None
    for d in uniq(us.get("related_domains", []) or []):
        inds.append({"category": "network", "type": "domain", "value": d, "role": "unknown",
                     "confidence": 45, "source_url": us_src, "note": "urlscan related"})
    for ip in uniq(us.get("ips", []) or []):
        inds.append({"category": "network", "type": "ipv4", "value": ip, "role": "unknown",
                     "confidence": 45, "source_url": us_src, "note": "urlscan related"})
    return inds


# ----------------------------------------------------------------------------- render

def _fmt_ts(ts):
    return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}" if len(ts) >= 8 else ts


def render_timeline(res):
    span = res.get("span")
    lines = [f"# Archive IOC harvest — {res['domain']}",
             f"({res['snapshots_scanned']} of {res['snapshots_total']} snapshots scanned"
             + (f", {_fmt_ts(span[0])} → {_fmt_ts(span[1])})" if span else ")"),
             ""]
    recs = [r for r in res["records"] if r["kind"] != "title"]
    if not recs:
        lines.append("_No selectors/IOCs found in sampled snapshots._")
        return "\n".join(lines)

    # group by top-level kind family for readability
    families = {}
    for r in recs:
        fam = r["kind"].split(":", 1)[0]
        families.setdefault(fam, []).append(r)

    label = {"email": "📧 Emails", "phone": "📞 Phones", "wallet": "💰 Wallets",
             "tracker": "📊 Tracking IDs", "verification": "✅ Verification IDs",
             "saas": "🧩 SaaS / operator IDs", "social": "🔗 Socials"}
    for fam in ["email", "phone", "wallet", "tracker", "verification", "saas", "social"]:
        if fam not in families:
            continue
        lines.append(f"## {label.get(fam, fam)}")
        for r in families[fam]:
            k = r["kind"].split(":", 1)[1] if ":" in r["kind"] else ""
            tag = f" _{k}_" if k else ""
            lines.append(f"- `{r['value']}`{tag} — seen {r['hits']}× | "
                         f"{_fmt_ts(r['first'])} → {_fmt_ts(r['last'])}")
        lines.append("")
    lines.append(f"**{len(res['indicators'])} indicators** ready for the IOC bundle "
                 f"(`--indicators` → merge into case findings).")
    return "\n".join(lines)


# ----------------------------------------------------------------------------- cli

def main():
    ap = argparse.ArgumentParser(
        description="Full-IOC harvest across a domain's Wayback history (+ optional urlscan).")
    ap.add_argument("domain", nargs="?", help="domain or URL, e.g. suspect.example")
    ap.add_argument("-f", "--file", help="file of domains, one per line")
    ap.add_argument("--max", type=int, default=15, help="max snapshots to sample per domain")
    ap.add_argument("--from", dest="yfrom", help="earliest year, e.g. 2019")
    ap.add_argument("--to", dest="yto", help="latest year")
    ap.add_argument("--urlscan", action="store_true",
                    help="also fold in urlscan prior-scan related domains/IPs (needs URLSCAN_API_KEY)")
    ap.add_argument("--timeline", action="store_true", help="markdown timeline instead of JSON")
    ap.add_argument("--indicators", action="store_true",
                    help="emit case-schema indicators[] JSON (for /case → IOC bundle)")
    ap.add_argument("--root-only", action="store_true",
                    help="legacy exact-apex scan (no subdomains/subpaths); faster, narrower")
    ap.add_argument("--html-only", action="store_true",
                    help="restrict to text/html captures (skip archived JS/JSON)")
    ap.add_argument("--limit-scan", type=int, default=2000, help="max CDX rows to pull")
    ap.add_argument("--urlscan-pages", type=int, default=3,
                    help="max urlscan search pages to paginate (size 100 each)")
    ap.add_argument("--pretty", action="store_true")
    ap.add_argument("-o", "--out", help="write JSON output to file")
    args = ap.parse_args()

    if args.file:
        with open(args.file) as fh:
            domains = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    elif args.domain:
        domains = [args.domain]
    else:
        ap.error("provide a domain or -f file")

    results = [analyze_domain(d, args.max, args.yfrom, args.yto, args.urlscan,
                              root_only=args.root_only, include_assets=not args.html_only,
                              limit_scan=args.limit_scan, urlscan_pages=args.urlscan_pages)
               for d in domains]

    if args.timeline:
        out_text = "\n\n".join(render_timeline(r) for r in results)
        print(out_text)
        return

    if args.indicators:
        payload = [i for r in results for i in r["indicators"]]
    else:
        payload = results[0] if len(results) == 1 else results

    text = json.dumps(payload, indent=2 if args.pretty else None, ensure_ascii=False)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"[wayback-harvest] wrote {args.out} "
              f"({sum(len(r['indicators']) for r in results)} indicators)", file=sys.stderr)
    else:
        print(text)


if __name__ == "__main__":
    main()
