#!/usr/bin/env python3
# Part of the WebPivot toolkit by Zeroska — https://github.com/Zeroska
# Adapted for the cti-expert skill by Hieu Ngo (chongluadao.vn).
"""
cdn_ranges.py — classify an IP as CDN/cloud edge (NOISE) vs candidate ORIGIN.

Most CDNs/clouds publish their IP ranges. This tool fetches those official lists,
caches them locally, and classifies any IP by CIDR membership. An IP inside a known
CDN/cloud range is shared edge infrastructure (near-zero attribution value); an IP
outside all of them is a *candidate origin* — the real backend, which IS
attribution-grade when two sites share it (see IntelAnalysis SKILL.md §1).

Zero dependencies — Python 3 stdlib only (urllib + ipaddress + json).

    python3 cdn_ranges.py --update                 # fetch + cache published ranges
    python3 cdn_ranges.py --classify 104.21.61.155 103.75.186.14
    python3 cdn_ranges.py -f ips.txt --json
    python3 cdn_ranges.py --stats

Cache: cdn_ranges.json co-located with this script  (CIDR + provider + kind).
Importable:  load_ranges() -> index;  classify(ip, index) -> {'ip','cdn','provider','kind'}.
"""
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
import sys
import os
import json
import argparse
import ipaddress
import urllib.request
from datetime import datetime, timezone

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
CACHE = os.path.join(HERE, "cdn_ranges.json")
UA = "Mozilla/5.0 (cdn-ranges OSINT tooling)"

# --- published range sources. Each returns list[(cidr, provider, kind)]. ---------


def _get(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def src_cloudflare():
    out = []
    for url in ("https://www.cloudflare.com/ips-v4/", "https://www.cloudflare.com/ips-v6/"):
        try:
            for line in _get(url).splitlines():
                line = line.strip()
                if "/" in line:
                    out.append((line, "cloudflare", "cdn"))
        except Exception as e:
            print(f"  cloudflare {url}: {e}", file=sys.stderr)
    return out


def src_fastly():
    try:
        d = json.loads(_get("https://api.fastly.com/public-ip-list"))
        return [(c, "fastly", "cdn") for c in d.get("addresses", []) + d.get("ipv6_addresses", [])]
    except Exception as e:
        print(f"  fastly: {e}", file=sys.stderr)
        return []


def src_aws_cloudfront():
    try:
        d = json.loads(_get("https://ip-ranges.amazonaws.com/ip-ranges.json"))
        out = []
        for p in d.get("prefixes", []):
            if p.get("service") in ("CLOUDFRONT", "GLOBALACCELERATOR"):
                out.append((p["ip_prefix"], "aws_" + p["service"].lower(), "cdn"))
        for p in d.get("ipv6_prefixes", []):
            if p.get("service") in ("CLOUDFRONT", "GLOBALACCELERATOR"):
                out.append((p["ipv6_prefix"], "aws_" + p["service"].lower(), "cdn"))
        return out
    except Exception as e:
        print(f"  aws: {e}", file=sys.stderr)
        return []


def src_google_cloud():
    out = []
    for url, prov in (("https://www.gstatic.com/ipranges/cloud.json", "google_cloud"),
                      ("https://www.gstatic.com/ipranges/goog.json", "google")):
        try:
            d = json.loads(_get(url))
            for p in d.get("prefixes", []):
                c = p.get("ipv4Prefix") or p.get("ipv6Prefix")
                if c:
                    out.append((c, prov, "cloud"))
        except Exception as e:
            print(f"  {prov}: {e}", file=sys.stderr)
    return out


def src_bunny():
    # BunnyCDN publishes its edge list as plain-text JSON arrays.
    out = []
    for url in ("https://bunnycdn.com/api/system/edgeserverlist",
                "https://bunnycdn.com/api/system/edgeserverlist/ipv6"):
        try:
            for ip in json.loads(_get(url)):
                out.append((ip + ("/128" if ":" in ip else "/32"), "bunnycdn", "cdn"))
        except Exception as e:
            print(f"  bunnycdn {url}: {e}", file=sys.stderr)
    return out


SOURCES = [src_cloudflare, src_fastly, src_aws_cloudfront, src_google_cloud, src_bunny]

# CDNs/WAFs that do NOT publish a machine-readable range list (need ASN lookup instead).
# Recorded so the analyst knows these can't be caught by CIDR alone.
NO_PUBLIC_LIST = {
    "akamai": "AS16625/AS20940 — no public CIDR list; classify via ASN",
    "imperva_incapsula": "AS19551 — partial list behind login",
    "sucuri": "classify via ASN AS30148",
    "stackpath": "no stable public list",
    "cloudfront_note": "covered above via AWS ip-ranges",
}


def update():
    ranges, per = [], {}
    for fn in SOURCES:
        got = fn()
        for cidr, prov, kind in got:
            ranges.append({"cidr": cidr, "provider": prov, "kind": kind})
            per[prov] = per.get(prov, 0) + 1
    # de-dup
    seen, uniq = set(), []
    for r in ranges:
        if r["cidr"] not in seen:
            seen.add(r["cidr"])
            uniq.append(r)
    doc = {
        "updated": datetime.now(timezone.utc).isoformat(),
        "count": len(uniq),
        "per_provider": per,
        "no_public_list": NO_PUBLIC_LIST,
        "ranges": uniq,
    }
    os.makedirs(os.path.dirname(CACHE), exist_ok=True)
    json.dump(doc, open(CACHE, "w"), indent=1)
    print(f"wrote {CACHE}: {len(uniq)} CIDRs from {len(per)} providers", file=sys.stderr)
    print(f"  {per}", file=sys.stderr)
    return doc


# --- classification --------------------------------------------------------------


def load_ranges(path=CACHE):
    """Return a fast index: {'v4':[(net,provider,kind)], 'v6':[...], 'meta':{...}}."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"{path} missing — run: cdn_ranges.py --update")
    doc = json.load(open(path))
    idx = {"v4": [], "v6": [], "meta": {k: doc.get(k) for k in ("updated", "count", "per_provider")}}
    for r in doc.get("ranges", []):
        try:
            net = ipaddress.ip_network(r["cidr"], strict=False)
        except ValueError:
            continue
        idx["v6" if net.version == 6 else "v4"].append((net, r["provider"], r["kind"]))
    return idx


def classify(ip, idx):
    """{'ip', 'cdn'(bool), 'provider', 'kind'}. cdn=False => candidate origin."""
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return {"ip": ip, "cdn": None, "provider": None, "kind": "invalid"}
    for net, prov, kind in idx["v6" if addr.version == 6 else "v4"]:
        if addr in net:
            return {"ip": ip, "cdn": True, "provider": prov, "kind": kind}
    return {"ip": ip, "cdn": False, "provider": None, "kind": "origin_candidate"}


def main():
    ap = argparse.ArgumentParser(description="Classify IPs as CDN/cloud edge vs candidate origin.")
    ap.add_argument("--update", action="store_true", help="fetch + cache published CDN/cloud ranges")
    ap.add_argument("--classify", nargs="*", help="IP(s) to classify")
    ap.add_argument("-f", "--file", help="file of IPs, one per line")
    ap.add_argument("--stats", action="store_true", help="show cache stats")
    ap.add_argument("--json", action="store_true", help="JSON output")
    args = ap.parse_args()

    if args.update:
        update()
        if not (args.classify or args.file or args.stats):
            return

    if args.stats:
        idx = load_ranges()
        print(json.dumps({"cache": CACHE, **idx["meta"],
                          "v4_cidrs": len(idx["v4"]), "v6_cidrs": len(idx["v6"])}, indent=1))
        return

    ips = list(args.classify or [])
    if args.file:
        ips += [l.strip() for l in open(args.file) if l.strip()]
    if not ips:
        ap.error("give IPs via --classify, -f, or run --update/--stats")
    idx = load_ranges()
    results = [classify(ip, idx) for ip in ips]
    if args.json:
        print(json.dumps(results, indent=1))
    else:
        for r in results:
            tag = ("CDN/cloud: " + r["provider"]) if r["cdn"] else \
                  ("ORIGIN candidate" if r["cdn"] is False else "invalid")
            print(f"  {r['ip']:<40} {tag}")


if __name__ == "__main__":
    main()
