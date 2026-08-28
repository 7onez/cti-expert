#!/usr/bin/env python3
"""cn_recon.py — PRC filing and corporate-registry recon: what is resolvable, and what is gated.

Backs /icp and /cn-corp. Both walk the same chain (domain -> ICP filing -> registered entity ->
corporate registry), so they share one tool.

BE HONEST ABOUT THE WALL. The authoritative sources are not machine-readable by design:
  - beian.miit.gov.cn (the ICP register) is CAPTCHA-walled and Chinese-only.
  - GSXT (the company register, ground truth for a PRC entity) uses a slider CAPTCHA.
  - TianYanCha / QCC / Aiqicha are IP-BLOCKED outside mainland China and need a +86 account.
None of that is worked around here. What this does instead: pull the keyless mirrors that do
answer, reverse the LICENCE SERIAL into sibling-domain queries, and hand over the exact lookups
for the gated sources with their gate named — so an analyst without CN egress knows precisely
what is missing rather than reading an empty result as "no filing".

The serial is the pivot, never the province. 苏ICP备12345678号-3 clusters on 12345678: the 苏
prefix is a whole province and the -3 suffix is one site within one filing.

Usage:
  cn_recon.py example.com
  cn_recon.py --serial 12345678 --pretty
"""
# /// script
# requires-python = ">=3.9"
# ///
import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

UA = "Mozilla/5.0 (compatible; cti-expert/cn_recon)"
SERIAL = re.compile(r"([一-鿿]{0,3})ICP[备备]?\s*(\d{6,10})号?(?:-(\d+))?", re.I)


def _get(url, timeout=20, as_json=True):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
        return (json.loads(raw) if as_json else raw), None
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code}"
    except Exception as e:  # noqa: BLE001
        return None, type(e).__name__


def icp_mirror(domain):
    """Keyless community mirrors of the MIIT register. They go stale — corroborate before use."""
    out = {}
    d, err = _get("https://api.vvhan.com/api/icp?url=" + urllib.parse.quote(domain))
    if d and not err and isinstance(d, dict):
        info = d.get("info") or d.get("data") or {}
        if isinstance(info, dict) and (info.get("icp") or info.get("name")):
            out = {"status": "ok", "source": "vvhan mirror",
                   "licence": info.get("icp"), "entity": info.get("name"),
                   "nature": info.get("nature"), "title": info.get("title")}
    if not out:
        out = {"status": f"no mirror answered ({err or 'empty'})"}
    out["caveat"] = ("community MIRROR of beian.miit.gov.cn, not the register itself. Mirrors go "
                     "stale and drop revoked filings — treat a hit as a LEAD and confirm at "
                     "beian.miit.gov.cn (CAPTCHA, manual) before asserting the entity.")
    return out


def serial_pivots(serial):
    """Reverse the licence serial to sibling domains under one filing."""
    s = str(serial)
    return {
        "cluster_on": s,
        "never_cluster_on": "the province prefix (苏/京/沪…) — it covers a whole province",
        "queries": {
            "publicwww": [f'"ICP备{s}号"'],
            "fofa": [f'body="ICP备{s}"'],
            "quake": [f'body:"ICP备{s}"'],
            "zoomeye": [f'body:"ICP备{s}"'],
            "google": [f'"ICP备{s}号"'],
        },
        "suffix_walk": ([f"{s}号-{i}" for i in range(1, 6)],
                        "sites under ONE filing are numbered -1, -2, -3 …; walk the suffix to "
                        "enumerate siblings"),
    }


GATED = {
    "beian.miit.gov.cn": {"gate": "CAPTCHA + Chinese-only", "authority": "AUTHORITATIVE ICP register",
                          "url": "https://beian.miit.gov.cn/#/Integrated/recordQuery"},
    "GSXT": {"gate": "slider CAPTCHA", "authority": "GROUND TRUTH for a PRC company",
             "url": "https://www.gsxt.gov.cn/"},
    "TianYanCha": {"gate": "IP-blocked outside mainland CN; needs +86 account",
                   "authority": "shareholders, officers, branches", "url": "https://www.tianyancha.com/"},
    "QCC": {"gate": "IP-blocked outside mainland CN", "authority": "same as TianYanCha",
            "url": "https://www.qcc.com/"},
    "Aiqicha": {"gate": "IP-blocked outside mainland CN", "authority": "Baidu's registry view",
                "url": "https://aiqicha.baidu.com/"},
    "信用中国": {"gate": "limited API", "authority": "penalties / 失信 blacklist",
                 "url": "https://www.creditchina.gov.cn/"},
}


def main():
    ap = argparse.ArgumentParser(description="PRC ICP filing + corporate registry recon.")
    ap.add_argument("domain", nargs="?")
    ap.add_argument("--serial", help="pivot a licence serial you already hold")
    ap.add_argument("--company", help="a PRC entity name or USCC to build registry lookups for")
    ap.add_argument("--pretty", action="store_true")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()
    if not (a.domain or a.serial or a.company):
        ap.error("give a domain, --serial or --company")

    out = {"gated_sources": GATED,
           "collection_gap": ("The AUTHORITATIVE sources above are CAPTCHA-walled or geo-gated and "
                              "are NOT queried here. An empty result is an absence of collection, "
                              "never evidence that no filing or company exists.")}
    serial = a.serial
    if a.domain:
        dom = a.domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
        out["domain"] = dom
        out["icp"] = icp_mirror(dom)
        lic = (out["icp"] or {}).get("licence") or ""
        m = SERIAL.search(lic)
        if m and not serial:
            serial = m.group(2)
            out["icp"]["parsed"] = {"province_prefix": m.group(1) or None,
                                    "serial": m.group(2), "site_suffix": m.group(3)}
    if serial:
        out["serial_pivot"] = serial_pivots(serial)
    if a.company:
        c = a.company.strip()
        out["company_lookups"] = {
            "GSXT (ground truth, CAPTCHA)": f"https://www.gsxt.gov.cn/  → search {c}",
            "信用中国 (penalties)": "https://www.creditchina.gov.cn/  → search " + c,
            "TianYanCha (CN egress required)": "https://www.tianyancha.com/search?key="
                                               + urllib.parse.quote(c),
            "ENScan_GO (CLI, needs aggregator cookies)": f"enscan -n \"{c}\" -type all",
            "note": "run these from CN egress or by hand; none is queried here",
        }

    icp = out.get("icp") or {}
    print(f"{a.domain or a.serial or a.company}: "
          f"ICP {icp.get('status', 'not queried')}"
          + (f" — licence {icp.get('licence')}" if icp.get("licence") else "")
          + (f"; serial pivot on {serial}" if serial else ""), file=sys.stderr)
    print("  authoritative sources are CAPTCHA/geo-gated and were NOT queried — see gated_sources",
          file=sys.stderr)
    txt = json.dumps(out, indent=2 if a.pretty else None, ensure_ascii=False)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(txt)
    print(txt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
