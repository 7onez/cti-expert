#!/usr/bin/env python3
"""vuln_check.py — CVE lookup against the two corpora that are still genuinely keyless.

CIRCL cve-search and NVD API v2 both answer without a key (verified 2026-08-28). NVD rate-limits
hard without one — 5 requests / 30s — so CIRCL is tried first and NVD is the corroborator, not
the primary. Two sources matter here: CIRCL can lag on very fresh CVEs, NVD can lag on enrichment,
and a single-source severity is a number you cannot defend in a report.

Reconnaissance only. This maps a product/version to PUBLIC advisories; it never probes a host.

Usage:
  vuln_check.py CVE-2021-44228
  vuln_check.py --product apache/httpd [--limit 20]
  vuln_check.py CVE-2021-44228 --pretty -o cve.json
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

UA = "cti-expert/vuln_check (OSINT research)"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)


def _get(url, timeout=20):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r), None
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code}"
    except Exception as e:  # noqa: BLE001
        return None, type(e).__name__


def _cvss_from_circl(d):
    """CIRCL now returns CVE Record 5.1 — severity lives under containers.cna.metrics."""
    for m in (d.get("containers", {}).get("cna", {}) or {}).get("metrics", []) or []:
        for k, v in m.items():
            if k.startswith("cvssV") and isinstance(v, dict):
                return {"version": k, "score": v.get("baseScore"),
                        "severity": v.get("baseSeverity"), "vector": v.get("vectorString")}
    if d.get("cvss") is not None:                       # legacy shape, still seen on old records
        return {"version": "cvss", "score": d.get("cvss"), "severity": None, "vector": None}
    return None


def _desc_from_circl(d):
    for x in (d.get("containers", {}).get("cna", {}) or {}).get("descriptions", []) or []:
        if x.get("lang", "").lower().startswith("en"):
            return x.get("value")
    return d.get("summary")


def lookup_cve(cve):
    cve = cve.upper()
    out = {"cve": cve, "sources": {}, "severity": None, "description": None, "references": []}

    d, err = _get(f"https://cve.circl.lu/api/cve/{urllib.parse.quote(cve)}")
    if d and not err:
        out["sources"]["circl"] = "ok"
        out["severity"] = _cvss_from_circl(d)
        out["description"] = _desc_from_circl(d)
        refs = (d.get("containers", {}).get("cna", {}) or {}).get("references", []) or []
        out["references"] = [r.get("url") for r in refs if r.get("url")][:12]
        meta = d.get("cveMetadata", {}) or {}
        out["published"] = meta.get("datePublished")
        out["state"] = meta.get("state")
    else:
        out["sources"]["circl"] = f"unavailable ({err})"

    d2, err2 = _get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={urllib.parse.quote(cve)}")
    if d2 and not err2:
        vulns = d2.get("vulnerabilities") or []
        if vulns:
            c = vulns[0].get("cve", {})
            out["sources"]["nvd"] = "ok"
            metrics = c.get("metrics", {}) or {}
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(key):
                    md = metrics[key][0].get("cvssData", {})
                    nvd_sev = {"version": key, "score": md.get("baseScore"),
                               "severity": md.get("baseSeverity"), "vector": md.get("vectorString")}
                    out["nvd_severity"] = nvd_sev
                    if not out["severity"]:
                        out["severity"] = nvd_sev
                    break
            if not out["description"]:
                for dd in c.get("descriptions", []) or []:
                    if dd.get("lang") == "en":
                        out["description"] = dd.get("value")
                        break
            out["nvd_status"] = c.get("vulnStatus")
        else:
            out["sources"]["nvd"] = "no record"
    else:
        out["sources"]["nvd"] = f"unavailable ({err2})"

    # Disagreement between two independent scorers is a REPORTABLE fact, not a glitch to hide.
    a, b = out.get("severity") or {}, out.get("nvd_severity") or {}
    if a.get("score") is not None and b.get("score") is not None and a["score"] != b["score"]:
        out["severity_disagreement"] = {"circl": a.get("score"), "nvd": b.get("score")}

    if not any(v == "ok" for v in out["sources"].values()):
        out["verdict"] = "NO DATA — both corpora unreachable; report as absence of record"
    elif out["description"]:
        out["verdict"] = "resolved"
    else:
        out["verdict"] = "record exists but carries no English description"
    return out


def search_product(product, limit=20):
    """Keyword search on NVD. CIRCL's /api/search was retired with the 5.1 migration."""
    q = urllib.parse.quote(product.replace("/", " "))
    url = (f"https://services.nvd.nist.gov/rest/json/cves/2.0"
           f"?keywordSearch={q}&resultsPerPage={min(int(limit), 100)}")
    d, err = _get(url, timeout=30)
    if err or not d:
        return {"product": product, "error": f"NVD unavailable ({err})", "results": []}
    rows = []
    for v in d.get("vulnerabilities", []) or []:
        c = v.get("cve", {})
        sev = None
        for key in ("cvssMetricV31", "cvssMetricV30"):
            if (c.get("metrics", {}) or {}).get(key):
                md = c["metrics"][key][0].get("cvssData", {})
                sev = {"score": md.get("baseScore"), "severity": md.get("baseSeverity")}
                break
        desc = next((x.get("value") for x in c.get("descriptions", []) or []
                     if x.get("lang") == "en"), None)
        rows.append({"cve": c.get("id"), "published": c.get("published"),
                     "severity": sev, "description": (desc or "")[:220]})
    rows.sort(key=lambda r: (r["severity"] or {}).get("score") or 0, reverse=True)
    return {"product": product, "total": d.get("totalResults"), "results": rows}


def main():
    ap = argparse.ArgumentParser(description="CVE lookup (CIRCL + NVD, both keyless).")
    ap.add_argument("cve", nargs="*", help="one or more CVE ids")
    ap.add_argument("--product", help="keyword/product search instead of a CVE id")
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--pretty", action="store_true")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()

    if a.product:
        out = search_product(a.product, a.limit)
        n = len(out.get("results", []))
        print(f"{a.product}: {n} CVE(s) (of {out.get('total', '?')} total)", file=sys.stderr)
    elif a.cve:
        bad = [c for c in a.cve if not CVE_RE.match(c)]
        if bad:
            ap.error(f"not CVE ids: {', '.join(bad)} — use --product for keyword search")
        res = [lookup_cve(c) for c in a.cve]
        out = {"results": res}
        for r in res:
            sev = (r.get("severity") or {})
            print(f"{r['cve']}: {sev.get('severity') or '?'} "
                  f"{sev.get('score') if sev.get('score') is not None else ''} "
                  f"[{', '.join(f'{k}={v}' for k, v in r['sources'].items())}]", file=sys.stderr)
    else:
        ap.error("give a CVE id or --product")

    txt = json.dumps(out, indent=2 if a.pretty else None, ensure_ascii=False)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(txt)
    print(txt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
