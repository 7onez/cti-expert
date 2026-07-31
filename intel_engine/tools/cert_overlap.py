#!/usr/bin/env python3
"""TLS certificate / SAN-overlap check across a set of domains — a correlation (Analyze-phase)
signal, not collection. Two domains sharing a TLS certificate is one of the strongest
same-operator links there is: a SAN list is chosen by whoever controls the cert, so a single
cert whose SAN names cover two otherwise-unrelated domains binds them to one owner (near-decisive),
and two domains whose certs both carry a third common domain is a strong shared-infra tell.

Keyless, dual-source CT (Shodan CTL mirror + crt.sh). For each domain it pulls every logged
cert (identity = sha256 fingerprint from Shodan / crt.sh id) plus that cert's SAN names, then:
  - SHARED CERT      one certificate's SAN list covers >= 2 of the input domains  -> decisive
  - SAN CROSS-COVER  domain B's apex appears in a cert returned for domain A       -> decisive
  - SIBLING OVERLAP  two inputs' certs both carry the SAME third registrable domain -> strong
  - NO CT OVERLAP    none of the above

Usage:
  python3 tools/cert_overlap.py site-a.example site-b.example [--json]
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import sys
import urllib.parse
import urllib.request

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"


def _host(s: str) -> str:
    s = s.strip()
    if "://" in s:
        s = urllib.parse.urlparse(s).hostname or s
    return s.split("/")[0].lower()


def _reg(name: str) -> str:
    """Best-effort registrable domain (last two labels) — good enough to tell siblings apart."""
    return ".".join(name.lstrip("*.").split(".")[-2:])


def _get(url: str, timeout: int = 20) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "ignore")


def certs_for(domain: str) -> list[dict]:
    """Every logged cert for `domain`, as [{id, issuer, sans:set, not_before}], merged from
    Shodan CTL (sha256 fingerprint id) and crt.sh (crt.sh id). Each source is best-effort."""
    out, seen = [], set()

    # Shodan CTL — cert objects with a sha256 fingerprint (the cross-domain-stable identity)
    try:
        for row in json.loads(_get(
                f"https://ctl.shodan.io/api/v1/domain/{urllib.parse.quote(domain)}")):
            cid = "sha256:" + str(row.get("hash", ""))
            if cid in seen or not row.get("hash"):
                continue
            seen.add(cid)
            sans = {str(n).strip().lower().lstrip("*.")
                    for n in (row.get("san_dns_names") or []) if n}
            cn = str(row.get("subject_cn", "")).strip().lower().lstrip("*.")
            if cn:
                sans.add(cn)
            out.append({"id": cid, "issuer": row.get("issuer_cn"), "sans": sans,
                        "not_before": row.get("not_before")})
    except Exception:
        pass

    # crt.sh — supplement (its own row id; ?identity= is the steadier form)
    try:
        rows = []
        for param in ("q", "identity"):
            try:
                data = json.loads(_get("https://crt.sh/?" + urllib.parse.urlencode(
                    {param: domain, "output": "json"})))
                if isinstance(data, list):
                    rows = data
                    break
            except Exception:
                continue
        for row in rows:
            cid = "crtsh:" + str(row.get("id", ""))
            if cid in seen or not row.get("id"):
                continue
            seen.add(cid)
            sans = {n.strip().lower().lstrip("*.")
                    for n in str(row.get("name_value", "")).splitlines() if n and "@" not in n}
            cn = str(row.get("common_name", "")).strip().lower().lstrip("*.")
            if cn:
                sans.add(cn)
            out.append({"id": cid, "issuer": row.get("issuer_name"), "sans": sans,
                        "not_before": row.get("not_before")})
    except Exception:
        pass
    return out


def analyze(domains: list[str]) -> dict:
    domains = [_host(d) for d in domains]
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(6, len(domains) or 1)) as ex:
        certs = dict(zip(domains, ex.map(certs_for, domains)))

    shared_certs, cross_cover, sibling_overlap = [], [], []
    # every registrable domain each input's certs carry
    reg_by_dom = {d: {_reg(s) for c in certs[d] for s in c["sans"]} for d in domains}

    for i, a in enumerate(domains):
        for b in domains[i + 1:]:
            # (1) SHARED CERT / CROSS-COVER — a cert returned for A whose SANs include B (apex)
            for c in certs[a]:
                if b in c["sans"] or _reg(b) in {_reg(s) for s in c["sans"]}:
                    (shared_certs if any(b in cc["sans"] and a in cc["sans"]
                     for cc in certs[a]) else cross_cover).append(
                        {"a": a, "b": b, "cert": c["id"], "issuer": c["issuer"],
                         "sans_sample": sorted(c["sans"])[:8]})
                    break
            # (2) SIBLING OVERLAP — a third registrable domain both A and B certs carry
            common = (reg_by_dom[a] & reg_by_dom[b]) - {_reg(a), _reg(b)}
            if common:
                sibling_overlap.append({"a": a, "b": b, "shared_registrable": sorted(common)[:8]})

    if shared_certs or cross_cover:
        verdict, why = "SHARED-CERT", (
            "A single TLS certificate's SAN list covers two of the input domains — decisive "
            "same-owner link (SAN names are set by whoever controls the cert).")
    elif sibling_overlap:
        verdict, why = "SIBLING-OVERLAP", (
            "Input domains' certs carry a common third registrable domain — strong shared-infra "
            "signal; confirm the third domain isn't a shared CDN/SaaS host before clustering.")
    else:
        verdict, why = "NO-CT-OVERLAP", (
            "No shared cert, no SAN cross-cover, no common sibling domain across these certs. "
            "TLS does not corroborate a same-operator link here — rely on other pivots.")

    return {"domains": domains, "verdict": verdict, "rationale": why,
            "cert_counts": {d: len(certs[d]) for d in domains},
            "shared_certs": shared_certs, "cross_cover": cross_cover,
            "sibling_overlap": sibling_overlap[:20]}


def _human(r: dict) -> str:
    out = [f"CERT/SAN OVERLAP · {', '.join(r['domains'])} · VERDICT: {r['verdict']}",
           f"  {r['rationale']}",
           "  certs seen: " + ", ".join(f"{d}={n}" for d, n in r["cert_counts"].items())]
    for s in r["shared_certs"]:
        out.append(f"  🔗 SHARED CERT {s['a']} ⇄ {s['b']}  [{s['issuer']}]  cert={s['cert']}")
        out.append(f"       SANs: {', '.join(s['sans_sample'])}")
    for s in r["cross_cover"]:
        out.append(f"  🔗 SAN CROSS-COVER: a cert for {s['a']} lists {s['b']}  [{s['issuer']}]")
        out.append(f"       SANs: {', '.join(s['sans_sample'])}")
    for s in r["sibling_overlap"]:
        out.append(f"  • sibling overlap {s['a']} ⇄ {s['b']}: {', '.join(s['shared_registrable'])}")
    if r["verdict"] == "NO-CT-OVERLAP":
        out.append("  (no TLS-level link found)")
    return "\n".join(out)


def _main() -> None:
    ap = argparse.ArgumentParser(description="TLS cert / SAN-overlap check across domains")
    ap.add_argument("domains", nargs="+", help="two or more domains to compare")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    if len({_host(d) for d in a.domains}) < 2:
        sys.exit("need at least two distinct domains")
    r = analyze(a.domains)
    print(json.dumps(r, ensure_ascii=False, indent=2) if a.json else _human(r))


if __name__ == "__main__":
    _main()
