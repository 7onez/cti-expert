#!/usr/bin/env python3
"""TLS certificate / SAN-overlap check across a set of domains — a correlation (Analyze-phase)
signal, not collection. Two domains sharing a TLS certificate is one of the strongest
same-operator links there is: a SAN list is chosen by whoever controls the cert, so a single
cert whose SAN names cover two otherwise-unrelated domains binds them to one owner (near-decisive),
and two domains whose certs both carry a third common domain is a strong shared-infra tell.

Keyless CT through the shared client (wp_ct: crt.sh → PostgreSQL → Shodan CTL + CertSpotter). For
each domain it pulls every logged cert (deduplicated across sources by serial / sha256 / precert
twin) plus that cert's SAN names, then:
  - SHARED CERT      one certificate's SAN list covers >= 2 of the input domains  -> decisive
  - SAN CROSS-COVER  domain B's apex appears in a cert returned for domain A       -> decisive
  - SIBLING OVERLAP  two inputs' certs both carry the SAME third registrable domain -> strong
  - NO CT OVERLAP    none of the above, and crt.sh answered for every input        -> clean negative
  - INCONCLUSIVE-CT-DEGRADED  none of the above, but crt.sh was unreachable for an input — its
                     backups hold ~1 year, so an older shared cert would be invisible: NOT a negative

Usage:
  python3 tools/cert_overlap.py site-a.example site-b.example [--json]
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import sys
import urllib.parse

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "WebPivot", "tools"))
import wp_ct  # noqa: E402 — the one CT client


def _host(s: str) -> str:
    s = s.strip()
    if "://" in s:
        s = urllib.parse.urlparse(s).hostname or s
    return s.split("/")[0].lower()


def _reg(name: str) -> str:
    """Best-effort registrable domain (last two labels) — good enough to tell siblings apart."""
    return ".".join(name.lstrip("*.").split(".")[-2:])


def certs_for(domain: str) -> dict:
    """Every logged cert for `domain` through wp_ct, as {'certs': [{id, issuer, sans:set,
    not_before}], 'crtsh': ok|empty|degraded, 'completeness_line'}. Uncapped: an overlap hidden
    behind a listing cap would read as a negative."""
    r = wp_ct.ct_search(domain, max_certs=None, max_subdomains=None)
    certs = [{"id": c.get("id"), "issuer": c.get("issuer_cn") or c.get("issuer"),
              "sans": {n.lstrip("*.") for n in c.get("names") or []},
              "not_before": c.get("not_before")} for c in r.get("certs") or []]
    return {"certs": certs, "crtsh": (r.get("ct_status") or {}).get("crt.sh", {}).get("status"),
            "completeness_line": r.get("completeness_line")}


def analyze(domains: list[str]) -> dict:
    domains = [_host(d) for d in domains]
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(6, len(domains) or 1)) as ex:
        ct = dict(zip(domains, ex.map(certs_for, domains)))
    certs = {d: ct[d]["certs"] for d in domains}
    degraded = [d for d in domains if ct[d]["crtsh"] == "degraded"]

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
    elif degraded:
        verdict, why = "INCONCLUSIVE-CT-DEGRADED", (
            f"No shared cert, SAN cross-cover or common sibling in what was collected, but crt.sh was "
            f"unreachable for {', '.join(degraded)} — its backups cover ~1 year, so an older shared "
            "certificate would not be visible. This is NOT a negative: re-run when crt.sh answers.")
    else:
        verdict, why = "NO-CT-OVERLAP", (
            "No shared cert, no SAN cross-cover, no common sibling domain across these certs. "
            "TLS does not corroborate a same-operator link here — rely on other pivots.")

    return {"domains": domains, "verdict": verdict, "rationale": why,
            "cert_counts": {d: len(certs[d]) for d in domains},
            "ct_completeness": {d: ct[d]["completeness_line"] for d in domains},
            "shared_certs": shared_certs, "cross_cover": cross_cover,
            "sibling_overlap": sibling_overlap[:20]}


def _human(r: dict) -> str:
    out = [f"CERT/SAN OVERLAP · {', '.join(r['domains'])} · VERDICT: {r['verdict']}",
           f"  {r['rationale']}",
           "  certs seen: " + ", ".join(f"{d}={n}" for d, n in r["cert_counts"].items())]
    for d, line in (r.get("ct_completeness") or {}).items():
        out.append(f"  CT {d}: {line}")
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
