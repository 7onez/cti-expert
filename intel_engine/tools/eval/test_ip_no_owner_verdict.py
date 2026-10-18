#!/usr/bin/env python3
"""Offline gate for two IP-cluster rails (WebPivot/references/origin_history.json):

  1. no_owner_verdict — a parallel-run cluster whose members are only IPs, every one classified as
     cdn / parking / bogon / ad-edge / shared-hosting / platform with no owner-rung signal, gets a
     fixed `inconclusive` verdict from harness/orchestrator._no_owner_verdict and ZERO LLM assess
     calls; a cluster with one owner-rung member (a served certificate, or a real domain) still
     goes to the judge.
  2. ad_edge — a host answering on many AWS addresses across 3+ regions in one window is an ad
     network's edge pool (wp_origin_history.mark_ad_edges): two publishers sharing only that pool
     write no hosted_on edge and never cluster.

All seams stubbed, every input synthetic (RFC 5737 addresses, .example hosts, private-use ASNs).
"""
from __future__ import annotations

import asyncio
import datetime
import ipaddress
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.dirname(HERE)
ENGINE = os.path.dirname(TOOLS)
HARNESS = os.path.join(ENGINE, "harness")
for _p in (TOOLS, os.path.join(TOOLS, "kb"), os.path.join(ENGINE, "WebPivot", "tools"), HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import wp_origin_history as OH  # noqa: E402

TODAY = datetime.date.today().isoformat()
PARK_IP, CERT_IP = "198.51.100.7", "198.51.100.8"
# eight synthetic "regions": /27 slices of TEST-NET-3
EDGE_REGIONS = {f"region-{i}": [ipaddress.ip_network(f"203.0.113.{i * 32}/27")] for i in range(8)}
EDGE_IPS = [f"203.0.113.{i * 32 + 5}" for i in range(8)]


class _FakeCdn:
    """cdn_ranges stand-in: only 127/8, 10/8, 192.168/16 are bogons, nothing is a published edge."""

    @staticmethod
    def is_bogon(ip):
        a = ipaddress.ip_address(ip)
        return any(a in ipaddress.ip_network(n) for n in ("127.0.0.0/8", "10.0.0.0/8", "192.168.0.0/16"))

    @staticmethod
    def classify(ip, idx):
        return {"ip": ip, "cdn": False, "provider": None, "kind": "origin_candidate"}


def _ip_raw(ip, asn, org, extra_pivots=()):
    return {"meta": {"host": ip, "kind": "ip", "source": "IPPivot"},
            "artifacts": {"ip_intel": {"ipinfo": {"asn": asn, "org_name": org},
                                       "classification": {"ip": ip, "cdn": False, "kind": "origin_candidate"},
                                       "co_hosted_domains": [], "cohost_total": 0, "noise": False}},
            "pivots": [{"kind": "ip:information", "value": ip}, {"kind": "ip:asn", "value": f"{asn} {org}"},
                       *extra_pivots]}


def _run_parallel(orch, tmp, case, clusters, raws):
    """run_case_parallel over `clusters` with every collection/LLM seam stubbed; returns
    (entries, judge_calls)."""
    raw_dir = os.path.join(tmp, "cases", case, "raw")
    os.makedirs(raw_dir, exist_ok=True)
    for name, obj in raws.items():
        with open(os.path.join(raw_dir, f"{name}.json"), "w", encoding="utf-8") as fh:
            json.dump(obj, fh)
    from schemas import Assessment
    calls = []

    async def fake_judge(members, case_, members_only=False):
        calls.append(list(members))
        return (Assessment(bluf="judged", attribution_level="inconclusive", confidence="low",
                           cluster=[{"domain": m} for m in members]), {})

    hosts = sorted({m for c in clusters for m in c})
    names = ("ROOT", "_judge", "_compute_components", "_cluster_prior_verdict", "_domain_table",
             "_render_deliverables", "_report_cost", "_hand_back", "_binary_round",
             "_convergence_snapshot", "_all_collected")
    saved = {n: getattr(orch, n) for n in names}
    saved_T = (orch.T.collect_many, orch.T.ingest)
    import case_state as CS
    saved_cs_root = CS.ROOT
    try:
        orch.ROOT = CS.ROOT = tmp      # state.json / seeds / hops land in the temp case, never cases/
        orch._judge = fake_judge
        orch._compute_components = lambda case_, doms: [list(c) for c in clusters]
        orch._cluster_prior_verdict = lambda members: None
        orch._domain_table = lambda case_: ""
        orch._render_deliverables = lambda *a, **k: {}
        orch._report_cost = lambda *a, **k: None
        orch._hand_back = lambda *a, **k: None
        orch._binary_round = lambda *a, **k: None
        orch._convergence_snapshot = lambda case_, **k: ""
        orch._all_collected = lambda case_: hosts
        orch.T.collect_many = lambda *a, **k: [{"host": h, "ok": True, "reused": True} for h in hosts]
        orch.T.ingest = lambda case_: (True, "")
        entries = asyncio.run(orch.run_case_parallel(hosts, case, hostile=False, max_conc=2, judge_conc=2))
    finally:
        for n, v in saved.items():
            setattr(orch, n, v)
        orch.T.collect_many, orch.T.ingest = saved_T
        CS.ROOT = saved_cs_root
    return entries, calls


def check():
    out, passed, failed = [], 0, 0

    def ok(cond, label):
        nonlocal passed, failed
        passed, failed = (passed + 1, failed) if cond else (passed, failed + 1)
        out.append(("ok" if cond else "FAIL", label))

    saved_cdn, saved_regions = OH._cdn, OH.AD_EDGE_REGION_CIDRS
    saved_parking = OH.PARKING_MARKERS
    OH._cdn = lambda: (_FakeCdn, {"fake": True})
    OH.PARKING_MARKERS = tuple(saved_parking) + ("parkfarm",)   # the synthetic parking org below
    try:
        # --- 1. classifier units ---------------------------------------------------------------
        park = _ip_raw(PARK_IP, "AS64500", "ParkFarm Example Ltd")
        got = OH.no_owner_class(PARK_IP, park["artifacts"]["ip_intel"])
        ok(got is not None and got[0] == "parking" and "AS64500" in got[1],
           f"a parking-network IP classifies as parking with its ASN (got {got!r})")
        vps = _ip_raw("198.51.100.9", "AS64501", "Small VPS Example")
        vps["artifacts"]["ip_intel"].update({"noise": True, "cohost_total": 2})
        ok(OH.no_owner_class("198.51.100.9", vps["artifacts"]["ip_intel"]) is None,
           "a small noise-flagged VPS is NOT a no-owner class (may be the operator's own box)")
        cert = _ip_raw(CERT_IP, "AS64500", "ParkFarm Example Ltd",
                       [{"kind": "tls_cert:fingerprint_sha256", "value": "ab" * 32}])
        ok(OH.owner_signal(cert) and not OH.owner_signal(park),
           "a served leaf certificate is an owner-rung signal; ASN/info pivots are not")

        # --- 2. ad-network edge pool ------------------------------------------------------------
        OH.AD_EDGE_REGION_CIDRS = EDGE_REGIONS
        lr = {"dns": {"ips": list(EDGE_IPS)}}
        blk = OH.build(lr, None, "a.example")
        ok(all(r["status"] == "cdn" and r["provider"] == OH.AD_EDGE_PROVIDER for r in blk["ips"])
           and not blk["origin_candidates"],
           "8 live addresses across 8 ad-edge regions are reclassified cdn (ad edge), none collectable")
        two = OH.build({"dns": {"ips": EDGE_IPS[:2]}}, None, "solo.example")
        ok(all(r["status"] == "origin" for r in two["ips"]),
           "two addresses in two regions stay origins (below the ad-edge bounds)")
        stored = {"origin_history": {"ips": [{"ip": ip, "status": "origin", "live": True, "sources": ["live_dns"]}
                                             for ip in EDGE_IPS]}}
        ok(all(r["status"] == "cdn" for r in OH.block_for(stored)["ips"]),
           "a stored pre-rule origin_history block gets the ad-edge rule re-applied")

        import ingest_webpivot as IW
        from knowledge_base import KB
        with tempfile.TemporaryDirectory() as kbdir:
            kb = KB(kbdir)
            for host in ("a.example", "b.example"):
                IW._resolved_ip_edges(kb, host, {"dns": {"ips": list(EDGE_IPS)}}, TODAY, "ev")
            shared = kb.shared_indicators(min_domains=2, drop_noise=False)
            ips_shared = [s for s in shared if str(s.get("indicator", "")).startswith("ip:")]
            ok(not ips_shared,
               f"two domains sharing only an 8-region ad-edge set are NOT clustered (shared ip indicators: "
               f"{len(ips_shared)})")
        OH.AD_EDGE_REGION_CIDRS = saved_regions

        # --- 3. parallel fan-out: deterministic verdict vs LLM ----------------------------------
        sys.path.insert(0, HARNESS)
        os.environ.setdefault("HARNESS_BACKEND", "codex")
        try:
            import backend_select as bs
            bs.PROBE_CACHE = os.path.join(tempfile.mkdtemp(prefix="intel-probe-cache-"), "backend_probe.json")
            import orchestrator as orch
        except ImportError as e:
            out.append(("skip", f"harness modules unavailable ({e}) — re-run under the harness venv"))
            return passed, failed, out

        with tempfile.TemporaryDirectory() as tmp:
            entries, calls = _run_parallel(orch, tmp, "CASE-0001", [[PARK_IP]], {PARK_IP: park})
            a = entries[0][1] if entries else None
            ok(not calls, f"IP-only parking cluster: zero LLM assess calls (got {len(calls)})")
            ok(a is not None and a.attribution_level == "inconclusive" and a.confidence == "high"
               and len(a.evidence) == 1 and "parking" in a.evidence[0] and "AS64500" in a.evidence[0],
               f"deterministic verdict: inconclusive, class confidence, one evidence line naming ASN/class "
               f"(got {a.evidence if a else None!r})")
        with tempfile.TemporaryDirectory() as tmp:
            entries, calls = _run_parallel(orch, tmp, "CASE-0002", [[PARK_IP, CERT_IP]],
                                           {PARK_IP: park, CERT_IP: cert})
            ok(len(calls) == 1, f"a cluster with an owner-rung member (served cert) still calls the judge "
                                f"(got {len(calls)})")
        with tempfile.TemporaryDirectory() as tmp:
            entries, calls = _run_parallel(orch, tmp, "CASE-0003", [[PARK_IP, "shop.example"]],
                                           {PARK_IP: park})
            ok(len(calls) == 1, "a cluster holding a real domain still calls the judge")
    finally:
        OH._cdn, OH.AD_EDGE_REGION_CIDRS, OH.PARKING_MARKERS = saved_cdn, saved_regions, saved_parking
    return passed, failed, out


if __name__ == "__main__":
    p, f, lines = check()
    for s, l in lines:
        print(f"  {'ok ' if s == 'ok' else ('-- ' if s == 'skip' else '✗  ')} {l}")
    print(f"\n{p}/{p + f} passed")
    sys.exit(1 if f else 0)
