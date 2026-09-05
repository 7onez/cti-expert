#!/usr/bin/env python3
"""Regression: a SHARED-HOSTING ("landlord") IP never binds a same-operator cluster.

WHAT THIS PROTECTS
------------------
`domain --hosted_on--> ip:<x>` is a strong binder when <x> is a dedicated origin box. It is
co-tenancy when <x> answers for hundreds of unrelated apexes — yet the KB's prevalence cap saw only
the two tenants THIS case collected there and merged a 12-host estate with 84 strangers into one
96-host "operator" (the collector itself had flagged the IP as answering 2,500 apexes). ONE number
(noise_filters.SHARED_HOSTING_MAX_COHOSTS) now drives three places, asserted here:
  1. the ingester records a landlord IP as a FACT on the domain, never a hosted_on edge;
     a small IP still gets the edge;
  2. the cluster partition (query._components) ignores hosted_on edges to IPs the case's own
     collection showed to be landlords / CDN edges, even for edges ingested before the gate;
  3. case_state.shared_hosting_ips(cdir) finds those IPs from the raw files, and the frontier's
     MAX_IP_COHOSTS is the same constant (frontier and KB cannot disagree about a landlord).
"""
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENGINE = os.path.join(ROOT, "intel_engine")
for p in (os.path.join(ENGINE, "tools"), os.path.join(ENGINE, "tools", "kb"),
          os.path.join(ENGINE, "WebPivot", "tools")):
    sys.path.insert(0, p)

import case_state as CS  # noqa: E402
import ingest_webpivot as I  # noqa: E402
import noise_filters as NF  # noqa: E402
import query as Q  # noqa: E402
from knowledge_base import KB  # noqa: E402

LANDLORD, ORIGIN = "203.0.113.9", "203.0.113.10"


def _raw(host, ips, fofa_total_for_landlord=2500):
    """A domain pivot resolving to `ips`; the FOFA IP-reverse for LANDLORD is truncated at 2 rows of 2500."""
    lr = {"dns": {"ips": ips, "ip_classification": [{"ip": ip, "cdn": False} for ip in ips]},
          "fofa_ip_reverse": {"query": f'ip="{LANDLORD}"', "total": fofa_total_for_landlord,
                              "results": [{"host": "tenant-a.example", "ip": LANDLORD},
                                          {"host": "tenant-b.example", "ip": LANDLORD}]}}
    return {"meta": {"host": host, "kind": "domain", "fetched_at": "2026-01-01T00:00:00+00:00"},
            "pivots": [{"kind": "domain", "value": host, "live_results": lr}], "artifacts": {}}


def check():
    passed = failed = 0
    lines = []

    def ok(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1
            lines.append(("ok", label))
        else:
            failed += 1
            lines.append(("FAIL", label))

    ok(CS.MAX_IP_COHOSTS == NF.SHARED_HOSTING_MAX_COHOSTS,
       "frontier MAX_IP_COHOSTS and KB SHARED_HOSTING_MAX_COHOSTS are the same number")
    ok(NF.is_shared_hosting_ip(NF.SHARED_HOSTING_MAX_COHOSTS + 1) and not NF.is_shared_hosting_ip(NF.SHARED_HOSTING_MAX_COHOSTS),
       "is_shared_hosting_ip trips strictly above the bound")

    with tempfile.TemporaryDirectory() as tmp:
        kbdir = os.path.join(tmp, "knowledge")
        cdir = os.path.join(tmp, "CASE-0001")
        os.makedirs(os.path.join(cdir, "raw"))
        paths = []
        for host in ("seed.example", "other.example"):
            p = os.path.join(cdir, "raw", host + ".json")
            json.dump(_raw(host, [LANDLORD, ORIGIN]), open(p, "w"))
            paths.append(p)

        # 1. ingest: landlord -> fact, origin -> edge
        kb = KB(kbdir)
        for p in paths:
            I.ingest_file(kb, p)
        edges = [e for e in kb.edges() if e["rel"] == "hosted_on"]
        dsts = {e["dst"] for e in edges}
        ok(f"ip:{ORIGIN}" in dsts, "a small origin IP still gets a hosted_on edge")
        ok(f"ip:{LANDLORD}" not in dsts, "a landlord IP (2500 co-tenants) gets NO hosted_on edge")
        facts = kb.entity("domain", "seed.example")["facts"]
        ok(any(f["attribute"] == "shared_hosting_ip" and LANDLORD in str(f["value"]) for f in facts),
           "…and is recorded as a shared_hosting_ip FACT with its co-tenant count")

        # 2. partition: a legacy hosted_on edge to the landlord (ingested before the gate) must not bind
        kb.add_edge("domain", "seed.example", "hosted_on", "indicator", f"ip:{LANDLORD}",
                    "legacy", "test", "2026-01-01T00:00:00+00:00", "medium")
        kb.add_edge("domain", "other.example", "hosted_on", "indicator", f"ip:{LANDLORD}",
                    "legacy", "test", "2026-01-01T00:00:00+00:00", "medium")
        # remove the ORIGIN edges so the landlord is the ONLY thing the two share
        kb._edges = [e for e in kb._edges if e["dst"] != f"ip:{ORIGIN}"]
        restrict = {"seed.example", "other.example"}
        comps_blind = Q._components(kb, kbdir, 8, restrict)
        comps_aware = Q._components(kb, kbdir, 8, restrict, noise_ips={LANDLORD})
        ok(any(len(c) == 2 for c in comps_blind), "without the landlord set the legacy edge merges the two domains")
        ok(all(len(c) == 1 for c in comps_aware) and len(comps_aware) == 2,
           "with noise_ips the landlord edge is ignored: two singletons")

        # 3. the case's own raw files expose the landlord
        found = CS.shared_hosting_ips(cdir)
        ok(LANDLORD in found and ORIGIN not in found,
           f"shared_hosting_ips(cdir) finds the landlord and not the origin ({sorted(found)})")
    return passed, failed, lines


if __name__ == "__main__":
    _passed, _failed, _lines = check()
    for _status, _label in _lines:
        print(f"{_status:>4}  {_label}")
    print(f"\n{_passed} passed, {_failed} failed")
    raise SystemExit(bool(_failed))
