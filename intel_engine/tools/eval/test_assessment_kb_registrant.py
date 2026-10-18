#!/usr/bin/env python3
"""Regression: render_cluster_report's same-operator BLUF must agree with the KB `registered_by`
binding clusters.json partitions on (tools/kb/query.py._components / tools/intel.py._write_clusters),
not just the pivots embedded in THIS run's raw JSON.

Pre-fix: a `registered_by` email/phone edge already in the KB (current-era WHOIS-history, or a
sibling's reverse-WHOIS hit) that never showed up as this run's own pivot for >=2 hosts was
invisible to the renderer — the BLUF said "surfaced no shared identity artifact ... common control
is not established" even when clusters.json bound the SAME hosts by that exact registrant email.
Post-fix the renderer folds KB `registered_by` edges (scoped to the case's own hosts, filtered by
the SAME noise/bulk-cap checks the renderer already applies to its own pivots) into its
shared-artifact map, so the two can never disagree.

Also defends:
  * a registrar/privacy role-mailbox `registered_by` edge (a managed-provider WHOIS, e.g.
    abuse@registrar.example) must still never bind a cluster — same noise filter as before.
  * a case with no KB (kb_dir=None) reproduces the pre-fix "no shared identity artifact" BLUF
    exactly — the KB fold is a pure enhancement, never load-bearing.
"""
import os
import sys
import tempfile
import shutil

HERE = os.path.dirname(os.path.abspath(__file__))
ENGINE_ROOT = os.path.dirname(os.path.dirname(HERE))
for _p in ("WebPivot/tools", "tools/kb"):
    _abs = os.path.join(ENGINE_ROOT, _p)
    if _abs not in sys.path:
        sys.path.insert(0, _abs)

import evidence_report as ER  # noqa: E402
from knowledge_base import KB  # noqa: E402


def _host_result(host):
    """A raw pivot_extract-shaped result with NO registrant pivots of its own."""
    return {"meta": {"host": host}, "pivots": []}


def _seed_kb(kb_dir, edges):
    """edges: iterable of (host, dst_type, value) -> one `registered_by` edge each."""
    kb = KB(kb_dir)
    for host, dst_type, value in edges:
        kb.add_edge("domain", host, "registered_by", dst_type, value,
                    "whoisxml", "test", "2026-01-01", "high")
    return kb


def _bluf(report_md):
    return report_md.split("## Bottom Line Up Front", 1)[1].split("\n## ", 1)[0]


def check():
    out, passed, failed = [], 0, 0

    def ok(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1
            out.append(("ok", label))
        else:
            failed += 1
            out.append(("FAIL", label))

    # Network/filesystem seam: render_domain_table would resolve `case` to a real
    # cases/<case>/whois cache and, on a miss, fetch WHOIS live. Stub it out for every case in
    # this test — the KB-registrant fold under test lives entirely in render_cluster_report's own
    # shared-artifact map, not in the Domain Summary table.
    _orig_table = ER.render_domain_table
    ER.render_domain_table = None
    tmp_good = tempfile.mkdtemp(prefix="kb-registrant-good-")
    tmp_noise = tempfile.mkdtemp(prefix="kb-registrant-noise-")
    try:
        # --- 1. a KB registrant email binds 3 hosts with NO registrant pivots of their own ------
        hosts = ["a.example", "b.example", "c.example"]
        _seed_kb(tmp_good, [(h, "email", "owner@example.com") for h in hosts])
        results = [_host_result(h) for h in hosts]
        rep = ER.render_cluster_report(results, case="CASE-0001", kb_dir=tmp_good)
        bluf = _bluf(rep)
        ok("no shared identity artifact" not in bluf,
           "a KB registrant binding must not fall back to the no-shared-artifact BLUF")
        ok("common operator control" in bluf,
           "BLUF asserts common operator control from the KB registrant binding")
        ok("owner@example.com" in bluf, "BLUF names the KB-bound registrant email")
        ok(all(h in rep for h in hosts),
           "all 3 KB-bound hosts appear in the report (sub-cluster / per-host sections)")

        # --- 2. a registrar/privacy role mailbox must NOT create a cluster ----------------------
        noise_hosts = ["x.example", "y.example", "z.example"]
        _seed_kb(tmp_noise, [(h, "email", "abuse@registrar.example") for h in noise_hosts])
        rep2 = ER.render_cluster_report([_host_result(h) for h in noise_hosts],
                                        case="CASE-0002", kb_dir=tmp_noise)
        bluf2 = _bluf(rep2)
        ok("no shared identity artifact" in bluf2,
           "a registrar/privacy role-mailbox registered_by edge must not bind a cluster "
           "(managed-provider case)")
        ok("abuse@registrar.example" not in bluf2,
           "the noise mailbox itself must never surface as the cluster-forming identity")

        # --- 3. no KB -> pre-fix behaviour, unchanged --------------------------------------------
        rep3 = ER.render_cluster_report(results, case="CASE-0001", kb_dir=None)
        bluf3 = _bluf(rep3)
        ok("no shared identity artifact" in bluf3,
           "with no kb_dir the renderer must reproduce the old (pivot-only) BLUF")
        ok("owner@example.com" not in bluf3,
           "with no kb_dir the KB-only registrant must not leak into the BLUF")
    finally:
        ER.render_domain_table = _orig_table
        shutil.rmtree(tmp_good, ignore_errors=True)
        shutil.rmtree(tmp_noise, ignore_errors=True)

    return passed, failed, out


if __name__ == "__main__":
    passed, failed, lines = check()
    for status, label in lines:
        print(f"[{status}] {label}")
    print(f"\n{passed} passed, {failed} failed")
    raise SystemExit(bool(failed))
