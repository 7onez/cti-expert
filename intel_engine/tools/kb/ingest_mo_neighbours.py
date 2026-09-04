#!/usr/bin/env python3
"""ingest_mo_neighbours — cases/<id>/mo_neighbours.json -> knowledge base, FACTS ONLY.

The MO-neighbour pivot names other customers of the same provider (rung 10). `KB.shared_indicators()`
clusters on EDGES alone, so the only way to make this observation recallable (`/cti-recall` shows
"mo_neighbour_of: CASE-…") without ever letting it cluster a persona into the estate is to write
`add_fact` rows and nothing else. This module therefore has NO add_edge call by construction, and a
test asserts it stays that way. The attribute vocabulary is deliberately neutral:

  email:<persona>   co_tenant_observation  {case, origin_ips, domains, signals, rung: 10}
  domain:<apex>     mo_neighbour_of        <CASE-ID>
  domain:<apex>     mo_neighbour_class     same_mo | same_registrant

`same_registrant` rows are ALSO recorded as facts only: their estate membership is established by
the normal collect → ingest_webpivot path once the frontier collects them (a real join-key edge).
Never `operator_lead`, never `registered_by`.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from knowledge_base import KB  # noqa: E402

COLLECTOR = "mo_neighbours"
SOURCE = "case_state"


def ingest(kb, blk, evidence_ref=None):
    """Write the facts for one classification block. Returns the number of facts written."""
    case = str(blk.get("case") or "")
    observed = str(blk.get("generated") or "")
    n = 0
    for p in blk.get("related_personas") or []:
        ident = str(p.get("persona") or "").strip().lower()
        if not ident:
            continue
        etype = "email" if "@" in ident else "indicator"
        kb.touch(etype, ident, observed)
        kb.add_fact(etype, ident, "co_tenant_observation",
                    {"case": case, "origin_ips": p.get("origin_ips") or [], "domains": p.get("domains") or [],
                     "signals": p.get("signals") or [], "rung": 10},
                    SOURCE, COLLECTOR, observed, "low", evidence_ref)
        n += 1
        for d in p.get("domains") or []:
            kb.touch("domain", d, observed)
            kb.add_fact("domain", d, "mo_neighbour_of", case, SOURCE, COLLECTOR, observed, "low", evidence_ref)
            kb.add_fact("domain", d, "mo_neighbour_class", "same_mo", SOURCE, COLLECTOR, observed, "low", evidence_ref)
            n += 2
    for r in blk.get("same_registrant") or []:
        d = str(r.get("apex") or "").lower()
        if not d:
            continue
        kb.touch("domain", d, observed)
        kb.add_fact("domain", d, "mo_neighbour_of", case, SOURCE, COLLECTOR, observed, "medium", evidence_ref)
        kb.add_fact("domain", d, "mo_neighbour_class", "same_registrant", SOURCE, COLLECTOR, observed, "medium", evidence_ref)
        n += 2
    return n


def main():
    ap = argparse.ArgumentParser(description="mo_neighbours.json -> KB facts (never edges)")
    ap.add_argument("--kb", required=True)
    ap.add_argument("block", help="cases/<id>/mo_neighbours.json")
    a = ap.parse_args()
    blk = json.load(open(a.block, encoding="utf-8"))
    n = ingest(KB(a.kb), blk, evidence_ref=os.path.relpath(a.block))
    print(f"ingested {n} MO-neighbour fact(s) from {a.block} (facts only — no edges)")


if __name__ == "__main__":
    main()
