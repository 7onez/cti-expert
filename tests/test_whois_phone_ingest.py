#!/usr/bin/env python3
"""Regression: WHOIS registrant PHONE must become a queryable KB entity (registered_by edge).

Before this fix, ingest_webpivot wrote registered_by edges for the registrant EMAIL and NAME but
never the PHONE, so a phone that WAS collected (and sits in the raw WHOIS record) returned
"no record" from kb_entity — the harness adversarial review then wrongly downgraded it from
"collected this pass" to "prior-case prose only". A phone is a strong correlatable selector; it
must be an edge, not a lost field.

Contract defended here:
  1. a real registrant phone -> a registered_by/phone edge, digits-only normalised
  2. a too-short/garbage phone -> NO edge (never pollute the graph)
  3. registrant_country is recorded as a per-domain fact (fabricated country is a signal)

Zero deps (no pytest needed):  python3 tests/test_whois_phone_ingest.py
No case data — only synthetic placeholders (CLAUDE.md RULE 5).
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "intel_engine", "tools", "kb"))

from knowledge_base import KB          # noqa: E402
from ingest_webpivot import ingest_file  # noqa: E402

FAILURES = []


def check(label, got, want):
    if got != want:
        FAILURES.append(f"{label}: got {got!r}, want {want!r}")


def _edges(root):
    """Every edge dict written under a KB root (append-only jsonl anywhere in the tree)."""
    out = []
    for dp, _dn, fns in os.walk(root):
        for fn in fns:
            if not fn.endswith(".jsonl"):
                continue
            with open(os.path.join(dp, fn), encoding="utf-8") as fh:
                for ln in fh:
                    ln = ln.strip()
                    if not ln:
                        continue
                    try:
                        o = json.loads(ln)
                    except ValueError:
                        continue
                    if o.get("rel"):
                        out.append(o)
    return out


def _facts_for(root, host):
    p = os.path.join(root, "entities", "domain", f"{host}.json")
    return json.load(open(p, encoding="utf-8")) if os.path.exists(p) else {}


def _ingest(root, host, whois):
    doc = {"meta": {"host": host}, "artifacts": {"whois": whois}}
    p = os.path.join(root, f"_{host}.json")
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(doc, fh)
    ingest_file(KB(root), p)


def main():
    # (1) + (2) + (3): a real phone edges (normalised), a short one does not, country is a fact.
    with tempfile.TemporaryDirectory() as root:
        _ingest(root, "phone-real-test.com", {
            "registrant_phone": "+1 555 010 0042",
            "registrant_email": "operator.person@example.com",
            "registrant_name": "Operator Person",
            "registrant_country": "NARNIA",
        })
        edges = _edges(root)
        phone_edges = [e for e in edges
                       if e.get("rel") == "registered_by" and e.get("dst_type") == "phone"]
        check("real phone -> exactly one registered_by/phone edge", len(phone_edges), 1)
        if phone_edges:
            check("phone dst is digits-only normalised",
                  phone_edges[0]["dst"], "15550100042")
            check("phone edge src is the domain",
                  phone_edges[0]["src"], "phone-real-test.com")
        # the country the operator fabricated is kept as a per-domain fact (queryable), not dropped
        blob = json.dumps(_facts_for(root, "phone-real-test.com"))
        check("registrant_country recorded as a fact",
              "whois_registrant_country" in blob and "NARNIA" in blob, True)

    with tempfile.TemporaryDirectory() as root:
        _ingest(root, "phone-short-test.com", {
            "registrant_phone": "12345",             # < 7 digits: garbage, must not edge
            "registrant_email": "someone@example.com",
            "registrant_name": "Someone Else",
        })
        short_edges = [e for e in _edges(root)
                       if e.get("rel") == "registered_by" and e.get("dst_type") == "phone"]
        check("too-short phone -> no phone edge", len(short_edges), 0)

    if FAILURES:
        print("FAIL:")
        for f in FAILURES:
            print("  -", f)
        sys.exit(1)
    print("ok - whois phone ingest")


if __name__ == "__main__":
    main()
