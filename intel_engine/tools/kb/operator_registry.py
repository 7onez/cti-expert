#!/usr/bin/env python3
"""
operator_registry.py — the confirmed-operator ledger the pipeline learns from.

An investigation ends with a *conclusion* (this cluster = operator X). That conclusion is
the single most valuable thing to carry into the NEXT case — yet nothing persisted it in a
form the tooling could reuse. This registry does: one attributed operator per line, git-ignored
(it names real actors → OPSEC-sensitive, lives under knowledge/), read by `intel.py open` so a
new case automatically inherits "these seeds belong to a known operator" (the LEARN loop closed).

  knowledge/operators.jsonl     one JSON object per line:
    {"operator": "...", "domains": [...], "case": "...", "confidence": "assessed|likely|possible",
     "basis": "what tied them", "added": "YYYY-MM-DD"}

Usage:
  # append a confirmed attribution at case close (the LEARN step)
  python3 tools/kb/operator_registry.py add "Operator Name" \
      --domains site-a.com,site-b.asia --case example-cluster \
      --confidence assessed --basis "reused GSC/GA4 tokens across all domains"

  python3 tools/kb/operator_registry.py list           # audit the ledger
  python3 tools/kb/operator_registry.py find <domain>  # who is this domain attributed to?
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
REGISTRY = os.path.join(ROOT, "knowledge", "operators.jsonl")


def _load():
    out = []
    if os.path.isfile(REGISTRY):
        for line in open(REGISTRY, encoding="utf-8"):
            line = line.strip()
            if line and not line.startswith("#"):
                try:
                    out.append(json.loads(line))
                except Exception:
                    pass
    return out


def _norm(d):
    return d.strip().lower().rstrip(".")


def cmd_add(a):
    domains = sorted({_norm(d) for d in a.domains.split(",") if d.strip()})
    if not domains:
        sys.exit("no --domains given")
    recs = _load()
    # merge into an existing operator record instead of duplicating
    for r in recs:
        if r.get("operator", "").lower() == a.operator.lower():
            r["domains"] = sorted(set(r.get("domains", [])) | set(domains))
            if a.case:
                r["case"] = a.case
            if a.confidence:
                r["confidence"] = a.confidence
            if a.basis:
                r["basis"] = a.basis
            r["added"] = a.date or r.get("added")
            break
    else:
        recs.append({"operator": a.operator, "domains": domains, "case": a.case,
                     "confidence": a.confidence, "basis": a.basis, "added": a.date})
    os.makedirs(os.path.dirname(REGISTRY), exist_ok=True)
    tmp = REGISTRY + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        for r in recs:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    os.replace(tmp, REGISTRY)   # atomic: never truncate the confirmed-operator ledger
    print(f"registry: {a.operator} now holds {len(domains)} domain(s) "
          f"({len(recs)} operator(s) tracked) -> {os.path.relpath(REGISTRY, ROOT)}")


def cmd_list(a):
    recs = _load()
    if not recs:
        print("registry empty — no confirmed operators recorded yet.")
        return
    for r in sorted(recs, key=lambda x: -len(x.get("domains", []))):
        print(f"• {r.get('operator')}  [{r.get('confidence','?')}]  "
              f"{len(r.get('domains', []))} domain(s)  (case {r.get('case','?')})")
        if a.verbose:
            print(f"    basis: {r.get('basis','')}")
            print(f"    {', '.join(r.get('domains', []))}")


def cmd_find(a):
    needle = _norm(a.domain)
    hits = [r for r in _load() if needle in r.get("domains", [])]
    if not hits:
        print(f"{needle}: not attributed to any known operator.")
        return
    for r in hits:
        print(f"{needle} -> {r.get('operator')}  [{r.get('confidence','?')}]  "
              f"(case {r.get('case','?')}; {r.get('basis','')})")


def main():
    ap = argparse.ArgumentParser(description="Confirmed-operator registry (the LEARN ledger).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("add", help="record/merge a confirmed operator attribution")
    p.add_argument("operator")
    p.add_argument("--domains", required=True, help="comma-separated domains attributed to them")
    p.add_argument("--case", default=None)
    p.add_argument("--confidence", default="assessed",
                   choices=["assessed", "likely", "possible"])
    p.add_argument("--basis", default=None, help="the artifacts that tied them (cited)")
    p.add_argument("--date", default=None, help="YYYY-MM-DD (defaults to unset; pass to stamp)")
    p.set_defaults(func=cmd_add)

    p = sub.add_parser("list", help="audit the ledger")
    p.add_argument("-v", "--verbose", action="store_true")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("find", help="who is a domain attributed to?")
    p.add_argument("domain")
    p.set_defaults(func=cmd_find)

    a = ap.parse_args()
    a.func(a)


if __name__ == "__main__":
    main()
