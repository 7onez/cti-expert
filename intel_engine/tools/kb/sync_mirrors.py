#!/usr/bin/env python3
"""
sync_mirrors.py — keep the DUPLICATED reference groups identical across skills.

WHY THIS EXISTS
---------------
Each skill (WebPivot, BinaryPivot, IntelGraph, IntelReport) is imported onto other machines
STANDALONE, so it cannot read a repo-root package or another skill's `references/` directory. A
denylist that both the collector and the ingest need therefore has to be physically duplicated —
the same reason the five `*_refs.py` loaders are byte-identical copies rather than one module.

Duplication is safe only while something enforces equality, because the failure mode is SILENT.
When the platform-default favicon lists drifted, WebPivot filtered the Wix default and the KB
filtered the GoHighLevel default, so each happily let the other's through: the collector emitted
a pivot the ingest would have dropped, and the ingest built a thousand-edge cluster the collector
would have dropped. Nothing errored. Nobody saw it until the cluster was the biggest in the KB.

`tests/reference_mirrors.json` declares which groups are mirrors. This tool reports drift and,
with --write, repairs it from the CANONICAL copy named in the manifest.

Usage:
  python3 tools/kb/sync_mirrors.py                 # report drift, exit 1 if any (CI-friendly)
  python3 tools/kb/sync_mirrors.py --write         # propagate canonical -> mirrors
  python3 tools/kb/sync_mirrors.py --union         # merge both sides, then propagate

--union is the SAFE direction when two copies each hold values the other lacks, which is what an
independent edit on each side produces. Prefer it when you are unsure: over-filtering costs a
lead, under-filtering manufactures a false cluster, and a value already present on one side was
put there by an analyst who had a reason.
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
MANIFEST = os.path.join(ROOT, "tests", "reference_mirrors.json")


def _load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _save(path, doc):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


def _payload_key(node):
    """Reference groups carry either a `values` list or named scalars (thresholds)."""
    if "values" in node:
        return "values"
    if "entries" in node:
        return "entries"
    return None


def _compare(a, b):
    """True when two group payloads are equivalent, order-insensitively for lists."""
    if isinstance(a, list) and isinstance(b, list):
        return sorted(map(str, a)) == sorted(map(str, b))
    return a == b


def _scalars(node):
    return {k: v for k, v in node.items() if not k.startswith("_")}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--write", action="store_true", help="repair drift from the canonical copy")
    ap.add_argument("--union", action="store_true",
                    help="merge values from every copy first, then propagate (safe direction)")
    args = ap.parse_args()

    manifest = _load(MANIFEST)
    drifted, repaired, checked = [], [], 0

    for entry in manifest["mirrors"]:
        concept = entry["concept"]
        can = entry["canonical"]
        can_path = os.path.join(ROOT, can["file"])
        can_doc = _load(can_path)
        if can["group"] not in can_doc:
            print(f"  [ERROR] {concept}: canonical group {can['group']!r} missing from "
                  f"{can['file']}", file=sys.stderr)
            drifted.append(concept)
            continue
        can_node = can_doc[can["group"]]
        key = _payload_key(can_node)

        targets = []
        for m in entry["mirrors"]:
            m_path = os.path.join(ROOT, m["file"])
            m_doc = _load(m_path)
            if m["group"] not in m_doc:
                print(f"  [ERROR] {concept}: mirror group {m['group']!r} missing from "
                      f"{m['file']}", file=sys.stderr)
                drifted.append(concept)
                continue
            targets.append((m, m_path, m_doc, m_doc[m["group"]]))

        # optionally merge every copy into the canonical first
        if args.union and key == "values":
            merged = list(can_node["values"])
            seen = {str(v) for v in merged}
            for _m, _p, _d, node in targets:
                for v in node.get("values", []):
                    if str(v) not in seen:
                        seen.add(str(v))
                        merged.append(v)
            if not _compare(merged, can_node["values"]):
                can_node["values"] = merged
                if args.write:
                    _save(can_path, can_doc)
                print(f"  [union] {concept}: canonical now holds {len(merged)} values")

        for m, m_path, m_doc, node in targets:
            checked += 1
            if key == "values":
                same = _compare(can_node.get("values"), node.get("values"))
                new_payload = list(can_node["values"])
            elif key == "entries":
                same = can_node.get("entries") == node.get("entries")
                new_payload = dict(can_node["entries"])
            else:   # named scalars (thresholds)
                same = _scalars(can_node) == _scalars(node)
                new_payload = _scalars(can_node)

            label = f"{m['file']}:{m['group']}"
            if same:
                print(f"  ok      {concept}\n            = {label}")
                continue
            drifted.append(concept)
            print(f"  DRIFT   {concept}\n            canonical {can['file']}:{can['group']}"
                  f"\n            mirror    {label}")
            if key == "values":
                a = {str(v) for v in can_node.get("values", [])}
                b = {str(v) for v in node.get("values", [])}
                if a - b:
                    print(f"              only canonical: {sorted(a - b)[:8]}")
                if b - a:
                    print(f"              only mirror   : {sorted(b - a)[:8]}")
            if args.write:
                if key in ("values", "entries"):
                    node[key] = new_payload
                else:
                    for k, v in new_payload.items():
                        node[k] = v
                _save(m_path, m_doc)
                repaired.append(label)

    print()
    if args.write and repaired:
        print(f"repaired {len(repaired)} mirror(s): {', '.join(repaired)}")
        print("re-run without --write to confirm, then run tests/test_references.py")
        return 0
    if drifted:
        print(f"DRIFT in {len(set(drifted))} mirrored concept(s) across {checked} checked pair(s).")
        print("Repair with:  python3 tools/kb/sync_mirrors.py --union --write")
        return 1
    print(f"all {checked} mirrored pair(s) identical.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
