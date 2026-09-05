#!/usr/bin/env python3
"""case_drift.py — what CHANGED in a case between two collections.

Backs /drift. Re-running collection on a live estate produces a new set of facts; the question
that matters is what MOVED. A domain that changed origin IP, gained a nameserver, lost a tracker
or went dark between two runs is telling you the operator acted — and the date of that action is
often the most useful thing in a report.

Compares two snapshots of a case's raw pivot JSON. With no explicit pair it diffs the case's
current raw/ against the most recent stored snapshot under drift/.

Pure: reads local case files, writes a snapshot on request. No network.

Usage:
  case_drift.py CASE-0001 --snapshot        # store the current state
  case_drift.py CASE-0001                   # diff current vs the last snapshot
  case_drift.py CASE-0001 --against drift/2026-08-01.json --pretty
"""
# /// script
# requires-python = ">=3.9"
# ///
import argparse
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.join(os.path.dirname(os.path.dirname(HERE)), "intel_engine")
CASES = os.environ.get("INTEL_CASES") or os.path.join(ENGINE, "cases")

# The fields whose movement is worth reporting. Deliberately narrow: a diff that reports every
# byte of a re-scrape buries the three facts that matter under a thousand that do not.
TRACKED = ["ip", "ips", "nameservers", "ns", "favicon", "trackers", "emails", "phones",
           "telegram", "crypto", "third_party_hosts", "server_headers", "title", "status"]


def _flatten(obj, prefix=""):
    """Depth-limited flatten of the artifact block into comparable scalars."""
    out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, (dict, list)):
                out.update(_flatten(v, key))
            elif v not in (None, "", []):
                out[key] = str(v)
    elif isinstance(obj, list):
        vals = sorted(str(x) for x in obj if isinstance(x, (str, int, float)) and str(x))
        if vals:
            out[prefix] = " | ".join(vals[:20])
        for i, x in enumerate(obj):
            if isinstance(x, dict):
                out.update(_flatten(x, f"{prefix}[{i}]"))
    return out


def snapshot(case_dir):
    """host -> {tracked field: value} for the case's current raw pivot JSON."""
    state = {}
    for raw in sorted(glob.glob(os.path.join(case_dir, "raw", "*.json"))):
        try:
            d = json.load(open(raw, encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        for doc in (d if isinstance(d, list) else [d]):
            if not isinstance(doc, dict):
                continue
            host = ((doc.get("meta") or {}).get("host")
                    or os.path.splitext(os.path.basename(raw))[0]).lower()
            flat = _flatten(doc.get("artifacts") or doc)
            keep = {k: v for k, v in flat.items()
                    if any(t in k.lower() for t in TRACKED)}
            if keep:
                state.setdefault(host, {}).update(keep)
    return state


def diff(old, new):
    hosts = sorted(set(old) | set(new))
    changes = []
    for h in hosts:
        o, n = old.get(h) or {}, new.get(h) or {}
        if h not in old:
            changes.append({"host": h, "change": "APPEARED", "fields": len(n)})
            continue
        if h not in new:
            changes.append({"host": h, "change": "DISAPPEARED",
                            "note": "no longer collected — went dark, or was dropped from scope"})
            continue
        for k in sorted(set(o) | set(n)):
            if o.get(k) != n.get(k):
                changes.append({"host": h, "field": k,
                                "change": "ADDED" if k not in o else
                                          "REMOVED" if k not in n else "CHANGED",
                                "before": o.get(k), "after": n.get(k)})
    return changes


def main():
    ap = argparse.ArgumentParser(description="Diff two collections of a case.")
    ap.add_argument("case")
    ap.add_argument("--snapshot", action="store_true", help="store the current state and exit")
    ap.add_argument("--against", help="explicit snapshot file to diff against")
    ap.add_argument("--pretty", action="store_true")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()

    case_dir = os.path.join(CASES, a.case)
    if not os.path.isdir(case_dir):
        print(json.dumps({"error": f"no case at {case_dir}"})); return 3
    drift_dir = os.path.join(case_dir, "drift")
    cur = snapshot(case_dir)
    if not cur:
        print(json.dumps({"case": a.case, "error": "no raw pivot JSON — nothing to compare",
                          "hint": "collect first: intel.py pivot-extract <target>"})); return 0

    if a.snapshot:
        os.makedirs(drift_dir, exist_ok=True)
        n = len(glob.glob(os.path.join(drift_dir, "*.json"))) + 1
        path = os.path.join(drift_dir, f"snapshot-{n:03d}.json")
        json.dump(cur, open(path, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
        print(f"{a.case}: snapshot stored ({len(cur)} host(s)) -> "
              f"{os.path.relpath(path, ENGINE)}", file=sys.stderr)
        print(json.dumps({"case": a.case, "snapshot": os.path.relpath(path, ENGINE),
                          "hosts": len(cur)}))
        return 0

    prior_path = a.against
    if not prior_path:
        prior = sorted(glob.glob(os.path.join(drift_dir, "*.json")))
        if not prior:
            print(json.dumps({"case": a.case, "hosts": len(cur), "changes": [],
                              "verdict": ("no prior snapshot — nothing to diff against. Run with "
                                          "--snapshot now, re-collect later, then run again."),
                              "note": "this is an absence of baseline, not an absence of change"}))
            return 0
        prior_path = prior[-1]
    old = json.load(open(prior_path, encoding="utf-8"))
    ch = diff(old, cur)

    out = {"case": a.case, "baseline": os.path.relpath(prior_path, ENGINE),
           "hosts_now": len(cur), "hosts_before": len(old), "changes": ch, "n_changes": len(ch),
           "verdict": (f"{len(ch)} change(s) since the baseline" if ch else
                       "no tracked field changed — the estate is static between these two runs"),
           "tracked_fields": TRACKED,
           "caveat": ("Only the fields above are diffed; a change elsewhere is not reported. A "
                      "field going missing can mean the operator removed it OR that the "
                      "collector failed that run — check the collection status before calling "
                      "it an operator action.")}
    print(f"{a.case}: {len(ch)} change(s) vs {os.path.basename(prior_path)}", file=sys.stderr)
    for c in ch[:10]:
        print(f"  {c['host']}: {c.get('field', c.get('change'))} {c.get('change', '')}",
              file=sys.stderr)
    txt = json.dumps(out, indent=2 if a.pretty else None, ensure_ascii=False)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(txt)
    print(txt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
