#!/usr/bin/env python3
"""
calibration.py — close the loop on the AI JUDGEMENT layer.

WHY THIS EXISTS
---------------
IntelAnalysis (and the analyst) attach a confidence — "HIGH confidence these two
domains are one operator." But nothing ever checked whether the HIGH calls were later
confirmed and the LOW calls were the ones that fell through. Without that feedback the
confidence labels are decoration, not calibration. This tool records each judgement when
it's made and its outcome when it's known, then scores how well-calibrated the confidence
labels actually are (Brier score + a reliability table). That is the "Reflector" step:
the judgement layer stays an *aid*, but a measured one — you learn whether to trust your
own HIGHs.

STORE
-----
`knowledge/calibration.jsonl` — one JSON record per line:
  {id, ts, case, claim, confidence, prob, outcome, resolved_ts}
`outcome` is null until resolved, then "confirmed" or "refuted".

USAGE
-----
  # when you make an attribution/cluster call, log it:
  python3 tools/kb/calibration.py record --case example-cluster \
      --claim "site-a.com, site-b.com = one operator (reused GA4)" --confidence high

  # later, when reality settles it:
  python3 tools/kb/calibration.py resolve --id 3f2a --outcome confirmed

  python3 tools/kb/calibration.py score      # calibration report
  python3 tools/kb/calibration.py list        # recent + still-open predictions
"""
import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

# confidence label -> the probability it asserts (ICD-203 flavored). Override per-record
# with --prob if you use a finer scale.
CONF_PROB = {"high": 0.85, "medium": 0.60, "low": 0.35,
             "almost_certain": 0.93, "likely": 0.75, "probable": 0.75,
             "even": 0.50, "unlikely": 0.25, "remote": 0.08}


def _store(kb_root):
    return os.path.join(kb_root, "calibration.jsonl")


def _load(path):
    if not os.path.exists(path):
        return []
    out = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def _save(path, records):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        for r in records:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    os.replace(tmp, path)   # atomic: an interrupted write can't truncate the calibration ledger


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _gen_id(claim, ts):
    return hashlib.sha1(f"{claim}|{ts}".encode()).hexdigest()[:6]


def cmd_record(args):
    path = _store(args.kb)
    records = _load(path)
    ts = _now()
    conf = args.confidence.lower()
    prob = args.prob if args.prob is not None else CONF_PROB.get(conf)
    if prob is None:
        print(f"unknown confidence '{conf}'; pass --prob, or use one of {sorted(CONF_PROB)}",
              file=sys.stderr)
        return 2
    rid = _gen_id(args.claim, ts)
    records.append({"id": rid, "ts": ts, "case": args.case, "claim": args.claim,
                    "confidence": conf, "prob": prob, "outcome": None, "resolved_ts": None})
    _save(path, records)
    print(f"recorded prediction {rid}  [{conf} p={prob}]  {args.claim}")
    return 0


def cmd_resolve(args):
    path = _store(args.kb)
    records = _load(path)
    hit = next((r for r in records if r["id"] == args.id), None)
    if not hit:
        print(f"no prediction with id {args.id}", file=sys.stderr)
        return 2
    if args.outcome not in ("confirmed", "refuted"):
        print("outcome must be 'confirmed' or 'refuted'", file=sys.stderr)
        return 2
    hit["outcome"] = args.outcome
    hit["resolved_ts"] = _now()
    _save(path, records)
    print(f"resolved {args.id} -> {args.outcome}  ({hit['confidence']} p={hit['prob']}): {hit['claim']}")
    return 0


def cmd_score(args):
    records = _load(_store(args.kb))
    resolved = [r for r in records if r.get("outcome") in ("confirmed", "refuted")]
    openp = [r for r in records if r.get("outcome") is None]
    print(f"# Calibration — {len(resolved)} resolved, {len(openp)} open\n")
    if not resolved:
        print("no resolved predictions yet — record calls, resolve them as reality settles.")
        return 0
    # Brier score: mean( (prob - outcome)^2 ), outcome=1 confirmed / 0 refuted. Lower = better.
    brier = sum((r["prob"] - (1.0 if r["outcome"] == "confirmed" else 0.0)) ** 2
                for r in resolved) / len(resolved)
    hits = sum(1 for r in resolved if r["outcome"] == "confirmed")
    print(f"Brier score: {brier:.3f}   (0=perfect, 0.25=coin-flip, lower is better)")
    print(f"base rate confirmed: {hits}/{len(resolved)} = {hits/len(resolved):.0%}\n")
    print("reliability by confidence label (predicted p vs. observed confirmed rate):")
    print(f"  {'label':<14}{'pred':>6}{'observed':>10}{'n':>5}   calibration")
    buckets = {}
    for r in resolved:
        buckets.setdefault(r["confidence"], []).append(r)
    for conf in sorted(buckets, key=lambda c: -CONF_PROB.get(c, 0)):
        rs = buckets[conf]
        obs = sum(1 for r in rs if r["outcome"] == "confirmed") / len(rs)
        pred = sum(r["prob"] for r in rs) / len(rs)
        gap = obs - pred
        verdict = ("well-calibrated" if abs(gap) <= 0.1
                   else "OVERconfident" if gap < 0 else "UNDERconfident")
        print(f"  {conf:<14}{pred:>6.2f}{obs:>10.0%}{len(rs):>5}   {verdict} ({gap:+.2f})")
    return 0


def cmd_list(args):
    records = _load(_store(args.kb))
    if not records:
        print("no predictions recorded yet.")
        return 0
    openp = [r for r in records if r.get("outcome") is None]
    done = [r for r in records if r.get("outcome")]
    if openp:
        print("# OPEN predictions (resolve these as you learn the truth):")
        for r in openp[-25:]:
            print(f"  {r['id']}  [{r['confidence']:<6} p={r['prob']}]  {r.get('case','-')}: {r['claim']}")
    if done:
        print("\n# RESOLVED:")
        for r in done[-25:]:
            mark = "✓" if r["outcome"] == "confirmed" else "✗"
            print(f"  {mark} {r['id']}  [{r['confidence']:<6}]  {r['claim']}  -> {r['outcome']}")
    return 0


def main():
    ap = argparse.ArgumentParser(description="Judgement calibration log for IntelAnalysis")
    ap.add_argument("--kb", default="knowledge", help="knowledge base dir (holds calibration.jsonl)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("record", help="log a confidence-tagged judgement")
    r.add_argument("--case", default="-")
    r.add_argument("--claim", required=True)
    r.add_argument("--confidence", required=True, help="high/medium/low or an ICD-203 term")
    r.add_argument("--prob", type=float, default=None, help="override the mapped probability")
    r.set_defaults(fn=cmd_record)

    rs = sub.add_parser("resolve", help="mark a prediction confirmed/refuted")
    rs.add_argument("--id", required=True)
    rs.add_argument("--outcome", required=True, choices=["confirmed", "refuted"])
    rs.set_defaults(fn=cmd_resolve)

    sc = sub.add_parser("score", help="Brier score + reliability table")
    sc.set_defaults(fn=cmd_score)

    ls = sub.add_parser("list", help="show open + resolved predictions")
    ls.set_defaults(fn=cmd_list)

    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
