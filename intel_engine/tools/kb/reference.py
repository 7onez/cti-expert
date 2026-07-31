#!/usr/bin/env python3
"""reference.py — a curated fingerprint reference that grows as you investigate.

WHY THIS EXISTS
---------------
Hash/keyword matches (favicon mmh3, CSS/DOM hashes, urlscan resource hashes, distinctive
strings) are the backbone of clustering — but a match is only as good as the artifact's
UNIQUENESS. A favicon shared because both sites ship the same jQuery/Bootstrap/Font-Awesome
bundle, or a popular logo, or a CDN package, is a FALSE POSITIVE: it links benign, unrelated
sites. `noise_filters.py` hardcodes the well-known offenders and `query.py --max-prevalence`
catches things common *within our KB* — but neither remembers "favicon:X is the generic
WordPress default" or "css_hash:Y is TailwindCSS", learned once and reused forever.

This is that memory. Two verdicts:

  benign  — a globally common artifact (logo / CDN / CSS framework / template default).
            SUPPRESSED from clustering everywhere it's consulted, regardless of local prevalence.
  signal  — a distinctive hash/keyword harvested from a confirmed case that we WANT to keep
            searching for (a watchlist / IOC). A new collection hitting one is a high-value lead
            tied back to its origin case(s).

Store: <kb>/reference.jsonl  (one JSON object per line, upserted on (type, value)). Lives in the
git-ignored KB, so case-derived `signal` entries never leave the box.

  python3 tools/kb/reference.py --kb knowledge add --value favicon:0 --verdict benign --label "empty favicon"
  python3 tools/kb/reference.py --kb knowledge add --value favicon:123456789 --verdict signal --label "Brand X" --case CASE-0001
  python3 tools/kb/reference.py --kb knowledge check favicon:123456789
  python3 tools/kb/reference.py --kb knowledge search "Brand X"
  python3 tools/kb/reference.py --kb knowledge ingest-case CASE-0001     # harvest a case's unique artifacts as signals
"""
from __future__ import annotations

import argparse
import datetime
import glob
import json
import os
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))  # tools/kb -> repo root


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _path(kb: str) -> str:
    return os.path.join(kb if os.path.isabs(kb) else os.path.join(REPO, kb), "reference.jsonl")


def _infer_type(value: str) -> str:
    """Type = the indicator prefix ('favicon:123' -> 'favicon'); a bare string -> 'keyword'."""
    return value.split(":", 1)[0] if ":" in value else "keyword"


def load(kb: str) -> list[dict]:
    p = _path(kb)
    if not os.path.exists(p):
        return []
    out = []
    for line in open(p, encoding="utf-8"):
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except Exception:  # noqa: BLE001
                pass
    return out


def _save(kb: str, entries: list[dict]) -> None:
    p = _path(kb)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    os.replace(tmp, p)   # atomic: an interrupted write can't truncate the live signal ledger


def benign_values(kb: str) -> set[str]:
    """The set of `value` strings marked benign — the suppression denylist for clustering."""
    return {e["value"] for e in load(kb) if e.get("verdict") == "benign"}


def upsert(kb: str, value: str, verdict: str, *, type_: str = "", label: str = "",
           note: str = "", case: str = "", tags: list[str] | None = None) -> dict:
    """Add or merge one entry, keyed on (type, value). Re-adding merges cases/tags and refreshes
    label/note/verdict. Returns the stored entry."""
    value = value.strip()
    type_ = type_ or _infer_type(value)
    entries = load(kb)
    for e in entries:
        if e.get("type") == type_ and e.get("value") == value:
            e["verdict"] = verdict
            if label:
                e["label"] = label
            if note:
                e["note"] = note
            if case and case not in e.setdefault("cases", []):
                e["cases"].append(case)
            for t in (tags or []):
                if t not in e.setdefault("tags", []):
                    e["tags"].append(t)
            e["updated"] = _now()
            _save(kb, entries)
            return e
    entry = {"type": type_, "value": value, "verdict": verdict, "label": label, "note": note,
             "cases": [case] if case else [], "tags": tags or [], "added": _now(), "updated": _now()}
    entries.append(entry)
    _save(kb, entries)
    return entry


def check(kb: str, value: str, type_: str = "") -> dict:
    value = value.strip()
    type_ = type_ or _infer_type(value)
    for e in load(kb):
        if e.get("value") == value and (not type_ or e.get("type") == type_):
            return {"known": True, **e}
    return {"known": False, "value": value, "type": type_, "verdict": "unknown"}


def search(kb: str, q: str) -> list[dict]:
    q = q.lower().strip()
    return [e for e in load(kb)
            if q in e.get("value", "").lower() or q in e.get("label", "").lower()
            or q in e.get("note", "").lower() or any(q in t.lower() for t in e.get("tags", []))]


def ingest_case(kb: str, case: str, verdict: str = "signal", max_prevalence: int = 8) -> dict:
    """Harvest a case's high-signal artifacts (favicon/tracker/wallet/saas/verification/social/
    email — NOT boilerplate) into the reference as a searchable watchlist. Skips anything already
    noise-filtered AND (guided-pivot) any indicator carried by > max_prevalence domains in the KB —
    those are generic (kit favicons, shared trackers), not a distinctive signal. Returns
    {'added': [...], 'skipped_common': [...]}."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from convergence import _indicators_from_raw  # same extractor the KB/convergence use
    try:
        from noise_filters import is_noise_indicator
    except Exception:  # noqa: BLE001
        def is_noise_indicator(_):  # noqa: ANN001
            return False
    # KB prevalence: how many domains carry each indicator (generic == common == not a signal).
    prevalence: dict = {}
    try:
        from knowledge_base import KB
        for e in KB(kb).edges():
            if e["src_type"] == "domain":
                prevalence.setdefault(e["dst"], set()).add(e["src"])
    except Exception:  # noqa: BLE001
        pass
    cdir = case if os.path.isdir(case) else os.path.join(REPO, "cases", case)
    label = os.path.basename(cdir.rstrip("/"))
    inds: set[str] = set()
    for path in glob.glob(os.path.join(cdir, "raw", "*.json")):
        try:
            inds |= _indicators_from_raw(json.load(open(path, encoding="utf-8")))
        except Exception:  # noqa: BLE001
            pass
    added, skipped = [], []
    for v in sorted(inds):
        if is_noise_indicator(v):
            continue
        if len(prevalence.get(v, ())) > max_prevalence:
            skipped.append(v)                # too common in the KB to be a distinctive signal
            continue
        added.append(upsert(kb, v, verdict, case=label, label=f"harvested from {label}"))
    return {"added": added, "skipped_common": skipped}


# --------------------------------------------------------------------------- CLI
def _human_entry(e: dict) -> str:
    icon = {"benign": "🟢 BENIGN (suppress — false-positive risk)",
            "signal": "🔴 SIGNAL (pivot on it)"}.get(e.get("verdict"), e.get("verdict", "?"))
    cases = f"  cases: {', '.join(e['cases'])}" if e.get("cases") else ""
    lab = f"  — {e['label']}" if e.get("label") else ""
    return f"  [{e.get('type')}] {e.get('value')}  {icon}{lab}{cases}"


def _main() -> None:
    ap = argparse.ArgumentParser(description="curated fingerprint reference (benign/signal)")
    ap.add_argument("--kb", default=os.environ.get("HARNESS_KB", "knowledge"))
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("add", help="add/merge a benign or signal fingerprint")
    a.add_argument("--value", required=True, help="indicator string (favicon:123, css_hash:..) or keyword")
    a.add_argument("--verdict", required=True, choices=["benign", "signal"])
    a.add_argument("--type", default="")
    a.add_argument("--label", default="")
    a.add_argument("--note", default="")
    a.add_argument("--case", default="")
    a.add_argument("--tag", action="append", default=[])

    c = sub.add_parser("check", help="is this value benign / signal / unknown?")
    c.add_argument("value")
    c.add_argument("--type", default="")

    s = sub.add_parser("search", help="substring search over value/label/note/tags")
    s.add_argument("query")

    ic = sub.add_parser("ingest-case", help="harvest a case's unique artifacts as signals")
    ic.add_argument("case")
    ic.add_argument("--verdict", default="signal", choices=["benign", "signal"])
    ic.add_argument("--max-prevalence", type=int, default=8,
                    help="skip indicators carried by more than this many KB domains (too common "
                         "to be a distinctive signal; default 8)")

    ls = sub.add_parser("list", help="dump the reference")
    ls.add_argument("--verdict", default="", choices=["", "benign", "signal"])

    args = ap.parse_args()
    if args.cmd == "add":
        e = upsert(args.kb, args.value, args.verdict, type_=args.type, label=args.label,
                   note=args.note, case=args.case, tags=args.tag)
        print("stored:\n" + _human_entry(e))
    elif args.cmd == "check":
        r = check(args.kb, args.value, args.type)
        if not r["known"]:
            print(f"{r['value']} ({r['type']}): UNKNOWN — not in reference (treat on its own merits).")
        else:
            print(_human_entry(r) + (f"\n  note: {r['note']}" if r.get("note") else ""))
    elif args.cmd == "search":
        hits = search(args.kb, args.query)
        print(f"{len(hits)} match(es) for '{args.query}':")
        for e in hits:
            print(_human_entry(e))
    elif args.cmd == "ingest-case":
        res = ingest_case(args.kb, args.case, args.verdict, args.max_prevalence)
        added, skipped = res["added"], res["skipped_common"]
        print(f"ingested {len(added)} {args.verdict} fingerprint(s) from {args.case} "
              f"({len(skipped)} skipped as too common in the KB).")
        for e in added[:20]:
            print(_human_entry(e))
        if skipped:
            print(f"  skipped (prevalence > {args.max_prevalence}): {', '.join(skipped[:10])}"
                  f"{' …' if len(skipped) > 10 else ''}")
    elif args.cmd == "list":
        for e in load(args.kb):
            if not args.verdict or e.get("verdict") == args.verdict:
                print(_human_entry(e))


if __name__ == "__main__":
    _main()
