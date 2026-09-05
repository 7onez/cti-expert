#!/usr/bin/env python3
"""kb_crossref.py — which identifiers appear across MORE THAN ONE case?

Backs /crossref. `kb_query_shared` answers "which indicators bind domains"; this answers the
different question that matters once you have a backlog: does an identifier in the case you are
working on ALSO appear in a case you closed months ago? A repeat across cases is the strongest
same-operator signal available, because the two collections were independent.

Noise control is inherited, not reinvented: it reads the KB through the same shared_indicators()
path, so the managed-DNS / parking-favicon filters in noise_filters.py apply here too. Adding a
second filter would guarantee the two drift apart.

Pure: reads the local KB only. No network, no keys.

Usage:
  kb_crossref.py                       # every cross-case identifier
  kb_crossref.py --case CASE-0001      # only identifiers this case shares with others
  kb_crossref.py --min-cases 3 --pretty
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
KB_TOOLS = os.path.join(ENGINE, "tools", "kb")
KB_DIR = os.environ.get("INTEL_KB") or os.path.join(ENGINE, "knowledge")
CASES = os.path.join(ENGINE, "cases")


def case_hosts():
    """host -> {cases it appears in}, read from each case's collected pivot JSON."""
    out = {}
    for raw in glob.glob(os.path.join(CASES, "*", "raw", "*.json")):
        case = os.path.basename(os.path.dirname(os.path.dirname(raw)))
        try:
            d = json.load(open(raw, encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        # Raw pivot files are usually one object, but some collectors write a LIST of pages.
        # Handle both; fall back to the filename, which the pipeline names after the host.
        docs = d if isinstance(d, list) else [d]
        hosts = set()
        for doc in docs:
            if isinstance(doc, dict):
                h = ((doc.get("meta") or {}).get("host") or "").lower()
                if h:
                    hosts.add(h)
        if not hosts:
            hosts = {os.path.splitext(os.path.basename(raw))[0].lower()}
        for h in hosts:
            out.setdefault(h, set()).add(case)
    return out


def main():
    ap = argparse.ArgumentParser(description="Identifiers appearing across more than one case.")
    ap.add_argument("--case", help="restrict to identifiers touching this case")
    ap.add_argument("--min-cases", type=int, default=2)
    ap.add_argument("--pretty", action="store_true")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()

    sys.path.insert(0, KB_TOOLS)
    try:
        from knowledge_base import KB
    except Exception as e:  # noqa: BLE001
        print(json.dumps({"error": f"KB unavailable: {type(e).__name__}: {e}",
                          "hint": "run from a checkout where intel_engine/knowledge exists"}))
        return 3
    if not os.path.isdir(KB_DIR):
        print(json.dumps({"error": f"no KB at {KB_DIR}",
                          "verdict": "nothing ingested yet — absence of data, not of overlap"}))
        return 0

    kb = KB(KB_DIR)
    hosts = case_hosts()
    n_cases = len({c for cs in hosts.values() for c in cs})

    # The SAME boilerplate rels _write_clusters excludes. shared_indicators() drops noisy
    # INDICATORS (managed DNS, parking favicons) but not noisy RELATIONS: a shared DOM skeleton
    # or HTML comment is template reuse, and two cases "sharing" 29 of those is a shared CMS,
    # not a shared operator. Without this the tool argues for merging unrelated cases.
    NOISE_RELS = {"same_inline_css", "same_comment", "same_template"}
    try:
        from reference import benign_values
        benign = benign_values(KB_DIR)
    except Exception:  # noqa: BLE001
        benign = set()

    rows, dropped = [], 0
    for s in kb.shared_indicators(1):          # indicator-level noise filtering applied inside
        strong = [r for r in (s.get("rels") or []) if r not in NOISE_RELS]
        if not strong or s.get("indicator") in benign:
            dropped += 1
            continue
        cases = set()
        for d in s.get("domains") or []:
            cases |= hosts.get(str(d).lower(), set())
        if len(cases) < a.min_cases:
            continue
        if a.case and a.case not in cases:
            continue
        rows.append({"indicator": f"{s['indicator_type']}:{s['indicator']}",
                     "rels": strong, "cases": sorted(cases), "n_cases": len(cases),
                     "domains": sorted(s.get("domains") or [])[:12],
                     "kb_wide_domains": s.get("domain_count")})
    # rarest KB-wide but spanning the most cases = most distinctive
    rows.sort(key=lambda r: (-r["n_cases"], r["kb_wide_domains"]))

    out = {"kb": KB_DIR, "cases_seen": n_cases, "min_cases": a.min_cases,
           "scoped_to": a.case, "crossrefs": rows, "count": len(rows),
           "note": ("An identifier in two INDEPENDENTLY collected cases is a strong same-operator "
                    "signal. Still apply the two-artifact rule: one shared identifier across two "
                    "cases is a lead; corroborate with a second before merging the cases. "
                    "kb_wide_domains >> the domains listed means prevalent infrastructure, "
                    "not an owner link."),
           "noise_filtering": ("indicator-level from noise_filters.py via KB.shared_indicators; "
                               "relation-level using the SAME boilerplate set _write_clusters "
                               "excludes (same_inline_css / same_comment / same_template) plus "
                               "the /reference benign ledger"),
           "boilerplate_dropped": dropped}
    if not rows:
        out["verdict"] = (f"no identifier spans >={a.min_cases} of the {n_cases} case(s) in this "
                          f"KB. With few cases ingested this is expected — absence of overlap, "
                          f"not evidence of unrelated operators.")
    else:
        out["verdict"] = f"{len(rows)} identifier(s) span >={a.min_cases} cases"
    print(f"crossref: {len(rows)} identifier(s) across {n_cases} case(s)", file=sys.stderr)
    for r in rows[:8]:
        print(f"  {r['indicator']}  → {', '.join(r['cases'])}", file=sys.stderr)
    txt = json.dumps(out, indent=2 if a.pretty else None, ensure_ascii=False)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(txt)
    print(txt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
