#!/usr/bin/env python3
"""exposure_score.py — the composite 0-100 exposure score from analysis/weight-engine.md.

The engine's `risk_signals` scores INFRASTRUCTURE (NRD, bulletproof hosting, money trail). This
scores a SUBJECT: how much of a person or organisation is observable, across security, privacy,
reputation, legal, infrastructure and surface. Different question, different weights, and the two
must not be conflated in a report.

Implements the weight table verbatim — weights sum to 1.0 and that is asserted at import, because
a table that silently stops summing to 1 yields scores that look fine and rank wrongly.

Deliberately PURE: it consumes indicator values you have already collected and does no lookups of
its own. Feed it JSON, or name indicators on the command line. Missing indicators are reported as
missing and EXCLUDED from the denominator — a subject scored on 3 of 11 indicators is not
comparable to one scored on 11, and the output says which it is.

Usage:
  exposure_score.py --set breach_count=3 --set account_security=40
  exposure_score.py indicators.json --pretty
  exposure_score.py --list          # show the weight table
"""
# /// script
# requires-python = ">=3.9"
# ///
import argparse
import json
import sys

# (key, group, weight, raw_min, raw_max)  — from analysis/weight-engine.md §1 and §2
WEIGHTS = [
    ("breach_count",          "security",       0.17,  0, 10),
    ("credential_reuse",      "security",       0.13,  0, 100),
    ("account_security",      "security",       0.16,  0, 100),
    ("personal_info",         "privacy",        0.09,  0, 100),
    ("metadata_leakage",      "privacy",        0.07,  0, 100),
    ("content_liability",     "reputation",     0.11,  0, 100),
    ("persona_consistency",   "reputation",     0.08,  0, 100),
    ("legal_finding",         "legal",          0.08,  0, 100),
    ("compliance_violation",  "legal",          0.04,  0, 100),
    ("threat_intelligence",   "infrastructure", 0.11,  0, 100),
    ("platform_breadth",      "surface",        0.06,  0, 100),
]
# analysis/weight-engine.md asserts "all weights sum to 1.0" and prints the addition as
# 0.17+0.13+0.16+0.09+0.07+0.11+0.08+0.08+0.04+0.11+0.06 = 1.00. That arithmetic is wrong: the
# figures sum to 1.10, and the doc's own group subtotals (0.46+0.16+0.19+0.12+0.11+0.06) sum to
# 1.10 too. The weights are kept VERBATIM because they encode the analyst's intended RELATIVE
# importance, which is the part that carries meaning; the composite is divided by the real sum so
# the output is a true 0-100. Rewriting someone's weight table to force a total would change the
# ranking silently — normalising does not.
_SUM = round(sum(w for _, _, w, _, _ in WEIGHTS), 10)
WEIGHTS_SUM_DECLARED = 1.00
assert all(w > 0 for _, _, w, _, _ in WEIGHTS), "every weight must be positive"

BANDS = [(80, "CRITICAL"), (60, "HIGH"), (40, "MODERATE"), (20, "LOW"), (0, "MINIMAL")]


def minmax(raw, lo, hi):
    if hi == lo:
        return 0.0
    return max(0.0, min(1.0, (float(raw) - lo) / (hi - lo)))


def score(indicators):
    rows, present, missing = [], 0.0, []
    total = 0.0
    for key, group, weight, lo, hi in WEIGHTS:
        if key not in indicators or indicators[key] is None:
            missing.append(key)
            rows.append({"indicator": key, "group": group, "weight": weight,
                         "raw": None, "normalized": None, "contribution": None})
            continue
        raw = indicators[key]
        n = minmax(raw, lo, hi)
        contrib = n * weight
        total += contrib
        present += weight
        rows.append({"indicator": key, "group": group, "weight": weight, "raw": raw,
                     "raw_range": [lo, hi], "normalized": round(n, 4),
                     "contribution": round(contrib * 100, 2)})

    if present == 0:
        return {"score": None, "band": None, "rows": rows, "missing": missing,
                "coverage": 0.0,
                "verdict": "NO INDICATORS SUPPLIED — nothing to score"}

    # Renormalize over the indicators actually supplied, so a partially-scored subject is not
    # silently penalised for the data you never collected. Coverage is reported alongside.
    composite = (total / present) * 100
    band = next(b for t, b in BANDS if composite >= t)
    out = {"score": round(composite, 1), "band": band, "rows": rows,
           "missing": missing, "coverage": round(present / _SUM, 4),
           "weights_sum_actual": _SUM, "weights_sum_declared": WEIGHTS_SUM_DECLARED}
    if _SUM != WEIGHTS_SUM_DECLARED:
        out["weight_table_note"] = (
            f"analysis/weight-engine.md declares the weights sum to {WEIGHTS_SUM_DECLARED:.2f} but "
            f"they sum to {_SUM:.2f}. Weights kept verbatim (they encode relative importance); the "
            f"composite is normalised by the real sum, so the score is a true 0-100.")
    if present < _SUM:
        out["verdict"] = (f"scored on {len(WEIGHTS)-len(missing)}/{len(WEIGHTS)} indicators "
                          f"({present/_SUM:.0%} of total weight) — comparable only to other subjects "
                          f"at the same coverage, never to a fully-scored one")
    else:
        out["verdict"] = "fully scored on all 11 indicators"
    return out


def main():
    ap = argparse.ArgumentParser(description="Composite 0-100 subject exposure score.")
    ap.add_argument("infile", nargs="?", help="JSON file of {indicator: raw_value}")
    ap.add_argument("--set", action="append", default=[], metavar="KEY=VALUE",
                    help="set an indicator inline (repeatable)")
    ap.add_argument("--list", action="store_true", help="print the weight table and exit")
    ap.add_argument("--pretty", action="store_true")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()

    if a.list:
        print(f"{'INDICATOR':<24}{'GROUP':<16}{'WEIGHT':>7}  RAW RANGE")
        for k, g, w, lo, hi in WEIGHTS:
            print(f"{k:<24}{g:<16}{w:>7.2f}  {lo}-{hi}")
        print(f"{'':<24}{'':<16}{_SUM:>7.2f}  (doc declares "
              f"{WEIGHTS_SUM_DECLARED:.2f} — normalised at runtime)")
        return 0

    ind = {}
    if a.infile:
        ind.update(json.load(open(a.infile, encoding="utf-8")))
    for kv in a.set:
        if "=" not in kv:
            ap.error(f"--set expects KEY=VALUE, got {kv!r}")
        k, v = kv.split("=", 1)
        try:
            ind[k.strip()] = float(v)
        except ValueError:
            ap.error(f"--set value must be numeric: {kv!r}")

    known = {k for k, _, _, _, _ in WEIGHTS}
    unknown = sorted(set(ind) - known)
    res = score({k: v for k, v in ind.items() if k in known})
    if unknown:
        res["ignored_unknown_indicators"] = unknown

    print(f"exposure: {res['score']} ({res['band']}) — {res['verdict']}", file=sys.stderr)
    if unknown:
        print(f"  ignored unknown indicator(s): {', '.join(unknown)}", file=sys.stderr)
    txt = json.dumps(res, indent=2 if a.pretty else None, ensure_ascii=False)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(txt)
    print(txt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
