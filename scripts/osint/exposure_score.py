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

The EXECUTIVE model (--model executive, analysis/weight-engine.md §7) is a different, DEDUCTIVE
score for a protected person: start at 100, eight criteria C1..C8 each rated 0-3 by the analyst,
deduction = max * rating / 3. Higher = SAFER. Criteria, maxima and bands are reference DATA
(references/exposure_executive.json). Unrated criteria are reported as coverage gaps, never
silently scored as 0 deduction.

Usage:
  exposure_score.py --set breach_count=3 --set account_security=40
  exposure_score.py indicators.json --pretty
  exposure_score.py --list          # show the weight table
  exposure_score.py --model executive --set c1=2 --set c2=3 --set c2_rationale="ID number in a leak"
  exposure_score.py --model executive ratings.json   # {"c1": 2, "c2": {"rating": 3, "rationale": "..."}}
  exposure_score.py --model executive --list
"""
# /// script
# requires-python = ">=3.9"
# ///
import argparse
import json
import os
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


# ── EXECUTIVE model: deductive 8-criteria score (analysis/weight-engine.md §7) ──────────────────
# Fallback = the documented model itself, so a missing reference file changes nothing silently
# (load_ref still warns on stderr).
_EXEC_FALLBACK = {
    "settings": {"start_score": 100, "rating_max": 3},
    "criteria": {
        "c1": {"label": "Digital account footprint", "max": 15},
        "c2": {"label": "PII exposure", "max": 20},
        "c3": {"label": "Family / close-relation exposure", "max": 15},
        "c4": {"label": "Physical address & habits", "max": 15},
        "c5": {"label": "Corporate assets & financial exposure", "max": 10},
        "c6": {"label": "Political / reputation", "max": 10},
        "c7": {"label": "Breach records & stealer logs", "max": 10},
        "c8": {"label": "Account & infrastructure security", "max": 5},
    },
    "bands": {"80": "LOW", "60": "MODERATE", "40": "HIGH", "0": "CRITICAL"},
}


def _load_exec_refs():
    try:
        eng = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                            "..", "..", "intel_engine", "WebPivot", "tools"))
        if eng not in sys.path:
            sys.path.insert(0, eng)
        from wp_refs import load_ref, ref_path
        return load_ref(ref_path(__file__, "exposure_executive.json"), _EXEC_FALLBACK)
    except Exception:  # noqa: BLE001 — loader missing: the embedded model, loudly
        print("[!] exposure_executive.json not loaded — using the embedded model", file=sys.stderr)
        return dict(_EXEC_FALLBACK)


def _exec_inputs(raw):
    """{cN: number | {"rating", "rationale"}, cN_rationale: str} -> ({cN: rating}, {cN: text})."""
    ratings, notes = {}, {}
    for k, v in raw.items():
        k = str(k).strip().lower()
        if k.endswith("_rationale"):
            notes[k[:-len("_rationale")]] = str(v)
        elif isinstance(v, dict):
            if v.get("rating") is not None:
                ratings[k] = v["rating"]
            if v.get("rationale"):
                notes[k] = str(v["rationale"])
        else:
            ratings[k] = v
    return ratings, notes


def score_executive(raw, refs=None):
    """Deductive executive score. `raw` = {c1..c8: rating 0..rating_max, cN_rationale: str}.

    score = start - Σ max_i * rating_i / rating_max over the RATED criteria. Unrated criteria
    are listed in `missing`, their maxima summed into `unassessed_max_deduction`, and
    `score_floor` shows the worst case if every unrated criterion turned out fully exposed."""
    refs = refs or _load_exec_refs()
    crit = refs["criteria"]
    start = float(refs["settings"].get("start_score", 100))
    rmax = float(refs["settings"].get("rating_max", 3))
    bands = sorted(((float(t), b) for t, b in refs["bands"].items()), reverse=True)
    ratings, notes = _exec_inputs(raw)

    rows, missing, invalid, total_ded, unassessed = [], [], [], 0.0, 0.0
    for key, c in crit.items():
        mx = float(c["max"])
        r = ratings.get(key)
        row = {"criterion": key, "label": c.get("label", key), "max": mx}
        if r is not None:
            try:
                r = float(r)
            except (TypeError, ValueError):
                invalid.append(f"{key}={r!r} (not a number)")
                r = None
            else:
                if not 0 <= r <= rmax:
                    invalid.append(f"{key}={r:g} (outside 0-{rmax:g})")
                    r = None
        if r is None:
            missing.append(key)
            unassessed += mx
            row.update(rating=None, deduction=None)
        else:
            ded = mx * r / rmax
            total_ded += ded
            row.update(rating=r, deduction=round(ded, 2))
        if notes.get(key):
            row["rationale"] = notes[key]
        rows.append(row)

    n, rated = len(crit), len(crit) - len(missing)
    unknown = sorted(set(ratings) - set(crit))
    out = {"model": "executive", "start": start, "rows": rows,
           "deductions_total": round(total_ded, 2), "missing": missing,
           "coverage": f"{rated}/{n}", "coverage_ratio": round(rated / n, 4) if n else 0.0}
    if invalid:
        out["invalid"] = invalid
    if unknown:
        out["ignored_unknown_criteria"] = unknown
    if rated == 0:
        out.update(score=None, band=None,
                   verdict="NO CRITERIA RATED — nothing to score")
        return out
    sc = start - total_ded
    out["score"] = round(sc, 2)
    out["band"] = next(b for t, b in bands if sc >= t)
    out["unassessed_max_deduction"] = round(unassessed, 2)
    out["score_floor"] = round(sc - unassessed, 2)
    if missing:
        out["band_floor"] = next(b for t, b in bands if out["score_floor"] >= t)
        out["verdict"] = (f"rated on {rated}/{n} criteria — unrated ({', '.join(missing)}) are NOT "
                          f"zero exposure; worst case {out['score_floor']:g} ({out['band_floor']}) "
                          f"if they prove fully exposed")
    else:
        out["verdict"] = f"fully rated on all {n} criteria"
    return out


def main():
    ap = argparse.ArgumentParser(description="Composite 0-100 subject exposure score.")
    ap.add_argument("infile", nargs="?", help="JSON file of {indicator: raw_value} "
                    "(executive: {cN: rating | {rating, rationale}, cN_rationale: text})")
    ap.add_argument("--model", choices=("composite", "executive"), default="composite",
                    help="composite = the weight-engine 0-100 (default, higher = more exposed); "
                         "executive = deductive 8-criteria score from 100 (higher = safer)")
    ap.add_argument("--set", action="append", default=[], metavar="KEY=VALUE",
                    help="set an indicator inline (repeatable); executive also takes "
                         "cN_rationale=TEXT")
    ap.add_argument("--list", action="store_true", help="print the weight table and exit")
    ap.add_argument("--pretty", action="store_true")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()

    if a.model == "executive":
        refs = _load_exec_refs()
        if a.list:
            print(f"{'CRITERION':<11}{'LABEL':<42}{'MAX':>5}")
            for k, c in refs["criteria"].items():
                print(f"{k:<11}{c.get('label', k):<42}{float(c['max']):>5g}")
            print(f"start {refs['settings'].get('start_score', 100)}; deduction = max * rating / "
                  f"{refs['settings'].get('rating_max', 3)}; bands: "
                  + ", ".join(f">={t} {b}" for t, b in refs["bands"].items()))
            return 0
        raw = {}
        if a.infile:
            raw.update(json.load(open(a.infile, encoding="utf-8")))
        for kv in a.set:
            if "=" not in kv:
                ap.error(f"--set expects KEY=VALUE, got {kv!r}")
            k, v = kv.split("=", 1)
            raw[k.strip()] = v
        res = score_executive(raw, refs)
        print(f"executive exposure: {res['score']} ({res['band']}) coverage {res['coverage']} — "
              f"{res['verdict']}", file=sys.stderr)
        if res.get("invalid"):
            print(f"  invalid rating(s) treated as unrated: {'; '.join(res['invalid'])}",
                  file=sys.stderr)
        txt = json.dumps(res, indent=2 if a.pretty else None, ensure_ascii=False)
        if a.out:
            open(a.out, "w", encoding="utf-8").write(txt)
        print(txt)
        return 0

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
