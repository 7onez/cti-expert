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

The ORGANISATION model (--model organisation, analysis/weight-engine.md §8) rates an organisation
by risk DOMAIN: the analyst gives each domain exploitability 0-3 and harm 0-3; the pair maps onto
0-10 through the reference score_matrix and the overall score is the mean of the RATED domains.
Analyst judgement on a fixed scale — never automatic, never a probability. Unrated domains are
excluded and listed under coverage; organisations rated on different coverage are not comparable.
Domains, matrix, bands and priorities are reference DATA (references/exposure_organisation.json).

Usage:
  exposure_score.py --set breach_count=3 --set account_security=40
  exposure_score.py indicators.json --pretty
  exposure_score.py --list          # show the weight table
  exposure_score.py --model executive --set c1=2 --set c2=3 --set c2_rationale="ID number in a leak"
  exposure_score.py --model executive ratings.json   # {"c1": 2, "c2": {"rating": 3, "rationale": "..."}}
  exposure_score.py --model executive --list
  exposure_score.py --model organisation --set edge=3x3 --set edge_rationale="public exploit for the VPN"
  exposure_score.py --model organisation ratings.json --case CASE-0001
                    # {"edge": {"exploitability": 3, "harm": 3, "rationale": "...", "issue": "..."}}
  exposure_score.py --model organisation --list
  exposure_score.py --model actor --set actor="SAMPLE PANDA" --set intent=0.5 ... --case CASE-0001
  exposure_score.py --model actor ratings.json --set exposure_level=Significant
                    # {"actor": "...", "intent": {"rating": 0.75, "rationale": "...", "evidence": "https://..."}}
  exposure_score.py --model tier --set severity=High --set exposure=Extensive --set rationale="..."
  exposure_score.py --model tier --case CASE-0001 --set item=... --set trigger=new_exposure ...
  exposure_score.py --model actor --list | --model tier --list

The ACTOR model (--model actor, weight-engine.md §9) is an analyst-rated Threat Score (0-1) for
one actor against one organisation: intent, capability, sectoral_reach, org_exposure in 0.25
steps; the Intent floor rule zeroes it when intent is 0. The TIER model (--model tier, §10 and
handbook/severity-tiers.md) reads a P1-P4 response tier off the Severity Tier Matrix grid. Both
adapt [PK Packt ACTIH companion repo, 2026, chapter-01] (MIT); weights, steps, bands, grid and
triggers are reference DATA (references/exposure_actor.json, references/severity_tiers.json).
"""
# /// script
# requires-python = ">=3.9"
# ///
import argparse
import copy
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


# ── ORGANISATION model: analyst-rated risk by domain (analysis/weight-engine.md §8) ────────────
# Each domain is rated exploitability 0-3 x harm 0-3 BY THE ANALYST; the pair maps onto 0-10 via
# the reference score_matrix; overall = mean of the RATED domains. Nothing here is automatic and
# the score is not a probability. Fallback = the documented model itself (load_ref still warns).
_ORG_FALLBACK = {
    "settings": {"rating_max": 3, "score_max": 10, "decimals": 1, "rationale_required_harm": 3,
                 "min_coverage_ratio": 0.5, "overall_method": "mean of rated domains"},
    "domains": {
        "affiliates": {"name": "Affiliate, member and partner compromise"},
        "impersonation": {"name": "Impersonation and fraud industry"},
        "edge": {"name": "Network edge and remote access"},
        "insider": {"name": "Insider and channel abuse"},
        "personnel": {"name": "Key personnel and leadership"},
        "actors": {"name": "State actors and criminal markets"},
        "credentials": {"name": "Staff credentials"},
        "suppliers": {"name": "Suppliers and partners"},
        "mail_dns": {"name": "Certificates, email and domains"},
        "code_docs": {"name": "Code, apps and documents"},
    },
    "score_matrix": {"0": [0.0, 0.0, 0.0, 0.0], "1": [0.0, 1.1, 2.2, 3.3],
                     "2": [0.0, 2.2, 4.4, 6.7], "3": [0.0, 3.3, 6.7, 10.0]},
    "bands": {"8.0": "Critical", "6.0": "High", "4.0": "Medium", "0": "Low"},
    "priorities": {"P1": "7 days", "P2": "30 days", "P3": "90 days"},
    "rubric": {},
}
_ORG_FIELDS = (("_exploitability", "exploitability"), ("_main_issue", "issue"), ("_harm", "harm"),
               ("_rationale", "rationale"), ("_issue", "issue"))


def _load_org_refs():
    try:
        eng = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                            "..", "..", "intel_engine", "WebPivot", "tools"))
        if eng not in sys.path:
            sys.path.insert(0, eng)
        from wp_refs import load_ref, ref_path
        return load_ref(ref_path(__file__, "exposure_organisation.json"), _ORG_FALLBACK)
    except Exception:  # noqa: BLE001 — loader missing: the embedded model, loudly
        print("[!] exposure_organisation.json not loaded — using the embedded model", file=sys.stderr)
        return dict(_ORG_FALLBACK)


def _round_half_up(x, decimals):
    from decimal import ROUND_HALF_UP, Decimal
    return float(Decimal(repr(float(x))).quantize(Decimal(1).scaleb(-int(decimals)), ROUND_HALF_UP))


def org_level(score, refs=None):
    """0-10 score -> level, from the reference bands (lower bound inclusive, highest first)."""
    refs = refs or _load_org_refs()
    bands = sorted(((float(t), b) for t, b in refs["bands"].items()), reverse=True)
    return next((b for t, b in bands if score >= t), bands[-1][1])


def _org_inputs(raw, domain_ids):
    """{d: "2x3" | {exploitability, harm, rationale, issue}, d_exploitability, d_harm,
    d_rationale, d_issue} -> {d: {field: value}}. Unknown domain ids raise: a typo must not
    silently become an unrated domain and change coverage."""
    out, unknown = {}, []
    for k, v in raw.items():
        k = str(k).strip().lower()
        dom, field = k, None
        for suf, name in _ORG_FIELDS:
            if k.endswith(suf) and k[:-len(suf)] in domain_ids:
                dom, field = k[:-len(suf)], name
                break
        if dom not in domain_ids:
            unknown.append(k)
            continue
        slot = out.setdefault(dom, {})
        if field:
            slot[field] = v
        elif isinstance(v, dict):
            for fk, fv in v.items():
                fk = {"main_issue": "issue"}.get(str(fk), str(fk))
                if fk in ("exploitability", "harm", "rationale", "issue") and fv not in (None, ""):
                    slot[fk] = fv
        elif isinstance(v, str) and any(s in v.lower() for s in ("x", "*", "×")):
            parts = v.lower().replace("*", "x").replace("×", "x").split("x")
            if len(parts) != 2:
                raise ValueError(f"{dom}={v!r}: expected EXPLOITABILITYxHARM, e.g. 2x3")
            slot["exploitability"], slot["harm"] = parts[0].strip(), parts[1].strip()
        else:
            raise ValueError(f"{dom}={v!r}: expected EXPLOITABILITYxHARM (e.g. 2x3) or "
                             f"{dom}_exploitability / {dom}_harm")
    if unknown:
        raise ValueError(f"unknown domain key(s): {', '.join(sorted(unknown))} — known domains: "
                         f"{', '.join(domain_ids)}")
    return out


def _org_axis(dom, name, v, rmax):
    try:
        f = float(v)
    except (TypeError, ValueError):
        raise ValueError(f"{dom}_{name}={v!r} is not a number") from None
    if f != int(f) or not 0 <= f <= rmax:
        raise ValueError(f"{dom}_{name}={v!r} must be an integer 0-{rmax}")
    return int(f)


def score_organisation(raw, refs=None):
    """Analyst-rated organisation risk by domain -> the C1 risk object.

    Domain score = score_matrix[exploitability][harm] (0-10); overall = mean of the RATED
    domains. Unrated domains are excluded and listed under coverage. Raises ValueError on an
    unknown domain, a half-rated domain, an out-of-range rating, a harm >= rationale_required_harm
    without a rationale, or when no domain is rated at all."""
    refs = refs or _load_org_refs()
    st = refs["settings"]
    rmax = int(st.get("rating_max", 3))
    dec = int(st.get("decimals", 1))
    smax = float(st.get("score_max", 10))
    need_why = float(st.get("rationale_required_harm", rmax))
    matrix = refs["score_matrix"]
    domains = refs["domains"]
    ids = list(domains)
    given = _org_inputs(raw, ids)

    rated, unrated, scores = [], [], []
    for d in ids:
        g = given.get(d) or {}
        has_e, has_h = g.get("exploitability") not in (None, ""), g.get("harm") not in (None, "")
        if not has_e and not has_h:
            if g.get("rationale") or g.get("issue"):
                raise ValueError(f"{d}: rationale/issue given but the domain is not rated")
            unrated.append(d)
            continue
        if has_e != has_h:
            raise ValueError(f"{d}: rate BOTH exploitability and harm (got only "
                             f"{'exploitability' if has_e else 'harm'})")
        e = _org_axis(d, "exploitability", g["exploitability"], rmax)
        h = _org_axis(d, "harm", g["harm"], rmax)
        why = str(g.get("rationale") or "").strip()
        if h >= need_why and not why:
            raise ValueError(f"{d}: harm {h} requires {d}_rationale naming the evidence")
        row = matrix.get(str(e))
        if not isinstance(row, list) or len(row) != rmax + 1:
            raise ValueError(f"score_matrix row {e} must list {rmax + 1} scores")
        sc = float(row[h])
        if not 0 <= sc <= smax:
            raise ValueError(f"score_matrix[{e}][{h}]={sc:g} is outside 0-{smax:g}")
        sc = _round_half_up(sc, dec)
        scores.append(sc)
        rated.append({"id": d, "name": domains[d].get("name", d), "exploitability": e,
                      "harm": h, "score": sc, "level": org_level(sc, refs),
                      "main_issue": str(g.get("issue") or "").strip(), "rationale": why})
    if not rated:
        raise ValueError("no domain rated — the organisation model needs at least one rated "
                         "domain (exploitability AND harm)")

    overall = _round_half_up(sum(scores) / len(scores), dec)
    n, total = len(rated), len(ids)
    coverage = {"rated": n, "total": total, "unrated": unrated,
                "note": (f"rated on {n}/{total} domains; unrated domains are unknown, not low risk. "
                         f"Never compare organisations scored on different domain coverage.")}
    if n / total < float(st.get("min_coverage_ratio", 0.5)):
        coverage["warning"] = (f"only {n}/{total} domains rated (fewer than "
                               f"{float(st.get('min_coverage_ratio', 0.5)):.0%}) — the overall "
                               f"score reflects a minority of the attack surface")
    bands = {b: float(t) for t, b in sorted(((float(t), b) for t, b in refs["bands"].items()),
                                             reverse=True)}
    return {"model": "organisation", "domains": rated,
            "overall": {"score": overall, "level": org_level(overall, refs),
                        "method": str(st.get("overall_method", "mean of rated domains")),
                        "note": "analyst judgement on a fixed 0-10 scale, not a probability"},
            "coverage": coverage, "bands": bands, "priorities": dict(refs["priorities"])}


def _case_dir(case):
    """A case is a bare id living under $INTEL_HOME/cases (default intel_engine/cases). The id
    must match the shared case-ID rule (wp_appliance._CASE_RE): an absolute path, a slash or a
    leading dot is refused with ValueError, so --case can never write outside cases/."""
    c = str(case)
    eng = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                        "..", "..", "intel_engine", "WebPivot", "tools"))
    if eng not in sys.path:
        sys.path.insert(0, eng)
    from wp_appliance import _CASE_RE  # the one case-ID rule
    if not _CASE_RE.fullmatch(c):
        raise ValueError(f"invalid case id {c!r} — a bare id (letters, digits, '.', '_', '-'), "
                         f"not a path")
    skill = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
    home = os.environ.get("INTEL_HOME") or os.path.join(skill, "intel_engine")
    return os.path.join(home, "cases", c)


def write_case(case, result):
    """Write the C1 object to cases/<id>/exposure_organisation.json; returns the path."""
    cdir = _case_dir(case)
    if not os.path.isdir(cdir):
        raise FileNotFoundError(f"no case at {cdir}")
    path = os.path.join(cdir, "exposure_organisation.json")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, ensure_ascii=False)
    os.replace(tmp, path)
    return path


# ── ACTOR model: Threat Score from intent / capability / opportunity (weight-engine.md §9) ──────
# Adapted from [PK Packt ACTIH companion repo, 2026, chapter-01/Threat Actor Scoring Model.md].
# Four analyst ratings in fixed steps; Opportunity = reach x 0.6 + exposure x 0.4; Threat Score =
# intent x 0.5 + capability x 0.25 + opportunity x 0.25; the Intent floor rule zeroes it when
# intent is 0. Organisation-specific, a lead, never attribution. The fallback carries the numbers
# only (no postures, no scale text), so a loaded posture proves the reference file was read.
_ACTOR_FALLBACK = {
    "settings": {"rating_min": 0.0, "rating_max": 1.0, "step": 0.25, "decimals": 2,
                 "floor_value": 0.0, "evidence_required_intent": 0.75,
                 "evidence_pattern": r"https?://\S+|\bCASE-[A-Za-z0-9_-]+|\bcases/\S+",
                 "drift_warn_shift": 0.10},
    "weights": {"intent": 0.5, "capability": 0.25, "opportunity": 0.25},
    "opportunity_weights": {"sectoral_reach": 0.6, "org_exposure": 0.4},
    "dimensions": {"intent": {"name": "Intent"}, "capability": {"name": "Capability"},
                   "sectoral_reach": {"name": "Opportunity: sectoral reach"},
                   "org_exposure": {"name": "Opportunity: organisational exposure"}},
    "bands": {"Critical": {"min": 0.85, "review_cadence_days": 30},
              "High": {"min": 0.60, "review_cadence_days": 90},
              "Medium": {"min": 0.35, "review_cadence_days": 90},
              "Low": {"min": 0.10, "review_cadence_days": None},
              "Negligible": {"min": 0.0, "review_cadence_days": None}},
    "axis1_map": {"Critical": "Critical", "High": "High", "Medium": "Medium", "Low": "Low",
                  "Negligible": "Low"},
}
ACTOR_DIMS = ("intent", "capability", "sectoral_reach", "org_exposure")
_ACTOR_META = ("actor", "organisation", "rationale", "reason", "exposure_level", "as_of")
ACTOR_NOTE = ("Threat Score is analyst judgement for ONE organisation (sectoral_reach and "
              "org_exposure describe that organisation), not a probability, not attribution and "
              "never a same-operator edge. Never compare actor scores across organisations or "
              "across different org_exposure ratings.")

# ── SEVERITY TIER MATRIX (weight-engine.md §10, handbook/severity-tiers.md) ────────────────────
# Adapted from [PK Packt ACTIH companion repo, 2026, chapter-01/CTI Severity Tier Matrix.md].
# Fallback = the grid and tier deadlines only (no dimension guides, no trigger text).
_TIER_FALLBACK = {
    "severities": ["Critical", "High", "Medium", "Low"],
    "exposures": ["None", "Limited", "Significant", "Extensive"],
    "grid": {"Critical": ["P3", "P2", "P1", "P1"], "High": ["P4", "P3", "P2", "P1"],
             "Medium": ["P4", "P3", "P3", "P2"], "Low": ["P4", "P4", "P4", "P3"]},
    "rules": {"p1_min_severity": "High", "p1_min_exposure": "Significant", "auto_close": False},
    "tiers": {"P1": {"deadline": "7 days", "report_priority": "P1"},
              "P2": {"deadline": "30 days", "report_priority": "P2"},
              "P3": {"deadline": "90 days", "report_priority": "P3"},
              "P4": {"deadline": None, "report_priority": "P4"}},
    "retier_triggers": {k: {} for k in ("exploitation_confirmed", "new_exposure",
                                        "mitigation_threshold", "actor_adopts", "sector_shift",
                                        "attribution_downgrade", "actor_rescored")},
}
_EXPOSURE_ALIASES = {"negligible": "None", "none/negligible": "None"}


def _load_refs_file(name, fallback):
    try:
        eng = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                            "..", "..", "intel_engine", "WebPivot", "tools"))
        if eng not in sys.path:
            sys.path.insert(0, eng)
        from wp_refs import load_ref, ref_path
        return load_ref(ref_path(__file__, name), fallback)
    except Exception:  # noqa: BLE001 — loader missing: the embedded model, loudly
        print(f"[!] {name} not loaded — using the embedded model", file=sys.stderr)
        return copy.deepcopy(fallback)


def _load_actor_refs():
    return _load_refs_file("exposure_actor.json", _ACTOR_FALLBACK)


def _load_tier_refs():
    refs = _load_refs_file("severity_tiers.json", _TIER_FALLBACK)
    check_grid(refs)
    return refs


def check_grid(refs):
    """Enforce the matrix design rules on whatever grid is loaded: every row/column present,
    every cell a known tier (nothing closes automatically), and P1 only where BOTH axes reach
    the rules' minimums. Raises ValueError — a re-weighted grid that breaks a rule must not load."""
    sev, exp, grid, tiers = refs["severities"], refs["exposures"], refs["grid"], refs["tiers"]
    rules = refs.get("rules") or {}
    if list(grid) != list(sev):
        raise ValueError(f"severity_tiers grid rows {list(grid)} must equal severities {sev}")
    smin = sev.index(rules.get("p1_min_severity", "High"))
    emin = exp.index(rules.get("p1_min_exposure", "Significant"))
    for i, s in enumerate(sev):
        row = grid[s]
        if not isinstance(row, list) or len(row) != len(exp):
            raise ValueError(f"severity_tiers grid row {s} must list {len(exp)} tiers")
        for j, cell in enumerate(row):
            if cell not in tiers:
                raise ValueError(f"severity_tiers grid {s}/{exp[j]}={cell!r} is not a known tier "
                                 f"({', '.join(tiers)}) — no cell may close an item")
            if cell == "P1" and (i > smin or j < emin):
                raise ValueError(f"severity_tiers grid {s}/{exp[j]}=P1 breaks the design rule: "
                                 f"P1 needs severity >= {sev[smin]} AND exposure >= {exp[emin]}")


def _canon(value, allowed, what, aliases=None):
    v = str(value or "").strip()
    low = v.lower()
    if aliases and low in aliases:
        return aliases[low]
    for a in allowed:
        if a.lower() == low:
            return a
    raise ValueError(f"{what}={value!r} — expected one of {', '.join(allowed)}")


def tier_cell(severity, exposure, refs=None):
    """(severity, exposure) -> the tier object for that grid cell."""
    refs = refs or _load_tier_refs()
    sev = _canon(severity, refs["severities"], "severity")
    exp = _canon(exposure, refs["exposures"], "exposure", _EXPOSURE_ALIASES)
    tier = refs["grid"][sev][refs["exposures"].index(exp)]
    meta = refs["tiers"][tier]
    out = {"severity": sev, "exposure": exp, "tier": tier,
           "cell": {"row": sev, "column": exp, "value": tier},
           "deadline": meta.get("deadline"), "report_priority": meta.get("report_priority")}
    if meta.get("name"):
        out["tier_name"] = meta["name"]
    notes = []
    if meta.get("deadline") is None:
        notes.append(f"{tier} is track only: no deadline, recorded and not closed; it may carry "
                     f"key_findings.priority {meta.get('report_priority') or tier} but never "
                     f"becomes a roadmap row (roadmap accepts P1-P3)")
    if exp == refs["exposures"][0] and sev == refs["severities"][0]:
        notes.append("no current exposure, but a top-severity threat stays tracked: exposure can "
                     "appear through a new deployment, a missed asset or a vendor change")
    if notes:
        out["notes"] = notes
    return out


def score_tier(raw, refs=None):
    """{severity, exposure, rationale?, item?, trigger?} -> tier object (--model tier)."""
    refs = refs or _load_tier_refs()
    raw = {str(k).strip().lower(): v for k, v in raw.items()}
    unknown = sorted(set(raw) - {"severity", "exposure", "rationale", "item", "trigger"})
    if unknown:
        raise ValueError(f"unknown tier key(s): {', '.join(unknown)} — expected severity, "
                         f"exposure, rationale, item, trigger")
    for k in ("severity", "exposure"):
        if raw.get(k) in (None, ""):
            raise ValueError(f"the tier model needs both severity and exposure (missing {k})")
    out = {"model": "tier", **tier_cell(raw["severity"], raw["exposure"], refs)}
    why = str(raw.get("rationale") or "").strip()
    if why:
        out["rationale"] = why
    for k in ("item", "trigger"):
        if raw.get(k):
            out[k] = str(raw[k]).strip()
    out["note"] = "a tier is a response priority set by analyst judgement, never attribution"
    return out


def _step_ok(v, step):
    q = v / step
    return abs(q - round(q)) < 1e-9


def actor_band(score, refs=None):
    """Rounded Threat Score -> band name (inclusive lower bounds, highest first)."""
    refs = refs or _load_actor_refs()
    bands = sorted(((float(b["min"]), n) for n, b in refs["bands"].items()), reverse=True)
    return next((n for t, n in bands if score >= t - 1e-12), bands[-1][1])


def _actor_inputs(raw):
    """{dim: number | {rating, rationale, evidence}, dim_rationale, dim_evidence, actor, ...}
    -> (ratings, rationales, evidence, meta). Unknown keys raise: a typo must not drop a rating."""
    ratings, notes, evid, meta, unknown = {}, {}, {}, {}, []
    for k, v in raw.items():
        k = str(k).strip().lower()
        if k in _ACTOR_META:
            meta[k] = v
        elif k in ACTOR_DIMS:
            if isinstance(v, dict):
                if v.get("rating") not in (None, ""):
                    ratings[k] = v["rating"]
                if v.get("rationale"):
                    notes[k] = str(v["rationale"]).strip()
                if v.get("evidence"):
                    evid[k] = str(v["evidence"]).strip()
            else:
                ratings[k] = v
        elif k.endswith("_rationale") and k[:-10] in ACTOR_DIMS:
            notes[k[:-10]] = str(v).strip()
        elif k.endswith("_evidence") and k[:-9] in ACTOR_DIMS:
            evid[k[:-9]] = str(v).strip()
        else:
            unknown.append(k)
    if unknown:
        raise ValueError(f"unknown actor key(s): {', '.join(sorted(unknown))} — expected "
                         f"{', '.join(ACTOR_DIMS)} (+ _rationale / _evidence), "
                         f"{', '.join(_ACTOR_META)}")
    return ratings, notes, evid, meta


def _as_of(meta):
    import datetime as dt
    v = meta.get("as_of")
    if v in (None, ""):
        return dt.datetime.now(dt.timezone.utc).date()
    try:
        return dt.date.fromisoformat(str(v).strip())
    except ValueError:
        raise ValueError(f"as_of={v!r} must be YYYY-MM-DD") from None


def score_actor(raw, refs=None, tier_refs=None):
    """Analyst-rated Threat Score for ONE actor against ONE organisation.

    Raises ValueError on a missing actor name, a missing or off-step rating, a dimension without
    a rationale, intent >= evidence_required_intent without cited evidence, or a Negligible
    result without an overall `rationale`. With exposure_level, also returns the tier."""
    import re
    refs = refs or _load_actor_refs()
    st = refs["settings"]
    lo, hi = float(st.get("rating_min", 0.0)), float(st.get("rating_max", 1.0))
    step, dec = float(st.get("step", 0.25)), int(st.get("decimals", 2))
    ratings, notes, evid, meta = _actor_inputs(raw)
    actor = str(meta.get("actor") or "").strip()
    if not actor:
        raise ValueError("actor=<name> is required — scores are stored per actor")
    missing = [d for d in ACTOR_DIMS if ratings.get(d) in (None, "")]
    if missing:
        raise ValueError(f"rate all four dimensions (missing {', '.join(missing)}); an unrated "
                         f"dimension cannot be scored as 0")
    dims = {}
    for d in ACTOR_DIMS:
        try:
            v = float(ratings[d])
        except (TypeError, ValueError):
            raise ValueError(f"{d}={ratings[d]!r} is not a number") from None
        if not lo <= v <= hi or not _step_ok(v, step):
            raise ValueError(f"{d}={ratings[d]!r} must be {lo:g}-{hi:g} in steps of {step:g}")
        dims[d] = v
    no_why = [d for d in ACTOR_DIMS if not notes.get(d)]
    if no_why:
        raise ValueError(f"every rated dimension needs a rationale (missing "
                         f"{', '.join(d + '_rationale' for d in no_why)})")
    pat = re.compile(str(st.get("evidence_pattern") or _ACTOR_FALLBACK["settings"]["evidence_pattern"]))
    need = float(st.get("evidence_required_intent", 0.75))
    if dims["intent"] >= need - 1e-12:
        cited = " ".join(filter(None, (evid.get("intent"), notes.get("intent"))))
        if not pat.search(cited):
            raise ValueError(f"intent {dims['intent']:g} (>= {need:g}) must cite evidence: a URL "
                             f"or a case reference (CASE-…, cases/…) in intent_evidence or "
                             f"intent_rationale")

    ow, w = refs["opportunity_weights"], refs["weights"]
    opp = ow["sectoral_reach"] * dims["sectoral_reach"] + ow["org_exposure"] * dims["org_exposure"]
    floor = abs(dims["intent"] - float(st.get("floor_value", 0.0))) < 1e-12
    ts = 0.0 if floor else (w["intent"] * dims["intent"] + w["capability"] * dims["capability"]
                            + w["opportunity"] * opp)
    # round(…, 10) first so binary drift in the weighted sum (…4999999) cannot flip a half-up
    # rounding of the published two-decimal value.
    opp_r, ts_r = _round_half_up(round(opp, 10), dec), _round_half_up(round(ts, 10), dec)
    band = actor_band(ts_r, refs)
    b = refs["bands"][band]
    overall_why = str(meta.get("rationale") or "").strip()
    if band == "Negligible" and not overall_why:
        raise ValueError("a Negligible actor needs rationale=<why> — the stored written rationale "
                         "is the artifact a later analyst reads"
                         + (" (the Intent floor rule set this score)" if floor else ""))
    import datetime as dt
    as_of = _as_of(meta)
    days = b.get("review_cadence_days")
    rationales = {d: notes[d] for d in ACTOR_DIMS}
    if overall_why:
        rationales["overall"] = overall_why
    out = {"model": "actor", "actor": actor, "dimensions": dims, "opportunity": opp_r,
           "threat_score": ts_r, "band": band, "posture": list(b.get("posture") or []),
           "review_cadence": b.get("review_cadence") or (f"every {days} days" if days else
                                                          "out-of-cycle triggers only"),
           "review_due": (as_of + dt.timedelta(days=int(days))).isoformat() if days else None,
           "as_of": as_of.isoformat(), "floor_applied": floor, "rationales": rationales,
           "evidence": {d: e for d, e in evid.items()}, "note": ACTOR_NOTE}
    if meta.get("organisation"):
        out["organisation"] = str(meta["organisation"]).strip()
    if floor:
        out["floor_note"] = ("Intent floor rule: intent is 0, so the Threat Score is 0 whatever "
                             "the capability and opportunity ratings")
    if meta.get("exposure_level") not in (None, ""):
        trefs = tier_refs or _load_tier_refs()
        sev = refs["axis1_map"][band]
        t = tier_cell(sev, meta["exposure_level"], trefs)
        if band != sev:
            t.setdefault("notes", []).insert(
                0, f"actor band {band} has no Axis 1 row and maps to {sev}; the grid never closes "
                   f"an item, so the lowest possible result is a tracked P4")
        out["tier"] = t
    return out


def _utc_now():
    import datetime as dt
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _read_json(path):
    if not os.path.isfile(path):
        return {}
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    if not isinstance(doc, dict):
        raise ValueError(f"{path} is not a JSON object")
    return doc


def _write_json(path, doc):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


def _actor_snapshot(res):
    snap = {k: res.get(k) for k in ("dimensions", "opportunity", "threat_score", "band",
                                    "floor_applied", "as_of")}
    if res.get("tier"):
        snap["tier"] = res["tier"]["tier"]
    return snap


def write_actor_case(case, res, reason=None, refs=None):
    """Store `res` in cases/<id>/actor_scores.json keyed by actor name. A re-score appends
    {utc, old, new, reason} to that actor's `history`; a shift above drift_warn_shift with no
    reason adds a warning (to the history entry and the returned list). Returns (path, warnings)."""
    refs = refs or _load_actor_refs()
    cdir = _case_dir(case)
    if not os.path.isdir(cdir):
        raise FileNotFoundError(f"no case at {cdir}")
    path = os.path.join(cdir, "actor_scores.json")
    doc = _read_json(path)
    prev = doc.get(res["actor"])
    history = list((prev or {}).get("history") or [])
    warnings = []
    why = str(reason or "").strip() or None
    if prev:
        shift = round(res["threat_score"] - float(prev.get("threat_score") or 0.0), 10)
        limit = float(refs["settings"].get("drift_warn_shift", 0.10))
        entry = {"utc": _utc_now(), "old": _actor_snapshot(prev), "new": _actor_snapshot(res),
                 "shift": round(shift, 4), "reason": why}
        if abs(shift) > limit + 1e-9 and not why:
            w_ = (f"{res['actor']}: Threat Score moved {shift:+.2f} (more than {limit:.2f}) with no "
                  f"reason — record what changed (reason=...)")
            entry["warning"] = w_
            warnings.append(w_)
        history.append(entry)
    stored = dict(res)
    stored["history"] = history
    doc[res["actor"]] = stored
    _write_json(path, doc)
    return path, warnings


def write_tier_case(case, res, refs=None):
    """Record a tier in cases/<id>/tier_log.json keyed by `item`. Every assignment that changes
    the cell appends {utc, old, new, trigger, rationale} to the item's `log`; a re-tier (an item
    already tiered) must name a retier_triggers id and carry a rationale. Returns the path."""
    refs = refs or _load_tier_refs()
    item = str(res.get("item") or "").strip()
    if not item:
        raise ValueError("--case with --model tier needs item=<what is being tiered>")
    cdir = _case_dir(case)
    if not os.path.isdir(cdir):
        raise FileNotFoundError(f"no case at {cdir}")
    path = os.path.join(cdir, "tier_log.json")
    doc = _read_json(path)
    prev = doc.get(item)
    new = {k: res[k] for k in ("severity", "exposure", "tier")}
    old = {k: prev["current"][k] for k in ("severity", "exposure", "tier")} if prev else None
    log = list((prev or {}).get("log") or [])
    why = str(res.get("rationale") or "").strip()
    if old is None:
        log.append({"utc": _utc_now(), "old": None, "new": new,
                    "trigger": res.get("trigger") or "initial", "rationale": why or None})
    elif old != new:
        trig = str(res.get("trigger") or "").strip()
        if trig not in refs["retier_triggers"]:
            raise ValueError(f"re-tiering {item} ({old['tier']} -> {new['tier']}) needs "
                             f"trigger=<id>, one of {', '.join(refs['retier_triggers'])}")
        if not why:
            raise ValueError(f"re-tiering {item} needs rationale=<what changed>")
        log.append({"utc": _utc_now(), "old": old, "new": new, "trigger": trig, "rationale": why})
    doc[item] = {"current": {**new, "rationale": why or (prev or {}).get("current", {}).get("rationale"),
                             "deadline": res.get("deadline")},
                 "log": log}
    _write_json(path, doc)
    return path


def main():
    ap = argparse.ArgumentParser(description="Composite 0-100 subject exposure score.")
    ap.add_argument("infile", nargs="?", help="JSON file of {indicator: raw_value} "
                    "(executive: {cN: rating | {rating, rationale}, cN_rationale: text}; "
                    "organisation: {d: \"ExH\" | {exploitability, harm, rationale, issue}})")
    ap.add_argument("--model", choices=("composite", "executive", "organisation", "actor", "tier"),
                    default="composite",
                    help="composite = the weight-engine 0-100 (default, higher = more exposed); "
                         "executive = deductive 8-criteria score from 100 (higher = safer); "
                         "organisation = analyst-rated risk by domain, 0-10 (higher = riskier); "
                         "actor = analyst-rated Threat Score 0-1 for one actor; "
                         "tier = Severity Tier Matrix P1-P4 from severity x exposure")
    ap.add_argument("--set", action="append", default=[], metavar="KEY=VALUE",
                    help="set an indicator inline (repeatable); executive also takes "
                         "cN_rationale=TEXT; organisation takes d=2x3 or d_exploitability=2, "
                         "d_harm=3, d_rationale=TEXT, d_issue=TEXT; actor takes actor=, intent=, "
                         "capability=, sectoral_reach=, org_exposure= (+ <dim>_rationale, "
                         "intent_evidence), rationale=, reason=, exposure_level=, as_of=; tier "
                         "takes severity=, exposure=, rationale=, item=, trigger=")
    ap.add_argument("--ratings", metavar="JSON",
                    help="executive/organisation/actor/tier: the ratings as an inline JSON object "
                         "(same shape as infile; merged after infile, before --set)")
    ap.add_argument("--case", help="organisation: write cases/<id>/exposure_organisation.json; "
                                   "actor: update cases/<id>/actor_scores.json; tier: update "
                                   "cases/<id>/tier_log.json")
    ap.add_argument("--list", action="store_true", help="print the weight table and exit")
    ap.add_argument("--pretty", action="store_true")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()
    if a.case and a.model not in ("organisation", "actor", "tier"):
        ap.error("--case is only written by --model organisation / actor / tier")
    if a.ratings and a.model == "composite":
        ap.error("--ratings applies to --model executive / organisation / actor / tier")

    def _raw():
        raw = {}
        if a.infile:
            raw.update(json.load(open(a.infile, encoding="utf-8")))
        if a.ratings:
            try:
                extra = json.loads(a.ratings)
            except ValueError as exc:
                ap.error(f"--ratings is not valid JSON: {exc}")
            if not isinstance(extra, dict):
                ap.error("--ratings must be a JSON object")
            raw.update(extra)
        for kv in a.set:
            if "=" not in kv:
                ap.error(f"--set expects KEY=VALUE, got {kv!r}")
            k, v = kv.split("=", 1)
            raw[k.strip()] = v
        return raw

    def _emit(res):
        txt = json.dumps(res, indent=2 if a.pretty else None, ensure_ascii=False)
        if a.out:
            open(a.out, "w", encoding="utf-8").write(txt)
        print(txt)
        return 0

    if a.model == "actor":
        refs = _load_actor_refs()
        if a.list:
            st, w, ow = refs["settings"], refs["weights"], refs["opportunity_weights"]
            for k, d in refs["dimensions"].items():
                print(f"{k}  {d.get('name', k)} — {d.get('question', '')}")
                for lvl, text in (d.get("scale") or {}).items():
                    print(f"  {lvl:<5} {text}")
            print(f"\nopportunity = {ow['sectoral_reach']:g} x sectoral_reach + "
                  f"{ow['org_exposure']:g} x org_exposure; threat_score = {w['intent']:g} x intent "
                  f"+ {w['capability']:g} x capability + {w['opportunity']:g} x opportunity; "
                  f"intent = {float(st.get('floor_value', 0)):g} forces 0 (Intent floor rule); "
                  f"steps of {float(st.get('step', 0.25)):g}")
            for n, b in refs["bands"].items():
                print(f">={float(b['min']):.2f} {n} ({b.get('review_cadence', '')})")
            return 0
        try:
            raw = _raw()
            res = score_actor(raw, refs)
            warns, path = [], None
            if a.case:
                reason = next((v for k, v in raw.items() if str(k).strip().lower() == "reason"), None)
                path, warns = write_actor_case(a.case, res, reason, refs)
        except (ValueError, FileNotFoundError) as exc:
            print(json.dumps({"model": "actor", "error": str(exc)}, ensure_ascii=False))
            print(f"[!] actor score: {exc}", file=sys.stderr)
            return 2
        if warns:
            res["warnings"] = warns
        print(f"actor {res['actor']}: threat score {res['threat_score']:.2f} ({res['band']})"
              + (" — Intent floor rule applied" if res["floor_applied"] else "")
              + (f"; tier {res['tier']['tier']}" if res.get("tier") else "")
              + " — analyst judgement for one organisation, not attribution", file=sys.stderr)
        for w_ in warns:
            print(f"  [!] {w_}", file=sys.stderr)
        if path:
            print(f"  wrote {path}", file=sys.stderr)
        return _emit(res)

    if a.model == "tier":
        try:
            refs = _load_tier_refs()
        except ValueError as exc:
            print(f"[!] severity tier grid: {exc}", file=sys.stderr)
            return 2
        if a.list:
            ex = refs["exposures"]
            print(f"{'SEVERITY':<10}" + "".join(f"{e:<13}" for e in ex))
            for s in refs["severities"]:
                print(f"{s:<10}" + "".join(f"{c:<13}" for c in refs["grid"][s]))
            print()
            for t, m in refs["tiers"].items():
                print(f"{t} {m.get('name', '')}: {m.get('deadline') or 'no deadline'} — "
                      f"{m.get('meaning', '')}")
            print("\nre-tier triggers: " + ", ".join(refs["retier_triggers"]))
            return 0
        try:
            res = score_tier(_raw(), refs)
            path = write_tier_case(a.case, res, refs) if a.case else None
        except (ValueError, FileNotFoundError) as exc:
            print(json.dumps({"model": "tier", "error": str(exc)}, ensure_ascii=False))
            print(f"[!] severity tier: {exc}", file=sys.stderr)
            return 2
        print(f"tier {res['tier']} = {res['severity']} x {res['exposure']} "
              f"({res['deadline'] or 'track only'})", file=sys.stderr)
        if path:
            print(f"  wrote {path}", file=sys.stderr)
        return _emit(res)

    if a.model == "organisation":
        refs = _load_org_refs()
        if a.list:
            print(f"{'DOMAIN':<15}NAME")
            for k, d in refs["domains"].items():
                print(f"{k:<15}{d.get('name', k)}")
            for axis, levels in (refs.get("rubric") or {}).items():
                print(f"\n{axis.upper()}")
                for lvl, text in levels.items():
                    print(f"  {lvl}  {text}")
            print("\nscore = score_matrix[exploitability][harm] (0-10); overall = "
                  f"{refs['settings'].get('overall_method', 'mean of rated domains')}; bands: "
                  + ", ".join(f">={t} {b}" for t, b in refs["bands"].items())
                  + "; priorities: " + ", ".join(f"{p} {t}" for p, t in refs["priorities"].items()))
            return 0
        try:
            res = score_organisation(_raw(), refs)
            path = write_case(a.case, res) if a.case else None
        except (ValueError, FileNotFoundError) as exc:
            print(json.dumps({"model": "organisation", "error": str(exc)}, ensure_ascii=False))
            print(f"[!] organisation exposure: {exc}", file=sys.stderr)
            return 2
        cov = res["coverage"]
        print(f"organisation risk: {res['overall']['score']:g} ({res['overall']['level']}) "
              f"coverage {cov['rated']}/{cov['total']} — analyst judgement, not a probability",
              file=sys.stderr)
        if cov.get("warning"):
            print(f"  [!] {cov['warning']}", file=sys.stderr)
        if path:
            print(f"  wrote {path}", file=sys.stderr)
        txt = json.dumps(res, indent=2 if a.pretty else None, ensure_ascii=False)
        if a.out:
            open(a.out, "w", encoding="utf-8").write(txt)
        print(txt)
        return 0

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
        raw = _raw()
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
