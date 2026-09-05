#!/usr/bin/env python3
"""signature_scan.py — surface recurring behavioural signatures from analysis/signature-catalog.md.

Backs /signatures. The catalogue defines four families (TEMPORAL, BEHAVIORAL, NETWORK,
LINGUISTIC) with thresholds — e.g. posting-interval variance <=3 min reads as automation. Until now
those thresholds lived only in prose, so the interpretation depended on whoever had read the file
most recently.

This parses the catalogue and evaluates the observations you supply against it. It DOES NOT
COLLECT: it has no way to observe posting cadence, and inventing one would be worse than useless.
Feed it what you already measured; it tells you which signature fires and what the catalogue says
that means.

Pure: reads the local catalogue. No network.

Usage:
  signature_scan.py --list
  signature_scan.py --set posting_interval_variance_min=2
  signature_scan.py observations.json --pretty
"""
# /// script
# requires-python = ">=3.9"
# ///
import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
CATALOG = os.path.join(REPO, "analysis", "signature-catalog.md")

# Observation key -> (signature id, family, evaluator, meaning). Thresholds mirror the catalogue;
# the catalogue text is quoted back so the two cannot silently diverge in interpretation.
RULES = [
    ("posting_interval_variance_min", "T-01", "TEMPORAL",
     lambda v: ("HIGH automation probability" if v <= 3 else
                "possible scheduler" if v <= 15 else "likely manual"),
     "variance in minutes between consecutive posts"),
    ("off_timezone_ratio", "T-02", "TEMPORAL",
     lambda v: ("activity clusters OUTSIDE the claimed timezone — the stated location is "
                "doubtful" if v >= 0.6 else "consistent with the claimed timezone"),
     "share of activity outside the subject's claimed working hours (0-1)"),
    ("accounts_posting_within_60s", "T-03", "TEMPORAL",
     lambda v: ("coordinated multi-account activity" if v >= 3 else
                "no coordination signal at this threshold"),
     "how many distinct accounts post the same content within 60s"),
    ("dormancy_days_before_burst", "T-04", "TEMPORAL",
     lambda v: ("dormancy-burst cycle — consistent with a held or resold account" if v >= 90
                else "no dormancy signal"),
     "days idle immediately before a burst of activity"),
    ("handle_leet_substitutions", "B-01", "BEHAVIORAL",
     lambda v: ("handle obfuscation — enumerate the variant space when pivoting" if v >= 1
                else "no substitution pattern"),
     "count of leet/homoglyph substitutions in the handle"),
    ("platforms_present", "B-02", "BEHAVIORAL",
     lambda v: ("broad platform footprint — a persona maintained deliberately" if v >= 5 else
                "narrow footprint — consistent with a single-purpose or disposable account"),
     "number of platforms the handle resolves on"),
    ("follower_to_following_ratio", "N-01", "NETWORK",
     lambda v: ("inorganic follower graph — bought or farmed" if v <= 0.1 else
                "unremarkable follower structure"),
     "followers divided by following"),
    ("shared_phrase_accounts", "N-02", "NETWORK",
     lambda v: ("coordinated messaging — the same phrasing across accounts" if v >= 3 else
                "no coordination signal"),
     "accounts sharing a distinctive phrase verbatim"),
]


def catalog_families():
    if not os.path.isfile(CATALOG):
        return {"status": f"catalogue not found at {CATALOG}"}
    txt = open(CATALOG, encoding="utf-8").read()
    fams = re.findall(r"^## ([A-Z_]+_SIGNATURES)$", txt, re.M)
    ids = re.findall(r"^### ([A-Z]-\d+): (.+)$", txt, re.M)
    return {"status": "ok", "families": fams,
            "signatures": [{"id": i, "title": t.strip()} for i, t in ids],
            "path": os.path.relpath(CATALOG, REPO)}


def main():
    ap = argparse.ArgumentParser(description="Evaluate observations against the signature catalogue.")
    ap.add_argument("infile", nargs="?", help="JSON of {observation: value}")
    ap.add_argument("--set", action="append", default=[], metavar="KEY=VALUE")
    ap.add_argument("--list", action="store_true", help="show the catalogue and the inputs it takes")
    ap.add_argument("--pretty", action="store_true")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()

    if a.list:
        cat = catalog_families()
        print(json.dumps({"catalog": cat,
                          "accepted_observations": [
                              {"key": k, "signature": sid, "family": fam, "means": desc}
                              for k, sid, fam, _, desc in RULES]},
                         indent=2, ensure_ascii=False))
        return 0

    obs = {}
    if a.infile:
        obs.update(json.load(open(a.infile, encoding="utf-8")))
    for kv in a.set:
        if "=" not in kv:
            ap.error(f"--set expects KEY=VALUE, got {kv!r}")
        k, v = kv.split("=", 1)
        try:
            obs[k.strip()] = float(v)
        except ValueError:
            ap.error(f"--set value must be numeric: {kv!r}")

    known = {k for k, *_ in RULES}
    fired, quiet = [], []
    for key, sid, fam, ev, desc in RULES:
        if key not in obs:
            continue
        verdict = ev(obs[key])
        row = {"signature": sid, "family": fam, "observation": key,
               "value": obs[key], "interpretation": verdict}
        (fired if verdict.lower().startswith(("high", "coordinated", "inorganic", "dormancy",
                                              "handle obfuscation", "activity clusters",
                                              "broad", "possible")) else quiet).append(row)

    out = {"catalog": catalog_families(), "fired": fired, "quiet": quiet,
           "evaluated": len(fired) + len(quiet),
           "ignored_unknown": sorted(set(obs) - known),
           "not_collected": ("This tool does NOT observe behaviour — it has no way to measure "
                             "posting cadence or follower graphs, and guessing them would be "
                             "worse than useless. Supply observations you actually measured."),
           "caveat": ("A fired signature is a HYPOTHESIS about behaviour, not an identification. "
                      "Automation, coordination and a bought follower graph are all consistent "
                      "with ordinary marketing as well as with fraud.")}
    if not out["evaluated"]:
        out["verdict"] = "no recognised observations supplied — nothing evaluated"
    else:
        out["verdict"] = f"{len(fired)} signature(s) fired of {out['evaluated']} evaluated"
    print(f"signatures: {len(fired)} fired / {out['evaluated']} evaluated", file=sys.stderr)
    for f in fired:
        print(f"  {f['signature']} [{f['family']}] {f['observation']}={f['value']} → "
              f"{f['interpretation']}", file=sys.stderr)
    txt = json.dumps(out, indent=2 if a.pretty else None, ensure_ascii=False)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(txt)
    print(txt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
