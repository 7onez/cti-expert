#!/usr/bin/env python3
"""dork_builder.py — build document/leak-hunt search queries. Emits; never scrapes.

Backs /docleak. The command promised an "18-platform document leak hunt with severity
classification". Actually FETCHING those platforms means automated querying of Google/Bing and
scraping doc hosts: it gets the egress IP blocked within a few queries, breaks whenever a layout
changes, and on several of these platforms violates the terms the analyst is bound by. So this
builds the queries and hands them over. Running one is a human decision, taken in a browser the
analyst controls.

Severity here grades the QUERY, not a result — how damaging a hit would be if one exists. That
distinction matters: nothing below is evidence of anything until a human opens it.

Pure: no network, no keys, deterministic.
Organisation targets also receive staff-email, job, freelancer and company-social
queries. These reveal possible staff names, hiring geography and tools in job specs,
not proven employment or account ownership. Templates live in references/dork_builder.json.

Usage:
  dork_builder.py "Company A Ltd"
  dork_builder.py example.com --severity high --pretty
"""
# /// script
# requires-python = """>=3.9"""
# ///
import argparse
import json
import sys
import os
import re

WP = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..",
                                   "intel_engine", "WebPivot", "tools"))
if WP not in sys.path:
    sys.path.insert(0, WP)
from wp_refs import load_ref, ref_path

_FALLBACK = {"platforms": [], "filetypes": [], "severity_order": {
    "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3},
    "engines": [], "patterns": {"domain": r"(?!)"},
    "staff_emails": [], "jobs": [], "freelancer_profiles": [], "company_socials": []}
_REFS = load_ref(ref_path(__file__, "dork_builder.json"), _FALLBACK)
PLATFORMS = _REFS["platforms"]
FILETYPES = _REFS["filetypes"]
ORDER = _REFS["severity_order"]


def main():
    ap = argparse.ArgumentParser(description="Build document/leak-hunt queries (emit, never run).")
    ap.add_argument("target", help="company name, brand string or domain")
    ap.add_argument("--severity", choices=["critical", "high", "medium", "low"],
                    help="only queries at this severity or worse")
    ap.add_argument("--pretty", action="store_true")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()

    t = a.target.strip()
    floor = ORDER.get((a.severity or "low").upper(), 3)
    rows = []
    for host, tmpl, sev, why in PLATFORMS:
        if ORDER[sev] <= floor:
            rows.append({"kind": "platform", "host": host, "severity": sev,
                         "why_it_matters": why, "query": tmpl.format(t=t)})
    for name, tmpl, sev in FILETYPES:
        if ORDER[sev] <= floor:
            rows.append({"kind": "filetype", "family": name, "severity": sev,
                         "query": tmpl.format(t=t)})
    domain = t.lower() if re.fullmatch(_REFS["patterns"]["domain"], t) else ""
    for family in ("staff_emails", "jobs", "freelancer_profiles", "company_socials"):
        for entry in _REFS[family]:
            if entry.get("domain_only") and not domain:
                continue
            if ORDER[entry["severity"]] <= floor:
                rows.append({"kind": "organisation", "family": family,
                             "host": entry["host"], "severity": entry["severity"],
                             "why_it_matters": entry["why_it_matters"],
                             "query": entry["template"].format(t=t, domain=domain),
                             "rung": "lead",
                             "caveat": "Search query only; hits need corroboration and never establish identity or employment."})
    rows.sort(key=lambda r: ORDER[r["severity"]])

    out = {"target": t, "queries": rows, "count": len(rows),
           "severity_counts": {s: sum(1 for r in rows if r["severity"] == s) for s in ORDER},
           "engines": _REFS["engines"],
           "execution": ("NOT RUN. Automated querying of these engines gets the egress blocked "
                         "within a few requests and breaks on every layout change; several doc "
                         "hosts also forbid it. Open them in a browser you control."),
           "severity_means": ("how damaging a hit WOULD be, not how likely one is. Nothing here "
                              "is evidence until a human opens the result.")}
    print(f"{t}: {len(rows)} queries "
          f"({out['severity_counts']['CRITICAL']} critical, {out['severity_counts']['HIGH']} high)"
          f" — emitted, not run", file=sys.stderr)
    txt = json.dumps(out, indent=2 if a.pretty else None, ensure_ascii=False)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(txt)
    print(txt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
