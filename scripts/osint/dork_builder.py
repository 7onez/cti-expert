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

Usage:
  dork_builder.py "Acme Corp"
  dork_builder.py example.com --severity high --pretty
"""
# /// script
# requires-python = """>=3.9"""
# ///
import argparse
import json
import sys

# (host, template, severity, why) — severity = damage IF a hit exists, not confidence of a hit.
PLATFORMS = [
    ("scribd.com",        'site:scribd.com "{t}"',              "HIGH",   "uploaded internal docs"),
    ("slideshare.net",    'site:slideshare.net "{t}"',          "MEDIUM", "decks with internal data"),
    ("docplayer.net",     'site:docplayer.net "{t}"',           "HIGH",   "mirrors leaked PDFs"),
    ("issuu.com",         'site:issuu.com "{t}"',               "MEDIUM", "published brochures"),
    ("yumpu.com",         'site:yumpu.com "{t}"',               "MEDIUM", "mirrored publications"),
    ("pdfcoffee.com",     'site:pdfcoffee.com "{t}"',           "HIGH",   "scraped document mirror"),
    ("vdocuments",        'site:vdocuments.mx OR site:vdocuments.net "{t}"', "HIGH", "doc mirror"),
    ("studylib.net",      'site:studylib.net "{t}"',            "MEDIUM", "uploaded materials"),
    ("coursehero.com",    'site:coursehero.com "{t}"',          "LOW",    "academic uploads"),
    ("academia.edu",      'site:academia.edu "{t}"',            "LOW",    "papers, org names"),
    ("pastebin.com",      'site:pastebin.com "{t}"',            "CRITICAL", "credentials and configs"),
    ("ghostbin/rentry",   'site:rentry.co OR site:ghostbin.com "{t}"', "CRITICAL", "paste mirrors"),
    ("trello.com",        'site:trello.com "{t}"',              "HIGH",   "public boards leak process"),
    ("s3 buckets",        'site:s3.amazonaws.com "{t}"',        "CRITICAL", "open object storage"),
    ("azure blobs",       'site:blob.core.windows.net "{t}"',   "CRITICAL", "open object storage"),
    ("gitlab snippets",   'site:gitlab.com "{t}" snippets',     "HIGH",   "pasted code and secrets"),
    ("google groups",     'site:groups.google.com "{t}"',       "MEDIUM", "mailing-list archives"),
    ("archive.org",       'site:archive.org "{t}"',             "LOW",    "archived copies"),
]

FILETYPES = [
    ("credentials",  'filetype:env OR filetype:ini OR filetype:cfg "{t}"',      "CRITICAL"),
    ("databases",    'filetype:sql OR filetype:db OR filetype:sqlite "{t}"',    "CRITICAL"),
    ("backups",      'filetype:bak OR filetype:old OR filetype:backup "{t}"',   "HIGH"),
    ("spreadsheets", 'filetype:xls OR filetype:xlsx OR filetype:csv "{t}"',     "HIGH"),
    ("documents",    'filetype:pdf OR filetype:doc OR filetype:docx "{t}"',     "MEDIUM"),
    ("logs",         'filetype:log "{t}"',                                      "HIGH"),
    ("keys",         'filetype:pem OR filetype:key OR filetype:ppk "{t}"',      "CRITICAL"),
]

ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


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
    rows.sort(key=lambda r: ORDER[r["severity"]])

    out = {"target": t, "queries": rows, "count": len(rows),
           "severity_counts": {s: sum(1 for r in rows if r["severity"] == s) for s in ORDER},
           "engines": ["https://www.google.com/search?q=", "https://duckduckgo.com/?q=",
                       "https://search.marcia.dev/?q=", "https://www.bing.com/search?q="],
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
