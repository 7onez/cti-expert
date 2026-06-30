#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# dependencies = []
# ///
"""
generate-cti-html.py — CTI Expert interactive HTML report generator.

Injects a case JSON file into cti-report-template.html, producing a single,
fully self-contained, OFFLINE HTML report (no CDN, no external assets, no network
calls). All charts, the 2D entity graph, the timeline and the comprehensive
indicator/selector extraction run client-side in vanilla JS inside the template.

Usage:
    uv run generate-cti-html.py <case.json> <out.html> [template.html]
    python3 generate-cti-html.py <case.json> <out.html> [template.html]

The case JSON uses the same flat "report JSON" shape consumed by the DOCX
generator (see scripts/sample-cti-report-data.json and SKILL.md §8).

Author: Hieu Ngo - chongluadao.vn
"""
import sys
import os
import json

# --- self-heal: force UTF-8 stdio so emoji / non-ASCII never crash on Windows ---
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass

PLACEHOLDER = "__CTI_CASE_DATA__"


def embed(data):
    """JSON-encode and make it safe to drop inside a <script> element."""
    payload = json.dumps(data, ensure_ascii=False)
    # '<'  -> <  neutralises any </script> or <!-- inside string values.
    # U+2028 / U+2029 are JS line terminators and are escaped defensively.
    payload = payload.replace("<", "\\u003c")
    payload = payload.replace(chr(0x2028), "\\u2028")
    payload = payload.replace(chr(0x2029), "\\u2029")
    return payload


def main(argv):
    if len(argv) < 2:
        print("usage: generate-cti-html.py <case.json> <out.html> [template.html]")
        return 2
    case_path, out_path = argv[0], argv[1]
    here = os.path.dirname(os.path.abspath(__file__))
    tpl_path = argv[2] if len(argv) > 2 else os.path.join(here, "cti-report-template.html")

    try:
        with open(tpl_path, encoding="utf-8") as f:
            tpl = f.read()
    except OSError as e:
        print("error: cannot read template %r: %s" % (tpl_path, e))
        return 1
    try:
        with open(case_path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        print("error: cannot read/parse case JSON %r: %s" % (case_path, e))
        return 1

    if PLACEHOLDER not in tpl:
        print("error: placeholder %s not found in template" % PLACEHOLDER)
        return 1

    html = tpl.replace(PLACEHOLDER, embed(data))

    out_dir = os.path.dirname(os.path.abspath(out_path))
    if out_dir and not os.path.isdir(out_dir):
        os.makedirs(out_dir, exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(html)

    case = data.get("case", {}) if isinstance(data, dict) else {}
    print("HTML report written: %s (%d KB)" % (out_path, len(html.encode("utf-8")) // 1024))
    print("  case: %s  |  subjects: %d  findings: %d  connections: %d" % (
        case.get("label") or case.get("id") or "?",
        len(data.get("subjects", []) or []),
        len(data.get("findings", []) or []),
        len(data.get("connections", []) or []),
    ))
    print("  open in any browser - fully offline, no external dependencies.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
