#!/usr/bin/env python3
"""Regression test for intel_engine/tools/evidence_import.py — analyst findings import.

Rails defended (synthetic data only, temp case + temp KB):
  * an owner-rung finding (owner rung + owner rung_class) becomes a KB edge, source analyst_import;
  * a kit-rung finding becomes facts only — no edge (RULE 5);
  * an owner rung on a kit rung_class is demoted, never an edge;
  * entries missing claim / admiralty (or with a malformed grade) are rejected with a message;
  * the import is stored under evidence/imported/ and assessment.md is byte-identical after.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.dirname(HERE)
for p in (TOOLS, os.path.join(TOOLS, "kb")):
    if p not in sys.path:
        sys.path.insert(0, p)

import evidence_import as EI  # noqa: E402
from knowledge_base import KB  # noqa: E402

_ASSESSMENT = "# Assessment\n\nAnalyst-authored BLUF — must never be touched.\n"

_FINDINGS = [
    {"claim": "site-a.example is registered to registrant@example.com",
     "source_url": "https://whois.example/site-a.example", "rung": "owner",
     "rung_class": "whois.registrant_email", "admiralty": "B2",
     "indicators": [{"type": "domain", "value": "site-a.example"},
                    {"type": "email", "value": "registrant@example.com"}],
     "selector_links": [{"from": "registrant@example.com", "to": "site-a.example",
                         "rel": "registrant_of"}]},
    {"claim": "site-b.example serves the same template title",
     "source_url": "https://archive.example/site-b.example", "rung": "kit",
     "rung_class": "title", "admiralty": "c3",
     "indicators": [{"type": "domain", "value": "site-b.example"}],
     "selector_links": [{"from": "site-b.example", "to": {"type": "title", "value": "Example Kit"},
                         "rel": "shares_title"}]},
    {"claim": "site-c.example lists a contact address on the page",
     "source_url": "https://site-c.example/contact", "rung": "owner",
     "rung_class": "page.email", "admiralty": "B-2",
     "selector_links": [{"from": "site-c.example", "to": "operator@example.com"}]},
    {"source_url": "https://site-d.example/", "rung": "owner", "admiralty": "A1",
     "rung_class": "whois.registrant_email",
     "selector_links": [{"from": "site-d.example", "to": "operator@example.com"}]},
    {"claim": "site-e.example ungraded claim", "rung": "owner",
     "rung_class": "whois.registrant_email",
     "selector_links": [{"from": "site-e.example", "to": "operator@example.com"}]},
    {"claim": "site-f.example badly graded", "admiralty": "Z9"},
]


def check():
    out, passed, failed = [], 0, 0

    def ok(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1
            out.append(("ok", label))
        else:
            failed += 1
            out.append(("FAIL", label))

    with tempfile.TemporaryDirectory() as td:
        cdir = os.path.join(td, "cases", "CASE-0001")
        os.makedirs(cdir)
        apath = os.path.join(cdir, "assessment.md")
        with open(apath, "w", encoding="utf-8") as fh:
            fh.write(_ASSESSMENT)
        before = os.stat(apath).st_mtime_ns
        fpath = os.path.join(td, "findings.json")
        with open(fpath, "w", encoding="utf-8") as fh:
            json.dump(_FINDINGS, fh)
        kb_root = os.path.join(td, "knowledge")

        with contextlib.redirect_stdout(io.StringIO()) as buf:
            rc = EI.main(["import", cdir, fpath, "--kb", kb_root])
        res = json.loads(buf.getvalue())
        ok(rc == 0 and "error" not in res, f"CLI import exits 0 ({res.get('error')})")
        ok(res.get("accepted") == 3 and res.get("rejected") == 3,
           f"3 accepted / 3 rejected (got {res.get('accepted')}/{res.get('rejected')})")
        rej = " | ".join(res.get("rejections") or [])
        ok("entry 3: missing claim" in rej, "an entry with no claim is rejected with a message")
        ok("entry 4: missing admiralty grade" in rej,
           "an entry with no admiralty grade is rejected with a message")
        ok("entry 5: admiralty grade 'Z9'" in rej, "a malformed admiralty grade is rejected")

        kb = KB(kb_root)
        edges = kb.edges()
        ok(len(edges) == 1, f"exactly one KB edge written (got {len(edges)})")
        e = edges[0] if edges else {}
        ok(e.get("src_type") == "domain" and e.get("src") == "site-a.example"
           and e.get("dst_type") == "email" and e.get("dst") == "registrant@example.com"
           and e.get("rel") == "registrant_of",
           "owner finding -> domain->email registrant_of edge (flipped to the clustering direction)")
        ok(e.get("source") == "analyst_import" and e.get("admiralty") == "B2"
           and str(e.get("evidence_ref") or "").startswith("cases/CASE-0001/evidence/imported/"),
           "owner edge tagged analyst_import with admiralty + evidence_ref to the stored import")
        ok(not any(x.get("src") in ("site-b.example", "site-c.example")
                   or x.get("dst") in ("site-b.example", "site-c.example") for x in edges),
           "kit and demoted findings never become edges (RULE 5)")

        b_facts = kb.entity("domain", "site-b.example")["facts"]
        ok(any(f["attribute"] == "kit_sibling" and f["source"] == "analyst_import"
               and f["value"].get("dst_entity") == ["indicator", "title:Example Kit"] for f in b_facts),
           "kit finding's selector_link stored as a kit_sibling fact")
        ok(any(f["attribute"] == "analyst_finding" and f["value"].get("admiralty") == "C3"
               for f in b_facts), "kit finding's indicator stored as an analyst_finding fact")
        c_facts = kb.entity("domain", "site-c.example")["facts"]
        ok(any(f["attribute"] == "kit_sibling" and f["value"].get("rung") == "kit" for f in c_facts),
           "owner rung on a kit rung_class (page.email) demoted to a kit fact")
        ok(any("demoted" in n for n in res.get("notes") or []), "the demotion is reported as a note")
        a_facts = kb.entity("email", "registrant@example.com")["facts"]
        ok(any(f["attribute"] == "analyst_finding" and f["confidence"] == 0.9 for f in a_facts),
           "owner finding's indicators are facts too, confidence from reliability B (high)")

        stored = res.get("stored") or ""
        ok(os.path.dirname(stored) == os.path.join(cdir, "evidence", "imported")
           and os.path.isfile(stored), "import stored under cases/<case>/evidence/imported/")
        rec = json.load(open(stored, encoding="utf-8")) if os.path.isfile(stored) else {}
        ok(len(rec.get("accepted") or []) == 3 and len(rec.get("rejected") or []) == 3
           and rec.get("source") == "analyst_import", "stored record keeps accepted + rejected")

        with open(apath, encoding="utf-8") as fh:
            ok(fh.read() == _ASSESSMENT and os.stat(apath).st_mtime_ns == before,
               "assessment.md is untouched")
        ok(sorted(os.listdir(cdir)) == ["assessment.md", "evidence"],
           "nothing written in the case outside evidence/")

        # Re-import is idempotent: same record file, no duplicate edge.
        with contextlib.redirect_stdout(io.StringIO()):
            EI.main(["import", cdir, fpath, "--kb", kb_root])
        ok(len(KB(kb_root).edges()) == 1
           and len(os.listdir(os.path.join(cdir, "evidence", "imported"))) == 1,
           "re-importing the same file rewrites one record and adds no edge")

        missing = EI.import_findings(os.path.join(td, "cases", "CASE-0002"), fpath, kb_root=kb_root)
        ok("error" in missing and not os.path.exists(os.path.join(td, "cases", "CASE-0002")),
           "a missing case is an error and is never created")

    return passed, failed, out


if __name__ == "__main__":
    p, f, lines = check()
    for status, label in lines:
        print(f"{'  ok  ' if status == 'ok' else '  FAIL'} {label}")
    print(f"\n{p} passed, {f} failed")
    raise SystemExit(bool(f))
