#!/usr/bin/env python3
"""evidence_import.py — import an analyst's graded findings into a case and the KB.

    evidence_import.py import <case> <findings.json> [--kb DIR]

Input: a JSON list (or {"findings": [...]}) of graded findings:

    {"claim": "...", "source_url": "https://...", "rung": "owner|kit|neighbour",
     "rung_class": "whois.registrant_email", "admiralty": "B2",
     "indicators": [{"type": "domain", "value": "site-a.example"}],
     "selector_links": [{"from": "site-a.example", "to": "registrant@example.com",
                         "rel": "registrant_of"}]}

What it does:
  * entries missing `claim` or a valid `admiralty` grade are REJECTED, each with a message;
  * the accepted + rejected set is stored under cases/<case>/evidence/imported/<sha12>.json
    (content-addressed: re-importing the same file rewrites the same record);
  * an OWNER finding's selector_links become KB edges; everything else — every indicator, and
    the links of kit / neighbour findings — is written as facts only (RULE 5: kit and neighbour
    never become edges, never cluster, never attribute). Owner needs the analyst's rung AND a
    rung_class that rungs.json grades owner; a weaker class demotes the finding, with a note;
  * every fact/edge carries source `analyst_import` (references/evidence_import.json) and an
    evidence_ref to the stored record, so the assessment can cite it.

Analyst ownership: this tool writes ONLY under evidence/imported/ and the KB — never
assessment.md / assessment.json or any other case file.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
KB_TOOLS = os.path.join(HERE, "kb")
for _p in (HERE, KB_TOOLS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from knowledge_base import KB  # noqa: E402
from selector_types import classify, kb_key, rung_for  # noqa: E402

try:
    from kb_refs import load_ref, ref_path  # noqa: E402 — the shared RULE 3 loader
except Exception:  # noqa: BLE001 — degrade, never block
    def ref_path(module_file, name):
        return os.path.join(os.path.dirname(os.path.abspath(module_file)), "kb", "references", name)

    def load_ref(path, fallback):
        print("[evidence_import] WARNING: kb_refs unavailable; evidence_import.json not read — "
              "running on the minimal embedded fallback.", file=sys.stderr)
        return dict(fallback)

# Conservative minimum: every reliability letter maps to LOW confidence until the file is read.
_REF_FALLBACK = {
    "admiralty": {"pattern": "^[A-F][1-6]$"},
    "reliability_confidence": {k: "low" for k in "ABCDEF"},
    "provenance": {"source": "analyst_import", "collector": "evidence_import",
                   "fact_attribute": "analyst_finding", "default_rel": "analyst_link"},
}
_REF = load_ref(os.path.join(KB_TOOLS, "references", "evidence_import.json"), _REF_FALLBACK)
ADMIRALTY_RE = re.compile(str((_REF.get("admiralty") or {}).get("pattern")
                              or _REF_FALLBACK["admiralty"]["pattern"]))
RELIABILITY_CONFIDENCE = dict(_REF.get("reliability_confidence")
                              or _REF_FALLBACK["reliability_confidence"])
_PROV = dict(_REF_FALLBACK["provenance"], **(_REF.get("provenance") or {}))
SOURCE = _PROV["source"]
COLLECTOR = _PROV["collector"]
FACT_ATTRIBUTE = _PROV["fact_attribute"]
DEFAULT_REL = _PROV["default_rel"]

_RUNG_ALIASES = {"owner": "owner", "kit": "kit", "neighbour": "neighbour", "neighbor": "neighbour"}
IMPORT_SUBDIR = os.path.join("evidence", "imported")


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _case_dir(case):
    """A path is used as given; a bare case ID resolves to ROOT/cases/<id> (never the CWD)."""
    c = str(case)
    if os.path.isabs(c) or os.sep in c or (os.altsep and os.altsep in c):
        return c
    return os.path.join(ROOT, "cases", c)


def normalise_admiralty(grade):
    """'b-2' / 'B 2' -> 'B2'; '' when the grade is absent or does not match the pattern."""
    g = re.sub(r"[\s\-]", "", str(grade or "")).upper()
    return g if g and ADMIRALTY_RE.match(g) else ""


def effective_rung(rung, rung_class):
    """(rung, note). Owner only when the analyst's rung (if given) is owner AND rung_class is
    graded owner in rungs.json; anything weaker is kept as the weaker rung (RULE 5)."""
    analyst = _RUNG_ALIASES.get(str(rung or "").strip().lower())
    rc = str(rung_class or "").strip()
    cls = rung_for(rc) if rc else None
    if analyst in ("kit", "neighbour"):
        return analyst, ""
    if cls == "owner":
        return "owner", ""
    if analyst == "owner":
        if cls:
            return cls, f"rung_class {rc!r} is {cls} in rungs.json — owner rung demoted to {cls}"
        return "kit", "owner rung needs a rung_class rungs.json grades owner — stored as kit"
    if cls:
        return cls, ""
    note = f"unknown rung {rung!r} — stored as kit" if str(rung or "").strip() else ""
    return "kit", note


def _selector(raw):
    """A link endpoint / indicator -> (type, value) or None. Accepts {type, value} or a string
    (classified by selector_types.classify)."""
    if isinstance(raw, dict):
        val = str(raw.get("value") or "").strip()
        typ = str(raw.get("type") or "").strip().lower() or (classify(val) if val else "")
        return (typ, val) if val and typ else None
    val = str(raw or "").strip()
    if not val:
        return None
    if val.lower().startswith("domain:"):
        return "domain", val.split(":", 1)[1].strip()
    return classify(val), val


def _finding_id(entry):
    blob = "|".join(str(entry.get(k) or "") for k in ("claim", "source_url", "admiralty"))
    return "AI-" + hashlib.sha1(blob.encode("utf-8")).hexdigest()[:10]


def validate(entries):
    """Split raw entries into (accepted, rejected). Accepted findings are normalised copies with
    `id`, `admiralty`, `effective_rung` and `notes`; rejected rows carry `index` + `reason`."""
    accepted, rejected = [], []
    for i, raw in enumerate(entries):
        if not isinstance(raw, dict):
            rejected.append({"index": i, "reason": "entry is not a JSON object", "entry": raw})
            continue
        claim = str(raw.get("claim") or "").strip()
        if not claim:
            rejected.append({"index": i, "reason": "missing claim", "entry": raw})
            continue
        if not str(raw.get("admiralty") or "").strip():
            rejected.append({"index": i, "reason": "missing admiralty grade", "entry": raw})
            continue
        grade = normalise_admiralty(raw.get("admiralty"))
        if not grade:
            rejected.append({"index": i, "reason": f"admiralty grade {raw.get('admiralty')!r} is "
                             f"not reliability A-F + credibility 1-6 (e.g. B2)", "entry": raw})
            continue
        f = dict(raw)
        f["claim"] = claim
        f["admiralty"] = grade
        f["id"] = _finding_id(f)
        rung, note = effective_rung(raw.get("rung"), raw.get("rung_class"))
        f["effective_rung"] = rung
        notes = [note] if note else []
        if rung == "owner" and not raw.get("selector_links"):
            notes.append("owner finding carries no selector_links — no edge written")
        f["notes"] = notes
        accepted.append(f)
    return accepted, rejected


def _load_findings(path):
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    if isinstance(doc, dict) and isinstance(doc.get("findings"), list):
        return doc["findings"]
    if isinstance(doc, list):
        return doc
    raise ValueError("findings file must be a JSON list or an object with a `findings` list")


def _ingest(kb, case, findings, record_ref, when):
    """Write accepted findings to `kb`. Returns (edges, facts)."""
    edges = facts = 0
    for f in findings:
        conf = RELIABILITY_CONFIDENCE.get(f["admiralty"][0], "low")
        rung, rc = f["effective_rung"], str(f.get("rung_class") or "").strip()
        meta = {"finding_id": f["id"], "claim": f["claim"], "admiralty": f["admiralty"],
                "rung": rung, "rung_class": rc, "source_url": f.get("source_url") or "",
                "case": case}
        for ind in f.get("indicators") or []:
            sel = _selector(ind)
            if not sel:
                continue
            et, ev = kb_key(*sel)
            kb.add_fact(et, ev, FACT_ATTRIBUTE, meta, source=SOURCE, collector=COLLECTOR,
                        observed_at=when, confidence=conf, evidence_ref=record_ref)
            facts += 1
        for link in f.get("selector_links") or []:
            if not isinstance(link, dict):
                continue
            a, b = _selector(link.get("from")), _selector(link.get("to"))
            if not a or not b:
                continue
            at, av = kb_key(*a)
            bt, bv = kb_key(*b)
            rel = str(link.get("rel") or "").strip() or DEFAULT_REL
            if rung == "owner":
                # Clustering reads domain -> indicator edges (KB.shared_indicators), so a link
                # written indicator -> domain is flipped, as ingest_typed does.
                if bt == "domain" and at != "domain":
                    at, av, bt, bv = bt, bv, at, av
                kb.add_edge(at, av, rel, bt, bv, source=SOURCE, collector=COLLECTOR,
                            observed_at=when, confidence=conf, evidence_ref=record_ref,
                            attrs=dict(meta))
                edges += 1
                continue
            # kit / neighbour: a fact on the `from` entity, never an edge (RULE 5)
            attr = "neighbour" if rung == "neighbour" else "kit_sibling"
            kb.add_fact(at, av, attr, dict(meta, rel=rel, dst_entity=[bt, bv]),
                        source=SOURCE, collector=COLLECTOR, observed_at=when,
                        confidence=conf, evidence_ref=record_ref)
            kb.touch(bt, bv, when)
            facts += 1
    return edges, facts


def import_findings(case, findings_path, kb_root=None):
    """Validate, store and ingest one findings file. Returns a JSON-able summary dict; on a
    missing case or unreadable file returns {"error": ...} (never raises)."""
    cdir = _case_dir(case)
    if not os.path.isdir(cdir):
        return {"error": f"case directory not found: {cdir}"}
    try:
        with open(findings_path, "rb") as fh:
            blob = fh.read()
        entries = _load_findings(findings_path)
    except (OSError, ValueError) as exc:
        return {"error": f"cannot read findings {findings_path}: {exc}"}
    accepted, rejected = validate(entries)
    when = _utcnow()
    sha = hashlib.sha256(blob).hexdigest()
    out_dir = os.path.join(cdir, IMPORT_SUBDIR)
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{sha[:12]}.json")
    case_id = os.path.basename(os.path.normpath(cdir))
    record = {"source": SOURCE, "case": case_id, "imported_at": when,
              "source_file": os.path.basename(findings_path), "sha256": sha,
              "accepted": accepted, "rejected": rejected}
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=2, ensure_ascii=False)
    record_ref = "/".join(("cases", case_id, "evidence", "imported", os.path.basename(out_path)))
    kb = KB(kb_root or os.path.join(ROOT, "knowledge"))
    edges, facts = _ingest(kb, case_id, accepted, record_ref, when)
    return {"case": case_id, "stored": out_path, "source": SOURCE,
            "accepted": len(accepted), "rejected": len(rejected),
            "edges": edges, "facts": facts,
            "rejections": [f"entry {r['index']}: {r['reason']}" for r in rejected],
            "notes": [f"{f['id']}: {n}" for f in accepted for n in f["notes"]]}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Import graded analyst findings into a case + KB.")
    ap.add_argument("--kb", default=None, help="KB root (default: <engine>/knowledge)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("import", help="import <case> <findings.json>")
    p.add_argument("case")
    p.add_argument("findings")
    p.add_argument("--kb", dest="kb_sub", default=None, help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    kb_root = a.kb_sub or a.kb
    if kb_root and not os.path.isabs(kb_root):
        kb_root = os.path.join(ROOT, kb_root)
    res = import_findings(a.case, a.findings, kb_root=kb_root)
    print(json.dumps(res, indent=2, ensure_ascii=False))
    return 1 if res.get("error") else 0


if __name__ == "__main__":
    raise SystemExit(main())
