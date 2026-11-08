#!/usr/bin/env python3
"""evidence_import.py — import an analyst's graded findings into a case and the KB.

    evidence_import.py import <case> <findings.json> [--kb DIR]

Input: a JSON list (or {"findings": [...], "report": {...}}) of graded findings:

    {"claim": "...", "source_url": "https://...", "rung": "owner|kit|neighbour",
     "rung_class": "whois.registrant_email", "admiralty": "B2",
     "indicators": [{"type": "domain", "value": "site-a.example"}],
     "selector_links": [{"from": "site-a.example", "to": "registrant@example.com",
                         "rel": "registrant_of"}],
     "attributes": [{"entity": "site-a.example", "attribute": "whois_registrar",
                     "value": "Registrar B", "valid_from": "2026-03-01"}],
     "confirmation": "strong_indirect", "not_proven": "who controls the mailbox"}

Optional `report` block (schema: references/evidence_import.json `report_sections`): lists of
key_questions (KQ-nn), open_questions (OQ-nn), roles, scenarios (SC-nn), roadmap (P1-P3),
incident_timeline (Tnnn, ISO-8601 `when`), attack_mapping (MAP-nn, technique_id T1234[.567]),
counting_rules and metrics ({metric, value number, unit, values[] as-is, status, components[]} —
the anti-inflation validator's input; `values` may hold secrets and is never printed or ingested),
subject_profile ({entity default "subject", field, value, basis, source, admiralty?, status};
basis + source REQUIRED on alias / relative rows), client_seeds ({type, value, note?, sensitive})
and `engagement` — ONE object, not a list ({author, version, created, modified, hours, client?}).
The summary's `report_lint` carries report_sections.lint() QA warnings (warn only, never blocks).
Each malformed row is rejected with a message, the rest are stored in the same
imported record and read back by tools/report_sections.py for the house report. Report rows —
roles included — NEVER touch the KB (RULE 5: a role is analyst judgement for the report only).

What it does:
  * entries missing `claim` or a valid `admiralty` grade are REJECTED, each with a message;
  * the accepted + rejected set is stored under cases/<case>/evidence/imported/<sha12>.json
    (content-addressed: re-importing the same file rewrites the same record);
  * an OWNER finding's selector_links become KB edges; everything else — every indicator, and
    the links of kit / neighbour findings — is written as facts only (RULE 5: kit and neighbour
    never become edges, never cluster, never attribute). Owner needs the analyst's rung AND a
    rung_class that rungs.json grades owner; a weaker class demotes the finding, with a note;
  * every fact/edge carries source `analyst_import` (references/evidence_import.json) and an
    evidence_ref to the stored record, so the assessment can cite it;
  * optional `attributes` rows set a KB attribute at the ANALYST authority tier (above registry,
    vendor and extractor data) whatever the grade — the grade only sets confidence. A single-
    valued attribute (kb_memory.json) is reconciled by the KB's rule: the analyst value replaces
    the standing one only when its effective date is also on or after it; dated earlier, it is
    stored DISPUTED beside it (rank alone never wins). An analyst re-importing a value for the
    same slot updates its own earlier claim (a correction when dated earlier). Any other
    attribute is a plain analyst fact. Without valid_from the effective date is the import day.
    A row with an unreadable entity, an empty value, a malformed or reserved attribute name, or an
    unparseable date is skipped with a note; the rest of the finding still imports. The summary
    lists each row's outcome (create / extend / supersede / dispute / skip);
  * optional finding `confirmation` (references `finding_fields`) and `not_proven` are stored
    with the finding for the report only; an unknown confirmation is dropped with a note.

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

from knowledge_base import KB, valid_day  # noqa: E402
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
    "attribute_rows": {"name_pattern": "^[a-z][a-z0-9_]{0,63}$",
                       "reserved": ["analyst_finding", "kit_sibling", "neighbour", "mention",
                                    "kind"]},
    "finding_fields": {"confirmation": ["confirmed", "strong_indirect", "attempted_unproven",
                                        "unverified"]},
    # No schema until the file is read: every report row is rejected (never stored unchecked).
    "report_sections": {},
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
_ROWS = dict(_REF_FALLBACK["attribute_rows"], **(_REF.get("attribute_rows") or {}))
ATTRIBUTE_NAME_RE = re.compile(str(_ROWS["name_pattern"]))
RESERVED_ATTRIBUTES = frozenset(_ROWS["reserved"])
CONFIRMATION_LEVELS = tuple(str(x).lower() for x in
                            ((_REF.get("finding_fields") or {}).get("confirmation")
                             or _REF_FALLBACK["finding_fields"]["confirmation"]))
REPORT_SCHEMA = {k: v for k, v in (_REF.get("report_sections") or {}).items()
                 if isinstance(v, dict)}

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
        f["attributes"], row_notes = _attribute_rows(raw.get("attributes"))
        notes += row_notes
        notes += _boundary_fields(f)
        f["notes"] = notes
        accepted.append(f)
    return accepted, rejected


def _attribute_rows(rows):
    """Valid `attributes` rows (normalised) + a note per skipped row. Never rejects the finding."""
    if rows is None:
        return [], []
    if not isinstance(rows, list):
        return [], ["`attributes` is not a list — ignored"]
    good, notes = [], []
    for j, row in enumerate(rows):
        if not isinstance(row, dict):
            notes.append(f"attributes[{j}] is not an object — skipped")
            continue
        sel = _selector(row.get("entity"))
        attr = str(row.get("attribute") or "").strip()
        val = row.get("value")
        if not sel or not sel[0]:
            notes.append(f"attributes[{j}]: entity {row.get('entity')!r} unreadable — skipped")
        elif not ATTRIBUTE_NAME_RE.match(attr):
            notes.append(f"attributes[{j}]: attribute {attr!r} is not a valid name — skipped")
        elif attr in RESERVED_ATTRIBUTES:
            notes.append(f"attributes[{j}]: {attr!r} is reserved (importer / RULE 5 links) — "
                         f"skipped")
        elif val is None or (isinstance(val, (str, list, dict)) and not val):
            notes.append(f"attributes[{j}]: empty value — skipped")
        elif any(row.get(k) not in (None, "") and not valid_day(row.get(k))
                 for k in ("valid_from", "valid_until")):
            notes.append(f"attributes[{j}]: valid_from/valid_until is not a date — skipped")
        else:
            good.append({"entity": {"type": sel[0], "value": sel[1]}, "attribute": attr,
                         "value": val.strip() if isinstance(val, str) else val,
                         "valid_from": valid_day(row.get("valid_from")),
                         "valid_until": valid_day(row.get("valid_until"))})
    return good, notes


def _boundary_fields(f):
    """Normalise the optional report-only `confirmation` / `not_proven` on finding `f` in place.
    A bad value is dropped with a note — never rejects the finding, never reaches the KB."""
    notes = []
    conf = f.pop("confirmation", None)
    if conf not in (None, ""):
        level = re.sub(r"[\s\-]+", "_", str(conf).strip().lower())
        if level in CONFIRMATION_LEVELS:
            f["confirmation"] = level
        else:
            notes.append(f"confirmation {conf!r} is not one of {', '.join(CONFIRMATION_LEVELS)} — "
                         f"dropped")
    np_ = f.pop("not_proven", None)
    if np_ not in (None, ""):
        if isinstance(np_, str) and np_.strip():
            f["not_proven"] = np_.strip()
        else:
            notes.append("not_proven is not a non-empty string — dropped")
    return notes


def _iso_ok(v) -> bool:
    """ISO-8601 date (YYYY-MM-DD) or date-time (`Z` accepted)."""
    s = str(v or "").strip()
    if not re.match(r"^\d{4}-\d{2}-\d{2}", s):
        return False
    try:
        if len(s) == 10:
            datetime.date.fromisoformat(s)
        else:
            datetime.datetime.fromisoformat(s[:-1] + "+00:00" if s.endswith(("Z", "z")) else s)
        return True
    except ValueError:
        return False


def _report_row(spec, raw):
    """One report row -> (normalised row, None) or (None, reason). Spec keys: required, enums,
    patterns, dates, lists (strings), numbers, raw_lists (scalars kept as-is), objects (a list of
    sub-rows validated with their own spec)."""
    if not isinstance(raw, dict):
        return None, "row is not a JSON object"
    row = {}
    lists = set(spec.get("lists") or [])
    raw_lists = set(spec.get("raw_lists") or [])
    objects = spec.get("objects") or {}
    for k, v in raw.items():
        if k in lists:
            if isinstance(v, str):
                v = [v] if v.strip() else []
            if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
                return None, f"`{k}` must be a list of strings"
            row[k] = [x.strip() for x in v if x.strip()]
        elif k in raw_lists:
            if not isinstance(v, list) or not all(isinstance(x, (str, int, float)) and not isinstance(x, bool)
                                                  for x in v):
                return None, f"`{k}` must be a list of strings / numbers"
            row[k] = list(v)                       # as-is: the duplicate check needs the raw items
        elif k in objects:
            if not isinstance(v, list):
                return None, f"`{k}` must be a list of objects"
            subs = []
            for j, sub in enumerate(v):
                s, why = _report_row(objects[k], sub)
                if s is None:
                    return None, f"`{k}[{j}]`: {why}"
                subs.append(s)
            row[k] = subs
        elif isinstance(v, str):
            row[k] = v.strip()
        elif v is None or isinstance(v, (int, float, bool)):
            row[k] = v
        else:
            return None, f"`{k}` must be a string"
    for k, v in (spec.get("defaults") or {}).items():
        if row.get(k) in (None, ""):
            row[k] = v
    for k in spec.get("numbers") or []:
        v = row.get(k)
        if v is not None and (isinstance(v, bool) or not isinstance(v, (int, float)) or v != v):
            return None, f"`{k}` {v!r} is not a number"
    for k in spec.get("booleans") or []:
        if row.get(k) is not None and not isinstance(row[k], bool):
            return None, f"`{k}` {row[k]!r} is not true / false"
    for k in spec.get("required") or []:
        if row.get(k) in (None, "", []):
            return None, f"missing required `{k}`"
    # conditional requirements: {"field": {"alias": ["basis", "source"]}} — keyed on the RAW value,
    # matched the way enums are (case-insensitive, spaces/hyphens as underscores)
    for k, by_val in (spec.get("required_when") or {}).items():
        val = re.sub(r"[\s\-]+", "_", str(row.get(k) or "").strip().lower())
        for need in (by_val or {}).get(val) or []:
            if row.get(need) in (None, "", []):
                return None, f"missing required `{need}` (required when {k} = {val})"
    for k, allowed in (spec.get("enums") or {}).items():
        if row.get(k) in (None, ""):
            continue
        val = str(row[k]).strip()
        allowed = [str(a) for a in allowed]
        hit = next((a for a in allowed if a.lower() == re.sub(r"[\s\-]+", "_", val.lower())), None)
        if hit is None:
            return None, f"`{k}` {val!r} is not one of {', '.join(allowed)}"
        row[k] = hit
    for k, pat in (spec.get("patterns") or {}).items():
        if row.get(k) in (None, ""):
            continue
        if k == "admiralty":
            row[k] = normalise_admiralty(row[k]) or str(row[k])
        if not re.match(pat, str(row[k])):
            return None, f"`{k}` {row[k]!r} does not match {pat}"
    for k in spec.get("dates") or []:
        if row.get(k) not in (None, "") and not _iso_ok(row[k]):
            return None, f"`{k}` {row[k]!r} is not an ISO-8601 date / date-time"
    return row, None


def validate_report(report):
    """Split a `report` block into (accepted {section: [rows]}, rejected [{section, index, reason}]).
    Schema: references/evidence_import.json `report_sections`. RULE 5: rows are report data only."""
    if report is None:
        return {}, []
    if not isinstance(report, dict):
        return {}, [{"section": "report", "index": None, "reason": "`report` is not a JSON object"}]
    accepted, rejected = {}, []
    for section, rows in report.items():
        if str(section).startswith("_"):
            continue
        spec = REPORT_SCHEMA.get(section)
        if spec is None:
            rejected.append({"section": section, "index": None,
                             "reason": f"unknown report section (known: {', '.join(REPORT_SCHEMA) or 'none — schema not loaded'})"})
            continue
        if spec.get("kind") == "object":           # one object, not a list of rows (engagement)
            row, why = _report_row(spec, rows)
            if row is None:
                rejected.append({"section": section, "index": None, "reason": why, "entry": rows})
            else:
                accepted[section] = row
            continue
        if not isinstance(rows, list):
            rejected.append({"section": section, "index": None, "reason": "section is not a list"})
            continue
        good, seen = [], set()
        for i, raw in enumerate(rows):
            row, why = _report_row(spec, raw)
            if row is not None and row.get("id"):
                if row["id"] in seen:
                    row, why = None, f"duplicate id {row['id']} in this import"
                else:
                    seen.add(row["id"])
            if row is None:
                rejected.append({"section": section, "index": i, "reason": why, "entry": raw})
            else:
                good.append(row)
        if good:
            accepted[section] = good
    return accepted, rejected


def _load_findings(path):
    """(findings list, report block or None)."""
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    if isinstance(doc, dict) and (isinstance(doc.get("findings"), list) or "report" in doc):
        findings = doc.get("findings")
        if findings is not None and not isinstance(findings, list):
            raise ValueError("`findings` must be a JSON list")
        return findings or [], doc.get("report")
    if isinstance(doc, list):
        return doc, None
    raise ValueError("findings file must be a JSON list or an object with a `findings` list "
                     "and/or a `report` block")


def _ingest(kb, case, findings, record_ref, when):
    """Write accepted findings to `kb`. Returns (edges, facts, attribute_results)."""
    edges = facts = 0
    results = []
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
        for row in f.get("attributes") or []:
            et, ev = kb_key(row["entity"]["type"], row["entity"]["value"])
            outcome = kb.add_fact(et, ev, row["attribute"], row["value"], source=SOURCE,
                                  collector=COLLECTOR, observed_at=when, confidence=conf,
                                  evidence_ref=record_ref, valid_from=row["valid_from"],
                                  valid_until=row["valid_until"])
            results.append({"finding_id": f["id"], "entity": f"{et}:{ev}",
                            "attribute": row["attribute"], "value": row["value"],
                            "outcome": outcome})
    return edges, facts, results


def _lint(report, findings):
    """report_sections.lint over THIS import's accepted rows — warnings only, never blocks."""
    try:
        import report_sections  # noqa: E402 — sibling module; lazy so a broken reader never blocks import
        return report_sections.lint(report, findings)
    except Exception as exc:  # noqa: BLE001
        return [f"lint not run: {exc}"]


def import_findings(case, findings_path, kb_root=None):
    """Validate, store and ingest one findings file. Returns a JSON-able summary dict; on a
    missing case or unreadable file returns {"error": ...} (never raises)."""
    cdir = _case_dir(case)
    if not os.path.isdir(cdir):
        return {"error": f"case directory not found: {cdir}"}
    try:
        with open(findings_path, "rb") as fh:
            blob = fh.read()
        entries, report_raw = _load_findings(findings_path)
    except (OSError, ValueError) as exc:
        return {"error": f"cannot read findings {findings_path}: {exc}"}
    accepted, rejected = validate(entries)
    report, report_rejected = validate_report(report_raw)
    when = _utcnow()
    sha = hashlib.sha256(blob).hexdigest()
    out_dir = os.path.join(cdir, IMPORT_SUBDIR)
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{sha[:12]}.json")
    case_id = os.path.basename(os.path.normpath(cdir))
    record = {"source": SOURCE, "case": case_id, "imported_at": when,
              "source_file": os.path.basename(findings_path), "sha256": sha,
              "accepted": accepted, "rejected": rejected,
              "report": report, "report_rejected": report_rejected}
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=2, ensure_ascii=False)
    record_ref = "/".join(("cases", case_id, "evidence", "imported", os.path.basename(out_path)))
    kb = KB(kb_root or os.path.join(ROOT, "knowledge"), case=case_id)
    edges, facts, attr_results = _ingest(kb, case_id, accepted, record_ref, when)
    # report rows (roles included) are never ingested — analyst judgement for the report (RULE 5)
    return {"case": case_id, "stored": out_path, "source": SOURCE,
            "accepted": len(accepted), "rejected": len(rejected),
            "edges": edges, "facts": facts, "attributes": attr_results,
            "report": {s: (len(rows) if isinstance(rows, list) else 1) for s, rows in report.items()},
            "report_rejected": len(report_rejected),
            "report_lint": _lint(report, accepted),
            "rejections": [f"entry {r['index']}: {r['reason']}" for r in rejected]
            + [f"report.{r['section']}" + (f"[{r['index']}]" if r["index"] is not None else "")
               + f": {r['reason']}" for r in report_rejected],
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
