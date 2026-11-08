#!/usr/bin/env python3
"""report_sections.py — read the analyst's report sections and the case's sources-checked ledger.

    report_sections.py load <case>       # merged `report` blocks + findings boundaries (JSON)
    report_sections.py sources <case>    # one row per (source, selector), zero hits kept (JSON)
    report_sections.py lint <case>       # QA warnings over the merged sections (JSON)

load(case_dir) -> dict
    Merges the `report` blocks evidence_import stored under cases/<case>/evidence/imported/*.json.
    Imports are read oldest-first by file mtime, so a LATER import wins per row: rows with an `id`
    (KQ-nn, OQ-nn, SC-nn, Tnnn, MAP-nn) merge on it; roles / roadmap / counting_rules merge on a
    content key (references/report_sections.json `merge_keys`). Accepted findings that carry a
    `confirmation` level or a `not_proven` boundary are exposed as `findings_boundaries`.
    Every section key is always present (an empty list when nothing was imported) — a renderer
    prints nothing for an empty section and never invents one. `engagement` (one object, not a
    list) is the LATEST import's value ({} when none).

lint(sections, findings=None) -> list[str]
    Pure QA warnings (never blocks): one identifier (e-mail, digits-only phone, platform:id,
    handle) on 2+ entities or under incompatible fields of one entity; alias / relative rows
    without basis or source; any profile row without source; near-duplicate handles (edit
    distance 1, or equal without . _ -); a client seed contradicting a confirmed single-valued
    profile row. Rules: references/report_sections.json `lint`. is_client_provided(row, seeds)
    tells the identity card which values the client supplied.

sources_checked(case_dir) -> list[dict]
    One row per (source, selector) from the case's tool-call ledger (cases/<case>/tool_calls.jsonl,
    written by harness/audit.py) plus the licensed-API ledger rows tagged with this case
    ($API_USAGE_LOG, else <case store root>/MEMORY/api_usage.jsonl). Each row: source, kind
    (tool|api), source_class (public wording, IntelReport Rule 12), selector, calls, hits (int, or
    'unknown' when no result count was recorded), status (hit|zero|error|skipped|unknown —
    'unknown' = the call ran but its ledger row records no result count), errors, skipped,
    first / last (UTC). ZERO-HIT ROWS ARE KEPT: a source that returned nothing bounds the claim.

RULE 5: nothing here writes to the KB or turns a row into an attribution — roles are analyst
judgement for the report only. Stdlib only; read-only; never raises on a damaged file.
"""
from __future__ import annotations

import argparse
import datetime
import glob
import json
import os
import re
import sys
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
KB_TOOLS = os.path.join(HERE, "kb")
if KB_TOOLS not in sys.path:
    sys.path.insert(0, KB_TOOLS)

try:
    from kb_refs import load_ref  # noqa: E402 — the shared RULE 3 loader
except Exception:  # noqa: BLE001 — degrade, never block
    def load_ref(path, fallback):
        print("[report_sections] WARNING: kb_refs unavailable; report_sections.json not read — "
              "running on the minimal embedded fallback.", file=sys.stderr)
        return dict(fallback)

# Conservative minimum: id sections merge on id, the rest on their natural key; no class wording.
_REF_FALLBACK = {
    "merge_keys": {"key_questions": ["id"], "open_questions": ["id"], "scenarios": ["id"],
                   "incident_timeline": ["id"], "attack_mapping": ["id"],
                   "roles": ["entity", "role"], "roadmap": ["priority", "action"],
                   "counting_rules": ["metric"], "metrics": ["metric"],
                   "subject_profile": ["entity", "field", "value"], "client_seeds": ["type", "value"]},
    "selector_args": ["selector", "target", "indicator", "url", "domain", "query"],
    "hit_fields": ["hits", "results"],
    "error_fields": ["error"],
    "source_classes": {},
    # Lint: conservative minimum — only exact identifier matches across entities are checked.
    "lint": {"profile_fields": ["name", "alias", "dob", "birthplace", "email", "phone", "address",
                                "company", "account", "relative", "other"],
             "handle_fields": ["alias", "account"], "phone_fields": ["phone", "account", "other"],
             "compatible_fields": [["alias", "account"]], "wildcard_fields": ["other"],
             "basis_required_fields": ["alias", "relative"], "single_valued_fields": ["dob"],
             "date_fields": ["dob"], "date_formats": ["%Y-%m-%d"], "seed_type_fields": {},
             "platform_hosts": {}, "strip_host_prefixes": ["www."], "id_query_params": ["id"],
             "skip_path_segments": [], "basis_id_pattern": "(?!)", "min_id_digits": 5,
             "min_phone_digits": 8, "near_duplicate_min_length": 4, "finding_handle_types": []},
}
_REF = load_ref(os.path.join(KB_TOOLS, "references", "report_sections.json"), _REF_FALLBACK)
MERGE_KEYS = dict(_REF.get("merge_keys") or _REF_FALLBACK["merge_keys"])
SECTIONS = tuple(MERGE_KEYS)
SELECTOR_ARGS = list(_REF.get("selector_args") or _REF_FALLBACK["selector_args"])
HIT_FIELDS = list(_REF.get("hit_fields") or _REF_FALLBACK["hit_fields"])
ERROR_FIELDS = list(_REF.get("error_fields") or _REF_FALLBACK["error_fields"])
SOURCE_CLASSES = {str(k).lower(): v for k, v in (_REF.get("source_classes") or {}).items()}
LINT = dict(_REF_FALLBACK["lint"], **(_REF.get("lint") or {}))

IMPORT_SUBDIR = os.path.join("evidence", "imported")
_PRIORITY_ORDER = {"P1": 1, "P2": 2, "P3": 3}


def _case_dir(case):
    """A path is used as given; a bare case ID resolves to ROOT/cases/<id> (never the CWD)."""
    c = str(case or "").strip()
    if os.path.isabs(c) or os.sep in c or (os.altsep and os.altsep in c):
        return os.path.abspath(c)
    return os.path.join(ROOT, "cases", c)


def _load_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _norm(v) -> str:
    return re.sub(r"\s+", " ", str(v if v is not None else "")).strip().lower()


def _row_key(section, row):
    return tuple(_norm(row.get(k)) for k in MERGE_KEYS.get(section) or ["id"])


def _id_sort(v):
    """'KQ-02' < 'KQ-10'; 'T007' < 'T012' — numeric where the id ends in digits."""
    m = re.match(r"^(.*?)(\d+)$", str(v or ""))
    return (m.group(1), int(m.group(2))) if m else (str(v or ""), 0)


def _imports(case_dir):
    """Imported records oldest-first (mtime, then name) — so a later import wins on merge."""
    paths = glob.glob(os.path.join(case_dir, IMPORT_SUBDIR, "*.json"))

    def key(p):
        try:
            return (os.path.getmtime(p), os.path.basename(p))
        except OSError:
            return (0.0, os.path.basename(p))
    return sorted(paths, key=key)


def load(case_dir) -> dict:
    """Merged report sections + findings boundaries for one case dir. See the module doc."""
    case_dir = _case_dir(case_dir)
    merged = {s: {} for s in SECTIONS}
    bounds: dict = {}
    engagement: dict = {}
    used = []
    for path in _imports(case_dir):
        rec = _load_json(path)
        if not isinstance(rec, dict):
            continue
        rep = rec.get("report") if isinstance(rec.get("report"), dict) else {}
        took = False
        for section in SECTIONS:
            for row in rep.get(section) or []:
                if not isinstance(row, dict):
                    continue
                k = _row_key(section, row)
                merged[section].pop(k, None)          # re-insert: a later import moves to the end
                merged[section][k] = dict(row, import_record=os.path.basename(path))
                took = True
        if isinstance(rep.get("engagement"), dict) and rep["engagement"]:
            engagement = dict(rep["engagement"], import_record=os.path.basename(path))
            took = True
        for f in rec.get("accepted") or []:
            if not isinstance(f, dict) or not (f.get("confirmation") or f.get("not_proven")):
                continue
            fid = f.get("id") or _norm(f.get("claim"))
            bounds.pop(fid, None)
            bounds[fid] = {"id": f.get("id") or "", "claim": f.get("claim") or "",
                           "admiralty": f.get("admiralty") or "",
                           "confirmation": f.get("confirmation") or "",
                           "not_proven": f.get("not_proven") or "",
                           "source_url": f.get("source_url") or "",
                           "import_record": os.path.basename(path)}
            took = True
        if took:
            used.append(os.path.basename(path))
    out = {}
    for section in SECTIONS:
        rows = list(merged[section].values())
        if MERGE_KEYS.get(section) == ["id"]:
            if section == "incident_timeline":
                rows.sort(key=lambda r: (str(r.get("when") or ""), _id_sort(r.get("id"))))
            else:
                rows.sort(key=lambda r: _id_sort(r.get("id")))
        elif section == "roadmap":
            rows.sort(key=lambda r: _PRIORITY_ORDER.get(str(r.get("priority") or "").upper(), 9))
        out[section] = rows
    out["findings_boundaries"] = list(bounds.values())
    out["engagement"] = engagement
    out["imports"] = used
    return out


# --------------------------------------------------------------------------- QA lint
# Identifier normalisation: one person's e-mail / phone / platform id / handle must compare equal
# however the analyst typed it, so a value recorded twice (on two entities, or under two
# incompatible fields) is caught. Rules + thresholds: references/report_sections.json `lint`.
def _url_parts(text):
    """(platform, id, vanity) from a platform profile URL inside `text`, else None."""
    s = str(text or "").strip()
    m = re.search(r"(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(/[^\s]*)?", s, re.I)
    if not m:
        return None
    host = m.group(1).lower()
    for pre in LINT["strip_host_prefixes"]:
        if host.startswith(pre):
            host = host[len(pre):]
    platform = LINT["platform_hosts"].get(host)
    if not platform:
        return None
    url = urlparse("https://" + host + (m.group(2) or ""))
    pid = None
    q = parse_qs(url.query)
    for p in LINT["id_query_params"]:
        if q.get(p) and str(q[p][0]).isdigit():
            pid = q[p][0]
            break
    segs = [x for x in url.path.split("/") if x]
    for sg in segs:
        if pid is None and sg.isdigit() and len(sg) >= int(LINT["min_id_digits"]):
            pid = sg
    while segs and segs[0].lower() in LINT["skip_path_segments"]:
        segs = segs[1:]
    vanity = segs[0].lstrip("@").lower() if segs and not segs[0].isdigit() else None
    if vanity and vanity.endswith(".php"):
        vanity = None
    return platform, pid, vanity


def _digits(v) -> str:
    return re.sub(r"\D", "", str(v or ""))


def _phone_like(v) -> bool:
    s = str(v or "").strip()
    return bool(re.fullmatch(r"\+?[\d\s().\-]+", s)) and len(_digits(s)) >= int(LINT["min_phone_digits"])


def _handle(v) -> str:
    return str(v or "").strip().lstrip("@").lower()


def ident_keys(field, value, source="", basis="") -> set:
    """Normalised identifier keys of one value: email:<lower>, phone:<digits>, <platform>:<id>,
    handle:<lower>. Empty for a value that is not an identifier (a name, a date, an address)."""
    field = str(field or "").lower()
    v = str(value or "").strip()
    keys = set()
    if not v:
        return keys
    parts = _url_parts(v)
    if parts:
        platform, pid, vanity = parts
        if pid is None:
            m = re.search(LINT["basis_id_pattern"], str(basis or ""))
            pid = m.group(1) if m else None
        if pid:
            keys.add(f"{platform}:{pid}")
        if vanity:
            keys.add(f"handle:{vanity}")
        return keys
    if "@" in v and re.fullmatch(r"[^@\s]+@[^@\s]+\.[A-Za-z]{2,}", v):
        return {f"email:{v.lower()}"}
    if field in LINT["phone_fields"] and _phone_like(v):
        return {f"phone:{_digits(v)}"}
    if field in LINT["handle_fields"]:
        src = _url_parts(source)
        if v.isdigit() and src:
            return {f"{src[0]}:{v}"}
        if re.fullmatch(r"@?[\w.\-]{2,}", v):
            return {f"handle:{_handle(v)}"}
    return keys


def _norm_date(v) -> str:
    s = str(v or "").strip()
    for fmt in LINT["date_formats"]:
        try:
            return datetime.datetime.strptime(s, fmt).strftime("%Y-%m-%d")
        except ValueError:
            continue
    return _norm(s)


def _same_value(field, a, b) -> bool:
    if field in LINT["date_fields"]:
        return _norm_date(a) == _norm_date(b)
    ka, kb = ident_keys(field, a), ident_keys(field, b)
    return bool(ka & kb) if (ka and kb) else _norm(a) == _norm(b)


def seed_field(seed) -> str:
    """A client seed's `type` -> the subject_profile field it describes ('' when none)."""
    t = re.sub(r"[\s\-]+", "_", str((seed or {}).get("type") or "").strip().lower())
    return LINT["seed_type_fields"].get(t, t if t in LINT["profile_fields"] else "")


def client_seed_for(row, seeds):
    """The client seed a subject_profile row's value ORIGINATED from (same field, same normalised
    value), else None — so the identity card can tell findings apart from what the client gave."""
    f = str(row.get("field") or "")
    for s in seeds or []:
        if isinstance(s, dict) and seed_field(s) == f and _same_value(f, s.get("value"), row.get("value")):
            return s
    return None


def is_client_provided(row, seeds) -> bool:
    return client_seed_for(row, seeds) is not None


def _edit1(a, b) -> bool:
    """Levenshtein distance <= 1 (one insert / delete / substitute)."""
    if a == b:
        return False
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la > lb:
        a, b, la, lb = b, a, lb, la
    i = j = diff = 0
    while i < la and j < lb:
        if a[i] != b[j]:
            diff += 1
            if diff > 1:
                return False
            if la == lb:
                i += 1
            j += 1
            continue
        i += 1
        j += 1
    return diff + (lb - j) + (la - i) <= 1


def lint(sections: dict, findings: list | None = None) -> list:
    """QA warnings over a report block (merged or one import). Pure; never raises, never blocks.

      (a) one identifier on 2+ different entities, or on one entity under incompatible fields;
      (b) alias / relative rows without basis or source;
      (c) any other subject_profile row without a source;
      (d) near-duplicate handles anywhere in the block (and in the findings' indicators):
          edit distance 1, or equal once . _ - are removed;
      (e) a client seed contradicting a CONFIRMED profile row of a single-valued field.
    """
    s = sections if isinstance(sections, dict) else {}
    prof = [r for r in (s.get("subject_profile") or []) if isinstance(r, dict)]
    seeds = [r for r in (s.get("client_seeds") or []) if isinstance(r, dict)]
    warns = []

    def who(r):
        return f"{r.get('entity') or 'subject'}/{r.get('field')}={r.get('value')!r}"

    # (a) identifier collisions
    by_key: dict = {}
    for r in prof:
        for k in ident_keys(r.get("field"), r.get("value"), r.get("source"), r.get("basis")):
            by_key.setdefault(k, []).append(r)
    seen_sig = set()
    compatible = [set(g) for g in LINT["compatible_fields"]]
    wild = set(LINT["wildcard_fields"])
    for k, rows in by_key.items():
        ents = sorted({str(r.get("entity") or "subject") for r in rows})
        sig = frozenset(id(r) for r in rows)
        if len(ents) > 1 and sig not in seen_sig:
            seen_sig.add(sig)
            warns.append(f"Identifier collision: {k} is attached to {len(ents)} different entities ("
                         + ", ".join(ents) + ") — rows " + "; ".join(who(r) for r in rows)
                         + ". One identifier, two people: confirm which entity owns it.")
            continue
        for ent in ents:
            fields = sorted({str(r.get("field")) for r in rows
                             if str(r.get("entity") or "subject") == ent} - wild)
            bad = [(a, b) for i, a in enumerate(fields) for b in fields[i + 1:]
                   if not any({a, b} <= g for g in compatible)]
            if bad and (sig, ent) not in seen_sig:
                seen_sig.add((sig, ent))
                warns.append(f"Identifier under incompatible fields: {k} is recorded for {ent} as "
                             + " and ".join(fields) + " — one of the rows is mis-filed.")
    # (b) + (c) sourcing
    strict = set(LINT["basis_required_fields"])
    for r in prof:
        if str(r.get("field")) in strict:
            missing = [x for x in ("basis", "source") if not str(r.get(x) or "").strip()]
            if missing:
                warns.append(f"Unsupported {r.get('field')}: {who(r)} has no " + " or ".join(missing)
                             + f" — an unsourced {r.get('field')} is how a wrong person enters a profile.")
        elif not str(r.get("source") or "").strip():
            warns.append(f"Unsourced profile row: {who(r)} has no source.")
    # (d) near-duplicate handles
    handles: dict = {}
    for r in prof:
        for k in ident_keys(r.get("field"), r.get("value"), r.get("source"), r.get("basis")):
            if k.startswith("handle:"):
                handles.setdefault(k[7:], str(r.get("value")))
    for sd in seeds:
        if seed_field(sd) in LINT["handle_fields"]:
            for k in ident_keys(seed_field(sd), sd.get("value")):
                if k.startswith("handle:"):
                    handles.setdefault(k[7:], str(sd.get("value")))
    for f in findings or []:
        for ind in (f.get("indicators") or []) if isinstance(f, dict) else []:
            if isinstance(ind, dict) and str(ind.get("type") or "").lower() in LINT["finding_handle_types"]:
                for k in ident_keys("account", ind.get("value")):
                    if k.startswith("handle:"):
                        handles.setdefault(k[7:], str(ind.get("value")))
    names = sorted(h for h in handles if len(h) >= int(LINT["near_duplicate_min_length"]))
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            if _edit1(a, b) or re.sub(r"[._\-]", "", a) == re.sub(r"[._\-]", "", b):
                warns.append(f"Possible typo or look-alike: {handles[a]} vs {handles[b]} — the same "
                             "account mistyped, or an impersonating look-alike; verify both.")
    # (e) client seeds vs confirmed single-valued rows
    single = set(LINT["single_valued_fields"])
    for sd in seeds:
        f = seed_field(sd)
        if f not in single:
            continue
        ent = str(sd.get("entity") or "subject")
        conf = [r for r in prof if r.get("field") == f and r.get("status") == "confirmed"
                and str(r.get("entity") or "subject") == ent]
        if conf and not any(_same_value(f, sd.get("value"), r.get("value")) for r in conf):
            shown = repr(sd.get("value"))      # renderers redact sensitive seeds (house --show-sensitive)
            warns.append(f"Client detail contradicts a confirmed finding: client-provided {f} {shown} vs "
                         f"confirmed {f} " + ", ".join(repr(r.get("value")) for r in conf)
                         + f" for {ent} — resolve before the report states either.")
    return warns


# --------------------------------------------------------------------------- sources checked
def _read_jsonl(path):
    rows = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except ValueError:
                    continue                          # a torn line never hides the rest
                if isinstance(r, dict):
                    rows.append(r)
    except OSError:
        pass
    return rows


def _short(v, limit=160) -> str:
    if isinstance(v, (list, tuple)):
        v = ", ".join(str(x) for x in v[:5]) + (f" (+{len(v) - 5})" if len(v) > 5 else "")
    elif isinstance(v, dict):
        v = json.dumps(v, ensure_ascii=False, sort_keys=True)
    s = re.sub(r"\s+", " ", str(v)).strip()
    return s if len(s) <= limit else s[:limit - 1] + "…"


def _selector(args) -> str:
    if not isinstance(args, dict):
        return "(case)"
    for k in SELECTOR_ARGS:
        v = args.get(k)
        if v not in (None, "", [], {}):
            return _short(v)
    return "(case)"


def _hits(rec):
    """int hits, or None when the record carries no result count."""
    for k in HIT_FIELDS:
        v = rec.get(k)
        if isinstance(v, bool):
            continue
        if isinstance(v, int):
            return v
        if isinstance(v, float) and v == v:
            return int(v)
        if isinstance(v, (list, dict)):
            return len(v)
    return None


def source_class(name: str) -> str:
    """Public source class for a tool / provider name (Rule 12 wording); the name itself, with
    underscores as spaces, when references/report_sections.json does not list it."""
    n = str(name or "").strip().lower()
    base = n.split(":", 1)[0]
    return SOURCE_CLASSES.get(n) or SOURCE_CLASSES.get(base) or base.replace("_", " ")


def _api_log(case_dir):
    env = os.environ.get("API_USAGE_LOG")
    if env:
        return env
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(case_dir))),
                        "MEMORY", "api_usage.jsonl")


def _observations(case_dir, case_id):
    """(source, kind, selector, ts, outcome, hits, reason) per ledger row of this case."""
    for r in _read_jsonl(os.path.join(case_dir, "tool_calls.jsonl")):
        if r.get("case") not in (None, "", case_id):
            continue
        tool = str(r.get("tool") or r.get("tool_fq") or "").strip()
        if not tool:
            continue
        if str(r.get("decision") or "").upper() == "DENY":
            outcome = "skipped"
        elif any(r.get(k) for k in ERROR_FIELDS):
            outcome = "error"
        else:
            outcome = "ran"
        yield (tool, "tool", _selector(r.get("args")), r.get("ts") or "", outcome, _hits(r),
               r.get("reason") or "")
    for r in _read_jsonl(_api_log(case_dir)):
        if r.get("case") != case_id:
            continue
        prov = str(r.get("provider") or "").strip()
        if not prov:
            continue
        src = prov + (f":{r['action']}" if r.get("action") else "")
        err = r.get("ok") is False or any(r.get(k) for k in ERROR_FIELDS)
        yield (src, "api", _short(r.get("query")) if r.get("query") else "(case)",
               r.get("ts") or "", "error" if err else "ran", _hits(r), "")


def sources_checked(case_dir) -> list:
    """One row per (source, selector); zero-hit rows kept. See the module doc for the row shape."""
    case_dir = _case_dir(case_dir)
    case_id = os.path.basename(os.path.normpath(case_dir))
    agg: dict = {}
    for src, kind, sel, ts, outcome, hits, reason in _observations(case_dir, case_id):
        row = agg.setdefault((src, sel), {
            "source": src, "kind": kind, "source_class": source_class(src), "selector": sel,
            "calls": 0, "_hits": [], "_unknown": 0, "errors": 0, "skipped": 0,
            "first": "", "last": "", "reason": ""})
        row["calls"] += 1
        if outcome == "skipped":
            row["skipped"] += 1
            row["reason"] = reason or row["reason"]
        elif outcome == "error":
            row["errors"] += 1
        elif hits is None:
            row["_unknown"] += 1
        else:
            row["_hits"].append(hits)
        if ts:
            row["first"] = min(row["first"] or ts, ts)
            row["last"] = max(row["last"] or ts, ts)
    out = []
    for row in agg.values():
        known = row.pop("_hits")
        unknown = row.pop("_unknown")
        total = sum(known)
        if total > 0:
            status = "hit"
        elif known:
            status = "zero"                       # a counted empty result outranks an error
        elif row["errors"]:
            status = "error"
        elif unknown:
            status = "unknown"
        else:
            status = "skipped"
        row["hits"] = total if known else "unknown"
        row["status"] = status
        if not row["reason"]:
            row.pop("reason")
        out.append(row)
    out.sort(key=lambda r: (r["source_class"], r["source"], r["selector"]))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="Report sections + sources-checked reader for a case.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, hlp in (("load", "merged analyst report sections"),
                      ("sources", "sources checked (zero hits kept)"),
                      ("lint", "QA warnings over the merged sections (warn only)")):
        p = sub.add_parser(name, help=hlp)
        p.add_argument("case", help="case id under cases/ or a case dir path")
    a = ap.parse_args(argv)
    cdir = _case_dir(a.case)
    if not os.path.isdir(cdir):
        print(json.dumps({"error": f"case directory not found: {cdir}"}))
        return 1
    if a.cmd == "load":
        res = load(cdir)
    elif a.cmd == "lint":
        res = {"case": os.path.basename(os.path.normpath(cdir)), "warnings": lint(load(cdir))}
    else:
        res = {"case": os.path.basename(os.path.normpath(cdir)), "sources": sources_checked(cdir)}
    print(json.dumps(res, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
