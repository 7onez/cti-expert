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
    list) is the LATEST import's value ({} when none); so is `risk_assessment` (the C1 organisation
    risk object), which falls back to cases/<case>/exposure_organisation.json (written by
    exposure_score.py --model organisation --case) when no import carries one. key_findings sort
    by `n`, threat_events by `start`, leak_claims by `date`, negative_checks by `check`.
    `actor_profile` (one object) is the LATEST import's value ({} when none); when the case holds
    an actor-score file (references/report_sections.json `actor_profile.scores_file`) the entry
    keyed by its `threat_score_ref` (else its name) is attached as `threat_score` (score_keys only).
    playbook rows sort by ATT&CK tactic order (unknown tactics last, analyst order kept).
    `actor_refs` = {"tempo": tempo_ref_check(...)} resolves actor_profile.tempo_ref against the case
    ({} when none), so lint() can check it without touching the disk for the case.

attack_coverage(sections) -> list[dict]
    The actor chapter's ATT&CK coverage index, DERIVED (never imported): one row per technique id
    named by a playbook row or a hunt hypothesis — technique_id, tactics[], playbook (bool),
    hunts [HH-nn], mappings ["MAP-nn (status)"] cross-referencing the existing attack_mapping
    rows — in tactic order, then technique id.

lint(sections, findings=None, today=None) -> list[str]
    Pure QA warnings (never blocks): one identifier (e-mail, digits-only phone, platform:id,
    handle) on 2+ entities or under incompatible fields of one entity; alias / relative rows
    without basis or source; any profile row without source; near-duplicate handles (edit
    distance 1, or equal without . _ -); a client seed contradicting a confirmed single-valued
    profile row; a Critical/High key finding without a priority (or Critical with P4, a tier-matrix
    mismatch); an overall risk score that is
    not the mean of its domain scores; a threat event over before `today` (stale); a proven leak
    claim without evidence; an actor attribution without an ICD-203 likelihood term or a
    confidence; an actor intent with no evidence; a High claim_confidence row without sources; a
    hunt hypothesis without priority telemetry or behavioural signals; a playbook row naming an
    ATT&CK id with no evidence; a hunt_package_ref not in the hunt-package index (index missing ->
    one "unavailable" warning); a tempo_ref that is not the case's timeline ledger with an
    operator_tempo read, or a tempo_summary beside an `insufficient` read. Rules:
    references/report_sections.json `lint` + `risk` + `actor_profile` (+ `pointers`).
    is_client_provided(row, seeds) tells the identity card which values the client supplied.

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
                   "subject_profile": ["entity", "field", "value"], "client_seeds": ["type", "value"],
                   "key_findings": ["n"], "affiliate_exposure": ["org", "country"],
                   "leak_claims": ["actor", "venue", "claim"], "threat_events": ["event", "start"],
                   "usernames_to_reserve": ["platform", "handle"], "negative_checks": ["check", "scope"],
                   "email_services": ["email", "service"], "relationships": ["from", "to", "relation"],
                   "actors": ["name", "type"], "claim_confidence": ["claim"],
                   "pivot_opportunities": ["seed_artifact", "pivot_question"], "playbook": ["tactic", "behaviours"],
                   "hunt_hypotheses": ["id"], "telemetry_priorities": ["source"]},
    # P4 still renders as untimed; the Critical-vs-P4 mismatch lint is off without the file.
    "risk": {"score_max": 10, "overall_tolerance": 0.06, "priority_required_severities": ["critical", "high"],
             "untimed_priorities": {"P4": "track only — no deadline"}, "priority_mismatch": {}},
    # Actor chapter: no tactic order (analyst order kept), the seven primary ICD-203 terms only.
    "actor_profile": {"tactic_order": [], "likelihood_terms": ["almost no chance", "very unlikely", "unlikely",
                                                               "roughly even chance", "likely", "very likely",
                                                               "almost certain"],
                      "confidence_terms": ["high", "moderate", "low"], "sources_required_confidence": ["high"],
                      "scores_file": "actor_scores.json", "score_keys": ["threat_score", "band"],
                      # no hunt index path: refs are reported unchecked; the tempo ledger contract is fixed
                      "pointers": {"hunt_index": "", "tempo_key": "operator_tempo",
                                   "tempo_ledger_suffix": "_events.json", "abstain_statuses": ["insufficient"]}},
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
RISK = dict(_REF_FALLBACK["risk"], **(_REF.get("risk") or {}))
ACTOR = dict(_REF_FALLBACK["actor_profile"], **(_REF.get("actor_profile") or {}))
ACTOR.pop("_comment", None)

IMPORT_SUBDIR = os.path.join("evidence", "imported")
ORG_RISK_FILE = "exposure_organisation.json"     # exposure_score.py --model organisation --case
_PRIORITY_ORDER = {"P1": 1, "P2": 2, "P3": 3}
_ROW_SORT = {   # section -> sort key over merged rows (analyst order otherwise)
    "key_findings": lambda r: (r.get("n") if isinstance(r.get("n"), (int, float)) else 1e9),
    "threat_events": lambda r: str(r.get("start") or ""),
    "leak_claims": lambda r: str(r.get("date") or ""),
    "negative_checks": lambda r: _norm(r.get("check")),
    "playbook": lambda r: tactic_rank(r.get("tactic")),
}


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
    risk: dict = {}
    actor: dict = {}
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
        if isinstance(rep.get("risk_assessment"), dict) and rep["risk_assessment"].get("domains"):
            risk = dict(rep["risk_assessment"], import_record=os.path.basename(path))
            took = True
        if isinstance(rep.get("actor_profile"), dict) and rep["actor_profile"]:
            actor = dict(rep["actor_profile"], import_record=os.path.basename(path))
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
        elif section in _ROW_SORT:
            rows.sort(key=_ROW_SORT[section])
        out[section] = rows
    out["findings_boundaries"] = list(bounds.values())
    out["engagement"] = engagement
    if not risk:                    # the scorer's own case file when no import carries the object
        org = _load_json(os.path.join(case_dir, ORG_RISK_FILE))
        if isinstance(org, dict) and isinstance(org.get("domains"), list) and org["domains"]:
            risk = dict(org, import_record=ORG_RISK_FILE)
    out["risk_assessment"] = risk
    if actor:
        actor.pop("threat_score", None)          # only ever read from the case's actor-score file
        score = _actor_score(case_dir, actor.get("threat_score_ref") or actor.get("name"))
        if score:
            actor["threat_score"] = score
    out["actor_profile"] = actor
    # resolved against THIS case dir here, so lint() stays pure (a hand-authored REPORT.json has none)
    out["actor_refs"] = {"tempo": tempo_ref_check(case_dir, actor.get("tempo_ref"))} \
        if actor and _filled(actor.get("tempo_ref")) else {}
    out["imports"] = used
    return out


def priority_label(priority, priorities=None) -> str:
    """'P1 (7 days)' with the deadline from risk_assessment.priorities; an untimed priority (risk
    untimed_priorities — the tier matrix P4) as 'P4 (track only — no deadline)'; '' for none."""
    p = str(priority or "").strip().upper()
    if not p:
        return ""
    prio = priorities if isinstance(priorities, dict) else {}
    note = prio.get(p) or (RISK.get("untimed_priorities") or {}).get(p)
    return f"{p} ({note})" if note else p


# --------------------------------------------------------------------------- actor chapter
def tactic_rank(tactic) -> int:
    """Position of an ATT&CK tactic in references actor_profile.tactic_order (case/spacing/hyphen
    insensitive); an unknown tactic ranks after every known one (a stable sort keeps analyst order)."""
    order = [re.sub(r"[\s_\-]+", " ", _norm(t)) for t in ACTOR.get("tactic_order") or []]
    t = re.sub(r"[\s_\-]+", " ", _norm(tactic))
    return order.index(t) if t in order else len(order)


def _actor_score(case_dir, key):
    """{actor, <score_keys>, source} from the case's actor-score file for `key` (exact, then
    case-insensitive), or {} — a missing or damaged file is no score, never an error."""
    if not key:
        return {}
    doc = _load_json(os.path.join(case_dir, str(ACTOR.get("scores_file") or "actor_scores.json")))
    if isinstance(doc, dict) and isinstance(doc.get("actors"), dict):
        doc = doc["actors"]
    if not isinstance(doc, dict):
        return {}
    hit = doc.get(key)
    if not isinstance(hit, dict):
        hit = next((v for k, v in doc.items() if _norm(k) == _norm(key) and isinstance(v, dict)), None)
    if not isinstance(hit, dict):
        return {}
    kept = {k: hit[k] for k in ACTOR.get("score_keys") or [] if hit.get(k) not in (None, "")}
    return dict(kept, actor=str(key), source=str(ACTOR.get("scores_file"))) if kept else {}


def _ids(v) -> list:
    items = [v] if isinstance(v, str) else (v if isinstance(v, list) else [])
    return [str(x).strip().upper() for x in items if str(x).strip()]


def attack_coverage(sections: dict) -> list:
    """The actor chapter's ATT&CK coverage index — derived from playbook + hunt_hypotheses, with the
    attack_mapping rows that name the same technique cross-referenced (never duplicated). See the
    module doc for the row shape."""
    s = sections if isinstance(sections, dict) else {}
    rows: dict = {}

    def at(tid):
        return rows.setdefault(tid, {"technique_id": tid, "tactics": [], "playbook": False,
                                     "hunts": [], "mappings": []})

    for r in s.get("playbook") or []:
        if isinstance(r, dict):
            for tid in _ids(r.get("attack_ids")):
                row = at(tid)
                row["playbook"] = True
                if r.get("tactic") and r["tactic"] not in row["tactics"]:
                    row["tactics"].append(r["tactic"])
    for r in s.get("hunt_hypotheses") or []:
        if isinstance(r, dict):
            for tid in _ids(r.get("attack_ids")):
                if r.get("id") and r["id"] not in at(tid)["hunts"]:
                    rows[tid]["hunts"].append(r["id"])
    for r in s.get("attack_mapping") or []:
        if isinstance(r, dict) and str(r.get("technique_id") or "").strip().upper() in rows:
            row = rows[str(r["technique_id"]).strip().upper()]
            row["mappings"].append(f"{r.get('id')} ({r.get('status')})" if r.get("status") else str(r.get("id")))
            if r.get("tactic") and r["tactic"] not in row["tactics"]:
                row["tactics"].append(r["tactic"])
    for row in rows.values():
        row["tactics"].sort(key=tactic_rank)
    return sorted(rows.values(), key=lambda r: (min((tactic_rank(t) for t in r["tactics"]),
                                                    default=len(ACTOR.get("tactic_order") or []) + 1),
                                                r["technique_id"]))


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


def lint(sections: dict, findings: list | None = None, today: str | None = None) -> list:
    """QA warnings over a report block (merged or one import). Pure; never raises, never blocks.

      (a) one identifier on 2+ different entities, or on one entity under incompatible fields;
      (b) alias / relative rows without basis or source;
      (c) any other subject_profile row without a source;
      (d) near-duplicate handles anywhere in the block (and in the findings' indicators):
          edit distance 1, or equal once . _ - are removed;
      (e) a client seed contradicting a CONFIRMED profile row of a single-valued field;
      (f) risk / threat sections — see _lint_risk (`today` = the report date, ISO; default UTC today);
      (g) actor threat-profile sections — see _lint_actor.
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
    warns += _lint_risk(s, today)
    warns += _lint_actor(s)
    return warns


def _lint_risk(s: dict, today: str | None = None) -> list:
    """(f) a Critical/High key finding with no priority; a key finding whose priority the tier
    matrix can never give its severity (risk priority_mismatch: Critical is never P4); an overall
    risk score that is not the mean of the listed domain scores; a threat event already over at the
    report date (stale); a leak claim marked proven with no evidence. Thresholds:
    references/report_sections.json `risk`."""
    warns = []
    today = str(today or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d"))[:10]
    need = {str(x).lower() for x in RISK["priority_required_severities"]}
    mismatch = {str(k).lower(): {str(p).upper() for p in v} for k, v in (RISK.get("priority_mismatch") or {}).items()}
    for r in s.get("key_findings") or []:
        if not isinstance(r, dict):
            continue
        sev, prio = str(r.get("severity") or "").lower(), str(r.get("priority") or "").upper()
        if sev in need and not prio:
            warns.append(f"Key finding {r.get('n', '?')} is {r.get('severity')} but has no priority — "
                         "give it P1 / P2 / P3 so the reader knows the deadline.")
        elif prio and prio in mismatch.get(sev, ()):
            warns.append(f"Key finding {r.get('n', '?')} is {r.get('severity')} but priority {prio} — the "
                         "severity tier matrix never gives that severity this tier; re-check the severity, "
                         "the exposure rating or the priority.")
    ra = s.get("risk_assessment") if isinstance(s.get("risk_assessment"), dict) else {}
    scores = [d.get("score") for d in (ra.get("domains") or []) if isinstance(d, dict)
              and isinstance(d.get("score"), (int, float)) and not isinstance(d.get("score"), bool)]
    overall = (ra.get("overall") or {}).get("score") if isinstance(ra.get("overall"), dict) else None
    if scores and isinstance(overall, (int, float)) and not isinstance(overall, bool):
        mean = sum(scores) / len(scores)
        if abs(mean - overall) > float(RISK["overall_tolerance"]):
            warns.append(f"Overall risk score {overall} is not the mean of the {len(scores)} rated domain "
                         f"score(s) ({mean:.1f}) — re-run the scorer or correct the domain rows.")
    for r in s.get("threat_events") or []:
        if not isinstance(r, dict):
            continue
        last = str(r.get("end") or r.get("start") or "")[:10]
        if last and last < today:
            warns.append(f"Stale threat event: {r.get('event')!r} ended {last}, before the report date "
                         f"{today} — drop it or move it to the incident timeline.")
    for r in s.get("leak_claims") or []:
        if isinstance(r, dict) and r.get("proven") is True and not r.get("evidence"):
            warns.append(f"Leak claim by {r.get('actor')!r} on {r.get('venue')!r} is marked proven but cites "
                         "no evidence — cite it or mark it unproven.")
    return warns


def _filled(v) -> bool:
    if isinstance(v, list):
        return any(str(x).strip() for x in v)
    return bool(str(v or "").strip())


def _lint_actor(s: dict) -> list:
    """(g) an actor attribution without an ICD-203 likelihood term or a confidence (RULE 5: it
    renders with both); an intent judgement with no evidence; a claim_confidence row at a
    sources-required level with no sources; a hunt hypothesis without priority telemetry or
    behavioural signals; a playbook row naming an ATT&CK id with no evidence.
    Vocabulary: references/report_sections.json `actor_profile`."""
    warns = []
    ap = s.get("actor_profile") if isinstance(s.get("actor_profile"), dict) else {}
    name = ap.get("name") or "the actor"
    att = ap.get("attribution") if isinstance(ap.get("attribution"), dict) else {}
    if _filled(att.get("assessment")):
        terms = {_norm(t) for t in ACTOR.get("likelihood_terms") or []}
        confs = {_norm(t) for t in ACTOR.get("confidence_terms") or []}
        missing = []
        if _norm(att.get("likelihood")) not in terms:
            missing.append("an ICD-203 likelihood term" + (f" ({att.get('likelihood')!r} is not one)"
                                                           if _filled(att.get("likelihood")) else ""))
        if re.sub(r"\s+confidence$", "", _norm(att.get("confidence"))) not in confs:
            missing.append("a confidence level" + (f" ({att.get('confidence')!r} is not one)"
                                                   if _filled(att.get("confidence")) else ""))
        if missing:
            warns.append(f"Attribution of {name!r} states no " + " and no ".join(missing)
                         + " — an attribution renders with both (RULE 5); add them or withdraw it.")
    intent = ap.get("intent") if isinstance(ap.get("intent"), dict) else {}
    if _filled(intent.get("motivations")) and not _filled(intent.get("evidence")):
        warns.append(f"Intent of {name!r} is asserted with no evidence — an intent judgement must cite "
                     "what it rests on.")
    need = {_norm(x) for x in ACTOR.get("sources_required_confidence") or []}
    for r in s.get("claim_confidence") or []:
        if isinstance(r, dict) and _norm(r.get("confidence")) in need and not _filled(r.get("sources")):
            warns.append(f"Claim {r.get('claim')!r} is rated {r.get('confidence')} confidence but cites no "
                         "sources — cite them or lower the rating.")
    for r in s.get("hunt_hypotheses") or []:
        if not isinstance(r, dict):
            continue
        gaps = [label for k, label in (("priority_telemetry", "priority telemetry"),
                                       ("behavioural_signals", "behavioural signals")) if not _filled(r.get(k))]
        if gaps:
            warns.append(f"Hunt hypothesis {r.get('id', '?')} has no " + " and no ".join(gaps)
                         + " — a hunter cannot run it as written.")
    for r in s.get("playbook") or []:
        if isinstance(r, dict) and _filled(r.get("attack_ids")) and not _filled(r.get("evidence")):
            warns.append(f"Playbook row {r.get('tactic')!r} maps ATT&CK " + ", ".join(_ids(r.get("attack_ids")))
                         + " but cites no evidence — cite the observation or drop the mapping.")
    warns += _lint_pointers(s)
    warns += _lint_baseline_refs(s)
    return warns


def _pointers() -> dict:
    return dict(_REF_FALLBACK["actor_profile"]["pointers"], **(ACTOR.get("pointers") or {}))


def telemetry_baseline_keys():
    """Every setting key in the telemetry-baseline map (`settings`, minus _comment), or None when the
    map is missing / unreadable / not configured (pointers.telemetry_baselines_index)."""
    rel = str(_pointers().get("telemetry_baselines_index") or "")
    doc = _load_json(os.path.join(ROOT, rel)) if rel else None
    settings = doc.get("settings") if isinstance(doc, dict) else None
    if not isinstance(settings, dict):
        return None
    return {str(k) for k in settings if not str(k).startswith("_")} or None


_BASELINE_SETTINGS = []     # [settings dict | None] once loaded — one read of the baseline map per process


def telemetry_baseline_setting(ref):
    """The display string for one telemetry_priorities baseline_ref — the setting's name (else its
    subcategory) plus its key event IDs, e.g. 'PowerShell Script Block Logging (4104)'; None for an
    empty / unknown ref or when the baseline map is missing / unreadable / not configured."""
    if not _BASELINE_SETTINGS:
        rel = str(_pointers().get("telemetry_baselines_index") or "")
        doc = _load_json(os.path.join(ROOT, rel)) if rel else None
        settings = doc.get("settings") if isinstance(doc, dict) else None
        _BASELINE_SETTINGS.append(settings if isinstance(settings, dict) else None)
    settings, key = _BASELINE_SETTINGS[0], str(ref if ref is not None else "").strip()
    entry = settings.get(key) if settings and key and not key.startswith("_") else None
    if not isinstance(entry, dict):
        return None
    name = str(entry.get("name") or entry.get("subcategory") or "").strip()
    if not name:
        return None
    ids = ", ".join(str(i) for i in entry.get("event_ids") or [] if str(i).strip())
    return f"{name} ({ids})" if ids else name


def _lint_baseline_refs(s: dict) -> list:
    """(g, pointers) a telemetry_priorities baseline_ref that is not a setting key in the
    telemetry-baseline map; map unavailable -> ONE warning, refs unchecked."""
    refs = [(r.get("source", "?"), str(r.get("baseline_ref")).strip()) for r in s.get("telemetry_priorities") or []
            if isinstance(r, dict) and _filled(r.get("baseline_ref"))]
    if not refs:
        return []
    keys = telemetry_baseline_keys()
    if keys is None:
        return ["Telemetry baseline map unavailable — refs not checked "
                f"({len(refs)} baseline_ref value(s) left unverified)."]
    return [f"Priority telemetry {src!r} points at baseline setting {ref!r}, which is not in the telemetry "
            "baseline map — fix the key or drop the reference." for src, ref in refs if ref not in keys]


def hunt_package_ids():
    """Every valid hunt_package_ref across the hunt indexes in pointers.hunt_index (one path or a
    list, relative to intel_engine/): an `id` under a tactic group's `entries` (hunt_packages.json),
    a Sigma rule id under `sources.<repo>.rule_ids` or a Senrigan hunt id under `senrigan_hunts`
    (hunt_rules_yamato.json). None when none is configured or ANY listed index is missing /
    unreadable — a ref absent from the readable ones may live in the missing one, so the lint
    reports all refs unchecked once rather than flag them."""
    rels = _pointers().get("hunt_index") or []
    rels = [rels] if isinstance(rels, str) else list(rels)
    ids = set()
    for rel in (str(r) for r in rels if r):
        doc = _load_json(os.path.join(ROOT, rel))
        if not isinstance(doc, dict):
            return None
        ids |= {str(e["id"]) for g in doc.values() if isinstance(g, dict)
                for e in g.get("entries") or [] if isinstance(e, dict) and e.get("id")}
        src = doc.get("sources") if isinstance(doc.get("sources"), dict) else {}
        ids |= {str(i) for s in src.values() if isinstance(s, dict) for i in s.get("rule_ids") or []}
        ids |= {str(h["id"]) for h in doc.get("senrigan_hunts") or [] if isinstance(h, dict) and h.get("id")}
    return ids or None


def tempo_ref_check(case_dir, ref) -> dict:
    """Resolve an actor_profile.tempo_ref against the case: {ref, path, exists, has_key, status, error}.
    Grammar: '<case-relative ledger path>[#<tempo_key>]'; the path must stay inside the case dir and
    end with the ledger suffix case_timeline writes (<stem>_events.json)."""
    p = _pointers()
    key = str(p.get("tempo_key") or "operator_tempo")
    ref = str(ref or "").strip()
    out = {"ref": ref, "path": "", "exists": False, "has_key": False, "status": "", "error": ""}
    path, _, frag = ref.partition("#")
    base = os.path.realpath(_case_dir(case_dir))
    full = os.path.realpath(os.path.join(base, path.strip()))
    if frag and frag.strip() != key:
        out["error"] = f"fragment '#{frag}' is not '#{key}'"
    elif not path.strip().endswith(str(p.get("tempo_ledger_suffix") or "_events.json")) \
            or os.path.isabs(path.strip()) or not full.startswith(base + os.sep):
        out["error"] = (f"not a case-relative timeline ledger (<stem>{p.get('tempo_ledger_suffix')}, "
                        f"optionally #{key})")
    else:
        out["path"] = os.path.relpath(full, base)
        doc = _load_json(full)
        out["exists"] = os.path.isfile(full)
        tempo = doc.get(key) if isinstance(doc, dict) else None
        out["has_key"] = isinstance(tempo, dict)
        out["status"] = str(tempo.get("status") or "") if isinstance(tempo, dict) else ""
    return out


def _lint_pointers(s: dict) -> list:
    """(g, pointers) hunt_package_ref not in the hunt-package index (index unavailable -> ONE warning);
    a tempo_ref that does not resolve to a case timeline ledger carrying the tempo key; a tempo
    stated (tempo_summary) while that read abstained (status in abstain_statuses). The tempo check
    needs load()'s `actor_refs`; without it (a hand-authored report JSON) it is skipped."""
    warns = []
    refs = [(r.get("id", "?"), str(r.get("hunt_package_ref")).strip()) for r in s.get("hunt_hypotheses") or []
            if isinstance(r, dict) and _filled(r.get("hunt_package_ref"))]
    if refs:
        ids = hunt_package_ids()
        if ids is None:
            warns.append("Hunt package index unavailable — refs not checked "
                         f"({len(refs)} hunt_package_ref value(s) left unverified).")
        else:
            warns += [f"Hunt hypothesis {hid} points at hunt package {ref!r}, which is not in the hunt-package "
                      "index — fix the id or drop the reference." for hid, ref in refs if ref not in ids]
    ap = s.get("actor_profile") if isinstance(s.get("actor_profile"), dict) else {}
    tc = (s.get("actor_refs") or {}).get("tempo") if isinstance(s.get("actor_refs"), dict) else None
    if isinstance(tc, dict) and tc.get("ref"):
        key = _pointers().get("tempo_key")
        if tc.get("error"):
            warns.append(f"Tempo ref {tc['ref']!r}: {tc['error']} — point it at the case's timeline ledger.")
        elif not tc.get("exists"):
            warns.append(f"Tempo ref {tc['ref']!r}: ledger {tc.get('path')} is absent from the case — run "
                         "case_timeline with --tempo or drop the reference.")
        elif not tc.get("has_key"):
            warns.append(f"Tempo ref {tc['ref']!r}: ledger {tc.get('path')} has no {key!r} read — re-run "
                         "case_timeline with --tempo.")
        elif _norm(tc.get("status")) in {_norm(x) for x in _pointers().get("abstain_statuses") or []} \
                and _filled(ap.get("tempo_summary")):
            warns.append(f"Tempo of {ap.get('name') or 'the actor'!r} is stated as a finding, but the operator-tempo "
                         f"read it cites is {tc.get('status')!r} — withdraw the tempo summary or collect more events.")
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
