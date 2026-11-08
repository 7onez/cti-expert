#!/usr/bin/env python3
# cti-expert skill — house-report sections for the flat report JSON (stdlib only).
"""cti_report_sections.py — the analyst `report` block (evidence_import) as report-JSON sections.

One place for what the DOCX (cti_docx_sections) and HTML (generate-cti-html) renderers share:
the section order and columns, the P1/P2/P3 roadmap grouping, the open-question -> gap-string
derivation build_report_data keeps for backward compatibility, and the anti-inflation check.

  SECTIONS                      ordered (key, title, [(field|(alt, ...), header), ...])
  rows(data, key)               -> the section's dict rows ([] when absent / malformed)
  cell(row, field)              -> display string for one table cell (lists joined, None -> "—")
  roadmap_groups(data)          -> [(heading, [rows])] P1 / P2 / P3 (unknown priority last)
  gap_strings(open_questions)   -> flat `intelligence_gaps` strings
  validate_metrics(data)        -> [warning, ...] — never mutates a number
  ensure_metric_warnings(data)  -> fills `metric_warnings` on a hand-authored report JSON (stderr)
  withhold_client(data, show)   -> sensitive client-seed values (and identity rows carrying them)
                                   replaced by WITHHELD unless `show`; idempotent
  identity_cards(data)          -> [(entity, [rows in FIELD_ORDER])] for the Subject identity card
  engagement_items(data)        -> [(label, value)] document-control metadata (author · version …)
  apply_engagement(data)        -> copies engagement.author onto case.analyst (the cover reads it)
  ensure_qa_warnings(data)      -> fills `qa_warnings` via the engine's report_sections.lint (stderr)

Every row is the analyst's judgement for the report only: a role, a scenario or a timeline entry is
not a KB edge and never names an operator on a single signal (RULE 5).
"""
import json
import re
import sys

from cti_refs import load_ref

ROLES_NOTE = ("Roles are the analyst's judgement for this report (RULE 5): a role is not a "
              "knowledge-base edge, and no operator is named on a single signal.")
COUNTING_NOTE = "Each headline number counts exactly what the 'Counts' column says — nothing more."
SOURCES_CHECKED_NOTE = ("Every source queried for this case, including those that returned nothing: "
                        "a zero-hit row is a negative result at the collection time, not proof of absence.")
IDENTITY_NOTE = ("Identity details as recorded for this report, each with its basis, source and status. "
                 "'client-provided' marks a value the client supplied; it is a seed, not an independent "
                 "finding. A value on this card is not a knowledge-base edge (RULE 5).")
CLIENT_NOTE = ("Details the client supplied at intake. They seeded collection and are not independent "
               "corroboration of any finding.")
QA_NOTE = ("Consistency checks over the analyst report block (lint). Each line is something a reviewer "
           "should resolve or explain before release; none changes the report content.")
WITHHELD = "provided by client — withheld"
CLIENT_TAG = "client-provided"
# Subject identity card: fixed field order; a field with no row is omitted
FIELD_ORDER = ["name", "alias", "dob", "birthplace", "email", "phone", "address", "company",
               "account", "relative", "other"]
FIELD_LABELS = {"name": "Name", "alias": "Alias", "dob": "Date of birth", "birthplace": "Birthplace",
                "email": "E-mail", "phone": "Phone", "address": "Address", "company": "Company",
                "account": "Account", "relative": "Relative", "other": "Other"}
IDENTITY_COLS = [(lambda r: FIELD_LABELS.get(str(r.get("field") or "other").lower(), r.get("field")), "Field"),
                 (lambda r: _identity_value(r), "Value"), ("status", "Status"), ("basis", "Basis"),
                 ("source", "Source"), ("admiralty", "Admiralty")]
ENGAGEMENT_FIELDS = [("author", "Author"), ("version", "Version"), ("created", "Created"),
                     ("modified", "Modified"), ("hours", "Hours"), ("client", "Client")]

# (report-JSON key, heading, columns). A column field may be a tuple of alternative keys (first
# present wins) or a callable(row) -> value.
SECTIONS = [
    ("key_questions", "Key Questions", [
        ("id", "ID"), ("question", "Question"), ("status", "Status"), ("answer", "Answer"),
        ("confidence", "Confidence"), ("refs", "Refs")]),
    ("counting_rules", "Counting Rules", [
        ("metric", "Metric"), ("counts", "Counts"), ("does_not_mean", "Does not mean")]),
    ("roles", "Roles", [
        ("entity", "Entity"), ("role", "Role"), ("basis", "Basis"), ("confidence", "Confidence"),
        ("admiralty", "Admiralty")]),
    ("incident_timeline", "Incident Timeline", [
        ("id", "ID"), ("when", "When (UTC)"), ("event", "Event"), ("proves", "Proves"),
        ("not_proven", "Not proven"), ("evidence", "Evidence"), ("kind", "Kind")]),
    ("attack_mapping", "ATT&CK Mapping", [
        ("id", "MAP"), ("technique_id", "Technique ID"), ("technique", "Technique"),
        ("tactic", "Tactic"), ("chain", "Chain"), ("status", "Status"), ("evidence", "Evidence"),
        ("limits", "Limits")]),
    ("scenarios", "Scenarios", [
        ("id", "ID"), ("title", "Title"), ("feasibility", "Feasibility"), ("impact", "Impact"),
        ("narrative", "Narrative"), ("controls", "Controls")]),
    ("roadmap", "Recommendations", [
        ("action", "Action"), ("owner", "Owner"), ("done_when", "Done when")]),
    ("open_questions", "Open Questions", [
        ("id", "OQ"), ("question", "Question"), ("decision_at_stake", "Decision at stake"),
        ("sources_needed", "Sources needed"),
        (lambda r: _window(r), "Window"), ("owner", "Owner")]),
    ("client_seeds", "Client-provided details", [
        ("type", "Type"), ("value", "Value"), ("note", "Note"),
        (lambda r: "yes" if r.get("sensitive") else "no", "Sensitive")]),
    ("qa_warnings", "Appendix — QA Warnings", []),
    ("sources_checked", "Appendix — Sources Checked", [
        (("source_class", "source", "tool", "name"), "Source"), (("selector", "target", "query"), "Selector"),
        ("calls", "Calls"), (lambda r: _checked_hits(r), "Hits"), (lambda r: _checked_status(r), "Status"),
        (("first", "first_utc", "first_seen"), "First (UTC)"),
        (("last", "last_utc", "last_seen"), "Last (UTC)")]),
]
SECTION = {k: (t, cols) for k, t, cols in SECTIONS}
PRIORITY_HEADINGS = [("P1", "P1 — this week"), ("P2", "P2 — this month"), ("P3", "P3 — ongoing")]

# a sources-checked row whose call ran but whose result count was never recorded is neither a hit nor
# a zero — rendered as such, never folded into either
UNRECORDED = "n/r — ran, result count not recorded"


def _checked_status(row):
    status = str(row.get("status") or "").lower()
    if status == "unknown" or (status in ("", "hit", "zero") and row.get("hits") == "unknown"):
        return UNRECORDED
    return status or None


def _checked_hits(row):
    hits = row.get("hits")
    return "n/r" if hits == "unknown" or str(row.get("status") or "").lower() == "unknown" else hits


def _window(row):
    a, b = row.get("window_start"), row.get("window_end")
    if a and b:
        return f"{a} – {b}"
    return a or b or None


def rows(data, key):
    val = data.get(key) if isinstance(data, dict) else None
    return [r for r in val if isinstance(r, dict)] if isinstance(val, list) else []


def cell(row, field):
    if callable(field):
        val = field(row)
    elif isinstance(field, tuple):
        val = next((row.get(k) for k in field if row.get(k) not in (None, "", [])), None)
    else:
        val = row.get(field)
    if val is None or val == "" or val == []:
        return "—"
    if isinstance(val, (list, tuple)):
        return "; ".join(str(v) for v in val if v not in (None, ""))
    if isinstance(val, dict):
        return json.dumps(val, ensure_ascii=False)
    return str(val)


def roadmap_groups(data):
    """[(heading, rows)] in P1, P2, P3 order; rows with another/no priority go last ('Unprioritised')."""
    items, out = rows(data, "roadmap"), []
    for code, heading in PRIORITY_HEADINGS:
        grp = [r for r in items if str(r.get("priority") or "").upper() == code]
        if grp:
            out.append((heading, grp))
    rest = [r for r in items if str(r.get("priority") or "").upper() not in dict(PRIORITY_HEADINGS)]
    if rest:
        out.append(("Unprioritised", rest))
    return out


def gap_strings(open_questions):
    """The flat `intelligence_gaps` strings older consumers read, derived from structured OQ rows."""
    out = []
    for r in open_questions or []:
        if not isinstance(r, dict) or not r.get("question"):
            continue
        text = (f"{r['id']}: " if r.get("id") else "") + str(r["question"]).strip()
        extra = []
        if r.get("decision_at_stake"):
            extra.append(f"decision at stake: {r['decision_at_stake']}")
        if r.get("sources_needed"):
            sn = r["sources_needed"]
            extra.append("sources needed: " + (", ".join(map(str, sn)) if isinstance(sn, list) else str(sn)))
        if _window(r):
            extra.append(f"window: {_window(r)}")
        if r.get("owner"):
            extra.append(f"owner: {r['owner']}")
        out.append(text + (" — " + "; ".join(extra) if extra else ""))
    return out


# ------------------------------------------------------------------ identity card / client seeds
def _norm_seed(v):
    return re.sub(r"[\s\-().]+", "", str(v or "")).lower()


def _identity_value(row):
    val = row.get("value")
    if val in (None, "", []):
        return None
    val = "; ".join(map(str, val)) if isinstance(val, list) else str(val)
    return f"{val} [{CLIENT_TAG}]" if row.get("client_provided") else val


def _blank_or_withheld(v):
    """Empty, or already the WITHHELD marker (also after cti_text_normalize turned its dash ASCII)."""
    return v in (None, "", []) or re.sub(r"[^a-z]", "", str(v).lower()) == re.sub(r"[^a-z]", "", WITHHELD)


def withhold_client(data, show=False):
    """Mark identity rows whose value the client supplied (`client_provided`), and — unless `show` — replace
    every SENSITIVE client-seed value, and any identity row carrying the same value, by WITHHELD.
    Mutates `data` in place (idempotent) and returns it; `sensitive_shown` records the choice."""
    if not isinstance(data, dict):
        return data
    seeds = rows(data, "client_seeds")
    sensitive = {_norm_seed(s.get("value")) for s in seeds
                 if s.get("sensitive") and not _blank_or_withheld(s.get("value"))}
    provided = {_norm_seed(s.get("value")) for s in seeds if not _blank_or_withheld(s.get("value"))}
    provided |= sensitive
    show = bool(show or data.get("sensitive_shown"))
    for r in rows(data, "subject_profile"):
        key = _norm_seed(r.get("value"))
        if key and (key in provided or "client" in str(r.get("source") or "").lower()):
            r["client_provided"] = True
        if not show and key in sensitive:
            r["value"] = WITHHELD
    if not show:
        for s in seeds:
            if s.get("sensitive") and s.get("value") not in (None, ""):
                s["value"] = WITHHELD
    data["sensitive_shown"] = show
    return data


def scrub_withheld(texts, data, raw_values):
    """Replace each raw sensitive client value inside free text (lint messages) by WITHHELD unless
    the report shows sensitive values. `raw_values` are the pre-withholding values."""
    if data.get("sensitive_shown"):
        return list(texts)
    vals = sorted({str(v) for v in raw_values if not _blank_or_withheld(v)}, key=len, reverse=True)
    out = []
    for t in texts:
        for v in vals:
            t = re.sub(re.escape(v), WITHHELD, t, flags=re.I)
        out.append(t)
    return out


def identity_cards(data):
    """[(entity, rows)] — one card per entity in first-seen order, rows in FIELD_ORDER (unknown
    fields as 'other'), rows without a value dropped."""
    cards = {}
    for r in rows(data, "subject_profile"):
        if r.get("value") in (None, "", []):
            continue
        cards.setdefault(str(r.get("entity") or "Subject"), []).append(r)
    rank = {f: i for i, f in enumerate(FIELD_ORDER)}
    return [(ent, sorted(rs, key=lambda r: rank.get(str(r.get("field") or "").lower(), rank["other"])))
            for ent, rs in cards.items()]


def engagement_items(data):
    eng = data.get("engagement") if isinstance(data, dict) else None
    if not isinstance(eng, dict):
        return []
    return [(label, str(eng[k])) for k, label in ENGAGEMENT_FIELDS if eng.get(k) not in (None, "")]


def apply_engagement(data):
    """The cover page reads case.analyst: an engagement author is that analyst."""
    eng = data.get("engagement") if isinstance(data, dict) else None
    if isinstance(eng, dict) and eng.get("author"):
        data.setdefault("case", {})["analyst"] = str(eng["author"])
    return data


def _engine_report_sections():
    import os  # noqa: PLC0415
    home = os.environ.get("INTEL_HOME") or os.path.normpath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "intel_engine"))
    tools = os.path.join(home, "tools")
    if tools not in sys.path:
        sys.path.insert(0, tools)
    import report_sections  # noqa: PLC0415
    return report_sections


def qa_lint(sections, findings=None, who="report"):
    """The engine's report_sections.lint over `sections`; [] (with a stderr note) when unavailable."""
    try:
        lint = getattr(_engine_report_sections(), "lint")
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"{who}: report_sections.lint unavailable ({exc}); QA warnings not computed.\n")
        return []
    try:
        out = lint(sections, findings=findings) or []
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"{who}: report_sections.lint failed ({exc}).\n")
        return []
    return [str(w) for w in out if w]


def ensure_qa_warnings(data, who="report"):
    """Fill `qa_warnings` on a hand-authored report JSON that lacks it (build_report_data already
    carries them), printing each to stderr. Returns `data`."""
    if isinstance(data, dict) and "qa_warnings" not in data:
        data["qa_warnings"] = qa_lint(data, data.get("findings"), who)
        for w in data["qa_warnings"]:
            sys.stderr.write(f"{who}: QA WARNING — {w}\n")
    return data


def prepare(data, who="report"):
    """Everything a generator does to a loaded report JSON before rendering: withhold sensitive
    client values (unless the builder recorded --show-sensitive), cover analyst from the engagement,
    metric + QA warnings for a hand-authored file."""
    withhold_client(data)
    apply_engagement(data)
    ensure_metric_warnings(data, who)
    ensure_qa_warnings(data, who)
    return data


# ------------------------------------------------------------------ anti-inflation check
_METRIC_FALLBACK = {
    "entity_terms": ["account", "accounts", "user", "users", "victim", "victims", "host", "hosts",
                     "record", "records", "people", "person"],
    "non_entity_units": ["token", "tokens", "credential", "credentials", "byte", "bytes",
                         "chain", "chains", "attack_chain", "attack_chains", "line", "lines"],
    "attempted_terms": ["attempted", "attempt", "attempts", "unproven", "unconfirmed", "attempted_unproven"],
    "confirmed_terms": ["confirmed", "verified", "proven", "observed"],
    "unit_fields": ["unit", "source", "counts"],
}
_RULES = None


def _rules():
    global _RULES
    if _RULES is None:
        ref = load_ref("report_metrics.json", _METRIC_FALLBACK)
        _RULES = {k: ({str(v).lower() for v in ref[k]} if k != "unit_fields" else list(ref[k]))
                  for k in _METRIC_FALLBACK}
    return _RULES


def _words(text):
    """Lower-cased words of a label, plus each adjacent pair joined by '_' (attack_chain)."""
    w = [x for x in re.split(r"[^0-9a-z]+", str(text or "").lower()) if x]
    return set(w) | {f"{a}_{b}" for a, b in zip(w, w[1:])}


def _norm_value(v):
    if isinstance(v, (dict, list)):
        return json.dumps(v, ensure_ascii=False, sort_keys=True)
    return str(v).strip().lower()


def _label(row):
    return str(row.get("metric") or row.get("label") or row.get("name") or "unnamed metric")


def validate_metrics(data):
    """Warnings for headline counts that read bigger than what was counted. Never mutates `data`.

    Reads `metrics[]` ({metric, value, unit|source|counts, values[], status, components[]}) and
    `counting_rules[]` ({metric, counts, does_not_mean}). Warns when
      * the label implies entities (accounts/victims/hosts/records) but the unit is tokens,
        credentials, bytes, attack chains … (a counting rule with a `does_not_mean` is the remedy);
      * the counted `values` hold duplicates, or two metrics of one unit count the same value;
      * attempted and confirmed outcomes are summed into one number.
    """
    R = _rules()
    warns = []

    def unit_words(row):
        return set().union(*(_words(row.get(f)) for f in R["unit_fields"]))

    disclaimed = {_label(r).lower() for r in rows(data, "counting_rules") if r.get("does_not_mean")}

    for r in rows(data, "metrics"):
        label, val = _label(r), r.get("value")
        shown = f"'{label}'" + (f" = {val}" if val is not None else "")
        units = unit_words(r) & R["non_entity_units"]
        if (_words(label) & R["entity_terms"]) and units and label.lower() not in disclaimed:
            u = sorted(units)[0]
            warns.append(f"metric {shown} counts {u}, but its label implies "
                         f"{'/'.join(sorted(_words(label) & R['entity_terms']))} — {u} are not one "
                         "entity each; report the distinct-entity count or relabel, and add a "
                         "counting rule stating what it does not mean.")
        vals = r.get("values")
        if isinstance(vals, list) and vals:
            distinct = len({_norm_value(v) for v in vals})
            if distinct < len(vals):
                warns.append(f"metric {shown} counts {len(vals)} value(s) but only {distinct} are "
                             f"distinct — {len(vals) - distinct} duplicate credential/key value(s) "
                             "counted more than once.")
            elif isinstance(val, (int, float)) and val > len(vals):
                warns.append(f"metric {shown} is larger than the {len(vals)} value(s) listed for it.")
        statuses = {str(r.get("status") or "").lower()}
        for c in r.get("components") or []:
            if isinstance(c, dict):
                statuses |= {str(c.get("status") or "").lower()} | _words(c.get("label") or c.get("metric"))
        statuses |= _words(label)
        if statuses & R["attempted_terms"] and (statuses & R["confirmed_terms"] or "mixed" in statuses):
            warns.append(f"metric {shown} sums attempted and confirmed outcomes — report them as "
                         "separate numbers.")
        elif "mixed" in statuses:
            warns.append(f"metric {shown} has status 'mixed' — split attempted from confirmed.")

    # the same value counted under two metrics of one unit
    seen = {}
    for r in rows(data, "metrics"):
        vals = r.get("values")
        if not isinstance(vals, list):
            continue
        key = frozenset(unit_words(r) & R["non_entity_units"]) or frozenset(["?"])
        for v in {_norm_value(x) for x in vals}:
            seen.setdefault((key, v), []).append(_label(r))
    pairs = {}
    for labels in seen.values():
        if len(set(labels)) > 1:
            k = tuple(sorted(set(labels)))
            pairs[k] = pairs.get(k, 0) + 1
    for labels, n in sorted(pairs.items()):
        warns.append(f"{n} value(s) are counted in more than one metric ({', '.join(labels)}) — "
                     "do not add these metrics together.")

    for r in rows(data, "counting_rules"):
        label = _label(r)
        if r.get("does_not_mean"):
            continue
        units = _words(r.get("counts")) & R["non_entity_units"]
        if (_words(label) & R["entity_terms"]) and units:
            warns.append(f"counting rule '{label}' counts {sorted(units)[0]} under an entity label "
                         "and states no 'does_not_mean' — say what the number is not.")
    return warns


def ensure_metric_warnings(data, who="report"):
    """Fill `metric_warnings` on a report JSON that lacks it (a hand-authored file) and print each
    warning to stderr; a report from build_report_data already carries them. Returns `data`."""
    if isinstance(data, dict) and "metric_warnings" not in data:
        data["metric_warnings"] = validate_metrics(data)
        for w in data["metric_warnings"]:
            sys.stderr.write(f"{who}: METRIC WARNING — {w}\n")
    return data
