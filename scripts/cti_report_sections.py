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
  display_rows(data, key)       -> rows ready to render: the risk / threat / person sections sorted
                                   and labelled as the house report shows them (others = rows())
  section_note(data, key)       -> the intro sentence of a section ('' when none); the leak-claim
                                   tally "Of N … claims naming the subject, K are proven"
  claim_tally(rows)             -> (N claims, K proven) — K counts only `proven` literally true
  risk_overall(data) / rating_scales(data) -> the organisation risk object, house-report wording
  nothing_found(data)           -> (negative_checks rows, ["<source>: no results for …"] zero-hit lines)
  counts_only(data)             -> affiliate_exposure rows cut to their named count fields
  figures(data, group, base)    -> [(name, png bytes, caption)] for card maps / affiliate-exposure
                                   charts in `report_figures` that pass resolve_figure (a PNG under the
                                   size cap inside the report JSON's dir or the case report/ dir), read
                                   once through one no-follow descriptor — renderers embed these bytes
                                   and never reopen the path
  triage_exposure(data)         -> exposure charts drawn from stealer-log triage (no affiliate rows):
                                   rendered under EXPOSURE_TRIAGE_TITLE
  actor_blocks(data)            -> [(heading, [("p", text) | ("bullets", [..]) | ("table", cols, rows)])] of
                                   the "Actor Profile" chapter in house order ([] when no actor section);
                                   attribution always with its likelihood term + confidence, every dissent line

Every row is the analyst's judgement for the report only: a role, a scenario or a timeline entry is
not a KB edge and never names an operator on a single signal (RULE 5).
"""
import json
import os
import re
import stat
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
    ("risk_assessment", "Overall Risk", [
        ("name", "Domain"), (lambda r: _score(r.get("score")), "Score"), ("level", "Level"),
        ("main_issue", "Main issue")]),
    ("rating_scales", "Rating Scales", []),
    ("key_findings", "Key Findings — Severity and Priority", [
        ("n", "#"), ("finding", "Finding"), ("severity", "Severity"), ("priority_label", "Priority")]),
    ("affiliate_exposure", "Affiliate Exposure — Infected Computers", [
        ("org", "Organisation"), ("country", "Country"), ("infected_hosts", "Infected computers"),
        (lambda r: str(r.get("latest_infection") or "")[:10], "Latest infection"),
        ("stealer_family", "Stealer family"), ("portal", "Portal exposed")]),
    ("leak_claims", "Dark-web and Telegram Claims", [
        (lambda r: str(r.get("date") or "")[:10], "Date"), ("actor", "Actor"), ("venue", "Venue"),
        ("claim", "Claim"), (lambda r: "Proven" if r.get("proven") is True else "Unconfirmed", "Status"),
        ("evidence", "Evidence")]),
    ("email_services", "Services Registered by E-mail", [
        ("email", "E-mail"), ("service", "Service"), ("evidence", "Evidence"),
        (lambda r: str(r.get("date") or "")[:10], "Date")]),
    ("threat_events", "Events That Raise the Threat", [
        (lambda r: _event_dates(r), "Dates"), ("event", "Event"), ("location", "Location"),
        ("why_it_raises_risk", "Why it raises the risk"), ("local_legal_notes", "Local legal notes"),
        ("grade", "Grade")]),
    ("usernames_to_reserve", "Usernames to Reserve", [
        ("platform", "Platform"), ("handle", "Handle"),
        (lambda r: RESERVE_LABEL.get(r.get("status"), str(r.get("status") or "").replace("_", " ")), "Status")]),
    ("negative_checks", "Checked — Nothing Found", [
        ("check", "Check"), ("scope", "Scope"), (lambda r: r.get("result") or "no record", "Result"),
        (lambda r: str(r.get("date") or "")[:10], "Date")]),
    # actor threat-profile chapter (ACTOR_TITLE) — block headings, house-report wording
    ("claim_confidence", "Source Basis and Confidence", [
        ("claim", "Claim"), (lambda r: str(r.get("confidence") or "").replace("_", " "), "Confidence"),
        ("rationale", "Rationale"), ("sources", "Sources")]),
    ("pivot_opportunities", "Infrastructure and Defensive Pivots", [
        ("seed_artifact", "Seed artifact"), ("pivot_question", "Pivot question"),
        ("defensive_use", "Defensive use")]),
    ("playbook", "Operational Playbook", [
        ("tactic", "Tactic"), ("behaviours", "Behaviours"), ("attack_ids", "ATT&CK"), ("evidence", "Evidence")]),
    ("attack_coverage", "ATT&CK Coverage", [
        ("technique_id", "Technique"), ("tactics", "Tactic"),
        (lambda r: "yes" if r.get("playbook") else "", "Playbook"), ("hunts", "Hunt hypotheses"),
        ("mappings", "Incident mapping")]),
    ("hunt_hypotheses", "Hunt Hypotheses", [
        ("id", "HH"), ("hypothesis", "Hypothesis"), ("priority_telemetry", "Priority telemetry"),
        ("behavioural_signals", "Behavioural signals"), ("attack_ids", "ATT&CK"),
        ("hunt_package_ref", "Hunt package")]),
    ("telemetry_priorities", "Priority Telemetry", [("source", "Source"), ("why", "Why")]),
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


# ------------------------------------------------------------------ risk / threat / person sections
# House-report wording (intel_engine/tools/house_report_sections.py), so both report paths read alike.
RESERVE_LABEL = {"available": "Available — register it now",
                 "taken_by_other": "Taken by another account — monitor for impersonation",
                 "reserved": "Already reserved by the subject"}
THREAT_EVENTS_NOTE = ("Dated events in the coming period that attract attackers, protesters or opportunistic "
                      "fraud towards the subject — plan monitoring and staffing around them.")
NOTHING_FOUND_NOTE = ("Each check below ran and returned no record. A negative result is true at the date of "
                      "the check; it bounds what this report claims and is not proof that no record exists.")
RISK_NOTE = ("Each domain is rated by the analyst for exploitability and harm and mapped onto a fixed "
             "0–{smax} scale (see Rating Scales). A score is analyst judgement, not a probability.")
WITHHELD_EMAIL = "(withheld)"
# affiliate_exposure: COUNTS ONLY — any other field (a credential, cookie, URL with a token) is dropped
COUNT_FIELDS = ("org", "country", "infected_hosts", "latest_infection", "stealer_family", "portal",
                "import_record")
# report_figures groups -> (figure name, caption) in render order; captions follow the house report
FIGURE_CAPTIONS = {
    "card_maps": [
        ("person", "Connections of the subject: the people, organisations, accounts and places the analyst "
                   "linked to them, grouped by kind, each graded on the Admiralty scale; dashed = unconfirmed."),
        ("threats", "Threat actors reported against the organisation, one panel per kind of actor, each graded "
                    "on the Admiralty scale; dashed = unconfirmed."),
        ("suppliers", "Third-party suppliers seen in public records (DNS verification records, mail routing, "
                      "certificates, documents); a dashed card is a low-confidence inference, not a confirmed "
                      "contract.")],
    "exposure_charts": [
        ("fig_exposure_year", "Infected computers by year of infection — counts only"),
        ("fig_exposure_country", "Infected computers by country — counts only"),
        ("fig_exposure_family", "Infected computers by stealer family — counts only")],
}
EXPOSURE_TRIAGE_TITLE = "Infected Computers — Stealer-Log Triage"
EXPOSURE_TRIAGE_NOTE = ("Counts only, one infected computer per stealer log triaged in this case; no "
                        "affiliate-exposure rows were recorded, so no organisation is named. No credential, "
                        "cookie or password from the logs is reproduced.")
_RESERVE_ORDER = {"available": 0, "taken_by_other": 1, "reserved": 2}


def _real(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _score(v):
    return f"{float(v):.1f}" if _real(v) else "—"


def _num(v):
    if isinstance(v, float) and v.is_integer():
        v = int(v)
    return f"{v:,}" if _real(v) else str(v)


def _score_max():
    try:
        return _num(_engine_report_sections().RISK["score_max"])
    except Exception:  # noqa: BLE001 — engine not vendored: the C1 scale is 0-10
        return "10"


def _event_dates(r):
    s, e = str(r.get("start") or "")[:10], str(r.get("end") or "")[:10]
    return f"{s} – {e}" if e and e != s else s


def withheld_email(v):
    """'(withheld)@domain' — the domain kept, the mailbox never printed; idempotent."""
    s = str(v or "").strip()
    if s.startswith(WITHHELD_EMAIL):
        return s
    return WITHHELD_EMAIL + (s[s.rindex("@"):] if "@" in s else "")


def claim_tally(rows_):
    """(N claims, K proven) — K counts only rows whose `proven` is literally true."""
    rs = [r for r in (rows_ or []) if isinstance(r, dict)]
    return len(rs), sum(1 for r in rs if r.get("proven") is True)


def counts_only(data):
    """Cut every affiliate_exposure row to COUNT_FIELDS in place (a hand-authored JSON may carry a
    credential or cookie column; it must not even reach the HTML's embedded data). Returns `data`."""
    if isinstance(data, dict) and isinstance(data.get("affiliate_exposure"), list):
        data["affiliate_exposure"] = [{k: r[k] for k in COUNT_FIELDS if k in r}
                                      for r in data["affiliate_exposure"] if isinstance(r, dict)]
    return data


def _risk(data):
    ra = data.get("risk_assessment") if isinstance(data, dict) else None
    return ra if isinstance(ra, dict) and [d for d in ra.get("domains") or [] if isinstance(d, dict)] else {}


def risk_overall(data):
    """(summary sentence, coverage warning, unrated sentence) of the organisation risk object, or
    None when it has no rated domain. Domain rows: display_rows(data, 'risk_assessment')."""
    ra = _risk(data)
    if not ra:
        return None
    doms = [d for d in ra["domains"] if isinstance(d, dict)]
    ov = ra.get("overall") if isinstance(ra.get("overall"), dict) else {}
    cov = ra.get("coverage") if isinstance(ra.get("coverage"), dict) else {}
    rated = cov.get("rated") if _real(cov.get("rated")) else len(doms)
    total = cov.get("total") if _real(cov.get("total")) else rated
    line = (f"Overall risk score: {ov.get('level') or '—'} ({_score(ov.get('score'))}/{_score_max()}), "
            f"mean of {_num(rated)} of {_num(total)} rated domains. " + RISK_NOTE.format(smax=_score_max()))
    unrated = [str(u).replace("_", " ") for u in (cov.get("unrated") or []) if str(u).strip()]
    return (line, str(cov.get("warning") or ""),
            ("Not rated (no evidence either way): " + ", ".join(unrated) + ".") if unrated else "")


def _band_range(lo, hi, smax):
    if isinstance(lo, list) and len(lo) == 2:
        return f"{_num(lo[0])} – {_num(lo[1])}"
    if isinstance(lo, dict):
        return f"{_num(lo.get('min', '—'))} – {_num(lo.get('max', '—'))}"
    return f"{_score(lo)} – {smax}" if hi is None else f"{_score(lo)} to below {_score(hi)}"


def rating_scales(data):
    """([(risk level, score range)], [(priority, act within)]) — bands highest first; ([], []) when none."""
    ra = _risk(data)
    bands = ra.get("bands") if isinstance(ra.get("bands"), dict) else {}
    prio = ra.get("priorities") if isinstance(ra.get("priorities"), dict) else {}
    smax = _score_max()
    scalar = bool(bands) and all(_real(v) for v in bands.values())
    order = sorted(bands, key=lambda k: -bands[k]) if scalar else list(bands)
    band_rows = [(str(k), _band_range(bands[k], bands[order[i - 1]] if scalar and i else None, smax))
                 for i, k in enumerate(order)]
    return band_rows, [(str(k), str(v)) for k, v in sorted(prio.items())]


def display_rows(data, key):
    """Rows of `key` sorted / labelled as the house report shows them; rows() for the other sections."""
    if key == "risk_assessment":
        doms = [d for d in _risk(data).get("domains") or [] if isinstance(d, dict)]
        return sorted(doms, key=lambda d: (-(d["score"] if _real(d.get("score")) else -1), str(d.get("name") or "")))
    rs = rows(data, key)
    if key == "key_findings":
        prio = _risk(data).get("priorities") or {}
        prio = prio if isinstance(prio, dict) else {}
        label = _engine_attr("priority_label") or (lambda p, _prio: str(p or ""))
        return [dict(r, priority_label=label(r.get("priority"), prio))
                for r in sorted(rs, key=lambda r: r["n"] if _real(r.get("n")) else 1e9)]
    if key == "affiliate_exposure":
        return sorted(rs, key=lambda r: (-(r["infected_hosts"] if _real(r.get("infected_hosts")) else 0),
                                         str(r.get("org"))))
    if key == "leak_claims":
        return sorted(rs, key=lambda r: str(r.get("date") or ""))
    if key == "threat_events":
        return sorted(rs, key=lambda r: (str(r.get("start") or ""), str(r.get("event") or "")))
    if key == "usernames_to_reserve":
        return sorted(rs, key=lambda r: (_RESERVE_ORDER.get(r.get("status"), 9), str(r.get("platform"))))
    if key == "email_services":
        return sorted(rs, key=lambda r: (str(r.get("email")).lower(), str(r.get("service")).lower()))
    if key == "playbook":
        rank = _engine_attr("tactic_rank")
        return sorted(rs, key=lambda r: rank(r.get("tactic"))) if rank else rs
    if key == "hunt_hypotheses":
        return sorted(rs, key=lambda r: [int(x) if x.isdigit() else x for x in re.split(r"(\d+)", str(r.get("id")))])
    if key == "attack_coverage" and not rs:
        derive = _engine_attr("attack_coverage")
        return derive(data) if derive and (rows(data, "playbook") or rows(data, "hunt_hypotheses")) else []
    return rs


# ------------------------------------------------------------------ actor threat-profile chapter
# House-report wording (house_report_sections.actor_profile); structure adapted from
# [PK Packt ACTIH companion repo, 2026, chapter-03 threat-profile deliverable].
ACTOR_TITLE = "Actor Profile"
ACTOR_KEYS = ("actor_profile", "claim_confidence", "pivot_opportunities", "playbook", "hunt_hypotheses",
              "telemetry_priorities")
ATTRIBUTION_NOTE = ("The attribution is analyst judgement for this report: it is not a knowledge-base "
                    "edge or a same-operator link (RULE 5), and a threat score is a lead, not attribution.")
ACTOR_NOTES = {
    "claim_confidence": ("Each claim this profile makes, with the analyst's confidence in it and why. A High "
                         "rating must cite its sources."),
    "pivot_opportunities": "Artifacts a defender can pivot on. A hit is a lead to investigate, not a same-operator link.",
    "playbook": "Behaviours by ATT&CK tactic, in tactic order.",
    "attack_coverage": ("Every technique the playbook or a hunt hypothesis names, with the incident ATT&CK mapping "
                        "rows that evidence the same technique in this case."),
}
ALIAS_COLS = [("name", "Alias"), ("source", "Source")]
ACTIVITY_COLS = [("when", "When"), ("event", "Activity"), ("sources", "Sources")]
VICTIM_COLS = [(0, "Dimension"), (1, "Observed targeting")]


def _telemetry_why(r):
    """'Why', plus ' — Windows audit setting: …' when baseline_ref resolves in the telemetry-baseline map
    (REPORT.json's carried baseline_setting when the engine is unavailable); a row with no ref or an
    unresolved one prints its Why unchanged."""
    resolve = _engine_attr("telemetry_baseline_setting")
    st = (resolve(r.get("baseline_ref")) if resolve else None) or r.get("baseline_setting")
    return f"{cell(r, 'why')} — Windows audit setting: {st}" if st else r.get("why")


TELEMETRY_COLS = [(lambda r: r.get("_n"), "#"), ("source", "Source"), (_telemetry_why, "Why")]


def _engine_attr(name):
    try:
        return getattr(_engine_report_sections(), name, None)
    except Exception:  # noqa: BLE001 — a missing engine keeps the analyst order
        return None


def _items(v):
    v = [v] if isinstance(v, str) else (v if isinstance(v, list) else [])
    return [str(x).strip() for x in v if str(x).strip()]


def attribution_text(att):
    """(assessment sentence or '', [dissent lines]) — the assessment always carries its likelihood term
    and confidence; an absent one is said to be absent, never dropped (RULE 5)."""
    att = att if isinstance(att, dict) else {}
    line = ""
    if str(att.get("assessment") or "").strip():
        lk = str(att.get("likelihood") or "").strip() or "likelihood term not stated"
        cf = str(att.get("confidence") or "").strip()
        cf = (cf if cf.lower().endswith("confidence") else f"{cf} confidence") if cf else "confidence not stated"
        line = f"Assessment: {str(att['assessment']).strip()} — {lk}, {cf}."
    return line, _items(att.get("dissent"))


def threat_score_text(ts):
    ts = ts if isinstance(ts, dict) else {}
    if ts.get("threat_score") in (None, ""):
        return ""
    # posture may be a list of recommended actions: joined with '; ', never printed as a Python list
    bits = [_num(ts["threat_score"])] + [
        f"{k} {'; '.join(_items(ts[k])) if isinstance(ts[k], list) else ts[k]}"
        for k in ("band", "posture") if ts.get(k) and (_items(ts[k]) or not isinstance(ts[k], list))]
    return "Threat score (analyst lead, not attribution): " + " · ".join(bits) + " — from the case's actor scoring."


def has_actor_profile(data):
    return isinstance(data, dict) and (bool(data.get("actor_profile")) or any(rows(data, k) for k in ACTOR_KEYS[1:]))


def actor_blocks(data):
    """[(heading, [item])] of the Actor Profile chapter in house order; [] when no actor section is
    present. item = ("p", text) | ("bullets", [text]) | ("table", cols, rows)."""
    if not has_actor_profile(data):
        return []
    ap = data.get("actor_profile") if isinstance(data.get("actor_profile"), dict) else {}
    out = []

    def add(title, items):
        items = [i for i in items if i and (i[0] != "table" or i[2])]
        if items:
            out.append((title, items))

    def table(key):
        return ("table", SECTION[key][1], display_rows(data, key))

    def note(key):
        return ("p", ACTOR_NOTES[key]) if display_rows(data, key) else None

    add("Executive Line", [("p", f"Threat profile of {ap['name']}.") if ap.get("name") else None,
                           ("p", str(ap["executive_line"])) if ap.get("executive_line") else None,
                           ("p", threat_score_text(ap.get("threat_score"))) if threat_score_text(ap.get("threat_score")) else None])
    add(SECTION["claim_confidence"][0], [note("claim_confidence"), table("claim_confidence")])
    line, dissent = attribution_text(ap.get("attribution"))
    timeline = sorted((t for t in ap.get("activity_timeline") or [] if isinstance(t, dict)),
                      key=lambda t: str(t.get("when") or ""))
    add("Actor Overview", [("table", ALIAS_COLS, [a for a in ap.get("aliases") or [] if isinstance(a, dict)]),
                           ("p", line) if line else None,
                           ("p", "Dissent and alternative views:") if dissent else None,
                           ("bullets", dissent) if dissent else None,
                           ("p", ATTRIBUTION_NOTE) if (line or dissent) else None,
                           ("table", ACTIVITY_COLS, timeline)])
    intent = ap.get("intent") if isinstance(ap.get("intent"), dict) else {}
    if _items(intent.get("motivations")) or _items(intent.get("evidence")):
        add("Intent", [("p", "Motivations: " + ("; ".join(_items(intent.get("motivations"))) or "—")),
                       ("p", "Evidence: " + ("; ".join(_items(intent.get("evidence"))) or "—"))])
    cap = ap.get("capability") if isinstance(ap.get("capability"), dict) else {}
    if str(cap.get("summary") or "").strip() or _items(cap.get("evidence")):
        add("Capability", [("p", str(cap.get("summary") or "").strip() or "—"),
                           ("p", "Evidence: " + ("; ".join(_items(cap.get("evidence"))) or "—"))])
    vic = ap.get("victimology") if isinstance(ap.get("victimology"), dict) else {}
    add("Victimology", [("table", VICTIM_COLS,
                         [{0: label, 1: "; ".join(_items(vic.get(k)))}
                          for k, label in (("sectors", "Sectors"), ("geographies", "Geographies"),
                                           ("data_targeted", "Data targeted")) if _items(vic.get(k))])])
    add("Persona & OPSEC", [("bullets", _items(ap.get("persona_opsec"))) if _items(ap.get("persona_opsec")) else None])
    add("Tempo", [("p", str(ap["tempo_summary"]).strip()) if str(ap.get("tempo_summary") or "").strip() else None,
                  ("p", f"Tempo analysis: {str(ap['tempo_ref']).strip()} (case timeline).")
                  if str(ap.get("tempo_ref") or "").strip() else None])
    for key in ("pivot_opportunities", "playbook", "attack_coverage"):
        add(SECTION[key][0], [note(key), table(key)])
    add(SECTION["hunt_hypotheses"][0], [table("hunt_hypotheses")])
    add(SECTION["telemetry_priorities"][0],
        [("table", TELEMETRY_COLS, [dict(r, _n=i) for i, r in enumerate(rows(data, "telemetry_priorities"), 1)])])
    return out


def section_note(data, key):
    """The intro sentence the house report prints above a section ('' when it prints none)."""
    rs = rows(data, key)
    if key == "affiliate_exposure" and rs:
        total = sum(r["infected_hosts"] for r in rs if _real(r.get("infected_hosts")))
        return (f"{_num(total)} infected computer(s) recorded across {len(rs)} affiliated organisation(s). "
                "Counts only: no credential, cookie or password from the logs is reproduced in this report. "
                "An infected computer exposes the organisation's portals; it does not identify who used it.")
    if key == "leak_claims" and rs:
        n, k = claim_tally(rs)
        return (f"Of {n} dark-web/Telegram claims naming the subject, {k} are proven. An unconfirmed claim is "
                "an actor's statement, not a finding: it is listed so the reader knows it exists.")
    if key == "threat_events" and rs:
        return THREAT_EVENTS_NOTE
    if key == "usernames_to_reserve" and rs:
        free = sum(1 for r in rs if r.get("status") == "available")
        return ("Defensive recommendation: register the subject's handles before an impersonator does. "
                f"{free} of {len(rs)} handle(s) checked are still available.")
    if key == "email_services" and rs:
        return ("Services where an account exists for the e-mail address. An account shows the address was used "
                "to register; it does not show who registered it or that the account is active."
                + ("" if data.get("sensitive_shown") else
                   " E-mail addresses are withheld from this edition (domain kept)."))
    if key == "negative_checks":
        return NOTHING_FOUND_NOTE
    return ""


def nothing_found(data):
    """(negative_checks rows, zero-hit lines): the analyst's negative checks plus every sources_checked
    row with status 'zero', grouped by source class — the house 'Checked — nothing found'."""
    zero = {}
    for r in rows(data, "sources_checked"):
        if str(r.get("status") or "").lower() == "zero":
            sel = str(r.get("selector") or "")
            zero.setdefault(str(r.get("source_class") or r.get("source") or ""), []).append(
                "whole case" if sel in ("", "(case)") else sel)
    return rows(data, "negative_checks"), [f"{src}: no results for " + ", ".join(zero[src]) for src in sorted(zero)]


# report_figures containment: an embedded figure must be a PNG of bounded size inside the report JSON's
# directory or the case's report/ directory (a hand- or LLM-authored REPORT.json could otherwise pull
# any local file into a deliverable). Size cap in references/report_figures.json.
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_FIGURE_FALLBACK = {"figure_limits": {"max_bytes": 8 * 1024 * 1024}}
_CASE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_FIG_MAX = None


def figure_max_bytes():
    global _FIG_MAX
    if _FIG_MAX is None:
        lim = load_ref("report_figures.json", _FIGURE_FALLBACK).get("figure_limits")
        v = lim.get("max_bytes") if isinstance(lim, dict) else None
        _FIG_MAX = v if _real(v) and v > 0 else _FIGURE_FALLBACK["figure_limits"]["max_bytes"]
    return _FIG_MAX


def figure_roots(data, base=None):
    """Real directories a figure may come from: `base` (the report JSON's directory) and the case's
    report/ directory under the engine's cases/ tree (case.id must be a plain case id)."""
    roots = []
    if base:
        roots.append(os.path.realpath(base))
    cid = ((data.get("case") or {}) if isinstance(data, dict) else {}).get("id")
    if isinstance(cid, str) and _CASE_ID_RE.match(cid):
        home = os.environ.get("INTEL_HOME") or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "intel_engine")
        roots.append(os.path.realpath(os.path.join(home, "cases", cid, "report")))
    return roots


def _inside(real, roots):
    return any(real.startswith(r.rstrip(os.sep) + os.sep) for r in roots)


def resolve_figure(path, roots, base=None):
    """(png bytes, '') for a PNG of at most figure_max_bytes() inside one of `roots`; else (None, why).
    A relative path resolves against `base`; with no base it is refused. The file is opened ONCE
    (O_NOFOLLOW where available, so a final component swapped to a symlink after the containment check
    fails to open), the descriptor's own path is re-checked against `roots` where the OS exposes it
    (/proc/self/fd), fstat confirms a regular file under the cap, and at most cap+1 bytes are read —
    the signature, size and containment checks describe exactly the bytes returned. Never raises."""
    try:
        if not isinstance(path, str) or not path or "\x00" in path:
            return None, "no path"
        if not os.path.isabs(path):
            if not base:
                return None, "relative path with no report directory to resolve it against"
            path = os.path.join(base, path)
        real = os.path.realpath(path)
        if not _inside(real, roots):
            return None, "outside the report JSON's directory and the case report/ directory"
        cap = figure_max_bytes()
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) \
            | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
        fd = os.open(real, flags)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                return None, "not a file"
            if st.st_size > cap:
                return None, f"larger than {cap} bytes"
            proc = f"/proc/self/fd/{fd}"
            if os.path.islink(proc) and not _inside(os.readlink(proc), roots):
                return None, "outside the report JSON's directory and the case report/ directory"
            chunks, left = [], cap + 1
            while left > 0:
                b = os.read(fd, min(left, 1 << 20))
                if not b:
                    break
                chunks.append(b)
                left -= len(b)
        finally:
            os.close(fd)
        png = b"".join(chunks)
        if len(png) > cap:
            return None, f"larger than {cap} bytes"
        if not png.startswith(PNG_MAGIC):
            return None, "not a PNG"
        return png, ""
    except (OSError, ValueError) as exc:
        return None, f"unreadable ({exc.__class__.__name__})"


def figures(data, group, base=None):
    """[(name, png bytes, caption)] for `report_figures[group]` entries that pass resolve_figure; a
    relative path resolves against `base` (the report JSON's directory). A rejected figure is named
    on stderr and skipped, never embedded. Callers embed the returned bytes; they never reopen a path."""
    figs = (data.get("report_figures") or {}) if isinstance(data, dict) else {}
    got = figs.get(group) if isinstance(figs, dict) else None
    if not isinstance(got, dict):
        return []
    roots = figure_roots(data, base)
    out = []
    for name, caption in FIGURE_CAPTIONS.get(group, []):
        p = got.get(name)
        if not isinstance(p, str) or not p:
            continue
        png, why = resolve_figure(p, roots, base)
        if png:
            out.append((name, png, caption))
        else:
            sys.stderr.write(f"cti_report_sections: figure {group}/{name} skipped — {why}.\n")
    return out


def triage_exposure(data):
    """True when the exposure charts come from stealer-log triage (no affiliate_exposure rows): they
    render under EXPOSURE_TRIAGE_TITLE instead of under the (absent) Affiliate Exposure table."""
    figs = (data.get("report_figures") or {}) if isinstance(data, dict) else {}
    return (isinstance(figs, dict) and figs.get("exposure_source") == "triage"
            and not rows(data, "affiliate_exposure"))


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
    every SENSITIVE client-seed value, and any identity row carrying the same value, by WITHHELD, and
    every `email_services` address by '(withheld)@domain' (also inside `qa_warnings`).
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
        emails = set()
        for r in rows(data, "email_services"):
            if str(r.get("email") or "").strip() and not str(r["email"]).startswith(WITHHELD_EMAIL):
                emails.add(str(r["email"]).strip())
                r["email"] = withheld_email(r["email"])
        if emails and isinstance(data.get("qa_warnings"), list):
            data["qa_warnings"] = [scrub_values(w, emails, WITHHELD_EMAIL) for w in data["qa_warnings"]]
    data["sensitive_shown"] = show
    return data


def scrub_values(text, values, repl):
    """`text` with every value (longest first, case-insensitive) replaced by `repl`."""
    t = str(text)
    for v in sorted({str(v) for v in values if str(v or "").strip()}, key=len, reverse=True):
        t = re.sub(re.escape(v), repl, t, flags=re.I)
    return t


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
    counts_only(data)
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
    # a leak-claim tally carried in the JSON may not claim more than its rows mark proven
    tally = data.get("leak_claims_tally") if isinstance(data, dict) else None
    if isinstance(tally, dict) and rows(data, "leak_claims"):
        n, k = claim_tally(rows(data, "leak_claims"))
        if tally.get("claims") != n or tally.get("proven") != k:
            warns.append(f"leak_claims_tally says {tally.get('proven')} of {tally.get('claims')} claims are "
                         f"proven, but the rows mark {k} of {n} proven (`proven` true) — the rows win.")
    return warns


def ensure_metric_warnings(data, who="report"):
    """Fill `metric_warnings` on a report JSON that lacks it (a hand-authored file) and print each
    warning to stderr; a report from build_report_data already carries them. Returns `data`."""
    if isinstance(data, dict) and "metric_warnings" not in data:
        data["metric_warnings"] = validate_metrics(data)
        for w in data["metric_warnings"]:
            sys.stderr.write(f"{who}: METRIC WARNING — {w}\n")
    return data
