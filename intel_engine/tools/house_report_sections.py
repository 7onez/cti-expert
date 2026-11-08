#!/usr/bin/env python3
"""
house_report_sections.py — the analyst's structured report sections inside the house report.

evidence_import stores an optional `report` block beside the graded findings; report_sections.py
merges those blocks across imports and builds the case's sources-checked rows from its ledgers.
This module turns them into house markdown blocks that house_report.compose() places:

  key_questions       Executive Summary, right after the BLUF  (KQ · question · status · answer · confidence)
  findings_boundaries Findings — confirmation level + a "Not proven" line per graded finding
  counting_rules      Methodology — what each number counts and what it does not mean
  metrics             Methodology "Key counts" (metric · value · unit · status); values[] only COUNTED,
                      never printed (they may be tokens / credentials)
  incident_timeline   Infrastructure and lifecycle  (Tnnn · UTC · event · proves · not proven · evidence)
  attack_mapping      Infrastructure and lifecycle  (MAP · technique · tactic · status · limits)
  roles               Attribution — analyst judgement with the RULE 5 note
  scenarios           Alternative analysis — feasibility × impact + controls
  open_questions      Gaps and limitations  (OQ · question · decision at stake · sources needed · window)
  roadmap             Recommendations, grouped P1 (this week) / P2 (this month) / P3 (ongoing)
  sources_checked     Appendix — every source queried, ZERO HITS INCLUDED
  subject_profile     Executive Summary, after Key questions: "Subject identity card", one table per
                      entity, fields in a fixed order, empty fields omitted; client-provided values tagged
  client_seeds        Methodology "Client-provided details"; sensitive values withheld unless
                      --show-sensitive (also in the identity card and QA warnings)
  qa_warnings         Appendix "QA warnings" — report_sections.lint(); warn only, never blocks

An absent or empty section renders as "" — never a placeholder, never an invented row. Every
cell passes through the composer's own `scrub` (Rule 12 + third-party masking) and `esc`; URLs
are left bare so the composer's citation pass turns them into linked `[n]` (Rule 21).
"""
from __future__ import annotations

import re

import report_sections as rs_mod

CONFIRMATION_LABEL = {"confirmed": "Confirmed", "strong_indirect": "Strong indirect evidence",
                      "attempted_unproven": "Attempted — not proven", "unverified": "Unverified"}
PRIORITY_HEAD = {"P1": "Priority 1 — this week", "P2": "Priority 2 — this month",
                 "P3": "Priority 3 — ongoing"}
STATUS_LABEL = {"hit": "results", "zero": "**no results**", "error": "error",
                "skipped": "not run (blocked)", "unknown": "ran — result count not recorded"}
_URL_ONLY_RE = re.compile(r"^https?://\S+$")


def _words(v) -> str:
    return str(v or "").replace("_", " ")


def _ts(v) -> str:
    s = str(v or "")
    return s[:16].replace("T", " ") if s else "—"


class _Cells:
    def __init__(self, scrub, esc):
        self.scrub, self.esc = scrub, esc

    def text(self, v) -> str:
        s = str(v if v is not None else "").strip()
        return self.esc(self.scrub(s)) if s else "—"

    def refs(self, items) -> str:
        """A list of evidence refs: bare URLs stay bare (cited [n] by the composer), the rest scrubbed."""
        if isinstance(items, str):
            items = [items]
        out = [i.strip() if _URL_ONLY_RE.match(i.strip()) else self.text(i)
               for i in (items or []) if str(i).strip()]
        return "; ".join(out) or "—"

    def code(self, v) -> str:
        s = str(v or "").replace("`", "'").replace("|", "\\|")
        return f"`{self.scrub(s, escape=False)}`" if s else "—"


def key_questions(rows, C) -> str:
    if not rows:
        return ""
    L = ["## Key questions", "",
         "The questions this report was asked to answer, and how far the evidence answers each.", "",
         "| KQ | Question | Status | Answer | Confidence |", "|:-:|:----------------|:----|:--------------------|:----|"]
    for r in rows:
        ans = C.text(r.get("answer"))
        if r.get("refs"):
            ans += f" ({C.refs(r.get('refs'))})"
        L.append(f"| {C.text(r.get('id'))} | {C.text(r.get('question'))} | **{_words(r.get('status'))}** | "
                 f"{ans} | {C.text(_words(r.get('confidence')))} |")
    return "\n".join(L)


def findings_boundaries(rows, C, cited) -> str:
    if not rows:
        return ""
    L = ["## What the evidence does and does not prove", "",
         "Each graded finding with its confirmation level, and the boundary the evidence does not cross.", ""]
    for r in rows:
        grade = f", grade {r['admiralty']}" if r.get("admiralty") else ""
        level = CONFIRMATION_LABEL.get(r.get("confirmation") or "", "")
        head = cited(C.scrub(str(r.get("claim") or "")), [r["source_url"]] if r.get("source_url") else [])
        L.append(f"- {head}")
        if level or grade:
            L.append(f"  - *Confirmation:* {level or 'not stated'}{grade}")
        if r.get("not_proven"):
            L.append(f"  - *Not proven:* {C.text(r.get('not_proven'))}")
    return "\n".join(L)


def counting_rules(rows, C) -> str:
    if not rows:
        return ""
    L = ["## Counting rules", "", "What each number in this report counts — and what it must not be read as.", "",
         "| Metric | What it counts | What it does not mean |", "|:------|:----------------|:----------------|"]
    for r in rows:
        L.append(f"| {C.text(r.get('metric'))} | {C.text(r.get('counts'))} | {C.text(r.get('does_not_mean'))} |")
    return "\n".join(L)


def roles(rows, C) -> str:
    if not rows:
        return ""
    L = ["## Roles", "",
         "Roles are the analyst's judgement of each party's part in the activity. A role is not an "
         "attribution: no party is named as the operator on a single signal, and a role carries no more "
         "weight than the basis and confidence shown beside it.", "",
         "| Entity | Role | Basis | Confidence |", "|:------|:----|:--------------------|:----|"]
    for r in rows:
        conf = _words(r.get("confidence")) or "—"
        if r.get("admiralty"):
            conf += f" ({r['admiralty']})"
        L.append(f"| {C.text(r.get('entity'))} | **{_words(r.get('role'))}** | {C.text(r.get('basis'))} | "
                 f"{C.text(conf)} |")
    return "\n".join(L)


def _num(v) -> str:
    if isinstance(v, float) and v.is_integer():
        v = int(v)
    return f"{v:,}" if isinstance(v, (int, float)) and not isinstance(v, bool) else str(v)


def key_counts(rows, C) -> str:
    """Analyst headline counts. `values[]` may hold secrets (tokens, credentials): only its COUNT
    is ever printed, never an item."""
    if not rows:
        return ""
    listed = any(isinstance(r.get("values"), list) and r.get("values") for r in rows)
    L = ["## Key counts", "", "Each headline number with the unit it counts — read it with the counting rules above.", "",
         "| Metric | Value | Unit | Status |" + (" Items listed |" if listed else ""),
         "|:------------|--:|:------|:------|" + (":-:|" if listed else "")]
    for r in rows:
        metric = C.text(r.get("metric"))
        comps = [c for c in (r.get("components") or []) if isinstance(c, dict)]
        if comps:
            metric += " (" + "; ".join(f"{C.text(c.get('label'))} {_num(c.get('value'))}"
                                       + (f" {_words(c.get('status'))}" if c.get("status") else "")
                                       for c in comps) + ")"
        n = len(r["values"]) if isinstance(r.get("values"), list) else None
        L.append(f"| {metric} | {_num(r.get('value'))} | {C.text(r.get('unit'))} | {C.text(_words(r.get('status')))} |"
                 + (f" {n if n is not None else '—'} |" if listed else ""))
    return "\n".join(L)


def incident_timeline(rows, C) -> str:
    if not rows:
        return ""
    L = ["## Incident timeline", "",
         "Each event with what it proves and what it does not; *context* rows set the scene and prove nothing technical.", "",
         "| T | When (UTC) | Event | Proves | Not proven | Evidence |",
         "|:-:|:--------|:----------------|:------------|:------------|:------|"]
    for r in rows:
        ev = C.text(r.get("event"))
        if r.get("kind") == "context":
            ev = "*(context)* " + ev
        L.append(f"| {C.text(r.get('id'))} | {_ts(r.get('when'))} | {ev} | {C.text(r.get('proves'))} | "
                 f"{C.text(r.get('not_proven'))} | {C.refs(r.get('evidence'))} |")
    return "\n".join(L)


def attack_mapping(rows, C) -> str:
    if not rows:
        return ""
    L = ["## ATT&CK mapping", "",
         "*Observed* means the technique is evidenced in the collected material; *attempted* that it was "
         "tried without evidence of success; *inferred* that it is the analyst's reading of indirect evidence. "
         "*Limits* states what the mapping does not establish.", "",
         "| MAP | Technique | Tactic | Status | Limits | Evidence |",
         "|:-:|:------------|:--------|:----|:------------|:------|"]
    for r in rows:
        tech = f"{r.get('technique_id')}" + (f" — {C.text(r.get('technique'))}" if r.get("technique") else "")
        tactic = C.text(r.get("tactic")) + (f" · {C.text(r.get('chain'))}" if r.get("chain") else "")
        L.append(f"| {C.text(r.get('id'))} | {tech} | {tactic} | **{_words(r.get('status'))}** | "
                 f"{C.text(r.get('limits'))} | {C.refs(r.get('evidence'))} |")
    return "\n".join(L)


def scenarios(rows, C) -> str:
    if not rows:
        return ""
    L = ["## Scenarios", "", "Forward-looking scenarios the evidence makes plausible, rated feasibility × impact, with the controls that address each.", "",
         "| SC | Scenario | Feasibility × impact | Controls |", "|:-:|:--------------------|:--------|:------------|"]
    for r in rows:
        sc = f"**{C.text(r.get('title'))}**" + (f" — {C.text(r.get('narrative'))}" if r.get("narrative") else "")
        ctl = "; ".join(C.text(x) for x in (r.get("controls") or [])) or "—"
        L.append(f"| {C.text(r.get('id'))} | {sc} | {_words(r.get('feasibility'))} × {_words(r.get('impact'))} | {ctl} |")
    return "\n".join(L)


def open_questions(rows, C) -> str:
    if not rows:
        return ""
    owner = any(r.get("owner") for r in rows)
    L = ["## Open questions", "", "What the evidence could not settle, the decision each one holds up, and what would settle it.", "",
         "| OQ | Question | Decision at stake | Sources needed | Window |" + (" Owner |" if owner else ""),
         "|:-:|:----------------|:------------|:------------|:--------|" + (":----|" if owner else "")]
    for r in rows:
        ws, we = r.get("window_start"), r.get("window_end")
        window = f"{_ts(ws) if ws else '…'} to {_ts(we) if we else '…'}" if (ws or we) else "—"
        srcs = "; ".join(C.text(x) for x in (r.get("sources_needed") or [])) or "—"
        L.append(f"| {C.text(r.get('id'))} | {C.text(r.get('question'))} | {C.text(r.get('decision_at_stake'))} | "
                 f"{srcs} | {window} |" + (f" {C.text(r.get('owner'))} |" if owner else ""))
    return "\n".join(L)


def roadmap(rows, C) -> str:
    if not rows:
        return ""
    L = []
    for p in ("P1", "P2", "P3"):
        group = [r for r in rows if r.get("priority") == p]
        if not group:
            continue
        L += [f"## {PRIORITY_HEAD[p]}", "", "| Action | Owner | Done when |", "|:--------------------|:----|:------------|"]
        L += [f"| {C.text(r.get('action'))} | {C.text(r.get('owner'))} | {C.text(r.get('done_when'))} |" for r in group]
        L.append("")
    return "\n".join(L).rstrip()


def sources_checked(rows, C) -> str:
    if not rows:
        return ""
    zero = sum(1 for r in rows if r.get("status") == "zero")
    L = [f"Every source queried for this case — {len(rows)} source/selector pair(s), {zero} with no results. "
         "A source that returned nothing is a result: it bounds what the report can claim. "
         "*Hits* is the number of records a source returned where that was recorded.", "",
         "| Source | Selector | Calls | Hits | Status | First (UTC) | Last (UTC) |",
         "|:--------|:------------|:-:|:-:|:--------|:------|:------|"]
    for r in rows:
        sel = r.get("selector") or ""
        sel = "whole case" if sel in ("", "(case)") else C.code(sel)
        hits = r.get("hits")
        hits = str(hits) if isinstance(hits, int) else "n/r"
        L.append(f"| {C.text(r.get('source_class') or r.get('source'))} | {sel} | {r.get('calls', 0)} | {hits} | "
                 f"{STATUS_LABEL.get(r.get('status'), C.text(r.get('status')))} | {_ts(r.get('first'))} | {_ts(r.get('last'))} |")
    return "\n".join(L)


FIELD_ORDER = ("name", "alias", "dob", "birthplace", "email", "phone", "address", "company",
               "account", "relative", "other")
FIELD_LABEL = {"name": "Name", "alias": "Alias", "dob": "Date of birth", "birthplace": "Place of birth",
               "email": "E-mail", "phone": "Phone", "address": "Address", "company": "Company",
               "account": "Account", "relative": "Relative", "other": "Other"}
WITHHELD = "provided by client — withheld"


def redact(warnings, sections, show_sensitive=False) -> list:
    """QA warnings with every sensitive client-seed value — and every identity-card value that
    originated from one, in whatever spelling the analyst recorded it — replaced by '(withheld)',
    unless show_sensitive. Used for the report appendix AND house_report's stderr echo."""
    warnings = list(warnings or [])
    if show_sensitive:
        return warnings
    seeds = [sd for sd in ((sections or {}).get("client_seeds") or []) if isinstance(sd, dict)]
    secret = {str(sd.get("value")) for sd in seeds if sd.get("sensitive") and str(sd.get("value") or "").strip()}
    for r in (sections or {}).get("subject_profile") or []:
        seed = rs_mod.client_seed_for(r, seeds) if isinstance(r, dict) else None
        if seed and seed.get("sensitive") and str(r.get("value") or "").strip():
            secret.add(str(r["value"]))
    for i, w in enumerate(warnings):
        for v in sorted(secret, key=len, reverse=True):
            w = w.replace(v, "(withheld)")
        warnings[i] = w
    return warnings


def identity_card(rows, seeds, C, show_sensitive=False) -> str:
    """One table per entity; rows grouped by field in FIELD_ORDER; a field with no rows is OMITTED."""
    rows = [r for r in (rows or []) if isinstance(r, dict)]
    if not rows:
        return ""
    ents = list(dict.fromkeys(str(r.get("entity") or "subject") for r in rows))
    if "subject" in ents:
        ents.remove("subject")
        ents.insert(0, "subject")
    L = ["## Subject identity card", "",
         "What the evidence says about who each entity is. *Status* is the analyst's judgement "
         "(confirmed / probable / possible); values marked *client-provided* came from the client at "
         "intake and are not findings of this investigation. An identity row is not an attribution.", ""]
    for ent in ents:
        mine = [r for r in rows if str(r.get("entity") or "subject") == ent]
        L += [f"### {C.text(ent if ent != 'subject' else 'Subject')}", "",
              "| Field | Value | Status | Basis | Source | Grade |",
              "|:------|:------------|:----|:------------|:--------|:-:|"]
        for f in FIELD_ORDER + tuple(sorted({str(r.get("field")) for r in mine} - set(FIELD_ORDER))):
            for r in (r for r in mine if str(r.get("field")) == f):
                seed = rs_mod.client_seed_for(r, seeds)
                val = (f"*{WITHHELD}*" if seed and seed.get("sensitive") and not show_sensitive
                       else (C.code(r.get("value")) if _URL_ONLY_RE.match(str(r.get("value") or "").strip())
                             else C.text(r.get("value"))))
                if seed:
                    val += " *(client-provided)*"
                L.append(f"| {FIELD_LABEL.get(f, C.text(f))} | {val} | {_words(r.get('status')) or '—'} | "
                         f"{C.text(r.get('basis'))} | {C.refs(r.get('source'))} | {r.get('admiralty') or '—'} |")
        L.append("")
    return "\n".join(L).rstrip()


def client_details(seeds, C, show_sensitive=False) -> str:
    seeds = [s for s in (seeds or []) if isinstance(s, dict)]
    if not seeds:
        return ""
    L = ["## Client-provided details", "",
         "Details the client supplied at intake. They seeded the collection; they are not findings, and the "
         "identity card marks every value that originated here."
         + ("" if show_sensitive or not any(s.get("sensitive") for s in seeds)
            else " Sensitive values are withheld from this edition."), "",
         "| Type | Value | Note |", "|:------|:------------|:------------|"]
    for s in seeds:
        val = C.text(s.get("value")) if (show_sensitive or not s.get("sensitive")) else f"*{WITHHELD}*"
        L.append(f"| {C.text(_words(s.get('type')))} | {val} | {C.text(s.get('note'))} |")
    return "\n".join(L)


def qa_warnings(warns, C) -> str:
    if not warns:
        return ""
    L = [f"{len(warns)} quality check(s) flagged the analyst sections of this report. They do not change "
         "any finding; each is a point to verify before the report is relied on.", ""]
    L += [f"- {C.text(w)}" for w in warns]
    return "\n".join(L)


def render(sections: dict, sources: list, scrub, esc, cited, show_sensitive: bool = False,
           warnings: list | None = None) -> dict:
    """{placement: markdown} for every section that has data; absent sections are ''."""
    C = _Cells(scrub, esc)
    s = sections or {}
    seeds = s.get("client_seeds") or []
    warnings = redact(warnings, s, show_sensitive)
    return {
        "key_questions": key_questions(s.get("key_questions"), C),
        "identity_card": identity_card(s.get("subject_profile"), seeds, C, show_sensitive),
        "client_details": client_details(seeds, C, show_sensitive),
        "findings_boundaries": findings_boundaries(s.get("findings_boundaries"), C, cited),
        "counting_rules": counting_rules(s.get("counting_rules"), C),
        "key_counts": key_counts(s.get("metrics"), C),
        "roles": roles(s.get("roles"), C),
        "incident_timeline": incident_timeline(s.get("incident_timeline"), C),
        "attack_mapping": attack_mapping(s.get("attack_mapping"), C),
        "scenarios": scenarios(s.get("scenarios"), C),
        "open_questions": open_questions(s.get("open_questions"), C),
        "roadmap": roadmap(s.get("roadmap"), C),
        "sources_checked": sources_checked(sources, C),
        "qa_warnings": qa_warnings(warnings, C),
    }
