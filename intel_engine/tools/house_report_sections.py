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
  risk_assessment     Executive Summary "Overall risk" — "<level> (<score>/10), mean of N of M rated
                      domains" + domain table (score descending); Methodology "Rating scales" (bands,
                      P1/P2/P3 deadlines) — the C1 object, else cases/<case>/exposure_organisation.json
  key_findings        Executive Summary "Key findings" (# · finding · severity · priority + deadline)
  affiliate_exposure  Findings — infected computers per affiliated organisation, COUNTS ONLY (charts:
                      house_report_exposure_charts)
  leak_claims         Findings — "Of N dark-web/Telegram claims naming the subject, K are proven";
                      unproven rows labelled Unconfirmed
  email_services      Findings "Services registered by e-mail"; the address withheld (domain kept)
                      unless --show-sensitive, and withheld in QA warnings by redact()
  threat_events       Findings "Events that raise the threat", by start date
  usernames_to_reserve Recommendations — defensive handle registration
  negative_checks     Appendix "Checked — nothing found", with the zero-hit sources_checked rows
  actor_profile       "# Actor Profile" chapter after Findings, rendered when actor_profile or any of
  claim_confidence    claim_confidence / pivot_opportunities / playbook / hunt_hypotheses /
  pivot_opportunities telemetry_priorities is present: Executive line (+ threat score, an analyst lead),
  playbook            Source basis and confidence, Overview (aliases, attribution WITH its likelihood
  hunt_hypotheses     term, confidence and every dissent line — RULE 5 —, activity timeline), Intent,
  telemetry_priorities Capability, Victimology, Persona & OPSEC, Tempo, Infrastructure and defensive
                      pivots, Operational playbook (ATT&CK tactic order), ATT&CK coverage (derived:
                      report_sections.attack_coverage, cross-referencing attack_mapping), Hunt
                      hypotheses, Priority telemetry. Structure adapted from [PK Packt ACTIH
                      companion repo, 2026, chapter-03 threat-profile deliverable] (MIT).

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
    originated from one, in whatever spelling the analyst recorded it — and every `email_services`
    address replaced by '(withheld)', unless show_sensitive. Used for the report appendix AND
    house_report's stderr echo."""
    warnings = list(warnings or [])
    if show_sensitive:
        return warnings
    seeds = [sd for sd in ((sections or {}).get("client_seeds") or []) if isinstance(sd, dict)]
    secret = {str(sd.get("value")) for sd in seeds if sd.get("sensitive") and str(sd.get("value") or "").strip()}
    for r in (sections or {}).get("subject_profile") or []:
        seed = rs_mod.client_seed_for(r, seeds) if isinstance(r, dict) else None
        if seed and seed.get("sensitive") and str(r.get("value") or "").strip():
            secret.add(str(r["value"]))
    for r in (sections or {}).get("email_services") or []:
        if isinstance(r, dict) and str(r.get("email") or "").strip():
            secret.add(str(r["email"]).strip())
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


# --------------------------------------------------------------------------- risk / threat / person
RESERVE_LABEL = {"available": "Available — register it now",
                 "taken_by_other": "Taken by another account — monitor for impersonation",
                 "reserved": "Already reserved by the subject"}


def _real(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _score(v) -> str:
    return f"{float(v):.1f}" if _real(v) else "—"


def risk_overall(ra, C) -> str:
    """Executive Summary: the overall score line + the domain table, highest score first."""
    doms = [d for d in ((ra or {}).get("domains") or []) if isinstance(d, dict)]
    if not doms:
        return ""
    ov = ra.get("overall") if isinstance(ra.get("overall"), dict) else {}
    cov = ra.get("coverage") if isinstance(ra.get("coverage"), dict) else {}
    rated = cov.get("rated") if _real(cov.get("rated")) else len(doms)
    total = cov.get("total") if _real(cov.get("total")) else rated
    smax = _num(rs_mod.RISK["score_max"])
    L = ["## Overall risk", "",
         f"**Overall risk score:** {C.text(ov.get('level'))} ({_score(ov.get('score'))}/{smax}), "
         f"mean of {_num(rated)} of {_num(total)} rated domains.", ""]
    if cov.get("warning"):
        L += [f"*{C.text(cov.get('warning'))}*", ""]
    L += ["Each domain is rated by the analyst for exploitability and harm and mapped onto a fixed "
          f"0–{smax} scale (see Rating scales in Methodology). A score is analyst judgement, not a probability.", "",
          "| Domain | Score | Level | Main issue |", "|:--------------------|:-:|:------|:----------------------------|"]
    doms.sort(key=lambda d: (-(d["score"] if _real(d.get("score")) else -1), str(d.get("name") or "")))
    L += [f"| {C.text(d.get('name'))} | {_score(d.get('score'))} | {C.text(d.get('level'))} | "
          f"{C.text(d.get('main_issue'))} |" for d in doms]
    unrated = [str(u) for u in (cov.get("unrated") or []) if str(u).strip()]
    if unrated:
        L += ["", "Not rated (no evidence either way): " + ", ".join(C.text(_words(u)) for u in unrated) + "."]
    return "\n".join(L)


def _band_range(lo, hi, smax) -> str:
    if isinstance(lo, list) and len(lo) == 2:
        return f"{_num(lo[0])} – {_num(lo[1])}"
    if isinstance(lo, dict):
        return f"{_num(lo.get('min', '—'))} – {_num(lo.get('max', '—'))}"
    return f"{_score(lo)} – {smax}" if hi is None else f"{_score(lo)} to below {_score(hi)}"


def rating_scales(ra, C) -> str:
    """Methodology: the risk bands (C1 lower bounds, highest first) and the P1/P2/P3 deadlines."""
    if not ((ra or {}).get("domains")):
        return ""
    bands = ra.get("bands") if isinstance(ra.get("bands"), dict) else {}
    prio = ra.get("priorities") if isinstance(ra.get("priorities"), dict) else {}
    if not bands and not prio:
        return ""
    smax = _num(rs_mod.RISK["score_max"])
    L = ["## Rating scales", ""]
    if bands:
        scalar = all(_real(v) for v in bands.values())
        order = sorted(bands, key=lambda k: -bands[k]) if scalar else list(bands)
        L += ["| Risk level | Score range |", "|:------|:------------|"]
        for i, k in enumerate(order):
            hi = bands[order[i - 1]] if scalar and i else None
            L.append(f"| {C.text(k)} | {_band_range(bands[k], hi, smax)} |")
        L.append("")
    if prio:
        L += ["| Priority | Act within |", "|:----|:------------|"]
        L += [f"| {C.text(k)} | {C.text(v)} |" for k, v in sorted(prio.items())]
        L.append("")
    return "\n".join(L).rstrip()


def key_findings(rows, prio, C) -> str:
    """Executive Summary: the numbered key findings with severity and priority (+ its deadline; P4 =
    'track only — no deadline')."""
    rows = [r for r in (rows or []) if isinstance(r, dict)]
    if not rows:
        return ""
    L = ["## Key findings", "", "| # | Finding | Severity | Priority |", "|:-:|:----------------------------|:------|:------|"]
    for r in rows:
        label = rs_mod.priority_label(r.get("priority"), prio)
        L.append(f"| {_num(r.get('n', '—'))} | {C.text(r.get('finding'))} | {C.text(r.get('severity'))} | "
                 f"{C.text(label) if label else '—'} |")
    return "\n".join(L)


EXPOSURE_TRIAGE_HEADING = "## Infected computers — stealer-log triage"
EXPOSURE_TRIAGE_NOTE = ("Counts only, one infected computer per stealer log triaged in this case; no "
                        "affiliate-exposure rows were recorded, so no organisation is named. No credential, "
                        "cookie or password from the logs is reproduced.")


def affiliate_exposure(rows, C) -> str:
    """Infected-computer exposure of affiliated organisations — COUNTS ONLY: only the named fields
    are read, so a credential / cookie that slipped into a row is never printed."""
    rows = [r for r in (rows or []) if isinstance(r, dict)]
    if not rows:
        return ""
    rows.sort(key=lambda r: (-(r["infected_hosts"] if _real(r.get("infected_hosts")) else 0), str(r.get("org"))))
    total = sum(r["infected_hosts"] for r in rows if _real(r.get("infected_hosts")))
    L = ["## Affiliate exposure — infected computers", "",
         f"{_num(total)} infected computer(s) recorded across {len(rows)} affiliated organisation(s). "
         "Counts only: no credential, cookie or password from the logs is reproduced in this report. "
         "An infected computer exposes the organisation's portals; it does not identify who used it.", "",
         "| Organisation | Country | Infected computers | Latest infection | Stealer family | Portal exposed |",
         "|:--------------|:--:|--:|:------|:------|:------|"]
    for r in rows:
        fam = r.get("stealer_family")
        fam = ", ".join(fam) if isinstance(fam, list) else fam
        L.append(f"| {C.text(r.get('org'))} | {C.text(r.get('country'))} | {_num(r.get('infected_hosts', '—'))} | "
                 f"{C.text(str(r.get('latest_infection') or '')[:10])} | {C.text(fam)} | {C.code(r.get('portal'))} |")
    return "\n".join(L)


def claim_tally(rows) -> tuple:
    """(N claims, K proven) — K counts only rows whose `proven` is literally true."""
    rows = [r for r in (rows or []) if isinstance(r, dict)]
    return len(rows), sum(1 for r in rows if r.get("proven") is True)


def leak_claims(rows, C) -> str:
    rows = [r for r in (rows or []) if isinstance(r, dict)]
    if not rows:
        return ""
    n, k = claim_tally(rows)
    L = ["## Dark-web and Telegram claims", "",
         f"Of {n} dark-web/Telegram claims naming the subject, {k} are proven. An unconfirmed claim is "
         "an actor's statement, not a finding: it is listed so the reader knows it exists.", "",
         "| Date | Actor | Venue | Claim | Status | Evidence |", "|:------|:------|:------|:--------------------|:------|:--------|"]
    for r in sorted(rows, key=lambda r: str(r.get("date") or "")):
        status = "Proven" if r.get("proven") is True else "**Unconfirmed**"
        L.append(f"| {C.text(str(r.get('date') or '')[:10])} | {C.text(r.get('actor'))} | {C.text(r.get('venue'))} | "
                 f"{C.text(r.get('claim'))} | {status} | {C.refs(r.get('evidence'))} |")
    return "\n".join(L)


def threat_events(rows, C) -> str:
    rows = [r for r in (rows or []) if isinstance(r, dict)]
    if not rows:
        return ""
    L = ["## Events that raise the threat", "",
         "Dated events in the coming period that attract attackers, protesters or opportunistic fraud "
         "towards the subject — plan monitoring and staffing around them.", "",
         "| Dates | Event | Location | Why it raises the risk | Local legal notes | Grade |",
         "|:------|:--------------|:------|:--------------------|:------------|:-:|"]
    for r in sorted(rows, key=lambda r: (str(r.get("start") or ""), str(r.get("event") or ""))):
        s, e = str(r.get("start") or "")[:10], str(r.get("end") or "")[:10]
        when = f"{s} – {e}" if e and e != s else s
        L.append(f"| {C.text(when)} | {C.text(r.get('event'))} | {C.text(r.get('location'))} | "
                 f"{C.text(r.get('why_it_raises_risk'))} | {C.text(r.get('local_legal_notes'))} | {r.get('grade') or '—'} |")
    return "\n".join(L)


def usernames_to_reserve(rows, C) -> str:
    rows = [r for r in (rows or []) if isinstance(r, dict)]
    if not rows:
        return ""
    free = sum(1 for r in rows if r.get("status") == "available")
    L = ["## Usernames to reserve", "",
         f"Defensive recommendation: register the subject's handles before an impersonator does. "
         f"{free} of {len(rows)} handle(s) checked are still available.", "",
         "| Platform | Handle | Status |", "|:------|:------------|:--------------------|"]
    order = {"available": 0, "taken_by_other": 1, "reserved": 2}
    for r in sorted(rows, key=lambda r: (order.get(r.get("status"), 9), str(r.get("platform")))):
        L.append(f"| {C.text(r.get('platform'))} | {C.code(r.get('handle'))} | "
                 f"{RESERVE_LABEL.get(r.get('status'), C.text(_words(r.get('status'))))} |")
    return "\n".join(L)


def nothing_found(sources, negatives, C) -> str:
    """'Checked — nothing found': the zero-hit ledger rows (the same rows the Sources checked table
    marks **no results**, grouped by source class) plus the analyst's `negative_checks`."""
    zero: dict = {}
    for r in sources or []:
        if isinstance(r, dict) and r.get("status") == "zero":
            sel = r.get("selector") or ""
            zero.setdefault(r.get("source_class") or r.get("source") or "", []).append(
                "whole case" if sel in ("", "(case)") else C.code(sel))
    negatives = [r for r in (negatives or []) if isinstance(r, dict)]
    if not zero and not negatives:
        return ""
    L = ["## Checked — nothing found", "",
         "Each check below ran and returned no record. A negative result is true at the date of the check; "
         "it bounds what this report claims and is not proof that no record exists.", ""]
    if negatives:
        L += ["| Check | Scope | Result | Date |", "|:--------------------|:------------|:------|:------|"]
        L += [f"| {C.text(r.get('check'))} | {C.text(r.get('scope'))} | {C.text(r.get('result') or 'no record')} | "
              f"{C.text(str(r.get('date') or '')[:10])} |" for r in negatives]
        L.append("")
    for src in sorted(zero):
        L.append(f"- {C.text(src)}: no results for " + ", ".join(zero[src]))
    return "\n".join(L).rstrip()


def _withheld_email(v) -> str:
    s = str(v or "").strip()
    return "(withheld)" + (s[s.rindex("@"):] if "@" in s else "")


def email_services(rows, C, show_sensitive=False) -> str:
    rows = [r for r in (rows or []) if isinstance(r, dict)]
    if not rows:
        return ""
    L = ["## Services registered by e-mail", "",
         "Services where an account exists for the e-mail address. An account shows the address was used "
         "to register; it does not show who registered it or that the account is active."
         + ("" if show_sensitive else " E-mail addresses are withheld from this edition (domain kept)."), "",
         "| E-mail | Service | Evidence | Date |", "|:------------|:------------|:--------------------|:------|"]
    for r in sorted(rows, key=lambda r: (str(r.get("email")).lower(), str(r.get("service")).lower())):
        em = C.text(r.get("email")) if show_sensitive else C.text(_withheld_email(r.get("email")))
        L.append(f"| {em} | {C.text(r.get('service'))} | {C.refs(r.get('evidence'))} | "
                 f"{C.text(str(r.get('date') or '')[:10])} |")
    return "\n".join(L)


def qa_warnings(warns, C) -> str:
    if not warns:
        return ""
    L = [f"{len(warns)} quality check(s) flagged the analyst sections of this report. They do not change "
         "any finding; each is a point to verify before the report is relied on.", ""]
    L += [f"- {C.text(w)}" for w in warns]
    return "\n".join(L)


# --------------------------------------------------------------------------- actor threat profile
ACTOR_SECTIONS = ("claim_confidence", "pivot_opportunities", "playbook", "hunt_hypotheses",
                  "telemetry_priorities")
ATTRIBUTION_NOTE = ("The attribution is analyst judgement for this report: it is not a knowledge-base "
                    "edge or a same-operator link (RULE 5), and a threat score is a lead, not attribution.")


def _items(v) -> list:
    if isinstance(v, str):
        v = [v]
    return [str(x).strip() for x in (v if isinstance(v, list) else []) if str(x).strip()]


def _joined(C, v) -> str:
    return "; ".join(C.text(x) for x in _items(v)) or "—"


def attribution_line(att, C) -> list:
    """Attribution lines: the assessment always with its likelihood term and confidence (an absent
    one is SAID to be absent, never dropped), then every dissent line."""
    att = att if isinstance(att, dict) else {}
    dissent = _items(att.get("dissent"))
    if not str(att.get("assessment") or "").strip() and not dissent:
        return []
    L = []
    if str(att.get("assessment") or "").strip():
        lk = str(att.get("likelihood") or "").strip() or "likelihood term not stated"
        cf = str(att.get("confidence") or "").strip()
        cf = (cf if cf.lower().endswith("confidence") else f"{cf} confidence") if cf else "confidence not stated"
        L += [f"**Assessment:** {C.text(att.get('assessment'))} — *{C.text(lk)}*, **{C.text(cf)}**.", ""]
    if dissent:
        L += ["**Dissent and alternative views:**", ""] + [f"- {C.text(d)}" for d in dissent] + [""]
    return L + [f"*{ATTRIBUTION_NOTE}*"]


def threat_score_line(ts, C) -> str:
    ts = ts if isinstance(ts, dict) else {}
    if ts.get("threat_score") in (None, ""):
        return ""
    bits = [f"**{_num(ts['threat_score'])}**"]
    if ts.get("band"):
        bits.append(f"band {C.text(ts['band'])}")
    posture = ts.get("posture")
    if isinstance(posture, list):   # a list of recommended actions: '; '-joined, never a Python list
        posture = "; ".join(C.text(p) for p in posture if str(p if p is not None else "").strip())
    elif posture:
        posture = C.text(posture)
    if posture:
        bits.append(f"posture {posture}")
    return ("**Threat score (analyst lead, not attribution):** " + " · ".join(bits)
            + " — from the case's actor scoring.")


def actor_profile(s, C) -> str:
    """The '# Actor Profile' chapter; '' when no actor section is present. Every sub-section is
    omitted when it has no data."""
    ap = s.get("actor_profile") if isinstance(s.get("actor_profile"), dict) else {}
    rows = {k: [r for r in (s.get(k) or []) if isinstance(r, dict)] for k in ACTOR_SECTIONS}
    if not ap and not any(rows.values()):
        return ""
    L = ["# Actor Profile", ""]
    if ap.get("name"):
        L += [f"Threat profile of **{C.text(ap['name'])}**.", ""]
    if ap.get("executive_line"):
        L += [f"> **Executive line.** {C.text(ap['executive_line'])}", ""]
    if threat_score_line(ap.get("threat_score"), C):
        L += [threat_score_line(ap.get("threat_score"), C), ""]
    if rows["claim_confidence"]:
        L += ["## Source basis and confidence", "",
              "Each claim this profile makes, with the analyst's confidence in it and why. A *High* rating "
              "must cite its sources.", "",
              "| Claim | Confidence | Rationale | Sources |", "|:--------------------|:------|:--------------------|:--------|"]
        L += [f"| {C.text(r.get('claim'))} | {C.text(_words(r.get('confidence')))} | "
              f"{C.text(r.get('rationale'))} | {C.refs(r.get('sources'))} |" for r in rows["claim_confidence"]]
        L.append("")
    aliases = [a for a in ap.get("aliases") or [] if isinstance(a, dict)]
    timeline = sorted((t for t in ap.get("activity_timeline") or [] if isinstance(t, dict)),
                      key=lambda t: str(t.get("when") or ""))
    att = attribution_line(ap.get("attribution"), C)
    if aliases or att or timeline:
        L += ["## Overview", ""]
        if aliases:
            L += ["### Aliases", "", "| Alias | Source |", "|:------------|:--------------------|"]
            L += [f"| {C.text(a.get('name'))} | {C.refs(a.get('source'))} |" for a in aliases] + [""]
        if att:
            L += ["### Attribution", ""] + att + [""]
        if timeline:
            L += ["### Activity timeline", "", "| When | Activity | Sources |", "|:------|:--------------------|:--------|"]
            L += [f"| {C.text(t.get('when'))} | {C.text(t.get('event'))} | {C.refs(t.get('sources'))} |"
                  for t in timeline] + [""]
    intent = ap.get("intent") if isinstance(ap.get("intent"), dict) else {}
    if _items(intent.get("motivations")) or _items(intent.get("evidence")):
        L += ["## Intent", "", f"**Motivations:** {_joined(C, intent.get('motivations'))}", "",
              f"**Evidence:** {C.refs(_items(intent.get('evidence')))}", ""]
    cap = ap.get("capability") if isinstance(ap.get("capability"), dict) else {}
    if str(cap.get("summary") or "").strip() or _items(cap.get("evidence")):
        L += ["## Capability", "", C.text(cap.get("summary")), "",
              f"**Evidence:** {C.refs(_items(cap.get('evidence')))}", ""]
    vic = ap.get("victimology") if isinstance(ap.get("victimology"), dict) else {}
    vrows = [(label, vic.get(k)) for k, label in (("sectors", "Sectors"), ("geographies", "Geographies"),
                                                   ("data_targeted", "Data targeted")) if _items(vic.get(k))]
    if vrows:
        L += ["## Victimology", "", "| Dimension | Observed targeting |", "|:------|:----------------------------|"]
        L += [f"| {label} | {_joined(C, v)} |" for label, v in vrows] + [""]
    if _items(ap.get("persona_opsec")):
        L += ["## Persona & OPSEC", ""] + [f"- {C.text(x)}" for x in _items(ap.get("persona_opsec"))] + [""]
    if str(ap.get("tempo_summary") or "").strip() or str(ap.get("tempo_ref") or "").strip():
        L += ["## Tempo", ""]
        if str(ap.get("tempo_summary") or "").strip():
            L += [C.text(ap.get("tempo_summary")), ""]
        if str(ap.get("tempo_ref") or "").strip():
            L += [f"Tempo analysis: {C.text(ap.get('tempo_ref'))} (case timeline).", ""]
    if rows["pivot_opportunities"]:
        L += ["## Infrastructure and defensive pivots", "",
              "Artifacts a defender can pivot on. A hit is a lead to investigate, not a same-operator link.", "",
              "| Seed artifact | Pivot question | Defensive use |", "|:------------|:--------------------|:------------|"]
        L += [f"| {C.text(r.get('seed_artifact'))} | {C.text(r.get('pivot_question'))} | "
              f"{C.text(r.get('defensive_use'))} |" for r in rows["pivot_opportunities"]] + [""]
    if rows["playbook"]:
        L += ["## Operational playbook", "", "Behaviours by ATT&CK tactic, in tactic order.", "",
              "| Tactic | Behaviours | ATT&CK | Evidence |", "|:------|:--------------------|:------|:--------|"]
        L += [f"| {C.text(r.get('tactic'))} | {_joined(C, r.get('behaviours'))} | "
              f"{'; '.join(rs_mod._ids(r.get('attack_ids'))) or '—'} | {C.refs(r.get('evidence'))} |"
              for r in sorted(rows["playbook"], key=lambda r: rs_mod.tactic_rank(r.get("tactic")))] + [""]
    cov = rs_mod.attack_coverage(s)
    if cov:
        L += ["## ATT&CK coverage", "",
              "Every technique the playbook or a hunt hypothesis names, with the incident ATT&CK mapping rows "
              "that evidence the same technique in this case.", "",
              "| Technique | Tactic | Playbook | Hunt hypotheses | Incident mapping |",
              "|:------|:------------|:-:|:------|:------|"]
        L += [f"| {r['technique_id']} | {_joined(C, r['tactics'])} | {'yes' if r['playbook'] else '—'} | "
              f"{'; '.join(r['hunts']) or '—'} | {_joined(C, r['mappings'])} |" for r in cov] + [""]
    if rows["hunt_hypotheses"]:
        L += ["## Hunt hypotheses", "",
              "| HH | Hypothesis | Priority telemetry | Behavioural signals | ATT&CK | Hunt package |",
              "|:-----|:--------------------|:--------|:------------|:------|:------------|"]
        L += [f"| {C.text(r.get('id'))} | {C.text(r.get('hypothesis'))} | {_joined(C, r.get('priority_telemetry'))} | "
              f"{_joined(C, r.get('behavioural_signals'))} | {'; '.join(rs_mod._ids(r.get('attack_ids'))) or '—'} | "
              f"{C.code(r.get('hunt_package_ref'))} |"
              for r in sorted(rows["hunt_hypotheses"], key=lambda r: rs_mod._id_sort(r.get("id")))] + [""]
    if rows["telemetry_priorities"]:
        def setting(r):     # the Windows audit setting baseline_ref resolves to ('' = no ref / unresolved)
            st = rs_mod.telemetry_baseline_setting(r.get("baseline_ref"))
            return f" — Windows audit setting: {C.text(st)}" if st else ""
        L += ["## Priority telemetry", "", "| # | Source | Why |", "|:-:|:------------|:--------------------|"]
        L += [f"| {i} | {C.text(r.get('source'))} | {C.text(r.get('why'))}{setting(r)} |"
              for i, r in enumerate(rows["telemetry_priorities"], 1)] + [""]
    return "\n".join(L).rstrip()


def render(sections: dict, sources: list, scrub, esc, cited, show_sensitive: bool = False,
           warnings: list | None = None) -> dict:
    """{placement: markdown} for every section that has data; absent sections are ''."""
    C = _Cells(scrub, esc)
    s = sections or {}
    seeds = s.get("client_seeds") or []
    warnings = redact(warnings, s, show_sensitive)
    ra = s.get("risk_assessment") if isinstance(s.get("risk_assessment"), dict) else {}
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
        "risk_overall": risk_overall(ra, C),
        "rating_scales": rating_scales(ra, C),
        "key_findings": key_findings(s.get("key_findings"), ra.get("priorities"), C),
        "affiliate_exposure": affiliate_exposure(s.get("affiliate_exposure"), C),
        "leak_claims": leak_claims(s.get("leak_claims"), C),
        "threat_events": threat_events(s.get("threat_events"), C),
        "email_services": email_services(s.get("email_services"), C, show_sensitive),
        "usernames_to_reserve": usernames_to_reserve(s.get("usernames_to_reserve"), C),
        "nothing_found": nothing_found(sources, s.get("negative_checks"), C),
        "actor_profile": actor_profile(s, C),
    }
