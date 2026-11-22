#!/usr/bin/env python3
"""
house_report_charts.py — the dashboard's analytic figures inside the editorial house report.

The dashboard DOCX/HTML (generate-cti-docx-hybrid / generate-cti-html) draws four figures the
house report lacked: the ICD-203 × Admiralty confidence scatter, the registration heatmap, the
domain × shared-indicator matrix and the editorial entity-relationship map. All four are drawn by
scripts/cti_report_figures.py from the flat report JSON, which scripts/build_report_data.py derives
deterministically from the case dir. This module chains the two so the house PDF/DOCX carry the
SAME pictures the dashboard shows — nothing is redrawn here.

Both steps run as subprocesses: build_report_data is stdlib; the figures need matplotlib (+ cairosvg
for the entity map), so the first interpreter that imports them is used — the engine's own, the
skills venv, then python3. A figure that cannot be drawn is reported by name (Rule 19), never
silently dropped.

RELATIONSHIP CARD MAPS (IntelGraph scripts/card_map.py, stdlib, drawn in-process) are built here
from the analyst's report block and the case's supplier map — only when there is data:

  person      subject_profile entities + `relationships` rows {from, to, relation, description,
              group, side, grade, confirmed, dates, cc, icon}: the subject is the hub; a row whose
              `from` is another card hangs under that card (a relation of a relation)
  threats     `actors` rows {name, type, claim, grade, confirmed, cc, date, icon}, one panel per type
  suppliers   cases/<id>/suppliers.json {"suppliers": [{name, category, evidence[], confidence}]},
              one panel per category; low confidence draws dashed (not confirmed)

Every string on a card passes through card_map.scrub_pii (reference-defined e-mail, phone and
birth-date patterns), then the composer's `clean` callable (house_report.scrub with escape=False:
Rule 12 + the third-party mask). Full dates on person cards are treated as birth dates; other
cards lose full dates only next to a birth cue. Year ranges and month-year dates stay.
Client-seed values marked sensitive never reach a card unless --show-sensitive.
No data -> no spec -> no figure, never an empty map.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCRIPTS = os.path.join(os.path.dirname(ROOT), "scripts")
BUILD_REPORT_DATA = os.path.join(SCRIPTS, "build_report_data.py")
REPORT_FIGURES = os.path.join(SCRIPTS, "cti_report_figures.py")
# Per-call ceiling for the build/figure subprocesses (env CTI_CALL_TIMEOUT → .env →
# references/timeouts.json → 18000s / 5 h); every bound below is floored to it.
sys.path.insert(0, os.path.join(ROOT, "WebPivot", "tools"))
from wp_timeouts import CALL_TIMEOUT  # noqa: E402

FIGURES = ("fig_confidence", "fig_registrations", "fig_cooccurrence", "fig_entity_map")


def _interpreters() -> list:
    cands = [sys.executable,
             os.path.join(os.path.expanduser("~"), ".claude", "skills", ".venv", "bin", "python"),
             "python3"]
    seen, out = set(), []
    for c in cands:
        if c and c not in seen and (os.sep not in c or os.path.exists(c)):
            seen.add(c)
            out.append(c)
    return out


def _can_draw(py: str) -> bool:
    r = subprocess.run([py, "-c", "import matplotlib, numpy"], capture_output=True, text=True, timeout=CALL_TIMEOUT)
    return r.returncode == 0


def build_report_json(case_dir: str, rep_dir: str) -> tuple:
    """case dir -> report/report-data.json via build_report_data.py. (path | None, note)."""
    out = os.path.join(rep_dir, "report-data.json")
    # --no-figures: the house run draws its own card maps / exposure charts; never draw them twice
    r = subprocess.run([sys.executable, BUILD_REPORT_DATA, case_dir, "-o", out, "--no-figures"],
                       capture_output=True, text=True, timeout=CALL_TIMEOUT)
    if r.returncode != 0 or not os.path.exists(out):
        return None, (r.stderr or r.stdout or "build_report_data failed").strip().splitlines()[-1][:160]
    return out, ""


def build_figures(case_dir: str, rep_dir: str) -> dict:
    """Returns {name: png path | None, "_notes": {name: why}} for FIGURES."""
    figs: dict = {n: None for n in FIGURES}
    notes: dict = {}
    data, why = build_report_json(case_dir, rep_dir)
    if not data:
        notes["report_json"] = why
        figs["_notes"] = notes
        return figs
    py = next((p for p in _interpreters() if _can_draw(p)), None)
    if not py:
        notes["interpreter"] = "no interpreter with matplotlib + numpy found"
        figs["_notes"] = notes
        return figs
    r = subprocess.run([py, REPORT_FIGURES, data, case_dir, rep_dir], capture_output=True, text=True, timeout=CALL_TIMEOUT)
    if r.returncode != 0:
        notes["render"] = (r.stderr or r.stdout or "figure render failed").strip().splitlines()[-1][:160]
        figs["_notes"] = notes
        return figs
    try:
        res = json.loads(r.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        notes["render"] = "figure render returned no manifest"
        figs["_notes"] = notes
        return figs
    for n in FIGURES:
        figs[n] = res.get(n)
    notes.update(res.get("_notes") or {})
    figs["_notes"] = notes
    return figs


# --------------------------------------------------------------------------- markdown blocks
def confidence_md(figs: dict, observed: str) -> str:
    p = figs.get("fig_confidence")
    if not p:
        return ""
    return (f"![The case's findings placed on both scales at once — ICD-203 likelihood along the bottom, "
            f"Admiralty source reliability down the side; each marker is one finding, coloured by severity. "
            f"Observed {observed}.]({os.path.basename(p)})")


def entity_map_md(figs: dict, observed: str) -> str:
    p = figs.get("fig_entity_map")
    if not p:
        return ""
    return (f"![Entity relationship map — the registrant persona and every domain it links to; the seed is "
            f"highlighted. Observed {observed}.]({os.path.basename(p)})")


def heatmaps_md(figs: dict, observed: str) -> str:
    L = []
    if figs.get("fig_registrations"):
        L += [f"![Registration heatmap — estate domains registered per month. Observed {observed}.]"
              f"({os.path.basename(figs['fig_registrations'])}){{width=85%}}", ""]
    if figs.get("fig_cooccurrence"):
        L += [f"![Domain × shared-indicator matrix — a filled cell means the domain carries that indicator. "
              f"Only indicators shared by two or more estate hosts are shown, and none that the false-positive "
              f"control excluded (shared providers, kit defaults, saturated favicons); a domain whose registration "
              f"is privacy-redacted has no such indicator and is absent. Observed {observed}.]"
              f"({os.path.basename(figs['fig_cooccurrence'])}){{width=85%}}", ""]
    return "\n".join(L).rstrip()


def missing_md(figs: dict) -> str:
    """One line naming the analytic figures that could not be drawn (Rule 19)."""
    notes = figs.get("_notes") or {}
    names = {"fig_confidence": "confidence scatter", "fig_registrations": "registration heatmap",
             "fig_cooccurrence": "shared-indicator matrix", "fig_entity_map": "entity relationship map"}
    gone = [names[n] for n in FIGURES if not figs.get(n)]
    if not gone:
        return ""
    # Rule 12: the detail (interpreter, tracebacks, paths) goes to stderr in build_figures; the body
    # gets a closed phrase only.
    tooling = any(k in notes for k in ("report_json", "interpreter", "render"))
    return ("Not drawn for this build: " + ", ".join(gone)
            + (" (not rendered in this build)." if tooling else " (nothing to draw from the collected data)."))


# --------------------------------------------------------------------------- relationship card maps
CARD_MAPS = ("person", "threats", "suppliers")
CARD_MAP_STEM = "card_map_{}"
_PROFILE_LINE_FIELDS = ("company", "address", "birthplace")   # never e-mail / phone / dob on a card


def _card_map_mod():
    p = os.path.join(ROOT, "IntelGraph", "scripts")
    if p not in sys.path:
        sys.path.insert(0, p)
    import card_map  # noqa: E402
    return card_map


def _s(v) -> str:
    return str(v if v is not None else "").strip()


def _confirmed(v) -> bool:
    return not (v is False or _s(v).lower() in ("false", "no", "0"))


def _type_icon(kind: str, default: str = "") -> str:
    icons = _card_map_mod().REF.get("type_icons") or {}
    k = _s(kind).lower()
    for needle, icon in icons.items():
        if needle != "default" and needle in k:
            return icon
    return default or icons.get("default") or "group"


def _card(clean, name, lines=(), relation="", grade="", confirmed=True, dates="", cc="", icon=""):
    person = _s(icon).lower() == "person"
    scrub = _card_map_mod().scrub_pii
    original_clean = clean
    clean = lambda text: original_clean(scrub(text, person=person))
    c = {"name": clean(_s(name)), "lines": [clean(_s(x)) for x in lines if _s(x)]}
    for k, v in (("relation", relation), ("dates", dates)):
        if _s(v):
            c[k] = clean(_s(v))
    if _s(grade):
        c["grade"] = _s(grade).upper()
    if _s(cc):
        c["cc"] = _s(cc).upper()
    if _s(icon):
        c["icon"] = _s(icon).lower()
    if not confirmed:
        c["confirmed"] = False
    return c


def _sided(panels: list, sides: dict) -> list:
    """Panels in first-appearance order; an explicit side wins, the rest alternate left/right."""
    out, flip = [], 0
    for p in panels:
        side = sides.get(p["title"])
        if side not in ("left", "right", "full"):
            side = ("left", "right")[flip % 2]
            flip += 1
        out.append(dict(p, side=side))
    return out


def person_spec(sections: dict, observed: str, clean, show_sensitive: bool = False,
                fallback_name: str = "") -> dict | None:
    """subject_profile + relationships -> a C2 card-map spec (None when there is nothing to map).
    Hub name: the subject's profile name, else the most frequent relationships[].from, else
    `fallback_name` (scope brand / seed), else "Subject"."""
    import report_sections as rs_mod
    original_clean = clean
    clean = lambda text: original_clean(_card_map_mod().scrub_pii(text))
    sections = sections or {}
    seeds = [x for x in sections.get("client_seeds") or [] if isinstance(x, dict)]
    # a sensitive client-seed value never reaches a card, in whatever row the analyst repeated it
    secret = [] if show_sensitive else sorted(
        {_s(sd.get("value")) for sd in seeds if sd.get("sensitive") and _s(sd.get("value"))},
        key=lambda v: (-len(v), v))
    if secret:
        _clean = clean

        def clean(t):
            for v in secret:
                t = t.replace(v, "(withheld)")
            return _clean(t)
    prof: dict = {}
    for r in sections.get("subject_profile") or []:
        if not isinstance(r, dict) or not _s(r.get("value")):
            continue
        seed = rs_mod.client_seed_for(r, seeds)
        if seed and seed.get("sensitive") and not show_sensitive:
            continue
        prof.setdefault(_s(r.get("entity")) or "subject", []).append(r)

    def ent_name(ent):
        names = [r for r in prof.get(ent, []) if _s(r.get("field")) == "name"]
        names.sort(key=lambda r: 0 if _s(r.get("status")).lower() == "confirmed" else 1)
        return _s(names[0]["value"]) if names else ""

    def ent_lines(ent):
        return [_s(r["value"]) for f in _PROFILE_LINE_FIELDS
                for r in prof.get(ent, []) if _s(r.get("field")) == f][:3]

    by_name = {}
    for ent in prof:
        by_name[ent.lower()] = ent
        if ent_name(ent):
            by_name[ent_name(ent).lower()] = ent
    rels = [r for r in sections.get("relationships") or []
            if isinstance(r, dict) and _s(r.get("to")) and _s(r.get("relation"))]
    froms = Counter(_s(r.get("from")) for r in rels
                    if _s(r.get("from")) and _s(r.get("from")).lower() != "subject")
    hub_name = (ent_name("subject") or (froms.most_common(1)[0][0] if froms else "")
                or _s(fallback_name) or "Subject")
    hub_alias = {"subject", hub_name.lower()}

    panels: dict = {}            # title -> {"title", "cards": [(key, card, children)]}
    sides: dict = {}
    placed: dict = {}            # card key (lower) -> (panel title, children list)
    used_ents = {"subject"}
    for r in rels:
        to, frm = _s(r.get("to")), _s(r.get("from")) or "subject"
        ent = by_name.get(to.lower())
        if ent:
            used_ents.add(ent)
        lines = (ent_lines(ent) if ent else []) + [_s(r.get("description"))]
        card = _card(clean, ent_name(ent) or to if ent else to, lines, r.get("relation"),
                     r.get("grade"), _confirmed(r.get("confirmed")), r.get("dates"), r.get("cc"),
                     r.get("icon"))
        parent = placed.get(frm.lower()) if frm.lower() not in hub_alias else None
        if parent:
            card["indent"] = True
            parent[1].append(card)
            continue
        title = _s(r.get("group")) or "Relationships"
        if _s(r.get("side")) and title not in sides:
            sides[title] = _s(r.get("side")).lower()
        children: list = []
        panels.setdefault(title, []).append((card, children))
        placed[to.lower()] = (title, children)
    for ent in (e for e in prof if e not in used_ents):
        panels.setdefault("Other profiled entities", []).append(
            (_card(clean, ent_name(ent) or ent, ent_lines(ent)), []))
    if not panels:
        return None
    raw = [{"title": t, "cards": [c for card, kids in rows for c in [card] + kids]}
           for t, rows in panels.items()]
    sided = [dict(p, title=clean(p["title"])) for p in _sided(raw, sides)]
    hub = _card(clean, hub_name, ent_lines("subject"), icon="person")
    return {"title": clean(f"Connections of {hub_name}"),
            "subtitle": f"Public sources, compiled to {observed}",
            "hub": hub, "trunk_labels": [], "panels": sided, "legend": True}


def threat_spec(sections: dict, subject: str, observed: str, clean) -> dict | None:
    """`actors` rows -> a C2 spec: the organisation is the hub, one panel per actor type."""
    original_clean = clean
    clean = lambda text: original_clean(_card_map_mod().scrub_pii(text))
    rows = [r for r in (sections or {}).get("actors") or []
            if isinstance(r, dict) and _s(r.get("name")) and _s(r.get("type"))]
    if not rows:
        return None
    panels: dict = {}
    for r in rows:
        t = _s(r.get("type"))
        panels.setdefault(t, []).append(_card(
            clean, r.get("name"), [r.get("claim")], "", r.get("grade"), _confirmed(r.get("confirmed")),
            r.get("date"), r.get("cc"), r.get("icon") or _type_icon(t)))
    subject = _s(subject) or "the organisation"
    return {"title": clean(f"Threat actors reported against {subject}, by type"),
            "subtitle": f"Public sources, compiled to {observed}",
            "hub": _card(clean, subject, icon="organisation"), "trunk_labels": [],
            "panels": [dict(p, title=clean(p["title"])) for p in
                       _sided([{"title": t, "cards": cs} for t, cs in panels.items()], {})],
            "legend": True}


def supplier_spec(doc: dict, subject: str, observed: str, clean) -> dict | None:
    """cases/<id>/suppliers.json (C3) -> a C2 spec, one panel per supplier category."""
    original_clean = clean
    clean = lambda text: original_clean(_card_map_mod().scrub_pii(text))
    rows = [r for r in (doc or {}).get("suppliers") or [] if isinstance(r, dict) and _s(r.get("name"))]
    if not rows:
        return None
    panels: dict = {}
    for r in rows:
        cat = _s(r.get("category")) or "Other"
        ev = [e for e in r.get("evidence") or [] if isinstance(e, dict) and _s(e.get("value"))]
        lines = [f"{_s(e.get('kind')).replace('_', ' ')}: {_s(e.get('value'))}" for e in ev[:2]]
        if len(ev) > 2:
            lines.append(f"and {len(ev) - 2} more record(s)")
        conf = _s(r.get("confidence")).lower()
        panels.setdefault(cat, []).append(_card(
            clean, r.get("name"), lines, f"{conf} confidence" if conf else "", "",
            conf != "low", "", "", _type_icon(cat, "organisation")))
    subject = _s(subject) or "the organisation"
    return {"title": clean(f"Third-party suppliers visible in public records of {subject}"),
            "subtitle": f"Public sources, compiled to {observed}",
            "hub": _card(clean, subject, icon="organisation"), "trunk_labels": [],
            "panels": [dict(p, title=clean(p["title"])) for p in
                       _sided([{"title": t, "cards": cs} for t, cs in panels.items()], {})],
            "legend": True}


def card_map_specs(c: dict, observed: str, clean) -> dict:
    """{name: spec} for every card map the case has data for (absent when none)."""
    secs = c.get("report_sections") or {}
    subject = (c.get("scope") or {}).get("brand") or c.get("seed") or ""
    case_dir = c.get("dir") or ""
    sup = {}
    p = os.path.join(case_dir, "suppliers.json") if case_dir else ""
    if p and os.path.exists(p):
        try:
            with open(p, encoding="utf-8") as fh:
                sup = json.load(fh)
        except (OSError, ValueError) as exc:
            sys.stderr.write(f"card map suppliers: unreadable suppliers.json ({exc})\n")
    specs = {"person": person_spec(secs, observed, clean, bool(c.get("show_sensitive")), subject),
             "threats": threat_spec(secs, subject, observed, clean),
             "suppliers": supplier_spec(sup if isinstance(sup, dict) else {}, subject, observed, clean)}
    return {k: v for k, v in specs.items() if v}


def build_card_maps(c: dict, rep_dir: str, observed: str, clean) -> dict:
    """Render each card map that has data -> {name: png path | None, "_notes": {name: why}}."""
    out: dict = {"_notes": {}}
    specs = card_map_specs(c, observed, clean)
    if not specs:
        return out
    cm = _card_map_mod()
    for name, spec in specs.items():
        stem = os.path.join(rep_dir, CARD_MAP_STEM.format(name))
        res = cm.write(spec, stem + ".svg", png=stem + ".png", pdf=stem + ".pdf", base_dir=rep_dir)
        out[name] = res.get("png")
        if res.get("error"):
            out["_notes"][name] = res["error"]
    return out


def existing_card_maps(rep_dir: str) -> dict:
    """--no-figures: reuse the card maps an earlier build left in report/."""
    out: dict = {"_notes": {}}
    for name in CARD_MAPS:
        p = os.path.join(rep_dir, CARD_MAP_STEM.format(name) + ".png")
        if os.path.exists(p):
            out[name] = p
    return out


_CARD_MAP_CAPTION = {
    "person": "Connections of the subject: the people, organisations, accounts and places the analyst "
              "linked to them, grouped by kind, each graded on the Admiralty scale; dashed = unconfirmed.",
    "threats": "Threat actors reported against the organisation, one panel per kind of actor, each graded "
               "on the Admiralty scale; dashed = unconfirmed.",
    "suppliers": "Third-party suppliers seen in public records (DNS verification records, mail routing, "
                 "certificates, documents); a dashed card is a low-confidence inference, not a confirmed contract.",
}


def card_map_md(maps: dict | None, name: str, observed: str) -> str:
    p = (maps or {}).get(name)
    if not p:
        return ""
    return f"![{_CARD_MAP_CAPTION[name]} Observed {observed}.]({os.path.basename(p)})"
