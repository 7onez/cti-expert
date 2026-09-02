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
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCRIPTS = os.path.join(os.path.dirname(ROOT), "scripts")
BUILD_REPORT_DATA = os.path.join(SCRIPTS, "build_report_data.py")
REPORT_FIGURES = os.path.join(SCRIPTS, "cti_report_figures.py")

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
    r = subprocess.run([py, "-c", "import matplotlib, numpy"], capture_output=True, text=True, timeout=60)
    return r.returncode == 0


def build_report_json(case_dir: str, rep_dir: str) -> tuple:
    """case dir -> report/report-data.json via build_report_data.py. (path | None, note)."""
    out = os.path.join(rep_dir, "report-data.json")
    r = subprocess.run([sys.executable, BUILD_REPORT_DATA, case_dir, "-o", out],
                       capture_output=True, text=True, timeout=300)
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
    r = subprocess.run([py, REPORT_FIGURES, data, case_dir, rep_dir], capture_output=True, text=True, timeout=300)
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
