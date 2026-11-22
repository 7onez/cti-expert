"""
house_report_exposure_charts.py — the infected-computer charts under "Affiliate exposure".

Three bar charts — infected computers by year of infection, by country and by stealer family —
drawn only when the case holds data for them:

  1. the analyst `report` block's `affiliate_exposure` rows (report_sections.load): each row's
     `infected_hosts` is counted under its `country`, its `stealer_family` and the year of its
     `latest_infection` (so the year chart reads "year of the most recent infection per
     organisation" — the row does not carry per-host dates);
  2. else the stealer-triage artifacts in the case dir (scripts/stealer_log_parse.py
     STEALER-ANALYSIS-*.json): one infected computer per log, under its `family`,
     `host.country` and the year of `host.date`.

COUNTS ONLY. Only those named fields are read; no credential, cookie, password, URL or host
identifier ever reaches a chart or a caption.

Drawing follows house_report_charts: matplotlib runs in a subprocess under the first interpreter
that can import it (the engine's own, the skills venv, then python3); with none, nothing is drawn
and the section's table still carries the numbers. Stdlib in-process.
"""
from __future__ import annotations

import glob
import json
import os
import re
import subprocess
from collections import Counter

import house_report_charts as hrg

FIGURES = ("fig_exposure_year", "fig_exposure_country", "fig_exposure_family")
TRIAGE_GLOB = "STEALER-ANALYSIS-*.json"
UNKNOWN = "not recorded"
_YEAR_RE = re.compile(r"\b((?:19|20)\d{2})\b")

_DRAW = r"""
import json, sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
spec = json.load(sys.stdin)
out = {}
for name, chart in spec["charts"].items():
    items = chart["items"]
    labels = [k for k, _ in items]
    values = [v for _, v in items]
    fig, ax = plt.subplots(figsize=(7.2, max(1.6, 0.38 * len(items) + 0.9)), dpi=200)
    bars = ax.barh(range(len(items)), values, color="#1f3a5f")
    ax.set_yticks(range(len(items)))
    ax.set_yticklabels(labels, fontsize=8)
    ax.invert_yaxis()
    ax.set_xlabel("Infected computers", fontsize=8)
    ax.set_title(chart["title"], fontsize=9, loc="left")
    ax.tick_params(axis="x", labelsize=7)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for b, v in zip(bars, values):
        ax.text(b.get_width(), b.get_y() + b.get_height() / 2, f" {v:,}", va="center", fontsize=7)
    fig.tight_layout()
    path = spec["paths"][name]
    fig.savefig(path)
    plt.close(fig)
    out[name] = path
print(json.dumps(out))
"""


def _year(v) -> str:
    m = _YEAR_RE.search(str(v or ""))
    return m.group(1) if m else ""


def _count(v) -> int:
    return int(v) if isinstance(v, (int, float)) and not isinstance(v, bool) and v > 0 else 0


def _triage_logs(case_dir):
    """Per-log (family, country, year) from the case's stealer-triage JSON — nothing else is read."""
    out = []
    if not case_dir or not os.path.isdir(case_dir):
        return out
    rep = os.path.join(case_dir, "report") + os.sep
    for path in sorted(glob.glob(os.path.join(case_dir, "**", TRIAGE_GLOB), recursive=True)):
        if path.startswith(rep):
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                logs = json.load(fh)
        except (OSError, ValueError):
            continue
        for log in logs if isinstance(logs, list) else []:
            if not isinstance(log, dict):
                continue
            host = log.get("host") if isinstance(log.get("host"), dict) else {}
            out.append((str(log.get("family") or "").strip(), str(host.get("country") or "").strip(),
                        _year(host.get("date"))))
    return out


def aggregate(sections, case_dir=None) -> dict:
    """{"source": "report"|"triage", "by_year", "by_country", "by_family"} ({} when there is no
    infected-computer count anywhere). Each "by_*" is [(label, count)], largest first (years in order)."""
    by_year, by_country, by_family = Counter(), Counter(), Counter()
    rows = [r for r in ((sections or {}).get("affiliate_exposure") or [])
            if isinstance(r, dict) and _count(r.get("infected_hosts"))]
    if rows:
        source = "report"
        for r in rows:
            n = _count(r.get("infected_hosts"))
            fam = r.get("stealer_family")
            fam = " / ".join(str(f) for f in fam if str(f).strip()) if isinstance(fam, list) else str(fam or "").strip()
            by_country[str(r.get("country") or "").strip() or UNKNOWN] += n
            by_family[fam or UNKNOWN] += n
            if _year(r.get("latest_infection")):
                by_year[_year(r.get("latest_infection"))] += n
    else:
        logs = _triage_logs(case_dir)
        if not logs:
            return {}
        source = "triage"
        for fam, cc, yr in logs:
            by_family[fam or UNKNOWN] += 1
            by_country[cc or UNKNOWN] += 1
            if yr:
                by_year[yr] += 1
    return {"source": source, "by_year": sorted(by_year.items()),
            "by_country": by_country.most_common(), "by_family": by_family.most_common()}


_TITLES = {"fig_exposure_year": ("by_year", "Infected computers by year of infection"),
           "fig_exposure_country": ("by_country", "Infected computers by country"),
           "fig_exposure_family": ("by_family", "Infected computers by stealer family")}


def build_charts(case_dir, rep_dir, sections) -> dict:
    """{name: png | None, "_source": ..., "_notes": {...}}; {} when there is nothing to draw."""
    agg = aggregate(sections, case_dir)
    if not agg:
        return {}
    figs: dict = {n: None for n in FIGURES}
    figs["_source"], figs["_notes"] = agg["source"], {}
    charts = {n: {"title": t, "items": agg[k]} for n, (k, t) in _TITLES.items() if agg[k]}
    py = next((p for p in hrg._interpreters() if hrg._can_draw(p)), None)
    if not py:
        figs["_notes"]["interpreter"] = "no interpreter with matplotlib found"
        return figs
    spec = {"charts": charts, "paths": {n: os.path.join(rep_dir, n + ".png") for n in charts}}
    r = subprocess.run([py, "-c", _DRAW], input=json.dumps(spec), capture_output=True, text=True,
                       timeout=hrg.CALL_TIMEOUT)
    try:
        drawn = json.loads(r.stdout.strip().splitlines()[-1]) if r.returncode == 0 else {}
    except (ValueError, IndexError):
        drawn = {}
    if r.returncode != 0 or not drawn:
        figs["_notes"]["render"] = (r.stderr or r.stdout or "chart render failed").strip().splitlines()[-1][:160]
    for n, p in drawn.items():
        if n in figs and os.path.exists(p):
            figs[n] = p
    return figs


def existing(case_dir, rep_dir, sections) -> dict:
    """--no-figures: reuse charts an earlier build left, but only while the case still has the data."""
    agg = aggregate(sections, case_dir)
    if not agg:
        return {}
    figs = {n: (os.path.join(rep_dir, n + ".png") if agg[_TITLES[n][0]]
                and os.path.exists(os.path.join(rep_dir, n + ".png")) else None) for n in FIGURES}
    figs["_source"] = agg["source"]
    return figs


def charts_md(figs, observed) -> str:
    if not figs or not any(figs.get(n) for n in FIGURES):
        return ""
    report = figs.get("_source") == "report"
    basis = "from the affiliate-exposure rows" if report else "one infected computer per triaged stealer log"
    L = []
    for n in FIGURES:
        if figs.get(n):
            year = ("; the year is each organisation's most recent infection"
                    if report and n == "fig_exposure_year" else "")
            L += [f"![{_TITLES[n][1]} — counts only, {basis}{year}. Observed {observed}.]"
                  f"({os.path.basename(figs[n])}){{width=75%}}", ""]
    return "\n".join(L).rstrip()

