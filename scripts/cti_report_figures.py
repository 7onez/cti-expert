#!/usr/bin/env python3
"""
cti_report_figures.py — the analytic FIGURES of the CTI report as PNG bytes, independent of the
document they land in. One source for the dashboard DOCX (cti_docx_charts / cti_docx_heatmaps
embed these through python-docx) and the editorial house report (house_report_charts embeds
them through pandoc), so the two deliverables can never show different pictures for one case.

Figures (each returns PNG bytes or None when the case carries nothing to draw):
  confidence_matrix_png(findings, subjects)   ICD-203 likelihood × Admiralty reliability scatter
  registration_heatmap_png(regs)              year × month grid of estate registrations
  cooccurrence_heatmap_png(built)             domain × shared-indicator matrix
  entity_map_png(report_json)                 Diagram Design editorial entity map (cairosvg)

CLI — used by the house report, which may run in an interpreter without matplotlib:
  python3 cti_report_figures.py <report.json> <case-dir> <out-dir>
prints one JSON object {figure: path | null, "_notes": {...}} and writes fig_*.png into out-dir.
"""
from __future__ import annotations

import json
import os
import sys
from io import BytesIO

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import matplotlib  # noqa: E402
matplotlib.use("Agg")
import matplotlib.patches as mpatches  # noqa: E402
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

from cti_palette import COLORS_HEX, SEVERITY_COLORS_HEX  # noqa: E402  — no python-docx needed


def fig_png(fig) -> bytes:
    buf = BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", dpi=150, facecolor="white")
    plt.close(fig)
    return buf.getvalue()


# --------------------------------------------------------------------------- confidence matrix
_ICD203 = [
    ("Almost\nno chance", 2), ("Very\nunlikely", 12), ("Unlikely", 32),
    ("Roughly\neven", 50), ("Likely", 67), ("Very\nlikely", 87),
    ("Almost\ncertain", 97),
]
_ADMIRALTY = [
    "A \u00b7 Completely reliable", "B \u00b7 Usually reliable", "C \u00b7 Fairly reliable",
    "D \u00b7 Not usually reliable", "E \u00b7 Unreliable", "F \u00b7 Cannot be judged",
]


def likelihood_col(conf) -> int:
    c = max(0, min(100, int(conf or 0)))
    for i, hi in enumerate((5, 20, 45, 55, 80, 95)):
        if c < hi:
            return i
    return 6


def reliability_row(verified) -> int:
    """Admiralty source reliability derived from corroboration state."""
    if verified is True:
        return 1   # B — usually reliable (independently corroborated)
    if verified is False:
        return 3   # D — not usually reliable (single, uncorroborated)
    return 2       # C — fairly reliable (default OSINT posture)


def confidence_matrix_png(findings: list, subjects: list) -> bytes | None:
    """Two-axis confidence explainer: ICD-203 likelihood (x) vs Admiralty source reliability (y).
    The labelled grid IS the legend; each finding is plotted in its cell, coloured by severity."""
    if not findings:
        return None
    ncol, nrow = len(_ICD203), len(_ADMIRALTY)
    fig, ax = plt.subplots(figsize=(8.2, 4.4), dpi=150)
    ax.imshow(np.zeros((nrow, ncol)), cmap="Greys", vmin=0, vmax=1, aspect="auto")
    ax.set_xticks(np.arange(-.5, ncol, 1), minor=True)
    ax.set_yticks(np.arange(-.5, nrow, 1), minor=True)
    ax.grid(which="minor", color="#c8cdd3", linewidth=0.8)
    ax.tick_params(which="minor", length=0)
    ax.set_xticks(range(ncol))
    ax.set_xticklabels(["%s\n%d%%" % (lbl, pct) for lbl, pct in _ICD203], fontsize=7)
    ax.set_yticks(range(nrow))
    ax.set_yticklabels(_ADMIRALTY, fontsize=8)
    ax.set_xlabel("ICD-203 likelihood  \u2014  probability the judgment is correct",
                  fontsize=8.5, color=COLORS_HEX["text"])
    ax.set_ylabel("Admiralty  \u2014  source reliability", fontsize=8.5, color=COLORS_HEX["text"])
    ax.set_title("Confidence scale (two-axis): ICD-203 likelihood \u00d7 Admiralty reliability",
                 fontsize=10, color=COLORS_HEX["text"], pad=10)

    sub_verified = {s.get("id"): s.get("verified") for s in (subjects or [])}
    rng = np.random.default_rng(7)          # fixed seed: the jitter is deterministic per case
    seen, handles = {}, {}
    for f in findings:
        col = likelihood_col(f.get("confidence", 0))
        row = reliability_row(sub_verified.get(f.get("subject_id")))
        k = (row, col)
        seen[k] = seen.get(k, 0) + 1
        jx = (rng.random() - 0.5) * 0.5 if seen[k] > 1 else 0.0
        jy = (rng.random() - 0.5) * 0.5 if seen[k] > 1 else 0.0
        sev = str(f.get("weight", "INFO")).upper()
        color = SEVERITY_COLORS_HEX.get(sev, COLORS_HEX["muted"])
        ax.scatter(col + jx, row + jy, s=150, color=color, edgecolor="white", linewidth=1.2, zorder=3)
        handles.setdefault(sev, color)
    if handles:
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        ax.legend(handles=[mpatches.Patch(color=handles[s], label=s) for s in order if s in handles],
                  title="Finding severity", fontsize=7, title_fontsize=7.5, loc="upper left",
                  bbox_to_anchor=(1.01, 1.0), frameon=False)
    ax.set_xlim(-0.5, ncol - 0.5)
    ax.set_ylim(nrow - 0.5, -0.5)  # A at top
    return fig_png(fig)


# --------------------------------------------------------------------------- heatmaps
_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def registration_heatmap_png(regs: list) -> bytes | None:
    """regs = [(domain, (year, month))] -> year × month heatmap; cell = registrations that month."""
    if not regs:
        return None
    years = sorted({ym[0] for _, ym in regs})
    grid = np.zeros((len(years), 12), dtype=int)
    yidx = {y: i for i, y in enumerate(years)}
    for _, (y, mo) in regs:
        grid[yidx[y], mo - 1] += 1
    fig, ax = plt.subplots(figsize=(7.4, max(1.5, 0.5 * len(years) + 1.0)), dpi=150)
    im = ax.imshow(grid, cmap="OrRd", aspect="auto", vmin=0, vmax=max(1, grid.max()))
    ax.set_xticks(range(12))
    ax.set_xticklabels(_MONTHS, fontsize=8)
    ax.set_yticks(range(len(years)))
    ax.set_yticklabels([str(y) for y in years], fontsize=9)
    for i in range(len(years)):
        for j in range(12):
            if grid[i, j]:
                ax.text(j, i, str(grid[i, j]), ha="center", va="center", fontsize=9, fontweight="bold",
                        color="white" if grid[i, j] > grid.max() * 0.6 else COLORS_HEX["text"])
    ax.set_title("Malicious-domain registration timeline (count per month)",
                 fontsize=10, color=COLORS_HEX["text"], pad=8)
    cbar = fig.colorbar(im, ax=ax, fraction=0.025, pad=0.02)
    cbar.ax.tick_params(labelsize=7)
    fig.tight_layout()
    return fig_png(fig)


def _short(label, n=26):
    return label if len(label) <= n else label[: n - 1] + "\u2026"


def cooccurrence_heatmap_png(built, attr_label=lambda t: t) -> bytes | None:
    """built = (domains, shared_attribute_tokens, 0/1 matrix) -> domain × indicator heatmap."""
    if not built:
        return None
    domains, shared, mat = built
    if not domains or not shared:
        return None
    fig, ax = plt.subplots(figsize=(max(6.0, 0.5 * len(shared) + 2.5), max(2.0, 0.34 * len(domains) + 1.2)), dpi=150)
    ax.imshow(mat, cmap="Blues", aspect="auto", vmin=0, vmax=1)
    ax.set_xticks(range(len(shared)))
    ax.set_xticklabels([attr_label(a) for a in shared], rotation=45, ha="right", fontsize=7)
    ax.set_yticks(range(len(domains)))
    ax.set_yticklabels([_short(d) for d in domains], fontsize=7)
    ax.set_xticks(np.arange(-.5, len(shared), 1), minor=True)
    ax.set_yticks(np.arange(-.5, len(domains), 1), minor=True)
    ax.grid(which="minor", color="#d9dde2", linewidth=0.6)
    ax.tick_params(which="minor", length=0)
    ax.set_title("Domain \u00d7 shared-indicator correlation", fontsize=10, color=COLORS_HEX["text"], pad=8)
    fig.tight_layout()
    return fig_png(fig)


# --------------------------------------------------------------------------- entity map
def entity_map_png(data: dict) -> bytes | None:
    """Diagram Design editorial entity-relationship map, rasterized (needs cairosvg)."""
    try:
        from cti_diagram_design import build_entity_svg, render_svg_to_png
    except Exception:  # noqa: BLE001
        return None
    try:
        return render_svg_to_png(build_entity_svg(data), scale=2.0)
    except Exception:  # noqa: BLE001
        return None


# --------------------------------------------------------------------------- CLI
def build_all(data: dict, case_dir: str | None, out_dir: str) -> dict:
    """Write every figure the case supports into out_dir; return {name: path|None, _notes: {}}."""
    from cti_docx_heatmaps import build_cooccurrence, collect_registrations, _attr_label
    os.makedirs(out_dir, exist_ok=True)
    out, notes = {}, {}
    jobs = {
        "fig_confidence": lambda: confidence_matrix_png(data.get("findings") or [], data.get("subjects") or []),
        "fig_registrations": lambda: registration_heatmap_png(collect_registrations(data, case_dir)),
        # cap=None: the house report shows every estate domain (Rule 19 — no sampling)
        "fig_cooccurrence": lambda: cooccurrence_heatmap_png(build_cooccurrence(data, case_dir, cap=None), _attr_label),
        "fig_entity_map": lambda: entity_map_png(data),
    }
    for name, job in jobs.items():
        try:
            png = job()
        except Exception as e:  # noqa: BLE001
            png, notes[name] = None, f"{type(e).__name__}: {e}"
        if png:
            p = os.path.join(out_dir, name + ".png")
            with open(p, "wb") as fh:
                fh.write(png)
            out[name] = p
        else:
            out[name] = None
            notes.setdefault(name, "nothing to draw" if name != "fig_entity_map" else "no subjects or cairosvg unavailable")
    out["_notes"] = notes
    return out


def main(argv: list) -> int:
    if len(argv) != 3:
        print("usage: cti_report_figures.py <report.json> <case-dir|-> <out-dir>", file=sys.stderr)
        return 2
    with open(argv[0], encoding="utf-8") as fh:
        data = json.load(fh)
    case_dir = None if argv[1] == "-" else argv[1]
    print(json.dumps(build_all(data, case_dir, argv[2]), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
