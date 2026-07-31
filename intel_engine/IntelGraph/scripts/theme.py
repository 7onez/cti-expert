#!/usr/bin/env python3
"""
theme.py — the IntelGraph matplotlib house style (muted, editorial, SOC-report).

Non-negotiable rules baked in: DejaVu Sans (renders Vietnamese diacritics),
muted colorblind-safe slate/steel/ochre/brick palette, left-aligned title +
grey subtitle, hairline gridlines on one axis, despined top/right, caption
footer for source + Admiralty grading + date. No neon, no 3D, no gradients.

Requires matplotlib:  pip install matplotlib

    import sys; sys.path.insert(0, "<skill>/scripts")
    from theme import apply_theme, PALETTE, save_dual, caption
    apply_theme(lang="en")
    ...
    caption(fig, source="CTI team", grading="B2", date="2026-07-08")
    save_dual(fig, "/path/out")   # out_hires.png (300dpi), out.svg, out_thumb.png
"""

# muted, colorblind-safe — slate / steel / ochre / brick
PALETTE = {
    "ink":     "#1f1d1a",
    "muted":   "#6f6a61",
    "grid":    "#d9d3c7",
    "primary": "#3b5566",   # steel
    "slate":   "#22333f",
    "ochre":   "#b0790f",
    "brick":   "#8c2d2d",
    "olive":   "#5a6b3b",
    "sand":    "#c9b892",
    "paper":   "#ffffff",
}
# ordered categorical cycle (colorblind-safe, no default matplotlib blue)
CYCLE = [PALETTE["primary"], PALETTE["brick"], PALETTE["ochre"],
         PALETTE["olive"], PALETTE["slate"], PALETTE["sand"]]

# link-analysis palettes — shared by render_network.py (interactive HTML) and
# graph_to_diagram.py (editable Mermaid) so the community/edge colors are defined
# ONCE. COMMUNITY_CYCLE: Louvain community fill, ≤8 then wrap. EDGE_CLASS: edge
# stroke by evidence class.
COMMUNITY_CYCLE = ["#3b5566", "#8c2d2d", "#b0790f", "#5a6b3b",
                   "#5a4a7a", "#2f6b6b", "#9a5b2f", "#7a2f52"]
EDGE_CLASS = {"operator": "#b00020", "kit": "#7b4bab",
              "infra": "#3b5566", "link": "#b9b2a4"}

_I18N = {
    "en": {"source": "Source", "grading": "Confidence", "updated": "Updated"},
    "vi": {"source": "Nguồn", "grading": "Độ tin cậy", "updated": "Cập nhật"},
}


def apply_theme(lang="en"):
    import matplotlib as mpl
    from matplotlib import cycler
    mpl.rcParams.update({
        "font.family": "DejaVu Sans",
        "font.size": 11,
        "figure.facecolor": PALETTE["paper"],
        "axes.facecolor": PALETTE["paper"],
        "axes.edgecolor": PALETTE["muted"],
        "axes.labelcolor": PALETTE["ink"],
        "axes.titlecolor": PALETTE["ink"],
        "axes.grid": True,
        "axes.grid.axis": "y",
        "grid.color": PALETTE["grid"],
        "grid.linewidth": 0.8,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "xtick.color": PALETTE["muted"],
        "ytick.color": PALETTE["muted"],
        "text.color": PALETTE["ink"],
        "axes.prop_cycle": cycler(color=CYCLE),
        "figure.dpi": 110,
    })
    apply_theme._lang = lang
    return PALETTE


def caption(fig, source="", grading="", date="", lang=None):
    """Footer line: Source · Confidence · Date — house style."""
    lang = lang or getattr(apply_theme, "_lang", "en")
    w = _I18N.get(lang, _I18N["en"])
    bits = []
    if source:
        bits.append(f"{w['source']}: {source}")
    if grading:
        bits.append(f"{w['grading']}: {grading}")
    if date:
        bits.append(f"{w['updated']}: {date}")
    if bits:
        fig.text(0.01, 0.01, "   ·   ".join(bits), ha="left", va="bottom",
                 fontsize=8.5, color=PALETTE["muted"])


def title_block(ax, title, subtitle=None):
    """Left-aligned bold title + smaller grey subtitle."""
    ax.set_title(title, loc="left", fontweight="bold", pad=14 if subtitle else 8)
    if subtitle:
        ax.text(0.0, 1.02, subtitle, transform=ax.transAxes, ha="left", va="bottom",
                fontsize=9.5, color=PALETTE["muted"])


def save_dual(fig, stem, pdf=False):
    """Write <stem>_hires.png (300dpi), <stem>.svg, <stem>_thumb.png (110dpi)."""
    import os
    os.makedirs(os.path.dirname(os.path.abspath(stem)), exist_ok=True)
    fig.tight_layout(rect=(0, 0.03, 1, 1))
    outs = []
    fig.savefig(f"{stem}_hires.png", dpi=300, bbox_inches="tight"); outs.append(f"{stem}_hires.png")
    fig.savefig(f"{stem}.svg", bbox_inches="tight");                 outs.append(f"{stem}.svg")
    fig.savefig(f"{stem}_thumb.png", dpi=110, bbox_inches="tight");  outs.append(f"{stem}_thumb.png")
    if pdf:
        fig.savefig(f"{stem}.pdf", bbox_inches="tight"); outs.append(f"{stem}.pdf")
    return outs
