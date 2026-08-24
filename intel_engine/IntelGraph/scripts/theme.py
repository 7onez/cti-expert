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
#
# RED IS RESERVED. The operator anchor is the only red-filled node in a diagram, because it is
# the one node a reader must find first. Brick therefore sits LAST in the community cycle: with
# it second, a two-cluster case (the common shape) rendered a whole community in almost the same
# red as the anchor, and the eye could no longer tell "this is the operator" from "these nodes
# happen to be in cluster 1".
#
# The cycle must also stay DISTINGUISHABLE at the second position, which is where a two-cluster
# case lands: two adjacent slate tones read as one cluster rendered twice.
COMMUNITY_CYCLE = ["#3b5566", "#5a6b3b", "#b0790f", "#5a4a7a",
                   "#2f6b6b", "#9a5b2f", "#7a2f52", "#8c2d2d"]
EDGE_CLASS = {"operator": "#b00020", "kit": "#7b4bab",
              "infra": "#3b5566", "link": "#b9b2a4"}
OPERATOR_FILL = "#5a1a1a"
OPERATOR_STROKE = "#b00020"

# Mermaid look, defined once so a generated case graph and a hand-authored reasoning figure are
# the same object in the reader's eye. Emitted into the .mmd as an %%{init}%% directive by
# graph_to_diagram; the matching CSS (references/diagram.css) is injected at render time by
# render_mermaid for EVERY mermaid figure, including hand-authored ones.
#
# fontSize is 20px, not the 28px this used to carry: 28 was compensating for a downscaled raster.
# Sharpness is now bought with the renderer's device scale (render_mermaid --scale), which
# multiplies pixels without inflating type — so the figure keeps a printed-page type size
# instead of looking like a slide someone shrank.
DIAGRAM = {
    # SINGLE-WORD FAMILIES ONLY — see the quote rule in mermaid_init(). A multi-word family
    # would need quoting, and a quote anywhere in the init directive voids the entire directive.
    # The generic `sans-serif` tail is what carries Vietnamese diacritics on a bare Linux
    # container (fontconfig resolves it to DejaVu Sans), which is why it is never omitted.
    "font_family": "Helvetica, Arial, sans-serif",
    "font_size": "20px",
    "node_border": "#ffffff",
    "cluster_bkg": "#fbfaf7",
    "cluster_border": "#d9d3c7",
    "line": "#8d867a",
    "edge_label_bkg": "#ffffff",
    "text": "#1f1d1a",
    "node_spacing": 48,
    "rank_spacing": 88,
    "padding": 12,
    "diagram_padding": 26,
    "subgraph_title_margin": {"top": 10, "bottom": 16},
}


def mermaid_init(extra_flowchart=None):
    """The %%{init}%% directive line every generated .mmd opens with.

    TWO MERMAID QUIRKS ARE ENCODED HERE, both established by isolating them against mmdc 11.12,
    and both of which fail SILENTLY — the diagram still renders, just not the way it was asked to:

    1. `fontFamily` is a TOP-LEVEL config key, not a themeVariable. Set inside `themeVariables`
       (where every other appearance setting lives, and where this used to sit) it is ignored,
       and the figure renders in mermaid's default trebuchet/verdana stack — which on a headless
       Chrome that has none of those resolves to a SERIF face, so the diagram quietly stops
       matching every other figure in the report.
    2. A QUOTE CHARACTER ANYWHERE IN THE DIRECTIVE VOIDS THE WHOLE DIRECTIVE. Not just the one
       value — mermaid discards the entire init block and falls back to defaults for font size,
       spacing, colours, everything. That rules out quoted multi-word font families, so the stack
       must be single-word names plus a generic. The assertion below is what keeps a future
       edit from reintroducing it.
    """
    fc = {"curve": "basis", "nodeSpacing": DIAGRAM["node_spacing"],
          "rankSpacing": DIAGRAM["rank_spacing"], "padding": DIAGRAM["padding"],
          "diagramPadding": DIAGRAM["diagram_padding"],
          "subGraphTitleMargin": DIAGRAM["subgraph_title_margin"],
          "useMaxWidth": False, "htmlLabels": True}
    fc.update(extra_flowchart or {})
    tv = {"fontSize": DIAGRAM["font_size"],
          "lineColor": DIAGRAM["line"], "textColor": DIAGRAM["text"],
          "clusterBkg": DIAGRAM["cluster_bkg"], "clusterBorder": DIAGRAM["cluster_border"],
          "edgeLabelBackground": DIAGRAM["edge_label_bkg"]}
    import json as _json
    line = "%%{init: " + _json.dumps({"theme": "neutral",
                                      "fontFamily": DIAGRAM["font_family"],
                                      "flowchart": fc,
                                      "themeVariables": tv}) + "}%%"
    assert "'" not in line, ("a quote in the mermaid init directive voids the whole directive "
                             "— see quirk 2 above")
    return line

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
