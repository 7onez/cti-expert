"""
cti_palette.py — the CTI house palette as hex, dependency-free.

Muted editorial palette, IDENTICAL to the PDF (IntelGraph/scripts/theme.py + IntelReport/templates/
house-header.tex): slate / steel / ochre / brick / grid. cti_docx_styles derives its python-docx
RGBColor table from THIS dict, and the matplotlib figures (cti_report_figures) read it directly —
so the DOCX, the PDF charts and the house report agree, and the chart code never needs python-docx.
Change a colour HERE and every DOCX chart, table, heading and house-report figure follows.
"""

FONT_BODY = "Georgia"      # serif body — the house choice (read in print, at length)
FONT_HEADING = "Arial"     # sans headings / furniture — distinct from the serif body
FONT_MONO = "Consolas"     # inline code: domains, hashes, endpoints

COLORS_HEX = {
    "primary": "#22333F",   # slate — H1, cover title, strong
    "steel":   "#3B5566",   # steel — H2/H3, links
    "accent":  "#3B5566",   # steel (alias kept for callers)
    "ochre":   "#B0790F",
    "brick":   "#8C2D2D",
    "olive":   "#5A6B3B",
    "critical": "#8C2D2D",  # brick
    "high":    "#B0790F",   # ochre
    "medium":  "#9A5B2F",   # muted amber-brown
    "low":     "#5A6B3B",   # olive
    "info":    "#3B5566",   # steel
    "text":    "#1F1D1A",   # ink
    "muted":   "#6F6A61",
    "white":   "#FFFFFF",
    "band":    "#DEE4E8",   # table header band (light steel-grey)
    "bg_light": "#F2F2F2",  # zebra stripe / subtle fill
    "callout": "#F7F4ED",   # IC callout background
    "border":  "#D9D3C7",   # grid
}

# Ordered categorical cycle for charts (colorblind-safe, no default matplotlib blue) —
# matches theme.py CYCLE so a DOCX pie and a PDF figure agree.
CYCLE_HEX = ["#3B5566", "#8C2D2D", "#B0790F", "#5A6B3B", "#22333F", "#C9B892",
             "#5A4A7A", "#2F6B6B"]

SEVERITY_COLORS_HEX = {
    "CRITICAL": COLORS_HEX["critical"],
    "HIGH": COLORS_HEX["high"],
    "MEDIUM": COLORS_HEX["medium"],
    "LOW": COLORS_HEX["low"],
    "INFO": COLORS_HEX["info"],
}


def hex_rgb(h: str) -> tuple:
    """'#RRGGBB' -> (r, g, b)."""
    h = h.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
