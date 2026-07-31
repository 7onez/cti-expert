#!/usr/bin/env python3
"""
graph_to_diagram.py — turn a graph_build.py case_graph.json into an EDITABLE
Mermaid diagram source (.mmd), then render it to the IntelGraph triple
(<stem>_hires.png, <stem>.svg, <stem>_thumb.png) via render_mermaid.py.

Why this exists: render_network.py emits an opaque, interactive Cytoscape HTML.
That's great for exploring a dense web live, but you can't hand-edit it or drop
it into a PDF/DOCX. This emits a plain-text Mermaid source you CAN edit (rename
a cluster, prune a node, fix a label) and re-render to PNG/SVG for the report.

Faithful to the network encoding:
  node shape  = entity type (domain/operator/wallet/tracker/ip/…)
  node fill   = Louvain community (cluster), operator anchor = red
  node label  = type glyph + name (same emoji vocabulary as the HTML)
  subgraph    = one box per cluster (community)
  edge style  = solid = confirmed, dashed = inferred
  edge color  = operator(red) / kit(purple) / infra(steel) / link(grey)

Usage:
  graph_to_diagram.py case_graph.json out/case_diagram --title "One operator, N sites"
  graph_to_diagram.py case_graph.json out/case_diagram --legend --direction TB
  graph_to_diagram.py case_graph.json out/case_diagram --no-render   # just the .mmd

The .mmd is written next to the stem (out/case_diagram.mmd). Same case + same
input JSON => same filenames, so a re-render overwrites rather than accumulates.
"""
import argparse
import json
import os
import subprocess
import sys

# palettes are defined ONCE in theme.py (sibling module) and shared with
# render_network.py: COMM = Louvain community fill, EDGE_COLOR = edge stroke by
# evidence class. Runs as a script, so its own dir is on sys.path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from theme import COMMUNITY_CYCLE as COMM, EDGE_CLASS as EDGE_COLOR  # noqa: E402

# Mermaid delimiters (open, close) keyed off graph_build's semantic `shape`
# vocabulary (TYPE_META in WebPivot/tools/graph_build.py) — which every node
# already carries — so a new entity type added upstream renders correctly here
# with no edit. Mermaid's shape set is smaller than Cytoscape's, so several
# collapse to a sensible nearest (pentagon/vee → hexagon/diamond).
SHAPE_BY_CYTO = {
    "round-rectangle": ('("', '")'),     # rounded rectangle
    "ellipse":         ('("', '")'),
    "star":            ('["', '"]'),     # operator anchor (also class-styled red)
    "diamond":         ('{"', '"}'),
    "vee":             ('{"', '"}'),
    "barrel":          ('[("', '")]'),   # cylinder
    "hexagon":         ('{{"', '"}}'),
    "pentagon":        ('{{"', '"}}'),
    "concave-hexagon": ('{{"', '"}}'),
    "octagon":         ('[["', '"]]'),   # subroutine
    "rhomboid":        ('[/"', '"/]'),   # parallelogram
    "tag":             ('>"', '"]'),     # asymmetric / tag
}
# fallback for hand-built graphs whose nodes carry `type` but no `shape`.
SHAPE_BY_TYPE = {
    "domain": ('("', '")'), "person": ('("', '")'), "host": ('("', '")'),
    "registrant": ('("', '")'), "operator": ('["', '"]'),
    "email": ('{"', '"}'), "verification": ('{"', '"}'), "regdate": ('{"', '"}'),
    "wallet": ('[("', '")]'), "tracker": ('{{"', '"}}'), "favicon": ('{{"', '"}}'),
    "template": ('{{"', '"}}'), "theme": ('{{"', '"}}'), "ip": ('{{"', '"}}'),
    "nameserver": ('[["', '"]]'), "registrar": ('[/"', '"/]'),
    "social": ('>"', '"]'),
}
DEFAULT_SHAPE = ('["', '"]')

# fall-back glyphs if a node lacks an icon (keeps parity with graph_build TYPE_META)
ICON = {
    "domain": "🌐", "operator": "👤", "person": "🕵️", "email": "📧",
    "wallet": "₿", "tracker": "📊", "favicon": "🖼️", "verification": "🔑",
    "social": "💬", "ip": "📍", "host": "🔗", "registrant": "🧑",
    "registrar": "🏛️", "nameserver": "📡", "theme": "🎨", "template": "🧩",
    "regdate": "📆",
}


def esc(text, maxlen=42):
    """Make a label safe for a quoted Mermaid node string, and keep it short."""
    s = str(text).replace("\n", " ").replace('"', "'").replace("#", "＃").strip()
    if len(s) > maxlen:
        s = s[: maxlen - 1] + "…"
    return s


def node_stmt(nid, node):
    icon = node.get("icon") or ICON.get(node.get("type", ""), "•")
    label = f"{icon} {esc(node.get('label', node.get('id', '')))}".strip()
    # prefer the builder's semantic shape; fall back to type, then default
    o, c = (SHAPE_BY_CYTO.get(node.get("shape"))
            or SHAPE_BY_TYPE.get(node.get("type", ""), DEFAULT_SHAPE))
    return f'{nid}{o}{label}{c}'


def build_mermaid(graph, title, direction, legend):
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    # stable synthetic ids — real ids contain ., @, / etc. that Mermaid rejects
    idmap = {n["id"]: f"n{i}" for i, n in enumerate(nodes)}
    by_comm = {}
    for n in nodes:
        by_comm.setdefault(n.get("community_rank", 0), []).append(n)
    ranks = sorted(by_comm)

    out = []
    if title:
        out += ["---", f"title: {esc(title, 120)}", "---"]
    out.append(r"%%{init: {'theme':'neutral', "
               r"'flowchart':{'curve':'basis','nodeSpacing':60,'rankSpacing':75,'padding':18}, "
               r"'themeVariables':{'fontFamily':'DejaVu Sans, Arial, sans-serif','fontSize':'28px'}}}%%")
    out.append(f"flowchart {direction}")

    # nodes grouped into one subgraph per cluster
    for rank in ranks:
        out.append(f'  subgraph cl{rank}["Cluster {rank}"]')
        out.append("    direction TB")
        for n in by_comm[rank]:
            out.append("    " + node_stmt(idmap[n["id"]], n))
        out.append("  end")

    # edges (declared after subgraphs so they can cross cluster boxes).
    # line_styles is index-aligned with every edge line we emit, so linkStyle N
    # always targets the Nth edge — real edges first, legend samples last.
    line_styles = []
    for e in edges:
        s, t = idmap.get(e.get("source")), idmap.get(e.get("target"))
        if not s or not t:
            continue
        inferred = str(e.get("confidence", "")).lower() in {
            "inferred", "low", "weak", "possible"}
        arrow = "-.->" if inferred else "-->"
        rel = esc(e.get("rel", ""), 18)
        out.append(f'  {s} {arrow}|"{rel}"| {t}')
        line_styles.append(EDGE_COLOR.get(e.get("link_class", "link"), "#b9b2a4"))

    # classDef per community (node fill = cluster); operator = red anchor
    for rank in ranks:
        fill = COMM[rank % len(COMM)]
        out.append(f"  classDef cluster{rank} fill:{fill},color:#ffffff,"
                   f"stroke:#2b2b2b,stroke-width:1px;")
    out.append("  classDef operator fill:#5a1a1a,color:#ffffff,"
               "stroke:#b00020,stroke-width:3px;")

    # assign classes
    for rank in ranks:
        ids = [idmap[n["id"]] for n in by_comm[rank]
               if n.get("type") not in ("operator", "person")]
        if ids:
            out.append(f"  class {','.join(ids)} cluster{rank};")
    anchors = [idmap[n["id"]] for n in nodes
               if n.get("type") in ("operator", "person")]
    if anchors:
        out.append(f"  class {','.join(anchors)} operator;")

    if legend:
        # sample edges whose stroke is the real class color (styled below)
        out.append('  subgraph legend["Legend — edge color = evidence class"]')
        out.append("    direction LR")
        out.append('    lop1["same operator"] --> lop2["…"]')
        out.append('    lkit1["same kit / fingerprint"] --> lkit2["…"]')
        out.append('    linf1["shared infra"] --> linf2["…"]')
        out.append('    llnk1["page link"] --> llnk2["…"]')
        out.append("  end")
        line_styles += [EDGE_COLOR["operator"], EDGE_COLOR["kit"],
                        EDGE_COLOR["infra"], EDGE_COLOR["link"]]

    # per-edge stroke color = evidence class (index-aligned with emitted edges)
    for i, col in enumerate(line_styles):
        out.append(f"  linkStyle {i} stroke:{col},stroke-width:1.6px;")

    return "\n".join(out) + "\n"


def render_triple(mmd_path, stem):
    """Shell out to the sibling render_mermaid.py to emit PNG + SVG + thumb."""
    render = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "render_mermaid.py")
    r = subprocess.run([sys.executable, render, mmd_path, stem],
                       capture_output=True, text=True)
    if r.returncode != 0:
        sys.stderr.write(r.stdout + r.stderr)
        sys.exit(f"render_mermaid.py failed for {stem} (the .mmd is still written)")
    return [f"{stem}.svg", f"{stem}_hires.png", f"{stem}_thumb.png"]


def main():
    ap = argparse.ArgumentParser(
        description="case_graph.json -> editable Mermaid -> PNG/SVG")
    ap.add_argument("graph_json", help="graph_build.py case graph JSON")
    ap.add_argument("stem", help="output path stem (no extension)")
    ap.add_argument("--title", default="", help="diagram title (frontmatter)")
    ap.add_argument("--direction", default="LR", choices=["LR", "TB", "RL", "BT"],
                    help="flow direction (default LR)")
    ap.add_argument("--legend", action="store_true", help="append an edge legend box")
    ap.add_argument("--drop-types", default="",
                    help="comma-list of node TYPES to prune before rendering (declutters a report "
                         "figure so the meaningful nodes render large), e.g. "
                         "nameserver,registrar,template,theme,email")
    ap.add_argument("--no-render", action="store_true",
                    help="write only the .mmd source; skip PNG/SVG rendering")
    args = ap.parse_args()

    graph = json.load(open(args.graph_json, encoding="utf-8"))
    if args.drop_types:
        drop = {t.strip() for t in args.drop_types.split(",") if t.strip()}
        keep = [n for n in graph.get("nodes", []) if n.get("type") not in drop]
        ids = {n["id"] for n in keep}
        graph["nodes"] = keep
        graph["edges"] = [e for e in graph.get("edges", [])
                          if e.get("source") in ids and e.get("target") in ids]
    os.makedirs(os.path.dirname(os.path.abspath(args.stem)), exist_ok=True)
    mmd = build_mermaid(graph, args.title, args.direction, args.legend)
    mmd_path = f"{args.stem}.mmd"
    with open(mmd_path, "w", encoding="utf-8") as fh:
        fh.write(mmd)

    outs = [mmd_path]
    if not args.no_render:
        outs += render_triple(mmd_path, args.stem)
    print("wrote (editable source first):\n  " + "\n  ".join(outs))


if __name__ == "__main__":
    main()
