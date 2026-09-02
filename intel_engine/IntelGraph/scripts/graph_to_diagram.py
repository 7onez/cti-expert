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
  node fill   = Louvain community (cluster), operator anchor = red (and ONLY the anchor)
  node label  = type glyph + name (same emoji vocabulary as the HTML)
  subgraph    = one box per cluster (community)
  edge style  = solid = confirmed, dashed = inferred
  edge color  = operator(red) / kit(purple) / infra(steel) / link(grey)

THE LEGEND IS ITS OWN FIGURE (this is the default on a multi-cluster graph)
---------------------------------------------------------------------------
An in-diagram legend box competes with the graph for space and loses: mermaid centres a
subgraph title over a box sized by its CONTENT, so a four-row key with a sentence for a title
overflows its own border and lands on top of the sample nodes. Worse, dagre stacks the legend
as just another cluster, so on a two-cluster case it ate the top third of the figure and pushed
the actual estate into a letterbox.

So past `legend_split_min_clusters` the legend is emitted as a COMPANION FIGURE
(<stem>_legend.*) — a proper key card that also explains what the shapes and the cluster fills
mean, which the inline box never did. Embed it beside the graph; `--inline-legend` restores the
old single-figure behaviour, and titles are length-capped so the overflow cannot come back.

EDGE LABELS ARE DE-DUPLICATED
-----------------------------
In a real estate graph fifteen domains share one registrar, and labelling every edge writes
"registrar" fifteen times across the same fan of curves. The relation is a property of the
TARGET (that node is a registrar), so the label is emitted once per (relation → target) and
suppressed on the repeats. The edges, their colours and their styles are untouched — nothing is
hidden, only said once. `--all-edge-labels` turns it off.

Usage:
  graph_to_diagram.py case_graph.json out/case_diagram --title "One operator, N sites"
  graph_to_diagram.py case_graph.json out/case_diagram --legend --direction TB
  graph_to_diagram.py case_graph.json out/case_diagram --legend --inline-legend
  graph_to_diagram.py case_graph.json out/case_diagram --split-clusters   # one figure per cluster
  graph_to_diagram.py case_graph.json out/case_diagram --pdf              # + vector for the PDF
  graph_to_diagram.py case_graph.json out/case_diagram --no-render        # just the .mmd

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
from theme import (COMMUNITY_CYCLE as COMM, EDGE_CLASS as EDGE_COLOR,  # noqa: E402
                   OPERATOR_FILL, OPERATOR_STROKE, mermaid_init)

# A subgraph title is centred over a box whose width comes from its CONTENT, so a long one
# overflows onto the nodes underneath — the defect that made the old inline legend unreadable.
# Every title this module emits goes through `box_title`, so it cannot come back by accident.
MAX_BOX_TITLE = 26

# Past this many clusters the legend stops being an inline box and becomes its own figure.
# Two is already enough: with two clusters plus a legend, dagre gives each a full band and the
# legend takes a third of the page to say four words.
LEGEND_SPLIT_MIN_CLUSTERS = 2

# Above this, a single figure stops being readable at printed width whatever the styling does.
# We still render it — the analyst may want the overview — but we say so.
CROWDED_NODES = 45

# Fan-out infrastructure types that multiply without carrying the argument (fifteen
# domains all pointing at one registrar). When a large estate is downsampled to a
# readable REPRESENTATIVE subset, these are dropped FIRST — the meaningful nodes
# (operator anchor, hubs, one per cluster) survive. The full set never disappears:
# it stays in the IOC bundle (CSV / Markdown / JSONL), which the figure caption says.
FANOUT_TYPES = {"nameserver", "registrar", "regdate", "template", "theme"}

EDGE_CLASS_LABEL = {
    "operator": "same operator",
    "kit": "same kit / fingerprint",
    "infra": "shared infrastructure",
    "link": "page link",
}

# Human names for the node types, for the legend's shape key. A type not listed here still
# renders — it just shows its raw type name, which is the honest fallback.
TYPE_LABEL = {
    "domain": "domain / host", "operator": "operator (anchor)", "person": "person",
    "email": "email", "wallet": "wallet", "tracker": "tracker id", "favicon": "favicon",
    "verification": "verification token", "social": "social handle", "ip": "IP address",
    "registrant": "registrant", "registrar": "registrar", "nameserver": "nameserver",
    "theme": "theme", "template": "template", "regdate": "reg. date",
    "host": "host",
}

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


def yaml_title(text, maxlen=120):
    """Frontmatter `title:` is YAML — an unquoted scalar breaks on ': ' or ' #' (the reduced-subset
    note contains both), which mmdc reports as a bare YAMLException. Always emit a quoted scalar."""
    s = esc(text, maxlen).replace("\\", "\\\\").replace('"', "'")
    return '"' + s + '"'


def node_stmt(nid, node):
    icon = node.get("icon") or ICON.get(node.get("type", ""), "•")
    label = f"{icon} {esc(node.get('label', node.get('id', '')))}".strip()
    # prefer the builder's semantic shape; fall back to type, then default
    o, c = (SHAPE_BY_CYTO.get(node.get("shape"))
            or SHAPE_BY_TYPE.get(node.get("type", ""), DEFAULT_SHAPE))
    return f'{nid}{o}{label}{c}'


def box_title(text):
    """A subgraph title, length-capped. See MAX_BOX_TITLE — an over-long title overflows the box
    mermaid sizes from the box's CONTENT and lands on the nodes inside it."""
    return esc(text, MAX_BOX_TITLE)


def is_inferred(edge):
    return str(edge.get("confidence", "")).lower() in {"inferred", "low", "weak", "possible"}


def _cluster_caption(rank, members):
    """`CLUSTER 0 · 10 nodes` — short by construction, and the count tells a reader whether a
    thin-looking box is a small cluster or a pruned one."""
    return box_title(f"Cluster {rank} · {len(members)} nodes")


def build_mermaid(graph, title, direction, legend, *, dedup_labels=True):
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
        out += ["---", f"title: {yaml_title(title)}", "---"]
    out.append(mermaid_init())
    out.append(f"flowchart {direction}")

    # nodes grouped into one subgraph per cluster
    for rank in ranks:
        out.append(f'  subgraph cl{rank}["{_cluster_caption(rank, by_comm[rank])}"]')
        out.append("    direction TB")
        for n in by_comm[rank]:
            out.append("    " + node_stmt(idmap[n["id"]], n))
        out.append("  end")

    # edges (declared after subgraphs so they can cross cluster boxes).
    # line_styles is index-aligned with every edge line we emit, so linkStyle N
    # always targets the Nth edge — real edges first, legend samples last.
    line_styles = []
    labelled = set()          # (rel, target) already named — see the de-duplication note above
    for e in edges:
        s, t = idmap.get(e.get("source")), idmap.get(e.get("target"))
        if not s or not t:
            continue
        arrow = "-.->" if is_inferred(e) else "-->"
        rel = esc(e.get("rel", ""), 18)
        key = (rel, t)
        if rel and (not dedup_labels or key not in labelled):
            labelled.add(key)
            out.append(f'  {s} {arrow}|"{rel}"| {t}')
        else:
            out.append(f"  {s} {arrow} {t}")
        line_styles.append(EDGE_COLOR.get(e.get("link_class", "link"), "#b9b2a4"))

    out += _class_defs(ranks)
    out += _class_assignments(nodes, by_comm, ranks, idmap)

    if legend:
        out.append(f'  subgraph legend["{box_title("Legend")}"]')
        out.append("    direction LR")
        for i, (cls, text) in enumerate(EDGE_CLASS_LABEL.items()):
            out.append(f'    lg{i}a(("&nbsp;")) -->|"{text}"| lg{i}b(("&nbsp;"))')
            line_styles.append(EDGE_COLOR[cls])
        out.append("  end")

    # per-edge stroke color = evidence class (index-aligned with emitted edges)
    out += _link_styles(line_styles)
    return "\n".join(out) + "\n"


def _class_defs(ranks):
    """Node fill = cluster. White hairline border, because the fills are dark and a dark stroke
    just thickens the silhouette; the shape carries the type, the fill carries the cluster."""
    out = []
    for rank in ranks:
        fill = COMM[rank % len(COMM)]
        out.append(f"  classDef cluster{rank} fill:{fill},color:#ffffff,"
                   f"stroke:#ffffff,stroke-width:1.25px;")
    out.append(f"  classDef operator fill:{OPERATOR_FILL},color:#ffffff,"
               f"stroke:{OPERATOR_STROKE},stroke-width:2.5px;")
    return out


def _class_assignments(nodes, by_comm, ranks, idmap):
    out = []
    for rank in ranks:
        ids = [idmap[n["id"]] for n in by_comm[rank]
               if n.get("type") not in ("operator", "person")]
        if ids:
            out.append(f"  class {','.join(ids)} cluster{rank};")
    anchors = [idmap[n["id"]] for n in nodes
               if n.get("type") in ("operator", "person")]
    if anchors:
        out.append(f"  class {','.join(anchors)} operator;")
    return out


def _link_styles(line_styles):
    return [f"  linkStyle {i} stroke:{col},stroke-width:1.6px;"
            for i, col in enumerate(line_styles)]


def build_legend(graph, title="Legend — how to read the graph"):
    """The legend as a STANDALONE figure — a key card, not a box competing with the graph.

    It says three things the inline box never did: what an edge COLOUR means, what a dashed edge
    means (inferred, not observed — the difference between a fact and a hypothesis in the same
    picture), and what each SHAPE and CLUSTER FILL is. Only the types and clusters actually
    present in this graph are drawn, so the key never explains a shape the reader cannot see."""
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    present_types, present_classes = [], []
    for n in nodes:
        t = n.get("type") or ""
        if t and t not in present_types:
            present_types.append(t)
    for e in edges:
        c = e.get("link_class") or "link"
        if c in EDGE_CLASS_LABEL and c not in present_classes:
            present_classes.append(c)
    present_classes = present_classes or list(EDGE_CLASS_LABEL)
    ranks = sorted({n.get("community_rank", 0) for n in nodes})
    has_inferred = any(is_inferred(e) for e in edges)
    has_confirmed = any(not is_inferred(e) for e in edges)

    # LAYOUT, WHICH IS ALL DAGRE DIRECTION RULES AND WORTH WRITING DOWN ONCE:
    #   * outer `flowchart TB` + an INVISIBLE `~~~` chain between the boxes stacks them top to
    #     bottom IN DECLARED ORDER. Without the chain the boxes are disconnected components and
    #     dagre packs them in whatever order it likes — which came out reversed, so the reader
    #     met "cluster fill" before "edge colour".
    #   * a box whose content is CONNECTED pairs (the edge samples) needs `direction LR`, or the
    #     sample arrow is drawn pointing downwards and the box grows into a column.
    #   * a box whose content is DISCONNECTED single nodes (the shape key) needs `direction TB`,
    #     which lays them out in a row. Yes, that is the opposite of what it sounds like: the
    #     direction governs the flow axis, and unconnected nodes stack across it.
    # A key card wants to be compact: the graph's generous rank spacing here just puts air
    # between four small boxes and makes the figure taller than the graph it explains.
    out = ["---", f"title: {yaml_title(title)}", "---",
           mermaid_init({"rankSpacing": 34, "nodeSpacing": 30}), "flowchart TB"]
    styles, boxes = [], []

    boxes.append("lgc")
    out.append(f'  subgraph lgc["{box_title("Edge colour")}"]')
    out.append("    direction LR")
    for i, cls in enumerate(present_classes):
        out.append(f'    c{i}a(("&nbsp;")) -->|"{EDGE_CLASS_LABEL[cls]}"| c{i}b(("&nbsp;"))')
        styles.append(EDGE_COLOR[cls])
    out.append("  end")

    # Explain whichever styles are actually drawn. A graph where EVERY edge is inferred still
    # needs the dashed line explained — arguably more than a mixed one does, because a reader
    # who is not told will take the whole picture for observed fact.
    if has_inferred or has_confirmed:
        boxes.append("lgs")
        out.append(f'  subgraph lgs["{box_title("Edge style")}"]')
        out.append("    direction LR")
        if has_confirmed:
            out.append('    s0a(("&nbsp;")) -->|"observed / confirmed"| s0b(("&nbsp;"))')
            styles.append(EDGE_COLOR["infra"])
        if has_inferred:
            out.append('    s1a(("&nbsp;")) -.->|"inferred — not observed"| s1b(("&nbsp;"))')
            styles.append(EDGE_COLOR["infra"])
        out.append("  end")

    if present_types:
        boxes.append("lgn")
        out.append(f'  subgraph lgn["{box_title("Node type")}"]')
        out.append("    direction TB")
        for i, t in enumerate(present_types):
            fake = {"type": t, "icon": ICON.get(t, "•"),
                    "label": TYPE_LABEL.get(t, t.replace("_", " "))}
            out.append("    " + node_stmt(f"t{i}", fake))
        out.append("  end")

    if len(ranks) > 1:
        boxes.append("lgk")
        out.append(f'  subgraph lgk["{box_title("Cluster fill")}"]')
        out.append("    direction TB")
        for rank in ranks:
            out.append(f'    k{rank}["Cluster {rank}"]')
        out.append("  end")

    # The invisible spine. Declared AFTER every sample edge so it cannot shift the linkStyle
    # indices those depend on.
    for a, b in zip(boxes, boxes[1:]):
        out.append(f"  {a} ~~~ {b}")

    out += _class_defs(ranks)
    # the shape key is tinted neutrally: it explains SHAPE, and colouring it by cluster would
    # imply a type belongs to a cluster, which is exactly the wrong reading.
    out.append("  classDef keyshape fill:#4a6572,color:#ffffff,stroke:#ffffff,stroke-width:1.25px;")
    out.append("  classDef keydot fill:#ffffff,stroke:#ffffff,color:#ffffff;")
    if present_types:
        ids = [f"t{i}" for i, t in enumerate(present_types) if t not in ("operator", "person")]
        anchors = [f"t{i}" for i, t in enumerate(present_types) if t in ("operator", "person")]
        if ids:
            out.append(f"  class {','.join(ids)} keyshape;")
        if anchors:
            out.append(f"  class {','.join(anchors)} operator;")
    if len(ranks) > 1:
        for rank in ranks:
            out.append(f"  class k{rank} cluster{rank};")
    dots = []
    for i, _ in enumerate(present_classes):
        dots += [f"c{i}a", f"c{i}b"]
    if has_inferred and has_confirmed:
        dots += ["s0a", "s0b", "s1a", "s1b"]
    if dots:
        out.append(f"  class {','.join(dots)} keydot;")
    out += _link_styles(styles)
    return "\n".join(out) + "\n"


def subgraph_of_cluster(graph, rank):
    """One cluster's own sub-graph — nodes in it, plus every edge with both ends inside."""
    nodes = [n for n in graph.get("nodes", []) if n.get("community_rank", 0) == rank]
    ids = {n["id"] for n in nodes}
    edges = [e for e in graph.get("edges", [])
             if e.get("source") in ids and e.get("target") in ids]
    return {"nodes": nodes, "edges": edges}


def _node_degree(edges):
    deg = {}
    for e in edges:
        deg[e.get("source")] = deg.get(e.get("source"), 0) + 1
        deg[e.get("target")] = deg.get(e.get("target"), 0) + 1
    return deg


def downsample(graph, max_nodes):
    """Reduce a large estate to a READABLE, REPRESENTATIVE subgraph of <= max_nodes.

    A 300-node estate rendered in one figure is an unreadable hairball — labels
    shrink to nothing and mermaid/dagre can time out. Rather than break the display
    (or silently ship the hairball), keep the nodes that carry the argument and say
    so on the figure; the FULL indicator set stays in the IOC bundle.

    Selection is deterministic and evidence-led:
      1. every operator/person ANCHOR (the nodes a reader must find),
      2. the highest-degree node in EACH community (no cluster vanishes),
      3. fill the remaining budget by global degree (hubs first), dropping the
         fan-out infrastructure types (FANOUT_TYPES) last.

    Returns (subgraph, kept_count, total_count). A graph already within budget is
    returned unchanged.
    """
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    total = len(nodes)
    if total <= max_nodes:
        return graph, total, total
    deg = _node_degree(edges)

    def is_anchor(n):
        return n.get("type") in ("operator", "person")

    kept = {n["id"] for n in nodes if is_anchor(n)}

    by_comm = {}
    for n in nodes:
        by_comm.setdefault(n.get("community_rank", 0), []).append(n)
    for members in by_comm.values():
        best = max(members, key=lambda n: deg.get(n["id"], 0))
        kept.add(best["id"])

    # Fill by degree; fan-out infra sorts last so hubs and meaningful nodes win the
    # budget. Tie-break on id keeps the choice deterministic across runs.
    remaining = [n for n in nodes if n["id"] not in kept]
    remaining.sort(key=lambda n: (n.get("type") in FANOUT_TYPES,
                                  -deg.get(n["id"], 0), str(n["id"])))
    for n in remaining:
        if len(kept) >= max_nodes:
            break
        kept.add(n["id"])

    sub_nodes = [n for n in nodes if n["id"] in kept]
    sub_edges = [e for e in edges
                 if e.get("source") in kept and e.get("target") in kept]
    sub = dict(graph)
    sub["nodes"] = sub_nodes
    sub["edges"] = sub_edges
    return sub, len(sub_nodes), total


def render_triple(mmd_path, stem, *, scale=2, width=0, pdf=False):
    """Shell out to render_mermaid.py for PNG + SVG + thumb (+ vector PDF). Non-fatal and bounded:
    a timeout or render failure warns, keeps the editable .mmd, and returns [] so the caller still
    emits the legend/cluster companions and finishes."""
    render = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "render_mermaid.py")
    cmd = [sys.executable, render, mmd_path, stem, "--scale", str(scale)]
    if width:
        cmd += ["--width", str(width)]
    if pdf:
        cmd += ["--pdf"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=int(os.environ.get("MERMAID_RENDER_TIMEOUT") or 200))
    except subprocess.TimeoutExpired:
        sys.stderr.write(f"[graph_to_diagram] render timed out for {stem} — kept the .mmd, "
                         "skipped raster; companion figures continue.\n")
        return []
    if r.returncode != 0:
        sys.stderr.write((r.stdout or "") + (r.stderr or ""))
        sys.stderr.write(f"[graph_to_diagram] render_mermaid.py failed for {stem} — kept the .mmd, "
                         "skipped raster; companion figures continue.\n")
        return []
    outs = [f"{stem}.svg", f"{stem}_hires.png", f"{stem}_thumb.png"]
    return outs + ([f"{stem}.pdf"] if pdf else [])


def _write(mmd_text, stem):
    path = f"{stem}.mmd"
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(mmd_text)
    return path


def main():
    ap = argparse.ArgumentParser(
        description="case_graph.json -> editable Mermaid -> PNG/SVG")
    ap.add_argument("graph_json", help="graph_build.py case graph JSON")
    ap.add_argument("stem", help="output path stem (no extension)")
    ap.add_argument("--title", default="", help="diagram title (frontmatter)")
    ap.add_argument("--direction", default="LR", choices=["LR", "TB", "RL", "BT"],
                    help="flow direction (default LR)")
    ap.add_argument("--legend", action="store_true",
                    help="emit the legend. On a multi-cluster graph this is a COMPANION FIGURE "
                         "(<stem>_legend.*) — embed it beside the graph")
    ap.add_argument("--inline-legend", action="store_true",
                    help="force the legend into the diagram itself (single figure). On a "
                         "multi-cluster graph it competes with the graph for space")
    ap.add_argument("--split-clusters", action="store_true",
                    help="also emit one figure per cluster (<stem>_cluster<N>.*) — for an estate "
                         "too dense to read at printed width in one picture")
    ap.add_argument("--all-edge-labels", action="store_true",
                    help="label every edge, including the repeats (default: one label per "
                         "relation→target, so fifteen domains sharing a registrar say it once)")
    ap.add_argument("--scale", type=float, default=2,
                    help="device scale for the hi-res PNG (default 2) — pixel density without "
                         "shrinking the type")
    ap.add_argument("--width", type=int, default=0, help="layout width px (default: renderer's)")
    ap.add_argument("--pdf", action="store_true",
                    help="also emit <stem>.pdf, the VECTOR figure a PDF report should embed")
    ap.add_argument("--drop-types", default="",
                    help="comma-list of node TYPES to prune before rendering (declutters a report "
                         "figure so the meaningful nodes render large), e.g. "
                         "nameserver,registrar,template,theme,email")
    ap.add_argument("--no-render", action="store_true",
                    help="write only the .mmd source; skip PNG/SVG rendering")
    ap.add_argument("--max-nodes", type=int, default=CROWDED_NODES,
                    help="above this many nodes the MAIN figure is reduced to a readable "
                         "REPRESENTATIVE subset (anchors + per-cluster hubs + top-degree "
                         "nodes; fan-out infra dropped first) and the figure title says so, "
                         "pointing the reader to the full IOC bundle. Default %d" % CROWDED_NODES)
    ap.add_argument("--full", action="store_true",
                    help="never downsample — render every node in one figure even when it is "
                         "too dense to read (the old behaviour; the overview an analyst may want)")
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

    full_nodes = graph.get("nodes", [])
    full_ranks = sorted({n.get("community_rank", 0) for n in full_nodes})

    # Large infra: build the MAIN figure from a representative subset so it stays
    # readable instead of collapsing into a hairball. The full graph is still used
    # for the legend and the per-cluster figures; the full indicator set lives in
    # the IOC bundle, which the subset title names.
    if args.full:
        graph_main, kept, total = graph, len(full_nodes), len(full_nodes)
    else:
        graph_main, kept, total = downsample(graph, args.max_nodes)
    subset = kept < total
    title = args.title
    if subset:
        note = ("representative subset: %d of %d nodes — full IOCs in the bundle "
                "(CSV / Markdown / JSONL)" % (kept, total))
        title = ("%s · %s" % (args.title, note)) if args.title else ("Case graph · %s" % note)

    main_ranks = sorted({n.get("community_rank", 0) for n in graph_main.get("nodes", [])})
    # The split decision, in one place: a legend was asked for, the graph has enough clusters to
    # make an inline box crowd it out, and the caller has not overridden.
    split_legend = bool(args.legend) and not args.inline_legend \
        and len(main_ranks) >= LEGEND_SPLIT_MIN_CLUSTERS

    mmd_path = _write(build_mermaid(graph_main, title, args.direction,
                                    legend=bool(args.legend) and not split_legend,
                                    dedup_labels=not args.all_edge_labels), args.stem)
    outs, companions = [mmd_path], []
    render = dict(scale=args.scale, width=args.width, pdf=args.pdf)
    if not args.no_render:
        outs += render_triple(mmd_path, args.stem, **render)

    if split_legend:
        lstem = f"{args.stem}_legend"
        lpath = _write(build_legend(graph), lstem)
        companions.append(lpath)
        if not args.no_render:
            companions += render_triple(lpath, lstem, **render)

    if args.split_clusters and len(full_ranks) > 1:
        for rank in full_ranks:
            sub = subgraph_of_cluster(graph, rank)
            if not sub["nodes"]:
                continue
            cstem = f"{args.stem}_cluster{rank}"
            ctitle = f"{args.title} — cluster {rank}" if args.title else f"Cluster {rank}"
            cpath = _write(build_mermaid(sub, ctitle, args.direction, legend=False,
                                         dedup_labels=not args.all_edge_labels), cstem)
            companions.append(cpath)
            if not args.no_render:
                companions += render_triple(cpath, cstem, **render)

    print("wrote (editable source first):\n  " + "\n  ".join(outs))
    if companions:
        print("companion figure(s) — EMBED THESE TOO, the main figure no longer explains "
              "itself alone:\n  " + "\n  ".join(companions))
    if subset:
        sys.stderr.write(
            "[graph_to_diagram] NOTE: %d nodes reduced to a REPRESENTATIVE subset of %d for a "
            "readable figure. The full indicator set is in the IOC bundle "
            "(generate-cti-iocs.py -> .csv / .txt / STIX; open the .csv in Excel). Use --full "
            "to force the whole graph, or --split-clusters for one figure per cluster.\n"
            % (total, kept))
    elif len(full_nodes) > CROWDED_NODES and not args.split_clusters:
        sys.stderr.write(
            f"[graph_to_diagram] NOTE: {len(full_nodes)} nodes in one figure. At printed width "
            f"the labels will be small. Consider --split-clusters, or --drop-types to prune the "
            f"infrastructure nodes (nameserver,registrar,regdate) that fan out without "
            f"carrying the argument.\n")


if __name__ == "__main__":
    main()
