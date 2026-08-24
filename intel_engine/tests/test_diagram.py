#!/usr/bin/env python3
"""
test_diagram.py — the gate on the IntelGraph FIGURE layer (mermaid case graphs).

Run:  python3 tests/test_diagram.py
      python3 tools/eval/run_eval.py          (runs as part of the regression gate)

WHAT THIS PROTECTS
------------------
Every defect below shipped in a real report before it was fixed, and every one of them fails
SILENTLY — the figure renders, it is just wrong in a way only a reader notices:

  1. THE INIT DIRECTIVE. mermaid discards the ENTIRE `%%{init}%%` block if it contains a quote
     character, and reads `fontFamily` only at the config top level (not inside themeVariables).
     Either mistake leaves the figure at mermaid defaults — 16px type in a trebuchet stack that a
     headless Chrome resolves to a SERIF face, so the diagram quietly stops matching the report.
  2. METRIC-CHANGING CSS. mmdc appends the house stylesheet INTO the finished SVG, after mermaid
     has hard-coded a <foreignObject> per label from its own measurement. A font-size or padding
     rule there overflows a box that can no longer grow, and the label renders as a blank white
     pill with the glyphs clipped away.
  3. THE LEGEND. An inline legend box on a multi-cluster graph overflows its own title and eats a
     third of the figure; it must become a companion figure instead.
  4. EDGE-LABEL REPEATS. Fifteen domains sharing one registrar wrote "registrar" fifteen times
     across the same fan of curves.
  5. RED. The operator anchor is the one node a reader must find first, so no community fill may
     collide with it, and two adjacent clusters must not read as one.

All offline: the .mmd source and the stylesheet are strings, so nothing here needs mmdc, a
browser, or the network.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "IntelGraph", "scripts"),):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import graph_to_diagram as G          # noqa: E402
import theme as T                     # noqa: E402

CSS = os.path.join(ROOT, "IntelGraph", "references", "diagram.css")

# Properties that change how wide or tall a label renders. See failure mode 2.
METRIC_PROPS = ("font-size", "padding", "letter-spacing", "text-transform",
                "font-weight", "line-height", "font-family", "white-space")
# The one selector allowed to set them: a standalone centred title with no box to overflow.
METRIC_SAFE_SELECTORS = ("flowchartTitleText",)


def _graph(n_clusters=2, rel="registrar", n_domains=3):
    """A synthetic case graph: n_domains domains in cluster 0 all pointing at ONE registrar,
    plus an operator anchor, plus a second cluster when asked. Placeholder values only."""
    nodes = [{"id": f"site-{i}.example", "type": "domain", "label": f"site-{i}.example",
              "shape": "round-rectangle", "community_rank": 0} for i in range(n_domains)]
    nodes.append({"id": "registrar:example", "type": "registrar", "label": "Registrar Name",
                  "shape": "rhomboid", "community_rank": 0})
    nodes.append({"id": "operator-a", "type": "operator", "label": "Operator A",
                  "shape": "star", "community_rank": 0})
    edges = [{"source": f"site-{i}.example", "target": "registrar:example", "rel": rel,
              "link_class": "infra", "confidence": "inferred"} for i in range(n_domains)]
    if n_clusters > 1:
        nodes.append({"id": "other.example", "type": "domain", "label": "other.example",
                      "shape": "round-rectangle", "community_rank": 1})
        nodes.append({"id": "ip:198.51.100.7", "type": "ip", "label": "198.51.100.7",
                      "shape": "hexagon", "community_rank": 1})
        edges.append({"source": "other.example", "target": "ip:198.51.100.7", "rel": "ip",
                      "link_class": "operator", "confidence": "confirmed"})
    return {"nodes": nodes, "edges": edges}


def check():
    """Return (passed, failed, [(status, label)]) — the tools/eval unit-module contract."""
    out, passed, failed = [], 0, 0

    def ok(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1
            out.append(("ok", label))
        else:
            failed += 1
            out.append(("FAIL", label))

    # --- 1. the init directive ----------------------------------------------------------
    init = T.mermaid_init()
    ok("'" not in init,
       "the mermaid init directive contains NO quote character — one voids the whole directive "
       "and drops the figure to mermaid defaults, silently")
    ok(re.search(r'"fontFamily"\s*:', init.split('"themeVariables"')[0]) is not None,
       "fontFamily is a TOP-LEVEL config key — inside themeVariables it is ignored and the "
       "figure renders in a default stack that resolves to serif on headless Chrome")
    ok('"fontFamily"' not in init.split('"themeVariables"')[-1],
       "fontFamily is not ALSO left in themeVariables, where it would read as the live setting")
    ok('"fontSize"' in init and '"subGraphTitleMargin"' in init,
       "the directive still carries the metric settings that must be read BEFORE measurement")

    # --- 2. the stylesheet is metric-safe ------------------------------------------------
    css = open(CSS, encoding="utf-8").read()
    body = re.sub(r"/\*.*?\*/", "", css, flags=re.S)          # comments may discuss anything
    offenders = []
    for block in re.finditer(r"([^{}]+)\{([^}]*)\}", body):
        selector, decls = block.group(1).strip(), block.group(2)
        if any(s in selector for s in METRIC_SAFE_SELECTORS):
            continue
        for prop in METRIC_PROPS:
            if re.search(r"(^|[;\s])%s\s*:" % re.escape(prop), decls):
                offenders.append(f"{selector.splitlines()[-1].strip()} → {prop}")
    ok(not offenders,
       "the injected stylesheet sets NO metric-changing property outside the title — mmdc "
       "appends it after mermaid has sized every label box, so such a rule clips the text"
       + (f" (found: {offenders[:3]})" if offenders else ""))
    ok("!important" in css,
       "the stylesheet uses !important where it must beat mermaid's own id-prefixed rules")

    # --- 3. edge-label de-duplication -----------------------------------------------------
    g = _graph(n_clusters=1, n_domains=4)
    mmd = G.build_mermaid(g, "t", "LR", legend=False)
    ok(mmd.count('|"registrar"|') == 1,
       "four domains sharing one registrar produce ONE 'registrar' label, not four")
    ok(mmd.count("-.->") == 4,
       "every edge is still DRAWN — de-duplication removes repeated labels, never edges")
    mmd_all = G.build_mermaid(g, "t", "LR", legend=False, dedup_labels=False)
    ok(mmd_all.count('|"registrar"|') == 4,
       "--all-edge-labels restores every repeat for an analyst who wants them")

    # --- 4. linkStyle indices stay aligned with the emitted edges -------------------------
    g2 = _graph(n_clusters=2)
    mmd2 = G.build_mermaid(g2, "t", "LR", legend=True)          # inline legend adds sample edges
    n_edges = len([ln for ln in mmd2.splitlines()
                   if re.search(r"\s(-->|-\.->)", ln) and "linkStyle" not in ln])
    n_styles = len(re.findall(r"^\s*linkStyle \d+", mmd2, re.M))
    ok(n_edges == n_styles,
       "one linkStyle per emitted edge — the colours are index-aligned, so a mismatch would "
       f"paint evidence classes onto the wrong edges (edges={n_edges}, styles={n_styles})")

    # --- 5. the legend splits on a multi-cluster graph -------------------------------------
    main = G.build_mermaid(g2, "t", "LR", legend=False)
    ok("subgraph legend" not in main,
       "the split main figure carries no legend box competing with the graph")
    leg = G.build_legend(g2)
    ok(leg.startswith("---") and "flowchart TB" in leg,
       "the legend is a standalone figure with its own title")
    ok("~~~" in leg,
       "the legend's boxes are chained with an invisible link so they stack in DECLARED order — "
       "without it dagre packs them in its own order and the reader meets the cluster key first")
    ok('"same operator"' in leg and '"shared infrastructure"' in leg,
       "the legend explains the edge classes actually present in the graph")
    ok("inferred" in leg and "observed" in leg,
       "the legend explains the dashed edge — a reader not told takes the whole picture for fact")
    ok("registrar" in leg and "IP address" in leg,
       "the legend explains the node SHAPES, which the old inline box never did")
    ok("Cluster 0" in leg and "Cluster 1" in leg,
       "the legend names each cluster fill")
    only_one = G.build_legend(_graph(n_clusters=1))
    ok("Cluster 0" not in only_one,
       "a single-cluster graph gets no cluster-fill key — the legend never explains a "
       "distinction the reader cannot see")

    # --- 6. box titles cannot overflow their own box --------------------------------------
    long_title = G.box_title("Legend — edge colour = evidence class, dashed = inferred")
    ok(len(long_title) <= G.MAX_BOX_TITLE,
       "every subgraph title is length-capped — an over-long one is centred over a box sized by "
       "its CONTENT and lands on the nodes inside it (the original defect)")
    cap = G._cluster_caption(0, list(range(10)))
    ok("10 nodes" in cap and len(cap) <= G.MAX_BOX_TITLE,
       "a cluster caption states its size, so a thin-looking box can be told from a pruned one")

    # --- 7. red is reserved for the anchor -------------------------------------------------
    ok(T.OPERATOR_FILL not in T.COMMUNITY_CYCLE,
       "no community fill equals the operator anchor's fill")
    ok(T.COMMUNITY_CYCLE[0] != T.COMMUNITY_CYCLE[1],
       "the first two community fills differ — a two-cluster case is the common shape and two "
       "near-identical slates read as one cluster rendered twice")
    ok(len({c.lower() for c in T.COMMUNITY_CYCLE}) == len(T.COMMUNITY_CYCLE),
       "no community fill is repeated in the cycle")

    # --- 8. per-cluster split -------------------------------------------------------------
    sub = G.subgraph_of_cluster(g2, 1)
    ok(len(sub["nodes"]) == 2 and len(sub["edges"]) == 1,
       "a per-cluster figure carries that cluster's nodes and only the edges inside it")
    return passed, failed, out


if __name__ == "__main__":
    _PASSED, _FAILED, _LINES = check()
    for _status, _label in _LINES:
        print(f"  {'ok  ' if _status == 'ok' else 'FAIL'} {_label}")
    print(f"\n{'PASS' if not _FAILED else 'FAIL'} — {_PASSED} passed, {_FAILED} failed")
    sys.exit(1 if _FAILED else 0)
