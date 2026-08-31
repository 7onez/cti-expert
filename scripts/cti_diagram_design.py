#!/usr/bin/env python3
"""
cti_diagram_design.py — editorial CTI diagrams as self-contained SVG, following
the Diagram Design editorial system (https://github.com/cathrynlavery/diagram-design).

Diagram Design ships no renderer — it is an editorial *style system* (tokens,
typography, density and accent rules). This module applies that system
deterministically to two CTI figures:

  * build_entity_svg(data)    — entity relationship map (subjects + connections)
  * build_topology_svg(data)  — infrastructure tiers (orgs -> domains -> hosts)

Design rules honored (see vendor/diagram-design/style-guide.md):
  * cool editorial palette (white-smoke paper, jet-black ink, atomic-tangerine accent)
  * accent is FOCAL, 1-2 nodes max (primary subject + top critical)
  * hairline rules, no shadows, radius 6, every coord on a 4px grid
  * serif title / sans names / mono eyebrows & arrow labels

OFFLINE constraint: the CTI HTML report ships no CDN/web-fonts, so we use generic
serif/sans/mono font stacks instead of Diagram Design's Google-hosted Geist /
Instrument Serif. The editorial *look* (palette, density, hairlines, accent) is
preserved; only the exact typeface differs.

render_svg_to_png() rasterizes SVG for embedding in DOCX (cairosvg); it returns
None when cairosvg / its cairo system lib is unavailable, so callers fall back.

Author: CTI Expert
"""
import math

# --- editorial tokens (light skin) -------------------------------------------
PAPER = "#f5f5f5"
PAPER2 = "#ececec"
INK = "#2d3142"
MUTED = "#4f5d75"
SOFT = "#7a8399"
RULE = "rgba(45,49,66,0.12)"
RULE_SOLID = "#bfc0c0"
ACCENT = "#eb6c36"
ACCENT_TINT = "rgba(235,108,54,0.10)"

SERIF = "'Iowan Old Style','Palatino Linotype',Palatino,Georgia,'Times New Roman',serif"
SANS = "system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif"
MONO = "ui-monospace,'SF Mono','Cascadia Mono',Consolas,'Liberation Mono',monospace"

# CTI entity type -> editorial treatment (fill, stroke) per style-guide "Node type"
TREATMENTS = {
    "backend": ("#ffffff", INK),
    "store": ("rgba(45,49,66,0.05)", MUTED),
    "external": ("rgba(45,49,66,0.03)", "rgba(45,49,66,0.30)"),
    "focal": (ACCENT_TINT, ACCENT),
}
# entity type -> treatment role
TYPE_ROLE = {
    "person": "external", "individual": "external",
    "organization": "external", "org": "external",
    "email": "external", "username": "external", "handle": "external",
    "phone": "external", "location": "external",
    "domain": "backend", "url": "backend",
    "ip": "store", "network_addr": "store", "device": "store", "asn": "store",
    "document": "store", "asset": "store", "image": "store",
    "wallet": "store", "crypto_address": "store",
}
TYPE_LABEL = {
    "person": "PERSON", "individual": "PERSON", "organization": "ORG", "org": "ORG",
    "domain": "DOMAIN", "url": "URL", "email": "EMAIL", "username": "USERNAME",
    "handle": "USERNAME", "ip": "IP", "network_addr": "IP", "device": "DEVICE",
    "asn": "ASN", "phone": "PHONE", "wallet": "WALLET", "crypto_address": "WALLET",
    "location": "LOCATION", "document": "DOCUMENT", "asset": "ASSET",
    "image": "IMAGE", "event": "EVENT",
}
TYPE_TIER = {
    "person": 0, "individual": 0, "organization": 0, "org": 0,
    "username": 0, "handle": 0, "email": 0,
    "domain": 1, "url": 1,
    "ip": 2, "network_addr": 2, "device": 2, "asn": 2,
}
MISC_TIER = 3
SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

NODE_H = 52
GAP_X = 32
GAP_Y = 64
MARGIN = 40
TOP = 96          # title band
MAX_COLS = 5


def _esc(s):
    return (str("" if s is None else s)
            .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


def _lc(v):
    return str(v or "").strip().lower()


def _q4(n):
    """Round up to the 4px grid (style-guide hard rule)."""
    return int(math.ceil(n / 4.0) * 4)


def _text_w(s, px, em=0.60):
    return len(str(s)) * px * em


def _truncate(s, maxchars):
    s = str(s)
    return s if len(s) <= maxchars else s[:maxchars - 1] + "\u2026"


def _top_severity(findings):
    best = {}
    for f in findings or []:
        sid = f.get("subject_id")
        if not sid:
            continue
        w = str(f.get("weight") or "INFO").upper()
        r = SEV_RANK.get(w, 4)
        if sid not in best or r < best[sid][0]:
            best[sid] = (r, w)
    return {sid: w for sid, (_, w) in best.items()}


def _focal_ids(subjects, case, sev):
    """Pick <=2 focal nodes: primary subject + the single most-severe subject."""
    focal = set()
    primary = _lc(case.get("subject"))
    for s in subjects:
        if primary and _lc(s.get("label")) == primary:
            focal.add(s["id"])
            break
    ranked = sorted((s for s in subjects if sev.get(s["id"]) in ("CRITICAL", "HIGH")),
                    key=lambda s: SEV_RANK.get(sev.get(s["id"], "INFO"), 4))
    for s in ranked:
        if len(focal) >= 2:
            break
        focal.add(s["id"])
    return focal


def _edge_point(cx, cy, w, h, tx, ty):
    """Point on the border of a box (centered cx,cy, size w,h) toward (tx,ty)."""
    dx, dy = tx - cx, ty - cy
    if dx == 0 and dy == 0:
        return cx, cy
    hw, hh = w / 2.0, h / 2.0
    sx = hw / abs(dx) if dx else float("inf")
    sy = hh / abs(dy) if dy else float("inf")
    s = min(sx, sy)
    return cx + dx * s, cy + dy * s


def _node_width(subjects):
    longest = 6
    for s in subjects:
        longest = max(longest, len(_truncate(s.get("label") or s["id"], 26)))
    return int(_clamp(_q4(longest * 7.2 + 28), 132, 240))


def _clamp(n, lo, hi):
    return max(lo, min(hi, n))


def _defs():
    return (
        '<defs>'
        '<marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
        'markerHeight="7" orient="auto-start-reverse">'
        '<path d="M0 0 L10 5 L0 10 z" fill="%s"/></marker>'
        '</defs>' % MUTED
    )


def _title_block(eyebrow, title, x=MARGIN, y=40):
    return (
        '<text x="%d" y="%d" font-family="%s" font-size="8" letter-spacing="3" '
        'fill="%s">%s</text>'
        '<text x="%d" y="%d" font-family="%s" font-size="21" fill="%s">%s</text>'
        % (x, y - 16, MONO, SOFT, _esc(eyebrow),
           x, y + 8, SERIF, INK, _esc(title))
    )


def _node_svg(x, y, w, h, role, eyebrow, name, sub):
    fill, stroke = TREATMENTS[role]
    dash = ' stroke-dasharray="4,4"' if role == "external" and False else ""
    focal = role == "focal"
    parts = [
        '<rect x="%d" y="%d" width="%d" height="%d" rx="6" fill="%s" stroke="%s" '
        'stroke-width="%s"%s/>' % (x, y, w, h, fill, stroke, "1.2" if focal else "1", dash),
        '<text x="%d" y="%d" font-family="%s" font-size="7.5" letter-spacing="2" '
        'fill="%s">%s</text>' % (x + 12, y + 17, MONO, ACCENT if focal else SOFT, _esc(eyebrow)),
        '<text x="%d" y="%d" font-family="%s" font-size="12" font-weight="600" '
        'fill="%s">%s</text>' % (x + 12, y + 34, SANS, INK, _esc(name)),
    ]
    if sub:
        parts.append(
            '<text x="%d" y="%d" font-family="%s" font-size="9" fill="%s">%s</text>'
            % (x + 12, y + 46, MONO, SOFT, _esc(sub)))
    return "".join(parts)


def build_entity_svg(data):
    """Entity relationship map as editorial SVG string (or None if no subjects)."""
    if not isinstance(data, dict):
        return None
    subjects = [s for s in (data.get("subjects") or []) if isinstance(s, dict) and s.get("id")]
    if not subjects:
        return None
    case = data.get("case", {}) or {}
    sev = _top_severity(data.get("findings"))
    focal = _focal_ids(subjects, case, sev)

    tiers = {}
    for s in subjects:
        tiers.setdefault(TYPE_TIER.get(_lc(s.get("type")), MISC_TIER), []).append(s)
    cols = _clamp(max((len(v) for v in tiers.values()), default=1), 1, MAX_COLS)
    nodeW = _node_width(subjects)
    stepX = nodeW + GAP_X
    stepY = NODE_H + GAP_Y

    pos = {}
    row_cursor = 0
    for tier in sorted(tiers):
        members = tiers[tier]
        n = len(members)
        for i, s in enumerate(members):
            r = row_cursor + (i // cols)
            c = i % cols
            row_n = min(cols, n - (i // cols) * cols)  # nodes in this wrapped row
            # centre each (possibly short) row within the grid width
            row_w = row_n * nodeW + (row_n - 1) * GAP_X
            grid_w = cols * nodeW + (cols - 1) * GAP_X
            x0 = MARGIN + (grid_w - row_w) / 2.0 + (i % cols) * stepX
            x = x0
            y = TOP + r * stepY
            pos[s["id"]] = (x + nodeW / 2.0, y + NODE_H / 2.0, x, y)
        row_cursor += math.ceil(n / cols) if n else 0

    rows_total = row_cursor
    width = _q4(MARGIN * 2 + cols * nodeW + (cols - 1) * GAP_X)
    height = _q4(TOP + rows_total * stepY - GAP_Y + MARGIN + 24)

    # edges — merge parallel/bidirectional pairs so overlapping relations don't pile
    # up into an unreadable stack of coincident lines + labels (Diagram Design
    # density-4/10 rule). Above ~30 distinct pairs, drop edge labels entirely.
    byid = {s["id"]: s for s in subjects}
    agg = {}
    for c in data.get("connections") or []:
        a, b = c.get("from_id"), c.get("to_id")
        if a not in pos or b not in pos or a == b:
            continue
        e = agg.get(frozenset((a, b)))
        if e is None:
            e = {"a": a, "b": b, "rels": [], "strong": False}
            agg[frozenset((a, b))] = e
        rel = str(c.get("relationship") or c.get("type") or "").replace("_", " ")
        if rel and rel not in e["rels"]:
            e["rels"].append(rel)
        if _lc(c.get("strength")) == "confirmed":
            e["strong"] = True
    show_labels = len(agg) <= 30
    edges = []
    for e in agg.values():
        acx, acy, _, _ = pos[e["a"]]
        bcx, bcy, _, _ = pos[e["b"]]
        p1 = _edge_point(acx, acy, nodeW, NODE_H, bcx, bcy)
        p2 = _edge_point(bcx, bcy, nodeW, NODE_H, acx, acy)
        dash = "" if e["strong"] else ' stroke-dasharray="5,4"'
        edges.append(
            '<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="%s" '
            'stroke-width="1"%s marker-end="url(#ah)"/>'
            % (p1[0], p1[1], p2[0], p2[1], MUTED, dash))
        if show_labels and e["rels"]:
            rel = e["rels"][0] if len(e["rels"]) == 1 else "%s \u00d7%d" % (e["rels"][0], len(e["rels"]))
            mx, my = (p1[0] + p2[0]) / 2.0, (p1[1] + p2[1]) / 2.0
            lw = _text_w(rel, 8, 0.62) + 8
            edges.append(
                '<rect x="%.1f" y="%.1f" width="%.1f" height="13" fill="%s"/>'
                '<text x="%.1f" y="%.1f" font-family="%s" font-size="8" '
                'letter-spacing="0.5" fill="%s" text-anchor="middle">%s</text>'
                % (mx - lw / 2, my - 9, lw, PAPER, mx, my, MONO, MUTED, _esc(rel)))

    nodes = []
    for s in subjects:
        _, _, x, y = pos[s["id"]]
        t = _lc(s.get("type"))
        role = "focal" if s["id"] in focal else TYPE_ROLE.get(t, "external")
        conf = s.get("confidence")
        sub = ("%d%% confidence" % int(conf)) if isinstance(conf, (int, float)) else ""
        sev_tag = sev.get(s["id"])
        if sev_tag in ("CRITICAL", "HIGH"):
            sub = (sub + "  ·  " + sev_tag) if sub else sev_tag
        nodes.append(_node_svg(int(x), int(y), nodeW, NODE_H, role,
                               TYPE_LABEL.get(t, (s.get("type") or "ENTITY")),
                               _truncate(s.get("label") or s["id"], 26), sub))

    legend = _legend(subjects, focal, width, height)
    title = _title_block("ENTITY RELATIONSHIP MAP",
                         case.get("label") or case.get("subject") or "CTI Entities")

    return _wrap(width, height, _defs() + title + "".join(edges) + "".join(nodes) + legend)


def _legend(subjects, focal, width, height):
    items = []
    if focal:
        items.append((ACCENT, "Focal"))
    roles_present = {TYPE_ROLE.get(_lc(s.get("type")), "external") for s in subjects}
    label = {"backend": "Domain/URL", "store": "Host/asset", "external": "Actor/contact"}
    for role in ("backend", "store", "external"):
        if role in roles_present:
            items.append((TREATMENTS[role][1], label[role]))
    y = height - 20
    out = []
    x = MARGIN
    for color, text in items:
        out.append(
            '<rect x="%d" y="%d" width="11" height="11" rx="2" fill="none" '
            'stroke="%s" stroke-width="1.2"/>'
            '<text x="%d" y="%d" font-family="%s" font-size="8" letter-spacing="1.5" '
            'fill="%s">%s</text>' % (x, y, color, x + 16, y + 9, MONO, SOFT, _esc(text.upper())))
        x += 20 + _text_w(text, 8, 0.62) + 22
    return "".join(out)


def build_topology_svg(data):
    """Infrastructure tiers (orgs -> domains/urls -> hosts) as editorial columns."""
    if not isinstance(data, dict):
        return None
    subjects = [s for s in (data.get("subjects") or []) if isinstance(s, dict) and s.get("id")]
    tiers = [
        ("ORGANIZATIONS", ("organization", "org")),
        ("DOMAINS / URLS", ("domain", "url")),
        ("HOSTS / IPS / DEVICES", ("ip", "network_addr", "device", "asn")),
    ]
    cols = []
    for label, types in tiers:
        cols.append((label, [s for s in subjects if _lc(s.get("type")) in types]))
    if not any(c[1] for c in cols):
        return None

    colW = 220
    gapX = 56
    top = TOP
    cardH = 46
    cardGap = 14
    width = _q4(MARGIN * 2 + 3 * colW + 2 * gapX)
    max_rows = max((len(c[1]) for c in cols), default=1)
    height = _q4(top + max_rows * (cardH + cardGap) + MARGIN)

    parts = [_title_block("INFRASTRUCTURE TOPOLOGY", "Organizations \u00b7 Domains \u00b7 Hosts")]
    centers = []  # per column: (x_left, x_right, [card_y_centers])
    for ci, (label, members) in enumerate(cols):
        cx = MARGIN + ci * (colW + gapX)
        parts.append(
            '<text x="%d" y="%d" font-family="%s" font-size="8" letter-spacing="2.5" '
            'fill="%s" text-anchor="middle">%s</text>'
            % (cx + colW / 2, top - 14, MONO, SOFT, _esc(label)))
        ys = []
        for i, s in enumerate(members):
            y = top + i * (cardH + cardGap)
            t = _lc(s.get("type"))
            conf = s.get("confidence")
            sub = TYPE_LABEL.get(t, "ENTITY") + (
                "  ·  %d%%" % int(conf) if isinstance(conf, (int, float)) else "")
            parts.append(
                '<rect x="%d" y="%d" width="%d" height="%d" rx="6" fill="#ffffff" '
                'stroke="%s" stroke-width="1"/>'
                '<rect x="%d" y="%d" width="3" height="%d" rx="1.5" fill="%s"/>'
                '<text x="%d" y="%d" font-family="%s" font-size="11.5" font-weight="600" '
                'fill="%s">%s</text>'
                '<text x="%d" y="%d" font-family="%s" font-size="8" letter-spacing="1" '
                'fill="%s">%s</text>'
                % (cx, y, colW, cardH, RULE_SOLID,
                   cx, y, cardH, ACCENT if i == 0 and ci == 0 else MUTED,
                   cx + 14, y + 20, SANS, INK, _esc(_truncate(s.get("label") or s["id"], 26)),
                   cx + 14, y + 36, MONO, SOFT, _esc(sub)))
            ys.append(y + cardH / 2.0)
        if not members:
            parts.append(
                '<text x="%d" y="%d" font-family="%s" font-size="9" fill="%s" '
                'text-anchor="middle">none</text>'
                % (cx + colW / 2, top + 24, MONO, SOFT))
        centers.append((cx, cx + colW, ys))

    # connectors between adjacent columns (first host of a column fans from the col before)
    for ci in range(len(cols) - 1):
        _, xr, ys_a = centers[ci]
        xl, _, ys_b = centers[ci + 1]
        if not ys_a or not ys_b:
            continue
        ay = sum(ys_a) / len(ys_a)
        for by in ys_b:
            parts.append(
                '<path d="M%d %.1f C %d %.1f, %d %.1f, %d %.1f" fill="none" '
                'stroke="%s" stroke-width="1" marker-end="url(#ah)"/>'
                % (xr, ay, xr + gapX / 2, ay, xl - gapX / 2, by, xl, by, MUTED))

    return _wrap(width, height, _defs() + "".join(parts))


def _wrap(width, height, inner):
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" '
        'height="%d" font-family="%s">'
        '<rect x="0" y="0" width="%d" height="%d" fill="%s"/>%s</svg>'
        % (width, height, width, height, SANS, width, height, PAPER, inner))


def render_svg_to_png(svg, scale=2.0):
    """Rasterize SVG -> PNG bytes via cairosvg; None if unavailable."""
    if not svg:
        return None
    try:
        import cairosvg
    except Exception:
        return None
    try:
        return cairosvg.svg2png(bytestring=svg.encode("utf-8"), scale=scale, background_color="#f5f5f5")
    except Exception:
        return None


if __name__ == "__main__":
    import json
    import sys
    if len(sys.argv) < 2:
        print("usage: cti_diagram_design.py <case.json> [out.svg]")
        sys.exit(2)
    with open(sys.argv[1], encoding="utf-8") as f:
        d = json.load(f)
    svg = build_entity_svg(d)
    if not svg:
        print("no subjects")
        sys.exit(1)
    out = sys.argv[2] if len(sys.argv) > 2 else "entity.svg"
    with open(out, "w", encoding="utf-8") as f:
        f.write(svg)
    print("wrote %s (%d bytes)" % (out, len(svg)))
