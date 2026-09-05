#!/usr/bin/env python3
"""
cti_archify.py — Convert a CTI Expert case (report JSON) into an Archify
`architecture` diagram IR (https://github.com/tt-a1i/archify).

The CTI case is an entity-relationship graph: `subjects` are nodes, `connections`
are edges, `findings` attach risk to subjects. Archify's `architecture` type with
a deterministic grid layout is the closest structural fit, so we emit that.

Layout is fully automatic (Archify grid: per-node row/col + fixed cell math), so
no coordinate solver is needed. The IR is fed to `archify render architecture`,
whose output is embedded inline in the CTI HTML report's "Blueprint" view.

Archify's architecture type targets small, sparse maps (BLUEPRINT_LIMITS). A dense
CTI estate (one operator, a hundred hosts) is first folded to APEX level — every
host under its registrable domain — and the long tail of low-value apexes into one
"+N more apexes" node, so the Blueprint reads as the operator's estate map while the
report's Network Graph and Editorial views keep the full host list.

Public API:
    select_ir(data: dict, mode: "auto"|"force"|"full") -> (dict | None, note: str)
        The IR the HTML generator embeds for a CTI_ARCHIFY mode, or None + reason.
    build_architecture_ir(data: dict, collapse: dict | None = None) -> dict | None
        Returns the IR, or None when there are no subjects to draw. `collapse` is
        the stats dict from collapse_estate(); it only annotates the cards.
    collapse_estate(data: dict, max_nodes: int = ...) -> (dict, dict) | (None, None)
        Apex-level copy of the report JSON + stats, or (None, None) when the case
        has no domain subjects to fold.
    density(ir) -> (components, connections, max_degree)
    fits_blueprint(ir) -> bool

Usage (standalone):
    python3 cti_archify.py <case.json> <ir.out.json> [--mode auto|force|full]
    python3 cti_archify.py <case.json> --plan

Author: CTI Expert
"""
import json
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# CTI entity type -> Archify component type (drives node color/icon).
# Archify component types: frontend, backend, database, cloud, security,
# messagebus, external. The mapping is semantic-best-effort for OSINT entities.
ENTITY_TYPE_MAP = {
    "person": "external", "individual": "external",
    "organization": "external", "org": "external",
    "domain": "cloud", "url": "cloud",
    "email": "external", "username": "external", "handle": "external",
    "ip": "backend", "network_addr": "backend", "device": "backend", "asn": "backend",
    "phone": "external",
    "wallet": "messagebus", "crypto_address": "messagebus",
    "location": "external",
    "document": "database", "asset": "database", "image": "database",
    "event": "external",
}

# Human-readable sublabel per entity type.
TYPE_LABEL = {
    "person": "Person", "individual": "Person",
    "organization": "Organization", "org": "Organization",
    "domain": "Domain", "url": "URL",
    "email": "Email", "username": "Username", "handle": "Username",
    "ip": "IP address", "network_addr": "IP address", "device": "Device", "asn": "ASN",
    "phone": "Phone",
    "wallet": "Wallet", "crypto_address": "Crypto wallet",
    "location": "Location",
    "document": "Document", "asset": "Asset", "image": "Image",
    "event": "Event",
}

# Vertical tier (grid row band) per entity type: who -> online -> hosting -> misc.
TYPE_TIER = {
    "person": 0, "individual": 0, "organization": 0, "org": 0,
    "username": 0, "handle": 0, "email": 0,
    "domain": 1, "url": 1,
    "ip": 2, "network_addr": 2, "device": 2, "asn": 2,
}
MISC_TIER = 3

# Connection strength -> Archify relationship variant.
STRENGTH_VARIANT = {
    "confirmed": "emphasis",
    "probable": "default",
    "possible": "dashed",
    "unconfirmed": "dashed",
    "suspected": "dashed",
}
# Strongest first — merged edges keep the best-supported strength.
STRENGTH_RANK = {"confirmed": 0, "probable": 1, "possible": 2, "suspected": 3, "unconfirmed": 4}

MAX_COLS = 6            # cap grid width; wider tiers wrap to extra rows
ARCHIFY_MAX_COLS = 12   # Archify's schema ceiling for layout.cols
SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# Archify's architecture type draws small, single-flow maps. Its clean-flow gate is a hard
# invariant (no profile bypass): a route may not pass through an unrelated node, so a hub's
# spokes must sit in single rows above and below it (see _positions). These limits are the
# readable envelope measured on the vendored v2.16.0 renderer with that placement; the degree
# cap equals the node cap minus one because an operator hub linked to every other node on the
# map is the normal shape of an apex-level estate.
BLUEPRINT_LIMITS = {"components": 12, "connections": 18, "max_degree": 11}
# CTI_ARCHIFY=force: the widest map the grid can hold without a hub route crossing a spoke —
# one full row of spokes above the hub and one below (ARCHIFY_MAX_COLS each), plus the hub.
FORCE_MAX_NODES = 2 * ARCHIFY_MAX_COLS + 1

APEX_ID_PREFIX = "APEX-"
APEX_TAIL_ID = "APEX-TAIL"


def _registrable_fn():
    """The engine's PSL-backed eTLD+1 reducer when the vendored engine is beside
    scripts/ (or INTEL_HOME points at one); else a conservative fallback that
    keeps three labels for the common two-part ccTLD suffixes."""
    roots = [os.environ.get("INTEL_HOME"), os.path.join(HERE, "..", "intel_engine")]
    for root in roots:
        if not root:
            continue
        wp_tools = os.path.join(root, "WebPivot", "tools")
        if not os.path.isfile(os.path.join(wp_tools, "wp_common.py")):
            continue
        if wp_tools not in sys.path:
            sys.path.insert(0, wp_tools)
        try:
            from wp_common import _registrable  # noqa: E402
            return _registrable
        except Exception:
            continue

    def _fallback(host):
        parts = str(host or "").strip().lower().strip(".").split(".")
        if len(parts) >= 3 and parts[-2] in ("com", "co", "net", "org", "gov", "edu", "id", "io", "ac") and len(parts[-1]) == 2:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    return _fallback


def _clamp(n, lo, hi):
    return max(lo, min(hi, n))


def _lc(v):
    return str(v or "").strip().lower()


def _tier_of(t):
    return TYPE_TIER.get(_lc(t), MISC_TIER)


def _top_severity_by_subject(findings):
    """subject_id -> highest (most severe) finding weight present."""
    best = {}
    for f in findings or []:
        sid = f.get("subject_id")
        if not sid:
            continue
        w = str(f.get("weight") or "INFO").upper()
        rank = SEV_RANK.get(w, 4)
        if sid not in best or rank < best[sid][0]:
            best[sid] = (rank, w)
    return {sid: w for sid, (_, w) in best.items()}


def _node_size(subjects):
    """Uniform node [w, h] wide enough to fit the longest label/sublabel.

    Archify's architecture validator fails closed when a node label is wider
    than the node box, so size every node to the widest text in the set. A single
    width also lets the grid cell width match, guaranteeing no horizontal overlap.
    """
    longest = 1
    for s in subjects:
        label = str(s.get("label") or s["id"])
        longest = max(longest, len(label), len(_sublabel(s)))
    # ~8.4px per char at the renderer's node font, plus horizontal padding.
    return [int(_clamp(longest * 8.4 + 30, 140, 264)), 66]


def _sublabel(s):
    """Explicit `sublabel` (set by collapse_estate) wins; else `<Type> · <conf>%`."""
    if s.get("sublabel"):
        return str(s["sublabel"])
    t = _lc(s.get("type"))
    sub = TYPE_LABEL.get(t, (s.get("type") or "Entity"))
    conf = s.get("confidence")
    return ("%s · %d%%" % (sub, int(conf))) if isinstance(conf, (int, float)) else str(sub)


def _hub(subjects, connections):
    """The subject id of a dominant hub, or None.

    A hub is a node linked to at least half of the other nodes (and to at least
    three). Placing it mid-row with its spokes split above and below is the only
    grid shape whose straight/dogleg routes never cross an unrelated node —
    stacked tiers put spokes beneath each other and the hub's vertical run
    through the first row fails Archify's clean-flow gate.
    """
    if len(subjects) < 4:
        return None
    ids = {s["id"] for s in subjects}
    deg = {}
    seen = set()
    for c in connections or []:
        a, b = c.get("from_id"), c.get("to_id")
        if a not in ids or b not in ids or a == b:
            continue
        key = frozenset((a, b))
        if key in seen:
            continue
        seen.add(key)
        deg[a] = deg.get(a, 0) + 1
        deg[b] = deg.get(b, 0) + 1
    if not deg:
        return None
    hub, d = max(deg.items(), key=lambda kv: kv[1])
    return hub if d >= max(3, math.ceil((len(subjects) - 1) / 2)) else None


def _positions(subjects, connections):
    """subject id -> (row, col), plus the grid column count.

    Hub-and-spoke: hub alone in its own row, spokes (tier order) split half above
    and half below. Within BLUEPRINT_LIMITS each half is one row, so no route
    crosses a node; past the limits (CTI_ARCHIFY=force) the halves wrap at
    Archify's schema cap of ARCHIFY_MAX_COLS and the validator reports the first
    crossing. Otherwise: one row band per tier (who -> online -> hosting -> misc),
    wrapping at MAX_COLS.
    """
    hub = _hub(subjects, connections)
    if hub:
        spokes = sorted((s for s in subjects if s["id"] != hub),
                        key=lambda s: _tier_of(s.get("type")))
        half = math.ceil(len(spokes) / 2)
        up, down = spokes[:half], spokes[half:]
        cols = _clamp(half, 1, ARCHIFY_MAX_COLS)
        up_rows = math.ceil(len(up) / cols)
        pos = {s["id"]: (i // cols, i % cols) for i, s in enumerate(up)}
        pos[hub] = (up_rows, min(len(up), cols) // 2)
        pos.update({s["id"]: (up_rows + 1 + i // cols, i % cols) for i, s in enumerate(down)})
        return pos, cols

    tiers = {}
    for s in subjects:
        tiers.setdefault(_tier_of(s.get("type")), []).append(s)
    cols = _clamp(max((len(v) for v in tiers.values()), default=1), 1, MAX_COLS)
    pos = {}
    row_cursor = 0
    for tier in sorted(tiers):
        members = tiers[tier]
        for i, s in enumerate(members):
            pos[s["id"]] = (row_cursor + i // cols, i % cols)
        row_cursor += math.ceil(len(members) / cols) if members else 0
    return pos, cols


def _components(subjects, connections, sev_by_subject, node_size):
    """Build Archify components with automatic grid placement (see _positions).

    Returns (components, cols, id_map). CTI subject ids can be anything (raw
    values like `1.2.3.4` or `user@x.com`, digit-leading, unicode), but Archify
    ids must match ^[a-zA-Z][a-zA-Z0-9_-]*$. So every node gets a synthetic,
    collision-free slug (`n1`, `n2`, ...) and the original value is preserved as
    the label; `id_map[original_id] = slug` lets connections rewrite endpoints.
    """
    pos, cols = _positions(subjects, connections)
    components = []
    id_map = {}
    for s in subjects:
        t = _lc(s.get("type"))
        slug = "n%d" % (len(id_map) + 1)
        id_map[s["id"]] = slug
        row, col = pos[s["id"]]
        comp = {
            "id": slug,
            "type": ENTITY_TYPE_MAP.get(t, "external"),
            "label": str(s.get("label") or s["id"]),
            "row": row,
            "col": col,
            "size": list(node_size),
            "sublabel": _sublabel(s),
        }
        sev = sev_by_subject.get(s["id"])
        if sev in ("CRITICAL", "HIGH"):
            comp["tag"] = sev
        components.append(comp)
    return components, cols, id_map


def _connections(connections, id_map):
    """Rewrite CTI connections onto slugged node ids (skip dangling/self edges).

    Edge labels are intentionally omitted: Archify's architecture validator fails
    closed on auto-placed labels that overlap nodes, which is common for
    programmatically generated grids. Direction (arrow) + strength (variant) carry
    the structure; full relationship wording stays in the report's Attribution
    list and subject drawer. The connection's own id is dropped (optional, and CTI
    ids need not match Archify's id pattern).
    """
    out = []
    seen = set()
    for c in connections or []:
        a = id_map.get(c.get("from_id"))
        b = id_map.get(c.get("to_id"))
        if not a or not b or a == b:
            continue
        # Collapse parallel/bidirectional edges to one — a CTI graph often has many
        # relations between the same pair, which would clutter the map and defeat
        # Archify's clean-flow routing.
        key = frozenset((a, b))
        if key in seen:
            continue
        seen.add(key)
        out.append({"from": a, "to": b,
                    "variant": STRENGTH_VARIANT.get(_lc(c.get("strength")), "default")})
    return out


def _cards(data, subjects, connections, sev_by_subject, collapse=None):
    case = data.get("case", {}) if isinstance(data, dict) else {}
    cards = []

    exposure = []
    if case.get("status"):
        exposure.append("Status: %s" % case["status"])
    if case.get("classification"):
        exposure.append("Classification: %s" % case["classification"])
    if exposure:
        cards.append({"dot": "rose", "title": "Case Posture", "items": exposure})

    counts = {}
    for w in sev_by_subject.values():
        counts[w] = counts.get(w, 0) + 1
    total_findings = len(data.get("findings", []) or [])
    fitems = []
    for w in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if counts.get(w):
            fitems.append("%d subject(s) with a %s finding" % (counts[w], w))
    if total_findings:
        fitems.insert(0, "%d finding(s) across %d subject(s)" % (
            total_findings, collapse["subjects"] if collapse else len(subjects)))
    if fitems:
        cards.append({"dot": "orange", "title": "Findings", "items": fitems[:6]})

    if collapse:
        graph = ["%d hosts across %d apexes, shown at apex level" % (collapse["hosts"], collapse["apexes"])]
        if collapse["folded_apexes"]:
            graph.append("%d apexes · %d hosts folded into one node" % (collapse["folded_apexes"], collapse["folded_hosts"]))
        graph.append("%d relationships" % len(connections))
    else:
        graph = ["%d entities · %d relationships" % (len(subjects), len(connections))]
    primary = case.get("subject")
    if primary:
        graph.append("Primary subject: %s" % primary)
    tcount = {}
    for s in subjects:
        lbl = TYPE_LABEL.get(_lc(s.get("type")), s.get("type") or "Entity")
        tcount[lbl] = tcount.get(lbl, 0) + 1
    for lbl, n in sorted(tcount.items(), key=lambda kv: -kv[1])[:4]:
        graph.append("%d × %s" % (n, lbl))
    cards.append({"dot": "cyan", "title": "Entity Graph", "items": graph[:6]})

    return cards


def density(ir):
    """(components, connections, max node degree) of an architecture IR."""
    deg = {}
    for c in ir["connections"]:
        deg[c["from"]] = deg.get(c["from"], 0) + 1
        deg[c["to"]] = deg.get(c["to"], 0) + 1
    return len(ir["components"]), len(ir["connections"]), (max(deg.values()) if deg else 0)


def fits_blueprint(ir):
    comps, rels, deg = density(ir)
    return (comps <= BLUEPRINT_LIMITS["components"] and rels <= BLUEPRINT_LIMITS["connections"]
            and deg <= BLUEPRINT_LIMITS["max_degree"])


def _merge_connections(connections, id_of):
    """Rewrite endpoints through `id_of`, drop self/dangling edges, and keep ONE edge per
    unordered pair carrying the strongest strength seen across the merged originals."""
    best = {}
    order = []
    for c in connections or []:
        a = id_of.get(c.get("from_id"))
        b = id_of.get(c.get("to_id"))
        if not a or not b or a == b:
            continue
        key = frozenset((a, b))
        rank = STRENGTH_RANK.get(_lc(c.get("strength")), 9)
        cur = best.get(key)
        if cur is None:
            order.append(key)
            best[key] = (rank, {"id": "%s__%s" % (a, b), "from_id": a, "to_id": b,
                               "relationship": c.get("relationship") or "related_to",
                               "strength": c.get("strength") or "possible"})
        elif rank < cur[0]:
            cur[1]["strength"] = c.get("strength")
            cur[1]["relationship"] = c.get("relationship") or cur[1]["relationship"]
            best[key] = (rank, cur[1])
    return [best[k][1] for k in order]


def collapse_estate(data, max_nodes=None):
    """Apex-level copy of the report JSON for a dense estate.

    Every `domain` subject is folded into a node for its registrable apex (label =
    apex, sublabel = `Estate · N hosts`, confidence = best member, severity tag =
    worst member). If the apexes still exceed the node budget left after the
    non-domain subjects, the lowest-ranked apexes (rank: worst finding, host count,
    confidence) are folded into a single `+N more apexes` node. Findings and
    connections are rewritten onto the new ids; parallel edges merge to the
    strongest. Returns (data_copy, stats) or (None, None) when there is nothing to
    fold (no domain subjects).
    """
    if not isinstance(data, dict):
        return None, None
    max_nodes = max_nodes or BLUEPRINT_LIMITS["components"]
    subjects = [s for s in (data.get("subjects") or []) if isinstance(s, dict) and s.get("id")]
    domains = [s for s in subjects if _lc(s.get("type")) == "domain"]
    if not domains:
        return None, None
    others = [s for s in subjects if _lc(s.get("type")) != "domain"]

    registrable = _registrable_fn()
    groups = {}
    for s in domains:
        host = str(s.get("label") or s["id"]).strip().lower()
        groups.setdefault(registrable(host) or host, []).append(s)

    sev = _top_severity_by_subject(data.get("findings"))

    def _conf(s):
        c = s.get("confidence")
        return c if isinstance(c, (int, float)) else -1

    def _rank(item):
        apex, members = item
        worst = min((SEV_RANK.get(sev.get(m["id"]), 5) for m in members), default=5)
        return (worst, -len(members), -max(_conf(m) for m in members), apex)

    ranked = sorted(groups.items(), key=_rank)
    budget = max_nodes - len(others)
    if len(ranked) > budget:
        keep, tail = ranked[:max(1, budget - 1)], ranked[max(1, budget - 1):]
    else:
        keep, tail = ranked, []

    id_of = {s["id"]: s["id"] for s in others}
    new_subjects = list(others)
    for n, (apex, members) in enumerate(keep, 1):
        sid = "%s%d" % (APEX_ID_PREFIX, n)
        for m in members:
            id_of[m["id"]] = sid
        hosts = sorted(str(m.get("label") or m["id"]) for m in members)
        best = max(_conf(m) for m in members)
        new_subjects.append({
            "id": sid, "type": "domain", "label": apex,
            "sublabel": ("Estate · %d hosts" % len(members)) if len(members) > 1 else "Domain",
            "confidence": best if best >= 0 else None,
            "notes": "Hosts: " + ", ".join(hosts),
        })
    folded_hosts = sum(len(m) for _, m in tail)
    if tail:
        for _, members in tail:
            for m in members:
                id_of[m["id"]] = APEX_TAIL_ID
        new_subjects.append({
            "id": APEX_TAIL_ID, "type": "domain",
            "label": "+%d more apexes" % len(tail),
            "sublabel": "%d hosts" % folded_hosts,
            "notes": "Apexes: " + ", ".join(a for a, _ in tail),
        })

    findings = []
    for f in data.get("findings") or []:
        if not isinstance(f, dict):
            continue
        g = dict(f)
        if g.get("subject_id") in id_of:
            g["subject_id"] = id_of[g["subject_id"]]
        findings.append(g)

    out = dict(data)
    out["subjects"] = new_subjects
    out["findings"] = findings
    out["connections"] = _merge_connections(data.get("connections"), id_of)
    stats = {"subjects": len(subjects), "hosts": len(domains), "apexes": len(groups),
             "shown_apexes": len(keep), "folded_apexes": len(tail), "folded_hosts": folded_hosts}
    return out, stats


def build_architecture_ir(data, collapse=None):
    """CTI report JSON -> Archify architecture IR dict (or None if no subjects)."""
    if not isinstance(data, dict):
        return None
    subjects = [s for s in (data.get("subjects") or []) if isinstance(s, dict) and s.get("id")]
    if not subjects:
        return None

    case = data.get("case", {}) or {}
    sev_by_subject = _top_severity_by_subject(data.get("findings"))
    node_size = _node_size(subjects)
    components, cols, id_map = _components(subjects, data.get("connections"), sev_by_subject, node_size)
    connections = _connections(data.get("connections"), id_map)

    return {
        "schema_version": 1,
        "diagram_type": "architecture",
        "meta": {
            "title": str(case.get("label") or case.get("subject") or "CTI Entity Relationship Map"),
        },
        "layout": {
            "mode": "grid",
            "cols": cols,
            "cellW": node_size[0],
            "cellH": node_size[1],
            "gapX": 40,
            "gapY": 78,
        },
        "components": components,
        "connections": connections,
        "cards": _cards(data, subjects, connections, sev_by_subject, collapse),
    }


def _apex_note(stats, rels):
    return "%d of %d apexes shown for %d hosts (%d apexes · %d hosts folded) · %d relationships" % (
        stats["shown_apexes"], stats["apexes"], stats["hosts"],
        stats["folded_apexes"], stats["folded_hosts"], rels)


def select_ir(data, mode="auto"):
    """(ir, note) for a CTI_ARCHIFY mode; ir is None when the Blueprint should be skipped
    and `note` then carries the reason.

    auto   full graph when it fits BLUEPRINT_LIMITS; else the apex-level fold when that
           fits; else skipped.
    force  bypass BLUEPRINT_LIMITS: the full graph up to FORCE_MAX_NODES, else the apex
           fold at that widest budget. Archify's own validator still has the last word.
    full   the raw graph, no gate (standalone experiments).
    """
    ir = build_architecture_ir(data)
    if ir is None:
        return None, "no subjects to map"
    comps, rels, _ = density(ir)
    full = "%d entities · %d relationships" % (comps, rels)
    if mode == "full":
        return ir, full
    if mode == "force":
        if comps <= FORCE_MAX_NODES:
            return ir, "forced past BLUEPRINT_LIMITS: full graph, %s" % full
        folded, stats = collapse_estate(data, max_nodes=FORCE_MAX_NODES)
        if folded is None:
            return None, "forced: %s exceeds the %d-node grid and there is no domain estate to fold" % (full, FORCE_MAX_NODES)
        fir = build_architecture_ir(folded, collapse=stats)
        return fir, "forced past BLUEPRINT_LIMITS, apex level at the widest grid: " + _apex_note(stats, density(fir)[1])
    if fits_blueprint(ir):
        return ir, full
    # Archify targets small, sparse maps. Fold the estate to apex level and let the report's
    # Editorial figure + Network Graph carry the full host list.
    folded, stats = collapse_estate(data)
    fir = build_architecture_ir(folded, collapse=stats) if folded else None
    if fir is None or not fits_blueprint(fir):
        return None, ("graph too dense for Blueprint even at apex level (%s) — see Editorial & Network "
                      "Graph, or CTI_ARCHIFY=force for the widest apex-level map" % full)
    return fir, "apex level: " + _apex_note(stats, density(fir)[1])


def main(argv):
    mode = "auto"
    plan = "--plan" in argv
    if "--mode" in argv:
        i = argv.index("--mode")
        mode = argv[i + 1] if i + 1 < len(argv) else ""
        del argv[i:i + 2]
    argv = [a for a in argv if a != "--plan"]
    if mode not in ("auto", "force", "full") or len(argv) < (1 if plan else 2):
        print("usage: cti_archify.py <case.json> <ir.out.json> [--mode auto|force|full]\n"
              "       cti_archify.py <case.json> --plan      # what each mode would embed, no render")
        return 2
    with open(argv[0], encoding="utf-8") as f:
        data = json.load(f)
    if plan:
        for m in ("auto", "force"):
            ir, note = select_ir(data, m)
            print("%-5s %s — %s" % (m, "embed" if ir else "skip ", note))
        return 0
    ir, note = select_ir(data, mode)
    if ir is None:
        print("nothing to render — %s" % note)
        return 1
    with open(argv[1], "w", encoding="utf-8", newline="\n") as f:
        json.dump(ir, f, ensure_ascii=False, indent=2)
    print("archify IR written: %s — %s" % (argv[1], note))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
