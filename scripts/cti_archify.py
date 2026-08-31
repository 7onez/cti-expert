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

Public API:
    build_architecture_ir(data: dict) -> dict | None
        Returns the IR, or None when there are no subjects to draw.

Usage (standalone):
    python3 cti_archify.py <case.json> <ir.out.json>

Author: CTI Expert
"""
import json
import math
import sys

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

MAX_COLS = 6            # cap grid width; wider tiers wrap to extra rows
SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


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
        t = _lc(s.get("type"))
        label = str(s.get("label") or s["id"])
        sub = TYPE_LABEL.get(t, (s.get("type") or "Entity"))
        conf = s.get("confidence")
        sublabel = ("%s · %d%%" % (sub, int(conf))) if isinstance(conf, (int, float)) else str(sub)
        longest = max(longest, len(label), len(sublabel))
    # ~8.4px per char at the renderer's node font, plus horizontal padding.
    return [int(_clamp(longest * 8.4 + 30, 140, 264)), 66]


def _components(subjects, sev_by_subject, node_size):
    """Build Archify components with automatic grid row/col placement.

    Returns (components, cols, id_map). CTI subject ids can be anything (raw
    values like `1.2.3.4` or `user@x.com`, digit-leading, unicode), but Archify
    ids must match ^[a-zA-Z][a-zA-Z0-9_-]*$. So every node gets a synthetic,
    collision-free slug (`n1`, `n2`, ...) and the original value is preserved as
    the label; `id_map[original_id] = slug` lets connections rewrite endpoints.
    """
    tiers = {}
    for s in subjects:
        tiers.setdefault(_tier_of(s.get("type")), []).append(s)

    widest = max((len(v) for v in tiers.values()), default=1)
    cols = _clamp(widest, 1, MAX_COLS)

    components = []
    id_map = {}
    row_cursor = 0
    for tier in sorted(tiers):
        members = tiers[tier]
        for i, s in enumerate(members):
            t = _lc(s.get("type"))
            slug = "n%d" % (len(id_map) + 1)
            id_map[s["id"]] = slug
            comp = {
                "id": slug,
                "type": ENTITY_TYPE_MAP.get(t, "external"),
                "label": str(s.get("label") or s["id"]),
                "row": row_cursor + (i // cols),
                "col": i % cols,
                "size": list(node_size),
            }
            sub = TYPE_LABEL.get(t, (s.get("type") or "Entity"))
            conf = s.get("confidence")
            comp["sublabel"] = "%s · %d%%" % (sub, int(conf)) if isinstance(conf, (int, float)) else str(sub)
            sev = sev_by_subject.get(s["id"])
            if sev in ("CRITICAL", "HIGH"):
                comp["tag"] = sev
            components.append(comp)
        row_cursor += math.ceil(len(members) / cols) if members else 0
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


def _cards(data, subjects, connections, sev_by_subject):
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
        fitems.insert(0, "%d finding(s) across %d subject(s)" % (total_findings, len(subjects)))
    if fitems:
        cards.append({"dot": "orange", "title": "Findings", "items": fitems[:6]})

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


def build_architecture_ir(data):
    """CTI report JSON -> Archify architecture IR dict (or None if no subjects)."""
    if not isinstance(data, dict):
        return None
    subjects = [s for s in (data.get("subjects") or []) if isinstance(s, dict) and s.get("id")]
    if not subjects:
        return None

    case = data.get("case", {}) or {}
    sev_by_subject = _top_severity_by_subject(data.get("findings"))
    node_size = _node_size(subjects)
    components, cols, id_map = _components(subjects, sev_by_subject, node_size)
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
        "cards": _cards(data, subjects, connections, sev_by_subject),
    }


def main(argv):
    if len(argv) < 2:
        print("usage: cti_archify.py <case.json> <ir.out.json>")
        return 2
    with open(argv[0], encoding="utf-8") as f:
        data = json.load(f)
    ir = build_architecture_ir(data)
    if ir is None:
        print("no subjects — nothing to render")
        return 1
    with open(argv[1], "w", encoding="utf-8", newline="\n") as f:
        json.dump(ir, f, ensure_ascii=False, indent=2)
    print("archify IR written: %s (%d components, %d connections)"
          % (argv[1], len(ir["components"]), len(ir["connections"])))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
