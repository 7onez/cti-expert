#!/usr/bin/env python3
# CTI Expert — recursive pivot orchestration engine.
# Adapted for the cti-expert skill by Hieu Ngo (chongluadao.vn).
"""
pivot_orchestrator.py — the "spider-map" state machine behind /case.

It turns /case from a one-pass collector into a recursive, self-expanding pivot
engine: every discovered identifier becomes a new seed, and the graph expands hop
by hop until the frontier is exhausted or a budget cap is hit. This script owns the
deterministic bookkeeping — identifier typing, dedup / cycle prevention (visited
set), per-node depth, the identifier-type → pivot-action edge matrix, confidence
gating, and per-depth checkpoints. The *agent* executes the actual technique
commands each hop and feeds results back via --ingest.

WHY A HELPER (vs. the agent tracking it by hand)
  A breadth-first pivot over dozens of nodes across many hops is exactly where an
  agent loses the thread: re-expanding a visited node, forgetting depth, or letting
  the frontier balloon past budget. This keeps the queue, the visited set, the depth
  map, and the gate rules in one auditable place so the recursion is reliable and the
  map is reproducible.

LOOP (BFS)
  1) --seed <value>            initialize state; print depth-0 pivot plan
  2) agent runs the plan's actions for the current frontier
  3) --ingest <discoveries>    add discovered identifiers as depth+1 nodes (deduped,
                               gated), record edges, build the next frontier
  4) --checkpoint              show the depth summary (new nodes/edges/next plan) →
                               approve (checkpoint-per-depth autonomy)
  5) --plan                    print the next frontier's gated actions → back to (2)
  Repeat until --plan is empty (frontier exhausted) or budget hit.

CONFIG (defaults chosen for this skill: Active-allowed · Exhaustive · Checkpoint-per-depth)
  --posture active|passive-first|passive     what the spider may touch
  --reach   exhaustive|balanced|focused      how far it expands
  --autonomy checkpoint|auto|checkpoint-weak how often it pauses

Gating reuses analysis/auto-branch-rules.md (Branch Priority Matrix + Suppression).
Passive by default for hostile infra even when posture=active. AUTHORIZED USE ONLY.
"""
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///

import sys
import os
import re
import json
import argparse

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass


# ----------------------------------------------------------------------------- identifier typing

_RX = {
    "email":     re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$"),
    "ipv4":      re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$"),
    "ipv6":      re.compile(r"^(?=.*:)[0-9A-Fa-f:]{3,}$"),
    "eth":       re.compile(r"^0x[a-fA-F0-9]{40}$"),
    "btc":       re.compile(r"^(bc1[a-z0-9]{20,}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$"),
    "asn":       re.compile(r"^AS\d{2,6}$", re.I),
    "cert_sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
    "favicon_mmh3": re.compile(r"^-?\d{6,12}$"),
    "ga_id":     re.compile(r"^(UA-\d{4,}-\d+|G-[A-Z0-9]{6,}|GTM-[A-Z0-9]{4,})$"),
    "adsense_id": re.compile(r"^(ca-)?pub-\d{10,}$"),
    "phone":     re.compile(r"^\+?\d[\d\s().\-]{7,16}\d$"),
    "url":       re.compile(r"^https?://", re.I),
    "domain":    re.compile(r"^(?=.{4,253}$)([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"),
    "social_handle": re.compile(r"^@[A-Za-z0-9._]{2,}$"),
}


def classify(value):
    v = value.strip()
    # order matters: most specific first. favicon_mmh3 (bare int) is intentionally
    # NOT auto-detected — it collides with phones/ids; callers pass its type explicitly.
    for t in ("email", "url", "ipv4", "ipv6", "eth", "btc", "asn", "ga_id",
              "adsense_id", "cert_sha256", "social_handle"):
        if _RX[t].match(v):
            return t
    if _RX["domain"].match(v):
        return "domain"
    if _RX["phone"].match(v):
        return "phone"
    if re.search(r"\s", v) and re.match(r"^[A-Za-z][A-Za-z.'\-]+(?:\s+[A-Za-z][A-Za-z.'\-]+)+$", v):
        return "person"
    if re.match(r"^[A-Za-z0-9._\-]{2,40}$", v):
        return "username"
    return "unknown"


def normalize(value, t):
    v = value.strip()
    if t in ("email", "domain", "url"):
        v = v.lower()  # GA/AdSense/GTM IDs are case-sensitive tokens — preserve case
    if t == "domain":
        v = re.sub(r"^www\.", "", v)
    if t == "phone":
        v = ("+" if v.strip().startswith("+") else "") + re.sub(r"\D", "", v)
    if t == "social_handle":
        v = v.lower()
    return v


def key_of(value, t):
    return f"{t}:{normalize(value, t)}"


# ----------------------------------------------------------------------------- edge matrix
# type -> list of pivot actions. Each: method, tool (actual skill command), yields
# (identifier types produced), rel (case-schema connection enum), confidence, active.

EDGE_MATRIX = {
    "email": [
        {"method": "reverse-whois", "tool": "whois_enrich.py <email> --reverse", "yields": ["domain"], "rel": "REGISTERED", "confidence": 88, "active": False},
        {"method": "breach", "tool": "/breach-deep <email>", "yields": ["email", "username", "phone", "password"], "rel": "REACHES", "confidence": 90, "active": False},
        {"method": "github-commit", "tool": "/github-osint <email>", "yields": ["username", "domain", "person"], "rel": "ALSO_KNOWN_AS", "confidence": 85, "active": False},
        {"method": "email-hygiene", "tool": "email_hygiene.py <email>", "yields": [], "rel": "OTHER", "confidence": 60, "active": False},
        {"method": "socials/gravatar+dork", "tool": "/dork-sweep <email>", "yields": ["username", "person", "social_handle"], "rel": "ALSO_KNOWN_AS", "confidence": 70, "active": False},
    ],
    "domain": [
        {"method": "webpivot-dom", "tool": "pivot_extract.py <domain> --leads", "yields": ["email", "phone", "btc", "eth", "ga_id", "adsense_id", "social_handle", "favicon_mmh3"], "rel": "CONTROLS", "confidence": 80, "active": True},
        {"method": "wayback-harvest", "tool": "wayback_harvest.py <domain> --indicators", "yields": ["email", "phone", "btc", "eth", "ga_id", "social_handle"], "rel": "CONTROLS", "confidence": 78, "active": False},
        {"method": "whois-current+history+reverse", "tool": "whois_enrich.py <domain>", "yields": ["email", "person", "domain"], "rel": "REGISTERED", "confidence": 85, "active": False},
        {"method": "subdomains", "tool": "/subdomain <domain>", "yields": ["domain"], "rel": "ENCOMPASSES", "confidence": 92, "active": False},
        {"method": "cert-pivot", "tool": "cert_pivot.py <domain>", "yields": ["domain", "ipv4", "cert_sha256"], "rel": "LINKED_TO", "confidence": 82, "active": True},
        {"method": "dns->ip+mx+txt", "tool": "/sweep <domain>", "yields": ["ipv4", "domain", "email"], "rel": "HOSTS", "confidence": 95, "active": True},
        {"method": "tracker-reuse", "tool": "wayback_ga.py <domain> --timeline", "yields": ["ga_id", "adsense_id"], "rel": "LINKED_TO", "confidence": 80, "active": False},
        {"method": "msft-tenant(if M365)", "tool": "/msftrecon <domain>", "yields": ["domain", "org"], "rel": "AUTHENTICATES", "confidence": 88, "active": True},
        {"method": "saas-identity", "tool": "/saas-map <domain>", "yields": ["domain", "org"], "rel": "AUTHENTICATES", "confidence": 75, "active": True},
    ],
    "url": [
        {"method": "webpivot-dom", "tool": "pivot_extract.py <url> --leads", "yields": ["domain", "email", "phone", "btc", "eth", "ga_id", "social_handle"], "rel": "CONTROLS", "confidence": 80, "active": True},
    ],
    "ipv4": [
        {"method": "reverse-dns", "tool": "/sweep <ip>", "yields": ["domain"], "rel": "HOSTS", "confidence": 85, "active": True},
        {"method": "passive-dns-cohosted", "tool": "/threat-check <ip>", "yields": ["domain"], "rel": "HOSTS", "confidence": 78, "active": False},
        {"method": "shodan-internetdb", "tool": "/appliance-scan <ip>", "yields": ["domain", "asn"], "rel": "HOSTS", "confidence": 82, "active": False},
        {"method": "asn->netblock", "tool": "asn.ps1 <ip>", "yields": ["asn", "ipv4"], "rel": "ENCOMPASSES", "confidence": 70, "active": False},
    ],
    "username": [
        {"method": "platform-enum", "tool": "/username <handle>", "yields": ["social_handle", "domain", "email", "person"], "rel": "ALSO_KNOWN_AS", "confidence": 88, "active": True},
        {"method": "variant-suggest", "tool": "pivot_suggest.py --usernames <handle>", "yields": ["username"], "rel": "ALSO_KNOWN_AS", "confidence": 75, "active": False},
        {"method": "github", "tool": "/github-osint <handle>", "yields": ["email", "domain", "person"], "rel": "ALSO_KNOWN_AS", "confidence": 82, "active": False},
    ],
    "person": [
        {"method": "username-guess+enum", "tool": "/username <name>", "yields": ["username", "social_handle"], "rel": "ALSO_KNOWN_AS", "confidence": 65, "active": True},
        {"method": "people-search+dork", "tool": "/dork-sweep <name>", "yields": ["email", "phone", "username", "org"], "rel": "REACHES", "confidence": 60, "active": False},
        {"method": "docleak-authorship", "tool": "/docleak <name>", "yields": ["email", "org", "domain"], "rel": "WORKS_AT", "confidence": 62, "active": False},
    ],
    "org": [
        {"method": "primary+brand-domains", "tool": "/sweep <org>", "yields": ["domain"], "rel": "CONTROLS", "confidence": 80, "active": False},
        {"method": "personnel", "tool": "/query <org>", "yields": ["person", "email"], "rel": "ENCOMPASSES", "confidence": 68, "active": False},
        {"method": "tenant", "tool": "/msftrecon <org>", "yields": ["domain"], "rel": "AUTHENTICATES", "confidence": 78, "active": True},
        {"method": "github-org", "tool": "/github-osint <org>", "yields": ["username", "domain", "email"], "rel": "CONTROLS", "confidence": 72, "active": False},
    ],
    "btc": [
        {"method": "onchain-flow", "tool": "crypto_balance.py <addr>", "yields": ["btc"], "rel": "COMMUNICATES", "confidence": 70, "active": False},
    ],
    "eth": [
        {"method": "onchain-flow", "tool": "crypto_balance.py <addr>", "yields": ["eth"], "rel": "COMMUNICATES", "confidence": 70, "active": False},
    ],
    "phone": [
        {"method": "reverse-phone+carrier", "tool": "/phone <number>", "yields": ["person", "social_handle"], "rel": "REACHES", "confidence": 72, "active": False},
    ],
    "ga_id": [
        {"method": "reverse-analytics", "tool": "PublicWWW/DNSlytics/urlscan \"<id>\"", "yields": ["domain"], "rel": "LINKED_TO", "confidence": 90, "active": False},
    ],
    "adsense_id": [
        {"method": "reverse-analytics", "tool": "PublicWWW/urlscan \"<id>\"", "yields": ["domain"], "rel": "LINKED_TO", "confidence": 90, "active": False},
    ],
    "cert_sha256": [
        {"method": "cert-fingerprint-pivot", "tool": "cert_pivot.py --hash <sha256>", "yields": ["domain", "ipv4"], "rel": "LINKED_TO", "confidence": 85, "active": False},
    ],
    "favicon_mmh3": [
        {"method": "favicon-reverse", "tool": "Shodan/FOFA http.favicon.hash:<mmh3>", "yields": ["domain", "ipv4"], "rel": "LINKED_TO", "confidence": 75, "active": False},
    ],
    "asn": [
        {"method": "asn-members", "tool": "asn.ps1 <asn>", "yields": ["ipv4", "domain"], "rel": "ENCOMPASSES", "confidence": 60, "active": False},
    ],
    "social_handle": [
        {"method": "profile->identity", "tool": "/username <handle>", "yields": ["person", "domain", "username"], "rel": "ALSO_KNOWN_AS", "confidence": 78, "active": True},
    ],
}


# ----------------------------------------------------------------------------- gating (auto-branch-rules)

def priority_of(conf):
    if conf >= 95:
        return "CRITICAL"
    if conf >= 78:
        return "HIGH"
    if conf >= 63:
        return "MEDIUM"
    return "LOW"


# Branch Priority Matrix §5 — max expansions per session, by priority.
PER_TYPE_CAP = {"CRITICAL": 10 ** 9, "HIGH": 5, "MEDIUM": 5, "LOW": 2}

REACH_DEPTH = {"focused": 2, "balanced": 3, "exhaustive": 6}      # exhaustive caps at budget
REACH_MIN_PRIORITY = {"focused": {"CRITICAL", "HIGH"},
                      "balanced": {"CRITICAL", "HIGH", "MEDIUM"},
                      "exhaustive": {"CRITICAL", "HIGH", "MEDIUM", "LOW"}}

PROTECTED_TYPES = {"person", "phone"}  # PII — needs confirmed authorization to auto-expand


def gate_node(node, state):
    """Return (status, reason): 'planned' | 'held' | 'suppressed'."""
    reach = state["config"]["reach"]
    max_depth = min(state["config"]["budget"]["max_depth"], REACH_DEPTH[reach])
    if node["depth"] > max_depth:
        return "suppressed", f"beyond depth cap ({max_depth}) for reach={reach}"
    prio = priority_of(node["confidence"])
    if prio not in REACH_MIN_PRIORITY[reach]:
        return "suppressed", f"{prio} below reach={reach} threshold"
    if prio == "LOW" and node.get("corroboration", 0) < 2:
        return "held", "LOW priority, <2 corroborating findings"
    # per-type expansion cap (CRITICAL is unbounded)
    expanded = sum(1 for n in state["nodes"].values()
                   if n["type"] == node["type"] and n["status"] == "expanded")
    if expanded >= PER_TYPE_CAP[prio]:
        return "held", f"{node['type']} expansion cap for {prio} reached"
    if node["type"] in PROTECTED_TYPES and state["config"].get("authorization") != "confirmed":
        return "held", "protected/PII target — authorization not confirmed"
    if len(state["nodes"]) >= state["config"]["budget"]["max_nodes"]:
        return "suppressed", "global node budget exhausted"
    return "planned", ""


def actions_for(node, state):
    """Gated pivot actions for a node, honoring posture (active/passive)."""
    posture = state["config"]["posture"]
    out = []
    for a in EDGE_MATRIX.get(node["type"], []):
        act = dict(a)
        if a["active"] and posture == "passive":
            act["status"] = "held-active"
            act["note"] = "requires active fetch; posture=passive"
        elif a["active"] and posture == "passive-first" and node.get("hostile"):
            act["status"] = "held-active"
            act["note"] = "hostile target; passive-first defers active fetch"
        else:
            act["status"] = "run"
        out.append(act)
    return out


# ----------------------------------------------------------------------------- state ops

def new_state(config):
    return {"config": config, "nodes": {}, "edges": [], "frontier": [],
            "current_depth": 0, "log": []}


def add_node(state, value, t=None, depth=0, parent_key=None, method=None,
             confidence=None, rel="LINKED_TO", hostile=False):
    t = t if (t and t != "auto") else classify(value)
    if t == "unknown":
        state["log"].append(f"skip unclassifiable: {value!r}")
        return None
    k = key_of(value, t)
    existing = state["nodes"].get(k)
    if existing is not None:
        # cycle/dedup: record the edge, bump corroboration, keep shallowest depth
        existing["corroboration"] = existing.get("corroboration", 1) + 1
        if parent_key and parent_key != k:
            _add_edge(state, parent_key, k, rel, confidence or existing["confidence"], method, depth)
        return None  # not re-queued
    node = {"value": normalize(value, t), "type": t, "depth": depth,
            "confidence": confidence if confidence is not None else 100 if depth == 0 else 70,
            "provenance": method or "seed", "parent": parent_key,
            "status": "seed" if depth == 0 else "new", "corroboration": 1,
            "hostile": hostile}
    state["nodes"][k] = node
    if parent_key:
        _add_edge(state, parent_key, k, rel, node["confidence"], method, depth)
    if depth == 0:
        node["status"] = "planned"
        state["frontier"].append(k)
    else:
        status, reason = gate_node(node, state)
        node["status"] = status
        node["gate_reason"] = reason
        if status == "planned":
            state["frontier"].append(k)
    return k


def _add_edge(state, frm, to, rel, confidence, method, depth):
    e = {"from": frm, "to": to, "rel": rel, "confidence": confidence,
         "method": method, "depth": depth}
    if e not in state["edges"]:
        state["edges"].append(e)


def ingest(state, discoveries):
    """discoveries: [{from, value, type?, method?, confidence?, rel?, hostile?}]."""
    added = 0
    for d in discoveries:
        parent_key = d.get("from")
        pnode = state["nodes"].get(parent_key) if parent_key else None
        depth = (pnode["depth"] + 1) if pnode else state["current_depth"] + 1
        k = add_node(state, d["value"], d.get("type", "auto"), depth, parent_key,
                     d.get("method"), d.get("confidence"), d.get("rel", "LINKED_TO"),
                     d.get("hostile", False))
        if k:
            added += 1
    # advance depth pointer to the shallowest frontier node
    if state["frontier"]:
        state["current_depth"] = min(state["nodes"][k]["depth"] for k in state["frontier"])
    return added


# ----------------------------------------------------------------------------- rendering

def render_plan(state):
    lines = [f"# Pivot plan — depth {state['current_depth']} "
             f"({len(state['frontier'])} node(s) queued)",
             f"posture={state['config']['posture']} · reach={state['config']['reach']} "
             f"· autonomy={state['config']['autonomy']}", ""]
    if not state["frontier"]:
        lines.append("_Frontier empty — spider exhausted at this budget. Ready to render the map + report._")
        return "\n".join(lines)
    for k in state["frontier"]:
        n = state["nodes"][k]
        lines.append(f"## {n['type']}: `{n['value']}`  (depth {n['depth']}, "
                     f"conf {n['confidence']}, {priority_of(n['confidence'])})")
        for a in actions_for(n, state):
            tag = "▶ run" if a["status"] == "run" else f"⏸ {a['status']}"
            tool = a["tool"].replace("<domain>", n["value"]).replace("<email>", n["value"]) \
                            .replace("<ip>", n["value"]).replace("<url>", n["value"]) \
                            .replace("<handle>", n["value"]).replace("<name>", n["value"]) \
                            .replace("<addr>", n["value"]).replace("<number>", n["value"]) \
                            .replace("<org>", n["value"]).replace("<id>", n["value"]) \
                            .replace("<sha256>", n["value"]).replace("<mmh3>", n["value"]) \
                            .replace("<asn>", n["value"])
            yld = ",".join(a["yields"]) or "—"
            lines.append(f"  - {tag} · `{tool}`  → yields: {yld}  (edge {a['rel']}, conf {a['confidence']})")
        lines.append("")
    return "\n".join(lines)


def render_checkpoint(state):
    depth = state["current_depth"]
    at_depth = [n for n in state["nodes"].values() if n["depth"] == depth]
    new = [n for n in at_depth if n["status"] == "planned"]
    held = [n for n in state["nodes"].values() if n["status"] == "held"]
    supp = [n for n in state["nodes"].values() if n["status"] == "suppressed"]
    by_type = {}
    for n in new:
        by_type.setdefault(n["type"], []).append(n["value"])
    lines = [f"# ⛓ Depth-{depth} checkpoint — {state['config']['autonomy']}",
             f"nodes total: {len(state['nodes'])} · edges: {len(state['edges'])} · "
             f"frontier: {len(state['frontier'])} · budget: "
             f"{len(state['nodes'])}/{state['config']['budget']['max_nodes']} nodes",
             ""]
    lines.append(f"## New at depth {depth} ({len(new)})")
    for t, vals in sorted(by_type.items()):
        lines.append(f"- **{t}** ({len(vals)}): " + ", ".join(f"`{v}`" for v in vals[:12])
                     + (" …" if len(vals) > 12 else ""))
    if held:
        lines.append(f"\n## ⏸ Held for approval ({len(held)})")
        for n in held[:15]:
            lines.append(f"- {n['type']} `{n['value']}` — {n.get('gate_reason','')}")
    if supp:
        lines.append(f"\n## ✕ Suppressed ({len(supp)}) — dedup/depth/threshold")
    lines.append(f"\n**Next:** approve to expand depth {depth+1} "
                 f"(`--plan` shows the {len(state['frontier'])} queued pivots), "
                 f"or stop and render the map.")
    return "\n".join(lines)


def _label(state, key):
    n = state["nodes"].get(key)
    return f"{n['type']}:{n['value']}" if n else key


def emit_edges(state):
    """Case-schema-flavored connection edges (workspace assigns UUIDs)."""
    return [{"from": _label(state, e["from"]), "to": _label(state, e["to"]),
             "type": e["rel"], "confidence": e["confidence"],
             "attributes": {"method": e["method"], "hop_depth": e["depth"]}}
            for e in state["edges"]]


# ----------------------------------------------------------------------------- cli

def load_state(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def save_state(state, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)


def main():
    ap = argparse.ArgumentParser(description="Recursive pivot orchestration engine (spider-map behind /case).")
    ap.add_argument("--state", required=True, help="state JSON file (created by --seed)")
    ap.add_argument("--seed", help="seed identifier to initialize the case")
    ap.add_argument("--type", default="auto", help="seed type (default: auto-classify)")
    ap.add_argument("--ingest", help="JSON file/'-' of discoveries to add: [{from,value,type?,method?,confidence?,rel?}]")
    ap.add_argument("--plan", action="store_true", help="print the current frontier's gated pivot actions")
    ap.add_argument("--checkpoint", action="store_true", help="print the per-depth checkpoint summary")
    ap.add_argument("--edges", action="store_true", help="emit connection edges (JSON)")
    ap.add_argument("--posture", default="active", choices=["active", "passive-first", "passive"])
    ap.add_argument("--reach", default="exhaustive", choices=["exhaustive", "balanced", "focused"])
    ap.add_argument("--autonomy", default="checkpoint", choices=["checkpoint", "auto", "checkpoint-weak"])
    ap.add_argument("--max-nodes", type=int, default=500)
    ap.add_argument("--max-depth", type=int, default=6)
    ap.add_argument("--authorization", default="unconfirmed", choices=["confirmed", "unconfirmed"])
    args = ap.parse_args()

    if args.seed:
        config = {"posture": args.posture, "reach": args.reach, "autonomy": args.autonomy,
                  "authorization": args.authorization,
                  "budget": {"max_nodes": args.max_nodes, "max_depth": args.max_depth}}
        state = new_state(config)
        add_node(state, args.seed, args.type, depth=0)
        save_state(state, args.state)
        print(render_plan(state))
        return

    state = load_state(args.state)

    if args.ingest:
        raw = sys.stdin.read() if args.ingest == "-" else open(args.ingest, encoding="utf-8").read()
        discoveries = json.loads(raw)
        # move just-expanded frontier nodes to 'expanded' before adding children
        for k in list(state["frontier"]):
            state["nodes"][k]["status"] = "expanded"
        state["frontier"] = []
        added = ingest(state, discoveries)
        save_state(state, args.state)
        print(render_checkpoint(state))
        print(f"\n[orchestrator] +{added} new nodes; frontier now {len(state['frontier'])}.", file=sys.stderr)
        return

    if args.checkpoint:
        print(render_checkpoint(state))
        return
    if args.edges:
        print(json.dumps(emit_edges(state), ensure_ascii=False, indent=2))
        return
    # default / --plan
    print(render_plan(state))


if __name__ == "__main__":
    main()
