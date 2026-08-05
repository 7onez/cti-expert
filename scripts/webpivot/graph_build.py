#!/usr/bin/env python3
# Part of the WebPivot toolkit by Zeroska — https://github.com/Zeroska
# Adapted for the cti-expert skill by Hieu Ngo (chongluadao.vn).
"""
graph_build.py — turn WebPivot pivot_extract JSON outputs into ONE normalized,
clustered case graph ready for interactive visualization.

Models shared artifacts (favicon, tracker, wallet, email, verification token) as
their own hub nodes, so two domains that share an artifact both connect to it —
that convergence is what reveals "same operator / same kit" at a glance.

Computes, zero-dependency:
  * connected components  (independent cases)
  * Louvain communities   (sub-network clustering → node color)
  * degree + betweenness centrality (→ node size; betweenness = broker/pivot)

Edges are typed and evidence-graded per investigative convention:
  link_class: operator | kit | infra | link
  confidence: confirmed (solid) | inferred (dashed)

Usage:
  graph_build.py out/*.json -o graph.json
  graph_build.py a.json b.json --operator "operator-a" --operator-links site-a.example,site-b.example -o graph.json

Feed graph.json to cti-expert's network renderer (the interactive HTML report;
see output/visuals/render-engine.md) or any force-directed graph viewer.
"""
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
import sys
import os
import json
import argparse
import math
from collections import defaultdict, deque

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

# Optional CDN/cloud classifier — separates shared edge IPs (noise) from candidate
# origin IPs (attribution-grade). Falls back cleanly if the range cache is missing.
try:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import cdn_ranges as _cdn
    _CDN_IDX = _cdn.load_ranges()
except Exception:
    _cdn, _CDN_IDX = None, None

# Optional relation-strength ranker — same-operator scoring + noise denylist. When present
# (default), the graph carries ranked `relations` + `clusters` and explicit `sibling` edges.
try:
    import rank_relations as _rank
except Exception:
    _rank = None

# ---- node type styling hints (shape/icon carried to the renderer) ----
TYPE_META = {
    "domain":       {"shape": "round-rectangle", "icon": "🌐"},
    "operator":     {"shape": "star",            "icon": "👤"},
    "person":       {"shape": "round-rectangle", "icon": "🕵️"},
    "email":        {"shape": "diamond",         "icon": "📧"},
    "wallet":       {"shape": "barrel",          "icon": "₿"},
    "tracker":      {"shape": "hexagon",         "icon": "📊"},
    "favicon":      {"shape": "pentagon",        "icon": "🖼️"},
    "verification": {"shape": "diamond",         "icon": "🔑"},
    "social":       {"shape": "tag",             "icon": "💬"},
    "ip":           {"shape": "hexagon",         "icon": "📍"},
    "host":         {"shape": "ellipse",         "icon": "🔗"},
    "registrant":   {"shape": "round-rectangle", "icon": "🧑"},
    "registrar":    {"shape": "rhomboid",        "icon": "🏛️"},
    "nameserver":   {"shape": "octagon",         "icon": "📡"},
    "theme":        {"shape": "vee",             "icon": "🎨"},
    "template":     {"shape": "concave-hexagon", "icon": "🧩"},
    "regdate":      {"shape": "diamond",         "icon": "📆"},
}
# how each artifact relationship is classified for evidence styling
LINK_CLASS = {
    "email": "operator", "wallet": "operator", "verification": "operator",
    "social": "operator", "favicon": "kit", "tracker": "kit",
    "ip": "infra", "host": "infra", "link": "link",
    "registrant": "operator", "registrar": "infra", "nameserver": "infra",
    "theme": "kit", "template": "kit", "reg_batch": "operator",
    "sibling": "operator",
}


def load_pivots(paths):
    out = []
    for p in paths:
        try:
            d = json.load(open(p, encoding="utf-8"))
        except Exception as e:
            print(f"  skip {p}: {e}", file=sys.stderr)
            continue
        if isinstance(d, list):
            out.extend(d)
        else:
            out.append(d)
    return out


def load_history(path):
    """wayback_ga.py output -> {domain: {'first':'YYYYMMDD','last':...}} for the timeline."""
    if not path:
        return {}
    try:
        data = json.load(open(path, encoding="utf-8"))
    except Exception as e:
        print(f"  history skipped: {e}", file=sys.stderr)
        return {}
    if isinstance(data, dict):
        data = [data]
    hist = {}
    for r in data:
        dom, span = r.get("domain"), r.get("span")
        if dom and span:
            hist[dom] = {"first": span[0][:8], "last": span[1][:8]}
    return hist


def _fmt_date(ts8):
    return f"{ts8[:4]}-{ts8[4:6]}-{ts8[6:8]}" if ts8 and len(ts8) >= 8 else None


class Graph:
    def __init__(self):
        self.nodes = {}   # id -> {id,label,type,...}
        self.edges = {}   # (a,b,rel) -> {source,target,rel,link_class,confidence,evidence}

    def node(self, nid, ntype, label=None, **kw):
        if nid not in self.nodes:
            self.nodes[nid] = {"id": nid, "type": ntype, "label": label or nid,
                               "shape": TYPE_META.get(ntype, {}).get("shape", "ellipse"),
                               "icon": TYPE_META.get(ntype, {}).get("icon", "•"), **kw}
        else:
            # node may have been pre-created as a link target — merge in richer info
            nd = self.nodes[nid]
            if label and nd.get("label") == nid:
                nd["label"] = label
            for k, v in kw.items():
                if v is not None and nd.get(k) in (None, "", False):
                    nd[k] = v
        return nid

    def edge(self, a, b, rel, confidence="confirmed", evidence="", **extra):
        key = (a, b, rel)
        if key not in self.edges:
            d = {"source": a, "target": b, "rel": rel,
                 "link_class": LINK_CLASS.get(rel, "link"),
                 "confidence": confidence, "evidence": evidence}
            d.update(extra)   # ranked sibling edges carry relation_strength/signals/assessment
            self.edges[key] = d
        return key


def build(analyses, operator=None, operator_links=None, history=None):
    g = Graph()
    history = history or {}
    domain_set = set()
    for a in analyses:
        host = (a.get("meta") or {}).get("host")
        if host:
            domain_set.add(host)

    for a in analyses:
        meta = a.get("meta") or {}
        art = a.get("artifacts") or {}
        host = meta.get("host")
        if not host:
            continue
        h = history.get(host, {})
        g.node(host, "domain", title=art.get("title") or host,
               archived=meta.get("archived_via_wayback", False),
               first_seen=_fmt_date(h.get("first")), last_seen=_fmt_date(h.get("last")))

        for label, vals in (art.get("trackers") or {}).items():
            for v in vals:
                tid = f"tracker:{v}"
                g.node(tid, "tracker", label=v, subtype=label)
                g.edge(host, tid, "tracker", evidence=label)
        # CSS / template same-kit indicators
        for th in art.get("wp_themes") or []:
            tid = f"theme:{th}"
            g.node(tid, "theme", label=th)
            g.edge(host, tid, "theme", confidence="inferred", evidence="wp theme")
        if art.get("dom_skeleton_sha1"):
            sk = art["dom_skeleton_sha1"][:12]
            g.node(f"dom:{sk}", "template", label="dom " + sk[:8])
            g.edge(host, f"dom:{sk}", "template", confidence="inferred", evidence="dom skeleton")
        fav = art.get("favicon")
        if fav and fav.get("shodan_mmh3") is not None:
            fid = f"favicon:{fav['shodan_mmh3']}"
            g.node(fid, "favicon", label=str(fav["shodan_mmh3"]), md5=fav.get("md5"))
            g.edge(host, fid, "favicon", evidence="favicon mmh3")
        for e in (art.get("emails") or []):
            eid = f"email:{e.lower()}"
            g.node(eid, "email", label=e)
            g.edge(host, eid, "email", evidence="on-page email")
        for coin, vals in (art.get("crypto") or {}).items():
            for v in vals:
                wid = f"wallet:{v}"
                g.node(wid, "wallet", label=v, coin=coin)
                g.edge(host, wid, "wallet", confidence="inferred", evidence=f"{coin} on page")
        for label, tok in (art.get("verifications") or {}).items():
            vid = f"verify:{tok}"
            g.node(vid, "verification", label=tok[:16] + "…", subtype=label)
            g.edge(host, vid, "verification", evidence=label)
        for net, handles in (art.get("socials") or {}).items():
            for h in handles:
                sid = f"social:{h}"
                g.node(sid, "social", label=h.split('/')[-1] or h, network=net)
                g.edge(host, sid, "social", evidence=net)
        # domain -> domain page links (only within the case set)
        for th in (art.get("third_party_hosts") or []):
            if th in domain_set and th != host:
                g.node(th, "domain")
                g.edge(host, th, "link", evidence="page link")
        # urlscan fallback related infra
        us = a.get("related_urlscan") or {}
        for ip in (us.get("ips") or [])[:8]:
            cls = _cdn.classify(ip, _CDN_IDX) if _CDN_IDX else None
            if cls and cls["cdn"]:
                continue  # shared CDN/cloud edge IP — noise, never a same-operator hub (§1)
            origin = bool(cls and cls["cdn"] is False)
            g.node(f"ip:{ip}", "ip", label=ip, origin_candidate=origin,
                   ip_provider=(cls or {}).get("provider"))
            g.edge(host, f"ip:{ip}", "ip",
                   confidence="inferred",
                   evidence="shared origin IP (candidate)" if origin else "urlscan IP")
        # WhoisXML registration data (registrant = operator-grade glue)
        wh = art.get("whois") or {}
        _PRIV_MARK = ("privacy", "redacted", "whoisguard", "data protected", "withheld",
                      "not disclosed", "domains by proxy", "domainsbyproxy",
                      "registration private", "private by design", "identity protect",
                      "contact privacy", "perfect privacy",
                      # WHOIS status/placeholder registrants — never a real identity, so
                      # they must not become false hubs linking unrelated domains.
                      "reactivation", "redemption", "pending delete", "statutory masking",
                      "masking enabled", "registry registrant id", "not available from registry",
                      "registrant country", "registrant state", "registrant city",
                      "whois agent", "see notes", "see the notes", "on how to view",
                      # registrar orgs / expired-domain placeholders (not the owner)
                      "domain expired", "runsystem", "gmo-z.com", "gmo internet",
                      "domain admin", "c/o id#", "domainadmin")
        _PROXY_DOM = ("porkbun.com", "godaddy.com", "namecheap.com", "domainsbyproxy.com",
                      "withheldforprivacy.com", "privacyprotect.org", "contactprivacy.com",
                      # registrars/resellers whose role mailbox is not the operator
                      "onamae.com", "tenten.vn", "inet.vn", "gname.com", "sav.com",
                      "enom.com", "gmo.jp", "matbao.com", "pavietnam.vn", "raothue.com")
        # role mailboxes: registrar/abuse/reseller inboxes, never the registrant
        _ROLE_LOCAL = ("abuse@", "abuse-contact@", "hostmaster@", "noc@", "postmaster@",
                       "registrar@", "admin@onamae", "complaint@", "reg_", "reactivation",
                       "proxy@", "protected@", "dataprotected@", "info@", "sales@",
                       "support@", "contact@", "noreply@", "no-reply@")

        def _priv(s):
            s = (s or "").strip().lower()
            if not s or s.startswith("http"):
                return True
            if any(m in s for m in _PRIV_MARK):
                return True
            if s.startswith(_ROLE_LOCAL):
                return True
            if "@" in s and s.split("@", 1)[1] in _PROXY_DOM:
                return True
            return False
        cur_email = wh.get("registrant_email")
        hist = wh.get("history") or {}
        seen_emails = set()
        for em in ([cur_email] if cur_email else []) + (hist.get("registrant_emails") or []):
            em = (em or "").lower().strip()
            if not em or _priv(em) or em in seen_emails:
                continue
            seen_emails.add(em)
            rid = f"registrant_email:{em}"
            g.node(rid, "email", label=em, subtype="registrant")
            g.edge(host, rid, "registrant",
                   confidence="confirmed" if em == cur_email else "inferred",
                   evidence="whois registrant email" if em == cur_email else "historical whois email")
        _corrupt = lambda s: any(0x80 <= ord(c) <= 0x9f for c in s)  # C1 mojibake bytes
        for nm in ([wh.get("registrant_name") or wh.get("registrant_org")]
                   + (hist.get("registrant_names") or [])):
            nm = (nm or "").strip()
            if not nm or _priv(nm) or _corrupt(nm):
                continue
            nid = f"registrant:{nm.lower()}"
            g.node(nid, "registrant", label=nm)
            g.edge(host, nid, "registrant", confidence="inferred", evidence="whois registrant name")
        if wh.get("registrar") and not _priv(wh["registrar"]):
            gid = f"registrar:{wh['registrar'].lower()}"
            g.node(gid, "registrar", label=wh["registrar"])
            g.edge(host, gid, "registrar", confidence="inferred", evidence="registrar")
        for ns in (wh.get("name_servers") or []):
            ns = (ns or "").lower().strip()
            if not ns:
                continue
            nsid = f"ns:{ns}"
            g.node(nsid, "nameserver", label=ns)
            g.edge(host, nsid, "nameserver", confidence="inferred", evidence="name server")
        # shared WHOIS creation date = domains batch-registered in one sitting (same actor).
        # Same class as sequential GA/UA numbers — corroborating same-operator. Day precision.
        created = wh.get("created")
        if isinstance(created, str) and len(created) >= 10:
            day = created[:10]
            did = f"regdate:{day}"
            g.node(did, "regdate", label=day)
            g.edge(host, did, "reg_batch", confidence="inferred",
                   evidence=f"registered {day}")

    # explicit operator persona overlay
    if operator:
        oid = f"operator:{operator}"
        g.node(oid, "operator", label=operator)
        for d in (operator_links or []):
            if d in g.nodes:
                g.edge(oid, d, "email", confidence="confirmed", evidence="operator identity on page")
    return g


# ------------------------------------------------ graph analytics (zero-dep)
def adjacency(nodes, edges):
    adj = {n: set() for n in nodes}
    for e in edges:
        adj[e["source"]].add(e["target"])
        adj[e["target"]].add(e["source"])
    return adj


def connected_components(adj):
    seen, comp = {}, 0
    for start in adj:
        if start in seen:
            continue
        comp += 1
        q = deque([start])
        seen[start] = comp
        while q:
            u = q.popleft()
            for v in adj[u]:
                if v not in seen:
                    seen[v] = comp
                    q.append(v)
    return seen  # node -> component id


def louvain(adj, passes=8):
    """Compact Louvain (local moving + aggregation) on an unweighted graph."""
    # weighted adjacency as dict of dict
    nodes = list(adj)
    w = {u: {v: 1.0 for v in adj[u]} for u in nodes}
    m2 = sum(sum(d.values()) for d in w.values())  # 2m
    if m2 == 0:
        return {n: i for i, n in enumerate(nodes)}
    comm = {n: n for n in nodes}
    # map original node -> current super-node, to unwind at the end
    origin = {n: [n] for n in nodes}

    def one_level(w, comm):
        k = {u: sum(d.values()) for u, d in w.items()}
        tot = defaultdict(float)
        for u in w:
            tot[comm[u]] += k[u]
        improved, moved_any = True, False
        while improved:
            improved = False
            for u in list(w):
                cu = comm[u]
                # remove u from its community
                tot[cu] -= k[u]
                # neighbor community weights
                nc = defaultdict(float)
                for v, wt in w[u].items():
                    if v != u:
                        nc[comm[v]] += wt
                best, best_gain = cu, 0.0
                for c, wsum in nc.items():
                    gain = wsum - tot[c] * k[u] / m2
                    if gain > best_gain:
                        best_gain, best = gain, c
                tot[best] += k[u]
                comm[u] = best
                if best != cu:
                    improved = True
                    moved_any = True
        return comm, moved_any

    for _ in range(passes):
        comm, moved = one_level(w, comm)
        if not moved:
            break
        # aggregate
        comms = {}
        for n, c in comm.items():
            comms.setdefault(c, []).append(n)
        new_origin = {}
        neww = defaultdict(lambda: defaultdict(float))
        cid = {c: i for i, c in enumerate(comms)}
        for c, members in comms.items():
            new_origin[cid[c]] = [o for mem in members for o in origin[mem]]
        for u in w:
            for v, wt in w[u].items():
                neww[cid[comm[u]]][cid[comm[v]]] += wt
        w = {u: dict(d) for u, d in neww.items()}
        origin = new_origin
        comm = {u: u for u in w}

    # unwind: super-node -> original nodes -> community index
    result = {}
    for super_id, members in origin.items():
        for orig in members:
            result[orig] = super_id
    return result


def leiden(node_ids, edges):
    """Higher-quality communities via igraph+leidenalg, if installed. Else None."""
    try:
        import igraph as ig
        import leidenalg
    except Exception:
        return None
    idx = {n: i for i, n in enumerate(node_ids)}
    elist = [(idx[e["source"]], idx[e["target"]]) for e in edges
             if e["source"] in idx and e["target"] in idx]
    G = ig.Graph(n=len(node_ids), edges=elist)
    part = leidenalg.find_partition(G, leidenalg.ModularityVertexPartition)
    return {node_ids[i]: c for i, c in enumerate(part.membership)}


def betweenness(adj):
    """Brandes' betweenness centrality (unweighted, undirected), normalized 0..1."""
    nodes = list(adj)
    bc = {n: 0.0 for n in nodes}
    for s in nodes:
        S, P, sigma, dist = [], {v: [] for v in nodes}, dict.fromkeys(nodes, 0), dict.fromkeys(nodes, -1)
        sigma[s], dist[s] = 1, 0
        q = deque([s])
        while q:
            v = q.popleft(); S.append(v)
            for w in adj[v]:
                if dist[w] < 0:
                    dist[w] = dist[v] + 1; q.append(w)
                if dist[w] == dist[v] + 1:
                    sigma[w] += sigma[v]; P[w].append(v)
        delta = dict.fromkeys(nodes, 0.0)
        while S:
            w = S.pop()
            for v in P[w]:
                delta[v] += (sigma[v] / sigma[w]) * (1 + delta[w])
            if w != s:
                bc[w] += delta[w]
    n = len(nodes)
    scale = 1.0 / ((n - 1) * (n - 2)) if n > 2 else 1.0
    mx = (max(bc.values()) if bc else 0.0) or 1.0   # tiny/edgeless graph → no crash
    return {k: v / mx for k, v in bc.items()}


def assemble(g, algo="louvain"):
    node_ids = list(g.nodes)
    edges = list(g.edges.values())
    adj = adjacency(node_ids, edges)
    comp = connected_components(adj)
    comm = None
    if algo == "leiden":
        comm = leiden(node_ids, edges)
        if comm is None:
            print("  leiden unavailable (need igraph+leidenalg); using Louvain",
                  file=sys.stderr)
    if comm is None:
        comm = louvain(adj)
    deg = {n: len(adj[n]) for n in node_ids}
    maxdeg = max(deg.values()) if deg else 1
    bc = betweenness(adj)

    out_nodes = []
    for nid, nd in g.nodes.items():
        nd = dict(nd)
        nd["component"] = comp.get(nid, 0)
        nd["community"] = comm.get(nid, 0)
        nd["degree"] = deg.get(nid, 0)
        nd["betweenness"] = round(bc.get(nid, 0.0), 4)
        # size hint: emphasize brokers; sqrt keeps hubs from swamping
        nd["size"] = round(18 + 46 * math.sqrt(max(bc.get(nid, 0), deg.get(nid, 0) / maxdeg)), 1)
        out_nodes.append(nd)

    n_comm = len(set(comm.values()))
    n_comp = len(set(comp.values()))
    # rank communities by size for stable coloring
    csize = defaultdict(int)
    for nd in out_nodes:
        csize[nd["community"]] += 1
    order = {c: i for i, c in enumerate(sorted(csize, key=lambda c: -csize[c]))}
    for nd in out_nodes:
        nd["community_rank"] = order[nd["community"]]

    # timeline events from domain first-seen dates (if history was provided)
    op_links = {e["target"] for e in edges if e["rel"] == "email"
                and g.nodes.get(e["source"], {}).get("type") == "operator"}
    timeline = []
    for nd in out_nodes:
        if nd["type"] == "domain" and nd.get("first_seen"):
            timeline.append({"date": nd["first_seen"], "id": nd["id"],
                             "label": nd["label"], "operator_linked": nd["id"] in op_links})
    timeline.sort(key=lambda x: x["date"])

    return {
        "meta": {"nodes": len(out_nodes), "edges": len(edges),
                 "communities": n_comm, "components": n_comp,
                 "algo": algo},
        "nodes": out_nodes,
        "edges": edges,
        "timeline": timeline,
    }


def main():
    ap = argparse.ArgumentParser(description="Build a clustered case graph from WebPivot JSON.")
    ap.add_argument("inputs", nargs="+", help="pivot_extract JSON files")
    ap.add_argument("--operator", help="add an operator persona node")
    ap.add_argument("--operator-links", help="comma-separated domains the operator is tied to")
    ap.add_argument("--history", help="wayback_ga.py JSON to attach first-seen dates + timeline")
    ap.add_argument("--leiden", action="store_true",
                    help="use Leiden clustering (needs igraph+leidenalg; falls back to Louvain)")
    ap.add_argument("--no-rank", action="store_true",
                    help="disable relation-strength ranking + sibling edges")
    ap.add_argument("--rank-include-weak", action="store_true",
                    help="include weak single-signal relations when ranking")
    ap.add_argument("-o", "--out", default="graph.json")
    args = ap.parse_args()

    analyses = load_pivots(args.inputs)
    links = [d.strip() for d in (args.operator_links or "").split(",") if d.strip()]
    history = load_history(args.history)
    g = build(analyses, operator=args.operator, operator_links=links, history=history)

    # Relation-strength ranking (default on) — score same-operator siblings, drop noise,
    # and inject explicit ranked `sibling` edges so a single graph pass carries them.
    ranked = None
    if _rank is not None and not args.no_rank:
        denylist = frozenset() if _rank.denylist_disabled() else _rank.load_denylist()
        ranked = _rank.rank(analyses, denylist, min_strength=1,
                            include_weak=args.rank_include_weak)
        for r in ranked["relations"]:
            strong = r["assessment"] == "same_operator_likely"
            g.edge(r["a"], r["b"], "sibling",
                   confidence="confirmed" if strong else "inferred",
                   evidence=f"relation_strength={r['relation_strength']}: " + ", ".join(r["signals"]),
                   link_class="operator" if strong else "link",
                   relation_strength=r["relation_strength"], signals=r["signals"],
                   assessment=r["assessment"], ranked=True)

    graph = assemble(g, algo="leiden" if args.leiden else "louvain")
    if ranked is not None:
        graph["relations"] = ranked["relations"]
        graph["clusters"] = ranked["clusters"]
        graph["meta"]["relations"] = len(ranked["relations"])
        graph["meta"]["operator_clusters"] = len(ranked["clusters"])
    json.dump(graph, open(args.out, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    m = graph["meta"]
    extra = (f", {m.get('relations', 0)} ranked relations, "
             f"{m.get('operator_clusters', 0)} operator clusters") if ranked is not None else ""
    print(f"wrote {args.out}: {m['nodes']} nodes, {m['edges']} edges, "
          f"{m['communities']} communities, {m['components']} components{extra}", file=sys.stderr)


if __name__ == "__main__":
    main()
