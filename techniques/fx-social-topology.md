# fx-social-topology

## Purpose
Analyze the structural properties of a subject's social network — not just who they connect to, but where they sit within the graph and what that position reveals about their role and influence.

## Quick Reference
| Item | Detail |
|------|--------|
| Command | /social-topology |
| Input | Seed account(s) with connection data or exported graph |
| Output | Topology report with centrality metrics, community assignments, anomaly flags |
| Confidence | HIGH for directly observed connections; MEDIUM for derived metrics |

## Methodology
1. Collect connection data for seed subject: follower/following lists, mention history, reply graphs (2-hop minimum)
2. Build edge list: `source, target, type, weight, timestamp`
3. Load into NetworkX or Gephi; compute centrality metrics (see table below)
4. Run community detection (Louvain algorithm recommended for large graphs, k-clique for small dense networks)
5. Identify the subject's role: hub (high degree), broker (high betweenness), peripheral (low closeness), or authority (high eigenvector)
6. Flag structural anomalies: sudden connection bursts, coordinated mutual-follow clusters, connections to suspended accounts
7. Detect coordinated behavior: accounts posting identical content within the same time window; dense mutual-follow subgraphs created within 48 hours
8. Map community labels to real-world affiliations by sampling member profiles and shared content

## Graph Metrics Reference
| Metric | Formula Concept | High Value Means | OSINT Use |
|--------|----------------|-----------------|-----------|
| Degree centrality | Edge count / (n-1) | Many direct connections | Popularity, reach |
| Betweenness centrality | Fraction of shortest paths through node | Bridge between groups | Information broker, gatekeeper |
| Closeness centrality | 1 / avg distance to all nodes | Few hops to everyone | Rapid propagation potential |
| Eigenvector centrality | Connections × neighbor importance | Connected to influential nodes | Influence quality |
| Clustering coefficient | Closed triangles / possible triangles | Neighbors know each other | Tight community membership |
| PageRank | Iterative importance propagation | Cited by important accounts | Authority score |

## Community Structure Interpretation
| Pattern | Interpretation |
|---------|----------------|
| Subject bridges two otherwise disconnected clusters | Broker role — controls information flow between groups |
| Subject deeply embedded in one dense cluster | Core member — likely shares ideology/affiliation with cluster |
| Subject has high degree but low clustering | Hub connecting diverse, unrelated audiences |
| Dense subgraph created rapidly (< 7 days) | Coordinated inauthentic behavior — investigate |
| Mutual-follow cluster with identical creation dates | Botnet or sock puppet network |

## Tools & Fallbacks
| Priority | Tool | Install | Notes |
|----------|------|---------|-------|
| 1 | NetworkX | `pip3 install networkx` | Full metric suite; scriptable |
| 2 | Gephi | gephi.org | Visual layout; Force Atlas 2; Louvain module |
| 3 | Cytoscape | cytoscape.org | Bioinformatics origin; strong community detection |
| 4 | igraph (R or Python) | `pip3 install igraph` | Fast for large graphs |
| 5 | Maltego CE | maltego.com | OSINT-native; transforms for social data |
| 6 | NodeXL | nodexl.codeplex.com | Excel-based; accessible for non-coders |

## Output Format
```
Subject: @target_account

Graph Stats:
  Nodes:  312 (2-hop neighborhood)
  Edges:  1,847
  Density: 0.038 (sparse — expected for social networks)

Subject Centrality:
  Degree:      0.34 (top 8% of graph)
  Betweenness: 0.41 (top 3% — BROKER ROLE)
  Closeness:   0.28 (moderate)
  Eigenvector: 0.61 (connected to influential nodes)
  Clustering:  0.12 (low — bridges multiple communities)

Communities Detected (Louvain, 4 communities):
  C1 (89 nodes): political commentary cluster
  C2 (74 nodes): tech/security professionals
  C3 (112 nodes): mainstream media accounts
  Subject: bridges C1 ↔ C2 (betweenness spike)

Anomalies:
  - 47-node subgraph in C1 created within 3-day window (2025-01-18–21)
  - 89% mutual-follow rate within that subgraph → coordinated behavior flag
```

## Relative discovery

Use only lawfully accessible public material. Start with same-surname accounts in
following/follower/friend lists, maiden-name or former-surname variants, family tags and
comments, and explicit “mom”, “bro”, “sister” or similar language. Kinship language can be
figurative; a shared surname can be common and a follow can be incidental. Do not bypass
private-profile controls or contact family members to validate a hypothesis.

Cross-check public company/WHOIS records for shared surnames at the same address, and
public obituaries or wedding pages for an explicitly named relationship. A company address
may be a formation agent or shared office, and a WHOIS address may be a proxy; neither
establishes a household. Reposts of one announcement are one source, not independent signals.
Check dates, name collisions and whose account actually made a statement before grading.

| Relationship status | Required basis |
|---|---|
| confirmed | An explicit relationship statement in a post/comment by the account, or an official record identifying the relationship; retain the source and assess account/record identity separately |
| probable | Two independent signals supporting the same relationship, not two copies of one source |
| possible | Surname-only match; no relationship established |

Every relative remains a lead even when the relationship status is confirmed. Record
`rung: "lead"`, `status`, the relationship claim, its source URL/date and a `caveat`
explaining uncertainty and scope. Never call KB `add_edge` or create an `operator_lead`
for relatives; a relationship is not an identity or common-operator edge. Keep relationship
notes outside the KB identity graph and do not expand collection solely because kinship exists.

Privacy: avoid collecting minors' identities, dates of birth, schools, routine locations or
contact details. Public availability is not a reason to publish them. Omit incidental family
details and retain only the minimum relevant, lawful evidence. See
[public people records](people-records-global.md) for jurisdiction and access limitations.

## Limitations
- Platform API restrictions limit collection depth; follower counts visible but full lists often blocked
- Private accounts produce invisible edges — topology is always an undercount
- Centrality scores are sensitive to graph completeness; partial graphs inflate betweenness of boundary nodes
- Community detection algorithms are non-deterministic; run multiple times and compare
- Temporal snapshots miss relationship changes; a high-betweenness bridge may have dissolved

## Related Techniques
- [fx-network-mapping.md](fx-network-mapping.md) — construct the graph data this technique analyzes
- [fx-breach-discovery.md](fx-breach-discovery.md) — cross-reference high-centrality subjects against breach findings
- [fx-geolocation.md](fx-geolocation.md) — geolocate subject and community cluster members
