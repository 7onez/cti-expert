# Graphviz recipes — entity / infrastructure link analysis

Node shapes per entity type (house convention):

| Entity | shape | fill |
|---|---|---|
| Threat actor | `box` | brick `#8c2d2d` |
| Domain | `ellipse` | steel `#3b5566` |
| IP address | `hexagon` | slate `#22333f` |
| Victim / target | `folder` | ochre `#b0790f` |
| Wallet | `cylinder` | olive `#5a6b3b` |
| Registrar / ASN | `note` | sand `#c9b892` |

## Template (`graph.dot`)
```dot
digraph infra {
  rankdir=LR;
  bgcolor="white";
  node [style="filled", fontname="DejaVu Sans", fontsize=11, color="#22333f", fontcolor="white"];
  edge [color="#6f6a61", fontname="DejaVu Sans", fontsize=9, fontcolor="#6f6a61"];

  actor  [label="APT-XX",        shape=box,      fillcolor="#8c2d2d"];
  d1     [label="evil.example",  shape=ellipse,  fillcolor="#3b5566"];
  d2     [label="evil2.example", shape=ellipse,  fillcolor="#3b5566"];
  ip1    [label="185.10.20.30",  shape=hexagon,  fillcolor="#22333f"];
  victim [label="Bank customers", shape=folder,   fillcolor="#b0790f"];
  w1     [label="bc1q…",         shape=cylinder, fillcolor="#5a6b3b"];

  actor -> d1 [label="registers"];
  actor -> d2 [label="registers"];
  d1 -> ip1   [label="A record"];
  d2 -> ip1   [label="shared IP"];
  d1 -> victim [label="phishes"];
  victim -> w1 [label="pays"];
}
```
Render:
```bash
python scripts/render_graphviz.py graph.dot outputs/infra_map
```

Tips: use `rank=same { ip1 ip2 }` to align infra rows; label edges with the pivot
that proves them (`favicon hash`, `GA4 G-…`, `shared IP`) so the graph is
self-documenting. Keep to one accent (brick) for the focal actor; everything else muted.
