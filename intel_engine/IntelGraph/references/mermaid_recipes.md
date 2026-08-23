# Mermaid recipes (works locally via `mmdc`)

House theme init (muted): put this as line 1 of any `.mmd`:
```
%%{init: {'theme':'base','themeVariables':{'primaryColor':'#3b5566','primaryTextColor':'#fff','lineColor':'#6f6a61','fontFamily':'Helvetica'}}}%%
```
Render: `python scripts/render_mermaid.py diagram.mmd outputs/stem`

## Relationship / link graph (flowchart)
```
flowchart LR
  a["actor"]:::brick --> d1["evil.example"]:::steel
  d1 --> ip["185.10.20.30"]:::slate
  classDef brick fill:#8c2d2d,color:#fff;
  classDef steel fill:#3b5566,color:#fff;
  classDef slate fill:#22333f,color:#fff;
```

### Confidence-encoded links + rejected nodes (REQUIRED on any attribution graph)

A relationship graph is read at a glance, so the *strength* of each link must be visible in the
line, not buried in the prose — otherwise a "Low"-confidence extension (e.g. registrant → operator)
reads as identical to a confirmed same-operator link, and the diagram overstates the case. Use ONE
fixed vocabulary and put a legend in the figure so the reader never guesses:

- **solid arrow `-->`** = confirmed / high confidence (≥2 attribution-grade artifacts).
- **dashed arrow `-.->`** with a `?` label = assessed / **tentative** (the low-confidence extension;
  the registrant→operator leap belongs here, never on a solid line).
- **dotted arrow `..>`** into a `rejected` node = a link tested and **discarded** (keeps the
  falsified alternative visible — the strongest tradecraft signal — without asserting it).

```
flowchart LR
  reg["Registrant Name<br/>(registrant)"]:::steel
  op["site-a.example<br/>operator"]:::brick
  acct["Same-name individual<br/>(unrelated business)"]:::rejected
  reg -.->|"assessed · Low"| op
  reg ..>|"rejected: shared registrar only"| acct
  subgraph Legend [" "]
    direction LR
    l1[" "] -->|confirmed| l2[" "]
    l3[" "] -.->|"assessed (?)"| l4[" "]
    l5[" "] ..>|rejected| l6[" "]
  end
  classDef brick fill:#8c2d2d,color:#fff;
  classDef steel fill:#3b5566,color:#fff;
  classDef rejected fill:#2b2b2b,color:#bbb,stroke:#8c2d2d,stroke-width:2px,stroke-dasharray:4 3;
```

Keep node text to an identifier plus a one-line role — the narrative carries the detail, the
diagram carries the topology. A node crammed with a full sentence is the #1 legibility defect.

## Kill-chain / attack flow
```
flowchart TD
  R[Recon] --> W[Weaponize] --> D[Deliver] --> E[Exploit] --> I[Install] --> C[C2] --> A[Actions]
```
Vietnamese: Trinh sát → Vũ khí hóa → Phát tán → Khai thác → Cài đặt → Điều khiển → Hành động.

## Gantt (campaign phases)
```
gantt
  title Campaign timeline
  dateFormat YYYY-MM-DD
  section Infra
  Domain registration :2026-05-01, 6d
  section Response
  Detection & report :crit, 2026-05-16, 2d
```
(For report-native Gantt/timeline prefer `scripts/gantt.py` — matplotlib, no browser.)

## Timeline
```
timeline
  title Incident timeline
  2026-05-01 : Domain registered
  2026-05-10 : First phishing wave
  2026-05-16 : Reported & sinkholed
```
