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
