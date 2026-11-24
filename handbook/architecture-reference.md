# Architecture reference — directory map of the skill

The annotated tree of the repository as the analyst-facing skill sees it. Read it when you need to
find where a capability lives. `STRUCTURE.md` is the authority on the two-layer layout and the
anti-drift rules; `connectors/intel-backend.md` covers the backend tiers and the op map.

```
cti-expert/
├── SKILL.md                    This file
├── README.md                   User-facing overview
│
├── engine/                     Case data model and state management
│   ├── case-schema.json        Subject and finding data structures
│   ├── subject-registry.md     How subjects are tracked and versioned
│   ├── finding-framework.md    Finding lifecycle, trust scores, evidence chains
│   ├── pivot-orchestration.md  Recursive spider-map pivot engine (BFS loop, edge matrix, gating)
│   ├── workspace-format.md     Workspace serialization spec
│   ├── workspace-manager.md    Save/open/list workspace logic
│   └── conflict-resolver.md    CONTESTED finding resolution
│
├── analysis/                   Pattern detection and intelligence engines
│   ├── deviation-detector.md   Behavioral anomaly detection
│   ├── auto-branch-rules.md    Automatic pivot trigger rules
│   ├── drift-monitor.md        Subject state change tracking
│   ├── cross-reference-engine.md Shared identifier detection across subjects
│   ├── archive-explorer.md     Wayback Machine integration and diff
│   ├── signature-catalog.md    Behavioral pattern library
│   ├── exposure-model.md       Exposure score calculation framework
│   ├── risk-trend-tracker.md   Temporal risk score tracking (/drift)
│   ├── pattern-library.md      Username, email, bot detection patterns
│   └── weight-engine.md        Finding aggregation and confidence weighting
│
├── techniques/                 Collection techniques and module specs
│   ├── fx-metadata-parsing.md  EXIF, headers, document metadata
│   ├── fx-image-verification.md Image authenticity and provenance
│   ├── fx-breach-discovery.md  Breach database and paste site methods
│   ├── fx-geolocation.md       GPS, W3W, Plus Codes, Street View
│   ├── fx-social-topology.md   Social graph construction and topology
│   ├── fx-email-header-analysis.md Header analysis, SPF/DKIM
│   ├── fx-document-forensics.md Document forensics and extraction
│   ├── fx-http-fingerprint.md  HTTP fingerprinting and signatures
│   ├── fx-leak-monitoring.md   Leak and breach monitoring
│   ├── username-osint.md       Platform enumeration (3000+)
│   ├── phone-osint.md          Phone carrier/VoIP/spam lookup
│   ├── email-osint.md          Deep email investigation
│   ├── threat-intel.md         Threat intelligence free lookups
│   ├── web-traffic-analysis.md Traffic estimation methods
│   ├── secret-scanning.md      Credential/secret detection
│   ├── github-osint.md         GitHub profiles, repos, code, commits, forks
│   ├── domain-advanced.md      Subdomain enumeration methods
│   ├── social-media-platforms.md Platform-specific techniques
│   ├── advanced-geolocation-techniques.md Overpass Turbo, road signs, reflected text
│   ├── wifi-ssid-osint.md      WiFi SSID/BSSID geolocation via Wigle.net
│   ├── web-dns-forensics.md    DNS, GitHub, Telegram, WHOIS
│   ├── fx-visitor-intelligence.md Visitor stats, tech stack, geo analysis
│   ├── scam-check.md           Phishing/scam domain verification
│   ├── cloud-audit.md          Cloud infrastructure security audit
│   ├── microsoft-tenant-recon.md M365/Azure tenant enumeration
│   ├── china-recon.md          ICP filings, PRC registries, CN cyberspace engines, CJK variants
│   ├── fiat-payment-osint.md   IBAN/BIC/bank accounts as selectors, VN-SEA rails
│   ├── drainer-investigation.md wallet-drainer heuristic, drainer contracts kit rung
│   ├── fx-edge-appliance-recon.md Edge/VPN appliance fingerprint → KEV/CVE catalog + port-risk matrix + passive patch lag
│   ├── fx-saas-identity-recon.md SaaS tenancy + IdP fingerprint + API/GraphQL/spec discovery
│   ├── fx-supplier-exposure.md   Supplier map + third-party risk (breach / KEV / stealer per supplier)
│   ├── dependency-audit.md     Supply chain security audit
│   ├── disk-forensics.md       Digital evidence analysis
│   ├── incident-triage.md      Security incident response
│   ├── owasp-audit.md          OWASP Top 10 source code audit
│   ├── prompt-injection-audit.md AI/LLM security audit
│   ├── stealer-log-analysis.md Infostealer-log triage, actor attribution & IOC extraction
│   ├── agent-browser.md        Interactive browser collection & evidence capture (vercel-labs/agent-browser)
│   └── ioc-export.md           IOC export (STIX 2.1, flat list)
│
├── experience/                 UX, tiers, and guided flows
│   ├── skill-tiers.md          Novice/Practitioner/Specialist spec
│   ├── layered-detail.md       Progressive disclosure rules
│   ├── guidance-system.md      How guided flows work
│   ├── case-progress.md        Progress tracking logic
│   ├── guided-flows/           Interactive step-by-step flows
│   │   ├── flow-person-lookup.md Person investigation guided flow
│   │   ├── flow-domain-sweep.md Domain reconnaissance guided flow
│   │   └── flow-image-check.md Image verification guided flow
│   ├── case-templates/         Pre-built case configurations
│   │   ├── tpl-index.md        Template index and descriptions
│   │   ├── tpl-due-diligence.md Due diligence case template
│   │   ├── tpl-security-review.md Security audit case template
│   │   └── tpl-background-check.md Background check case template
│   ├── tutorial.md             First-time onboarding guide (/onboard)
│   ├── feedback-system.md      Investigation quality feedback loops
│   └── accessibility/          Glossary and accessibility settings
│       ├── glossary.md         OSINT term glossary
│       └── accessible-mode.md  Low-jargon mode settings
│
├── output/                     Report and visualization specs
│   ├── reports/                Report format templates
│   │   ├── format-catalog.md   Report format specifications
│   │   ├── leadership-brief-template.md Executive brief template
│   │   ├── export-specs.md     Export format specifications
│   │   └── citation-guide.md   Source citation standards
│   └── visuals/                Chart and visualization specs
│       ├── chart-templates.md  Chart rendering templates
│       ├── ui-components.md    UI component library
│       ├── render-engine.md    ASCII render engine spec
│       ├── case-dashboard.md   Dashboard layout spec
│       ├── attack-path-diagram.md  Attack path flow visualization (/render threat-path)
│       └── attack-surface-map.md   Attack surface exposure map (/render attack-surface)
│
├── scripts/                    Cross-platform install + HTML / IOC / DOCX report generation
│   ├── platform-setup.md            Cross-platform reference: OS detection, uv-first install matrix, gotchas
│   ├── install.ps1                  Windows installer (uv-first: uv venv/pip/tool; winget + pip/pipx fallback)
│   ├── install.sh                   macOS/Linux/Git-Bash/WSL installer (uv-first; brew/apt + pip/pipx fallback)
│   ├── stealer_log_parse.py         Infostealer-log analyzer — attribution, profiling, IOCs (PEP 723 / `uv run`, zero-dep)
│   ├── iban_analyze.py              IBAN validate + decompose (ISO 13616/7064) → bank code, risk signals (PEP 723, zero-dep)
│   ├── phish_domain_survival.py     Phishing-domain registration/DNS profiling → maliciously-registered vs compromised + survival outlook (PEP 723, zero-dep)
│   ├── clickfix_detect.py           ClickFix / PasteJacking clipboard-hijack detector + `-enc` decode → C2 IOCs (PEP 723, zero-dep)
│   ├── html_visibility_analysis.py  Visibility-aware HTML analysis — hidden credential forms / off-origin links / off-screen text (PEP 723, zero-dep)
│   ├── apk_permission_scope.py      APK permission-scope risk scoring (BinaryPivot ext) — combo-based on-device-fraud capability; UTF-8/UTF-16 AXML decode (PEP 723, zero-dep)
│   ├── kit_template_fingerprint.py  Phishing kit/template structural fingerprint + similarity + commodity-trap grading (PEP 723, zero-dep)
│   ├── render_confirm.py            Renderer-level confirmation — reconciles static + rendered ClickFix/visibility evidence (PEP 723; optional Moli/Chromium/agent-browser)
│   ├── phishtrace_features.py       PhishTrace dynamic-feature characterization from a runtime trace → verdict + exfil IOCs (PEP 723, zero-dep)
│   ├── cld/cld_api.py               ChongLuaDao premium API client — IoC / denylist / data-leak dataset searches + bulk export / AI URL analysis / STIX-MISP-TAXII feeds (PEP 723 / `uv run`, zero-dep, X-API-Key)
│   ├── redact.py                    Reversible PII redaction — stable placeholders + exportable map; md/json/csv (PEP 723, zero-dep)
│   ├── cti-report-template.html     PRIMARY: interactive HTML report template — self-contained & OFFLINE (charts + 2D entity graph + topology + timeline + indicator panel + search; dark/light + print-to-PDF)
│   ├── generate-cti-html.py         HTML report generator — injects the report JSON into the template + builds the embedded Archify Blueprint (`CTI_ARCHIFY=1|force|0`; PEP 723 / `uv run`, zero-dep, self-heals UTF-8)
│   ├── cti_archify.py               CTI case → Archify `architecture` IR converter (drives the report's inline Blueprint diagram; folds dense estates to apex level + hub-and-spoke placement; stdlib-only, reuses the engine's PSL reducer when present)
│   ├── vendor/archify/              Vendored zero-dep Archify render subset (v2.16.0, MIT) — renders the Blueprint diagram; needs Node.js (see vendor/archify/VENDOR.md)
│   ├── cti_diagram_design.py        CTI case → Diagram Design editorial SVG (entity + topology); cairosvg rasterizer for DOCX (stdlib SVG)
│   ├── cti_cloud_arch.py            CTI case → Diagram AI Generator cloud figure (diagrams+graphviz, cloud-gated, opt-in; isolated uv subprocess)
│   ├── vendor/diagram-design/       Vendored Diagram Design style-guide + self_check + LICENSE (MIT) — editorial token/rule source
│   ├── vendor/diagram-ai-generator/ LICENSE + VENDOR note (MIT) — cloud figure applies its spec/approach via the `diagrams` library
│   ├── generate-cti-iocs.py         Comprehensive IOC/selector exporter → STIX 2.1 / flat / CSV (network IOCs + contacts + identities + social/messaging + wallets + attribution; PEP 723 / `uv run`, zero-dep)
│   ├── generate-cti-docx-hybrid.py  Hybrid MD+JSON DOCX generator — on request / `/report legal` (PEP 723 / `uv run`; self-heals UTF-8 + pandoc)
│   ├── generate-cti-docx.py         Fallback: JSON-only generator (PEP 723 / `uv run`)
│   ├── cti_docx_postprocess.py      Post-processing: styling, chart injection, cover page
│   ├── cti_docx_charts.py           Chart rendering (pie, bar, timeline, traffic, geo, ICD-203×Admiralty confidence matrix)
│   ├── cti_docx_heatmaps.py         Campaign heatmaps (registration timeline, domain×indicator correlation, domain×domain relation)
│   ├── cti_docx_pdf.py              DOCX→PDF via LibreOffice (document-style PDF; the --pdf path)
│   ├── cti_docx_diagrams.py         Entity relationship + network topology diagrams
│   ├── cti_docx_sections.py         Report section formatting (used by JSON-only generator)
│   ├── cti_docx_styles.py           Document styling, colors, cover page, header/footer
│   ├── requirements.txt             Python dependencies
│   └── sample-cti-report-data.json  Example JSON report data
│
├── workflows/                  Professional workflow guides
│   ├── wf-journalist.md
│   ├── wf-hr-screening.md
│   ├── wf-threat-analyst.md
│   ├── wf-emerging-threat.md     Emerging-threat response (intake → exposure → advisory/assessment → +7/+30 checkpoints)
│   └── wf-private-investigator.md
│
├── handbook/                   Reference material
│   ├── operator-queries.md     Search operator catalog
│   ├── quick-report.md         Rapid reporting reference
│   ├── discovery-paths.md      Per-target-type search paths
│   ├── report-template.md      INTSUM format specification
│   ├── admin-endpoint-indicators.md  Admin-panel / sensitive-endpoint detection vocab & rules
│   ├── analytic-standards.md    Likelihood bands, 5W1H coverage overlay, ACH (competing hypotheses), bias checks
│   ├── intrusion-modeling.md   Diamond Model (events, activity threads/groups), Pyramid of Pain pivot priority, ATT&CK mapping limits
│   ├── severity-tiers.md       Severity Tier Matrix: Axis 1 patterns per trigger type, Axis 2 exposure dimensions, P1–P4 grid, re-tiering log
│   ├── collection-preservation.md  Evidence collection/preservation standard (Berkeley Protocol): risk check, plan, capture fields, chain of custody, 3-part verification
│   ├── aam-actor-modeling.md   AAM actor-state overlay for /threat-model — OODA faces + Mirror/Twin/Opposite/Lever (eCrime 2026 "Modeling Adversaries Through Chaos")
│   ├── pivot-artifacts.md      Pivot-artifact catalog (favicon, trackers, wallets, certs…)
│   ├── pivot-services.md       Reverse-lookup engines per artifact — hash algo, cost, API/key notes
│   ├── api-keys.md             Premium/pro API key management and unlocks
│   └── tool-cascade-reference.md Tool priority and fallback chains
│
├── guides/                     Worked case walkthroughs
│   └── walkthroughs/           Step-by-step investigation examples
│       ├── walkthrough-person-lookup.md
│       ├── walkthrough-domain-sweep.md
│       └── walkthrough-username-trace.md
│
├── validation/                 Quality assurance
│   ├── coverage-matrix.md      Investigation area coverage tracking
│   ├── quality-scoring.md      Scoring methodology
│   └── verification-checklist.md Finding verification steps
│
└── connectors/                 External tool integrations
    ├── maltego-export.md
    ├── obsidian-setup.md
    ├── notion-schema.md
    ├── intel-backend.md
    └── chongluadao-api.md
```
