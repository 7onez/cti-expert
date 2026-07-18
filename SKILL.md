---
name: cti-expert
description: "CTI Expert — cyber threat intelligence and OSINT analysis toolkit. Activates on: OSINT, CTI, threat intelligence, digital footprint, social media investigation, username enumeration, email tracing, domain/subdomain recon, OPSEC, metadata analysis, people search, geolocation, breach checking, phone lookup, case investigation, due diligence, image forensics, face search, blockchain/crypto tracing, flight/maritime/vehicle tracking, darknet search, WiFi SSID geolocation, vulnerability lookup, ransomware check, infostealer/stealer log triage, admin panel & sensitive endpoint discovery, M365/Azure recon, web-infra pivoting, favicon/tracker-ID reverse lookup, campaign clustering, phishing-kit fingerprinting, premium API-key management. Commands: /case, /sweep, /query, /subject, /timeline, /report, /brief, /exposure, /username, /phone, /breach-deep, /vuln-check, /wifi, /flow, /threat-model, /msftrecon, /stealer-log, /webpivot, /rank-relations, /cert-pivot, /pivot-suggest, /crypto-balance, /email-hygiene, /sensitive-paths, /appliance-scan, /saas-map, /apikeys."
version: "2.5"
author: "Hieu Ngo - chongluadao.vn"
---

# CTI Expert

Cyber threat intelligence and open-source intelligence skill. Turns Claude into a trained CTI/OSINT analyst. Generates precision search queries, interprets public data, builds case timelines, and delivers structured intelligence products — no API keys, no paid subscriptions.

> **Runs anywhere.** Works in **Claude Code** (Desktop & CLI) and in **OpenAI Codex / ChatGPT** and other `AGENTS.md`-aware agents — see [`AGENTS.md`](AGENTS.md) for the cross-agent runtime contract. Throughout this file, **`$SKILL_DIR`** = the directory containing this `SKILL.md` (Claude Code: `~/.claude/skills/cti-expert`; Codex/manual clone: the repo you are working in). Resolve it by locating `SKILL.md` — never hard-assume `~/.claude`. Detect the OS once (Windows/macOS/Linux) and prefer **uv** for all Python — see §13 Tool Auto-Install Policy.

Collection method: `agent-browser` when available (JavaScript-heavy sites, infinite-scroll, screenshot evidence), with automatic fallback to web search / web fetch / direct URL fetch. Tool limitations are logged as collection gaps — never as case blockers.

---

## 1. Quick Start

```bash
# Full autonomous case — runs every applicable technique
/case target.com

# Guided flow for first-time investigators
/flow person

# Summary of what's been found so far
/brief
```

Append `--yolo` to any command to skip all interactive prompts and confirmations. The analyst makes every decision autonomously.

---

## 2. AEAD Case Lifecycle

Every investigation follows four phases:

| Phase | What Happens |
|-------|-------------|
| **Acquire** | Collect raw data — `/sweep`, `/query`, `/username`, `/phone`, `/email-deep`, `/subdomain`, `/webpivot` (domain/URL targets) |
| **Enrich** | **Recursive pivot loop** — the [pivot orchestration engine](engine/pivot-orchestration.md) treats every discovered identifier as a new seed and expands the graph hop-by-hop (`/branch`, `/crossref`, `/link-subjects`, `/signatures`) until the frontier is exhausted; checkpoints per depth. Acquire↔Enrich iterate, not run once. |
| **Assess** | Score and verify — `/exposure`, `/threat-model`, `/validate`, `/coverage`, `/verify-finding` |
| **Deliver** | Package output — `/report`, `/brief`, `/render`, `/workspace save` — **auto-saves .md + .html + .json + .csv + IOC bundle** |

Run `/progress` at any point to see which phase you're in and what's pending.

> **`/case` and web-infra pivoting.** For a **domain or URL** target, `/case` includes
> web-infrastructure pivoting (`/webpivot`) in the Acquire phase. It runs **keyless by default**
> (crt.sh + passive DNS + anonymous urlscan) and **upgrades automatically when premium keys are
> set** via `/apikeys` (Shodan/Censys/FOFA/DNSLytics/SecurityTrails/urlscan-PRO/WhoisXML). Because
> `/webpivot` can fetch the target directly, for hostile infrastructure it prefers passive capture
> (urlscan/Wayback) — see [`techniques/web-pivot.md`](techniques/web-pivot.md). It is **not** run for
> username/phone/person targets.
>
> **Archive IOC harvest runs by default too.** For domain/URL targets the Acquire phase also runs
> `wayback_harvest.py <domain> --indicators` (add `--urlscan` when `URLSCAN_API_KEY` is set),
> harvesting **emails, phones, crypto wallets, tracking/verification IDs, SaaS-operator IDs, and
> socials from the *entire* Wayback history** — not just the live page — with first-seen/last-seen
> per selector. It writes case-schema `indicators[]` to `<case>/raw/harvest.indicators.json`, which
> merge into the case and flow into the **auto-saved IOC bundle** at Deliver. This is the step that
> recovers selectors a network later scrubbed — across the whole snapshot corpus, not just the live page.
> Passive by construction — only web.archive.org (+ urlscan.io if keyed), never the target.

---

## 3. Command Reference

Commands grouped by AEAD phase.

### Acquire

| Command | What It Does | Example |
|---------|-------------|---------|
| `/case [target]` | Full pipeline — runs every applicable technique | `/case example.com` |
| `/sweep [target]` | Multi-vector recon on any target type | `/sweep @username` |
| `/query [subject]` | Builds 12–15 advanced search operator queries | `/query example.com` |
| `/username [handle]` | Enumerate handle across 3000+ platforms | `/username johndoe` |
| `/phone [number]` | Carrier, line type, reputation, public associations | `/phone +84901234567` |
| `/email-deep [email]` | Accounts, breach history, infrastructure | `/email-deep u@domain.com` |
| `/subdomain [domain]` | CT logs, brute-force, passive enumeration; flags admin/sensitive subdomains (`admin`,`adm`,`kef`,`ador`,`panel`…) per `handbook/admin-endpoint-indicators.md` | `/subdomain example.com` |
| `/breach-deep [email]` | Multi-source breach lookup with context | `/breach-deep u@domain.com` |
| `/traffic [domain]` | Traffic estimation, ranking, audience data | `/traffic example.com` |
| `/visitors [domain]` | Full visitor intelligence: tech, geo, sources, analytics | `/visitors example.com` |
| `/techstack [domain]` | Technology fingerprint (CMS, analytics, CDN, server) | `/techstack example.com` |
| `/competitors [domain]` | Competitor & related site discovery | `/competitors example.com` |
| `/secrets [target]` | Exposed credentials in repos and paste sites | `/secrets github.com/org` |
| `/github-osint [target]` | GitHub user/org/repo recon: profiles, repos, code search, commits, forks | `/github-osint github.com/org/repo` |
| `/threat-check [target]` | IP/domain/URL/hash threat intelligence | `/threat-check 185.1.1.1` |
| `/scam-check [domain]` | Phishing/scam/malicious domain check | `/scam-check susp-site.xyz` |
| `/webpivot [url]` | Web-infra pivoting — extract favicon mmh3 / GA-GTM-AdSense / wallet / SaaS-operator artifacts from a page's DOM → ranked pivot queries (Shodan/PublicWWW/urlscan/FOFA). Flags: `--render`, `--crawl`, `--history` (Wayback GA), `--fetch` (pull archived page content — WebFetch can't reach Wayback), `--harvest` (full-IOC harvest across whole archive history → emails/phones/wallets/IDs/socials), `--whois`, `--graph` (cluster), `--rank` (score same-operator relations), `--cert` (cert-fingerprint pivot), `--suggest`, `--wallets`, `--paths`. See `techniques/web-pivot.md` | `/webpivot https://scam-site.top` |
| `/cert-pivot [domain]` | Cert-fingerprint pivot — other hosts serving the same TLS cert + SAN siblings (keyless; Shodan/Censys with keys) | `/cert-pivot scam-site.top` |
| `/sensitive-paths [list]` | Classify a Wayback/URL list for exposed paths (.git/.env/backups/configs) — severity + per-year timeline | `/sensitive-paths waymore_index.txt` |
| `/email-hygiene [email]` | Grade an email domain 0–100 + A–F (disposable/MX/free/role) | `/email-hygiene admin@site.top` |
| `/vuln-check [query]` | CVE/vulnerability lookup (CIRCL + NVD) | `/vuln-check CVE-2024-1234` or `/vuln-check apache/httpd` |
| `/ransomware-check [org]` | Check if org is a ransomware victim | `/ransomware-check "Acme Corp"` |
| `/stealer-log [folder]` | Triage an infostealer-log folder — stealer-family attribution, victim-vs-operator profiling, cross-log actor correlation, IOC extraction (raw passwords/cookies/autofill/history shown) | `/stealer-log ./logs` |
| `/gdoc [url]` | Extract metadata/owner from Google document | `/gdoc https://docs.google.com/...` |
| `/msftrecon [domain]` | M365/Azure tenant recon — tenant ID, federation, MDI, SharePoint | `/msftrecon example.com` |
| `/appliance-scan [domain\|ip]` | Fingerprint internet-facing edge/VPN appliances (Citrix/F5/Cisco/Ivanti/Forti/PAN/Exchange) + exposed services → CISA KEV/CVE mapping. Passive-first (Shodan InternetDB/Censys); feeds `/vuln-check` + `/threat-model`. See `techniques/fx-edge-appliance-recon.md` | `/appliance-scan vpn.example.com` |
| `/saas-map [domain]` | Map SaaS tenancy + identity fabric — DNS-TXT tenancy tokens, non-Microsoft IdP fingerprint (Okta/Auth0/OneLogin/Ping/Keycloak/ADFS), unauth API/GraphQL/spec discovery. See `techniques/fx-saas-identity-recon.md` | `/saas-map example.com` |
| `/sharelink [url]` | Extract sharer identity from share link | `/sharelink https://vm.tiktok.com/ABC` |
<!-- dork-integration:phase-05 start -->
| `/dork-sweep [target] [--telegram\|--docs\|--filetype\|--all] [--after DATE] [--clean]` | Zero-auth dork sweep: Telegram ecosystem, 18 doc-hosts, filetype families; 4-tier fallback cascade | `/dork-sweep example.com --filetype` |
| `/docleak [target] [--platform list] [--severity high]` | 18-platform document leak hunt with severity classification (CRITICAL/HIGH/MEDIUM/LOW) | `/docleak "Acme Corp"` |
<!-- dork-integration:phase-05 end -->
| `/dns-history [domain]` | Historical DNS record changes (A, NS, MX) via passive DNS | `/dns-history example.com` |
| `/cert-history [domain]` | SSL/TLS certificate timeline from CT logs (crt.sh) | `/cert-history example.com` |
| `/email-permute [name] [domain]` | Generate email permutations from name + domain | `/email-permute "John Smith" company.com` |
| `/proton-check [email]` | Proton Mail account creation date via PGP key | `/proton-check user@proton.me` |
| `/pgp-lookup [email]` | PGP key search — creation date, UIDs, signatures | `/pgp-lookup dev@example.com` |
| `/wifi [ssid]` | WiFi SSID geolocation via Wigle.net | `/wifi "HomeNetwork"` |
| `/wifi --bssid [mac]` | Exact AP lookup by MAC address | `/wifi --bssid AA:BB:CC:DD:EE:FF` |
| `/register [name]` | Add a subject to the case workspace | `/register JohnDoe` |
| `/snapshots [url]` | List/fetch archived Wayback snapshots. **Note: WebFetch is blocked from web.archive.org (robots.txt) — use `scripts/webpivot/wayback_fetch.py` to list captures and pull archived content.** See `analysis/archive-explorer.md` | `/snapshots example.com` |

### Enrich

| Command | What It Does | Example |
|---------|-------------|---------|
| `/branch [data]` | Expand a discovered identifier laterally | `/branch john@mail.com` |
| `/pivot-suggest` | Rank "what to pivot on next" from findings — leet/variant/reuse/temporal/domain clusters | `/pivot-suggest` |
| `/rank-relations` | Score + rank same-operator relations across analyzed pages (noise-filtered, clustered) | `/rank-relations` |
| `/crypto-balance [addr]` | On-chain balance + lifetime flow for a wallet, valued at spot | `/crypto-balance 1A1z…` |
| `/timeline [subject]` | Assemble dated event sequence | `/timeline Company Inc` |
| `/crossref` | Detect shared identifiers across subjects | `/crossref` |
| `/link-subjects [A] [B]` | Define a connection between two subjects | `/link-subjects John Jane` |
| `/show-connections` | Display all logged connections | `/show-connections` |
| `/show-trail [subject]` | Show the evidence chain for a subject | `/show-trail JohnDoe` |
| `/watch [subject]` | Add subject to active tracking list | `/watch example.com` |
| `/record-finding` | Log a finding with source and confidence | Paste data after command |
| `/show-findings` | List all recorded findings | `/show-findings` |
| `/graph` | Full ASCII subject relationship map | `/graph` |
| `/pathfind [A] [B]` | Discover connection path between subjects | `/pathfind A B` |
| `/diff [url]` | Diff archived versions of a URL | `/diff example.com/page` |

### Assess

| Command | What It Does | Example |
|---------|-------------|---------|
| `/exposure [target]` | Composite exposure score (0–100) | `/exposure domain.com` |
| `/threat-model` | Build threat model from findings | `/threat-model` |
| `/signatures` | Surface recurring behavioral patterns | `/signatures` |
| `/validate` | Quality audit — score 0–100 | `/validate` |
| `/coverage` | Coverage matrix with identified gaps | `/coverage` |
| `/verify-finding [id]` | Re-check a specific finding's sources | `/verify-finding 12` |
| `/subject [name]` | View or create subject record | `/subject JohnDoe` |
| `/lookup [name]` | Retrieve a registered subject | `/lookup JohnDoe` |
| `/modify [name]` | Update a subject record | `/modify JohnDoe` |
| `/archive-subject [name]` | Remove subject from active tracking | `/archive-subject JohnDoe` |
| `/find [query]` | Search across all subjects | `/find domain:example.com` |
| `/show-trail [subject]` | Full evidence trail | `/show-trail JohnDoe` |
| `/blind-spots` | Prioritized investigation gap analysis | `/blind-spots` |
| `/source-check` | Batch source URL accessibility check | `/source-check` |
| `/drift [subject]` | Temporal risk score tracking | `/drift example.com` |
| `/clarify [finding]` | Plain-language finding explanation | `/clarify fnd-003` |

### Deliver

| Command | What It Does | Example |
|---------|-------------|---------|
| `/report` | Full report — auto-saves .md + .html + .json + .csv + IOC bundle | `/report` |
| `/report html` | Interactive self-contained HTML report (primary deliverable) | `/report html` |
| `/report brief` | Single-page executive brief | `/report brief` |
| `/report json` | Raw data as JSON | `/report json` |
| `/report csv` | Spreadsheet-compatible export | `/report csv` |
| `/report docx` | Word document (rich charts/diagrams) — on request | `/report docx` |
| `/report legal` | Evidence-formatted for legal proceedings (adds DOCX/PDF) | `/report legal` |
| `/report journalist` | Source-citation-heavy format | `/report journalist` |
| `/brief` | Plain-language summary (non-technical) | `/brief` |
| `/render entities` | ASCII subject relationship diagram | `/render entities` |
| `/render timeline` | Chronological event chart | `/render timeline` |
| `/render risk` | Exposure heatmap | `/render risk` |
| `/render network` | Network topology of connections | `/render network` |
| `/stats` | Counts and coverage statistics | `/stats` |
| `/workspace save [name]` | Persist case state | `/workspace save mycase` |
| `/workspace open [name]` | Resume a saved case | `/workspace open mycase` |
| `/workspace list` | Show saved cases | `/workspace list` |
| `/workspace diff [a] [b]` | Diff two saved workspaces | `/workspace diff case1 case2` |
| `/render threat-path` | ASCII attack path flow diagram | `/render threat-path` |
| `/render attack-surface` | ASCII attack surface exposure map | `/render attack-surface` |
| `/report ioc` | Export IOCs as STIX 2.1 or flat list | `/report ioc --format stix` |

### UX & Navigation

| Command | What It Does | Example |
|---------|-------------|---------|
| `/flow [type]` | Guided step-by-step case workflow | `/flow person` |
| `/template list` | Browse pre-built case templates | `/template list` |
| `/template run [name]` | Run a pre-built template | `/template run security-audit` |
| `/novice` | Toggle simplified, low-jargon mode | `/novice` |
| `/terms` | OSINT term glossary | `/terms` |
| `/progress` | Current case phase and coverage | `/progress` |
| `/opsec` | OPSEC checklist for current task | `/opsec` |
| `/onboard` | Interactive first-time onboarding guide | `/onboard` |
| `/quality` | Investigation quality composite score | `/quality` |

### Configure

| Command | What It Does | Example |
|---------|-------------|---------|
| `/apikeys` | Manage premium/pro API keys (Shodan, Censys, FOFA, SecurityTrails, DNSLytics, urlscan-PRO, WhoisXML, Hudson Rock, IntelX, GitHub, SerpAPI…) — `status`/`set`/`unset`/`test`/`unlocks`. Keys **upgrade existing techniques** (especially `/webpivot`); keyless/free stays the default. Stored chmod-600 in `$SKILL_DIR/.env` (gitignored), env-var override. See `handbook/api-keys.md` | `/apikeys set shodan <KEY>` |

---

## 4. Subject & Connection Model

Reference: `engine/case-schema.json`, `engine/subject-registry.md`

### Subject Types

| Type | Emoji | Examples |
|------|-------|---------|
| Person | 👤 | Full name, alias |
| Username | @ | Social handle |
| Email | 📧 | Address, domain |
| Domain | 🌐 | Site, subdomain |
| IP Address | 🖥 | IPv4, IPv6 |
| Organization | 🏢 | Company, group |
| Phone | 📱 | E.164 format |
| Location | 📍 | GPS, address |
| Asset | 📦 | Document, image |
| Event | 📅 | Dated occurrence |
| Device | 🖥️ | IoT device, server, workstation |
| Image | 🖼️ | Photograph, screenshot |
| Crypto Address | 💰 | Bitcoin, Ethereum wallet |
| Custom | 🏷️ | User-defined entity type |

### Connection Types

```
owns         — domain, email, or asset ownership
uses         — platform account or tool usage
works_at     — employment or affiliation
linked_to    — general association
alias        — same identity, different handle
communicated_with — observed contact
```

### Finding Trust Scores

| Score | Label | Meaning |
|-------|-------|---------|
| 5 | PRIMARY | Authoritative or official source |
| 4 | DERIVED | Confirmed by 2+ independent sources |
| 3 | CONFIRMED | Single reliable source, verified |
| 2 | ANECDOTAL | Reported but unverified |
| 1 | CONTESTED | Conflicting data exists |

### Source Reliability Scale

Complements numeric trust scores with source-level grading. Trust score rates finding content; source reliability rates the source itself.

| Grade | Label | Typical Sources |
|-------|-------|-----------------|
| A | Completely Reliable | Official registries, government records |
| B | Usually Reliable | Established outlets, corporate sources |
| C | Fairly Reliable | Known blogs, industry publications |
| D | Not Usually Reliable | Anonymous forums, unverified claims |
| E | Unreliable | Known disinformation, fabricated content |
| F | Cannot Be Judged | Insufficient information to assess |

### Confidence Levels

| Level | Label | Use When |
|-------|-------|---------|
| VERIFIED | Direct observation, primary source | |
| STRONG | Multiple corroborating sources | |
| MODERATE | Single reliable source | |
| WEAK | Circumstantial or inferred | |
| TENTATIVE | Analyst deduction only | |
| CHALLENGED | Contradicted by other findings | |

### Map Rendering (ASCII Mandatory)

**ALL visualization commands produce ASCII box-drawing art by default.** This includes `/graph`, `/render entities`, `/render network`, `/render timeline`, `/render risk`, `/pathfind`, and `/show-connections`. Mermaid available only with explicit `--mermaid` flag.

**Why ASCII-first:** Universal terminal compatibility, renders correctly in .md and .docx exports, no external renderer dependency.

```
┌─────────────────────────────┐   owns   ┌───────────────────────────┐
│ 👤 John Doe          [3/5] │══════════▶│ 🌐 example.com     [4/5] │
└─────────────────────────────┘           └───────────────────────────┘
         │ works_at                       │ hosted_on
         ▼                                ▼
┌─────────────────────────────┐  ┌───────────────────────────┐
│ 🏢 Acme Corp         [4/5] │  │ 🖥 203.0.113.10    [4/5] │
└─────────────────────────────┘  └───────────────────────────┘
```

**Connection arrows:**  `═══▶` owns · `───▶` confirmed · `···▶` inferred · `←─▶` bidirectional · `─·─▶` alias · `╌╌▶` works_at
**Box styles:**  `┌──┐` confirmed · `┌ ─ ┐` unverified · `╔══╗` target
**Badge:**  `[n/5]` trust score · emoji prefix = entity type

---

## 5. Finding Framework

Reference: `engine/finding-framework.md`, `engine/conflict-resolver.md`

Every finding logged via `/record-finding` captures:

```
Source URL / method
Collection method (browser | search | fetch | manual)
Trust score (1–5)
Confidence level (VERIFIED → CHALLENGED)
Timestamp
Linked subjects
```

**Conflict detection** (`engine/conflict-resolver.md`): When two findings about the same subject contradict each other, the system flags a CONTESTED state. Both findings are preserved. Resolution options: accept one, mark both TENTATIVE, or log the conflict as its own finding.

**Deviation detection** (`analysis/deviation-detector.md`): Automatically flags behavioral anomalies — account creation gaps, platform presence inconsistencies, metadata mismatches.

**Weight engine** (`analysis/weight-engine.md`): Aggregates trust scores across findings to compute subject-level confidence.

---

## 6. Technique Catalog

Reference directory: `techniques/`

| File | Covers |
|------|--------|
| `fx-metadata-parsing.md` | EXIF, email headers, document metadata analysis |
| `fx-image-verification.md` | Image authenticity and provenance workflow |
| `fx-breach-discovery.md` | Breach database methods and paste site search |
| `fx-geolocation.md` | GPS extraction, W3W, Plus Codes, MGRS, Street View |
| `fx-social-topology.md` | Social graph construction and topology |
| `fx-email-header-analysis.md` | Header analysis, SPF/DKIM, SMTP routing |
| `fx-document-forensics.md` | Document forensics and metadata extraction |
| `fx-http-fingerprint.md` | HTTP fingerprinting and server signature analysis |
| `fx-leak-monitoring.md` | Leak and breach monitoring, paste site search |
<!-- dork-integration:phase-05 start -->
| `fx-dork-sweep.md` | Zero-auth Google/Bing dork sweeps — Telegram ecosystem, doc-hosts, filetype families + 4-tier fallback cascade (WebSearch → Bing → DDG → agent-browser) |
| `fx-document-leak-hunt.md` | 18-platform document leak discovery with severity classification, paywall handling, auto-snapshot |
<!-- dork-integration:phase-05 end -->
| `username-osint.md` | 3000+ platform enumeration with pivot extraction |
| `phone-osint.md` | Carrier lookup, VoIP detection, spam databases, FreeCNAM CallerID, WhoCalld, USPhoneBook reverse lookup |
| `email-osint.md` | Full email investigation: accounts, breaches, infra, Proton API, PGP keys, permutation, manual reference tools |
| `fx-dns-cert-history.md` | Historical DNS records (passive DNS, A/NS/MX changes), SSL certificate timeline (crt.sh CT logs) |
| `threat-intel.md` | AbuseIPDB, GreyNoise, OTX, VirusTotal, **URLScan.io**, **CIRCL CVE**, **NVD API**, **ransomware.live** |
| `web-traffic-analysis.md` | SimilarWeb/Semrush estimation, audience data |
| `secret-scanning.md` | Credential/secret detection in repos and pastes |
| `github-osint.md` | GitHub user/org/repo profiling, code search, commit metadata, forks, collaboration networks |
| `domain-advanced.md` | Subfinder, Amass, CT log enumeration |
| `social-media-platforms.md` | Twitter/X Snowflake IDs, Discord, Strava, BlueSky, ShareTrace share link analysis |
| `advanced-geolocation-techniques.md` | Overpass Turbo, road sign analysis, reflected text |
| `web-dns-forensics.md` | Zone transfers, Tor lookups, GitHub, Telegram, WHOIS, Xeuledoc Google doc intel |
| `fx-visitor-intelligence.md` | Visitor stats, tech stack, geo, traffic sources, analytics/AdSense/advertising ID cross-domain linking, competitors |
| `wifi-ssid-osint.md` | WiFi SSID/BSSID geolocation via Wigle.net, encryption analysis, travel patterns |
| `scam-check.md` | Phishing/scam domain verification and detection |
| `cloud-audit.md` | Cloud infrastructure security (AWS/GCP/Azure): IAM, network, storage, compute, logging, secrets |
| `microsoft-tenant-recon.md` | M365/Azure tenant enumeration — federation, tenant ID, Azure AD config, MDI detection |
| `fx-edge-appliance-recon.md` | Edge/VPN appliance fingerprint → CISA KEV/CVE catalog (Citrix/F5/Cisco/Ivanti/Forti/PAN/Exchange) + exposed-service port-risk matrix (Shodan InternetDB, passive-first) |
| `fx-saas-identity-recon.md` | SaaS tenancy + identity-fabric mapping — DNS-TXT tenancy tokens, IdP fingerprinting (Okta/Auth0/OneLogin/Ping/Keycloak/ADFS/Entra), unauthenticated API/GraphQL/OpenAPI-spec discovery |
| `dependency-audit.md` | Supply chain security: CVE audit, framework-specific vulns, typosquatting, CI/CD security |
| `disk-forensics.md` | Digital evidence analysis: image integrity, Sleuth Kit, file carving, artifact recovery, timeline |
| `incident-triage.md` | Security incident response: NIST 800-61 methodology, containment, evidence preservation, IOC extraction |
| `owasp-audit.md` | OWASP Top 10 (2021) source code audit with grep patterns and CWE references |
| `prompt-injection-audit.md` | AI/LLM security: prompt injection classes, agent/MCP security, permission boundary audit |
| `stealer-log-analysis.md` | Infostealer-log triage: family fingerprinting (RedLine/Vidar/StealC/Lumma/META/traffer), victim-vs-operator profiling, cross-log actor correlation, IOC + attribution extraction (`uv run` parser, raw artifacts shown) |
| `agent-browser.md` | Interactive browser collection & evidence capture via vercel-labs/agent-browser (CDP, accessibility-tree `@eN` snapshots, screenshots; primary interactive collector, complementary to Scrapling) |

---

## 7. Workflow Guides

Reference directory: `workflows/`

| Guide | Intended User | File |
|-------|--------------|------|
| Journalist Source Verification | Journalists verifying claims | `wf-journalist.md` |
| HR Screening | HR professionals running background checks | `wf-hr-screening.md` |
| Cyber Threat Intelligence | Security analysts tracking adversaries | `wf-threat-analyst.md` |
| Private Investigator | Licensed PIs running person cases | `wf-private-investigator.md` |

Activate via `/flow [type]` — interactive guided prompts walk through each step.

---

## 8. Output Formats

Reference: `output/reports/`, `connectors/`

### Mandatory File Export (CRITICAL)

**Every `/report`, `/brief`, and `/case` command MUST auto-save the default export set to disk at the end of delivery:**

| # | Format | File | Role |
|---|--------|------|------|
| 1 | **Markdown** | `CTI-REPORT-[CASE-ID]-[YYYY-MM-DD].md` | Diffable, greppable source of truth; also the input to the HTML/DOCX generators |
| 2 | **Interactive HTML** | `CTI-REPORT-[CASE-ID]-[YYYY-MM-DD].html` | **Primary human-facing deliverable** — self-contained, OFFLINE; charts + 2D entity graph + topology + timeline + indicator panel + search |
| 3 | **JSON** | `CTI-REPORT-[CASE-ID]-[YYYY-MM-DD].json` | Structured case data (the report JSON below); feeds the generators and downstream tooling |
| 4 | **CSV** | `CTI-REPORT-[CASE-ID]-[YYYY-MM-DD].csv` | Findings (and indicators, via the IOC export) for spreadsheets / SIEM lookups |
| 5 | **IOC / selector bundle** | `IOC-[CASE-ID]-[YYYY-MM-DD].{stix.json,txt,csv}` | Comprehensive indicators & selectors — STIX 2.1 + flat + CSV |

**Save location:** Current working directory, or `./osint-reports/` subdirectory if it exists.

- **`--yolo`:** save the five-format default set with no prompt.
- **Interactive mode:** save the default set, then ask the user at the end whether they also want **DOCX** (Word) or **PDF**.
- **DOCX is NOT in the default set** (heaviest, most failure-prone toolchain). Generate it on request (`/report docx`) or automatically for `/report legal` (evidentiary, where a fixed Word/PDF artifact is expected). HTML **"Print → Save as PDF"** covers most PDF needs for free.
- Explicit machine-format subcommands always emit that format directly: `/report json`, `/report csv`, `/report ioc`.

**The HTML, JSON, CSV and IOC outputs all derive from one `report JSON`.** Build it once, then run the generators below.

**Step 1 — Build the report JSON file.** The generators expect a SPECIFIC flat format (NOT the engine case-schema.json). You MUST construct the JSON matching this exact structure before calling the scripts. Reference: `scripts/sample-cti-report-data.json`.

```json
{
  "case": {
    "id": "CTI-2026-001",          // string, case identifier
    "label": "Case Title",         // string, human-readable name
    "classification": "OPEN SOURCE", // string
    "analyst": "AI-Assisted CTI",  // string
    "date": "2026-04-08",          // ISO date
    "subject": "target.com",       // string, primary subject
    "status": "active",            // string
    "exposure_score": 72           // integer 0-100 (optional, enables risk gauge)
  },
  "executive_summary": "Full paragraph summarizing investigation findings...",
  "subjects": [
    {
      "id": "SUB-001",            // string ID (not UUID)
      "label": "target.com",      // human-readable name — REQUIRED for display
      "type": "domain",           // lowercase: domain, person, ip, organization, email, username
      "confidence": 95,           // INTEGER 0-100 (not string like "VERIFIED")
      "verified": true,           // boolean
      "aliases": ["alias1"],      // string array
      "first_seen": "2025-01-15", // ISO date string
      "notes": "Primary domain"   // string
    }
  ],
  "findings": [
    {
      "id": "FND-001",            // string ID
      "subject_id": "SUB-001",    // links to subject
      "type": "infrastructure",   // credential, infrastructure, identity, exposure, behavioral, legal
      "weight": "HIGH",           // CRITICAL, HIGH, MEDIUM, LOW, INFO — drives severity colors
      "description": "Full description of the finding...",
      "source_url": "https://...",
      "collected_at": "2026-04-08T10:00:00Z",
      "confidence": 88,           // INTEGER 0-100 (not string)
      "tags": ["tag1", "tag2"]
    }
  ],
  "connections": [
    {
      "id": "CON-001",
      "from_id": "SUB-001",       // subject ID
      "to_id": "SUB-002",         // subject ID
      "relationship": "owns",     // string describing relationship
      "strength": "confirmed"     // confirmed, probable, possible
    }
  ],
  "timeline": [
    {"date": "2025-01-15", "event": "Domain registered"}
  ],
  "sources": [
    {"name": "Source Name", "url": "https://...", "date": "2026-04-08"}
  ],
  "intelligence_gaps": [
    "Gap description string"
  ],
  "recommendations": [
    "Action item string"
  ],
  "visitor_stats": {              // optional — enables visitor intelligence charts
    "domain": "target.com",
    "monthly_visits": 150000,
    "traffic_sources": {"direct": 42, "search": 28, "referral": 15, "social": 10, "paid": 5},
    "top_countries": [{"country": "Vietnam", "share": 60}, {"country": "US", "share": 20}]
  },
  "caveats": ["Caveat string"]   // optional — overrides default methodology notes
}
```

**CRITICAL FORMAT RULES:**
- `confidence` on subjects and findings MUST be an **integer** (e.g., `85`), NOT a string (e.g., `"VERIFIED"`)
- `findings` MUST be a **flat top-level array**, NOT nested inside subjects
- `label` is REQUIRED on each subject (this is what displays in the report — not `value` or `display_name`)
- `weight` on findings drives severity coloring — use CRITICAL/HIGH/MEDIUM/LOW/INFO
- `recommendations` must be an array of **strings** (not objects with `priority`/`action` keys)
- All fields shown above should be **populated with actual data** — empty strings or "N/A" defeat the purpose
- Populate `executive_summary` with a full paragraph — this is the most-read section of the report

**Optional enrichment fields (backward-compatible — used by the HTML report & IOC export when present):**
- `subjects[].role` — `actor` | `victim` | `infrastructure` | `associate` | `witness` (drives the role chips and actor↔victim attribution; otherwise inferred from type/links)
- `subjects[].selectors[]` — contact/social points attached to a person/org: `{type, value, platform, url}` (e.g. a victim's phone, an actor's Telegram or LinkedIn) — surfaced in the Indicators panel and IOC export
- `indicators[]` — analyst-curated indicators to force into the export verbatim: `{type, value, category, role, confidence, source_url}`

**Step 2 — Generate the interactive HTML report (PRIMARY human-facing deliverable).** Self-contained, OFFLINE, zero toolchain to view — opens in any browser:
```bash
S="$SKILL_DIR/scripts"     # $SKILL_DIR = dir containing SKILL.md
uv run "$S/generate-cti-html.py" "REPORT.json" "REPORT.html"   # any OS, zero setup
# no uv installed: python3 "$S/generate-cti-html.py" "REPORT.json" "REPORT.html"   (Windows: py …)
```
It injects the report JSON into `cti-report-template.html` and renders, entirely client-side and offline (no CDN, no network calls): KPI cards, an exposure gauge, a finding-type pie, severity bars, a draggable/zoomable **2D entity graph**, **infrastructure topology**, an **event timeline**, and the **comprehensive Indicators & Selectors panel** (network IOCs + contacts + identities + social/messaging handles + wallets + actor↔victim attribution) — with global search, category menus, dark/light themes and a print-to-PDF stylesheet.

**Step 3 — Generate the comprehensive IOC / selector bundle.**
```bash
uv run "$S/generate-cti-iocs.py" "REPORT.json" "IOC-[CASE-ID]-[YYYY-MM-DD]" --format all
# single format: --format stix | flat | csv
```
Extracts EVERY indicator that profiles or can reach an actor/victim — network IOCs, emails/phones, usernames/names/aliases, social-media profiles, messaging handles, crypto wallets, and the attribution links between subjects. Full spec: [`techniques/ioc-export.md`](techniques/ioc-export.md).

**Step 4 — DOCX (on request, or automatically for `/report legal`).** Word is no longer auto-generated by default. When the user asks for it (or for evidentiary reports), build it from the SAME report JSON + MD. The generators carry **PEP 723 inline dependency metadata**, so the simplest, most portable runner is **`uv run`** — it provisions the deps on the fly with zero venv/pip setup, identically on every OS. The generator is also **self-healing**: it forces UTF-8 output and auto-locates pandoc (including Windows `%LOCALAPPDATA%\Pandoc`), so **no `PYTHONUTF8` / PATH prelude is needed**. Replace `REPORT` with `CTI-REPORT-[CASE-ID]-[YYYY-MM-DD]`.

**Preferred — `uv run` (any OS, any agent, zero setup):**
```bash
S="$SKILL_DIR/scripts"     # $SKILL_DIR = dir containing SKILL.md (Claude Code: ~/.claude/skills/cti-expert; Codex/clone: the repo)
# Primary: HYBRID — full narrative from MD + charts/diagrams from JSON (zero content loss)
uv run "$S/generate-cti-docx-hybrid.py" "REPORT.md" "REPORT.json" "REPORT.docx"
# Fallback 1: JSON-only (charts + structured data; no pandoc needed)
uv run "$S/generate-cti-docx.py" "REPORT.json" "REPORT.docx"
# Fallback 2: MD-only (styled narrative, no charts)
uv run "$S/generate-cti-docx-hybrid.py" "REPORT.md" "REPORT.docx"
```
> Windows PowerShell: set `$S = "$env:USERPROFILE\.claude\skills\cti-expert\scripts"` (Claude Code) or `"<repo>\scripts"` (Codex/clone), and use backslash paths.

**Fallback — no uv installed.** Use the OS interpreter; the script's `ensure_deps()` installs the libs on first run (via uv if present, else pip):
- macOS / Linux (Bash): `python3 "$S/generate-cti-docx-hybrid.py" "REPORT.md" "REPORT.json" "REPORT.docx"`
- Windows (PowerShell): `py "$S\generate-cti-docx-hybrid.py" "REPORT.md" "REPORT.json" "REPORT.docx"` — the Store `python3` stub will not run; use `py` or the venv python
- Last resort (no styling/charts): `pandoc "REPORT.md" -o "REPORT.docx" --from markdown --to docx --standalone`

**How the hybrid generator works:**
1. **Phase 1:** pandoc converts the MD file to a base DOCX (preserving ALL narrative content — tables, lists, formatting)
2. **Phase 2:** python-docx post-processes to add CTI professional styling, prepend cover page + TOC, and inject charts/diagrams from JSON at matching section headings

**The MD file is the primary content source.** It carries the full narrative (detailed person profiles, infrastructure tables, wallet addresses, corporate structure, legal history, etc.). The JSON file provides structured data for visual elements (charts, diagrams, risk gauge). Using both together produces a complete report with zero content loss.

**Rich hybrid DOCX includes:** Cover page titled "CTI REPORT", table of contents, **all narrative content from MD** (every paragraph, table, list, code block), pie chart (finding types), bar chart (severity), risk gauge (exposure score), timeline chart, entity relationship diagram, network topology diagram, traffic/geo charts, CTI-themed styling (navy headings, styled tables), header/footer with classification and page numbers.

**After saving, confirm all files to the user:**
```
📄 Report saved (default export set):
   → CTI-REPORT-CASE001-2026-03-30.md
   → CTI-REPORT-CASE001-2026-03-30.html   (interactive — open in any browser, fully offline)
   → CTI-REPORT-CASE001-2026-03-30.json
   → CTI-REPORT-CASE001-2026-03-30.csv
   → IOC-CASE001-2026-03-30.stix.json / .txt / .csv   (indicators & selectors)

   Need a Word (.docx) or PDF too? (PDF = open the .html and Print → Save as PDF)
```

### Report Formats

| Format | Command | Audience |
|--------|---------|---------|
| Interactive HTML | `/report` (default) · `/report html` | Everyone — analysts to execs; the primary deliverable |
| Technical INTSUM | `/report` | Analysts, security teams |
| Executive Brief | `/report brief` | Decision-makers, management |
| Plain-Language Summary | `/brief` | Non-technical stakeholders |
| Legal Evidence Format | `/report legal` | Attorneys, compliance teams (auto-adds DOCX/PDF) |
| Journalist Format | `/report journalist` | Reporters, media |
| JSON Export | `/report json` | Downstream tools, pipelines |
| CSV Export | `/report csv` | Spreadsheets, databases |
| IOC / selector bundle | `/report ioc` | SIEM/TIP ingest, threat-intel sharing |
| Word document | `/report docx` | Formal sharing (on request) |

Every narrative report auto-saves the **default export set** (.md + .html + .json + .csv + IOC bundle — see Mandatory File Export above). `/report legal` additionally produces DOCX/PDF. Machine-only subcommands (`json`, `csv`, `ioc`) emit their native format directly.

### Visual Outputs

| Type | Command | Format |
|------|---------|--------|
| Subject relationship map | `/render entities` | **ASCII** (default) — `--mermaid` for Mermaid |
| Chronological timeline | `/render timeline` | **ASCII** Gantt |
| Exposure heatmap | `/render risk` | **ASCII** |
| Network topology | `/render network` | **ASCII** |

**All visual outputs use ASCII box-drawing by default.** Mermaid only on explicit `--mermaid` flag.

**Diagram tradecraft:** [`output/visuals/diagram-patterns.md`](output/visuals/diagram-patterns.md) — compile-check a Mermaid diagram before presenting it, and pick the right diagram type per CTI question (attack → sequence, lifecycle → state, handoffs → swimlane, infra → graph).

The **interactive HTML report** (default deliverable) renders all of these as live, explorable visuals — a draggable/zoomable 2D force-directed entity graph, infrastructure topology, an event timeline, and SVG charts (pie/bar/gauge/donut) — alongside the ASCII versions in the `.md`.

### Connectors

| Tool | File | What It Exports |
|------|------|----------------|
| Maltego | `connectors/maltego-export.md` | GraphML entity graph |
| Obsidian | `connectors/obsidian-setup.md` | Linked markdown notes |
| Notion | `connectors/notion-schema.md` | Structured database |

---

## 9. Skill Tiers & Customization

Reference: `experience/skill-tiers.md`, `experience/layered-detail.md`

### Tiers

| Tier | Command | What Changes |
|------|---------|-------------|
| **Novice** | `/novice` | Jargon removed, steps explained, glossary auto-linked |
| **Practitioner** | (default) | Standard output, moderate detail |
| **Specialist** | `/novice off` | Full technical detail, raw findings, internal signals |

Switch tiers at any point — output adapts immediately.

### Guided Flows

`experience/guided-flows/` contains step-by-step interactive flows:

- `person-investigation.md` — Full guided person case
- `domain-reconnaissance.md` — Guided domain sweep
- `email-investigation.md` — Guided email tracing
- `rapid-case.md` — 10-minute abbreviated sweep

Activate: `/flow person` · `/flow domain` · `/flow email` · `/flow quick`

### Case Templates

`experience/case-templates/` contains pre-built starting configurations:

- `due-diligence.md` — Corporate partner vetting
- `security-audit.md` — Organization exposure audit
- `background-check.md` — Individual background research

Activate: `/template run [name]`

---

## 10. Ethics & Boundaries

This skill operates strictly within publicly available information.

### Permitted

- Journalists verifying facts about public figures or institutions
- Security professionals auditing their own organization's exposure
- Individuals reviewing their own digital footprint
- Corporate due diligence on business partners
- Academic research and educational demonstrations

### Prohibited

- Stalking, harassment, or doxing of any individual
- Accessing accounts or systems without authorization
- Social engineering or deception campaigns
- Any activity violating applicable law

Ethical reminders are issued automatically when the investigation approaches sensitive territory. Public data is not a license to cause harm.

---

## 11. Autonomous Mode (--yolo)

Append `--yolo` to any command or activate at session start.

**What changes:**
- No clarifying questions — analyst infers context and proceeds
- No confirmation prompts — scope expands automatically on new discoveries
- Guided flows skip Q&A — reasonable defaults applied
- Both `/report` and `/brief` generated without asking

**What stays the same:**
- Ethics and legal boundaries — always enforced
- Trust scores on every finding
- Source citations on every claim
- `/validate` and `/coverage` run before final delivery

Activate per-command: `/case target.com --yolo`
Activate for session: `/cti-expert --yolo`

---

## 12. Architecture Reference

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
│   ├── fx-edge-appliance-recon.md Edge/VPN appliance fingerprint → KEV/CVE catalog + port-risk matrix
│   ├── fx-saas-identity-recon.md SaaS tenancy + IdP fingerprint + API/GraphQL/spec discovery
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
│   ├── cti-report-template.html     PRIMARY: interactive HTML report template — self-contained & OFFLINE (charts + 2D entity graph + topology + timeline + indicator panel + search; dark/light + print-to-PDF)
│   ├── generate-cti-html.py         HTML report generator — injects the report JSON into the template (PEP 723 / `uv run`, zero-dep, self-heals UTF-8)
│   ├── generate-cti-iocs.py         Comprehensive IOC/selector exporter → STIX 2.1 / flat / CSV (network IOCs + contacts + identities + social/messaging + wallets + attribution; PEP 723 / `uv run`, zero-dep)
│   ├── generate-cti-docx-hybrid.py  Hybrid MD+JSON DOCX generator — on request / `/report legal` (PEP 723 / `uv run`; self-heals UTF-8 + pandoc)
│   ├── generate-cti-docx.py         Fallback: JSON-only generator (PEP 723 / `uv run`)
│   ├── cti_docx_postprocess.py      Post-processing: styling, chart injection, cover page
│   ├── cti_docx_charts.py           Chart rendering (pie, bar, gauge, timeline, traffic, geo)
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
│   └── wf-private-investigator.md
│
├── handbook/                   Reference material
│   ├── operator-queries.md     Search operator catalog
│   ├── quick-report.md         Rapid reporting reference
│   ├── discovery-paths.md      Per-target-type search paths
│   ├── report-template.md      INTSUM format specification
│   ├── admin-endpoint-indicators.md  Admin-panel / sensitive-endpoint detection vocab & rules
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
    └── notion-schema.md
```

---

## Technique Activation Matrix

Which techniques activate per target type in a `/case` run:

| Technique | Person | Domain | Org | Username | Email | IP |
|-----------|--------|--------|-----|----------|-------|----|
| `/sweep` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `/query` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `/username` | ✅ | — | ✅* | ✅ | — | — |
| `/email-deep` | ✅ | — | ✅* | — | ✅ | — |
| `/phone` | ✅ | — | ✅* | — | — | — |
| `/breach-deep` (LeakCheck + HudsonRock) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `/subdomain` | — | ✅ | ✅ | — | — | — |
| `/traffic` | — | ✅ | ✅ | — | — | — |
| `/threat-check` | — | ✅ | ✅ | — | — | ✅ |
| `/secrets` | — | ✅ | ✅ | ✅ | — | — |
| `/github-osint` | ✅* | ✅ | ✅ | ✅ | ✅* | — |
| `/scam-check` | — | ✅ | ✅ | — | — | — |
| `/branch` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `/gdoc` | — | ✅ | ✅ | — | — | — |
| `/sharelink` | ✅ | — | ✅ | ✅ | ✅ | — |
<!-- dork-integration:phase-05 start -->
| `/dork-sweep` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅* |
| `/docleak` | ✅ | ✅ | ✅ | ✅* | — | — |
<!-- dork-integration:phase-05 end -->
| Social media platforms | ✅ | — | ✅ | ✅ | — | — |
| Metadata forensics | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Photo verification | ✅ | — | ✅* | ✅ | — | — |
| Network analysis | — | ✅ | ✅ | — | — | ✅ |
| Advanced geolocation | ✅ | — | — | ✅ | — | — |
| Web & DNS forensics | — | ✅ | ✅ | — | ✅ | ✅ |
| `/timeline` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `/exposure` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `/threat-model` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `/wifi` (SSID/BSSID) | ✅ | ✅ | ✅ | — | — | ✅ |
| Visitor intelligence | — | ✅ | ✅ | — | — | ✅ |
| Cloud audit | — | ✅ | ✅ | — | — | ✅ |
| MSFTRecon (M365/Azure tenant) | — | ✅ | ✅ | — | — | — |
| Dependency audit | — | ✅ | ✅ | — | — | — |
| Disk forensics | — | — | — | — | — | — |
| Incident triage | — | ✅ | ✅ | — | — | ✅ |
| OWASP audit | — | ✅ | ✅ | — | — | — |
| Prompt injection audit | — | ✅ | ✅ | — | — | — |
| `/snapshots` | — | ✅ | ✅ | — | — | ✅ |
| Archive IOC harvest (`wayback_harvest.py`) | — | ✅ | ✅ | — | — | — |
| `/diff` | — | ✅ | ✅ | — | — | ✅ |
| `/drift` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `/render threat-path` | — | ✅ | ✅ | — | — | ✅ |
| `/render attack-surface` | — | ✅ | ✅ | — | — | ✅ |
| `/blind-spots` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `/source-check` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `/report ioc` | — | ✅ | ✅ | — | — | ✅ |
| `/report` + `/brief` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Shodan InternetDB (ports/tags/vulns) | — | ✅ | ✅ | — | — | ✅ |
| GreyNoise Community (noise/threat class) | — | ✅ | ✅ | — | — | ✅ |
| URLScan.io passive (scan history) | — | ✅ | ✅ | — | — | — |
| Disposable email check (kickbox) | ✅ | — | ✅* | — | ✅ | — |
| URLhaus (malware URL hosting) | — | ✅ | ✅ | — | — | ✅ |
| ThreatFox (IOC/C2 lookup) | — | ✅ | ✅ | — | — | ✅ |
| MalwareBazaar (hash → malware family) | — | — | — | — | — | — |
| ipwho.is (geo + ASN + ISP) | — | ✅ | ✅ | — | — | ✅ |
| DMARC/SPF/DKIM check (DNS) | — | ✅ | ✅ | — | ✅ | — |

`✅*` — runs for discovered key personnel within the organization
`MalwareBazaar` — activates only via `/hash [value]` when a file hash is discovered during investigation

**Recursive pivot orchestration (the spider-map).** `/case` is not a one-pass collector —
it runs a **recursive BFS pivot engine**: every discovered identifier becomes a new seed,
and the relationship graph expands **hop by hop until the frontier is exhausted** or a
budget cap is hit. The state machine — identifier typing, dedup / cycle prevention,
per-node depth, the identifier→pivot **edge matrix**, confidence gating, and per-depth
checkpoints — is [`scripts/pivot_orchestrator.py`](scripts/pivot_orchestrator.py); the full
spec is [`engine/pivot-orchestration.md`](engine/pivot-orchestration.md). The orchestrator
**plans and tracks**; the agent **executes** each hop's technique commands and feeds results
back via `--ingest`.

- **Defaults:** `posture=active` (may fetch/scan targets; still passive-first for hostile
  infra), `reach=exhaustive` (pivot till the frontier empties), `autonomy=checkpoint`
  (**pause after each depth level**, present new nodes + proposed pivots, await approval).
  Safety caps: `max_nodes=500`, `max_depth=6`.
- **Gating** (reuses [`analysis/auto-branch-rules.md`](analysis/auto-branch-rules.md)):
  exact-match links (≥95% — shared GA ID / cert / favicon / registrant email, handle
  exact-match) **auto-pursue unbounded**; HIGH/MEDIUM capped per type; LOW held unless
  corroborated; PII (`person`/`phone`) held unless `--authorization confirmed`; visited
  nodes and past-depth-cap nodes suppressed (loop-safe).
- **Example hops:** an **email** auto-pivots via reverse-WHOIS→domains, `/breach-deep`,
  `/github-osint`; a **domain** discovered from a person (high-confidence link) continues
  via `/webpivot`+`wayback_harvest`+`whois_enrich`+`cert_pivot`+subdomains; a shared **GA ID**
  reverse-pivots to sibling domains — each new node re-enters the loop.
- **Control flags:** `/case <t> --passive|--passive-first`, `--reach balanced|focused`,
  `--auto` (no checkpoints, run to closure), `--depth N`, `--budget N`, `--authorization confirmed`.
- **Termination** → emit edges → `graph_build.py` → interactive HTML force-graph + topology
  + timeline; findings/indicators roll into the auto-saved report + IOC bundle.

Legacy one-hop note (still true, now a subset of the loop): if `/sweep` on a domain finds an
email, `/email-deep` and `/breach-deep` trigger on it automatically.

**GitHub OSINT auto-fire in `/case`:**
- Domain/Org target → run `/github-osint` on the org name, primary domain, discovered GitHub orgs/repos, and developer-platform hits from `/query` or `/dork-sweep`.
- Username target → run `/github-osint` directly when the handle has a GitHub profile or GitHub search hit.
- Person target → run `/github-osint` only after discovering a likely GitHub handle, commit email, repo author, or developer profile link.
- Email target → run `/github-osint` only after discovering commit attribution, GitHub noreply patterns, profile links, or repo references.
- Results feed into `/secrets`, `/branch`, `/timeline`, `/crossref`, `/exposure`, and final `/report` automatically.

<!-- dork-integration:phase-05 start -->
**`✅*` dork coverage notes:** `/dork-sweep` on IP runs against reverse-DNS hostname once resolved (graceful skip if no rDNS); `/docleak` on Username targets document-author/uploader fields on scribd, slideshare, academia.edu, researchgate.

**Dork auto-fire matrix — every `/case` target type gains coverage:**
- Person → `/dork-sweep --telegram --docs` + `/docleak` on full name
- Domain → `/dork-sweep --filetype --docs` + `/docleak` on domain + org name
- Org → `/dork-sweep --filetype --docs --telegram` + `/docleak` on org + primary domain
- Username → `/dork-sweep --telegram --docs` + `/docleak` (author-angle)
- Email → `/dork-sweep --telegram --docs` on email + `@domain`
- IP → `/dork-sweep` on rDNS-resolved hostname (skipped if no rDNS)

Adaptive fan-out: discovered emails → Telegram dork; discovered personnel → `/docleak`; discovered subdomains → filetype dork; discovered usernames → Telegram + doc sweep; discovered IPs → rDNS → dork-sweep.
<!-- dork-integration:phase-05 end -->

When `/case` or `/sweep` runs on a Domain or Org target, it inspects the MX record and SPF TXT record. If MX ends in `protection.outlook.com` OR SPF contains `spf.protection.outlook.com`, `/msftrecon` auto-fires as part of the Acquire phase. Results feed back into the subject registry as `infrastructure` findings (tenant ID, federation type, MDI presence) and into `/exposure` scoring.

**`/case` pipeline walkthrough (M365-hosted Domain/Org):** (a) standard DNS/WHOIS/subdomain/traffic/scam-check/breach-deep checks run first, (b) if M365 indicators present → `/msftrecon` fires automatically with no extra flag, (c) tenant ID discovered becomes a pivot for `/branch` in Enrich phase (search other domains under the same tenant). No user intervention required.

**Parallel enrichment (3+ subjects):** When Acquire discovers 3+ subjects, enrichment commands fan out in parallel via AgentFlow DAG orchestration. Each subject's enrichment runs independently, results merge with dedup before Assess phase. Disable with `--sequential` flag. See `techniques/agentflow-enrichment.md`.

---

## Exposure Score Bands

| Range | Label | Action |
|-------|-------|--------|
| 0–25 | Minimal | Passive monitoring sufficient |
| 26–50 | Moderate | Periodic review advised |
| 51–75 | Elevated | Address within 30 days |
| 76–100 | Critical | Immediate escalation required |

---

## Tool Priority & Fallback

**Primary interactive collector: [`agent-browser`](https://github.com/vercel-labs/agent-browser)** (vercel-labs) — a fast native-Rust CDP browser that returns accessibility-tree snapshots (`@eN` element refs) + screenshots; **no API key** for core automation; cross-platform; also an MCP server. Full how-to + per-command usage in [`techniques/agent-browser.md`](techniques/agent-browser.md). It is **complementary to Scrapling, not in conflict** (different ecosystems — Rust binary via npm/brew/cargo vs Python via pip — each manages its own browser): use **agent-browser to *interact with and witness* a page** (logins, clicks, screenshots, JS render) and **Scrapling to *fetch and parse* pages programmatically**.

1. Check `agent-browser` first (`agent-browser --version`; load its guide via `agent-browser skills get core`; install per the auto-install policy if missing)
2. Use `agent-browser` for: screenshot evidence, logins/interactive UI, JS-rendered/SPA pages, complex multi-step browser flows
3. Use Scrapling DynamicFetcher for: JS-heavy sites, SPA content, auto-escalation from static (programmatic)
4. Use Scrapling StealthyFetcher for: anti-bot bypass, Cloudflare-protected targets
5. Use Scrapling Fetcher for: fast static page collection, HTML parsing (~2ms)
6. Fall back to web search → web fetch → direct curl — no investigation blockers
7. Tag each finding with collection method: `[browser]` · `[scrapling-dynamic]` · `[scrapling-stealth]` · `[scrapling-static]` · `[search]` · `[fetch]` · `[manual]` · `[whois-lib]` · `[whois-cli]` · `[whois-api]`

---

## Tool Auto-Install Policy

**Before running any CLI tool, detect the OS, check whether the tool exists, and if not, install it automatically and silently using the method correct for that OS.** This ensures zero-friction investigation on Windows, macOS, and Linux alike — the analyst never stalls on a missing dependency and never runs a Linux-only command on Windows.

> **Full cross-platform reference:** [`scripts/platform-setup.md`](scripts/platform-setup.md) — OS detection, `$PY`/shell conventions, package managers, the complete per-tool × per-OS install matrix, and known gotchas. Consult it whenever this summary is not enough.

### Step 0 — Detect the platform (once per session)

Determine the OS before running anything, and cache it for the rest of the session. In Claude Code the environment block already reports it (e.g. `Platform: win32` → Windows). Otherwise probe: PowerShell `$IsWindows`/`$IsMacOS`, or Bash `uname -s` (`Darwin`=macOS, `Linux`=Linux, `MINGW*`/`MSYS*`/`CYGWIN*`=Windows/Git Bash). Then fix these conventions:

| | Windows | macOS / Linux |
|--|---------|---------------|
| **Shell** | PowerShell | Bash |
| **Python runner** (`$PY`) | **`uv run`** (preferred) · else venv `…\.venv\Scripts\python.exe` · else **`py`** | **`uv run`** (preferred) · else venv `…/.venv/bin/python3` · else **`python3`** |
| **"exists?" check** | `Get-Command <tool> -ErrorAction SilentlyContinue` (or `where.exe <tool>`) | `command -v <tool>` |
| **System pkg manager** | `winget` (→ `choco`/`scoop`) | `brew` (macOS) · `sudo apt`/`dnf`/`pacman` (Linux) |

> On Windows, `python3`/`python` in the Bash tool is often a non-functional Microsoft Store stub. Prefer **uv** (it brings its own Python and sidesteps the stub); otherwise use `py` via PowerShell.

### Step 0.5 — Ensure uv (the primary Python toolchain)

**[uv](https://docs.astral.sh/uv/) is the preferred way to install and run everything Python in this skill.** It is a single fast, cross-platform tool that replaces `pip`, `pipx`, `venv`, and `pyenv`, manages its own Python (so the Windows Store-stub problem disappears), and resolves script dependencies on the fly. Using uv also **collapses the per-OS split for Python tools** — the same command works on Windows, macOS, and Linux.

- **Check:** `uv --version`
- **Install if missing:**
  - Windows: `winget install --id astral-sh.uv` — or `powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"`
  - macOS / Linux: `curl -LsSf https://astral.sh/uv/install.sh | sh` — or `brew install uv`
  - Any OS that already has pip: `python -m pip install uv`

If uv genuinely cannot be installed, fall back to the per-OS `pip`/`pipx`/`venv` path — nothing here hard-requires uv.

### Auto-Install Protocol

1. **Check:** OS-correct existence test from the table above (or `<$PY> -c "import <module>"` for Python modules)
2. **Install:** If missing, run the OS-correct install command (see dispatch below / `platform-setup.md`)
3. **Verify:** Confirm the tool resolves before proceeding — re-check; on Windows a fresh install may need a new shell or a probe of its install dir
4. **Log:** Note `[auto-installed]` in the finding's collection method tag
5. **Continue:** Proceed with the investigation — never block on tool availability

### Install Dispatch by Category

**Python tools — uv, identical on every OS** (the big win: no per-OS split). CLIs use `uv tool`; libraries go into the skill venv via `uv pip`. No-uv fallback in the last column.

| Python tool(s) | Install (any OS, uv) | No-uv fallback |
|----------------|----------------------|----------------|
| CLIs — maigret, sherlock-project, holehe, h8mail, theHarvester, trufflehog, waymore, xeuledoc | `uv tool install <pkg>` | `pipx install <pkg>` |
| Libraries — cloudscraper, oletools, whoisdomain, scrapling | `uv pip install --python <venv> <pkg>` | `<$PY> -m pip install <pkg>` |
| Scrapling headless | `uv tool install "scrapling[fetchers]"` then `scrapling install` | `<$PY> -m pip install "scrapling[fetchers]"` then `scrapling install` |
| AgentFlow | `uv pip install --python <venv> --no-deps agentflow` | `<$PY> -m pip install --no-deps agentflow` |
| Git-only — msftrecon, blackbird, sharetrace | `uv pip install "git+https://…/msftrecon.git"` · clone + `uv pip install -r requirements.txt` | clone + `<$PY> -m pip install -r requirements.txt` |
| **Run a generator script** | `uv run <script.py> ARGS` (deps auto via inline metadata) | `<$PY> <script.py> ARGS` |

`<$PY>` = `py` (Windows) / `python3` (macOS/Linux), or the venv python. On PEP-668 Linux add `--break-system-packages` to the pip fallback.

**System binaries — OS package manager** (uv does not manage these):

| Tool(s) | Windows | macOS | Linux |
|---------|---------|-------|-------|
| git, gh, jq, exiftool, pandoc, poppler/pdfinfo, qpdf, whois | `winget install <Id>` | `brew install <pkg>` | `sudo apt install -y <pkg>` |
| Go toolchain | `winget install GoLang.Go` | `brew install go` | `sudo apt install -y golang` |
| mat2 (metadata strip) | n/a → `exiftool -all= -overwrite_original <file>` | `brew install mat2` | `sudo apt install -y mat2` |
| **agent-browser** (interactive browser) | `npm i -g agent-browser` or `cargo install agent-browser` → `agent-browser install` | `brew install agent-browser` → `agent-browser install` | `npm i -g agent-browser` (or `cargo install`) → `agent-browser install` |

**Go tools** (after Go is present — identical on all OSes): `go install <module>` for subfinder, amass, gau, gitleaks, httpx. PhoneInfoga → GitHub release binary per OS/arch. **ASN** → Git Bash/WSL `bash <(curl -sL …/nitefood/asn/master/asn)` on Windows, native bash on macOS/Linux, or RDAP/ipwho.is HTTP fallback.

The exact winget IDs, brew formulae, apt packages, uv commands, import names, and Go module paths for **every** tool are tabulated in [`scripts/platform-setup.md`](scripts/platform-setup.md) §5. To provision a fresh machine in one shot, run the bundled installer for the detected OS:

- **Windows:** `powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\.claude\skills\cti-expert\scripts\install.ps1"`
- **macOS / Linux / Git Bash / WSL:** `bash ~/.claude/skills/cti-expert/scripts/install.sh`

(both accept `--headless`/`-Headless`, `--go`/`-Go`, `--all`/`-All`)

### Behavior Rules

- **uv first (anything Python):** prefer uv — `uv tool install` for CLIs, `uv pip install` for libraries, `uv run` for scripts. It behaves identically on every OS, so reach for it before per-OS pip/pipx. Fall back to `<$PY> -m pip` / `pipx` only when uv cannot be installed.
- **Detect before install (system binaries):** dispatch by the OS detected in Step 0 — never run `apt` on Windows or `winget` on Linux.
- **Silent install:** do not ask permission — install and proceed. Tool installation is a normal part of the investigation workflow.
- **Go tools:** require Go installed. If `go` is missing, install it via the OS package manager (`winget install GoLang.Go` / `brew install go` / `sudo apt install -y golang`), or note the gap and fall back to the next tool in the cascade.
- **Linux privileges:** system installs need `sudo` unless running as root.
- **Windows specifics:** `winget` may prompt UAC; a freshly installed tool may not be on PATH until the shell is reopened (probe its install dir or restart the shell before declaring failure). The DOCX generator self-heals UTF-8 output and pandoc location — see `platform-setup.md` §6.
- **Git-based install:** for tools without a PyPI package (msftrecon, blackbird, sharetrace), clone the repo and install its `requirements.txt` with `<$PY> -m pip install -r requirements.txt`.
- **Fallback on install failure:** if installation fails, log a collection gap and skip to the next tool in the cascade — never block the investigation.
