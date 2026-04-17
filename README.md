<div align="center">

# CTI Expert

### Cyber Threat Intelligence & OSINT Analysis Toolkit

**Transform Claude into a trained intelligence analyst — 67+ commands, 38 techniques, zero API keys required for core functionality.**

<br>

<p>
  <a href="#demo">View Demo</a>&nbsp;&nbsp;|&nbsp;&nbsp;<a href="#quick-start">Quick Start</a>&nbsp;&nbsp;|&nbsp;&nbsp;<a href="#command-reference">Commands</a>&nbsp;&nbsp;|&nbsp;&nbsp;<a href="#contributing">Contribute</a>
</p>

<br>

<!-- Feature Badges -->
<p>
  <a href="https://github.com/7onez/cti-expert"><img src="https://img.shields.io/badge/version-2.3-0080ff?style=for-the-badge&logo=semver&logoColor=white" alt="Version 2.3"></a>&nbsp;
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-00c853?style=for-the-badge&logo=opensourceinitiative&logoColor=white" alt="License: MIT"></a>&nbsp;
  <a href="#command-reference"><img src="https://img.shields.io/badge/commands-67+-ff6d00?style=for-the-badge&logo=windowsterminal&logoColor=white" alt="67+ Commands"></a>&nbsp;
  <a href="#technique-catalog"><img src="https://img.shields.io/badge/techniques-38-aa00ff?style=for-the-badge&logo=hackthebox&logoColor=white" alt="38 Techniques"></a>&nbsp;
  <a href="#installation"><img src="https://img.shields.io/badge/API_keys-none_for_core-00bfa5?style=for-the-badge&logo=shield&logoColor=white" alt="No API Keys for Core"></a>
</p>

<!-- GitHub Stats -->
<p>
  <a href="https://github.com/7onez/cti-expert/stargazers"><img src="https://img.shields.io/github/stars/7onez/cti-expert?style=flat-square&logo=github&label=Stars" alt="Stars"></a>&nbsp;
  <a href="https://github.com/7onez/cti-expert/network/members"><img src="https://img.shields.io/github/forks/7onez/cti-expert?style=flat-square&logo=github&label=Forks" alt="Forks"></a>&nbsp;
  <a href="https://github.com/7onez/cti-expert/releases"><img src="https://img.shields.io/github/downloads/7onez/cti-expert/total?style=flat-square&logo=github&label=Downloads&color=brightgreen" alt="Downloads"></a>&nbsp;
  <a href="https://github.com/7onez/cti-expert/issues"><img src="https://img.shields.io/github/issues/7onez/cti-expert?style=flat-square&logo=github&label=Issues" alt="Issues"></a>&nbsp;
  <a href="https://github.com/7onez/cti-expert/pulls"><img src="https://img.shields.io/github/issues-pr/7onez/cti-expert?style=flat-square&logo=github&label=PRs" alt="Pull Requests"></a>&nbsp;
  <a href="https://github.com/7onez/cti-expert/commits"><img src="https://img.shields.io/github/last-commit/7onez/cti-expert?style=flat-square&logo=github&label=Last%20Commit" alt="Last Commit"></a>&nbsp;
  <a href="https://github.com/7onez/cti-expert"><img src="https://img.shields.io/github/repo-size/7onez/cti-expert?style=flat-square&logo=github&label=Size" alt="Repo Size"></a>&nbsp;
  <a href="https://github.com/7onez/cti-expert/graphs/contributors"><img src="https://img.shields.io/github/contributors/7onez/cti-expert?style=flat-square&logo=github&label=Contributors" alt="Contributors"></a>
</p>

<!-- Language Selector -->
<p>
  <a href="#what-is-cti-expert"><img src="https://img.shields.io/badge/lang-English-blue?style=flat-square" alt="English"></a>&nbsp;
  <a href="#vietnamese"><img src="https://img.shields.io/badge/lang-Tiếng_Việt-red?style=flat-square" alt="Tiếng Việt"></a>&nbsp;
  <a href="#chinese"><img src="https://img.shields.io/badge/lang-中文-red?style=flat-square" alt="中文"></a>
</p>

<br>

<sub>Built by <a href="https://www.linkedin.com/in/hieu-minh-ngo-hieupc/"><b>Hieu Ngo</b></a> &bull; <a href="mailto:hieu.ngo@chongluadao.vn">hieu.ngo@chongluadao.vn</a> &bull; <a href="https://chongluadao.vn">chongluadao.vn</a></sub>

</div>

<br>

---

<br>

## What is CTI Expert?

A **Claude Code skill** that transforms Claude into a trained cyber threat intelligence and open-source intelligence analyst. It runs structured intelligence collection using **67+ commands** across **35 techniques** — no API keys required for core functionality. Some techniques offer optional enhanced access via free API keys (e.g., Wigle, VirusTotal, URLScan.io).

<table>
<tr>
<td width="50%">

**Core Capability**

Multi-vector reconnaissance on any target type — person, domain, organization, username, email, IP, WiFi — with automated finding validation, exposure scoring, and structured intelligence delivery.

</td>
<td width="50%">

**AEAD Workflow**

**A**cquire raw data &rarr; **E**nrich with pivot expansion &rarr; **A**ssess findings &rarr; **D**eliver structured reports (Markdown + Word with charts, diagrams, styled formatting).

</td>
</tr>
</table>

<br>

---

<br>

## Demo

### Full Case Investigation

<div align="center">
<img src="assets/demo-full-case.gif" alt="Full Case Demo — /case command running a complete investigation" width="800">
</div>

<br>

### CTI Report Generation

<div align="center">
<img src="assets/demo-cti-report.gif" alt="CTI Report Demo — Markdown + DOCX report output" width="800">
</div>

<br>

### Screenshots

<div align="center">

| INTSUM Report | Network Topology | Risk Assessment |
|:---:|:---:|:---:|
| <img src="assets/intsum.png" alt="INTSUM Report" width="280"> | <img src="assets/network-topology.png" alt="Network Topology Diagram" width="280"> | <img src="assets/risk-assessment.png" alt="Risk Assessment Score" width="280"> |

</div>

<br>

---

<br>

## What's New in v2.3

| Category | What's New | Details |
|----------|-----------|---------|
| **WHOIS** | Universal WHOIS for all TLDs | whoisdomain + CLI + Whoxy API; .vn, .th, .sg, .kr, 27+ ccTLD servers |
| **WHOIS** | Reverse & historical WHOIS (free) | Whoxy reverse API, historical lookup, ViewDNS |
| **Web Collection** | Scrapling adaptive scraping | 3-tier: static → anti-bot → JS rendering; headless auto-open |
| **Web Collection** | Headless browser auto-open default | JS-heavy sites auto-detected and rendered via DynamicFetcher |
| **Orchestration** | AgentFlow parallel enrichment | DAG-based parallel pivot expansion for 3+ subjects |
| **Performance** | HTML parsing ~2ms | Scrapling parser replaces slow HTTP scraping |
| **Platform** | Python 3.10+ minimum | Required by Scrapling and AgentFlow |

<details>
<summary><b>What's New in v2.2</b></summary>

## What's New in v2.2

| Category | What's New | Details |
|----------|-----------|---------|
| **Image Forensics** | Face search, reverse image, manipulation detection, AI geolocation | FaceCheck.id, TinEye, FotoForensics, Forensically, picarta.ai, GeoSpy, Pic2Map |
| **Blockchain** | Crypto wallet tracing, transaction graphs, scam detection | Blockchair, Etherscan, WalletExplorer, OXT.me, Chainabuse, Breadcrumbs |
| **Transport** | Aircraft tracking (unfiltered), vessel AIS, vehicle VIN lookup | ADS-B Exchange, Flightradar24, Marine Traffic, VesselFinder, NICB VINCheck |
| **Darknet** | Tor search, ransomware monitoring, onion service discovery | Ahmia.fi, onionsearch, DarknetLive, ransomwatch |
| **Social Media** | Reddit, Instagram, TikTok, Telegram investigation | Osintgram, instaloader, toutatis, RedditMetis, TGStat, TelegramDB, Bellingcat TikTok Timestamp |
| **People Search** | US people search engines, free reverse lookups | TruePeopleSearch, FastPeopleSearch, IDCrawl, That's Them |
| **Mega-Dorks** | 11 cross-platform Google dork templates covering 73 unique domains | Social, Telegram ecosystem, dev platforms, forums, paste sites, darknet, breach DBs, business, image, messaging, jobs |
| **IoT** | Webcam directories, IoT device search | Insecam, Thingful |

<details>
<summary><b>What's New in v2.1</b></summary>

| Category | New Commands | What It Does |
|----------|-------------|--------------|
| **Intelligence** | `/cti-expert /render threat-path`, `/cti-expert /render attack-surface` | Attack path flow + infrastructure exposure visualization |
| **Intelligence** | `/cti-expert /snapshots`, `/cti-expert /diff` | Wayback Machine snapshots and version diffing |
| **Intelligence** | `/cti-expert /drift`, `/cti-expert /report ioc` | Temporal risk tracking + IOC export (STIX 2.1) |
| **UX** | `/cti-expert /onboard`, `/cti-expert /clarify`, `/cti-expert /quality` | First-time tutorial, finding explanation, quality scoring |
| **UX** | `/cti-expert /blind-spots`, `/cti-expert /source-check` | Gap analysis + batch URL verification |
| **UX** | `/cti-expert /workspace diff` | Compare two saved investigation sessions |
| **Data Model** | Source Reliability A-F | Complements trust scores with source-level grading |
| **Data Model** | 4 new entity types | Device, Image, Crypto Address, Custom |
| **Data Model** | HIGH conflict severity | 4-level severity: CRITICAL/HIGH/NOTABLE/MINOR |

</details>

</details>

<br>

---

<br>

## Installation

### Quick Install (one command)

<table>
<tr>
<th>Platform</th>
<th>Command</th>
</tr>
<tr>
<td><b>Linux / macOS</b></td>
<td>

```bash
git clone https://github.com/7onez/cti-expert.git ~/.claude/skills/cti-expert && pip3 install -r ~/.claude/skills/cti-expert/scripts/requirements.txt
```

</td>
</tr>
<tr>
<td><b>Windows (PowerShell)</b></td>
<td>

```powershell
git clone https://github.com/7onez/cti-expert.git "$env:USERPROFILE\.claude\skills\cti-expert"; pip3 install -r "$env:USERPROFILE\.claude\skills\cti-expert\scripts\requirements.txt"
```

</td>
</tr>
<tr>
<td><b>Windows (CMD)</b></td>
<td>

```cmd
git clone https://github.com/7onez/cti-expert.git "%USERPROFILE%\.claude\skills\cti-expert" && pip3 install -r "%USERPROFILE%\.claude\skills\cti-expert\scripts\requirements.txt"
```

</td>
</tr>
</table>

---

### Option A &mdash; Claude Code CLI

> Install the CLI first: `npm install -g @anthropic-ai/claude-code` &mdash; [CLI docs](https://docs.anthropic.com/en/docs/claude-code/overview)

<details>
<summary><b>Linux / macOS</b></summary>

```bash
# Install Claude Code CLI
npm install -g @anthropic-ai/claude-code

# Clone skill + install dependencies
git clone https://github.com/7onez/cti-expert.git ~/.claude/skills/cti-expert
pip3 install -r ~/.claude/skills/cti-expert/scripts/requirements.txt

# Verify
ls ~/.claude/skills/cti-expert/SKILL.md
```

</details>

<details>
<summary><b>Windows (PowerShell)</b></summary>

```powershell
# Install Claude Code CLI
npm install -g @anthropic-ai/claude-code

# Clone skill + install dependencies
git clone https://github.com/7onez/cti-expert.git "$env:USERPROFILE\.claude\skills\cti-expert"
pip3 install -r "$env:USERPROFILE\.claude\skills\cti-expert\scripts\requirements.txt"

# Verify
Test-Path "$env:USERPROFILE\.claude\skills\cti-expert\SKILL.md"
```

</details>

---

### Option B &mdash; Claude Code Desktop (macOS / Windows)

> Download: [claude.ai/download](https://claude.ai/download) &mdash; available for **macOS** and **Windows**

**Step-by-step (no terminal needed):**

1. **Install Claude Code Desktop** &mdash; Download from [claude.ai/download](https://claude.ai/download) and install the app
2. **Download CTI Expert** &mdash; Go to the [GitHub repository](https://github.com/7onez/cti-expert), click the green **"Code"** button, then select **"Download ZIP"**
3. **Extract to your skills folder** &mdash; Unzip the downloaded file, then move the extracted folder to your skills directory and rename it to `cti-expert`:

   | Platform | How to navigate |
   |----------|----------------|
   | **macOS** | Open **Finder** &rarr; Press **Cmd + Shift + G** &rarr; Type `~/.claude/skills/` &rarr; Press **Go** &rarr; Move the folder here |
   | **Windows** | Open **File Explorer** &rarr; Type `%USERPROFILE%\.claude\skills\` in the address bar &rarr; Press **Enter** &rarr; Move the folder here |

   > **Note:** If the `skills` folder does not exist, create it inside the `.claude` folder first.

4. **Install Python dependencies** &mdash; Open Claude Code Desktop and send this message to Claude:

   > *"Install the Python requirements for CTI Expert by running: pip3 install -r ~/.claude/skills/cti-expert/scripts/requirements.txt"*

5. **Restart Claude Code Desktop** &mdash; Close and reopen the app
6. **Verify** &mdash; Type `/cti-expert` in the chat to confirm the skill is loaded

---

### Option C &mdash; Claude Code Web (Browser)

> Use directly at [claude.ai/code](https://claude.ai/code) &mdash; skills load from your `~/.claude/skills/` directory. Run the quick install command above first.

<details>
<summary><b>Requirements</b></summary>
<br>

| Requirement | Version | Purpose |
|-------------|---------|---------|
| [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code/overview) | Latest | Terminal runtime |
| [Claude Code Desktop](https://claude.ai/download) | Latest | GUI runtime (macOS/Windows) |
| Python | 3.10+ | DOCX report generation, Scrapling, AgentFlow |
| pip packages | See `requirements.txt` | Charts, diagrams, styling |
| git | Any | Clone the repository |

</details>

<br>

---

<br>

## Quick Start

> **How to run commands:** All commands below use the `/cti-expert` prefix. Type `/cti-expert` followed by the command in Claude Code.
>
> Example: `/cti-expert /case example.com` — not just `/case example.com`

### 1 &mdash; Full Autonomous Case

```bash
/cti-expert /case example.com
```

> Runs every applicable technique for the target type. Auto-generates `.md` and `.docx` reports.

### 2 &mdash; Guided Flows

```bash
/cti-expert /flow person           # Person investigation workflow
/cti-expert /flow domain           # Domain reconnaissance workflow
/cti-expert /flow image            # Image verification workflow
```

### 3 &mdash; Targeted Reconnaissance

```bash
/cti-expert /sweep @username                    # Multi-vector recon on handle
/cti-expert /query example.com                  # 12-15 advanced search queries
/cti-expert /username johndoe                   # Platform enumeration (3000+)
/cti-expert /email-deep user@domain.com         # Deep email investigation
/cti-expert /subdomain example.com              # Certificate transparency + brute-force
/cti-expert /threat-check 185.1.1.1             # IP/domain/URL threat intelligence
/cti-expert /scam-check suspicious-site.xyz     # Phishing/scam domain check
/cti-expert /breach-deep user@domain.com        # Multi-source breach lookup
```

### 4 &mdash; Analysis & Assessment

```bash
/cti-expert /exposure domain.com                # Composite risk score (0-100)
/cti-expert /threat-model                       # Build threat model from findings
/cti-expert /validate                           # Verify all findings
/cti-expert /coverage                           # Check investigation completeness
```

### 5 &mdash; Reporting

```bash
/cti-expert /report                             # Technical INTSUM report
/cti-expert /report brief                       # Executive summary
/cti-expert /brief                              # Plain-language summary
/cti-expert /workspace save                     # Save workspace + auto-generate .docx
```

<br>

---

<br>

## Features

<table>
<tr>
<td width="33%" valign="top">

### Identity & People

- Person lookup — 50+ data points
- Phone — carrier, reputation, associations
- Email — accounts, breaches, infrastructure
- Username — 3000+ platform enumeration

</td>
<td width="33%" valign="top">

### Domain & Infrastructure

- Subdomain enumeration via CT logs
- CMS, CDN, analytics fingerprinting
- DNS forensics & WHOIS deep/reverse
- Traffic analysis & audience demographics

</td>
<td width="33%" valign="top">

### Analysis & Verification

- Face search (FaceCheck.id) & reverse image (TinEye)
- Image forensics (FotoForensics, Forensically)
- AI photo geolocation (picarta.ai, GeoSpy)
- Document/email metadata forensics
- Google Docs identity extraction
- 100+ paste sites & breach DBs

</td>
</tr>
<tr>
<td width="33%" valign="top">

### WiFi, Geo & Transport

- SSID/BSSID lookup via Wigle.net
- W3W, Plus Codes, MGRS, Street View
- Aircraft tracking (ADS-B Exchange, Flightradar24)
- Vessel tracking (Marine Traffic, VesselFinder)
- Vehicle VIN lookup & plate recognition

</td>
<td width="33%" valign="top">

### Security Auditing

- Cloud audit (AWS/GCP/Azure)
- OWASP Top 10 source code review
- CVE & supply chain vulnerability checks
- LLM/agent/MCP prompt injection audit

</td>
<td width="33%" valign="top">

### Reporting & Export

- INTSUM, executive brief, plain-language
- DOCX with charts, diagrams, timelines
- Save/load case workspaces
- Legal, journalist, HR, threat analyst formats

</td>
</tr>
</table>

<br>

---

<br>

## AEAD Case Lifecycle

Every investigation follows four automated phases:

```
                         ╭──────────────────────────────────────╮
                         │         AEAD CASE LIFECYCLE          │
                         ╰──────────────────────────────────────╯

   ┌─── ACQUIRE ────────────────────────────────────────────────────────┐
   │  Collect raw data via /sweep, /query, /username, /phone, etc.     │
   │  Database search, enumeration, collection gap logging             │
   └────────────────────────────────┬───────────────────────────────────┘
                                    ▼
   ┌─── ENRICH ─────────────────────────────────────────────────────────┐
   │  Expand leads via /branch, /crossref, /link-subjects, /signatures │
   │  Shared identifier detection, relationship mapping                │
   └────────────────────────────────┬───────────────────────────────────┘
                                    ▼
   ┌─── ASSESS ─────────────────────────────────────────────────────────┐
   │  Score & verify via /exposure, /threat-model, /validate, /coverage│
   │  Risk scoring, completeness check, evidence chains                │
   └────────────────────────────────┬───────────────────────────────────┘
                                    ▼
   ┌─── DELIVER ────────────────────────────────────────────────────────┐
   │  Package output via /report, /brief, /render, /workspace save     │
   │  Auto-save .md + .docx with charts & diagrams                     │
   └────────────────────────────────────────────────────────────────────┘
```

> Run `/progress` at any point to see current phase and pending tasks.

<br>

---

<br>

## Command Reference

> Full command list: See **SKILL.md** for comprehensive reference.

<details>
<summary><b>Acquire</b> — Data collection commands</summary>
<br>

| Command | Purpose |
|---------|---------|
| `/cti-expert /case [target]` | Full pipeline — every applicable technique |
| `/cti-expert /sweep [target]` | Multi-vector recon (person/domain/org/username/email/IP) |
| `/cti-expert /query [subject]` | 12-15 advanced search operator queries |
| `/cti-expert /username [handle]` | 3000+ platform enumeration |
| `/cti-expert /phone [number]` | Carrier lookup, reputation, associations |
| `/cti-expert /email-deep [email]` | Accounts, breaches, infrastructure |
| `/cti-expert /subdomain [domain]` | CT logs + passive enumeration |
| `/cti-expert /threat-check [target]` | IP/domain/URL/hash threat intelligence |
| `/cti-expert /breach-deep [email]` | Multi-source breach lookup |

</details>

<details>
<summary><b>Enrich</b> — Lateral expansion commands</summary>
<br>

| Command | Purpose |
|---------|---------|
| `/cti-expert /branch [data]` | Lateral expansion (email&rarr;username, username&rarr;email, etc.) |
| `/cti-expert /crossref` | Shared identifier detection across subjects |
| `/cti-expert /link-subjects [A] [B]` | Define connection between subjects |
| `/cti-expert /show-connections` | Display logged connections |
| `/cti-expert /graph` | Full ASCII subject relationship map |

</details>

<details>
<summary><b>Assess</b> — Scoring & verification commands</summary>
<br>

| Command | Purpose |
|---------|---------|
| `/cti-expert /exposure [target]` | Composite risk score (0-100) |
| `/cti-expert /threat-model` | Build threat model from findings |
| `/cti-expert /validate` | Verify finding evidence chains |
| `/cti-expert /coverage` | Check investigation completeness |

</details>

<details>
<summary><b>Deliver</b> — Report generation commands</summary>
<br>

| Command | Purpose |
|---------|---------|
| `/cti-expert /report` | Technical INTSUM report |
| `/cti-expert /report brief` | Executive summary |
| `/cti-expert /brief` | Plain-language summary |
| `/cti-expert /workspace save` | Save workspace + auto-generate .docx |

</details>

<br>

---

<br>

## Skill Tiers

<table>
<tr>
<th width="33%">Novice</th>
<th width="33%">Practitioner</th>
<th width="33%">Specialist</th>
</tr>
<tr>
<td valign="top">

Low-jargon mode, step-by-step guidance, pre-built templates for due diligence, background checks, security reviews.

**Entry:** `/cti-expert /flow person`, `/cti-expert /flow domain`, `/cti-expert /template list`

</td>
<td valign="top">

Advanced search operators, manual pivot expansion, custom threat modeling, guided flows with explanation.

**Entry:** `/cti-expert /query [target]`, `/cti-expert /branch [data]`, `/cti-expert /crossref`, `/cti-expert /threat-model`

</td>
<td valign="top">

Raw technique access, custom evidence weighting, CONTESTED finding resolution, direct database queries.

**Entry:** `/cti-expert /username [handle]`, `/cti-expert /email-deep [email]`, `/cti-expert /secrets [target]`, `/cti-expert /threat-check [target]`

</td>
</tr>
</table>

<br>

---

<br>

## Technique Catalog

<details>
<summary><b>35 techniques</b> — click to expand full catalog</summary>
<br>

| Technique | Coverage | API Key Required? |
|-----------|----------|-------------------|
| `fx-metadata-parsing.md` | EXIF, email headers, document forensics | No |
| `fx-image-verification.md` | Image authenticity, provenance, reverse search | No |
| `fx-breach-discovery.md` | Breach database + paste site enumeration | Optional (HIBP bulk, DeHashed paid) |
| `fx-http-fingerprint.md` | HTTP signature analysis, server fingerprinting | No |
| `fx-leak-monitoring.md` | Leak and breach monitoring automation | Mixed (IntelligenceX/Shodan paid) |
| `fx-dns-cert-history.md` | Historical DNS + SSL/TLS certificate timeline | No |
| `fx-document-forensics.md` | PDF/Office authorship, creation chain, hidden content | No |
| `fx-network-mapping.md` | Network topology, entity graph construction | No |
| `username-osint.md` | 3000+ platform enumeration | No |
| `phone-osint.md` | Carrier lookup, VoIP, FreeCNAM, WhoCalld | No |
| `email-osint.md` | Deep email investigation, breach history | No |
| `threat-intel.md` | GreyNoise, AbuseIPDB, OTX, VirusTotal, CIRCL CVE, NVD | Optional (VT/URLScan free keys) |
| `web-traffic-analysis.md` | SimilarWeb, Semrush estimation | No |
| `domain-advanced.md` | CT logs, Amass, Subfinder, passive enum | No |
| `social-media-platforms.md` | Twitter/X, Discord, Strava, BlueSky, ShareTrace, Reddit, Instagram, TikTok, Telegram | Partial (Discord needs token) |
| `image-forensics-and-face-search.md` | FaceCheck.id, TinEye, FotoForensics, Forensically, picarta.ai, GeoSpy, Pic2Map | No |
| `blockchain-investigation.md` | Blockchair, Etherscan, WalletExplorer, OXT.me, Chainabuse, Breadcrumbs | Optional (Etherscan API for bulk) |
| `transport-tracking.md` | ADS-B Exchange, Flightradar24, Marine Traffic, VesselFinder, VIN decode | No |
| `darknet-investigation.md` | Ahmia.fi, onionsearch, DarknetLive, ransomwatch | No |
| `advanced-geolocation-techniques.md` | W3W, Plus Codes, MGRS, Overpass Turbo | No |
| `wifi-ssid-osint.md` | Wigle.net SSID/BSSID geolocation | Free account (Wigle API) |
| `web-dns-forensics.md` | Zone transfers, GitHub, Telegram, WHOIS | Optional (WHOIS API) |
| `scam-check.md` | Phishing/scam domain verification | No |
| `ioc-export.md` | IOC export (STIX 2.1, flat list) | No |
| `cloud-audit.md` | AWS/GCP/Azure IAM, network, compute audit | No |
| `dependency-audit.md` | CVE, supply chain, CI/CD security | No |
| `disk-forensics.md` | Sleuth Kit, file carving, artifact recovery | No |
| `incident-triage.md` | NIST 800-61, containment, IOC extraction | No |
| `owasp-audit.md` | OWASP Top 10 source code review | No |
| `prompt-injection-audit.md` | LLM/agent/MCP security assessment | No |
| `fx-visitor-intelligence.md` | Visitor stats, tech stack, geo analysis | No |
| `fx-social-topology.md` | Social graph construction and analysis | No |
| `fx-geolocation.md` | GPS, W3W, Plus Codes, MGRS, Street View | No |
| `secret-scanning.md` | Credential/secret detection in code | Optional (GitHub token for GitDorker) |
| `fx-email-header-analysis.md` | Email header analysis, SPF/DKIM | No |

</details>

<br>

---

<br>

## Report Formats

Every `/report`, `/brief`, and `/case` auto-saves two files:

<table>
<tr>
<td width="50%" valign="top">

### Markdown Report

- INTSUM format (technical)
- Executive brief (decision-makers)
- Plain-language summary (non-technical)
- Legal evidence format (attorneys)

</td>
<td width="50%" valign="top">

### Word Document (.docx)

- Cover page with classification
- Table of contents & styled finding cards
- Charts: pie, bar, gauge, timeline
- Entity relationship & network topology diagrams
- Source attribution table with page numbers

</td>
</tr>
</table>

<sub>Generated by <code>scripts/generate-cti-docx.py</code></sub>

<br>

---

<br>

## Architecture

<details>
<summary><b>Project structure</b> — click to expand</summary>
<br>

```
cti-expert/
├── SKILL.md                       Command reference & skill definition
├── README.md                      This file
│
├── engine/                        Case data model & state management
│   ├── subject-registry.md        How subjects are tracked
│   ├── finding-framework.md       Finding lifecycle & evidence chains
│   ├── workspace-format.md        Workspace serialization spec
│   └── conflict-resolver.md       CONTESTED finding resolution
│
├── techniques/                    Collection techniques (32 files)
│   ├── whois-universal.md         Universal multi-TLD WHOIS cascade
│   ├── web-collection-scrapling.md Scrapling adaptive web collection
│   ├── agentflow-enrichment.md    Parallel enrichment orchestration
│   ├── fx-metadata-parsing.md, fx-image-verification.md, ...
│   ├── username-osint.md, phone-osint.md, email-osint.md
│   ├── cloud-audit.md, dependency-audit.md, disk-forensics.md
│   └── ...
│
├── experience/                    UX, tiers, guided flows
│   ├── guided-flows/              Interactive workflows
│   ├── case-templates/            Pre-built case templates
│   └── accessibility/             Glossary, low-jargon mode
│
├── analysis/                      Pattern detection & intelligence engines
│   ├── deviation-detector.md      Behavioral anomaly detection
│   ├── cross-reference-engine.md  Shared identifier detection
│   └── exposure-model.md          Risk score calculation
│
├── output/                        Report & visualization specs
│   ├── reports/                   Report templates
│   └── visuals/                   Chart & render engine specs
│
├── scripts/                       DOCX report generation
│   ├── generate-cti-docx.py       Main generator
│   ├── cti_docx_charts.py         Chart rendering
│   ├── cti_docx_diagrams.py       Entity relationship diagrams
│   └── requirements.txt           Python dependencies
│
├── workflows/                     Professional use-case guides
│   ├── wf-journalist.md           Journalist source verification
│   ├── wf-threat-analyst.md       Cyber threat intelligence
│   └── wf-hr-screening.md        Background checks
│
├── guides/walkthroughs/           Worked case examples
│   ├── walkthrough-person-lookup.md
│   ├── walkthrough-domain-sweep.md
│   └── walkthrough-username-trace.md
│
└── validation/                    Quality assurance
    ├── coverage-matrix.md         Investigation area coverage
    ├── quality-scoring.md         Finding scoring methodology
    └── verification-checklist.md  Evidence chain validation
```

</details>

<br>

---

<br>

## Professional Workflows

| Workflow | Audience | File |
|----------|----------|------|
| **Journalist Source Verification** | Reporters, fact-checkers | `workflows/wf-journalist.md` |
| **HR Screening** | HR professionals, recruiters | `workflows/wf-hr-screening.md` |
| **Cyber Threat Intelligence** | Security analysts, IR teams | `workflows/wf-threat-analyst.md` |
| **Private Investigator** | Licensed PIs, legal teams | `workflows/wf-private-investigator.md` |

> Activate with `/cti-expert /flow [type]` for interactive guided prompts.

<br>

---

<br>

## Ethics & Responsible Use

> **This skill is for lawful research and professional security investigation only.**

<table>
<tr>
<th>Permitted</th>
<th>Prohibited</th>
</tr>
<tr>
<td valign="top">

- Journalist fact-checking & source verification
- HR background screening (with consent)
- Corporate security research & threat intelligence
- Authorized penetration testing & security audits
- Legal/compliance investigation
- Personal reputation monitoring (self-search)

</td>
<td valign="top">

- Doxxing, harassment, or stalking
- Unauthorized surveillance
- Social engineering or fraud
- Privacy violations
- Criminal activity

</td>
</tr>
</table>

**You are responsible for all use of this skill.** Comply with local laws, regulations, and platform terms of service. Always respect privacy and consent boundaries.

<br>

---

<br>

## Contributing

We welcome research contributions, new techniques, and workflow improvements.

<details>
<summary><b>Contribution guidelines</b></summary>
<br>

**Adding techniques:**
1. Create `techniques/fx-[name].md` with method description, free tool lists, limitations

**Workflow improvements:**
1. Document in `workflows/` with success criteria

**Pull request process:**
1. Fork and create feature branch: `git checkout -b feature/technique-name`
2. Document changes in SKILL.md and README.md
3. Test on at least 3 real-world targets
4. Submit PR with description

**Bug reports:** File issues with command output, environment, and target type.

</details>

<br>

---

<br>

## License

**MIT License** + Ethical Use Addendum

You are free to use, modify, and distribute this skill under the MIT license, provided that you include original attribution, comply with the ethical use guidelines above, and clearly mark any derivatives.

See [LICENSE](LICENSE) for full text.

<br>

---

<br>

<div align="center">

### Made with purpose by [Hieu Ngo](https://www.linkedin.com/in/hieu-minh-ngo-hieupc/)

<p>
  <a href="https://www.linkedin.com/in/hieu-minh-ngo-hieupc/"><img src="https://img.shields.io/badge/LinkedIn-Hieu_Ngo-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white" alt="LinkedIn"></a>&nbsp;
  <a href="mailto:hieu.ngo@chongluadao.vn"><img src="https://img.shields.io/badge/Email-hieu.ngo%40chongluadao.vn-0080ff?style=for-the-badge&logo=gmail&logoColor=white" alt="Email"></a>&nbsp;
  <a href="https://chongluadao.vn"><img src="https://img.shields.io/badge/Web-chongluadao.vn-00c853?style=for-the-badge&logo=googlechrome&logoColor=white" alt="Website"></a>&nbsp;
  <a href="https://github.com/7onez"><img src="https://img.shields.io/badge/GitHub-7onez-181717?style=for-the-badge&logo=github&logoColor=white" alt="GitHub"></a>
</p>

<sub>If this tool helps your work, consider giving it a star. It helps others find it.</sub>

</div>

<br>

---

<br>

<a id="vietnamese"></a>
<details>
<summary>

## :vietnam: CTI Expert &mdash; Tình Báo Mối Đe Dọa Mạng & OSINT

</summary>

<br>

### CTI Expert là gì?

Một kỹ năng của Claude Code biến Claude thành một nhà phân tích tình báo mối đe dọa mạng và tình báo nguồn mở chuyên nghiệp. Chạy thu thập tình báo có cấu trúc sử dụng **67+ lệnh** trên **35 kỹ thuật** — không cần API key cho chức năng cốt lõi. Một số kỹ thuật hỗ trợ API key miễn phí tùy chọn để truy cập nâng cao (VD: Wigle, VirusTotal, URLScan.io).

**Mới trong v2.2:** Pháp y hình ảnh & tìm kiếm khuôn mặt (FaceCheck.id, TinEye, FotoForensics, picarta.ai AI geolocation), điều tra blockchain (Blockchair, Etherscan, WalletExplorer, Chainabuse), theo dõi vận tải (ADS-B Exchange theo dõi máy bay, Marine Traffic theo dõi tàu, VIN decoder), điều tra darknet (Ahmia.fi tìm kiếm Tor, ransomwatch), mạng xã hội mở rộng (Reddit, Instagram, TikTok, Telegram), tra cứu người (TruePeopleSearch, IDCrawl), 11 mẫu Google mega-dork bao phủ 73 domain.

**Mới trong v2.1:** Trực quan hóa đường tấn công (`/cti-expert /render threat-path`), bề mặt tấn công (`/cti-expert /render attack-surface`), xuất IOC STIX 2.1 (`/cti-expert /report ioc`), theo dõi rủi ro theo thời gian (`/cti-expert /drift`), ảnh chụp Wayback (`/cti-expert /snapshots`, `/cti-expert /diff`), hướng dẫn người mới (`/cti-expert /onboard`), giải thích phát hiện (`/cti-expert /clarify`), phân tích khoảng trống (`/cti-expert /blind-spots`), kiểm tra nguồn (`/cti-expert /source-check`), so sánh phiên (`/cti-expert /workspace diff`), điểm chất lượng (`/cti-expert /quality`), thang độ tin cậy nguồn A-F, 4 loại thực thể mới.

**Khả năng cốt lõi:** Trinh sát đa vector trên mọi loại mục tiêu (cá nhân, tên miền, tổ chức, tên người dùng, email, IP, WiFi) với xác thực phát hiện tự động, chấm điểm rủi ro phơi bày, và báo cáo tình báo có cấu trúc ở nhiều định dạng.

**Quy trình:** Vòng đời AEAD — Thu thập dữ liệu thô &rarr; Làm giàu bằng mở rộng pivot &rarr; Đánh giá phát hiện &rarr; Phân phối báo cáo có cấu trúc (Markdown + Word với biểu đồ, sơ đồ, định dạng chuyên nghiệp).

---

### Cài đặt

#### Cài đặt nhanh (một lệnh)

<table>
<tr>
<th>Hệ điều hành</th>
<th>Lệnh</th>
</tr>
<tr>
<td><b>Linux / macOS</b></td>
<td>

```bash
git clone https://github.com/7onez/cti-expert.git ~/.claude/skills/cti-expert && pip3 install -r ~/.claude/skills/cti-expert/scripts/requirements.txt
```

</td>
</tr>
<tr>
<td><b>Windows (PowerShell)</b></td>
<td>

```powershell
git clone https://github.com/7onez/cti-expert.git "$env:USERPROFILE\.claude\skills\cti-expert"; pip3 install -r "$env:USERPROFILE\.claude\skills\cti-expert\scripts\requirements.txt"
```

</td>
</tr>
<tr>
<td><b>Windows (CMD)</b></td>
<td>

```cmd
git clone https://github.com/7onez/cti-expert.git "%USERPROFILE%\.claude\skills\cti-expert" && pip3 install -r "%USERPROFILE%\.claude\skills\cti-expert\scripts\requirements.txt"
```

</td>
</tr>
</table>

---

#### Tùy chọn A &mdash; Claude Code CLI

> Cài CLI trước: `npm install -g @anthropic-ai/claude-code` &mdash; [Tài liệu CLI](https://docs.anthropic.com/en/docs/claude-code/overview)

<details>
<summary><b>Linux / macOS</b></summary>

```bash
# Cài Claude Code CLI
npm install -g @anthropic-ai/claude-code

# Clone skill + cài dependencies
git clone https://github.com/7onez/cti-expert.git ~/.claude/skills/cti-expert
pip3 install -r ~/.claude/skills/cti-expert/scripts/requirements.txt

# Xác nhận
ls ~/.claude/skills/cti-expert/SKILL.md
```

</details>

<details>
<summary><b>Windows (PowerShell)</b></summary>

```powershell
# Cài Claude Code CLI
npm install -g @anthropic-ai/claude-code

# Clone skill + cài dependencies
git clone https://github.com/7onez/cti-expert.git "$env:USERPROFILE\.claude\skills\cti-expert"
pip3 install -r "$env:USERPROFILE\.claude\skills\cti-expert\scripts\requirements.txt"

# Xác nhận
Test-Path "$env:USERPROFILE\.claude\skills\cti-expert\SKILL.md"
```

</details>

---

#### Tùy chọn B &mdash; Claude Code Desktop (macOS / Windows)

> Tải về: [claude.ai/download](https://claude.ai/download) &mdash; hỗ trợ **macOS** và **Windows**

**Hướng dẫn từng bước (không cần terminal):**

1. **Cài đặt Claude Code Desktop** &mdash; Tải từ [claude.ai/download](https://claude.ai/download) và cài đặt ứng dụng
2. **Tải CTI Expert** &mdash; Vào [kho GitHub](https://github.com/7onez/cti-expert), nhấn nút **"Code"** màu xanh, sau đó chọn **"Download ZIP"**
3. **Giải nén vào thư mục skills** &mdash; Giải nén file đã tải, sau đó di chuyển thư mục vào thư mục skills và đổi tên thành `cti-expert`:

   | Hệ điều hành | Cách điều hướng |
   |-------------|----------------|
   | **macOS** | Mở **Finder** &rarr; Nhấn **Cmd + Shift + G** &rarr; Nhập `~/.claude/skills/` &rarr; Nhấn **Go** &rarr; Di chuyển thư mục vào đây |
   | **Windows** | Mở **File Explorer** &rarr; Nhập `%USERPROFILE%\.claude\skills\` vào thanh địa chỉ &rarr; Nhấn **Enter** &rarr; Di chuyển thư mục vào đây |

   > **Lưu ý:** Nếu thư mục `skills` chưa tồn tại, hãy tạo nó bên trong thư mục `.claude` trước.

4. **Cài đặt thư viện Python** &mdash; Mở Claude Code Desktop và gửi tin nhắn sau cho Claude:

   > *"Install the Python requirements for CTI Expert by running: pip3 install -r ~/.claude/skills/cti-expert/scripts/requirements.txt"*

5. **Khởi động lại Claude Code Desktop** &mdash; Đóng và mở lại ứng dụng
6. **Xác nhận** &mdash; Gõ `/cti-expert` trong chat để xác nhận skill đã được tải

---

#### Tùy chọn C &mdash; Claude Code Web (Trình duyệt)

> Sử dụng trực tiếp tại [claude.ai/code](https://claude.ai/code) &mdash; skills được tải từ thư mục `~/.claude/skills/` của bạn. Chạy lệnh cài đặt nhanh ở trên trước.

<details>
<summary><b>Yêu cầu hệ thống</b></summary>
<br>

| Yêu cầu | Phiên bản | Mục đích |
|----------|-----------|----------|
| [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code/overview) | Mới nhất | Runtime terminal |
| [Claude Code Desktop](https://claude.ai/download) | Mới nhất | Runtime giao diện (macOS/Windows) |
| Python | 3.10+ | Tạo báo cáo DOCX, Scrapling, AgentFlow |
| pip packages | Xem `requirements.txt` | Biểu đồ, sơ đồ, định dạng |
| git | Bất kỳ | Clone repository |

</details>

---

### Bắt đầu nhanh

```bash
/cti-expert /case example.com                   # Chạy case tự động hoàn toàn
/cti-expert /flow person                        # Quy trình điều tra cá nhân
/cti-expert /flow domain                        # Quy trình trinh sát tên miền
/cti-expert /sweep @username                    # Trinh sát đa vector trên handle
/cti-expert /query example.com                  # 12-15 truy vấn tìm kiếm nâng cao
/cti-expert /username johndoe                   # Liệt kê nền tảng (3000+)
/cti-expert /email-deep user@domain.com         # Điều tra email chuyên sâu
/cti-expert /exposure domain.com                # Điểm rủi ro tổng hợp (0-100)
/cti-expert /report                             # Báo cáo kỹ thuật INTSUM
/cti-expert /workspace save                     # Lưu workspace + tự động tạo .docx
```

---

### Tính năng theo lĩnh vực

| Lĩnh vực | Khả năng |
|-----------|----------|
| **Danh tính & Con người** | Tra cứu cá nhân (50+ điểm dữ liệu), điều tra số điện thoại, email chuyên sâu, liệt kê tên người dùng (3000+ nền tảng) |
| **Tên miền & Hạ tầng** | Liệt kê subdomain, fingerprint kỹ thuật, pháp y DNS, phân tích lưu lượng |
| **Phân tích & Xác minh** | Xác minh hình ảnh, pháp y metadata, pháp y web, cơ sở dữ liệu rò rỉ |
| **WiFi & Định vị** | Định vị WiFi qua Wigle.net, định vị nâng cao (W3W, Plus Codes, MGRS) |
| **Kiểm tra bảo mật** | Kiểm tra đám mây (AWS/GCP/Azure), kiểm tra OWASP, kiểm tra dependency, kiểm tra prompt injection |
| **Báo cáo & Xuất** | Báo cáo Markdown, DOCX với biểu đồ, workspace case, định dạng chuyên nghiệp |

---

### Đạo đức & Sử dụng có trách nhiệm

**Kỹ năng này chỉ dành cho nghiên cứu hợp pháp và điều tra bảo mật chuyên nghiệp.**

**Được phép:** Xác minh nguồn báo chí, sàng lọc nhân sự (có sự đồng ý), nghiên cứu bảo mật doanh nghiệp, kiểm tra xâm nhập được ủy quyền, điều tra pháp lý/tuân thủ, giám sát danh tiếng cá nhân.

**Cấm:** Doxxing, quấy rối, theo dõi, giám sát trái phép, kỹ thuật xã hội, gian lận, vi phạm quyền riêng tư, hoạt động tội phạm.

---

**Tác giả:** [Hieu Ngo](https://chongluadao.vn) &bull; [hieu.ngo@chongluadao.vn](mailto:hieu.ngo@chongluadao.vn) &bull; **Phiên bản:** 2.2 &bull; **Giấy phép:** MIT

</details>

<br>

<a id="chinese"></a>
<details>
<summary>

## :cn: CTI Expert &mdash; 网络威胁情报与开源情报

</summary>

<br>

### 什么是 CTI Expert？

一个 Claude Code 技能，将 Claude 转变为���练有素的网络威胁情报和开源情报分析师。使用 **67+ 个命令**、**35 种技术**进行结构化情报收集——核心功能无需 API 密钥。部分技术支持可选的免费 API 密钥以获取增强访问（如 Wigle、VirusTotal、URLScan.io）。

**v2.2 新功能：** 图像取证与人脸搜索（FaceCheck.id、TinEye、FotoForensics、picarta.ai AI地理定位）、区块链调查（Blockchair、Etherscan、WalletExplorer、Chainabuse）、交通追踪（ADS-B Exchange飞机追踪、Marine Traffic船舶追踪、VIN解码器）、暗网调查（Ahmia.fi Tor搜索、ransomwatch）、社交媒体扩展（Reddit、Instagram、TikTok、Telegram）、人员搜索（TruePeopleSearch、IDCrawl）、11个跨平台Google mega-dork模板覆盖73个域名。

**v2.1 新功能：** 攻击路径可视化（`/cti-expert /render threat-path`）、攻击面映射（`/cti-expert /render attack-surface`）、STIX 2.1 IOC 导出（`/cti-expert /report ioc`）、时间风险追踪（`/cti-expert /drift`）、Wayback 快照（`/cti-expert /snapshots`、`/cti-expert /diff`）、新手引导（`/cti-expert /onboard`）、发现解释（`/cti-expert /clarify`）、盲点分析（`/cti-expert /blind-spots`）、来源检查（`/cti-expert /source-check`）、会话比较（`/cti-expert /workspace diff`）、质量评分（`/cti-expert /quality`）、来源可靠性 A-F 等级、4 种新实体类型。

**核心能力：** 对任何目标类型（个人、域名、组织、用户名、电子邮件、IP、WiFi）进行多向量侦察，具备自动发现验证、暴露风险评分，以及多格式结构化情报交付。

**工作流程：** AEAD 生命周期——获取原始数据 &rarr; 通过枢轴扩展丰富 &rarr; 评估发现 &rarr; 交付结构化报告（Markdown + 带图表、图形、专业格式的 Word 文档）。

---

### 安装

#### 快速安装（一条命令）

<table>
<tr>
<th>操作系统</th>
<th>命令</th>
</tr>
<tr>
<td><b>Linux / macOS</b></td>
<td>

```bash
git clone https://github.com/7onez/cti-expert.git ~/.claude/skills/cti-expert && pip3 install -r ~/.claude/skills/cti-expert/scripts/requirements.txt
```

</td>
</tr>
<tr>
<td><b>Windows (PowerShell)</b></td>
<td>

```powershell
git clone https://github.com/7onez/cti-expert.git "$env:USERPROFILE\.claude\skills\cti-expert"; pip3 install -r "$env:USERPROFILE\.claude\skills\cti-expert\scripts\requirements.txt"
```

</td>
</tr>
<tr>
<td><b>Windows (CMD)</b></td>
<td>

```cmd
git clone https://github.com/7onez/cti-expert.git "%USERPROFILE%\.claude\skills\cti-expert" && pip3 install -r "%USERPROFILE%\.claude\skills\cti-expert\scripts\requirements.txt"
```

</td>
</tr>
</table>

---

#### 选项 A &mdash; Claude Code CLI

> 先安装 CLI：`npm install -g @anthropic-ai/claude-code` &mdash; [CLI 文档](https://docs.anthropic.com/en/docs/claude-code/overview)

<details>
<summary><b>Linux / macOS</b></summary>

```bash
# 安装 Claude Code CLI
npm install -g @anthropic-ai/claude-code

# 克隆技能 + 安装依赖
git clone https://github.com/7onez/cti-expert.git ~/.claude/skills/cti-expert
pip3 install -r ~/.claude/skills/cti-expert/scripts/requirements.txt

# 验证
ls ~/.claude/skills/cti-expert/SKILL.md
```

</details>

<details>
<summary><b>Windows (PowerShell)</b></summary>

```powershell
# 安装 Claude Code CLI
npm install -g @anthropic-ai/claude-code

# 克隆技能 + 安装依赖
git clone https://github.com/7onez/cti-expert.git "$env:USERPROFILE\.claude\skills\cti-expert"
pip3 install -r "$env:USERPROFILE\.claude\skills\cti-expert\scripts\requirements.txt"

# 验证
Test-Path "$env:USERPROFILE\.claude\skills\cti-expert\SKILL.md"
```

</details>

---

#### 选项 B &mdash; Claude Code 桌面版（macOS / Windows）

> 下载：[claude.ai/download](https://claude.ai/download) &mdash; 支持 **macOS** 和 **Windows**

**分步指南（无需终端）：**

1. **安装 Claude Code 桌面版** &mdash; 从 [claude.ai/download](https://claude.ai/download) 下载并安装应用
2. **下载 CTI Expert** &mdash; 访问 [GitHub 仓库](https://github.com/7onez/cti-expert)，点击绿色 **"Code"** 按钮，然后选择 **"Download ZIP"**
3. **解压到 skills 文件夹** &mdash; 解压下载的文件，将解压后的文件夹移动到 skills 目录并重命名为 `cti-expert`：

   | 操作系统 | 导航方法 |
   |---------|---------|
   | **macOS** | 打开 **Finder** &rarr; 按 **Cmd + Shift + G** &rarr; 输入 `~/.claude/skills/` &rarr; 点击 **前往** &rarr; 将文件夹移动到此处 |
   | **Windows** | 打开 **文件资源管理器** &rarr; 在地址栏输入 `%USERPROFILE%\.claude\skills\` &rarr; 按 **回车** &rarr; 将文件夹移动到此处 |

   > **注意：** 如果 `skills` 文件夹不存在，请先在 `.claude` 文件夹内创建它。

4. **安装 Python 依赖** &mdash; 打开 Claude Code 桌面版，发送以下消息给 Claude：

   > *"Install the Python requirements for CTI Expert by running: pip3 install -r ~/.claude/skills/cti-expert/scripts/requirements.txt"*

5. **重启 Claude Code 桌面版** &mdash; 关闭并重新打开应用
6. **验证** &mdash; 在聊天中输入 `/cti-expert` 确认技能已加载

---

#### 选项 C &mdash; Claude Code 网页版（浏览器）

> 直接访问 [claude.ai/code](https://claude.ai/code) 使用 &mdash; 技能从您的 `~/.claude/skills/` 目录加载。请先运行上面的快速安装命令。

<details>
<summary><b>系统要求</b></summary>
<br>

| 要求 | 版本 | 用途 |
|------|------|------|
| [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code/overview) | 最新版 | 终端运行时 |
| [Claude Code 桌面版](https://claude.ai/download) | 最新版 | 图形界面运行时（macOS/Windows） |
| Python | 3.10+ | DOCX 报告生成、Scrapling、AgentFlow |
| pip 包 | 见 `requirements.txt` | 图表、图形、样式 |
| git | 任意版本 | 克隆仓库 |

</details>

---

### 快速入门

```bash
/cti-expert /case example.com                   # 完全自动案例
/cti-expert /flow person                        # 人员调查流程
/cti-expert /flow domain                        # 域名侦察流程
/cti-expert /sweep @username                    # 对账号进行多向量侦察
/cti-expert /query example.com                  # 12-15 个高级搜索查询
/cti-expert /username johndoe                   # 平台枚举（3000+）
/cti-expert /email-deep user@domain.com         # 深度电子邮件调查
/cti-expert /exposure domain.com                # 综合风险评分（0-100）
/cti-expert /report                             # 技术 INTSUM 报告
/cti-expert /workspace save                     # 保存工作空间 + 自动生成 .docx
```

---

### 功能领域

| 领域 | 能力 |
|------|------|
| **身份与人员** | 人员查询（50+ 数据点）、电话调查、深度邮件分析、用户名枚举（3000+ 平台） |
| **域名与基础设施** | 子域枚举、技术指纹、DNS 取证、流量分析 |
| **分析与验证** | 图像验证、元数据取证、网页取证、泄露数据库 |
| **WiFi 与地理定位** | 通过 Wigle.net WiFi 定位、高级地理定位（W3W、Plus Codes、MGRS） |
| **安全审计** | 云审计（AWS/GCP/Azure）、OWASP 审计、依赖审计、提示注入审计 |
| **报告与导出** | Markdown 报告、带图表的 DOCX、案例工作空间、专业格式 |

---

### 道德与负责任使用

**此技能仅用于合法研究和专业安全调查。**

**允许：** 新闻事实核查、人力资源筛选（需征得同意）、企业安全研究、授权渗透测试、法律/合规调查、个人声誉监控。

**禁止：** 人肉搜索、骚扰、跟踪、未授权监控、社会工程、欺诈、隐私侵犯、犯罪活动。

---

**作者：** [Hieu Ngo](https://chongluadao.vn) &bull; [hieu.ngo@chongluadao.vn](mailto:hieu.ngo@chongluadao.vn) &bull; **版本：** 2.2 &bull; **许可证：** MIT

</details>
