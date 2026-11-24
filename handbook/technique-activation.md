# Technique activation — what fires automatically in a `/case` run

**Read this before the Acquire phase.** It decides which techniques run for each target type
without being asked, and when the on-discovery commands (`/icp`, `/cn-corp`, `/iban`, `/hash-id`)
fire. `SKILL.md` §2 and `commands/cti.md` point here.

## Technique Activation Matrix

Which techniques activate per target type in a `/case` run:

| Technique | Person | Domain | Org | Username | Email | IP |
|-----------|--------|--------|-----|----------|-------|----|
| `/sweep` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `/query` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `/username` | ✅ | — | ✅* | ✅ | — | — |
| `/email-deep` | ✅ | — | ✅* | — | ✅ | — |
| `/phone` | ✅ | — | ✅* | — | — | — |
| `/breach-deep` (separate breach-focused command; NOT re-run on an email already sent through `/email-deep`) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `/intelx` (strong selectors only; `phonebook <apex>` for apex inventory, keyed and spend-gated) | — | ✅ | ✅* | — | ✅* | ✅ |
| `/osint-industries` (email already covered by `/email-deep`; phone / username / name typed; spend-gated) | ✅ | — | ✅* | ✅ | ✅* | — |
| `/subdomain` | — | ✅ | ✅ | — | — | — |
| `/traffic` | — | ✅ | ✅ | — | — | — |
| `/threat-check` | — | ✅ | ✅ | — | — | ✅ |
| `/secrets` | — | ✅ | ✅ | ✅ | — | — |
| `/github-osint` | ✅* | ✅ | ✅ | ✅ | ✅* | — |
| `/scam-check` | — | ✅ | ✅ | — | — | — |
| `phish-domain-survival` (registration/DNS class) | — | ✅ | ✅ | — | — | — |
| `clickfix-detect` (page clipboard-hijack) | — | ✅ | ✅ | — | — | — |
| `html-visibility` (hidden-content evasion) | — | ✅ | ✅ | — | — | — |
| Drainer scan (`artifacts.web3`; automatic, stored JS with `--case`) | — | ✅ (Domain and URL) | — | — | — | — |
| `/branch` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `/gdoc` | — | ✅ | ✅ | — | — | — |
| `/sharelink` | ✅ | — | ✅ | ✅ | ✅ | — |
| `/meta-transparency` | ✅ | — | ✅ | ✅ | — | — |
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
| `/icp` (ICP filing → PRC entity) | — | ✅ | ✅ | — | — | ✅ |
| `/cn-corp` (PRC registry chain) | ✅* | ✅ | ✅ | — | — | — |
| `/iban` (payment-rail selector) | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| `/hash-id` (hash typing) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
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
`MalwareBazaar` — reached via `/hash [value]`, but only **after** `/hash-id` has typed the value

### The five v2.6 commands in `/case`

Four fire automatically as part of the standard pipeline — no flag needed. `/redact` is
opt-in.

| Command | Fires | Phase |
|---|---|---|
| **`/icp`** | **Unconditionally** for every domain/URL/org target, and on an IP target's resolved hostname. One cheap passive lookup — and a *missing* filing on CN-hosted infrastructure is itself a finding, so there is no CN-nexus precondition. A discovered **licence serial** re-enters the pivot loop as its own node and reverse-searches to sibling domains (same operator, HIGH). | Acquire |
| **`/cn-corp`** | Automatically on any company name or USCC the case surfaces — from the ICP filing, WHOIS registrant org, page footer, or personnel discovery. Runs the GSXT → aggregator → 信用中国 chain; officers/shareholders/subsidiaries re-enter the loop as new nodes. | Acquire → Enrich |
| **`/iban`** | Automatically on any payment detail that surfaces — page DOM, Wayback harvest, victim statement, invoice, stealer log. Validation is arithmetic on a string, so it is free and touches nothing. Valid accounts become `financial/iban` IOCs; a checksum-**invalid** account on a payment page is logged as a behavioural finding instead. | Acquire → Enrich |
| **EMVCo / VietQR payment QR** | Automatically on every decoded QR payload: a CRC-valid payload on a listed rail becomes `artifacts.payment_accounts` and a kit-rung `bank:<cc>:<bank-id>:<account>` fact; `which_cases bank:…` finds it across cases. Never clusters (mule accounts are rented). The holder name stays in `artifacts.emv_qr`. | — |
| **`/hash-id`** | Automatically on **every** discovered hash, and always **before** `/hash`. Decides file hash (→ MalwareBazaar/VT) vs credential material (→ `/breach-deep`, never a public service). 64-hex is queued for both the cert-fingerprint and file-hash readings, since it is genuinely ambiguous. | Acquire → Enrich |
| **`/redact`** | **Opt-in, not automatic** — pass `--redact` (or run `/redact` later). Emits `REPORT.redacted.{md,json,csv}` + `REPORT.map.json` alongside the unredacted set. A redacted report is a *weaker* artifact, so producing one stays a deliberate choice. | Deliver |

Registries needing mainland egress (TianYanCha/QCC/Aiqicha) are logged as **collection gaps**,
never blockers ([`techniques/china-recon.md`](../techniques/china-recon.md) §7). Non-IBAN rails
(VN transfer, VietQR/NAPAS BIN, card BIN, e-wallet) follow
[`techniques/fiat-payment-osint.md`](../techniques/fiat-payment-osint.md) §4.

**Flags:** `--no-cn` skips `/icp`+`/cn-corp` (both run by default). `--redact` *adds* the
redacted variant (off by default). `--no-harness` disables the non-convergence auto-escalation
to the harness deepening loop (on by default; see the "`/harness` deepening AUTO-ESCALATES" note in `SKILL.md` §2).

**Recursive pivot orchestration (the spider-map).** `/case` is not a one-pass collector —
it runs a **recursive BFS pivot engine**: every discovered identifier becomes a new seed,
and the relationship graph expands **hop by hop until the frontier is exhausted** or a
budget cap is hit. The state machine — identifier typing, dedup / cycle prevention,
per-node depth, the identifier→pivot **edge matrix**, confidence gating, and per-depth
checkpoints — is [`scripts/pivot_orchestrator.py`](../scripts/pivot_orchestrator.py); the full
spec is [`engine/pivot-orchestration.md`](../engine/pivot-orchestration.md). The orchestrator
**plans and tracks**; the agent **executes** each hop's technique commands and feeds results
back via `--ingest`.

- **Defaults:** `posture=active` (may fetch/scan targets; still passive-first for hostile
  infra), `reach=exhaustive` (pivot till the frontier empties), **`autonomy=auto`** — the loop
  **runs to closure unattended**, no per-depth approval prompts. Depth summaries are still
  printed as they happen, so the expansion stays auditable. Safety caps: `max_nodes=500`,
  `max_depth=6`.
- **Gating** (reuses [`analysis/auto-branch-rules.md`](../analysis/auto-branch-rules.md)):
  exact-match links (≥95% — shared GA ID / cert / favicon / registrant email, handle
  exact-match) **auto-pursue unbounded**; HIGH/MEDIUM capped per type; LOW held unless
  corroborated; PII (`person`/`phone`) **auto-expands by default** (hold with `--authorization unconfirmed`); visited
  nodes and past-depth-cap nodes suppressed (loop-safe).
- **Example hops:** an **email** auto-pivots via reverse-WHOIS→domains, `/breach-deep`,
  `/github-osint`; a **domain** discovered from a person (high-confidence link) continues
  via `/webpivot`+`wayback_harvest`+`whois_enrich`+`cert_pivot`+subdomains; a shared **GA ID**
  reverse-pivots to sibling domains; a discovered **document** (`.pdf`/office) or **image**
  (`.jpg`/`.png`) is itself a node — metadata/authorship→person/email/org and EXIF GPS +
  reverse-image/face→person/domain (face matches held pending corroboration) — each new node
  re-enters the loop.
  - **Media content is analyzed, not just fingerprinted.** An image/document node is **vision-analyzed** (`multix gemini` — OCR, sign/landmark/logo read, structured extraction) and A/V is **FFmpeg-preprocessed** (keyframes + audio track) then transcribed, *before* it is treated as terminal — see "Media Evidence Analysis" in `SKILL.md` (under Tool Priority & Fallback). Extracted text / GPS / entities re-enter the loop as new seeds; face matches stay held pending corroboration.
- **Control flags** (all *narrowing* — the defaults are already maximal):
  `/case <t> --passive|--passive-first`, `--reach balanced|focused`,
  **`--checkpoint`** (pause for approval after each depth level), `--depth N`, `--budget N`,
  `--authorization unconfirmed` (re-hold PII), `--no-cn`, `--no-harness` (skip harness
  auto-escalation); `--redact` opts *in* to the redacted variant.
- **Termination** → if the loop **converged** (frontier exhausted): emit edges → `graph_build.py`
  → interactive HTML force-graph + topology + timeline; findings/indicators roll into the
  auto-saved report + IOC bundle. If it stopped on a **cap** (`max_nodes`/`max_depth`/`--budget`)
  with the frontier still open — i.e. **not converged** — `/case` **auto-escalates to the harness
  deepening loop** (posture-gated, keyless-first; `--no-harness` opts out) before Deliver, per the
  "`/harness` deepening AUTO-ESCALATES" note in `SKILL.md` §2.

Legacy one-hop domain collection may expose a registrant email: the collector runs the keyed
CLD email IoC, then `/cti` runs `/email-deep` once with `--case`; it does not duplicate that
selector in `/breach-deep` or `/intelx`.

> **Canonical source:** the Step 1 (target→route) and Step 2c (discovered-identifier→auto-fire)
> tables live in `commands/cti.md`; the leak/breach, GitHub-OSINT and dork sub-sections below add
> per-topic detail on top of them and must not be read as a second, independent trigger matrix.

**Leak / breach / infostealer auto-fire in `/case`:**
- **Leak coverage is MANDATORY, not on request.** After round-1 collection — before any metered co-tenant/frontier pivot — the harness runs `intel.py enrich <case> --leak-only` on every **confirmed** selector (seeds, owner-rung nodes, seed/first-hop registrant email + phone, owned seed domains, social-intake account usernames); kit/neighbour selectors are never leak-checked. Per type: email → CLD exposure + `/email-deep` (Hudson Rock, IntelX via it); username → CLD exposure + Hudson Rock `search-by-login/usernames` (IntelX n/a — soft selector); phone → CLD route + IntelX logs; owned domain → CLD exposure + IntelX logs + Hudson Rock `search-by-domain`. Under `--free-only` / `no_spend` only CLD runs and each metered vendor is recorded `not_consulted` with the reason. **The final answer states, per selector, which leak vendors were consulted (result) and which were not, and why** — from `enrichment/leak_coverage.json`; a missing file means the fan-out never ran, never "no leaks". Hits are exposure facts, never attribution edges.
- **Every discovered registrant email** → `/email-deep` with `--case`. That one command sends Hudson Rock, ZoneCruncher, one IntelX stealer-log search, OSINT Industries account existence, and reverse-WHOIS (preview, purchase only if the count is not bulk). A stealer-log hit tying the credential to a machine that also holds the registrar/hosting/CMS login is **direct attribution**. An OSINT Industries hit is not: it is account existence and self-declared names only. Do **not** also run `/breach-deep`, `/intelx` or `/osint-industries` on that email.
- **Every discovered domain/URL** → the collector already sent Feeds and host-matched Shield. Do not re-run those. A registrant org that is not a privacy proxy still gets `intel.py cld ransomware <org>` and `internal-leaks <org>`.
- **A registrant phone** → `/phone` + `intel.py cld route <phone>`; when spending is allowed, `/osint-industries phone <E164> --case <id>` for caller-ID names and registered platforms (historic corroboration only — the number may have changed hands). A number scraped from page text is not this lead.
- **A Telegram handle** → `intel.py cld route t.me/<handle>`. Do not treat `t.me` as the target domain.
- **A file hash** → `/hash-id` first. Shield IoC only if hash-id says it is a file hash. Never a favicon, JARM, or cert fingerprint.
- **Every discovered wallet / IBAN** → `/intelx <selector>` (strong selectors only; a name is refused locally and still costs a unit).
- **A local infostealer-log folder** → `/stealer-log` for family attribution, victim-vs-operator profiling and IOC extraction.
- Domain ChongLuaDao (Feeds + host-matched Shield) and keyed registrant-email IoC run inside the collector. Full `pipeline open` then executes structured case leads for registrant email/phone, Telegram, organization, IntelX phonebook, and public GitHub links; `--no-collect` preserves zero egress and leaves enrichment for `intel.py enrich <case>`. The `/cti` agent still executes/reviews query-only dork/secret leads and newly verified owner links. Apply `--quick`/`--free-only`/`no_spend` and passive/hostile posture before calls; do not close a lead as `ran` if only its query was generated. State credits spent and capability gaps.
- **Pipeline auto-fire (deterministic path):** `intel.py pipeline open` now appends `--intelx` to the collector whenever an IntelX key is present and the case is not a `no_spend` posture; `pipeline loop` appends it **only under `--full`** — the default loop stays free-only and never spends an IntelX search on its own.

**GitHub OSINT auto-fire in `/case`:**
- Domain/Org target → run `/github-osint` on the org name, primary domain, discovered GitHub orgs/repos, and developer-platform hits from `/query` or `/dork-sweep`.
- Username target → run `/github-osint` directly when the handle has a GitHub profile or GitHub search hit.
- Person target → run `/github-osint` only after discovering a likely GitHub handle, commit email, repo author, or developer profile link.
- Email target → run `/github-osint` only after discovering commit attribution, GitHub noreply patterns, profile links, or repo references.
- Every `/github-osint` run executes the committer harvest first (`github_harvest` / `intel.py github <target>`), on the user or org AND on each discovered repo, before any code search; the harvested e-mails and former logins re-enter the pivot loop as seeds (e-mail → `/breach-deep`·`/intelx`·reverse-WHOIS; login → `/username`).
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
- Domain/Org → **GrayHatWarfare exposure** (`/grayhatwarfare` — open buckets for the label, shortener-corpus hosts + historical long URLs, git committers on a self-hosted apex mail domain; keyless dork fallback) — auto-fired once per apex by `pipeline open` (loop: `--full` only) and rendered in the assessment's *Exposure (leak surface — not attribution)* section. A bucket carrying the brand label, a short link, a committer e-mail are things to READ, never a same-operator pivot and never a frontier seed.

Adaptive fan-out: discovered emails → Telegram dork; discovered personnel → `/docleak`; discovered subdomains → filetype dork; discovered usernames → Telegram + doc sweep; discovered IPs → rDNS → dork-sweep.
<!-- dork-integration:phase-05 end -->

When `/case` or `/sweep` runs on a Domain or Org target, it inspects the MX record and SPF TXT record. If MX ends in `protection.outlook.com` OR SPF contains `spf.protection.outlook.com`, `/msftrecon` auto-fires as part of the Acquire phase. Results feed back into the subject registry as `infrastructure` findings (tenant ID, federation type, MDI presence) and into `/exposure` scoring.

**`/case` pipeline walkthrough (M365-hosted Domain/Org):** (a) standard DNS/WHOIS/subdomain/traffic/scam-check/breach-deep checks run first, (b) if M365 indicators present → `/msftrecon` fires automatically with no extra flag, (c) tenant ID discovered becomes a pivot for `/branch` in Enrich phase (search other domains under the same tenant). No user intervention required.

**Parallel enrichment (3+ subjects):** When Acquire discovers 3+ subjects, enrichment commands fan out in parallel via AgentFlow DAG orchestration. Each subject's enrichment runs independently, results merge with dedup before Assess phase. Disable with `--sequential` flag. See `techniques/agentflow-enrichment.md`.
