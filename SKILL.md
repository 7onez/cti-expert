---
name: cti-expert
description: "Cyber threat intelligence and OSINT analysis toolkit. Runs structured investigations and delivers analyst-grade intelligence products with sourced, trust-scored findings. Use for OSINT and CTI cases, digital-footprint and exposure review, domain/subdomain/DNS/certificate recon, web-infrastructure pivoting (favicon hashes, tracker IDs, TLS certs, phishing-kit fingerprinting, campaign clustering), username/email/phone enumeration, breach and infostealer-log triage, image forensics, geolocation, crypto-wallet and IBAN/bank-account tracing, darknet search, M365/Azure and SaaS tenant recon, China/Sinophone recon (ICP filings, PRC corporate registries, Baidu/FOFA/Quake/ZoomEye), vulnerability and ransomware lookup, threat modeling, PII redaction, and structured reporting. Commands include /case, /sweep, /query, /webpivot, /username, /phone, /email-deep, /breach-deep, /icp, /cn-corp, /iban, /stealer-log, /exposure, /threat-model, /report, /brief, /redact, /apikeys."
version: "2.11"
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
| **Acquire** | Collect raw data — `/sweep`, `/query`, `/username`, `/phone`, `/email-deep`, `/subdomain`, `/webpivot` + `/icp` (domain/URL targets), `/cn-corp` · `/iban` · `/hash-id` on discovery |
| **Enrich** | **Recursive pivot loop** — the [pivot orchestration engine](engine/pivot-orchestration.md) treats every discovered identifier as a new seed and expands the graph hop-by-hop (`/branch`, `/crossref`, `/link-subjects`, `/signatures`) **automatically until the frontier is exhausted**, no approval prompts (`autonomy=auto`). Acquire↔Enrich iterate, not run once. |
| **Assess** | Score and verify — `/exposure`, `/threat-model`, `/validate`, `/coverage`, `/verify-finding`. Judgments carry **likelihood terms**, coverage gets the **5W1H pass**, attributions get an **ACH matrix** ([`handbook/analytic-standards.md`](handbook/analytic-standards.md)) |
| **Deliver** | Package output — `/report`, `/brief`, `/render`, `/workspace save` — **auto-saves .md + .html + .json + .csv + IOC bundle**. When `CHONGLUADAO_API_KEY` is set, the IOC bundle also attaches CLD's **STIX + MISP indicator feed** as companion artifacts (`cld_api.py feed stix2\|misp --raw` → loadable bundle, not merged into the case graph). See [`connectors/chongluadao-api.md`](connectors/chongluadao-api.md) |

Run `/progress` at any point to see which phase you're in and what's pending.

> **`/case` and web-infra pivoting.** For a **domain or URL** target, `/case` includes
> web-infrastructure pivoting (`/webpivot`) in the Acquire phase. It runs **keyless by default**
> (crt.sh + passive DNS + anonymous urlscan) and **upgrades automatically when premium keys are
> set** via `/apikeys` (Shodan/Censys/FOFA/Hunter.how/DNSLytics/SecurityTrails/urlscan-PRO/WhoisXML). Because
> `/webpivot` can fetch the target directly, for hostile infrastructure it prefers passive capture
> (urlscan/Wayback) — see [`techniques/web-pivot.md`](techniques/web-pivot.md). It is **not** run for
> username/phone/person targets.
>
> **⭐ ChongLuaDao is the first-party premium upgrade.** With `CHONGLUADAO_API_KEY` set
> (`/apikeys set chongluadao <KEY>`), Acquire/Enrich fold CLD's own datasets into `/scam-check`,
> `/threat-check`, `/phone`, `/breach-deep`, `/email-deep`, `/vuln-check` and `/impersonate`, and
> `/cld <target>` is the direct entry point. Your client connects **only to ChongLuaDao, never
> to the target** (provable from `scripts/cld/cld_api.py`); for URL/AI/IP checks CLD does any
> target fetch server-side — the safe first-touch verdict on a live scam funnel before a direct
> pivot. Full catalog + AEAD placement: [`connectors/chongluadao-api.md`](connectors/chongluadao-api.md).
>
> **Archive IOC harvest runs by default too.** For domain/URL targets the Acquire phase also runs
> `wayback_harvest.py <domain> --indicators` (add `--urlscan` when `URLSCAN_API_KEY` is set),
> harvesting **emails, phones, crypto wallets, tracking/verification IDs, SaaS-operator IDs, and
> socials from the *entire* Wayback history** — not just the live page — with first-seen/last-seen
> per selector. It writes case-schema `indicators[]` to `<case>/raw/harvest.indicators.json`, which
> merge into the case and flow into the **auto-saved IOC bundle** at Deliver. This is the step that
> recovers selectors a network later scrubbed — across the whole snapshot corpus, not just the live page.
> Passive by construction — only web.archive.org (+ urlscan.io if keyed), never the target.
>
> **The five v2.6 commands are in the pipeline too — no flags.** `/icp` runs for every
> domain/URL/org target (and an IP's resolved hostname); `/cn-corp`, `/iban` and `/hash-id`
> fire the moment a company name/USCC, payment detail, or hash appears — and all three feed
> their yields **back into the recursive pivot loop** as new seeds, so an ICP licence serial or
> a reused bank account expands the graph like any other node. `/redact` is the exception: it
> is **opt-in** (`--redact`), because a redacted report is a weaker artifact and that should
> always be a deliberate choice. Full trigger table: §Technique Activation Matrix.
> Narrow with `--no-cn`.

> **Two layers, one skill: broad collector → deep pipeline.** cti-expert is the **broad
> collector** — the wide net of Acquire/Enrich commands (`/webpivot`, `/sweep`, `/subdomain`,
> `/icp`, `/username`, `/email-deep`, `/breach-deep`, …) that pull artifacts from anywhere. The
> **`intel_engine` engine is now vendored in-repo under `intel_engine/`** (`intel_engine/harness/`,
> `intel_engine/tools/`, `intel_engine/WebPivot/`, `intel_engine/IntelGraph|IntelReport|BinaryPivot|IntelAnalysis/`)
> and supplies the **pipeline chains + deeper pivoting logic**: a persistent knowledge base (`intel_engine/knowledge/`), versioned cases
> (`cases/`), cross-case correlation, calibrated assessment, and rendering.
>
> **The chain:** broad collection (cti-expert) → the pipeline (`/pipeline`, `/harness`) ingests it,
> then applies the deep logic — *"seen this operator before?"* (`/recall`), whole-KB clustering
> (`/kb --cluster`, `/cert-overlap`), false-positive control (`/reference`), risk scoring
> (`/risk`), hypothesis generation, confidence calibration, and a versioned `Assessment`. The
> pipeline drives cti-expert's own `scripts/webpivot/pivot_extract.py` collector, so the broad and
> deep layers share one artifact shape end-to-end.
>
> **Self-contained & self-resolving.** `/backend` resolves to **SELF** (in-repo) — no external
> setup. The bundled installer (`scripts/install.{sh,ps1}`) provisions the deep layer; or by hand: `uv venv && uv pip install -r requirements.txt` (harness SDK/MCP + IntelGraph
> renderers; the collector + KB + deterministic pipeline are stdlib and need none). An explicit
> `$INTEL_HOME` still overrides for a shared external KB. Full architecture, the op map, and the
> evidence-envelope schema: [`connectors/intel-backend.md`](connectors/intel-backend.md).

---

## 2.5. Pivot Priority & False-Positive Control (CRITICAL)

Two failure modes ruin a cluster: asserting a link that isn't there, and missing one that is.
This section governs both. Apply it in Enrich, before anything reaches a report.

### Pivot priority ladder

Work **down** this ladder. Never assert same-operator on a lower rung when a higher rung is
available or contradicts it. Tag every asserted link in the report with the rung it rests on.

| Rung | Indicator | Strength |
|---|---|---|
| 1 | Registrant email / phone / org — **including historic WHOIS** | decisive |
| 2 | One domain carrying **two identities across its own WHOIS history** | decisive — proves an alias |
| 3 | Site-verification token (Google Search Console, etc.) | decisive — proves account control |
| 4 | Shared TLS certificate / SAN cross-cover | strong |
| 5 | Nameserver delegation to a host the operator **runs themselves** | strong — proves zone control |
| 6 | APK signing certificate | strong |
| 7 | Distinctive favicon / analytics / tracker / backend tenant ID | moderate — verify below |
| 8 | Co-tenancy on a **dedicated** host (few tenants) | moderate |
| 9 | Site template / framework / kit | **weak — kit-level, never operator-level** |
| 10 | Co-tenancy on **shared/reseller** hosting; managed-provider nameservers | information, not a link |

**Reverse-WHOIS is the highest-yield pivot here.** Always `mode=preview` first — the count is
free. A term returning hundreds is shared boilerplate; do not purchase it.

### Mandatory false-positive control

Before any indicator becomes a cluster edge, run `/reference check <value>`. If it returns
UNKNOWN, **decide and record it** with `/reference add` so the next case inherits the judgement.

Six traps, all of which have produced real false clusters:

| Trap | Why it fools you | Test |
|---|---|---|
| **Commodity site kit** | A template sold to hundreds of unrelated fraud operators | Search the template path in urlscan/FOFA — a large population means kit-level |
| **Privacy-proxy contacts** | The registrar's boilerplate phone/email, shared by every customer of that service | Reverse-WHOIS it; a spread of unrelated domains means noise |
| **Shared/reseller hosting IP** | A 20+-tenant cPanel box links nothing | Count tenants before clustering |
| **Managed-provider nameservers** | Cloudflare/GoDaddy/Gandi/Wix NS are shared by millions | Self-hosted NS is rung 5; provider NS is rung 10 |
| **Org-name collision** | A registrant org string that also matches a real, unrelated company | Reverse-WHOIS the org; inspect what comes back before attributing |
| **Shared analytics / tag container** | Often one web developer reusing a container across unrelated clients | **Check domain creation dates** — a decade-old business sharing a tag with a new fraud domain is a third party |

> **Never put an unvalidated indicator into a report that recommends abuse reporting.** Naming an
> uninvolved business is the most damaging error this skill can produce. When a cluster rests on a
> single rung-7-or-below indicator, label it *candidate, single-indicator* — not a cluster member.

### Never submit the case's own sample to a public sandbox (CRITICAL)

`/anyrun` is **lookup-only**. It reads detonations that already happened; it has no submit path,
and the submission endpoint is deliberately absent from `BinaryPivot/references/anyrun.json`.
`tests/test_no_sample_submission.py` enforces that as a gate, so it cannot regress quietly.

**Do not work around it.** Uploading the case's own APK / installer / archive to ANY.RUN —
or VirusTotal, or any public sandbox — is an **outbound, irreversible** act:

- A public task is **world-readable**: the file, its hash, screenshots and full network log.
- **Operators watch for their own samples.** The standard response is to rotate the backend,
  revoke the signing key and re-skin the front — destroying the infrastructure the case is built
  on, often days before a takedown or referral can land.
- **It cannot be recalled.** Unlike a query from the wrong egress, there is no cleanup.

If detonation is genuinely necessary, **stop and put it to the analyst in plain terms** — what
becomes public, and that it is permanent — and let them do it themselves in the sandbox UI on a
**private** plan. Never as a side effect of a pivot, and never on standing permission inferred
from an earlier approval. The same reasoning governs `--submit` (urlscan/Wayback): a public
urlscan scan of a live scam funnel is visible to the operator too.

### A permuted email is a hypothesis, never a finding (CRITICAL)

When a case yields a **real person's name** or a **username**, and you already hold a domain that
matters to the case, run **`/email-permute`**. An operator's mailbox is almost never published, but
it is usually *derivable* — mail hosts use a small set of local-part conventions, and the operator's
own domain is the highest-yield thing to permute against.

That value comes with a matching hazard, so this rule is absolute:

- **Permute against the case's own domains.** Name × the operator's domain is a narrow, high-prior
  question. Name × `gmail.com` is volume with no prior behind it — `--free` exists, is capped, and
  should be a deliberate choice, not a reflex.
- **Never ingest a candidate into the KB, cite one in a report, or contact one.** A fabricated
  address that reaches `kb_ingest` becomes a shared indicator, and a shared indicator merges two
  operator clusters. A permutator wired straight into correlation does not enrich a case — it
  silently names an innocent party. This is the same failure RULE 5 exists to prevent.
- **Candidates are not seeds.** They never enter the spider-map frontier. Only an address in the
  tool's `promote` list — corroborated by *independent* evidence (Gravatar registration, breach
  corpus, a GitHub commit, a page/DOM hit, a dork) — may be treated as a real email seed, and that
  promotion is an analyst decision.
- **Never validate over SMTP.** `RCPT TO` probing connects to the *target's* mail server, which the
  egress posture exists to prevent on a hostile case; and a catch-all domain answers `250` for
  every address ever tried, so it manufactures confidence instead of measuring it. Use `--verify`,
  which gates on MX (RFC 7505 null MX included) and checks Gravatar — both keyless, neither
  touching the target.

State the status in the turn. *"12 candidates, 0 corroborated"* is an honest result; presenting
those 12 as discovered addresses is not.

### Dead seed? Do not stop

Zero pivots, a parked page, or NXDOMAIN is not an answer. Run **`/fallback <domain>`** — crt.sh,
the full Wayback timeline, archive.today, and the local KB. A parked apex frequently has live
subdomains: enumerate CT and the Wayback CDX host histogram before writing a seed off. Report an
empty result as empty; a collector that returned nothing is a finding, not something to omit.

### Egress control — proxy / rotation

On a hostile case your **egress IP is a selector too** — a direct fetch of scam
infrastructure exposes your real address to the operator, and repeated lookups
from one IP get you rate-limited or fingerprinted. The `/cti-proxy` layer routes
every **HTTP(S)** request the collectors make (keyless crt.sh, Wayback/CDX,
urlscan, the CLD connector, WHOIS, analytics reverses, `/apikeys test`) through a
configured proxy — or a **rotation pool** with automatic failover — so collection
egresses from an IP you choose, and successive calls can egress from different
ones. It also tunnels the collector's raw-socket TLS cert probe (`/cert-pivot`
leaf fingerprint) via CONNECT, **failing closed** rather than dialling direct.

> **Raw-socket TLS probes are handled too — nothing dials the target directly
> behind a proxy.** The cert-SHA probes (`wp_pssl.py`, `wp_recon.py`) and JARM
> (`jarm.py`) all take their socket from `cti_proxy.proxied_connection`: under an
> HTTP pool it is **CONNECT-tunnelled and fails closed** (never a direct dial);
> under a SOCKS pool the in-process socket hook carries it (installed at import via
> `wp_common`, and `jarm.py`'s own bootstrap) **when PySocks is present in that
> interpreter** — if it is not (e.g. the `intel.py` pipeline runs tools under
> `$INTEL_PY`), the hook is absent and these probes **fail closed instead of
> leaking**, so install `pysocks` there; with no proxy it dials direct. As a
> policy choice the `/webpivot` analyze path additionally **skips JARM under an
> HTTP pool** (ten tunnelled handshakes are slow) and runs it under SOCKS / no
> proxy — that gate honors the env/pool proxy, not just an explicit `--proxy`.

```bash
uv run scripts/proxy/proxy.py add http://user:pass@host:3128 --label res-1
uv run scripts/proxy/proxy.py add 1.2.3.4:8080        # bare host:port -> http://
uv run scripts/proxy/proxy.py rotation round-robin    # | random | sticky | off
uv run scripts/proxy/proxy.py test                    # confirm each proxy's egress IP
uv run scripts/proxy/proxy.py status                  # pool + policy + toggles
uv run scripts/proxy/proxy.py disable                 # back to the real IP
```

- It is **opt-in and additive** — with no proxy configured the skill runs exactly
  as before, from your real IP. A pool, once added, is enabled by default.
- **No-leak default:** with a pool set, a failed pool is **not** silently retried
  direct — turn that on deliberately with `allow-direct on`.
- **Precedence:** env `CTI_PROXY` / `CTI_PROXIES` (and standard `HTTPS_PROXY`)
  override the stored pool for a one-off session; the store lives in
  `scripts/proxy/proxies.json` (gitignored, chmod-600 — it may hold credentials).
- **Coverage:** the broad collectors (`scripts/…`) get full in-process rotation +
  failover; the deep pipeline (`/backend`, `/pipeline`, `/harness`) inherits the
  egress for every tool it spawns (one proxy per run). For an ad-hoc tool call or
  the MCP server, export first: `eval "$(python3 scripts/proxy/proxy.py use)"`.
- **Formats:** `add` accepts a full URL, a bare `host:port`, a provider
  `host:port:user:pass` export, a `user:pass@host:port` authority, or a pasted
  `http_proxy="…"` line. HTTP/HTTPS get the full rotation + failover + `no_proxy`
  behavior; `socks5://`/`socks5h://` auto-install PySocks on `add` but rotate only
  per run — no in-process failover, and `no_proxy` is not enforced (the global
  socket hook routes everything).
- Full reference: `/cti-proxy` (`commands/cti-proxy.md`).

---

## 3. Command Reference

### 3.0 Entry point & registered commands

**`/cti <target>` is the single entry to this skill.** It routes any target type — domain, IP,
email, username, phone, wallet, hash, APK — through recall → collect → cluster → assess. Plain
English works identically ("analyze example.com and pivot the infrastructure"); the command form
just removes ambiguity.

Nine commands are **registered with Claude Code** by `bash scripts/register.sh` and work from a
cold prompt in any project:

| Command | Does | Equivalent T2 op | Equivalent T1 tool |
|---|---|---|---|
| **`/cti <target>`** | **entry point — routes by target type** | *(whole chain)* | *(whole chain)* |
| `/cti-recall <seed>` | seen before? **run first, always** | `recall` | `domain_verdict`, `which_cases` |
| `/cti-case <ID> <seeds>` | full deterministic pipeline | `pipeline open` | *(none — CLI only)* |
| `/cti-pivot <url\|ip>` | collect one target | `pivot-extract` | `pivot_extract` |
| `/cti-cluster <domain>` | correlate & expand | `kb`, `cert-overlap` | `kb_cluster`, `cert_overlap` |
| `/cti-check <indicator>` | false-positive control | `reference check` | `reference_check`, `reference_add` |
| `/cti-report <ID>` | render graph + PDF/DOCX | `graph`, `report` | `render_diagram`, `render_report` |
| `/cti-status` | backend / MCP / credits health | `backend.py status` | `api_usage` |
| `/cti-proxy [op]` | egress proxy / rotation pool for **all** outbound calls | *(none — CLI only)* | *(none — CLI only)* |

> **Every other `/command` in §3 is a convention read from this file, not a registered command.**
> Once the skill is loaded they are unambiguous instructions; typed at a cold prompt they do
> nothing. When in doubt use `/cti` and describe the goal.

**Three layers, one operation.** The same capability is reachable three ways and the names differ
by layer — T0 uses `kebab-case` after a slash, T2 uses `kebab-case` ops, T1 uses `snake_case`
tools. The table above is the canonical mapping; when you add a capability, add a row here in the
same commit or the layers drift apart again.

Capabilities that are *not* registered commands still carry their layer mapping inline in the §3
tables. The engine's WebPivot/BinaryPivot collectors add these: `/capabilities` (T2 `capabilities`,
T1 `capability_check`), `/impersonate` (T2 `impersonate`, T1 `impersonation_hunt`), `/search-pivot`
(T2 `search-pivot`, T1 `search_pivot`), `/censys` (T2 `censys`, T1 `censys`), `/intelx`
(T2 `intelx`, T1 `intelx_search`) and `/anyrun` (T2 `anyrun`, T1 `anyrun_lookup`).

---

Commands grouped by AEAD phase.

### Acquire

| Command | What It Does | Example |
|---------|-------------|---------|
| `/case [target]` | Full pipeline — runs every applicable technique | `/case example.com` |
| `/sweep [target]` | Multi-vector recon on any target type | `/sweep @username` |
| `/query [subject]` | Builds 12–15 advanced search operator queries | `/query example.com` |
| `/username [handle]` | Enumerate handle across 3000+ platforms | `/username johndoe` |
| `/phone [number]` | Carrier, line type, reputation, public associations, **infostealer exposure** (Hudson Rock); **VN scam-phone reports (ChongLuaDao)** when keyed | `/phone +84901234567` |
| `/email-deep [email]` | Accounts, breach history, infrastructure; **breach/exposure records (ChongLuaDao data-leaks)** when keyed | `/email-deep u@domain.com` |
| `/subdomain [domain]` | CT logs, brute-force, passive enumeration; flags admin/sensitive subdomains (`admin`,`adm`,`kef`,`ador`,`panel`…) per `handbook/admin-endpoint-indicators.md` | `/subdomain example.com` |
| `/breach-deep [email]` | Multi-source breach lookup with context — Hudson Rock, IntelX, **ChongLuaDao data-leaks/exposure** when keyed | `/breach-deep u@domain.com` |
| `/traffic [domain]` | Traffic estimation, ranking, audience data | `/traffic example.com` |
| `/visitors [domain]` | Full visitor intelligence: tech, geo, sources, analytics | `/visitors example.com` |
| `/techstack [domain]` | Technology fingerprint (CMS, analytics, CDN, server) | `/techstack example.com` |
| `/competitors [domain]` | Competitor & related site discovery | `/competitors example.com` |
| `/secrets [target]` | Exposed credentials in repos and paste sites | `/secrets github.com/org` |
| `/github-osint [target]` | GitHub user/org/repo recon: profiles, repos, code search, commits, forks | `/github-osint github.com/org/repo` |
| `/cld [target]` ⭐ | **ChongLuaDao first-party premium connector** (`scripts/cld/cld_api.py`, needs `CHONGLUADAO_API_KEY`). Auto-routes any indicator (url/domain/ip/hash/email/phone/asn/CVE/.onion; non-indicators are skipped, never a blind metered call) to CLD's own datasets: URL verdict vs a ~20M denylist, deep **AI URL analysis** (risk 1–10 + findings), IoC verdict+evidence, denylist/brand-lookalike search, data-leak/breach **exposure + full data-leak module** (machines, stolen/exposed creds, cookies, leaked-accounts, devices, full-export — async start→poll), CVE/KEV + actor feeds, STIX/MISP export. Your client connects **only to CLD, never to the target**; CLD fetches server-side. **30-min timeout ceiling** (`--timeout`); **403/404 → skip, not fail**. Subcmds: `route\|checkurl\|analyze\|denylist\|checkphone\|whois\|burner\|ioc\|exposure\|leaks\|breaches\|machines\|stolen-credentials\|exposed-credentials\|cookies\|leaked-accounts\|devices\|device-detail\|device-credentials\|full-export\|brand-domains\|vulns\|actors\|onion\|feed`. See `connectors/chongluadao-api.md` | `/cld https://scam-site.top` |
| `/threat-check [target]` | IP/domain/URL/hash threat intelligence — **ChongLuaDao IoC verdict + evidence** (registration, reputation, threat feeds/reports) when keyed | `/threat-check 185.1.1.1` |
| `/scam-check [domain]` | Phishing/scam/malicious domain check — upgraded by **ChongLuaDao** `checkurl` (20M-URL denylist verdict) + `analyze` (deep AI, risk 1–10); client talks only to CLD, which fetches the target server-side | `/scam-check susp-site.xyz` |
| `/webpivot [url]` | Web-infra pivoting — extract favicon mmh3 / GA-GTM-AdSense / wallet / SaaS-operator artifacts from a page's DOM → ranked pivot queries (Shodan/PublicWWW/urlscan/FOFA). Flags: `--render`, `--crawl`, `--history` (Wayback GA), `--fetch` (pull archived page content — WebFetch can't reach Wayback), `--harvest` (full-IOC harvest across whole archive history → emails/phones/wallets/IDs/socials), `--whois`, `--graph` (cluster), `--rank` (score same-operator relations), `--cert` (cert-fingerprint pivot), `--suggest`, `--wallets`, `--paths`. See `techniques/web-pivot.md` (reverse-lookup engines per artifact → `handbook/pivot-services.md`) | `/webpivot https://scam-site.top` |
| *(automatic — no flag)* | Four layers now run on **every** collection and need no command. **Asset layer:** fetches the page's own JS bundles and re-runs every extractor over the source — the fix for SPA/white-label kits where the shell HTML is empty; yields off-apex `api_endpoint`/`websocket_endpoint` (the backend survives a front-end re-skin), `build_env:<KEY>` tenant tokens, `js_bundle_sha256`, and via `sourceMappingURL` the operator's own `dev_username`/`dev_project`. **SPA route table:** reads the app's router literals — `spa_route:admin`, `spa_route:funnel`, and a `spa_route_signature` that survives a re-skin. Zero extra requests, routes are leads only and are never fetched. **Well-known/policy files:** a fixed standards list (never a wordlist, no path brute-forcing) → `adstxt_publisher`, `apple_team_id`, `security_contact`. **JARM:** TLS-stack fingerprint of the server. Suppress with `--no-assets` / `--no-well-known`; cap fetches with `--assets-max N` | *(runs inside `/cti-pivot`)* |
| `/capabilities` | **Run this first, and again before reporting any "nothing found".** Which optional API keys are configured, and for each absent one the *evidence class that went unqueried* plus the free path that substitutes. A keyless run extracts every artifact but cannot **reverse** most of them — so "no sibling domains" with no FOFA/urlscan key is a fact about the credentials, not about the operator. Every collection also records this in `meta.capability`; carry the limitation statement into the assessment and cap confidence accordingly. T2: `capabilities` · T1: `capability_check` | `/capabilities` |
| `/impersonate [domain]` | Hunt **lookalike / typosquat** domains of a seed — typosquat permutations (omission, insertion, adjacent-key, transposition, homoglyph, hyphenation, combosquat) + a curated scam-heavy TLD sweep + a crt.sh keyword hunt, then existence-checked by live DNS. Output separates **confirmed registered lookalikes** (each an `impersonation:candidate` — run `/cti-pivot` on it and compare) from an unregistered **monitoring watchlist**. FREE (crt.sh + DNS); `--fofa` / `--urlscan` add the metered sweeps. Never live-fetches the lookalike infra. Tune the TLDs/affixes per campaign in `intel_engine/WebPivot/references/impersonation.json`. T2: `impersonate` · T1: `impersonation_hunt` | `/impersonate example.com` |
| `/search-pivot [indicator]` | Multi-engine **search-engine** pivot — the general-web complement to FOFA/PublicWWW, which only see served HTML. Takes any indicator (domain, slogan, tracking ID, wallet, Telegram/Zalo handle) and emits ready-to-open, URL-encoded dork queries across Google/Yandex/DuckDuckGo/Bing/Brave. It does **not** scrape: fire the queries with WebSearch, or WebFetch the DuckDuckGo html URL, then feed new hosts back into `/cti-pivot`. FREE, no keys. T2: `search-pivot` · T1: `search_pivot` | `/search-pivot "distinctive slogan"` |
| `/censys [mode] [value]` | Censys Platform — the **server-side** view FOFA/urlscan don't give. `cert <sha256>` returns every hostname on that exact leaf certificate (near-decisive cross-brand same-operator evidence, and it works on a **free** plan); `host <ip>`, `webproperty <host>` also free-plan. `query <kind> <value>` builds the CenQL **offline and keyless**; `budget` reports the balance. ⚠️ **100 credits/MONTH per account, no rollover** — a lookup is 1, a search 5, and running the emitted CenQL in the web UI costs the same 5. Prefer handing the analyst the query over spending a search. Needs `CENSYS_PAT`. T2: `censys` · T1: `censys` | `/censys cert 1a2b3c…` |
| `/intelx [selector]` | **Intelligence X** — search ONE strong selector across a corpus nothing else here indexes: breach dumps, infostealer logs, pastes, darknet mirrors, historical WHOIS. Takes an email / domain (`*.apex` wildcard ok) / URL / IP / phone / wallet / IBAN — **never a brand or person name** (soft terms are refused *and still cost a unit*; `classify_selector()` blocks them locally). `--phonebook <domain>` inventories every email, subdomain and URL under an apex — the highest-value call, PAID-only. **Grading is not optional:** a hit in a breach dump or stealer log is **EXPOSURE**, flagged NOT clusterable — two addresses in one combolist share *victims*, not an operator. Only `whois` / `pastes` / darknet hits may carry a same-operator edge. Keyless ≈ 50%: it still types the selector and hands you the intelx.io URL. T2: `intelx` · T1: `intelx_search` | `/intelx registrant@example.com` |
| `/anyrun [indicator]` | **ANY.RUN TI Lookup — READ-ONLY.** What samples carrying this indicator *did* when **other people** detonated them: contacted domains/IPs/URLs/ports, family label, Suricata context, public task links. Run it after `/binary` on the sample's sha256, backend host or `ip:port`. It is the **only** way to recover a **packed** sample's real endpoints — those exist only at runtime, so a thin string sweep plus a `binary:protection` finding is exactly the cue. A shared *family* is same-KIT, never attribution on its own. Keyless ≈ 50%: composes the query + UI link. **⚠️ This tool never submits a sample — see the box below.** T2: `anyrun` · T1: `anyrun_lookup` | `/anyrun <sha256>` |
| `/cert-pivot [domain]` | Cert-fingerprint pivot — other hosts serving the same TLS cert + SAN siblings (keyless; Shodan/Censys with keys) | `/cert-pivot scam-site.top` |
| `/sensitive-paths [list]` | Classify a Wayback/URL list for exposed paths (.git/.env/backups/configs) — severity + per-year timeline | `/sensitive-paths waymore_index.txt` |
| `/email-hygiene [email]` | Grade an email domain 0–100 + A–F (disposable/MX/free/role) | `/email-hygiene admin@site.top` |
| `/vuln-check [query]` | CVE/vulnerability lookup (CIRCL + NVD; **ChongLuaDao CVE/KEV threat-feed** when keyed) | `/vuln-check CVE-2024-1234` or `/vuln-check apache/httpd` |
| `/ransomware-check [org]` | Check if org is a ransomware victim | `/ransomware-check "Acme Corp"` |
| `/stealer-log [folder]` | Triage an infostealer-log folder — stealer-family attribution, victim-vs-operator profiling, cross-log actor correlation, IOC extraction (raw passwords/cookies/autofill/history shown) | `/stealer-log ./logs` |
| `/gdoc [url]` | Extract metadata/owner from Google document | `/gdoc https://docs.google.com/...` |
| `/msftrecon [domain]` | M365/Azure tenant recon — tenant ID, federation, MDI, SharePoint | `/msftrecon example.com` |
| `/icp [domain\|serial]` | ICP filing (工信部备案) → registered PRC entity + licence number; reverse the **licence serial** to sibling domains under the same filing (same-operator, HIGH). See `techniques/china-recon.md` | `/icp scam-site.top` |
| `/cn-corp [name\|USCC]` | PRC corporate registry chain — GSXT (ground truth) → TianYanCha/QCC/Aiqicha → 信用中国 blacklist → UBO; officers, shareholders, subsidiaries, revoked-status flags | `/cn-corp 深圳市某某科技有限公司` |
| `/iban [value]` | Validate + decompose a bank account as a selector — mod-97 checksum, country, BBAN split, bank code, jurisdiction-mismatch signals. See `techniques/fiat-payment-osint.md` | `/iban GB29NWBK60161331926819` |
| `/hash-id [hash]` | Identify a hash's algorithm **before** lookup — separates file hashes from credential material (32 hex = MD5 *or* NTLM) so it routes to the right service | `/hash-id 5f4dcc3b5aa765d61d8327deb882cf99` |
| `/appliance-scan [domain\|ip]` | Fingerprint internet-facing edge/VPN appliances (Citrix/F5/Cisco/Ivanti/Forti/PAN/Exchange) + exposed services → CISA KEV/CVE mapping. Passive-first (Shodan InternetDB/Censys); feeds `/vuln-check` + `/threat-model`. See `techniques/fx-edge-appliance-recon.md` | `/appliance-scan vpn.example.com` |
| `/saas-map [domain]` | Map SaaS tenancy + identity fabric — DNS-TXT tenancy tokens, non-Microsoft IdP fingerprint (Okta/Auth0/OneLogin/Ping/Keycloak/ADFS), unauth API/GraphQL/spec discovery. See `techniques/fx-saas-identity-recon.md` | `/saas-map example.com` |
| `/sharelink [url]` | Extract sharer identity from share link | `/sharelink https://vm.tiktok.com/ABC` |
| `/binary [file\|url]` | **Built-in.** Static IOC extraction from a scam/fraud binary (sideloaded APK, desktop trading `.exe`/`.dmg`, bundled `.jar`) via the in-repo `BinaryPivot/` — signing-cert SHA-256, package name/permissions, embedded C2/backend hosts, Firebase/S3 tenants, wallets, Telegram/WhatsApp handles. Output is WebPivot-shaped → clusters the app with web infra in the shared KB. See `connectors/intel-backend.md` §7 | `/binary ./trader.apk` |
<!-- dork-integration:phase-05 start -->
| `/dork-sweep [target] [--telegram\|--docs\|--filetype\|--all] [--after DATE] [--clean]` | Zero-auth dork sweep: Telegram ecosystem, 18 doc-hosts, filetype families; 4-tier fallback cascade | `/dork-sweep example.com --filetype` |
| `/docleak [target] [--platform list] [--severity high]` | 18-platform document leak hunt with severity classification (CRITICAL/HIGH/MEDIUM/LOW) | `/docleak "Acme Corp"` |
<!-- dork-integration:phase-05 end -->
| `/dns-history [domain]` | Historical DNS record changes (A, NS, MX) via passive DNS | `/dns-history example.com` |
| `/cert-history [domain]` | SSL/TLS certificate timeline from CT logs (crt.sh) | `/cert-history example.com` |
| `/proton-check [email]` | Proton Mail account creation date via PGP key | `/proton-check user@proton.me` |
| `/pgp-lookup [email]` | PGP key search — creation date, UIDs, signatures | `/pgp-lookup dev@example.com` |
| `/wifi [ssid]` | WiFi SSID geolocation via Wigle.net | `/wifi "HomeNetwork"` |
| `/wifi --bssid [mac]` | Exact AP lookup by MAC address | `/wifi --bssid AA:BB:CC:DD:EE:FF` |
| `/register [name]` | Add a subject to the case workspace | `/register JohnDoe` |
| `/snapshots [url]` | List/fetch archived Wayback snapshots. **Note: WebFetch is blocked from web.archive.org (robots.txt) — use `scripts/webpivot/wayback_fetch.py` to list captures and pull archived content.** See `analysis/archive-explorer.md` | `/snapshots example.com` |
| `/fallback [domain]` | **Dead-seed recovery** (§2.5) — crt.sh + full Wayback timeline + archive.today + local KB when a seed returns zero pivots / parked / NXDOMAIN; enumerates CT + Wayback host history before a seed is written off. T2: `fallback` · T1: `fallback_probe` | `/fallback scam-site.top` |

### Enrich

| Command | What It Does | Example |
|---------|-------------|---------|
| `/branch [data]` | Expand a discovered identifier laterally | `/branch john@mail.com` |
| `/pivot-suggest` | Rank "what to pivot on next" from findings — leet/variant/reuse/temporal/domain clusters | `/pivot-suggest` |
| `/email-permute [name\|handle]` | Derive email **candidates** from a person name or username against case domains. VN/CN/KR family-name-first aware; folds diacritics Unicode won't. `--verify` = MX gate + Gravatar. **Output is hypotheses — see the rule below** | `/email-permute "Nguyen Van A" --domain example.com --verify` |
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
| `/threat-model` | Build threat model from findings; every attribution claim carries an **ACH matrix** (competing hypotheses scored by inconsistency, runner-up named) per `handbook/analytic-standards.md` §3. **Backend hook (Assess):** if `/backend` is up, calibrate confidence on your own priors first — `intel.py operators list` + `intel.py risk --case <id>` + read `knowledge/{calibration.jsonl,analyst_profile.md}` — instead of scoring from scratch. See `connectors/intel-backend.md` §6 | `/threat-model` |
| `/signatures` | Surface recurring behavioral patterns | `/signatures` |
| `/validate` | Quality audit — score 0–100 | `/validate` |
| `/coverage` | Coverage matrix with identified gaps — technique matrix **plus** the 5W1H substantive pass (`Why`/`How` unanswered blocks Deliver-ready) | `/coverage` |
| `/verify-finding [id]` | Re-check a specific finding's sources | `/verify-finding 12` |
| `/subject [name]` | View or create subject record | `/subject JohnDoe` |
| `/lookup [name]` | Retrieve a registered subject | `/lookup JohnDoe` |
| `/modify [name]` | Update a subject record | `/modify JohnDoe` |
| `/archive-subject [name]` | Remove subject from active tracking | `/archive-subject JohnDoe` |
| `/find [query]` | Search across all subjects | `/find domain:example.com` |
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
| `/redact [file]` | Shareable variant of a report — stable numbered placeholders (`[EMAIL_1]`) + reversible JSON map; `.md`/`.json`/`.csv`. **Opt-in** — the default export set stays unredacted; request with `/redact` or `--redact` | `/redact REPORT.md` |

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
| `/apikeys` | Manage premium/pro API keys (**ChongLuaDao ⭐ first-party**, Shodan, Censys, FOFA, SecurityTrails, DNSLytics, urlscan-PRO, WhoisXML, Hudson Rock, IntelX, GitHub, SerpAPI…) — `status`/`set`/`unset`/`test`/`unlocks`. Keys **upgrade existing techniques** (especially `/cld` + `/webpivot`); keyless/free stays the default. Stored chmod-600 in `$SKILL_DIR/.env` (gitignored), env-var override. See `handbook/api-keys.md` | `/apikeys set chongluadao <KEY>` |
| `/backend` | Detect/report the optional persistent-intelligence backend and pick the tier — **Tier 1** typed MCP (`intel-harness`) → **Tier 2** CLI → **Tier 3** stateless. Runs `scripts/backend/backend.py` to resolve `$INTEL_HOME` (env → `.mcp.json` → sibling dir → symlink) and print the tier line. All the backend commands below dispatch through `scripts/backend/intel.py <op>` at Tier 2 (or the typed MCP tool at Tier 1). `intel.py list` maps **all 73 engine ops** (full CLI parity — CDN ranges, graph-build, hypothesize, calibration, evidence-report, case-store, cost, deterministic `pipeline`, …); `intel.py mcp` prints/writes the `.mcp.json` that enables Tier 1 ("the server"). See `connectors/intel-backend.md` | `/backend` · `/backend check` |
| `/kb [query]` | **Built-in.** Query the shared knowledge base. **T2:** `intel.py kb --stats`/`--entity <v>`/`--cluster <domain>`/`--shared --min N`; `intel.py operators list`. **T1:** `kb_entity`/`kb_cluster`/`kb_query_shared` | `/kb --entity example.com` |
| `/recall [seed]` | **Built-in.** "Have I seen this before?" — check a seed against every prior case before collecting. **T1:** `which_cases`/`domain_verdict` (typed MCP). **T2:** `intel.py recall <seed>` (query.py `--entity`; which_cases/domain_verdict are MCP-only). Surfaces known operators up front | `/recall scam-site.top` |
| `/risk [case]` | **Built-in.** Score a case's hosts for **NRD / bulletproof-hosting / money-trail** red flags. **T2:** `intel.py risk --case <id>` (or `--file <pivot.json>`). **T1:** `risk_signals` | `/risk CASE-0001` |
| `/reverse-whois [email\|name]` | **Built-in.** Reverse-WHOIS a registrant identity → only high-value pivots; refuses privacy/registrar terms, flags bulk resellers as noise. **T2:** `intel.py reverse-whois --reverse-email <e> --search-type historic --json`. **T1:** `reverse_whois` | `/reverse-whois owner@x.com` |
| `/cert-overlap [d1 d2 …]` | **Built-in.** KB-aware TLS/SAN same-operator **verdict** (SHARED-CERT / SIBLING-OVERLAP / NO-CT-OVERLAP) across 2+ domains — corroborates a cluster at the TLS layer. Complements the keyless `/cert-pivot`. **T2:** `intel.py cert-overlap a.com b.com`. **T1:** `cert_overlap` | `/cert-overlap a.com b.com` |
| `/reference [check\|add\|list]` | **Built-in.** Curated **false-positive control** ledger — is a fingerprint BENIGN (common logo/CDN → don't cluster), SIGNAL (distinctive, prior-case → pivot), or UNKNOWN. **T2:** `intel.py reference check <value>`. **T1:** `reference_check`/`reference_add` | `/reference check favicon:123` |
| `/pipeline [open\|status] <case> <domains-file>` | **Built-in.** The **deterministic** chain (no LLM key) — the bread-and-butter handoff: broad collect (cti-expert's `pivot_extract`) → ingest → prior-overlap → risk → shared-cluster → ICD-203 assessment, persisted under `cases/<case>/`. Prints `collector: cti-expert`. **T2:** `intel.py pipeline open <case> seeds.txt [--no-graph]` | `/pipeline open case1 seeds.txt` |
| `/harness [open\|continue\|status]` | **Built-in.** The **LLM-driven** whole-case orchestration (IntelHarness) — persistent, versioned, cross-case Collect→Correlate→Assess to convergence (needs the venv deps + an LLM key for `continue`). **T2:** `intel.py harness open CASE-0001 <seeds…>` · `continue CASE-0001 --depth 4` · `status [CASE-0001]`. Persists to `cases/`; `status` needs no key | `/harness status CASE-0001` |
| `/graph --render` | **Built-in.** **IntelGraph** publication-quality render of a case graph → PNG/SVG (distinct from the ASCII `/graph`). **T2:** `intel.py graph <case_graph.json> <out-stem> --legend`. **T1:** `render_diagram` | `/graph --render case_graph.json out` |
| `/report pdf` | **Built-in.** **IntelReport** pandoc render of an assessment `.md` → polished **PDF/DOCX** (editorial house style, cover/TOC/figures, VN-safe). Complements `/report docx`. **T2:** `intel.py report <assessment.md> <out-stem> --pdf --docx`. **T1:** `render_report` | `/report pdf assessment.md out` |
| `/clusters [case]` | **Built-in.** Partition a case into same-operator clusters **before** judging it — the unit of judgment is the cluster, not the case. Shows each binding indicator's KB-wide prevalence, so an indicator that binds 3 domains here but sits on 400 KB-wide reads as noise. Pure KB read. **T2:** `intel.py clusters <case>`. **T1:** `case_clusters` | `/clusters CASE-0001` |
| `/frontier [case]` | **Built-in.** The case's unresolved gaps — free next seeds already discovered (crt.sh SAN, passive-DNS co-host, TLS co-SAN, CORS, reverse-WHOIS) plus the **deferred metered leads** held for approval. `reopen` re-opens a converged case on new seeds. **T2:** `intel.py frontier <case>` · `intel.py reopen <case> <seed…>`. **T1:** `case_frontier`/`case_reopen` | `/frontier CASE-0001` |
| `/loop [case]` | **Built-in.** Collect → assess repeatedly until the case converges, instead of stopping at an arbitrary depth. **T2:** `intel.py loop <case>`. **T1:** `case_loop` | `/loop CASE-0001` |
| `/scope [case]` | **Built-in.** Case **intake**: the no-touch class, victim ownership and the egress gate, derived up front rather than assumed mid-run. A defaulted value is never rendered as an answer. **T2:** `intel.py scope <case>`. **T1:** `case_scope` | `/scope CASE-0001` |
| `/liveness [domain]` | **Built-in.** Is it actually alive? A 200 parking/default/suspended/soft-404 page is **not** live and a 404/403/5xx/bot-wall is **not** dead — only NXDOMAIN reports dead, and every still-controlled name sets `reuse_watch`. **T2:** `intel.py liveness <domain>`. **T1:** `domain_liveness` | `/liveness scam-site.top` |
| `/pssl [domain\|cert]` | **Built-in.** Passive SSL — the historical **cert → IP** direction that recovers an origin from behind a CDN, with the base-rate rail that keeps a shared CDN certificate out of the clustering. Free (same CIRCL account as passive DNS), so it is on by default in the pipeline. **T2:** `intel.py pssl <target>`. **T1:** `passive_ssl` | `/pssl example.com` |
| `/paths [url]` | **Built-in.** The URL **path** as a clustering indicator (`path_kit:`) — for an operator who rotates disposable hosts and selects the branded template by directory instead. A generic path (`/login`, `/assets`) emits nothing; the base-rate denylist is the whole reason this is safe. **T2:** `intel.py paths <url>`. **T1:** `url_paths` | `/paths https://host/kitname/` |
| `/serp [domain]` | **Built-in.** The **advertising** layer — Google Ads Transparency (who *paid*: a verified, billed advertiser identity) plus the cloaking probe with its falsification control. Opt-in per run: it spends a SerpApi search per host. **T2:** `intel.py serp <domain>`. **T1:** `serp_ads` | `/serp scam-site.top` |
| `/docmeta [url\|file]` | **Built-in.** Document/image metadata — PDF `/Info` + XMP, EXIF (incl. GPS), PNG chunks — the author string an operator forgot to strip. Base-rate filtered on both the pivot and ingest paths. **T2:** `intel.py docmeta <target>`. **T1:** `doc_metadata` | `/docmeta https://site/brochure.pdf` |
| `/screenshot [url]` | **Built-in.** A rendered **full-page PNG** as timestamped, hashed **visual evidence** — the page as a human sees it (a channel bio naming admins, a members-area panel, a deposit page). Renders post-JS in a real browser, so it captures what the page *displays*, not what the DOM says. `--verify` re-hashes a stored capture. **T2:** `intel.py screenshot <url> --case <id>`. **T1:** `capture_screenshot` | `/screenshot https://scam-site.top` |
| `/exhaust [case]` | **Built-in.** Which collection layers actually **RAN** versus silently never fired. A layer that never executed looks identical to a layer that found nothing — this names the difference, so "no wallets" is not read as a fact about the operator when the wallet extractor never ran. **T2:** `intel.py exhaust --file <pivot.json>`. **T1:** `collection_gaps` | `/exhaust CASE-0001` |
| `/misp-export [case]` | **Built-in.** **IntelShare** — build a MISP event from the case's own collected pivots. **Local only, no network**: it writes the event JSON so you can read every attribute before anything leaves the machine. Sets TLP, distribution, threat level and tags. **T2:** `intel.py misp-export <case> --tlp amber`. **T1:** `misp_export` | `/misp-export CASE-0001` |
| `/misp [search\|push\|publish]` | **Built-in. Two separate decisions, deliberately.** `search` asks the cheaper question first — is this indicator already known to the instance? `push` **stages** the event on your instance, organisation-only and unpublished (a real write, but still deletable). `publish` syncs it to the community and **cannot be recalled** — every indicator becomes somebody else's blocking rule, so a false positive blocks innocent infrastructure on networks you will never see. Both write paths prompt via `hooks/actionguard.py`. **T2:** `intel.py misp keycheck\|budget\|search\|push\|publish`. **T1:** `misp_search`/`misp_push`/`misp_publish` | `/misp search 1.2.3.4` |
| `/pivot-extract <.eml>` | **Built-in.** `pivot_extract` also takes a **victim's saved email**. The `.eml` is parsed to its HTML body, so every HTML-side extractor runs over **what the funnel actually sent** — then header/CDN-derived selectors (sender domains, sending platform) emit pivots like any other artifact. This is the funnel's *first hop*, and no live fetch of the landing page can recover it. **T2:** `intel.py pivot-extract ./saved.eml`. **T1:** `pivot_extract` | `/pivot-extract ./phish.eml` |
| `/victims [case]` | **Built-in.** Infer the **access vector** from the victim set, plus demography (country + sector) — who was hit tells you how. **T2:** `intel.py victims --case <id>`. **T1:** `victim_profile` | `/victims CASE-0001` |
| `/case-timeline [case]` | **Built-in.** **IntelGraph** infrastructure-lifecycle timeline — registration/expiry spans, registrant eras, IP hosting windows, cert validity, archive visibility — with an evidence ledger citing every dated fact to an online source. **T2:** `intel.py timeline <case>`. **T1:** `case_timeline` | `/case-timeline CASE-0001` |
| `/tool-calls [case]` | **Built-in.** Audit what the model **actually** called during a run, including the denied calls — `intel.py dashboard` serves the same data as a loopback-only inspector (cost, trace, tool pairing). **T2:** `intel.py tool-calls <case>` · `intel.py dashboard`. **T1:** `tool_calls` | `/tool-calls CASE-0001` |
| `/login-detect [url]` | **Built-in.** **Engage** (detection half — passive and free): find the login form, the password field and the registration page, and classify by *fields* (a confirm-password means register; an invite code is a pivot, not an OTP). **T2:** `intel.py login-detect <url>`. **T1:** `detect_login` | `/login-detect https://scam-site.top` |
| `/engage [url]` | **Built-in. GATED — outbound, attributable, irreversible.** Create a **synthetic-persona** account and log in to read the members area (panel, deposit/withdraw flow, affiliate tree, support handles). Refuses without explicit confirmation, refuses a non-synthetic persona or direct egress, and stops at a CAPTCHA. Same gate class as a sandbox submission — **ask first, always**. **T2:** `intel.py persona` → `intel.py engage <url>` → `intel.py engage-harvest` → `intel.py engage-report`. **T1:** `make_persona`/`engage_account`/`harvest_authenticated`/`engage_report` | `/engage https://scam-site.top` |

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
| Bank Account | 🏦 | IBAN, local account no., BIC |
| ICP Filing | 📋 | PRC licence serial (one registrant, many sites) |
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

### Likelihood Language (judgments, not findings)

The three scales above grade **evidence**. An analytic **judgment** built on that evidence —
an attribution, a motive, a forecast — carries a probability-anchored likelihood term instead.
Without an anchor, "MODERATE" routinely means a 30-point-different thing to writer and reader.

| Term | Band | | Term | Band |
|------|------|---|------|------|
| Almost no chance | 1–5% | | Likely / probable | 55–80% |
| Very unlikely | 5–20% | | Very likely | 80–95% |
| Unlikely | 20–45% | | Almost certain | 95–99% |
| Roughly even chance | 45–55% | | | |

**Likelihood and confidence are orthogonal — report both:**
> The operator is **very likely** based in Guangdong (**moderate confidence** — single
> registry record, unverified).

Never 0% or 100%. One term per judgment. Never attach a likelihood term to a directly
observed fact. `findings[].confidence` in the report JSON stays an integer describing
**evidence quality** — likelihood lives in the narrative.

**Attribution claims additionally require an ACH matrix** (competing hypotheses, scored by
inconsistency, runner-up named). Full rules — likelihood, the 5W1H coverage overlay, and ACH:
[`handbook/analytic-standards.md`](handbook/analytic-standards.md).

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
| `china-recon.md` | China/Sinophone layer — ICP filing → PRC entity + licence-serial sibling pivot, GSXT/信用中国/TianYanCha/QCC/Aiqicha registry chain, USCC validation, Quake/ZoomEye/FOFA cyberspace engines, Baidu dorking, CJK pinyin + Traditional variant generation, CN social platforms, access-reality gaps |
| `fiat-payment-osint.md` | Bank accounts as selectors — IBAN mod-97 validation + BBAN decomposition, BIC, VN/SEA non-IBAN rails (VietQR/NAPAS BIN), account-reuse pivot, mule-pattern signals |
| `fx-edge-appliance-recon.md` | Edge/VPN appliance fingerprint → CISA KEV/CVE catalog (Citrix/F5/Cisco/Ivanti/Forti/PAN/Exchange) + exposed-service port-risk matrix (Shodan InternetDB, passive-first) |
| `fx-saas-identity-recon.md` | SaaS tenancy + identity-fabric mapping — DNS-TXT tenancy tokens, IdP fingerprinting (Okta/Auth0/OneLogin/Ping/Keycloak/ADFS/Entra), unauthenticated API/GraphQL/OpenAPI-spec discovery |
| `dependency-audit.md` | Supply chain security: CVE audit, framework-specific vulns, typosquatting, CI/CD security |
| `disk-forensics.md` | Digital evidence analysis: image integrity, Sleuth Kit, file carving, artifact recovery, timeline |
| `incident-triage.md` | Security incident response: NIST 800-61 methodology, containment, evidence preservation, IOC extraction |
| `owasp-audit.md` | OWASP Top 10 (2021) source code audit with grep patterns and CWE references |
| `prompt-injection-audit.md` | AI/LLM security: prompt injection classes, agent/MCP security, permission boundary audit |
| `stealer-log-analysis.md` | Infostealer-log triage: family fingerprinting (RedLine/Vidar/StealC/Lumma/META/traffer), victim-vs-operator profiling, cross-log actor correlation, IOC + attribution extraction (`uv run` parser, raw artifacts shown) |
| `agent-browser.md` | Interactive browser collection & evidence capture via vercel-labs/agent-browser (CDP, accessibility-tree `@eN` snapshots, screenshots; primary interactive collector, complementary to Scrapling) |
| `phishing-domain-survival.md` | Registration/DNS strategy profiling — maliciously-registered vs **compromised** classification + takedown-survival outlook from WHOIS/DNS (`scripts/phish_domain_survival.py`, offline, zero-dep); eCrime 2026 "Built to Last?" |
| `clickfix-clipboard-hijack.md` | ClickFix / PasteJacking clipboard-hijack detection — clipboard-write + lure + OS-command co-occurrence, decodes PowerShell `-EncodedCommand` → C2 IOCs (`scripts/clickfix_detect.py`, offline, zero-dep); eCrime 2026 "PasteJacked" |
| `visibility-aware-html.md` | Visibility-aware HTML analysis — hidden credential forms / off-origin links / off-screen brand text a naive parser misses (`scripts/html_visibility_analysis.py`, offline, zero-dep); eCrime 2026 "Visibility-Aware HTML Analysis" |
| `apk-permission-scope.md` | APK permission-scope risk scoring — dangerous-permission combos (accessibility+overlay+SMS) = on-device-fraud capability; combination is the signal, capability≠guilt (`scripts/apk_permission_scope.py`, offline, zero-dep); eCrime 2026 "The 'Allow' Reflex" |
| `kit-template-attribution.md` | Phishing kit/template structural fingerprint + similarity → same-kit lineage; commodity-template match graded as noise, never auto-merged (`scripts/kit_template_fingerprint.py`, offline, zero-dep); eCrime 2026 tree-structured attribution |
| `renderer-confirmation.md` | Renderer-level confirmation of ClickFix + visibility — feeds runtime clipboard writes / computed-hidden elements into the static detectors and reconciles (`scripts/render_confirm.py`; renderer optional, degrades to a note); eCrime 2026 PasteJacked + Visibility-Aware HTML |
| `phishtrace-dynamic-features.md` | Runtime-trace phishing characterization — redirects / exfil endpoints / cloaking; exfil hosts are IOCs not attribution; thin trace on a flagged page = cloaked, never benign (`scripts/phishtrace_features.py`, offline, zero-dep); eCrime 2026 "PhishTrace" |

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

### Conversational domain table — show this in chat on every collection turn (CRITICAL)

Whenever a collection command (`/cti`, `/case`, `/sweep`, `/webpivot`, `/subdomain`, or the
pipeline) returns one or more domains, the reply's **first** element — before any prose — is a
markdown table summarizing each domain, so the operator sees the yield at a glance **in the
conversation**. The §8 file exports are the durable record; this table is the live view and is
never skipped, even for a single domain.

| Domain | Resolves | Top pivots | Risk | Cluster / peers | Seen before |
|---|---|---|---|---|---|
| `site-a.example` | ✓ | `favicon:123456789` · `G-XXXXXXXXXX` | NRD, BPH | 3 peers | CASE-0001 (Operator A) |
| `site-b.example` | ✓ | `registrant@example.com` | — | 3 peers | new |

Columns: **Resolves** ✓/✗ (collector got a host); **Top pivots** the 1–3 highest-rung indicators
(§2.5 ladder) as `kind:value`; **Risk** the `risk_signals` flags (NRD / BPH / money-trail, or `—`);
**Cluster / peers** shared-indicator peer count from the KB; **Seen before** the prior case +
operator from `/recall`, or `new`. Keep to these columns — detail goes in the prose below. One row
per domain; for a large sweep show the top 20 by risk and note how many rows were omitted.

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

**The default set is unredacted** — it is the analyst's working record. A shareable variant is
**opt-in**, never automatic, so nothing is ever quietly weakened. Request it with
`/redact` or `/case … --redact`:
```bash
S="$SKILL_DIR/scripts"; R="CTI-REPORT-[CASE-ID]-[YYYY-MM-DD]"
for f in md json csv; do
  uv run "$S/redact.py" "$R.$f" -o "$R.redacted.$f" --map "$R.map.json"
done
```
One `--map` across all three files keeps a selector's placeholder identical everywhere.
Infrastructure (URL/domain/IP) stays visible even then — in a CTI report the actor's
infrastructure is the analysis, not incidental PII; add `--all-types` to cover it too.
**Never ship the `.map.json`** — it reverses the redaction.

- **`--yolo`:** save the five-format default set with no prompt.
- **Interactive mode:** save the default set, then ask the user at the end whether they also want **DOCX** (Word) or **PDF**.
- **DOCX is NOT in the default set** (heaviest, most failure-prone toolchain). Generate it on request (`/report docx`) or automatically for `/report legal` (evidentiary, where a fixed Word/PDF artifact is expected). HTML **"Print → Save as PDF"** covers most PDF needs for free.
- Explicit machine-format subcommands always emit that format directly: `/report json`, `/report csv`, `/report ioc`.
- **Dash normalization (MANDATORY — covers every deliverable).** Em/en dashes (—, –) read as machine-authored, so no export may ship them. Two layers guarantee this: (1) the HTML, DOCX and pandoc PDF/DOCX generators normalize their prose automatically via `scripts/cti_text_normalize.py`; (2) for the on-disk **Markdown and JSON** deliverables — which no generator rewrites — run the normalizer in place as the final step before confirming files:
  ```bash
  S="$SKILL_DIR/scripts"; R="CTI-REPORT-[CASE-ID]-[YYYY-MM-DD]"
  uv run "$S/cti_text_normalize.py" "$R.md" "$R.json"   # rewrites — → - in place; no-op if clean
  ```
  Prefer writing plain `-` while drafting so this step is a no-op. It rewrites only when a dash is present and is safe for .md/.json/.csv alike (typographic dashes occur only inside string content, never in structural syntax).

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
| Intel backend | `connectors/intel-backend.md` | **Optional** persistent KB + cross-case correlation via the `intel_engine` engine (MCP/CLI). Absent → stateless as normal. Enables `/backend`, `/kb`, `/recall`, `/binary` |
| **ChongLuaDao** ⭐ | `connectors/chongluadao-api.md` | **First-party** premium connector (`scripts/cld/cld_api.py`) — IoC/denylist/breach/data-leak/AI/feeds. Enables `/cld`; upgrades `/scam-check`,`/threat-check`,`/phone`,`/breach-deep`,`/email-deep`,`/email-hygiene`,`/vuln-check`,`/impersonate`. Needs `CHONGLUADAO_API_KEY` |

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
│   ├── china-recon.md          ICP filings, PRC registries, CN cyberspace engines, CJK variants
│   ├── fiat-payment-osint.md   IBAN/BIC/bank accounts as selectors, VN-SEA rails
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
│   ├── iban_analyze.py              IBAN validate + decompose (ISO 13616/7064) → bank code, risk signals (PEP 723, zero-dep)
│   ├── phish_domain_survival.py     Phishing-domain registration/DNS profiling → maliciously-registered vs compromised + survival outlook (PEP 723, zero-dep)
│   ├── clickfix_detect.py           ClickFix / PasteJacking clipboard-hijack detector + `-enc` decode → C2 IOCs (PEP 723, zero-dep)
│   ├── html_visibility_analysis.py  Visibility-aware HTML analysis — hidden credential forms / off-origin links / off-screen text (PEP 723, zero-dep)
│   ├── apk_permission_scope.py      APK permission-scope risk scoring (BinaryPivot ext) — combo-based on-device-fraud capability; UTF-8/UTF-16 AXML decode (PEP 723, zero-dep)
│   ├── kit_template_fingerprint.py  Phishing kit/template structural fingerprint + similarity + commodity-trap grading (PEP 723, zero-dep)
│   ├── render_confirm.py            Renderer-level confirmation — reconciles static + rendered ClickFix/visibility evidence (PEP 723; optional Playwright/agent-browser)
│   ├── phishtrace_features.py       PhishTrace dynamic-feature characterization from a runtime trace → verdict + exfil IOCs (PEP 723, zero-dep)
│   ├── cld/cld_api.py               ChongLuaDao premium API client — IoC / denylist / breach + full data-leak module (async jobs) / AI URL analysis / STIX-MISP feeds (PEP 723 / `uv run`, zero-dep, X-API-Key)
│   ├── redact.py                    Reversible PII redaction — stable placeholders + exportable map; md/json/csv (PEP 723, zero-dep)
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
│   ├── analytic-standards.md    Likelihood bands, 5W1H coverage overlay, ACH (competing hypotheses)
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
| `phish-domain-survival` (registration/DNS class) | — | ✅ | ✅ | — | — | — |
| `clickfix-detect` (page clipboard-hijack) | — | ✅ | ✅ | — | — | — |
| `html-visibility` (hidden-content evasion) | — | ✅ | ✅ | — | — | — |
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
| **`/hash-id`** | Automatically on **every** discovered hash, and always **before** `/hash`. Decides file hash (→ MalwareBazaar/VT) vs credential material (→ `/breach-deep`, never a public service). 64-hex is queued for both the cert-fingerprint and file-hash readings, since it is genuinely ambiguous. | Acquire → Enrich |
| **`/redact`** | **Opt-in, not automatic** — pass `--redact` (or run `/redact` later). Emits `REPORT.redacted.{md,json,csv}` + `REPORT.map.json` alongside the unredacted set. A redacted report is a *weaker* artifact, so producing one stays a deliberate choice. | Deliver |

Registries needing mainland egress (TianYanCha/QCC/Aiqicha) are logged as **collection gaps**,
never blockers ([`techniques/china-recon.md`](techniques/china-recon.md) §7). Non-IBAN rails
(VN transfer, VietQR/NAPAS BIN, card BIN, e-wallet) follow
[`techniques/fiat-payment-osint.md`](techniques/fiat-payment-osint.md) §4.

**Flags:** `--no-cn` skips `/icp`+`/cn-corp` (both run by default). `--redact` *adds* the
redacted variant (off by default).

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
  infra), `reach=exhaustive` (pivot till the frontier empties), **`autonomy=auto`** — the loop
  **runs to closure unattended**, no per-depth approval prompts. Depth summaries are still
  printed as they happen, so the expansion stays auditable. Safety caps: `max_nodes=500`,
  `max_depth=6`.
- **Gating** (reuses [`analysis/auto-branch-rules.md`](analysis/auto-branch-rules.md)):
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
- **Control flags** (all *narrowing* — the defaults are already maximal):
  `/case <t> --passive|--passive-first`, `--reach balanced|focused`,
  **`--checkpoint`** (pause for approval after each depth level), `--depth N`, `--budget N`,
  `--authorization unconfirmed` (re-hold PII), `--no-cn`; `--redact` opts *in* to the redacted variant.
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
| CLIs — maigret, sherlock-project, holehe, h8mail, waymore, xeuledoc | `uv tool install <pkg>` | `pipx install <pkg>` |
| Libraries — cloudscraper, oletools, whoisdomain, scrapling | `uv pip install --python <venv> <pkg>` | `<$PY> -m pip install <pkg>` |
| Scrapling headless | `uv tool install "scrapling[fetchers]"` then `scrapling install` | `<$PY> -m pip install "scrapling[fetchers]"` then `scrapling install` |
| AgentFlow | `uv pip install --python <venv> --no-deps agentflow` | `<$PY> -m pip install --no-deps agentflow` |
| Git-only — theHarvester, msftrecon, blackbird, sharetrace | `uv tool install "git+https://…/theHarvester.git"` · `uv pip install "git+https://…/msftrecon.git"` · clone + `uv pip install -r requirements.txt` | `pipx install "git+https://…"` · clone + `<$PY> -m pip install -r requirements.txt` |
| **Run a generator script** | `uv run <script.py> ARGS` (deps auto via inline metadata) | `<$PY> <script.py> ARGS` |

`<$PY>` = `py` (Windows) / `python3` (macOS/Linux), or the venv python. On PEP-668 Linux add `--break-system-packages` to the pip fallback.

**System binaries — OS package manager** (uv does not manage these):

| Tool(s) | Windows | macOS | Linux |
|---------|---------|-------|-------|
| git, gh, jq, exiftool, pandoc, poppler/pdfinfo, qpdf, whois | `winget install <Id>` | `brew install <pkg>` | `sudo apt install -y <pkg>` |
| Go toolchain | `winget install GoLang.Go` | `brew install go` | `sudo apt install -y golang` |
| mat2 (metadata strip) | n/a → `exiftool -all= -overwrite_original <file>` | `brew install mat2` | `sudo apt install -y mat2` |
| **agent-browser** (interactive browser) | `npm i -g agent-browser` or `cargo install agent-browser` → `agent-browser install` | `brew install agent-browser` → `agent-browser install` | `npm i -g agent-browser` (or `cargo install`) → `agent-browser install` |

**Go tools** (after Go is present — identical on all OSes): `go install <module>` for subfinder, amass, gau, gitleaks, httpx. PhoneInfoga and TruffleHog → GitHub release binary per OS/arch (`go install` rejects TruffleHog's module for its `replace` directives; the PyPI `trufflehog` is the abandoned v2 Python tool and does not accept v3 syntax). **ASN** → Git Bash/WSL `bash <(curl -sL …/nitefood/asn/master/asn)` on Windows, native bash on macOS/Linux, or RDAP/ipwho.is HTTP fallback.

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
