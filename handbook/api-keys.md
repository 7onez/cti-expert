# API Keys — Premium/Pro Tier (`/apikeys`)

cti-expert runs **keyless/free by default** and always will. Premium API keys are
**strictly additive**: they upgrade existing techniques (higher rate limits, reverse-lookup
endpoints, richer feeds) and never gate the keyless path. `/apikeys` is the single control
surface. Tool: `scripts/apikeys/apikeys.py`; catalog: `scripts/apikeys/registry.json`.

## Key store

- **File:** the skill-root `.env` → `$SKILL_DIR/.env` (`~/.claude/skills/cti-expert/.env`),
  written `chmod 600` and **gitignored**. Override the location with `CTI_API_KEYS_ENV`.
- **Resolution order (everywhere):** OS **environment variable first**, then the `.env`, then
  keyless. An env var always overrides the file.
- **Values are always masked** in output (only length + last 2 chars). The plaintext key is
  never printed. Never commit the `.env`.

## The `/apikeys` command

```bash
AK="$SKILL_DIR/scripts/apikeys/apikeys.py"
uv run "$AK"                       # status (default): which keys are set + what they unlock
uv run "$AK" status --all          # include every supported service + how to get a key
uv run "$AK" set shodan <KEY>      # store a key (accepts service id OR the ENV_VAR name)
uv run "$AK" set shodan            # read the value from stdin (avoids it on the command line)
uv run "$AK" unset shodan          # remove a key
uv run "$AK" test [shodan]         # live-probe validity of one/all keys that have a probe
uv run "$AK" unlocks               # list the capabilities your current keys unlock
uv run "$AK" path                  # print the .env path + permissions
```

`test` reports `🟢 valid` / `🔴 invalid` (401/403) / `🟠 error` / `⚪ no-test`.

## Supported services

Keyless equivalents exist for most of these (crt.sh, anonymous urlscan, free Shodan web, etc.);
the key unlocks the higher-tier or reverse-lookup capability noted.

| Service | Env var | Tier | Unlocks in cti-expert | Get a key |
|---|---|---|---|---|
| **Infrastructure / host search** ||||
| Shodan | `SHODAN_API_KEY` | freemium | `/webpivot`: reverse favicon **mmh3** → hosts; host/service intel | account.shodan.io |
| Censys | `CENSYS_API_KEY` (+`CENSYS_ORG_ID`) | freemium | `/webpivot`: reverse favicon **MD5** → hosts; cert + host search | accounts.censys.io |
| FOFA | `FOFA_KEY` (+`FOFA_EMAIL`) | freemium | `/webpivot`: reverse `icon_hash` + tracker body → hosts; IP reverse | fofa.info |
| urlscan.io PRO | `URLSCAN_API_KEY` | freemium | `/webpivot`,`/scam-check`: authenticated DOM search, related domains, submit | urlscan.io/user/apikey |
| Hunter.how | `HUNTERHOW_API_KEY` | freemium | `/webpivot`,`/cert-pivot`: independent CN cyberspace index — reverse favicon **mmh3** / cert / `web.body` / domain / IP → hosts (a FOFA/Quake/ZoomEye peer) | hunter.how/search-api |
| Quake (360) | `QUAKE_API_KEY` | freemium | `/webpivot`: reverse favicon **mmh3** → hosts; independent CN-dense cyberspace index (FOFA/Hunter.how peer) | quake.360.net |
| ZoomEye | `ZOOMEYE_API_KEY` | freemium | `/webpivot`: reverse favicon **iconhash (mmh3)** → hosts; independent cyberspace index | zoomeye.ai/profile |
| **DNS / certs / WHOIS** ||||
| SecurityTrails | `SECURITYTRAILS_API_KEY` (+`_FALLBACK`) | freemium | `/webpivot`,`/dns-history`: passive DNS, subdomains, DNS/WHOIS history | securitytrails.com |
| WhoisXML | `WHOISXML_API_KEY` | freemium | `/webpivot --whois`,`/whois`: current + historic + reverse WHOIS | whoisxmlapi.com |
| SSLMate CertSpotter | `CERTSPOTTER_API_KEY` | free-tier | `/cert-history`,`/webpivot`: higher-rate CT lookups | sslmate.com/certspotter |
| ZoneCruncher/zetalytics | `ZONECRUNCHER_API_KEY` | freemium | **not scripted** — no code sends this key and no run queries it; reverse-email→domains is covered by Validin + WhoisXML. Listed for key-inventory completeness | zonecruncher.com |
| **Analytics-ID pivot** ||||
| DNSLytics | `DNSLYTICS_API_KEY` | freemium | `/webpivot`: reverse AdSense (`ca-pub-`) / legacy GA (`UA-`) → sibling domains | dnslytics.com/api |
| **Breach / leak / darknet** ||||
| Hudson Rock | `HUDSONROCK_API_KEY` | freemium | `/breach-deep`,`/stealer-log`: infostealer-breach feed | hudsonrock.com |
| **ChongLuaDao** ⭐ | `CHONGLUADAO_API_KEY` | premium | **first-party** — `/cld`,`/scam-check`,`/threat-check`,`/phone`,`/breach-deep`,`/email-deep`,`/vuln-check`,`/impersonate`,`/webpivot --whois`: URL/IP/hash/email/phone/bank IoC verdicts (server-side + passive), 20M-URL denylist search, data-leak/breach exposure, deep AI URL analysis, brand lookalikes, CVE/KEV feeds. See [`connectors/chongluadao-api.md`](../connectors/chongluadao-api.md) | chongluadao.vn |
| Intelligence X | `INTELX_API_KEY` | freemium | `/breach-deep`, darknet: dark-web/paste/leak selectors | intelx.io |
| GrayHatWarfare | `GRAYHATWARFARE_API_KEY` | freemium | `/secrets`,`/docleak`: open S3/Azure/GCS/Spaces buckets + exposed files by keyword/domain — **EXPOSURE, not a same-operator pivot** | grayhatwarfare.com/account |
| ANY.RUN | `ANYRUN_API_KEY` | freemium | `/anyrun`,`/binary`: TI Lookup over prior detonations — a packed sample's runtime endpoints (never submits a sample) | app.any.run/profile |
| **Code / repos** ||||
| GitHub token | `GITHUB_TOKEN` | free | `/github-osint`,`/secrets`: higher limits, repo/code discovery | github.com/settings/tokens |
| **Search-engine dorking** ||||
| SerpAPI | `SERPAPI_KEY` | freemium | `/webpivot --serp`: Google Ads Transparency (VERIFIED paying-advertiser identity behind a domain's ads) + SERP ads. **Does NOT power `/dork-sweep` or `/query`** (that engine is keyless) | serpapi.com |
| Bright Data SERP | `BRIGHTDATA_SERP_KEY` | paid | `/dork-sweep`: SerpAPI alternative + residential SERP | brightdata.com |
| **AI / vision** ||||
| Google Gemini | `GEMINI_API_KEY` | freemium | `media-vision-analysis` (multix, `npx @mrgoonie/multix`): image OCR + sign/landmark/logo/face read, structured selector extraction, A/V transcription | aistudio.google.com/apikey |

> **⭐ ChongLuaDao is the first-party key.** cti-expert is built by chongluadao.vn, so a CLD
> premium key is the single highest-leverage upgrade: it adds first-party VN scam/phishing
> verdicts and breach/exposure data across the scam, threat, phone, breach, whois, vuln and
> impersonation commands, and its `checkurl`/`analyze`/`ioc url` calls run **server-side +
> passive** (the analyst's egress never touches the target). Entry point `/cld <target>`; full
> catalog + AEAD placement in [`connectors/chongluadao-api.md`](../connectors/chongluadao-api.md).

> **Certificate Transparency is free.** CT lookups never require payment: **crt.sh** works with
> no key at all (it's just often slow/overloaded). The optional `CERTSPOTTER_API_KEY` (SSLMate) is a
> *reliability + rate-limit* upgrade — a faster, more reliable CT endpoint used as a crt.sh
> **fallback**; CertSpotter's free tier also works keyless at a low rate. You never need a key to
> query CT.

`registry.json` is the machine-readable source of truth (`apikeys.py` reads it). Keep the two
in sync when adding a service.

## How premium keys upgrade the infra pivot

When keys are present, `pivot_extract.py`'s live-enrichment (`enrich_live`) automatically
escalates from the keyless baseline (crt.sh, HackerTarget passive DNS, anonymous urlscan) to
premium reverse-lookups — **Shodan** (favicon mmh3 → hosts; **cert-SHA1 / JARM search**, Membership-
gated, degrades to a named skip), **Censys** (favicon MD5 → hosts; lookups on Free; **one case-level
cert search** over the estate's leaf-cert SHA-256s, run unless the case already recorded the plan as
`free` — the search is its own probe), **FOFA** (icon_hash + tracker body), **Hunter.how**
(favicon/body/domain → hosts, independent CN index), **Quake**/**ZoomEye** (favicon mmh3 → hosts),
**DNSLytics** (GA/AdSense → sibling domains; **reverse-IP** on the origin under its own key, routed
through the co-tenancy filter — bulk hosting is a lead, never a seed), **SecurityTrails** (subdomains;
**DNS history** → dated hosting eras on the timeline; **DSL reverse-WHOIS** for the CURRENT registrant
e-mail, diffed against WhoisXML; capped per CASE at `SECURITYTRAILS_MAX_CALLS_PER_CASE`, default 20
of the 50/month Free key), **urlscan PRO** (content search; **hostname lifecycle** — pre-registration
NS/A eras, left-censored when the walk is truncated; verdict rows), **WhoisXML** (reverse WHOIS;
**WHOIS history** is explicit opt-in — `--whois-history purchase`, seeds/cluster members only, ~50 DRS
per domain; the render path never buys it), **IntelX** (auto-fires in `pipeline open`; in the loop
only under `--full`; a selector is searched once per CASE), **GrayHatWarfare** (an exposure lead per
apex, never a same-operator pivot).

Two cross-cutting rules. **Entitlement is measured, not assumed:** free account probes (urlscan
quotas, Netlas plan, SecurityTrails/DNSLytics usage, IntelX `/authenticate/info`, Validin
`/api/paths`) fill `meta.capability.plans` once per case (`cases/<id>/capability_plans.json`); a key
measured `free` on urlscan skips the Pro calls that would 403. **Bought once per case, not once per
host:** the collector runs one process per host, so per-origin reverse-IP verification, IntelX
selectors, SecurityTrails reverse-WHOIS terms and the Censys cert search are memoised on disk under
the case (`mo_neighbours/`, `intelx/`, `securitytrails/`, `censys_search.json`). Each hit is attached
to the pivot as `live_results` and shown inline in `--leads`. See
[`techniques/web-pivot.md`](../techniques/web-pivot.md) § Premium tier. No keys → keyless mode,
identical to before; `--free-only` / a `no_spend` posture keeps every metered leg off.

## Security

- The `.env` is `chmod 600` + gitignored — never commit it. On Windows, filesystem perms differ;
  the `.gitignore` entry is the primary safeguard.
- Prefer setting sensitive keys via the **environment** (or a secrets manager) on shared machines;
  env vars override the file and leave nothing extra on disk.
- `set … <KEY>` puts the key on the command line (shell history). Use `set <service>` with the
  value on **stdin** to avoid that: `printf %s "$KEY" | uv run "$AK" set shodan`.
