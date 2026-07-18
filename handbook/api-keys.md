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
| **DNS / certs / WHOIS** ||||
| SecurityTrails | `SECURITYTRAILS_API_KEY` (+`_FALLBACK`) | freemium | `/webpivot`,`/dns-history`: passive DNS, subdomains, DNS/WHOIS history | securitytrails.com |
| WhoisXML | `WHOISXML_API_KEY` | freemium | `/webpivot --whois`,`/whois`: current + historic + reverse WHOIS | whoisxmlapi.com |
| SSLMate CertSpotter | `CERTSPOTTER_API_KEY` | free-tier | `/cert-history`,`/webpivot`: higher-rate CT lookups | sslmate.com/certspotter |
| ZoneCruncher/zetalytics | `ZONECRUNCHER_API_KEY` | freemium | `/webpivot`,`/dns-history`: liveDNS, reverse-email → domains | zonecruncher.com |
| **Analytics-ID pivot** ||||
| DNSLytics | `DNSLYTICS_API_KEY` | freemium | `/webpivot`: reverse AdSense (`ca-pub-`) / legacy GA (`UA-`) → sibling domains | dnslytics.com/api |
| **Breach / leak / darknet** ||||
| Hudson Rock | `HUDSONROCK_API_KEY` | freemium | `/breach-deep`,`/stealer-log`: infostealer-breach feed | hudsonrock.com |
| ChongLuaDao | `CHONGLUADAO_API_KEY` | free-tier | `/scam-check`,`/breach-deep`: VN phishing/scam + breach feed | chongluadao.vn |
| Intelligence X | `INTELX_API_KEY` | freemium | `/breach-deep`, darknet: dark-web/paste/leak selectors | intelx.io |
| **Code / repos** ||||
| GitHub token | `GITHUB_TOKEN` | free | `/github-osint`,`/secrets`: higher limits, repo/code discovery | github.com/settings/tokens |
| **Search-engine dorking** ||||
| SerpAPI | `SERPAPI_KEY` | freemium | `/dork-sweep`,`/query`: automated Google dork queries | serpapi.com |
| Bright Data SERP | `BRIGHTDATA_SERP_KEY` | paid | `/dork-sweep`: SerpAPI alternative + residential SERP | brightdata.com |

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
premium reverse-lookups — **Shodan** (favicon mmh3 → hosts), **Censys** (favicon MD5 → hosts),
**FOFA** (icon_hash + tracker body), **DNSLytics** (GA/AdSense → sibling domains),
**SecurityTrails** (passive DNS/subdomains), **urlscan PRO** (content search), **WhoisXML**
(reverse WHOIS). Each hit is attached to the pivot as `live_results` and shown inline in
`--leads`. See [`techniques/web-pivot.md`](../techniques/web-pivot.md) § Premium tier. No keys →
keyless mode, identical to before.

## Security

- The `.env` is `chmod 600` + gitignored — never commit it. On Windows, filesystem perms differ;
  the `.gitignore` entry is the primary safeguard.
- Prefer setting sensitive keys via the **environment** (or a secrets manager) on shared machines;
  env vars override the file and leave nothing extra on disk.
- `set … <KEY>` puts the key on the command line (shell history). Use `set <service>` with the
  value on **stdin** to avoid that: `printf %s "$KEY" | uv run "$AK" set shodan`.
