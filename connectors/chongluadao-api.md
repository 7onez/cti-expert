# ChongLuaDao Premium API — first-party threat-intelligence connector

ChongLuaDao (CLD) is cti-expert's **home organisation** (`chongluadao.vn`), so its premium
API is a **first-party** connector, not just another premium key. When
`CHONGLUADAO_API_KEY` is set it upgrades the scam/threat/phone/breach/whois/vuln/impersonation
commands with CLD's own datasets — a ~20-million-URL denylist, VN scam-phone and bank-account
reports, the full data-leak/breach corpus (with async bulk export), brand-protection lookalike
discovery, a deep AI URL analyzer, and CVE/KEV + threat-actor feeds. Keyless mode is unchanged;
every CLD call is strictly additive.

- **Client:** `scripts/cld/cld_api.py` (stdlib-only, `uv run`). One JSON envelope per call.
- **Key:** `X-API-Key` header only — never logged, never on the URL. Resolution: env var →
  skill-root `.env` → keyless. Accepted env names: `CHONGLUADAO_API_KEY`, `CLD_API_KEY`,
  `CHONGLUADAO_KEY`, `BURNER_API_KEY`.
- **Set it:** `uv run scripts/apikeys/apikeys.py set chongluadao <KEY>` · **test:**
  `uv run scripts/apikeys/apikeys.py test chongluadao` (🟢 valid / 🔴 invalid).

## Egress / opsec — what is actually provable

- **Provable (from `cld_api.py`):** the client opens connections to **only** `feeds.chongluadao.vn`
  and `api-ti.chongluadao.vn`. It never connects to the investigated target. So on a hostile
  scam funnel, your egress touches CLD, not the operator's infra.
- **Inferred (API behaviour, not client-verifiable):** for `checkurl` / `analyze` / `ioc url|ip`,
  CLD performs the target fetch and scoring **server-side** and returns the verdict + evidence
  (registration, reputation, threat feeds/reports observed in responses). Treat "CLD fetched it
  server-side" as a reasonable inference about the service, not something this repo can prove.

Net effect either way: CLD is the safe **first-touch verdict** on a live funnel before any
direct `/webpivot` fetch, and quieter than a world-readable urlscan submit.

> Still bound by the skill's opsec rules: CLD is a **lookup/verdict** service. It never uploads
> the case's own APK/installer/archive anywhere.

## Timeouts & failure handling

- **~83-minute ceiling.** Every call defaults to `--timeout 5000`; async jobs poll up to that
  budget. This is deliberate — premium data-leak/export searches are slow, and the point is to
  **get all the data** for pivoting, not to time out early. Lower it per call with
  `--timeout N` (placed **after** the subcommand).
- **403 / resource-404 → SKIP, not fail.** A forbidden endpoint (plan doesn't include that module)
  or a lookup that names the missing resource ("Victim not found.") returns immediately with
  `"skipped": true` and **exit 0**, so a `route`/batch continues. A 404 whose body is exactly
  `{"detail":"Not Found"}` is a route that no longer exists — that is an **error, exit 2**, so a
  removed endpoint can never pass silently as "not consulted". Other errors (timeout, 5xx, network)
  return `ok:false` exit 2 and the caller logs a collection gap and falls back to the keyless path.
- **`route` never burns a blind call.** It reuses `pivot_orchestrator.classify()`; an indicator
  with no CLD IoC endpoint (person, username, wallet, IBAN, …) is **skipped**, never POSTed to
  the metered `ioc/url`.

## Rate limits & quota posture

CLD charges **no per-call credit**, so no local spend gate applies (it runs under `--free-only`
and `no_spend`). Every key **is rate-limited**, though — the responses carry `X-RateLimit-*`
headers (observed 2026-10-20: Shield/TI **10/s · 100/min · 10,000/day**, Feeds **60/s**):

- **429 handling is built in.** A 429 whose exhausted window resets within ~65 s (second/minute)
  is waited out and retried inside the call budget, each attempt ledgered. A **day-window** 429 is
  returned at once with its reset time (`… day resets in Ns`) → log a gap, continue keyless.
- The envelope's `usage.rate_limit` shows the last `{second,minute,day}` snapshot per tier, so a
  long run can see its remaining daily budget.
- **Cheap & fast:** `checkurl`, `checkphone`, `whois`, `burner`, `onion`, `vulns/vuln`, `denylist`.
- **Slow — call deliberately:** `analyze` (AI), `ioc url/ip` (server-side fetch), `leaks`, the
  dataset searches (`machines`, `stolen-credentials`, `cookies`, `breaches`, `exposed-credentials`;
  ≈75 s server wait per page, results cached a day), and `full-export` (hours, polled once a minute).
- **Deduplicate through the case, not the API.** `route`'s classify-skip and the recall step
  (`/cti-recall`) keep you from re-querying the same seed and spending the 100/min window.

Each CLI/MCP request records one `chongluadao` usage row, including every `route` leg, async
start/poll and 429 retry, so a run's CALL count is auditable. `scripts/cld/references/cld_usage.json`
prices every endpoint at **0 units** — the ledger logs a call, never spend; the `usage` block shows
`billable_units: 0` and `basis: rate-limited`. (If the file is missing/malformed the loader falls
back to 1 unit — conservative over-report, never a silent free pass.)

## Two APIs, one client

| API | Base URL | What it serves |
|---|---|---|
| **Feeds** | `https://feeds.chongluadao.vn` | URL / phone / WHOIS / burner checks, denylist search, deep AI URL analysis |
| **Threat-Intel (Shield)** | `https://api-ti.chongluadao.vn` | IoC analyzers, Data-Leaks (incl. internal documents), Brand-Protection, ransomware victims, ClickFix / PhaaS / Telegram, Threat-Feeds, STIX/MISP/TAXII. Same `X-API-Key` as Feeds. |

## Subcommands (`uv run scripts/cld/cld_api.py <op> … [--timeout N] [--pretty] [--raw]`)

Parity: every path in the OpenAPI contract (`/api/v1/api-gateway/external/docs/<id>/openapi.json`,
78 operations, verified 2026-10-20) has an op, and every documented query/body parameter has a
flag. List endpoints take `--sort` (descending: `--sort=-<column>`, with `=`), `--limit`/`--offset`
(Threat Feeds, internal leaks) or `--page`/`--page-size` (Ransomware).

| Op | Endpoint | Notes |
|---|---|---|
| `route <target>` | both, by type | domain/url: Feeds `checkurl` + Shield IoC + ransomware + ClickFix + PhaaS + internal-leaks + defacements + underground-directory. A list row counts only when its host is the target (`hit`, `matched`). email: burner + IoC. phone: checkphone + IoC. `t.me/<handle>`: Telegram posts **and** actor-channels. hash/ip/asn: IoC only. `bank:<digits>` (or `stk:`): VN bank-account IoC → `account_holder_name` + `bank_name` (prefix required — bare digits are a phone). |
| `checkurl <url>` | POST feeds `/external/checkurl` | verdict `safe`/`malicious`/`no result` vs ~20M denylist+allowlist |
| `analyze <url> [--lang en\|vi] [--fresh]` | GET feeds `/api/v1/analyze-deep` | deep AI: `risk_score` 1–10 + `key_findings` |
| `denylist <search> [--type][--status][--page][--limit]` | GET feeds `/external/denylists/search` | search denylist → sibling scam URLs (campaign clustering) |
| `checkphone <q>` / `whois <q>` / `burner <q>` | GET feeds `/external/check{phone,whois,burneremail}` | VN scam-phone / WHOIS / disposable-email |
| `ioc <type> <value> [--ai]` | POST ti `/api/v1/ioc/external/<type>` | verdict + evidence; types `email password url ip phone bank-account hash asn`. `url` returns `data.registration` (registrar, dates, status, nameservers — any TLD), `domain_reputation`, `threat_matches`, `threat_reports`; `bank-account` returns the reported holder name + bank. |
| `leaks <query> [--input-type]` | POST ti `.../data-leaks/external/search` | one preview across every leak dataset: each block has `status` (`complete`/`partial`/`pending`/`unavailable`/`unsupported`), `total` and up to 3 examples. A kind still `pending` after the ≈20 s aggregate wait is settled on its own dataset endpoint (as the API documents) and that block replaces it. |
| `machines` / `stolen-credentials` / `cookies` / `breaches` / `exposed-credentials <query> [--input-type] [--limit] [--page] [--one-page]` | POST ti `.../<dataset>/search` | one dataset. The default follows the opaque `next` cursor until the dataset ends; `--page` only chooses the start, `--one-page` stops after that page. Body is `query` + `input_type` + `limit` (≤100) + `next`. `input_type`: `auto email domain ip username keyword password pc_name url`. |
| `full-export <query>` | POST ti `.../full-export/start` → GET `.../full-export/poll/{id}` | **async job, hours** — polled once a minute; `completed` carries `download_url` for a `.zip` of `records.jsonl` + `records.csv` (`credential`/`cookie`/`pii` rows, with `device_id`, `stealer_family`, `malware_path`) |
| `internal-leaks <search> [--severity]` / `internal-leak <id>` | GET ti `/data-leaks/external/internal-leaks` | leaked internal documents; the single record carries unmasked content |
| `brand-domains [--where F:OP:V]… [--field F]… [--group-by F]… [--order-by F[:desc]]… [--limit][--offset]` | POST ti `/brand-protection/external/domains` | lookalike domains for **this account's** brands. SQL-like: operators `eq ne gt gte lt lte in contains starts_with ends_with is_empty is_not_empty` (`in` takes a comma list), AND-ed; `--group-by` returns `records_count` per group. Items carry `artifacts` (screenshots, favicon, html, markdown URLs). |
| `brand-domain <id>` | GET ti `.../domains/{id}` | one domain record |
| `vulns [--q][--severity][--vendor][--product][--kev][--since][--until]` / `vuln <cve>` | GET ti `/threat-feeds/.../vulnerabilities` | CVE feed; `--kev` = known-exploited only |
| `actors [--q][--type][--attack-type][--channel-platform]` / `actor <id>` | GET ti `.../threat-actors` | threat-actor directory and one profile (all channels) |
| `actor-usernames <q> [--forum]` / `actor-channels [--q][--platform][--status]` | GET ti `.../threat-actor-usernames`, `.../actor-channels` | map a handle to a tracked actor, or a channel (forum/Telegram/Discord/market). `actor-channels --q` matches the **actor name**. |
| `incidents [--q][--category][--severity][--country][--actor][--network][--since][--until]` / `incident <id>` | GET ti `.../incidents` | dark-web incident intel; the single record adds `iocs` (domains/ips/hashes/emails) and `mitre` tactics/techniques |
| `c2 [--q]` / `c2-get <id>` · `lolbin [--q][--platform][--category]` / `lolbin-get <id>` | GET ti `.../c2-frameworks`, `.../living-off-the-land` | C2 frameworks (network IOCs, detection ideas, related repos); LOLBins with MITRE ids |
| `defacements [--q][--country][--since][--until]` / `defacement <id>` | GET ti `.../defacements` | archived defacements (attacker, team, target IP/server) |
| `underground [--q][--category][--subcategory][--tld]` / `underground-categories` | GET ti `.../underground-directory` | curated forums/markets/hosting/anti-detect directory |
| `seized-markets --q` · `onion <hostname>` | GET ti `.../seized-markets`, `.../onion-blocklist/check` | LE takedown banners; `.onion` abuse-blocklist check |
| `clickfix [--q][--country][--status]` / `clickfix-get <id>` · `phaas [--q][--country][--family][--tag]` / `phaas-get <id>` | GET ti `/threat-feeds/external/...` | ClickFix lures (`status`: malicious captcha clipboard compromised nsfw; clipboard payload) and PhaaS hosts (kit `families`, `tags`) |
| `telegram [--q][--handle][--channel-id]` / `telegram-channels [--limit]` | GET ti `.../telegram/...` | intercepted posts, monitored channels |
| `tf-stats <view> [--limit][--days]` | GET ti `/threat-feeds/external/stats/<view>` | `summary`, `vulnerabilities/by-severity`, `vulnerabilities/top-vendors`, `vulnerabilities/timeline`, `defacements/monthly`, `defacements/by-country`, `actors/by-type` |
| `ransomware <q> [--group][--country][--sector][--year][--month][--sort][--order][--page][--page-size]` / `ransomware-victim <id>` | GET ti `/ransomware/external/victims` | victims published by a ransomware group, with leak-site screenshot URL |
| `ransomware-stats` / `ransomware-monthly` / `ransomware-by-{country,sector,group}` / `ransomware-groups --q` / `ransomware-group <name>` / `ransomware-press --q` / `sec-filings --q\|--ticker` / `decryptors --q\|--group` | GET ti `/ransomware/external/...` | counts, group profiles (TTPs; alias-tolerant name), press, SEC 8-K filings, public decryptors |
| `feed <stix2\|misp\|stix1> [--limit][--type][--observed-after][--next][--all][--correlate]` | GET ti `/ioc/external/feeds/...` | CLD indicator feed; pages via the `X-Next` header (envelope `next`; stderr under `--raw`). `--all` follows every page and merges one loadable STIX bundle / MISP event (JSON formats only). `--type`: `asn cidr cve domain email hostname ip ip:port ja3 md5 sha1 sha256 ssl_fingerprint url`. |
| `taxii2` / `taxii2-root` / `taxii2-collections` / `taxii2-collection indicators` | GET ti `/ioc/external/taxii2/...` | TAXII 2.1 discovery, API root, collections (`indicators` is the only one) |
| `taxii2-objects indicators` / `taxii2-manifest indicators [--limit][--next][--type][--added-after][--all]` | GET ti `.../collections/indicators/{objects,manifest}` | STIX objects / manifest in a TAXII envelope; `--all` follows `next` while `more` |
| `taxii1` / `taxii1-poll indicators [--limit][--next][--type][--observed-after]` | GET ti `/ioc/external/taxii1/...` | legacy TAXII 1.x XML |
| `webhooks [--module]` / `webhook <id>` / `webhook-deliveries <id> [--limit]` | GET ti `/api/v1/webhooks` | this account's subscriptions and delivery log |
| `webhook-create <https-url> [--name][--module M]…[--secret]` / `webhook-update <id> [--url][--name][--module]…[--secret][--active\|--paused]` / `webhook-delete <id>` / `webhook-test <id> [--simulate][--event-type][--payload JSON]` | POST/PATCH/DELETE ti `/api/v1/webhooks…` | **account-mutating** — push real-time findings (data leaks, impersonation, threat feeds, ransomware) to your receiver. Deliveries are signed: `X-Signature: sha256=HMAC(secret, "t=<X-Timestamp>." + raw body)`; reject a timestamp older than 300 s. |
| `probe` | GET feeds `/external/checkburneremail` | fast key-validity check |

Envelope (every op): `{"tool":"chongluadao","op","input","ok","status","skipped","result","error"}`.
Exit: `0` ok **or** skipped(403/404/unsupported) · `2` other error · `3` no key.

## Where it plugs into the AEAD flow

| Phase | CLD calls | Feeds into |
|---|---|---|
| **Acquire** | `route`/`ioc *`, `checkurl`, `analyze`, `checkphone`, `whois`, `ioc bank-account`, `vulns/vuln` | `/scam-check`, `/threat-check`, `/phone`, `/webpivot --whois`, `/iban`, `/vuln-check`, `/appliance-scan` |
| **Enrich** | `denylist`, `brand-domains`, `ioc email`, `breaches`, `leaks`, dataset searches, `full-export` | `/impersonate`, `/email-deep`, `/breach-deep`, `/stealer-log` |
| **Assess** | `analyze` risk_score, `ioc` verdicts, `actors`, `onion` | `/exposure`, `/threat-model`, `/verify-finding` |
| **Deliver** | `feed stix2` + `feed misp` (**default when keyed**) | IOC bundle — attached as companion artifacts (see below) |

### Deliver: STIX/MISP feed attach (default when keyed)

At Deliver, when `CHONGLUADAO_API_KEY` is set, the IOC-bundle step **also** pulls the CLD
premium indicator feed and writes it beside the bundle:

```bash
uv run scripts/cld/cld_api.py feed stix2 --raw --observed-after <case-start> > IOC-<case>.cld.stix.json
uv run scripts/cld/cld_api.py feed misp  --raw --observed-after <case-start> > IOC-<case>.cld.misp.json
# --raw emits the loadable STIX-bundle / MISP body (no tool envelope); on non-2xx it writes
# NOTHING to stdout (skip silently — the redirect file stays empty and can be discarded).
# One call is ONE page (≤1000 indicators); the X-Next cursor goes to stderr. Add --all to follow
# every page into one merged bundle — bounded by --observed-after, otherwise it is the whole feed.
```

These ship **as companion artifacts referenced by the report**, never merged into the case
graph — the feed is CLD's org-wide curated IOC set, so folding it into the case's own
`indicators[]` would manufacture false same-operator edges. Skip-on-error; log a gap, don't block.

## Clustering discipline (CRITICAL)

- A CLD **verdict** (`malicious`/`safe`) is *reputation*, not a same-operator edge.
- The **`denylist` search** is the clusterable primitive: entries sharing a `targeted_brand`,
  `domain`, or description are candidate campaign siblings — run `/cti-pivot` on each and
  corroborate on the pivot-priority ladder (§2.5) before asserting one operator.
- **breach/leak/exposure + the imported feed = EXPOSURE, not attribution.** Two addresses in one
  combolist share victims, not an operator. Never turn a leak/feed co-occurrence into a cluster edge.
- Run `/reference check` on any CLD indicator before it becomes an edge (§2.5 false-positive control).

## Latency

`checkurl`/`checkphone`/`whois`/`burner`/`vulns`/`onion` <5 s. `analyze` and `ioc url/ip` ~10–30 s.
`leaks`/`breaches`/dataset searches and `full-export` can take minutes to hours — hence the ~83-min
ceiling. On any error the call degrades to the keyless path for that command; log a gap, never block.
