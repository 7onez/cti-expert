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

- **30-minute ceiling.** Every call defaults to `--timeout 1800`; async jobs poll up to that
  budget. This is deliberate — premium data-leak/export searches are slow, and the point is to
  **get all the data** for pivoting, not to time out early. Lower it per call with
  `--timeout N` (placed **after** the subcommand).
- **403 / 404 → SKIP, not fail.** A forbidden endpoint (plan doesn't include that module) or a
  not-found lookup returns immediately with `"skipped": true` and **exit 0**, so a `route`/batch
  continues to the next indicator instead of aborting. Other errors (timeout, 5xx, network)
  return `ok:false` exit 2 and the caller logs a collection gap and falls back to the keyless path.
- **`route` never burns a blind call.** It reuses `pivot_orchestrator.classify()`; an indicator
  with no CLD IoC endpoint (person, username, wallet, IBAN, …) is **skipped**, never POSTed to
  the metered `ioc/url`.

## Rate limits & quota posture

CLD publishes no per-endpoint quota in the OpenAPI spec, and the premium key is metered by
account, so treat it as a **paid, finite** resource:

- **Cheap & safe to spam:** `checkurl`, `checkphone`, `whois`, `burner`, `onion`, `vulns/vuln`,
  `denylist` (fast, keyed, low cost). Use freely during Acquire.
- **Expensive / slow — call deliberately:** `analyze` (AI), `ioc url/ip` (server-side fetch),
  `exposure`, `leaks`, `breaches`, the dataset searches, and especially the async
  `leaked-accounts` / `devices` / `full-export` jobs. Prefer one well-formed query over spraying.
- **Deduplicate through the case, not the API.** `route`'s classify-skip and the recall step
  (`/cti-recall`) keep you from re-querying the same seed. A 429 or a quota rejection surfaces as
  a non-2xx error → log a gap, back off, continue keyless; never hammer-retry.

## Two APIs, one client

| API | Base URL | What it serves |
|---|---|---|
| **Feeds** | `https://feeds.chongluadao.vn` | URL / phone / WHOIS / burner checks, denylist search, deep AI URL analysis |
| **Threat-Intel** | `https://api-ti.chongluadao.vn` | IoC analyzers, full Data-Leaks module (incl. async jobs), Brand-Protection, Threat-Feeds (CVE/KEV, actors, onion), STIX/MISP/TAXII feeds |

## Subcommands (`uv run scripts/cld/cld_api.py <op> … [--timeout N] [--pretty]`)

| Op | Endpoint | Notes |
|---|---|---|
| `route <target>` | auto | classify → best call (cve/onion/asn/email/hash/ip/phone/domain-url); the `/cld` entry point |
| `checkurl <url>` | POST feeds `/external/checkurl` | verdict `safe`/`malicious`/`no result` vs ~20M denylist+allowlist |
| `analyze <url> [--lang en\|vi] [--fresh]` | GET feeds `/api/v1/analyze-deep` | deep AI: `risk_score` 1–10 + `key_findings` |
| `denylist <search> [--type][--status][--page][--limit]` | GET feeds `/external/denylists/search` | search denylist → sibling scam URLs (campaign clustering) |
| `checkphone <q>` / `whois <q>` / `burner <q>` | GET feeds `/external/check{phone,whois,burneremail}` | VN scam-phone / WHOIS / disposable-email |
| `ioc <type> <value> [--ai]` | POST ti `/api/v1/ioc/external/<type>` | verdict + evidence; types `email password url ip phone bank-account hash asn` |
| `exposure <value> --type email\|username\|password\|domain` | POST ti `.../leaked-accounts/exposure` | is this identifier exposed in leaks |
| `leaks <query>` / `breaches <query>` | POST ti `.../search`, `.../breaches/search` | leak preview / breach collections |
| `machines`, `stolen-credentials`, `exposed-credentials`, `cookies` `<query>` | POST ti `.../<dataset>/search` | individual leak datasets (devices, creds, cookies) |
| `leaked-accounts <query>` | POST ti `.../leaked-accounts/search/start`→`/poll` | **async job** — live CyberTrust accounts |
| `devices <query>` | POST ti `.../devices/search/start`→`/poll` | **async job** — CyberTrust device inventory |
| `device-detail <id>` / `device-credentials <id>` | POST ti `.../devices/{detail,credentials}` | drill into one device |
| `full-export <query>` | POST ti `.../full-export/start` → GET `.../full-export/poll/{id}` | **async job** — bulk export, returns `download_url` |
| `brand-domains [--limit][--offset]` | POST ti `/brand-protection/external/domains` | discovered lookalike/typosquat domains |
| `vulns […]` / `vuln <cve>` | GET ti `/threat-feeds/.../vulnerabilities` | CVE feed; `--kev` = known-exploited only |
| `actors [--q][--type]` | GET ti `.../threat-actors` | threat-actor directory |
| `onion <hostname>` | GET ti `.../onion-blocklist/check` | `.onion` abuse-blocklist check |
| `feed <stix2\|misp\|stix1> [--limit][--type][--observed-after]` | GET ti `/ioc/external/feeds/...` | CLD indicator feed export |
| `probe` | GET feeds `/external/checkburneremail` | fast key-validity check |

Envelope (every op): `{"tool":"chongluadao","op","input","ok","status","skipped","result","error"}`.
Exit: `0` ok **or** skipped(403/404/unsupported) · `2` other error · `3` no key.

## Where it plugs into the AEAD flow

| Phase | CLD calls | Feeds into |
|---|---|---|
| **Acquire** | `route`/`ioc *`, `checkurl`, `analyze`, `checkphone`, `whois`, `ioc bank-account`, `vulns/vuln` | `/scam-check`, `/threat-check`, `/phone`, `/webpivot --whois`, `/iban`, `/vuln-check`, `/appliance-scan` |
| **Enrich** | `denylist`, `brand-domains`, `ioc email`, `breaches`, `exposure`, `leaks`, dataset + async jobs (`leaked-accounts`, `devices`, `full-export`) | `/impersonate`, `/email-deep`, `/breach-deep`, `/stealer-log` |
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
`exposure`/`leaks`/`breaches`/datasets and the async jobs can take minutes — hence the 30-min
ceiling. On any error the call degrades to the keyless path for that command; log a gap, never block.
