# WebPivot — Setup, API keys & the WHOIS tool

Load this when you need to wire up live pivoting (keys), understand what each key unlocks, or run
the standalone WHOIS client. **No keys → keyless mode, everything below is simply skipped.**

## First: what can this machine actually collect? — `tools/wp_capabilities.py`

```bash
python3 WebPivot/tools/wp_capabilities.py              # table: each key, present or absent, and the cost
python3 WebPivot/tools/wp_capabilities.py --json       # the same as meta.capability
python3 WebPivot/tools/wp_capabilities.py --free-only  # as the convergence loop sees it
```

Every `pivot_extract` run prints this as a **stderr banner** (silent only when every key is
present), records it as **`meta.capability`** in the result JSON, and shows it at the top of
`--leads`. MCP tool: `capability_check`.

**Why it exists.** Keyless is a supported mode, not a broken one — but it is a *different
investigation*. WebPivot always **extracts** every artifact; what a key buys is the ability to
**reverse** it. With no `FOFA_KEY`/`URLSCAN_API_KEY` the favicon-hash and tracker reverses never
execute, so a thin result means *"the indexes that would have found siblings were never queried"* —
which is a fact about the credentials, not about the operator. State the mode and the unqueried
indexes before presenting any negative finding, and put `meta.capability.statement` in the
assessment's collection-limitations note.

The per-key consequences are DATA in **`references/api_keys.json`** — edit that file (not the code)
when a key is added or a provider changes what a tier includes.

## API keys (optional — enables live pivoting)

`pivot_extract.py` reads keys from the environment first, then from the first `chmod 600` `.env` it
finds — the **invocation directory** (normally the repo root you run from), the **repo root**
relative to the script, then a **skill-local** `.env` next to `WebPivot/`. A real environment
variable always wins; among files, the earlier one wins. Recognized: `URLSCAN_API_KEY`, `FOFA_KEY` (or `FOFA_API_KEY`),
`FOFA_EMAIL`, `WHOISXML_API_KEY`, `PDNS_USERNAME` + `PDNS_PASSWORD` (passive DNS, optional
`PDNS_URL`), `CENSYS_PAT` (+ optional `CENSYS_ORG_ID`), `INTELX_KEY` (+ optional `INTELX_BASE_URL`),
`SERPAPI_KEY`,
and — for IPPivot — `IPINFO_TOKEN` (richer IPinfo ASN/abuse) and `SHODAN_KEY` (host ports/services).
BinaryPivot additionally reads `ANYRUN_API_KEY`. All optional.

### `INTELX_KEY` — Intelligence X (leaks / stealer logs / pastes / darknet / historical WHOIS)

Get it at <https://intelx.io/account?tab=developer> (Account → **Developer** tab), which also shows
the **API instance** your key is issued against. The client defaults to `https://2.intelx.io`; if the
Developer tab shows a different host, set `INTELX_BASE_URL` to it — otherwise every call answers
401 and reads as "expired key".

```bash
printf 'INTELX_KEY=…\n' >> .env && chmod 600 .env
python3 WebPivot/tools/wp_intelx.py caps      # what this key is entitled to
python3 WebPivot/tools/wp_intelx.py budget    # this month's search spend (offline, free)
```

What the key changes: with it, `pivot_extract --intelx` **runs** the selector searches and the
phonebook inventory; without it, every pivot still carries its IntelX selector and a click-to-run
`intelx.io` / `phonebook.cz` URL — **about half the layer**, since composing the query is free but
executing it is not. **`/phonebook/search` is PAID-only**: a free key gets HTTP 402 and the UI link.
Spend is capped per run and per month (`references/intelx.json → search_budget`, or
`INTELX_MAX_SEARCHES_PER_RUN` / `INTELX_MONTHLY_SEARCHES` for a single run). `--free-only` skips it.

### `SERPAPI_KEY` — Google Ads Transparency Center + SERP ads (the advertising layer)

Sign up at <https://serpapi.com/> and copy the private key from the dashboard. The free tier is currently
**250 searches a month** (`wp_serp.py budget` reads the authoritative figure off your account and
flags it when the local guard disagrees); the account endpoint is free and does not count against it.

```bash
printf 'SERPAPI_KEY=…\n' >> .env && chmod 600 .env
python3 WebPivot/tools/wp_serp.py budget                       # ledger + live quota
python3 WebPivot/tools/wp_serp.py advertiser site.example --region VN
```

What the key changes: with it, `pivot_extract --serp` resolves **who advertises a domain** — a
Google-verified, paying advertiser account and the legal name its ads are *funded by* — reverses
that `advertiser_id` to every other domain the account advertised, and opens a creative for
`ad_funded_by` (the verified **legal entity**) plus the per-region markets the ad ran in, each with
its own last-shown date. The creative's **destination link** — the operator's own `utm`/`gclid`
tagging — comes back only sometimes, because the archive commonly stores a text ad as a rendered
image; the tool says so instead of looking broken. Without it
the layer still runs at **~55%**: every ad parameter is classified, the free
`adstransparency.google.com` address for the domain and for any advertiser id is emitted (same data,
by hand), and — most importantly — **the click-keyed cloaking probe runs in full**, because it is
plain HTTP to the target and needs no credential. A keyless "no advertiser found" therefore means
*the archive was never asked* and must not be reported as a finding.

Two things to get right:

- **Region is not cosmetic.** The archive is queried **per region**, and the API and the web UI use
  different codes for the same country (SerpApi wants Google's numeric geotarget `2704`, the browser
  wants `VN`). A domain that advertises only in its victims' market returns nothing from the default
  `anywhere` — pass `--serp-region VN`. Codes and the `2000 + ISO-numeric` rule for anything
  unlisted: `references/serpapi.json → regions`.
- **Spend is capped** per run and per month from the same ledger every other metered layer uses
  (`references/serpapi.json → search_budget`, or `SERPAPI_MAX_SEARCHES_PER_RUN` /
  `SERPAPI_MONTHLY_SEARCHES` for one run). Opening creatives has its own smaller cap — a wide
  advertiser would otherwise spend a month's quota on one domain. `--free-only` skips the layer
  entirely; the cloaking probe is unaffected either way.

### `ANYRUN_API_KEY` — ANY.RUN TI Lookup (used by **BinaryPivot**, not by pivot_extract)

Get it from your ANY.RUN profile → **API and Limits** tab (<https://app.any.run/profile>). Paste the
bare key; the client adds the `API-KEY ` prefix. **TI Lookup is a separate licence from the
sandbox** — a sandbox-only key answers 401/403 on `/intelligence/*`, so check first:

```bash
printf 'ANYRUN_API_KEY=…\n' >> .env && chmod 600 .env
python3 BinaryPivot/tools/bp_anyrun.py keycheck   # entitled to TI Lookup?
python3 BinaryPivot/tools/bp_anyrun.py budget     # this month's request spend (offline, free)
```

**Submitting is gated on the analyst's explicit yes, every time.** `bp_anyrun.py submit <target>`
prints the risk briefing and sends **nothing**; only `--confirm-submission` actually detonates.
Privacy defaults to `owner` (only you), `public` is refused unless separately authorized, and a
free-plan submission is refused rather than silently downgraded to a public task. Nothing in the
collector path can submit — `analyze_artifact --anyrun` does lookups only. Without the key the layer
still composes the correct TI Lookup query for every artifact and gives the UI address to paste it
into (**~50% capability**). Capped per run and per month (`references/anyrun.json →
request_budget`, or `ANYRUN_MAX_REQUESTS_PER_RUN` / `ANYRUN_MONTHLY_REQUESTS`).

`URLSCAN_VISIBILITY` — set to `private` with a **urlscan Pro** key so submitted scans of hostile
infra stay team-only (never in the public feed); defaults to `unlisted`. A Pro key also auto-enables
`search_after` pagination (far more siblings per reverse), the **structure-similarity** pivot
(clusters re-skinned kits), and urlscan **verdict/brand** capture (feeds `risk_signals`).

With keys set, the tool runs the HIGH-confidence pivots live — FOFA reverses the favicon
`icon_hash` and tracker/verification bodies, authenticated urlscan content-searches the same
values, and WhoisXML adds current + historical registrant data plus reverse-WHOIS pivots — all
attached to each pivot as `live_results` (shown inline in `--leads`). Use `--no-enrich` /
`--no-whois` to skip; `--whois-reverse` runs reverse-WHOIS live (costs credits).

**WHOIS runs on every domain, key or not.** Without `WHOISXML_API_KEY` the tool falls back to
**keyless RDAP** (the IETF-standard, free, structured-JSON, ToS-respecting successor to port-43
whois — one polite request per domain via the `rdap.org` bootstrap redirector), with a system
`whois` port-43 fallback for ccTLDs that don't serve RDAP (e.g. `.vn`). RDAP reliably yields
**registrar, registration/expiry/updated dates, name servers, and domain status** even when the
registrant is GDPR-redacted — so the Domain Summary table + report are populated on every host,
not left blank. `meta.enriched_with` records the actual source (`rdap` / `whois43` / `whoisxml`,
or `whoisxml+rdap` when the licensed record was empty and RDAP backfilled it). History + reverse-
WHOIS still require the licensed WhoisXML API (RDAP has no reverse index).

### urlscan reverses match how urlscan INDEXES each artifact

(not one-size-fits-all) — this is often the better index than FOFA for freshly-stood-up domains
FOFA hasn't crawled:
- **tracker / verification IDs** → page-**content** search (`"<id>"`).
- **favicon** → resource-**hash** search (`hash:<sha256>`) — urlscan stores the favicon's SHA-256,
  not the mmh3 pivot value, so the reverse keys off `artifacts.favicon.sha256`.
- **saas token / third-party host** → resource-**filename** search (`filename:<basename>`). SaaS
  tokens and 3rd-party infra live inside a loaded resource URL, not page text, so urlscan indexes
  them by filename. The tool picks the **distinctive** external script tied to that host/token
  (a build-hash/long-token basename like `project_100000000_200000000_300000000.js` — never a generic
  `gtm.js`/`jquery.min.js` or the seed's own asset) and records it as `live_results.urlscan.reversed_resource`.
  *(Inline-script SHA-256s are intentionally NOT reversed — inline scripts aren't fetched resources,
  so urlscan doesn't index them.)* This is what clusters siblings sharing one chat/SaaS account.

By default FOFA reverses search only the most recent ~1-year window; add `--fofa-full` to
run every FOFA reverse (favicon `icon_hash`, tracker/verification bodies, live-IP reverse)
over **all historical data** (`full=true`) — this catches assets that were live in the past
and later scrubbed. Requires a FOFA tier that permits full/historical search; lower tiers
ignore or reject `full=true`.

### Censys Platform — `CENSYS_PAT` (a FREE plan is genuinely useful; read the tier rule first)

**Getting a free key.** Sign up at <https://platform.censys.io/> (free, no card). In the Platform
web console: **user icon, top right → API Access → Create New Token**. Copy the Personal Access
Token — it is shown once. If your account belongs to an organisation, copy the organisation ID too.
Then, in the repo root:

```bash
printf 'CENSYS_PAT=censys_pat_xxxxxxxxxxxxxxxx\n' >> .env    # add CENSYS_ORG_ID=… only if you have one
chmod 600 .env                                               # the loader ignores world-readable .env
python3 WebPivot/tools/wp_censys.py host 1.1.1.1             # verify: should print a host record
```

**The one rule that decides what you get.** A Censys **Free** account can call ONLY the *lookup*
endpoints. `POST /v3/global/search/query` — searching by favicon hash, body keyword or cert
fingerprint — answers **403 on Free**; it needs Starter (reached by buying any credits) or above.
So WebPivot uses the three lookups, which are free-plan reachable and are where the value is anyway:

| Call | Free plan | What it gives you |
|---|---|---|
| `wp_censys.py cert <sha256>` | ✅ | **the best one** — the certificate's own `names`: every hostname on that exact leaf cert. crt.sh gives fuzzy *name overlap*; this is the cert stating its own coverage, so a multi-apex list is near-decisive cross-brand same-operator evidence |
| `wp_censys.py host <ip>` | ✅ | ASN + WHOIS org, forward/reverse DNS names, open ports, per-service banners and cert fingerprints. Folded into IPPivot automatically |
| `wp_censys.py webproperty <host>[:port]` | ✅ | the cert, favicon hashes, body hash, software stack and threat labels Censys holds for that hostname. Folded into domain enrichment automatically |
| `wp_censys.py search '<CenQL>'` | ❌ 403 | Starter+. On Free it returns `skipped` **plus a `platform.censys.io` UI link that runs the identical query** — the UI search works on Free (1 page of 100 results), **but still costs 5 credits** |
| `wp_censys.py budget` | ✅ offline | this month's credit balance — no key, no spend. Check it before a batch |

**Credits — the tightest budget in the toolkit; spend deliberately.** Censys meters everything:
**1 credit per lookup, 5 per search** (8 with regex), and a Free account gets **100 credits a month
that do not roll over**. Two things make this sharper than the other metered APIs:

- the quota is **per account, not per case** — twenty careless searches empty the month and take
  Censys away from *every later case* until the 1st;
- **the UI link is not free either.** Running the emitted CenQL in the web console costs the same
  5 credits as the API search. Six clicked links = a third of the month.

So WebPivot enforces a budget rather than discovering the ceiling as an HTTP 402 mid-case:

```bash
python3 WebPivot/tools/wp_censys.py budget      # offline, free: this month's balance
```

| Guard | Default | What it stops |
|---|---|---|
| `monthly_credits` | 100 | spending past the month's grant — summed from `MEMORY/api_usage.jsonl` across **every** case, not just this run |
| `max_credits_per_run` | 20 | one batch of 200 domains quietly spending the whole month |
| `reserve_for_lookups` | 10 | a 5-credit search eating the last credits and leaving the 1-credit **cert lookup** — the free plan's highest-value call — unaffordable |
| `warn_at_remaining` | 30 | running out without warning: below this every call prints the balance |

Over budget → the same `{"skipped": reason, "ui_url": …}` degradation as a plan 403, carrying the
balance. Thresholds live in `references/censys_queries.json` → `credit_budget`; override for a
single run with `CENSYS_MONTHLY_CREDITS` / `CENSYS_MAX_CREDITS_PER_RUN` (raise `monthly_credits`
in the JSON if you buy credits or upgrade the plan).

**Value per credit, best first:** `cert <sha256>` (1 credit → every hostname on that leaf cert) →
`host <ip>` → `webproperty <host>` → `search` (5, Starter+ only). Censys is also skipped under
`--free-only`, disabled outright by `--no-censys`, logged to `MEMORY/api_usage.jsonl`, and memoised
per process so one run never pays twice for the same IP.

**Queries are always emitted, key or not.** The CenQL builder is offline and free, so every pivot
carries its Censys query and a click-to-run UI URL even with no `CENSYS_PAT` at all. Censys replaced
the old Legacy Search language with **CenQL**, which namespaces every field under `host.` / `web.` /
`cert.` — a Censys query copied from an older write-up does not run on the Platform. The current
field names live in `references/censys_queries.json`; edit that file, not the code.

*JARM caveat:* Censys indexes JARM but only makes it **searchable** with the Adversary Investigation
module — on Free/Starter/Core a `jarm.fingerprint` query returns nothing. Use Shodan `ssl.jarm:`.

### Passive DNS (CIRCL-style COF) — `PDNS_USERNAME` + `PDNS_PASSWORD`

When set, live enrichment adds a passive-DNS lookup on the base host: historical IPs the domain has
used (folded into the stale-vs-live-IP check) and other domains seen co-hosted on the same IPs —
attached to the domain pivot as `live_results.pdns` and counted toward corroboration. Uses HTTP
Basic auth against `PDNS_URL` (default CIRCL `https://www.circl.lu/pdns/query`); point `PDNS_URL`
at any COF-compatible instance. No creds → the lookup is simply skipped (keyless mode unchanged).

**No keys → keyless mode, unchanged.** Prefer your OS keychain over a plaintext `.env` —
see `INSTALL.md §5` for the macOS/Linux/Windows recipes.

## WHOIS tool — `tools/whois_enrich.py`

Standalone WHOIS client. **With `WHOISXML_API_KEY`:** current WHOIS, WHOIS history (every
registrant email/name ever seen), and reverse WHOIS by registrant email/name. **Without a key:**
current-registration lookup still works via keyless RDAP (+ port-43 fallback) — history/reverse
need the licensed key. `pivot_extract.py` calls it automatically for **every** domain (keyed or
keyless); `graph_build.py` models registrant email/name, registrar, and name servers as graph
hubs so shared registration data clusters domains.
```bash
python3 WebPivot/tools/whois_enrich.py suspect.example                     # current + history
python3 WebPivot/tools/whois_enrich.py --reverse-email owner@x.com         # owner's other domains
```
