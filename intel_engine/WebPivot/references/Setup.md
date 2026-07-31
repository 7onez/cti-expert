# WebPivot — Setup, API keys & the WHOIS tool

Load this when you need to wire up live pivoting (keys), understand what each key unlocks, or run
the standalone WHOIS client. **No keys → keyless mode, everything below is simply skipped.**

## Customization

**Before executing, check for user customizations at:**
`~/.config/cti-expert/WebPivot/`

If this directory exists, load and apply any PREFERENCES.md, API keys, or resources found there.
These override default behavior. If the directory does not exist, proceed with skill defaults.

## API keys (optional — enables live pivoting)

`pivot_extract.py` reads keys from the environment first, then from a `chmod 600` `.env` in the
customization dir (env wins). Recognized: `URLSCAN_API_KEY`, `FOFA_KEY` (or `FOFA_API_KEY`),
`FOFA_EMAIL`, `WHOISXML_API_KEY`, `PDNS_USERNAME` + `PDNS_PASSWORD` (passive DNS, optional
`PDNS_URL`), and — for IPPivot — `IPINFO_TOKEN` (richer IPinfo ASN/abuse) and `SHODAN_KEY` (host
ports/services). Both optional.

`URLSCAN_VISIBILITY` — set to `private` with a **urlscan Pro** key so submitted scans of hostile
infra stay team-only (never in the public feed); defaults to `unlisted`. A Pro key also auto-enables
`search_after` pagination (far more siblings per reverse), the **structure-similarity** pivot
(clusters re-skinned kits), and urlscan **verdict/brand** capture (feeds `risk_signals`).

With keys set, the tool runs the HIGH-confidence pivots live — FOFA reverses the favicon
`icon_hash` and tracker/verification bodies, authenticated urlscan content-searches the same
values, and WhoisXML adds current + historical registrant data plus reverse-WHOIS pivots — all
attached to each pivot as `live_results` (shown inline in `--leads`). Use `--no-enrich` /
`--no-whois` to skip; `--whois-reverse` runs reverse-WHOIS live (costs credits).

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

### Passive DNS (CIRCL-style COF) — `PDNS_USERNAME` + `PDNS_PASSWORD`

When set, live enrichment adds a passive-DNS lookup on the base host: historical IPs the domain has
used (folded into the stale-vs-live-IP check) and other domains seen co-hosted on the same IPs —
attached to the domain pivot as `live_results.pdns` and counted toward corroboration. Uses HTTP
Basic auth against `PDNS_URL` (default CIRCL `https://www.circl.lu/pdns/query`); point `PDNS_URL`
at any COF-compatible instance. No creds → the lookup is simply skipped (keyless mode unchanged).

**No keys → keyless mode, unchanged.** Prefer macOS Keychain over a plaintext `.env`;
see `~/.config/cti-expert/WebPivot/PREFERENCES.md` for setup.

## WHOIS tool — `tools/whois_enrich.py`

Standalone WhoisXML client: current WHOIS, WHOIS history (every registrant email/name ever seen),
and reverse WHOIS by registrant email/name. `pivot_extract.py` calls it automatically when
`WHOISXML_API_KEY` is set; `graph_build.py` models registrant email/name, registrar, and name
servers as graph hubs so shared registration data clusters domains.
```bash
python3 WebPivot/tools/whois_enrich.py suspect.example                     # current + history
python3 WebPivot/tools/whois_enrich.py --reverse-email owner@x.com         # owner's other domains
```
