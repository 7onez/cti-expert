# Workflow: AnalyzePage

Extract every pivot artifact from one page and produce ranked leads.

## Steps

1. **Authorization check.** Confirm the target is in scope (`../EthicalFramework.md`). For adversarial infra, prefer passive acquisition (step 2b) and non-attributable egress.

   Paths: `WP="$ROOT/WebPivot"` (skill scripts), `CASE="$ROOT/cases/<case>"` — see SKILL.md
   "Running the tools". Bare `tools/pivot_extract.py` fails from the project root.

2. **Acquire the page.** Always write the JSON into the case with `-o` (see Output contract).
   - Live static: `python3 "$WP/tools/pivot_extract.py" <URL> --pretty -o "$CASE/raw/<host>.json"`
   - JS-heavy SPA (renders post-JS DOM): add `--render` (needs `playwright install chromium`).
   - **Whole site, not just the landing page**: add `--crawl [MAXPAGES] [--crawl-depth D]` to also
     follow the site's nav/tabs/panels (same registrable domain) and merge every page's artifacts —
     `meta.crawled` lists the pages fetched. IDs that only appear on an inner page (contact form,
     about, checkout) get caught this way.
   - **Stay low-profile**: `--rotate-ua` rotates the User-Agent per request (auto-on with `--crawl`);
     `--proxy URL` or `--proxy-range SPEC` (comma list / file / `10.0.0.1-10.0.0.9:8080` IP range)
     routes the target-site fetches through a rotating proxy pool. No proxy flag → direct, unchanged.
   - **2b Passive** (hostile target): pull the DOM from urlscan.io or a Wayback snapshot, save to `page.html`, then `python3 "$WP/tools/pivot_extract.py" page.html --pretty -o "$CASE/raw/<host>.json"`.

2c. **ALWAYS check the web archive — every run, even when the live site loads.** The live
   page is one moment in time. The Wayback CDX timeline tells you whether the domain is
   parked-now-but-active-before, active-now-but-parked-before, or dropped-and-recatched (a
   `created` WHOIS date *inside* the capture history = a prior owner). Never conclude "parked /
   dead / nothing to pivot on" from the live page alone — a domain parked today may have hosted a
   live scam funnel last year, and that archived DOM is a full set of pivot artifacts.
   ```bash
   # full snapshot timeline (status codes reveal parking 302→ww1./ww25. PPC vs real 200 content)
   curl -s "http://web.archive.org/cdx/search/cdx?url=<host>*&output=json&collapse=digest&limit=200"
   ```
   - Read the **status codes + mimetypes**: `302 → ww1./ww2./ww25.<host>/?subid1=` is Bodis/
     above.com PPC parking; a Sedo/NameSilo `200` is parking too — neither is operator content.
   - For any capture with **real `200` content**, pull that archived DOM and run it through
     `pivot_extract.py page.html` — those are real pivot artifacts even if the site is dead now.
   - Then walk the **entire** analytics history (catches scrubbed/shared GA-GTM IDs):
     `python3 "$WP/tools/wayback_ga.py" <host> --max 15 --timeline` (see `HistoricalAnalytics.md`).
   - `pivot_extract.py` already auto-falls-back to Wayback/urlscan **only when the live fetch
     fails** — this step is the *additional* discipline of checking history on a live-and-loading
     target too, and mining every past-content snapshot, not just the most recent one.

3. **Read the artifacts.** The JSON `artifacts` block covers favicon hashes, trackers, crypto, emails, socials, third-party hosts, inline-script hashes, forms, comments, DOM-skeleton hash, tech fingerprint, cookies, headers, and **`qr_codes`** (decoded QR payloads + undecoded QR images).

3b. **QR codes + redirects — check them, the payload is often the key.** Scam funnels hide the
   deposit wallet / Telegram invite / affiliate link inside a **QR image**. The tool always
   zero-dep-decodes QR *generator-service* URLs (`?data=`/`&chl=`); add **`--decode-qr`** to also
   decode QR `<img>`/`data:` images from pixels (needs `pyzbar`+Pillow or OpenCV — else they surface
   as `qr:undecoded_image` leads). A canvas-drawn QR → `--render --screenshot`, decode the shot.
   Decoded payloads become `qr:crypto:<coin>` / `qr:telegram` / `qr:whatsapp` / `qr:url` pivots.
   For any **URL** payload (or the seed's own `meta.redirect_chain`), resolve the redirect fully —
   a QR/short URL usually hops to a more interesting host than the one on the page. Keep URLs
   **full and unshortened** when you record or resolve them.

4. **Get ranked leads.** `python3 "$WP/tools/pivot_extract.py" <URL> --leads` prints pivot suggestions high→low confidence with copy-paste queries.

5. **Run the top pivots.** Execute HIGH-confidence queries first (favicon hash, shared GA4/GTM/AdSense IDs) against `../references/PivotServices.md`.

5b. **Collect + archive.** Add `--save-dom "$CASE/dom/<host>.html"` to keep the raw DOM
   (use `--render` for the post-JS DOM — inline form scripts, injected IDs, and embedded
   Google-Sheet/webhook config only appear there), and `--submit` to push the URL to Wayback
   Save-Page-Now + a fresh urlscan scan for later mining.

6. **Persist, corroborate & report.** Ingest so the run is in the KB
   (`python3 tools/kb/ingest_webpivot.py --kb knowledge "$CASE"/raw/*.json`, from the project root).
   Require ≥2 overlapping artifacts before claiming a cluster. Summarize: artifacts found →
   pivots run → confirmed related hosts → confidence. Offer to render a relationship graph via
   the `IntelGraph` skill.

## Example
```bash
python3 "$WP/tools/pivot_extract.py" https://login-secure-verify.example --leads
# → [HIGH] favicon_hash = -1256781000
#     Shodan: http.favicon.hash:-1256781000
#     Censys: services.http.response.favicons.md5_hash=...
#   [HIGH] tracker:google_analytics_ga4 = G-ABC123XYZ
#     PublicWWW: "G-ABC123XYZ"
```
