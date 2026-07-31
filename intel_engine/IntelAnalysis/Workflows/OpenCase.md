# Workflow: Open a case — first moves (collect broad, then anchor)

Encodes the opening methodology (IntelAnalysis SKILL.md §0): collect maximally
before theorizing, start from the seed domain, anchor on the registrant email, prioritise
artifacts unique to the site. Hand off to `Correlate.md` once the KB is populated.

## Principle
The domain that looks central often isn't. Get the widest concrete footprint first; let
betweenness centrality — not first impressions — tell you the hub.

## Fast path (recommended): the one-command pipeline

Steps 1–5 below are automated by the orchestrator — it extracts every domain (WHOIS inline
when keys are set), ingests into the KB, and saves the cluster seeds, all into the case the
same way every run:

```bash
python3 tools/intel.py open <case-name> cases/<case-name>/domains.txt --render --operator "name"
python3 tools/intel.py status <case-name>     # audit: which hosts have raw JSON, is the graph built
```

Then jump to step 6 (anchor on the registrant, triage) and hand off to `Correlate.md`. Run the
manual steps below only when you need a single step in isolation or the pipeline flags don't cover it.

## Steps (manual equivalent)

1. **Set up the case workspace + keys.**
   ```bash
   CASE=cases/<case-name>; mkdir -p "$CASE/raw" "$CASE/whois"
   set -a; source ./.env; set +a          # FOFA + URLSCAN + WHOISXML (project .env)
   # put the seed list in $CASE/domains.txt, initial/tip domain on line 1
   ```

2. **Bulk-collect the WHOLE set — don't narrow early.** Extract artifacts for every domain.
   Acquire by hostility: passive-first for adversarial, live for low-risk. Under parallelism,
   web.archive.org rate-limits — use `-P 3` and re-run misses (empty `meta.host`).
   ```bash
   tr -d '\r' < "$CASE/domains.txt" | xargs -P 4 -n1 -I{} \
     python3 WebPivot/tools/pivot_extract.py "https://{}" --timeout 20 -o "$CASE/raw/{}.json"
   ```

3. **Bulk WHOIS current + history** (the registrant spine — most concrete glue).
   ```bash
   tr -d '\r' < "$CASE/domains.txt" | xargs -P 5 -n1 -I{} sh -c \
     'python3 WebPivot/tools/whois_enrich.py "{}" --json > "'"$CASE"'/whois/{}.json"'
   ```
   Inject the `whois` block into each `raw/*.json` so registrant email/name become graph hubs.

4. **Read the seed domain first, then the naming pattern.** Open the line-1 (initial) domain's
   artifacts by hand. Then eyeball `domains.txt` for brand families, TLD rotation, transliteration
   — pre-guess sub-groups before the tool clusters them. Do NOT commit to the seed being the hub.

4b. **Refresh CDN ranges once** so origin-vs-CDN IP classification is current (§1). `graph_build`
   then auto-drops shared CDN/cloud edge IPs and tags real backends `origin_candidate`.
   ```bash
   python3 WebPivot/tools/cdn_ranges.py --update      # published Cloudflare/Fastly/AWS/Google/Bunny ranges
   ```

5. **Ingest into the knowledge base** (so IntelAnalysis reasons over the store, not raw files).
   ```bash
   python3 tools/kb/ingest_webpivot.py --kb knowledge "$CASE"/raw/*.json
   python3 tools/kb/query.py --kb knowledge --shared --min 2   # cluster seeds, high→low
   ```

6. **Anchor on the registrant, prioritise unique artifacts.** Build the spine from the
   registrant email/name (§0.4). Rank shared indicators by the triage ladder (§1) — most-concrete
   first: registrant → owner-account tokens (GA/GTM, SEO/ads UUID, ahrefs/GSC) → **origin IP (not
   CDN/hosting)** → on-page DOM (phone, Zalo/Messenger, email, page schema). Drop noise
   (mis-parsed IDs, ad-network `pub-`/`g-recaptcha`, shared CDN IPs, registrar/placeholder WHOIS).

7. **Hand off to `Correlate.md`** — cluster into operators, disconfirm, calibrate confidence,
   write the assessment.

## Anti-steps (don't)
- Don't decide the central actor from the seed domain alone — verify with centrality.
- Don't narrow the collection before you've pulled the whole set + WHOIS history.
- Don't treat a shared Cloudflare/CDN IP or an ad-network ID as a same-operator link.
