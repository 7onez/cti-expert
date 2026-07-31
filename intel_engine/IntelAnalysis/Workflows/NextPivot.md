# Workflow: Decide the next pivot

Given the current cluster and open leads, pick the single highest-value next move.

## Steps

1. **List open leads.** From the assessment: unresolved indicators, un-run reverse
   lookups, domains with thin data, named identities not yet reverse-searched.

2. **Score each by expected yield ÷ cost (§5).**
   - yield: will it *confirm or kill* the hypothesis, or just add volume?
   - cost: free/passive (crt.sh, Wayback, KB) < paid credits (FOFA, WhoisXML) < attribution risk.
   - a reverse lookup on a **named identity** usually beats another artifact sweep.

   - **Distinctive HTML strings & unique subdomains are first-class next-pivots.** If a page
     carries a distinctive slogan / brand phrase / unique class or template literal, or a unique
     subdomain label (e.g. `svc-a.site-a.example`), hand it to WebPivot as an HTML search — FOFA `body=`
     / crt.sh / Shodan CT often out-reach PublicWWW on freshly-registered domains.

3. **Run the top pivot with the right collector**, then re-ingest:
   ```bash
   # example — reverse-WHOIS on a leaked registrant name via WebPivot's WHOIS tool
   python3 WebPivot/tools/whois_enrich.py --reverse-name "Registrant Name" --search-type historic
   # example — FOFA body-search a high-value HTML phrase the analysis surfaced (the HTML-search chain)
   python3 WebPivot/tools/pivot_extract.py https://newdomain.example \
       --fofa-keyword "distinctive phrase" --pretty -o cases/x.json
   # example — expand a domain and fold results back into the KB (a unique subdomain auto-emits a `subdomain` pivot)
   python3 WebPivot/tools/pivot_extract.py https://newdomain.example --pretty -o cases/x.json
   python3 tools/kb/ingest_webpivot.py --kb knowledge cases/x.json
   ```

4. **Re-correlate.** Re-run `--shared`; if the new domain joins an existing cluster, the
   hypothesis strengthened. If it introduces a conflicting artifact, revise.

5. **Stop condition.** Halt when new pivots stop adding domains for K rounds, or the
   remaining leads are all noise-tier. Record what you deliberately did NOT chase.
