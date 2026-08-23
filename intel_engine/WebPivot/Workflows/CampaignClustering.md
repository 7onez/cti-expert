# Workflow: CampaignClustering

Given many URLs (a list of suspected scam/phishing sites), group them into
operator clusters by shared artifacts.

## Steps

1. **Batch-extract.** Run the harness over every URL, one JSON per site:
   ```bash
   mkdir -p out
   while read u; do
     name=$(echo "$u" | sed 's#[^a-zA-Z0-9]#_#g')
     python3 tools/pivot_extract.py "$u" -o "out/$name.json" 2>/dev/null
   done < urls.txt
   ```
   For hostile targets, feed saved urlscan/Wayback DOMs instead of live fetches.

2. **Build the artifact index.** For each site collect the high-signal keys:
   `favicon.shodan_mmh3`, `trackers.*`, `crypto.*`, `emails`, `dom_skeleton_sha1`,
   `inline_script_sha256`, `forms[].inputs`. A quick collate:
   ```bash
   python3 - <<'PY'
   import json, glob, collections
   idx = collections.defaultdict(set)
   for f in glob.glob("out/*.json"):
       d = json.load(open(f)); site = d["meta"].get("host") or f
       a = d["artifacts"]
       if a.get("favicon"): idx[("favicon", a["favicon"]["shodan_mmh3"])].add(site)
       for k, vs in a.get("trackers", {}).items():
           for v in vs: idx[("tracker:"+k, v)].add(site)
       for k, vs in a.get("crypto", {}).items():
           for v in vs: idx[("crypto:"+k, v)].add(site)
       idx[("dom", a["dom_skeleton_sha1"])].add(site)
   for key, sites in sorted(idx.items(), key=lambda x:-len(x[1])):
       if len(sites) > 1: print(len(sites), key, sorted(sites))
   PY
   ```

3. **Cluster.** Sites sharing a distinctive artifact are one cluster. Merge clusters
   that overlap on ≥2 artifacts. A shared **DOM-skeleton hash** or **inline-script hash**
   across different domains is a strong "same kit" signal; a shared **favicon + GA4 ID**
   is a strong "same operator" signal.

4. **Expand.** For each cluster's strongest artifact, run `PivotFromArtifact.md` to
   discover sites not in the original list (PublicWWW / Shodan / Validin), then loop
   back to step 1 with the new URLs until it stops growing.

5. **Report.** Per cluster: member sites, the artifacts that bind them, confidence,
   and any expansion hits. Hand the cluster edges to the `IntelGraph` skill for a
   relationship / infrastructure diagram.
