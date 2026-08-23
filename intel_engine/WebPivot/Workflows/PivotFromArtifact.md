# Workflow: PivotFromArtifact

You already have one artifact (a favicon, a tracking ID, a wallet, an email) and
want to know everywhere else it appears.

## Steps

1. **Normalize the artifact.**
   - Have a favicon file, not a hash? Compute all three hashes:
     ```bash
     python3 - <<'PY'
     import base64, hashlib, sys
     sys.path.insert(0, "tools")
     from pivot_extract import shodan_favicon_hash
     raw = open("favicon.ico","rb").read()
     print("mmh3 :", shodan_favicon_hash(raw))
     print("md5  :", hashlib.md5(raw).hexdigest())
     print("sha256:", hashlib.sha256(raw).hexdigest())
     PY
     ```
   - Have a tracking ID / email / wallet already? Skip to step 2.

2. **Pick the engine(s)** from `../references/PivotServices.md` by artifact type:
   - favicon → Shodan `http.favicon.hash:<mmh3>`, Censys (MD5), Netlas (SHA-256), FOFA, ZoomEye
   - GA4/GTM/AdSense/pixel → PublicWWW `"G-XXXX"`, DNSlytics reverse-analytics, urlscan, AnalyzeID
   - email → reverse-WHOIS (ViewDNS/WhoisXML), Epieos, urlscan
   - wallet → Chainabuse, block explorer, Arkham/Breadcrumbs, PublicWWW for the string
   - source string → PublicWWW / NerdyData / Intelx

3. **Run and collect** the candidate hosts/domains.

4. **Filter false positives.** Shared CDNs, template defaults, and generic favicons produce noise. Drop hosts that only share a *generic* artifact; keep those sharing a *distinctive* one (custom favicon, private GA4 property).

5. **Second-order pivot.** For each new host, feed it back through `AnalyzePage.md` to find *its* artifacts — this is how a cluster grows. Stop when new hosts stop appearing or scope is exhausted.

6. **Report** the artifact → host list, confidence per link, and the query used (so it's reproducible).
