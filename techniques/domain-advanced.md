# Domain Advanced Module

> **Module ID:** DOM-ADV-001
> **Version:** 1.1.0
> **Phase:** 5 - Enhancement Modules
> **Classification:** Advanced Subdomain Enumeration & Infrastructure Mapping

---

## 1. Overview

Performs deep subdomain discovery and infrastructure clustering using passive and semi-passive sources — certificate transparency logs, BGP/ASN data, historical URL archives, and multi-source passive DNS.

**When to use:** Attack surface mapping, org infrastructure recon, pre-pentest scope validation, exposure assessment.

**Admin / sensitive-endpoint flagging:** after enumerating subdomains (and any discovered paths), classify each against [`handbook/admin-endpoint-indicators.md`](../handbook/admin-endpoint-indicators.md) — leftmost-label/path prefixes like `admin`, `adm`, `kef`, `ador`, `panel`, `cpanel`, `backend`, `dashboard`, plus CJK 后台/管理/客服/代理. Promote hits to high-priority findings (exposed admin panels / sensitive endpoints) and feed them into `/exposure` and `/report ioc`.

**Passive vs Active:**
- **Passive** — queries third-party databases; no direct contact with target. Safe, stealthy.
- **Active** — sends DNS queries or probes directly to target infrastructure. Leaves footprint.

This module defaults to **passive** enumeration only.

---

## 2. Tool Inventory

| Priority | Tool | Sources | Install |
|----------|------|---------|---------|
| Primary | Subfinder | 45+ passive sources | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| Secondary | Amass | 87 passive sources | `go install github.com/owasp-amass/amass/v4/...@master` |
| CT Logs | crt.sh | Certificate Transparency | `curl` + `jq` (no install) |
| Network | ASN Tool | BGP/ASN/CIDR/peers | `pip3 install asn` or `go install github.com/nitefood/asn@latest` |
| Historical | **Waymore** | Wayback + Common Crawl + OTX + URLScan + VT + more (7 sources) | `pip3 install waymore` |
| Historical | GAU | Wayback + AlienVault + Common Crawl + URLScan | `go install github.com/lc/gau/v2/cmd/gau@latest` |

---

## 3. Investigation Workflow

```
1. crt.sh query — fast, no auth, returns CT-logged subdomains (start here)
2. Subfinder — broad passive enumeration across 45+ sources
3. Amass passive — deeper coverage, slower, cross-reference with Subfinder
4. Deduplicate combined output into master list
5. ASN lookup — map IPs to network blocks, identify hosting/CDN/cloud
6. Waymore — pull archived URLs from 7 sources (replaces GAU as primary)
7. GAU — secondary historical URL discovery if waymore unavailable
8. Cluster findings by IP range, ASN, provider
9. Flag interesting targets (login panels, APIs, staging, internal-facing)
```

---

## 4. CLI Commands & Expected Output

### crt.sh — Certificate Transparency logs
```bash
curl -s "https://crt.sh/?q=%25.<domain>&output=json" \
  | jq -r '.[].name_value' \
  | sed 's/\*\.//g' \
  | sort -u \
  | tee crtsh-subdomains.txt
```
**Expected output:**
```
api.example.com
dev.example.com
mail.example.com
staging.example.com
vpn.example.com
```

### Subfinder — multi-source passive enumeration
```bash
subfinder -d <domain> -o subfinder-subdomains.txt -oJ -silent
```
**With provider config (recommended for full coverage):**
```bash
subfinder -d <domain> -pc ~/.config/subfinder/provider-config.yaml -o subfinder-subdomains.txt -oJ
```
**Expected JSON output:**
```json
{"host":"api.example.com","input":"example.com","source":"censys"}
{"host":"dev.example.com","input":"example.com","source":"certspotter"}
```

### Amass — passive-only enumeration
```bash
amass enum -passive -d <domain> -json amass-output.json -timeout 15
```
**Extract hostnames from JSON:**
```bash
cat amass-output.json | jq -r '.name' | sort -u | tee amass-subdomains.txt
```

### Deduplicate combined output
```bash
cat crtsh-subdomains.txt subfinder-subdomains.txt amass-subdomains.txt \
  | sort -u \
  | grep -v '^\*' \
  | tee all-subdomains.txt
wc -l all-subdomains.txt
```

### ASN Tool — BGP/network infrastructure mapping
```bash
asn -d <domain>
```
**Per-IP ASN lookup:**
```bash
asn <ip_address>
```
**Expected output:**
```
AS13335 | CLOUDFLARENET | US | 104.21.0.0/16 | Cloudflare
AS16509 | AMAZON-02     | US | 54.230.0.0/15 | AWS CloudFront
```

### Waymore — multi-source historical URL discovery (PRIMARY)
```bash
# All archived URLs including subdomains:
waymore -i <domain> -mode U -oU waymore-urls.txt

# Extract subdomains from discovered URLs:
cat waymore-urls.txt | grep -oP '(?<=://)[^/]+' | sort -u | grep "\.<domain>$" | tee waymore-subdomains.txt

# Download response bodies for content analysis:
waymore -i <domain> -mode R -oR ./waymore-responses/ -l 1000

# Filter by date range for targeted historical analysis:
waymore -i <domain> -mode U -from 2020 -to 2024 -oU waymore-urls.txt
```
**Install:** `pip3 install waymore` — https://github.com/xnl-h4ck3r/waymore

### GAU — historical URL discovery (FALLBACK if waymore unavailable)
```bash
echo <domain> | gau --subs --threads 5 2>/dev/null \
  | grep -oP '(?<=://)[^/]+' \
  | sort -u \
  | grep "\.<domain>$" \
  | tee gau-subdomains.txt
```

---

## 5. Fallback Cascade

```
Subfinder unavailable
  → Use amass alone: amass enum -passive -d <domain>
  → Use crt.sh + manual DNS search

Amass unavailable
  → Use Subfinder + crt.sh (covers ~70% of Amass sources)

crt.sh API down
  → Query directly: https://crt.sh/?q=<domain>&output=json
  → Use certspotter: https://api.certspotter.com/v1/issuances?domain=<domain>&include_subdomains=true

GAU unavailable
  → Wayback CDX API directly:
    curl "http://web.archive.org/cdx/search/cdx?url=*.<domain>&output=text&fl=original&collapse=urlkey"

ASN tool unavailable
  → BGP.he.net: https://bgp.he.net/dns/<domain>
  → ipinfo.io: curl https://ipinfo.io/<ip>/json
```

---

## 6. Output Interpretation

**Subdomain naming patterns to flag:**
```
dev.*, staging.*, test.*, qa.*  → Pre-production, often less hardened
admin.*, panel.*, manage.*      → Admin interfaces
api.*, v1.*, v2.*               → API endpoints
vpn.*, remote.*, citrix.*       → Remote access (high value)
mail.*, smtp.*, mx.*            → Email infrastructure
internal.*, intranet.*          → May be accidentally public
```

**Infrastructure clustering by ASN:**
- Same ASN across many subdomains = self-hosted or single cloud account
- Mixed ASNs = CDN + origin separation; CDN may mask real IP
- Single IP hosting many subdomains = shared hosting, virtual hosting attack surface

**GAU historical findings:**
- URLs present in archive but not in current DNS = decommissioned assets
- Check if old subdomains still resolve — forgotten infrastructure is often unpatched

---

## 7. NXDOMAIN / DGA Triage (lead generator)

**Trigger.** You hold a *set* of machine-looking names — NXDOMAIN answers from sandbox or client
resolver logs (`/anyrun` lookup), names pulled from a sample's config, a batch of co-resolving
names (`fx-dns-cert-history.md` §2.7), or CT names with random labels — and must decide whether a
domain-generation-algorithm (DGA) hypothesis is worth collection.

**Source.** FANCI (Feature-based Automated NXDomain Classification and Intelligence) classifies
NXDOMAIN names into benign non-existent domains and malicious algorithmically-generated domains
(mAGDs) from the name alone, with 21 features: 12 structural, 7 linguistic, 2 statistical
[P06 Schüppen et al., USENIX Sec 2018]. The NXDOMAIN focus follows from how DGAs work: bots query
many generated names, the botmaster registers few, so most queries fail. FANCI groups benign NXDs
into **typing errors** (human) and benign algorithmically-generated names from
**misconfiguration** and **misuse** (e.g. a browser probing random names to detect DNS hijacking,
anti-virus signature lookups over DNS). We use its feature list as a manual reading aid; we do not
run its classifier, and its accuracy figures are not ours.

**Inputs.** The name set; per name, when it was queried, by what (host, sample, sensor), and
whether it resolves.

**Steps.**
1. **Normalise.** Strip the public suffix (Public Suffix List, so dynamic-DNS parents like a
   `*.ddns`-style suffix count as suffixes) and work on the dot-free, suffix-free string, as FANCI
   does.
2. **Filter.** FANCI filters positives against a global popular-domain list (excluding zones where
   anyone can register a subdomain) and a local high-frequency list. Our equivalent (adaptation):
   `/reference check` plus the case's own benign set; drop names under a known service zone.
3. **Read the lexical shape** (FANCI subset): name length and label count; digit ratio and
   digit-only / hex-only labels; vowel ratio and consecutive-consonant ratio; repeated-character
   ratio; character entropy; a label repeated as a prefix; an embedded IP address; valid TLD.
4. **DGA vs human-named — five questions (adaptation):**
   - (a) Does it segment into words or a brand? Yes → human-named **or** a wordlist DGA.
   - (b) Is it one or two edits from a real domain? → typing error (benign NXD); if it resolves,
     a typosquat lead instead.
   - (c) Is it a hash, hex or digit run in a known machine-naming shape — CDN hostnames, device
     names with a serial, reverse-DNS-style `ip-…` / `host-…` labels? → benign machine-generated.
   - (d) Is there a **set** — same length or charset, same TLD rotation, same time window, same
     querying host? Required for a DGA hypothesis; one random-looking name is not a DGA.
   - (e) Which members resolve? Those are the candidate registered rendezvous points.
5. **Output.** Label each set `DGA-candidate`, `benign machine-generated`, `typo / misconfig` or
   `insufficient`, with its pattern (length, charset, TLD set, window, querying source).
6. **Next.** Search the pattern and resolving members in sandbox and report corpora (`/anyrun`
   lookup, `/search-pivot`); run `fx-dns-cert-history.md` §2.6 on resolving members; feed C2
   candidates to §8.

**Confounders / false positives.** FANCI's real-world potential false positives split into
human-generated (typos, near-real names) and machine-generated (random-looking or technical:
device and ISP host naming, CDN numeric labels, protocol probes); it notes some names cannot be
assigned to either class without context. Wordlist DGAs (Matsnu, and the concatenated-word sets in
its Figure 4) defeat entropy and consonant reads; permutation DGAs of one base name
(VolatileCedar) look like typos [P06].

**Ground-truth limits.** FANCI's authors call its real-world false-positive rate "only of limited
significance" because real-world ground truth is hard to establish, and in their test on
**successfully resolving** names the false-positive rate rose to about 7.5% (5-fold CV) — lexical
features are weaker outside NXDOMAIN traffic [P06]. Reading CT or pDNS names this way is
therefore weaker evidence than reading NXDOMAIN logs.

**Abstain** (`insufficient`) when: a single name; no query context (who, when); IDN / non-Latin
labels; names under a shared public suffix with nothing else known.

**Attribution boundary.** A DGA-candidate set describes malware behaviour on a host, not an
operator. Registered DGA names are often taken by researchers as sinkholes; a sinkhole registrant
or IP is never the operator.

---

## 8. Botnet / C2 Estate Reconstruction

**Trigger.** A case involves a malware family with C2 domains or IPs (from a sample, sandbox
report or feed) and the question is the **estate**: which C2 names and IPs belong together, how
they changed, and how many separate infrastructures exist.

**Source.** The Mirai study reconstructed a botnet from several vantage points, each answering a
different question: a network telescope for growth and size (Mirai probes carried a unique scan
fingerprint), Internet-wide scanning for device types, Telnet honeypots plus a malware repository
for binaries (credentials, C2 domains), active and passive DNS for ownership, C2 "milkers" for
attack commands, and DDoS-victim traces for corroboration [P07 Antonakakis et al., USENIX Sec
2017]. Ownership came from DNS expansion: starting from the C2 domains and IPs reverse-engineered
from binaries, they added each domain's historic IPs and every domain that **concurrently**
resolved those IPs, iterating to a graph of related historic domains and IPs (the RHDN / RHIP
notions from [P05 Antonakakis et al., USENIX Sec 2010]). In P07's data this gave 33 C2 clusters
sharing no infrastructure; the authors state they "cannot conclusively link each of these clusters
to distinct operators".

**Our vantage points (adaptation).** We run no telescope, honeypot or milker. Available: sample
config extraction (`/anyrun` lookup, `analyze_artifact`), dated DNS history (`/dns-history`,
`/origin-history`), CT (`/cert-history`), scan engines (`/censys`, Shodan, FOFA), threat feeds
(`/threat-check`, `/cld`), and victim-side reports.

**Steps.**
1. **Seed** with C2 names and IPs taken from samples, each tagged with sample hash and the
   sample's first-seen date.
2. **Expand with dates.** Per domain: its IPs with `[first_seen, last_seen]`. Per IP: the domains
   whose windows overlap (`fx-dns-cert-history.md` §2.7). Iterate. At **every hop** apply the
   tenancy guard (adaptation): an IP above `MAX_IP_COHOSTS` apexes, a CDN edge, parking or a
   sinkhole stops expansion and is recorded as a co-tenancy fact. P07's published cluster drawings
   include hosting-provider and unrelated names — what unguarded expansion pulls in.
3. **Cluster.** Connected components: domains as nodes, shared IPs as edges, each edge carrying
   its overlap window. A cluster is **same infrastructure**. It is not an operator, and two
   clusters are not proof of two operators.
4. **Evolution.** Tie each cluster to the samples whose configs name its domains; order by sample
   first-seen; record capability changes (P07 tracked credential lists, new scanned ports, a short
   lived DGA, packing). Relative activity from lookup volume is single-vantage (P07 used one large
   ISP and called it "not comprehensive").
5. **Window start.** P07 saw a cluster's first DNS lookups precede its use as C2 — start the
   window at first resolution, not at first sample.
6. **Residual trust.** Compare registration date with first C2 use. In P07's data at least 17% of
   Mirai C2 domains were expired names re-registered; history before re-registration is excluded.
7. **Corroborate across vantage points.** An estate claim needs two independent sources agreeing,
   e.g. sample config + pDNS window, or scan fingerprint + pDNS (P07 cross-checked telescope IPs
   against victim-side attacker lists). Feeds that republish the same report are one source, not
   several (adaptation, mirroring P07's collapsing of repeated attack commands).

**Confounders.** DHCP churn — P07 warns raw IP counts are a poor size measure; shared hosting,
CDN or bulletproof hosting fronting C2; sinkholes merging unrelated families after takedown;
port-forwarding / UPnP placing several devices behind one IP; **public source-code release** —
after Mirai's code leaked, many independent operators ran near-identical binaries, so code or
config similarity alone is never a same-operator link.

**Abstain** when: one vantage point only (report a "single-source estate sketch"); no dated
windows (no clustering); every shared IP is above the guard ("no infrastructure link found").

**Output.** One row per cluster: member domains and IPs with windows, seed samples, capability
notes, vantage points that support it, and rung (`same infrastructure` at most, unless an
owner-side link exists).

**Worked example (synthetic).**

```
Seeds (sample configs, CASE-0001)
  sample S1 (first seen 2026-03-04) → c2-alpha.example
  sample S2 (first seen 2026-04-18) → c2-bravo.example, update-check.example
  sample S3 (first seen 2026-05-30) → k3xq9vzt.example   (S3 also emits a DGA-candidate set, §7)

Dated expansion
  c2-alpha.example   192.0.2.15     2026-02-27 → 2026-04-20   (first lookup precedes S1: window starts 02-27)
  c2-bravo.example   192.0.2.15     2026-04-10 → 2026-05-02   overlap with alpha 10 days, 2 apexes on IP → edge
  c2-bravo.example   198.51.100.30  2026-05-02 → 2026-06-12
  update-check.example 198.51.100.30 2026-05-05 → 2026-06-10  overlap 36 days → edge
  update-check.example 203.0.113.80 2026-06-10 → open         312 apexes on IP → guard: co-tenancy fact, stop
  k3xq9vzt.example   203.0.113.81   2026-05-28 → 2026-06-20   no overlap with the above

WHOIS check: update-check.example re-registered 2026-04-29 → its 2019–2024 history excluded

Clusters
  C-A  c2-alpha, c2-bravo, update-check | samples S1, S2 | vantage: config + pDNS | same infrastructure
       evolution: S2 adds a second C2 name and a new scanned port
  C-B  k3xq9vzt                          | sample S3       | vantage: config only  | single-source sketch

Report: "C-A is one infrastructure (two vantage points, dated overlaps). C-B shares no dated
infrastructure with C-A. Whether C-A and C-B have one operator is not established."
Not said: that the 312 tenants of 203.0.113.80 are related, or that C-B is a different operator.
```

---

## 9. Confidence Ratings

| Finding Type | Confidence | Notes |
|--------------|-----------|-------|
| crt.sh CT log match | HIGH | Certificate was issued; subdomain existed |
| Subfinder verified source | HIGH | Cross-referenced across providers |
| Amass passive result | HIGH | 87-source cross-reference |
| GAU historical URL | MEDIUM | May be decommissioned |
| ASN attribution | HIGH | BGP routing data is authoritative |
| Inferred from naming pattern | LOW | Guessed, not confirmed |

---

## 10. Limitations

- **Passive only = no brute-force:** Uncommon or internal subdomains may be missed entirely
- **Wildcard DNS:** `*.example.com` resolving causes false positives in active probing; passive unaffected
- **crt.sh rate limits:** Excessive queries may return 429; add `sleep 2` between requests
- **Subfinder free tier:** Without provider API keys, ~30% of sources active. Configure `provider-config.yaml` for full coverage (Shodan, Censys, SecurityTrails, etc.)
- **Amass speed:** Passive mode with 87 sources can take 10-30 min for large orgs; use `-timeout` flag
- **GAU completeness:** Wayback Machine coverage varies; recent subdomains may not be archived
- **CDN masking:** Cloudflare/Akamai/Fastly IPs mask origin — ASN will show CDN, not host
- **§7–§8 are analyst procedures:** FANCI and the Mirai study ran on network-scale telemetry (resolver NXDOMAIN streams, telescopes, honeypots, ISP pDNS); their thresholds and rates are not rules here

---

## 11. Command Reference

### `/subdomain [domain]`

**Input:** Apex domain (e.g., `example.com`)
**Process:**
1. crt.sh CT log query
2. Subfinder passive scan
3. Amass passive enum (15-min timeout)
4. GAU historical subdomain extraction
5. Deduplicate all sources into master list
6. ASN lookup on resolved IPs
7. Cluster by provider/ASN
8. Flag high-interest naming patterns

**Subfinder Provider Config** (`~/.config/subfinder/provider-config.yaml`):
```yaml
shodan:
  - YOUR_SHODAN_API_KEY
censys:
  - YOUR_CENSYS_PAT:YOUR_CENSYS_ORG_ID   # Platform PAT; a bare PAT also works on a Free account
securitytrails:
  - YOUR_ST_API_KEY
```
All above have free tiers sufficient for OSINT use.

**Output:** Deduplicated subdomain list, ASN/provider map, flagged high-interest targets, total unique count per source.

---

*Domain Advanced Module v1.1.0*
*Part of Free OSINT Expert Skill - Phase 5*
*For authorized reconnaissance and educational purposes only*
