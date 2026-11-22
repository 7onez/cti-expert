# fx-edge-appliance-recon

## Purpose
Fingerprint internet-facing edge/VPN appliances and exposed infrastructure services from **passive banners and light path probes**, then map each product to its **CISA KEV / high-severity CVEs**. Turns a bare hostname or IP into a prioritized "known-exploited-vuln" exposure picture that feeds `/vuln-check`, `/threat-model`, and the vendor-flagging in `/subdomain`.

> **Scope discipline.** Reconnaissance only — identify product + version and map to *published* CVEs. No exploitation, no auth attempts, no fuzzing. Prefer Shodan/Censys/crt.sh historical banners over direct contact for hostile or third-party infrastructure. Direct probing is for assets the operator owns or is authorized to assess.

## Quick Reference
| Item | Detail |
|------|--------|
| Command | `/appliance-scan [domain\|ip]` — **standalone**: `/case`, `/subdomain` and `/techstack` do NOT run it. Run it yourself on the case's edge hosts (vendor-flagged subdomains, origin IPs) and import the result into the case with `intel.py appliance-scan <host> --case <ID> --kb knowledge` (engine-root relative; T1: `case=<ID> record_kb=true`) → `cases/<ID>/appliances.json` + KB facts |
| Implementation | `intel_engine/WebPivot/tools/wp_appliance.py` — **T2:** `intel.py appliance-scan <domain\|ip> [--free-only] [--case ID] [--kb DIR] [--advisory ID:YYYY-MM-DD[:fixed,…[:CVE]]] [--version-confirmed] [--edition standard\|fips\|ndcpp] --json` · **T1:** `appliance_scan`. Passive only (InternetDB keyless; Shodan host / Censys keyed, skipped under `--free-only` / scope `no_spend`, ledgered); KEV catalogue cached per `WebPivot/references/appliance.json`; output `cases/<id>/appliances.json`, KB facts only |
| Input | Domain, subdomain, or IP (best fed the vendor-flagged hosts from `/subdomain`) |
| Output | Per-host product + version + matched KEV/CVE list + severity |
| Confidence | HIGH for product-specific path/banner; version→CVE is TENTATIVE until the ANALYST confirms the version (a CPE or scan-index version field is not a confirmation) |

## Edge / VPN Appliance Fingerprint → KEV Catalog
Product-specific login/portal paths. Presence confirms product; grab version from HTML/headers, then confirm CVE applicability via `/vuln-check`.

| Product | Fingerprint path(s) | Notable exploited CVEs (verify version) |
|---------|--------------------|------------------------------------------|
| Citrix NetScaler / Gateway | `/vpn/index.html`, `/logon/LogonPoint/tmindex.html` | CVE-2023-4966 (CitrixBleed, KEV), CVE-2023-3519 (RCE, KEV), CVE-2019-19781 (KEV) |
| F5 BIG-IP | `/tmui/login.jsp`, `/mgmt/tm/sys/` + `BIGipServer` cookie | CVE-2022-1388 (auth bypass, KEV), CVE-2023-46747 (RCE) |
| Cisco ASA / AnyConnect | `/+CSCOE+/logon.html`, `/+CSCOE+/portal.html` | CVE-2020-3452 (file read, KEV), CVE-2018-0101 (RCE) |
| Ivanti / Pulse Connect Secure | `/dana-na/`, `/dana-na/auth/url_default/welcome.cgi` | CVE-2024-21887 (KEV), CVE-2023-46805 (KEV) |
| Fortinet FortiGate SSL-VPN | `/remote/login`, `/api/v2/` | CVE-2024-21762 (RCE, KEV), CVE-2022-42475 (RCE, KEV) |
| Palo Alto GlobalProtect | `/global-protect/login.esp`, `/sslmgr` | CVE-2024-3400 (RCE, KEV), CVE-2019-1579 |
| Microsoft Exchange (OWA/ECP) | `/owa/`, `/ecp/`, `/ews/exchange.asmx` | ProxyShell (CVE-2021-34473, KEV), ProxyLogon (CVE-2021-26855, KEV), ProxyNotShell (CVE-2022-41040) |

**Escalation rule:** a host whose version the **analyst has confirmed** (`--version-confirmed` / `version_confirmed=true`, after `/vuln-check`, the vendor advisory or an authorised check) and that is below the vendor's fixed release for a **CISA KEV** CVE → **CRITICAL**, regardless of other posture. A version read only from a CPE, the scan index's version field, a banner or a build string stays **TENTATIVE**, even when it is pre-fix. Attach the KEV CVE, the observed version string, where it was read, who confirmed it, and the evidence URL/banner.

**Citrix FIPS / NDcPP editions.** NetScaler ships standard, FIPS and NDcPP firmware trains that share release numbers: 13.1-37.x is both a standard build (13.1-37.38) and the FIPS train, and the bulletins give each edition its own fix (CTX579459: standard 13.1-49.15, 13.1-FIPS 13.1-37.164, 12.1-FIPS / 12.1-NDcPP 12.1-55.300; CTX561482: standard 13.1-49.13, 13.1-FIPS 13.1-37.159, 12.1-FIPS / 12.1-NDcPP 12.1-55.297; standard 12.1 is EOL with no fix). Comparing a FIPS build with the standard list misreads it — 13.1-FIPS 37.164 is fixed, yet reads pre-fix against 13.1-49.15. Citrix documents **no build range** that separates the trains, so `/appliance-scan` decides the edition only from documented signals:
- a **marker** inside version-bearing evidence (a CPE string or the index's product/version field) — Citrix names FIPS firmware with `FIPS` in the version (`14.1-FIPS, build 72.61`, [NetScaler FIPS FAQ](https://docs.netscaler.com/us/en/citrix-adc/current-release/fips/fips-faq.html)), and the bulletins name `-NDcPP`; a mention elsewhere in a page body does not count;
- an **exact match** in the vendor's standard 13.1 build index ([13.1 release notes](https://docs.netscaler.com/us/en/citrix-adc/13-1/citrix-adc-release-notes.html)) → standard. Absence from that index is not evidence of FIPS;
- the analyst's **`--edition standard|fips|ndcpp`** (`edition=`) after checking the device.

A known edition is compared with its own fixed list (`fixed_fips` / `fixed_ndcpp` in `WebPivot/references/appliance.json`). An unknown edition gets a single verdict only when every edition's list agrees; when they disagree the row reads `ambiguous_edition`, lists each edition's verdict, and the product stays **TENTATIVE** — even with `--version-confirmed` — with the reason "edition unknown, fixes differ by edition, no documented build range". The rules and build index live in `appliance.json → products.citrix_netscaler.editions`.

## Exposed-Service Port-Risk Matrix (passive, via Shodan InternetDB)
Query **without direct contact**: `curl -s https://internetdb.shodan.io/{IP}` returns open ports + CPE + hostnames. Map high-risk ports:

| Port | Service | Why it matters if internet-facing |
|------|---------|-----------------------------------|
| 445 | SMB | Legacy RCE family / anonymous shares |
| 2375 | Docker API (plaintext) | Unauthenticated host/container takeover |
| 3389 | RDP | BlueKeep-class exposure; brute/relay surface |
| 6379 | Redis | No-auth default; common data exposure |
| 9200 | Elasticsearch | Typically unauthenticated index access |
| 27017 | MongoDB | No-auth by default |
| 10250 | Kubelet (HTTPS) | Unauth pod listing/exec if misconfigured |
| 2379 | etcd | Cluster secrets exposure |
| 6443 | Kubernetes API | `system:anonymous` access if unrestricted |

For k8s/container ports, treat a public response as **CRITICAL** (they should never be internet-facing) and hand off to `techniques/cloud-audit.md`.

## Passive Patch-Lag Inference
Estimate how far behind a vendor fix an edge device runs **without sending it a packet**. Use only what public scan indexes, the Wayback Machine and urlscan already stored. There are two independent signals; report each separately and never merge them into "vulnerable".

> **Passive only.** Every input below comes from a scan-database record (Shodan, Censys, Netlas, ZoomEye, FOFA), an archive capture or a urlscan result someone else already made. Do **not** fetch the login page, query SNMP or open a TCP session to time it against a third-party asset. The scope rule at the top of this file applies; direct checks are for assets the operator owns or is authorised to assess.

### A. Uptime → "no reboot since"
Some indexes store an uptime value per service record:
- an SNMP `sysUpTime` read (OID `1.3.6.1.2.1.1.3.0`, [RFC 3418](https://www.rfc-editor.org/rfc/rfc3418));
- an uptime field in the banner (Shodan documents one in its [banner specification](https://datapedia.shodan.io/));
- an estimate from TCP timestamps ([RFC 7323](https://www.rfc-editor.org/rfc/rfc7323)).

Compute **boot ≈ scan timestamp − uptime**. Use the scan timestamp of that index record, not today's date.

**Wording:** "No reboot since ⟨boot date⟩ (per ⟨index⟩ record of ⟨scan date⟩); firmware updates that need a reboot cannot have been applied since then." **Never** write "vulnerable" or "unpatched". The vendor may ship the fix without a reboot (see the caveats).

Compare the boot date with the fix release date. If boot < fix date and the vendor's upgrade notes say the firmware upgrade reboots the device, the fixed firmware was not installed as of that scan.

Caveats. State the ones that apply:
- **Counter wraparound.** SNMP `sysUpTime` is a 32-bit TimeTicks value in hundredths of a second ([RFC 2578](https://www.rfc-editor.org/rfc/rfc2578) §7.1.8). It wraps every 2³² / 100 s ≈ **497.1 days**, so an uptime of 30 days may really be 527 or 1,024. A 1 kHz TCP-timestamp clock wraps every ≈ 49.7 days. Corroborate with two scans far enough apart: the uptime must grow by the elapsed time.
- **Load balancers and HA pairs.** One IP can front two or more nodes. The uptime you see belongs to whichever node answered that scan. Another node may have been upgraded and rebooted, or not. Conflicting uptimes across scans of one IP are a sign of this, not of a reboot.
- **Hot patching.** Some platforms apply hotfixes, configuration mitigations or kernel live-patches without a reboot. A long uptime then shows only that no *reboot-requiring* update was applied. Check the vendor advisory for whether the fix or its workaround needs a reboot.
- **Clock and scan-date offsets.** The index timestamp may be the ingest time rather than the probe time. Scanners may cache the uptime from an earlier probe. Many OSes randomise TCP-timestamp offsets per connection, as RFC 7323 recommends, so a TCP-derived uptime is often meaningless. Give the boot date as "on or about" (±1 day at least).

### B. Announced version or build → lag after advisory
Many appliances announce their software version or build in:
- the server or portal banner;
- a version endpoint body that the index stored;
- or, most often, **cache-busting query strings and timestamps on login-page static assets**, such as `?v=`, `?build=`, a build date inside an asset path, or a gzip header timestamp. Fox-IT documented this for Citrix NetScaler ([blog, 2022-12-28](https://blog.fox-it.com/2022/12/28/cve-2022-27510-cve-2022-27518-measuring-citrix-adc-gateway-version-adoption-on-the-internet/); [version-hash table](https://gist.github.com/fox-srt/c7eb3cbc6b4bf9bb5a874fa208277e86)).

Read these from the index's stored HTTP body and headers, a Wayback capture or a urlscan result.

1. **Map the build to a version** with the vendor's release notes or a published hash/timestamp table. If no mapping exists, keep the raw build string and mark the version UNMAPPED.
2. **Find the advisory.** Use the vendor PSIRT advisory for each CVE affecting that version: its publication date and the first fixed version. Resolve the CVEs with `/vuln-check` and check the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) for `dateAdded` and `dueDate` ([BOD 22-01](https://www.cisa.gov/news-events/directives/bod-22-01-reducing-significant-risk-known-exploited-vulnerabilities)).
3. **Compute lag.** Lag = (latest scan date still announcing a pre-fix build) − (advisory publication date), in days. A negative value means the build was last seen before the advisory: no lag can be shown. A build that later changes to a fixed one bounds the patch date between the two scans.
4. **Escalate.** Apply the **escalation rule** above: a pre-fix version matching a KEV entry is **TENTATIVE** until the analyst confirms the version, then **CRITICAL**. Add "past the KEV due date" when the last pre-fix scan falls after `dueDate`. That is context for prioritisation, not a legal finding about a non-federal subject.

### Table template
| Device | Announced version or build | First seen | Advisory date | Lag | Evidence |
|--------|----------------------------|------------|---------------|-----|----------|
| ⟨host (IP)⟩ — ⟨product⟩ | ⟨build string → mapped version, or UNMAPPED⟩ | ⟨first scan date announcing this build⟩ | ⟨vendor advisory id, publication date; KEV dateAdded⟩ | ⟨days after the advisory, last pre-fix scan⟩ | ⟨index + record date, asset URL / banner field; uptime line if any⟩ |

### Worked example (synthetic)
The device is `vpn.example.com` (`203.0.113.10`), product "ExampleGate SSL-VPN" (fictitious). The advisory is **EXAMPLE-SA-2026-001** for **CVE-2099-0001** (synthetic): published 2026-06-10, fixed in 9.4.2, added to KEV on 2026-06-12. The vendor's upgrade notes say a firmware upgrade reboots the device.

Stored records, with no contact to the host:
- index record, 2026-05-20: login page references `/static/login.js?build=20260302`; release notes map build 20260302 to **9.4.0**;
- index record, 2026-07-28: the same `?build=20260302`; the SNMP service record shows uptime **140 days** → boot ≈ **2026-03-10**.

| Device | Announced version or build | First seen | Advisory date | Lag | Evidence |
|--------|----------------------------|------------|---------------|-----|----------|
| vpn.example.com (203.0.113.10) — ExampleGate SSL-VPN | `build=20260302` → 9.4.0 | 2026-05-20 | EXAMPLE-SA-2026-001, 2026-06-10; KEV 2026-06-12 | **48 days** (still pre-fix 2026-07-28) | index HTTP body 2026-05-20 + 2026-07-28 (`/static/login.js?build=`); SNMP uptime 140 d at 2026-07-28 |

Write-up:
- "No reboot since about 2026-03-10; a firmware update that needs a reboot, including 9.4.2, cannot have been applied as of 2026-07-28."
- "The announced build maps to 9.4.0, below the fixed 9.4.2, and CVE-2099-0001 is in KEV. This is **TENTATIVE** (version inferred from a static-asset build string, not analyst-confirmed); it becomes **CRITICAL** once the analyst confirms 9.4.0."
- "A 140-day reading could in principle be 637 days (one 497-day wrap). That would put the boot in late 2024, before build 20260302 existed, and installing that build reboots the device. So 140 days is the only consistent reading."
- "Only one uptime reading exists, so an HA pair behind 203.0.113.10 cannot be excluded."

The write-up does **not** say "vpn.example.com is vulnerable".

## Methodology
1. Pick the case's edge hosts — vendor-flagged hosts from `/subdomain` (VPN/gateway/citrix/fortinet/owa prefixes) or an IP list — and run `/appliance-scan` on each with `--case <ID>` (it is not run automatically by any other command).
2. **Passive first:** pull banners from Shodan / Censys / crt.sh history and InternetDB — no packets to the target.
3. If authorized for direct contact: `curl -skI` the product path; confirm product from HTML title / headers / cookies.
4. Extract version string; run `/vuln-check <product/version>` (CIRCL + NVD) to resolve applicable CVEs.
5. Apply the **escalation rule**: a KEV CVE whose verified advisory shows the version as pre-fix → TENTATIVE; it becomes CRITICAL only after you confirm the version and re-run with `--version-confirmed` (the output's `version_confirmed_by` then reads `analyst`). Any other KEV family match → TENTATIVE. Record product, version, CVE, evidence, UTC timestamp. `wp_appliance` only uses advisory rows that carry `verified` + `source_url` in `WebPivot/references/appliance.json` (or one you pass with `--advisory`).
6. For each matched device, run the **Passive Patch-Lag Inference** above (uptime → "no reboot since"; announced build → lag in days after the advisory). Fill the table template from scan-database records only.
7. Hand exposed k8s/container/DB services to `cloud-audit.md`; hand Microsoft edge to `microsoft-tenant-recon.md`.

## Tools & Fallbacks
| Priority | Tool | Notes |
|----------|------|-------|
| 1 | Shodan InternetDB | `curl -s https://internetdb.shodan.io/{IP}` — free, no key, no target contact |
| 2 | crt.sh / Censys | Historical banners, cert SANs → sibling hosts |
| 3 | curl `-skI` | Direct path/header probe (authorized targets only) |
| 4 | Shodan/Censys (keyed) | Richer banners via `/apikeys`; upgrades this technique |
| 5 | `/vuln-check` | CVE resolution (CIRCL + NVD) once version is known |

## Output Format
```
Host: vpn.example.com (203.0.113.10)
  Product:   ExampleGate SSL-VPN (fictitious)  (/static/login.js?build=20260302 → 9.4.0, index record)
  KEV match: CVE-2099-0001 (synthetic; RCE, CISA KEV)  → TENTATIVE (pre-fix; CRITICAL once the analyst confirms the version)
  Evidence:  index HTTP body for https://vpn.example.com/  (2026-07-18T09:12:00Z)
  Note:      version-based match — confirm patch level before asserting exploitability
```

## Limitations
- Version strings are often stripped/spoofed; a fingerprint confirms *product*, not exploitability — always mark version→CVE mapping TENTATIVE until the version is verified.
- KEV/CVE lists drift; re-resolve via `/vuln-check` at analysis time rather than trusting the static table above.
- Direct path probing is detectable and may be logged/blocked — prefer passive banner sources for third-party infra.
- A WAF/reverse-proxy in front can mask or fake product paths (see [fx-http-fingerprint.md](fx-http-fingerprint.md)).

## Related Techniques
- [fx-http-fingerprint.md](fx-http-fingerprint.md) — server/WAF/CDN header fingerprinting (feeds product detection)
- [threat-intel.md](threat-intel.md) — `/vuln-check` CVE resolution, ransomware/KEV context
- [microsoft-tenant-recon.md](microsoft-tenant-recon.md) — Microsoft edge (OWA/Exchange) tenant angle
- [cloud-audit.md](cloud-audit.md) — exposed container/k8s/DB service deep audit
- [fx-saas-identity-recon.md](fx-saas-identity-recon.md) — SaaS tenancy + IdP surface mapping
- [fx-supplier-exposure.md](fx-supplier-exposure.md) — supplier map and third-party risk; on-prem vendor products come back here for patch lag
