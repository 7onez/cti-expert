# fx-edge-appliance-recon

## Purpose
Fingerprint internet-facing edge/VPN appliances and exposed infrastructure services from **passive banners and light path probes**, then map each product to its **CISA KEV / high-severity CVEs**. Turns a bare hostname or IP into a prioritized "known-exploited-vuln" exposure picture that feeds `/vuln-check`, `/threat-model`, and the vendor-flagging in `/subdomain`.

> **Scope discipline.** Reconnaissance only — identify product + version and map to *published* CVEs. No exploitation, no auth attempts, no fuzzing. Prefer Shodan/Censys/crt.sh historical banners over direct contact for hostile or third-party infrastructure. Direct probing is for assets the operator owns or is authorized to assess.

## Quick Reference
| Item | Detail |
|------|--------|
| Command | `/appliance-scan [domain\|ip]` (also runs inside `/case`, `/subdomain`, `/techstack`) |
| Input | Domain, subdomain, or IP (best fed the vendor-flagged hosts from `/subdomain`) |
| Output | Per-host product + version + matched KEV/CVE list + severity |
| Confidence | HIGH for product-specific path/banner; version→CVE is TENTATIVE until version confirmed |

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

**Escalation rule:** any host whose product+version matches a **CISA KEV** entry → **CRITICAL** finding regardless of other posture. Attach the KEV CVE, the observed version string, and the confirming evidence URL/banner.

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

## Methodology
1. Feed vendor-flagged hosts from `/subdomain` (VPN/gateway/citrix/fortinet/owa prefixes) or an IP list.
2. **Passive first:** pull banners from Shodan / Censys / crt.sh history and InternetDB — no packets to the target.
3. If authorized for direct contact: `curl -skI` the product path; confirm product from HTML title / headers / cookies.
4. Extract version string; run `/vuln-check <product/version>` (CIRCL + NVD) to resolve applicable CVEs.
5. Flag any KEV match as CRITICAL; record product, version, CVE, evidence URL, UTC timestamp.
6. Hand exposed k8s/container/DB services to `cloud-audit.md`; hand Microsoft edge to `microsoft-tenant-recon.md`.

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
  Product:   Fortinet FortiGate SSL-VPN  (/remote/login, version 7.0.6 in HTML)
  KEV match: CVE-2024-21762 (RCE, CISA KEV)  → CRITICAL
             CVE-2022-42475 (RCE, CISA KEV)  → CRITICAL
  Evidence:  https://vpn.example.com/remote/login  (2026-07-18T09:12:00Z)
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
