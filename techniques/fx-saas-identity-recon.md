# fx-saas-identity-recon

## Purpose
Map an organization's **SaaS tenancy and identity fabric** from passive signals: which third-party platforms it uses (each a separate credential/MFA/data surface), which identity provider (IdP) fronts its logins, and which API/GraphQL/spec endpoints are reachable without auth. Complements `microsoft-tenant-recon.md` (`/msftrecon`) by covering the non-Microsoft identity landscape and the broader SaaS estate.

> **Scope discipline.** All techniques here are passive metadata fetches (DNS TXT, OIDC discovery documents, unauthenticated spec paths). **No user enumeration, no login attempts, no credential submission** against third-party targets. Treat inferred tenancy as attack-surface intel for `/threat-model`, not as an access invitation.

## Quick Reference
| Item | Detail |
|------|--------|
| Command | `/saas-map [domain]` (also runs inside `/case`, `/msftrecon`) |
| Input | Root domain |
| Output | SaaS tenancy list, IdP fingerprint, reachable API/spec endpoints |
| Confidence | HIGH for server-returned discovery docs; TENTATIVE for inferred tenancy from a single token |

## DNS-TXT SaaS-Tenancy Token Catalog
Each verification TXT record proves the org provisioned that platform — a distinct attack surface with its own credentials and MFA. Pull with `dig +short TXT {domain}` (and on `_dmarc`, `selector._domainkey`, subdomains).

| TXT pattern | Platform revealed |
|-------------|-------------------|
| `google-site-verification=` | Google Workspace / Search Console |
| `MS=ms########` | Microsoft 365 (legacy verification format) |
| `mscid=` | Microsoft 365 (newer format) |
| `atlassian-domain-verification=` | Atlassian Cloud (Jira/Confluence) |
| `zscaler-verification-...` | Zscaler (ZIA/ZPA/ZDX) customer |
| `_amazonses.` / `amazonses:` | AWS SES sender identity |
| `salesforce-domain-verification=` | Salesforce |
| `workday-domain-verification=` | Workday (HR + Finance) |
| `docusign=` | DocuSign |
| `facebook-domain-verification=` | Meta Business |
| `adobe-idp-site-verification=` | Adobe Enterprise / Federated ID |

Record each as an INFO/MEDIUM finding: "org is a `{platform}` tenant → separate identity boundary." Cluster of tokens = rich shadow-IT / SSO map.

## IdP / SSO Fingerprinting (OIDC discovery)
Fetch the OpenID discovery doc and read the `issuer` field — no auth, no enumeration:
```
curl -s https://{host}/.well-known/openid-configuration
```
Probe SSO subdomain prefixes: `auth login sso idp iam identity accounts oauth`.

| `issuer` / URL contains | IdP |
|-------------------------|-----|
| `login.microsoftonline.com` | Microsoft Entra (→ `/msftrecon` for tenant GUID, federation) |
| `*.okta.com` / `*.oktapreview.com` | Okta |
| `*.auth0.com` | Auth0 |
| `*.onelogin.com` | OneLogin |
| `*.pingone.com`, `*.pingidentity.com` | Ping Identity |
| `/realms/<realm>` | Keycloak |
| `accounts.google.com` + MX `aspmx.l.google.com` | Google Workspace |

**ADFS (on-prem federation) passive fingerprint:** `GET https://{domain}/adfs/ls/idpinitiatedsignon.aspx` → 200 + `urn:com:microsoft:ADFS:` in HTML confirms ADFS (version often greppable). Federation posture from `getuserrealm.srf` is covered in [microsoft-tenant-recon.md](microsoft-tenant-recon.md).

**`device_authorization_endpoint`** present + unrestricted in the discovery doc = note device-code-phishing exposure (MEDIUM) for `/threat-model`.

## Unauthenticated API / GraphQL / Spec Discovery
Reachable API contracts leak internal structure and shadow endpoints. Probe (authorized targets):

**OpenAPI / Swagger:** `swagger.json`, `swagger.yaml`, `/api-docs`, `/api/swagger`, `/openapi.json`, `/v2/api-docs`, `/v3/api-docs`
→ spec reachable **without auth** = HIGH `LEAKY_API_SPEC`.

**GraphQL:** `/graphql`, `/graphiql`, `/api/graphql`, `/query`, `/playground`
→ if introspection is enabled, the schema is fully enumerable:
```graphql
query IntrospectionQuery { __schema { queryType { name } types { name kind fields { name } } } }
```
Introspection on **production** = HIGH; non-prod = MEDIUM.

Feed reachable specs to `techniques/owasp-audit.md` / `techniques/dependency-audit.md` for endpoint triage.

## Methodology
1. `dig +short TXT {domain}` (+ common subdomains) → match the tenancy token catalog.
2. Enumerate SSO prefixes; fetch `/.well-known/openid-configuration`; read `issuer` → IdP.
3. If Microsoft → hand to `/msftrecon`; if ADFS → passive `idpinitiatedsignon.aspx` fingerprint.
4. On live web hosts, probe the OpenAPI/GraphQL path lists; test GraphQL introspection (read-only).
5. Record each tenant/IdP/endpoint as a typed finding with the confirming URL + UTC timestamp.
6. Roll SaaS estate + IdP into `/threat-model` (federation = single-point-of-compromise; each SaaS = credential-reuse surface).

## Tools & Fallbacks
| Priority | Tool | Notes |
|----------|------|-------|
| 1 | `dig` / DNS-over-HTTPS | TXT record pull (`https://dns.google/resolve?name={d}&type=TXT`) |
| 2 | curl | OIDC discovery + spec/GraphQL probes |
| 3 | crt.sh | SSO subdomain discovery via CT logs |
| 4 | `/msftrecon` | Microsoft tenant deep-dive when Entra/ADFS detected |
| 5 | Shodan/Censys (keyed) | Confirm IdP hosts / SaaS edges via `/apikeys` |

## Output Format
```
Domain: example.com

SaaS Tenancy (DNS-TXT):
  Microsoft 365        (MS=ms12345678)
  Atlassian Cloud      (atlassian-domain-verification=...)
  Workday              (workday-domain-verification=...)   ← HR/Finance surface

Identity Provider:
  Okta                 (issuer: https://acme.okta.com)   [login.example.com → 302 acme.okta.com]
  device-code flow:    enabled, unrestricted  → phishing exposure (MEDIUM)

Reachable API Surface:
  /openapi.json        200, no auth   → LEAKY_API_SPEC (HIGH)
  /graphql             introspection ENABLED on prod  → HIGH
```

## Limitations
- A single TXT token can be stale (platform since dropped); corroborate with live login/MX before asserting active tenancy.
- OIDC discovery reveals the IdP but not account validity — never chain into user enumeration on third-party tenants.
- Spec/GraphQL probing is active and logged; restrict to owned/authorized assets and prefer Wayback CDX for third-party historical specs.
- Some orgs proxy multiple IdPs; one `issuer` may not be the whole identity picture.

## Related Techniques
- [microsoft-tenant-recon.md](microsoft-tenant-recon.md) — Microsoft Entra/ADFS tenant GUID + federation (`/msftrecon`)
- [fx-dns-cert-history.md](fx-dns-cert-history.md) — DNS/cert history feeding subdomain + token discovery
- [fx-edge-appliance-recon.md](fx-edge-appliance-recon.md) — internet-facing appliance KEV mapping
- [owasp-audit.md](owasp-audit.md) / [dependency-audit.md](dependency-audit.md) — triage discovered API endpoints
- [secret-scanning.md](secret-scanning.md) — validate any keys found for discovered SaaS platforms (read-only)
