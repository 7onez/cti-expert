# fx-supplier-exposure

## Purpose
Derive the **suppliers** an organisation depends on (SaaS, mail, DNS, CDN, certificate authority, identity provider) from evidence the case already collected. Then assess each supplier as **third-party risk to the subject**: the supplier's public breaches, actively exploited vulnerabilities (KEV) in its products, and infostealer infections among its staff whose stolen credentials include the subject.

This is the supply-chain half of an organisation risk assessment. It answers two questions: "who could be breached instead of us, and still hurt us?" and "which vendor can already send mail as us, or sign in for us?"

> **Attribution rail.** A supplier is a **relationship of the subject**, shared with every other customer of that vendor. It is never an operator link, a same-operator edge or a cluster key. The builder records it as a KB *fact*, never an edge. Two organisations that both use one vendor are **not** linked by that vendor.

> **Scope discipline.** Passive only. The supplier map is built from stored raws: no network, no credits. The per-supplier checks use the existing breach, stealer and vulnerability tools under their own gates, which include the metered-spend prompts. Nothing here logs in to a vendor, enumerates its users or probes its infrastructure.

## Quick Reference
| Item | Detail |
|------|--------|
| Builder | `python3 intel_engine/WebPivot/tools/wp_suppliers.py <CASE> --subject example.com[,example.net] [--kb <kb-dir>] [--print]` |
| Input | `cases/<id>/raw/*.json` (`pivot_extract` output: `artifacts.mail` MX/SPF/TXT, `whois.name_servers`, `tls_cert.issuer`, `artifacts.cnames`, `docmeta` files) |
| Output | `cases/<id>/suppliers.json`: `{subjects, relation, suppliers:[{name, category, evidence:[{kind, value, host, confidence}], confidence}], generated_utc, compiled_to, inputs, caveats}` |
| Pattern table | `intel_engine/WebPivot/references/suppliers.json` (TXT prefixes, SPF includes, CNAME targets, NS hosts, CA issuers, document keywords, confidence rules). MX hosts reuse `mail_providers.json`. |
| KB | `--kb` writes one `supplier` fact per (subject apex, supplier) and never an edge |
| Confidence | **high**: an exact TXT verification token, SPF include, MX or NS on the subject's own apex. **medium**: the same on a subdomain, a CNAME, or the certificate issuer. **low**: a document-metadata mention. |

## Evidence → supplier
| Evidence kind | Read from (raw) | What it proves | Default confidence |
|---------------|-----------------|----------------|--------------------|
| `txt_verification` | `artifacts.mail.txt_verifications[].record`, `artifacts.mail.txt_records[]` | The subject verified domain control to the vendor, so an account existed | high (apex) |
| `spf_include` | `artifacts.mail.spf.includes[]`, `spf_include` pivots | The vendor is authorised to **send mail as the subject** ([RFC 7208](https://www.rfc-editor.org/rfc/rfc7208)) | high (apex) |
| `mx` | `artifacts.mail.mx_hosts[]` → `mail_providers.json` | The vendor receives the subject's mail | high (apex) |
| `ns` | `artifacts.whois.name_servers[]` | The vendor answers the subject's DNS | high (apex) |
| `cname` | `artifacts.cnames[]` = `{host, chain}`: the collected host always; on an **organisation case** (`scope.json` `subject_type=org`) also, for an apex, the guessed `cname_probe_labels` under it (`www`, `sso`, `mail`, `status` — up to 5 first-hop CNAME lookups per apex, then one more per hop of any alias found); other cases resolve only the collected host. Resolved by the recursive resolver (`wp_recon.detect_cnames`); the queries reach the target's authoritative nameservers, so they are visible to the target | A subject name is served by the vendor (and is a takeover risk if the account lapses). Context only: no KB edge, no frontier seed | medium |
| `cert_issuer` | `artifacts.tls_cert.issuer` | The CA issued the subject's certificate (a CDN may have ordered it) | medium |
| `document` | `artifacts.docmeta.files[].meta` (producer, creator tool, software, title) on a subject host | One file passed through the tool | low |

Only hosts at or under a `--subject` apex count. A token, include or host that matches no row is **ignored**, never guessed. Add a row to `suppliers.json` when a run shows an unclassified one. Check the vendor's own documentation for the record shape before you add it.

## Methodology
1. **Collect.** Run the normal case collection on the subject's apexes (`/case` or `pivot_extract`), so each raw carries `artifacts.mail`, `whois` and `tls_cert`.
2. **Derive suppliers.** Run `wp_suppliers.py <CASE> --subject <apexes>`. Read `suppliers.json` top-down: high-confidence suppliers first.
3. **Corroborate before asserting current use.** A TXT token alone may be stale. Treat a supplier as **current** only when a second, independent evidence kind agrees (for example TXT + SPF, or TXT + MX). Otherwise write "verified at some point; current use not confirmed".
4. **For each supplier, check its public breaches.** Use the vendor's own apex as the selector:
   - `/breach-deep <vendor-domain>` (`scripts/osint/deep_profile.py --mode breach`): Hudson Rock `search-by-domain`, IntelX and the breach corpora (see [fx-breach-discovery.md](fx-breach-discovery.md));
   - the vendor's own security advisories or incident disclosures.
   Record each breach with its date and what data classes were in scope.
5. **For each supplier, check for KEVs in its products.** Run `/vuln-check --product "<vendor> <product>"` (`scripts/osint/vuln_check.py`; CIRCL + NVD). Cross-check the [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) ([JSON feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json), field `vendorProject`).
   - For **SaaS**, the vendor patches its own service, so a KEV is risk only during the vendor's exposure window. Quote the vendor advisory date.
   - For **on-premises products** the subject runs itself (an appliance, or a self-hosted server), hand the host to [fx-edge-appliance-recon.md](fx-edge-appliance-recon.md) for the patch-lag check.
6. **For each supplier, check for stealer infections among its staff that carry the subject.** The signal is a stolen-credential record whose **login identity is at the vendor's domain** and whose **URL is a subject host**: a vendor employee's machine holding access to the subject.
   - **Hudson Rock:** run `search-by-domain` / `urls-by-domain` on the **subject** domain, then filter the employee/third-party rows to vendor-domain logins.
   - **IntelX:** `intelx_search` on the subject domain with the logs pass, then open each `stealer_log_items` entry **one by one**. A log is one machine at one moment.
   - **Logs already in hand:** `uv run scripts/stealer_log_parse.py <logs> <out> --subject-emails <subject-addresses>` (see [stealer-log-analysis.md](stealer-log-analysis.md) §8 for corporate SaaS tagging).
   - Report counts and dates only. Personal data of vendor staff goes through the house report's third-party masking.
7. **Report** as a *Third-party risk* section (the template is below). Each row is a **risk to the subject through the supplier**, with its caveats. It is never a finding of compromise.

## Output Format
```
Third-party risk — example.com (public sources, compiled to 2026-11-01)

Supplier            Category                 Evidence (confidence)                       Supplier-side signal
Microsoft 365       email & productivity     TXT MS=, MX, SPF (high, current)            no signal checked
ExampleMail Co      email delivery           SPF include spf.examplemail.example (high)  vendor breach disclosed 2026-03 (customer
                                                                                         API keys in scope) → rotate keys, review SPF
ExampleSSO          identity provider        CNAME sso.example.com (medium)              2 stealer logs: vendor-domain login with an
                                                                                         sso.example.com URL, 2026-08 → reset, confirm MFA
DocuSign            e-signature              document metadata (low)                     none checked: mention only, account unproven
```
Real vendor names appear only where they map evidence (TXT `MS=` → Microsoft 365). Every illustrative breach, KEV or stealer signal is attached to a fictional vendor (ExampleMail Co, ExampleSSO).

## Worked example (synthetic)
The case is `CASE-0001` and the subject is `example.com`. The collected raw for `example.com` holds:
- `mail.txt_records`: `MS=ms00000000`, `atlassian-domain-verification=AAAABBBB`, `vendorx-verify=ZZZZ`;
- `mail.spf.includes`: `spf.protection.outlook.com`, `sendgrid.net`;
- `mail.mx_hosts`: `example-com.mail.protection.outlook.com`;
- `whois.name_servers`: `ns-0001.awsdns-00.com`;
- `tls_cert.issuer`: `DigiCert Inc`.

The `example.com` raw's `artifacts.cnames` holds `{"host": "sso.example.com", "chain": ["example.okta.com"]}`. A same-site PDF at `https://example.com/files/contract.pdf` has producer `DocuSign PDF Generator`.

`wp_suppliers.py CASE-0001 --subject example.com` yields:
- **high:** Microsoft 365 (TXT + MX + SPF), Atlassian (TXT), SendGrid (SPF), Amazon Route 53 (NS);
- **medium:** DigiCert (certificate issuer), Okta (CNAME on `sso.example.com`);
- **low:** DocuSign (document mention).

`vendorx-verify=ZZZZ` matches no row, so it is ignored.

Then the per-supplier checks. To illustrate their output without attributing incidents to real vendors, assume `sso.example.com` instead pointed at `tenant.examplesso.example`, and an analyst-added `cname_targets` row maps `.examplesso.example` to the fictional **ExampleSSO**:
- **Atlassian** (verified, but no second evidence kind): reported as "verified at some point; current use not confirmed". No supplier-side signal was checked.
- **ExampleSSO:** the logs pass finds one record with a `@examplesso.example` login against `https://sso.example.com/`. Reported as *one vendor-staff credential set that included the subject's SSO portal, 2026-08-14: verify the account still exists and MFA was enforced*. This is not reported as "ExampleSSO compromised example.com".

## Limitations
- **A shared SaaS vendor does not mean compromise.** A vendor breach is a risk to the subject only where the subject's data, tokens or access were in scope. Say which.
- **Dormant TXT records.** A verification record often outlives the account it verified. Corroborate with MX, SPF, a CNAME or a live login page before asserting current use.
- **Document mentions are weak.** One file produced by a tool does not prove an account (always low confidence).
- **Coverage is what was collected.** Raws hold the apex TXT records only where `artifacts.mail.txt_records` / `txt_verifications` were stored. A supplier verified on an uncollected subdomain is absent, not ruled out.
- **Vendor names are table data.** Re-check a vendor's record format against its documentation when you extend `suppliers.json`.
- For supplier-risk practice, see [NIST SP 800-161r1, Cybersecurity Supply Chain Risk Management](https://csrc.nist.gov/pubs/sp/800/161/r1/final).

## Related Techniques
- [fx-saas-identity-recon.md](fx-saas-identity-recon.md): TXT tenancy tokens and IdP fingerprint (the surface view; this file is the risk view)
- [fx-breach-discovery.md](fx-breach-discovery.md): breach corpora and Hudson Rock domain endpoints
- [stealer-log-analysis.md](stealer-log-analysis.md): reading a stealer log; corporate SaaS credential tagging
- [fx-edge-appliance-recon.md](fx-edge-appliance-recon.md): KEV escalation and passive patch-lag for products the subject runs itself
- [threat-intel.md](threat-intel.md): `/vuln-check` CVE resolution
