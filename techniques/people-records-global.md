# Public people records — global corroboration

## Purpose and evidence boundary

Use public civil, court, electoral and corporate records to corroborate a specific,
lawful identity claim, not to build indiscriminate dossiers. Coverage, access and publication
rules vary by jurisdiction and date; a search returning nothing is not evidence of absence.
Names alone never identify a person. Compare record dates, jurisdiction and independently
held identifiers; distinguish residential addresses from service/registered-office addresses.

All account, officer and relative associations remain `rung: "lead"` with a `caveat`, even
when a record explicitly states a relationship. Record claim, source URL, access date,
record date and relationship status separately. Never write these associations as KB
`add_edge` identity edges or `operator_lead` entries. Direct records can corroborate a
field; they do not prove that a web account belongs to the recorded person.

## Public sources by region

| Region | Public source / access path | What it may corroborate | Limits and interpretation |
|---|---|---|---|
| UK | [FreeBMD](https://www.freebmd.org.uk/) and the [GRO certificate/index service](https://www.gro.gov.uk/gro/content/certificates/) | Birth registration district/quarter, surname, mother's maiden surname where indexed; death age may constrain birth year; marriage index may supply spouse leads | Index coverage varies and registration is not exact birthplace/date. GRO access may require registration or payment. Order restricted certificates only through lawful entitlement, never pretexting. |
| UK | [1939 Register guidance](https://www.nationalarchives.gov.uk/help-with-your-research/research-guides/1939-register/), with licensed access through [FamilySearch](https://www.familysearch.org/) or [Ancestry](https://www.ancestry.co.uk/) where available | Historical household, address, occupation and recorded birth date; later surnames may aid maiden-name comparison | Principally England and Wales, not a UK-wide modern address index. Closed/redacted entries and provider access restrictions apply; transcription errors and historic household membership require context. |
| UK | [192.com](https://www.192.com/), legally available electoral-roll extracts, and [official register access guidance](https://www.gov.uk/electoral-register) | Dated address history, electoral registration and possible co-resident surname leads | The full register has restricted uses; the open register excludes opt-outs. No exact DOB or kinship follows from co-residence; never circumvent access or reuse restrictions. |
| UK | [Companies House](https://find-and-update.company-information.service.gov.uk/) officer records via `corp_registry` | Public officer DOB month/year, appointment dates and service-address history | Do not infer a full DOB or home address. Officers remain leads; same-name appointments and shared agents can mislead. |
| US | State vital-record offices via [CDC directory](https://www.cdc.gov/nchs/w2w/index.htm) | Public historic birth/death/marriage indexes may corroborate birth year/place and named relatives | No national unrestricted live-person vital-record search; state closure periods and certificate entitlement vary. Restricted records are not a collection fallback. |
| US | Public obituaries, including [Legacy](https://www.legacy.com/) and original publisher pages | Stated age, birthplace, surviving relatives and dated residence references | Family-submitted text can be wrong; locate the original, distinguish namesakes, and minimise incidental relatives. |
| US | State/local voter rolls where legally public, using the responsible election office | Registration/address history and age/year only if lawfully published | Access, redistribution and permitted uses differ by state; some jurisdictions prohibit non-election use. Do not acquire protected fields. |
| US | [PACER](https://pacer.uscourts.gov/) and official state court portals | Party names, case dates and explicitly stated residence/relationship facts | PACER requires an account and may charge fees; sealed/redacted material stays off limits. Allegations are not findings; party-name matches are leads. |
| US | Official county assessor/recorder/property portals | Dated property ownership, deeds and mailing-address history | Owner may be a trust/entity, mailing address need not be residence, and property co-ownership does not prove kinship. Respect protected-address exclusions. |
| EU | Official national gazettes, e.g. [Bundesanzeiger](https://www.bundesanzeiger.de/) and [BODACC](https://www.bodacc.fr/) | Corporate appointments, insolvency notices, business/service addresses and dated name variants | Coverage is publication-specific, not a general civil register; do not assume DOB, household or relatives are available. National privacy rules apply alongside GDPR. |
| Global | [FamilySearch](https://www.familysearch.org/), [BillionGraves](https://billiongraves.com/) and [Find a Grave](https://www.findagrave.com/) | Historical birth/death years, places, memorial inscriptions and proposed family links | Access may require login/onsite viewing. User trees and memorial edits are not official records; corroborate with an underlying image or civil record and consider living relatives' privacy. |
| Global | Official national company registries via `corp_registry`; official judiciary court portals | Dated office holdings, public service addresses and relationships expressly stated in records | An officer is a lead, not an operator identity. Registry fields and jurisdiction support vary; a court party is not necessarily liable or convicted. |
| SEA — Thailand | [DBD DataWarehouse](https://datawarehouse.dbd.go.th/) and [Royal Gazette](https://ratchakitcha.soc.go.th/) | Corporate registrations, disclosed officers/business addresses and official dated notices | DBD is a company source, not unrestricted personal civil records. Thai transliteration, entity changes, login/CAPTCHA and public-field restrictions require manual review. |
| SEA — Vietnam | `vn_corp` and the [court judgments portal](https://congbobanan.toaan.gov.vn/) | Business representative/address leads; public judgments may explicitly state biographical or relationship facts | `vn_corp` uses registry mirrors: check provenance and dates. Published judgments may anonymise names and identifying fields; do not reconstruct protected identities or treat allegations as findings. |
| SEA — Philippines | [SEC](https://www.sec.gov.ph/) public corporate disclosures and [PhilGEPS](https://www.philgeps.gov.ph/) procurement notices | Officers/business addresses where disclosed; supplier representatives and dated business location | Neither is an open personal civil registry. Public access, fees and document availability differ; procurement contacts do not establish private household or kinship. |

## Organisation-to-person discovery queries

`dork_builder` emits the following families for a domain or company name. It never runs
queries, fetches result pages or treats a result as evidence. Severity is potential
exposure if a hit exists, not confidence. Public staffing/hiring/profile queries are LOW;
existing document-leak families retain their separate severity scale.

| Family | What it reveals | Reading constraint |
|---|---|---|
| `staff_emails` | Offsite `"@example.com" -site:example.com`, PDF/XLSX email mentions, and LinkedIn profile mentions can reveal public staff names/contact details | Domain templates require a domain; company names get LinkedIn mentions without inventing an email domain. Verify current employment and mailbox attribution independently. |
| `jobs` | LinkedIn Jobs, Indeed, Glassdoor, JobStreet, OnlineJobs.ph, Kalibrr, JobsDB, VietnamWorks, TopCV, Infostud, Naukri, StepStone and Seek; generic careers/hiring mentions | Hiring geography and internal tools in job specs are useful contextual leads. Check posting date, recruiter/agency reposts and whether the employer actually authored the vacancy. |
| `freelancer_profiles` | Upwork, Fiverr, Freelancer, OnlineJobs and tutor/teacher marketplaces (Preply, italki, Superprof) | Self-declared client work, staff names and teaching locations are claims, not verified employment. |
| `company_socials` | Facebook, Instagram, TikTok, YouTube and public Telegram mentions | Company mentions, claimed official accounts and staff tags do not prove account control or identity. |

Example: `python3 scripts/osint/dork_builder.py 'Company A Ltd' --pretty`.
For a domain, `python3 scripts/osint/dork_builder.py example.com --pretty` adds domain-only
staff-email templates. Open any emitted query manually only when lawful and relevant.

Username numeric suffixes are still weaker: `username_enum --offline` emits `rung: "hint"`
interpretations with caveats. A number could be a jersey number, graduation year,
account-creation year or lucky number. Never import a suffix interpretation as a DOB.

## Legal and ethical handling

- Establish a lawful basis, permitted purpose and collection scope before using personal
  records. GDPR/UK GDPR and local civil-record, electoral and court-publication rules can
  restrict reuse even when a page is public. Public availability is not consent.
- Apply data minimisation, accuracy checks, retention limits, access control and an appropriate
  sharing audience. Keep source material in the case store, never in tracked code or examples.
- No pretexting, impersonation, restricted-register access, private-account bypass or requests
  for another person's credentials. Analyst-created research accounts do not confer extra
  entitlement to restricted records.
- Do not expand into minors' identities, schools, locations or DOBs. Exclude unnecessary
  family details and exact residential addresses from dissemination.
- Preserve the distinction between a record, a person's own statement and a third-party
  claim. Cite the original public URL directly and distinguish independent corroboration
  from mirrored/repeated content. Mark uncertainty; absence and stale records are not verdicts.

## References

The source links in the region table are the public entry points, not evidence that a
particular person's record is available. For handling principles see the
[GDPR text](https://eur-lex.europa.eu/eli/reg/2016/679/oj) and
[ICO data minimisation guidance](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/data-protection-principles/a-guide-to-the-data-protection-principles/data-minimisation/).
See also [relative discovery](fx-social-topology.md#relative-discovery).
