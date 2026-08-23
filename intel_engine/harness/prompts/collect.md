You have ONLY the provided tools — no shell or filesystem. Ignore any shell commands in the instructions; call the tools directly. (Do not rely on a list of tool names here: the collect server's toolset grows, and an enumeration in this prompt goes stale silently — read the tools you were actually given.)

{{scope}}
Case `{{case}}`. Prior knowledge — do NOT re-collect seeds already collected/attributed (pivot_extract returns cached data for those instantly); spend live collection only on NEW seeds:
{{prior}}

GOAL: this collection exists to UNMASK THE OPERATOR behind the infrastructure — the artifacts are the means, not the product. Infrastructure-scoped artifacts (favicon, TLS/JARM, ASN, kit path, DOM skeleton) only EXPAND the estate; what the case needs is IDENTITY-BEARING ones: registrant name/email/phone/address (current AND historical, then reverse them), owner-account tokens (GA4/GTM, GSC/Bing verification, ahrefs, ads.txt pub-), the paying advertiser id + the legal entity funding it, document/EXIF/XMP author metadata, source-map dev_username/dev_path/build_env, contact rails (Telegram/Zalo/WhatsApp/phone/support mailbox), wallets and payee accounts, leak/stealer-log hits. When a pivot yields new hosts, mine THOSE for identity-bearing artifacts too — expansion is more surface to read, not the finish line. Report which identity-bearing artifacts you got and which you did not.

For EACH seed: call pivot_extract, then kb_ingest the case.
EMPTY-RESULT RULE: if pivot_extract returns zero/near-zero pivots or a parked / empty-favicon / NXDOMAIN page (WHOIS+FOFA+urlscan all cold), you MUST call fallback_probe(seed) before moving on — never end a seed on a silent 'nothing found'. Report its VERDICT (PIVOTABLE with the surviving leads, or NO-PIVOT-YET with next steps) so the analyst always gets a verdict, not silence.
{{hostile_note}}Seeds:
{{seed_lines}}
