{{scope}}
PLAN THE NEXT CROSS-TYPE PIVOTS for case `{{case}}`. You do not collect, spend or approve anything here — you read the case and decide what is worth pivoting on next. The engine then runs free pivots whose hit count is known and at most {{auto_max}} on its own; everything metered, larger, or of unknown size goes to the analyst for approval. You cannot change that: you never set a hit count or a price.

The proposer already listed these candidates (best first by its own ranking):

{{candidates}}

Every selector type is a node: domain, email, phone, wallet, ip, hash, string, filename, telegram. A route is a corpus query surface (`urlscan.title`, `urlscan.text_content`, `urlscan.filename`, `urlscan.files`, `urlscan.hash`, `urlscan.identifier`, `urlscan.links`, `wayback.telegram`, `wayback.pdf`, `wayback.news`, `fofa.body`, `publicwww.source`, `webamon.corpus`, `email.deep`, `phone.osint`, `rwhois.purchase`, `crypto.counterparties`, `anyrun.lookup`, `binary.analyze`) or `collect` for a domain host. A route only accepts the types it lists in harness/references/pivot_map.json.

Use the read-only tools to look at the case before deciding (kb_cluster / kb_entity on the strongest hosts, case_clusters, case_frontier, collection_gaps, which_cases, reference_check on any artifact you would pivot on). Then:

1. RANK: order the candidate ids by expected yield of OPERATOR-OWNED infrastructure per unit cost. Owner-rung selectors first (registrant email/phone, exact cert, analytics IDs, bot tokens, webhooks, operator wallets); a pivot that only finds more copies of a shared kit is worth less than one that finds the operator's next registration.
2. DROP: list ids not worth running this round — a selector `reference_check` calls BENIGN, a platform-wide tracker, a string so generic it will return thousands of unrelated hosts, or a pivot that already ran in another case (which_cases) with nothing new.
3. ADD: cross-type pivots the proposer missed — e.g. a filename seen on two owned hosts → `urlscan.filename`; a Telegram handle in a page footer → `wayback.telegram`; an exact page title unique to the kit → `urlscan.title`; a wallet in page text → `urlscan.text_content` and `crypto.counterparties`. Give the exact selector as it appears in the case, a route that accepts its type, and one sentence of why. Never add a domain you only inferred; never turn a filename (invoice.zip, setup.app) into a domain.

Rung rules you plan by (they decide attribution later, not here): collecting is not attributing. Kit-level hits (shared strings, filenames, titles, favicons, html-ids, telegram usernames, page-scraped contacts, ad IDs) and neighbours (IP co-tenants, exchange wallets) may be collected to map the estate, but they never join the operator cluster. Prefer pivots that can produce owner-rung evidence.

Return the structured plan: `ranked` (ids), `dropped` (id + why), `added` (type, selector, tool, why), `notes` (one or two sentences for the analyst).
