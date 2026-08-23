# Workflow: Search the leak corpus → judge whose machine it is

Encodes IntelAnalysis SKILL.md §1.7. Run it on any case where you have a **domain** or an
**operator email** — which is every case. It answers a question no live-internet engine can:
*which machines held credentials for this infrastructure, and was one of them the operator's?*

Run from the project root. Placeholders: `<case>` = the case folder under `cases/`,
`<seed>` = the case apex, `<operator-email>` = a registrant / contact address you extracted.

## Why this order (do not invert it)

IntelX returns a **bounded page**. On a long-exposed selector, recycled public-breach rows fill it
and the one infostealer record never comes back at all — a truncation you cannot recover by sorting
afterwards. So the logs are queried in their **own pass, first**. Everything below assumes that.

| Search | Costs | Buys |
|---|---|---|
| `--logs-only` on the seed apex | 1 unit | the machines that held credentials for the site |
| default (logs pass + general) | 2 units | the above, plus pastes / darknet / historical WHOIS |
| `--no-logs-first` | 1 unit | a general search whose page may be all combolist |
| `phonebook <domain>` | 5 units, PAID | every email / subdomain / URL under the apex |

## Steps

1. **Check the budget and the entitlement before you spend.** Absence of records is meaningless if
   nothing ran.

   ```bash
   python3 WebPivot/tools/wp_intelx.py budget      # OFFLINE — no key, no spend
   python3 WebPivot/tools/wp_intelx.py caps        # what this key is entitled to
   ```

   No key? The layer still runs at ~50% — it classifies each selector and emits the `intelx.io`
   URL to run by hand. **Say so** before reporting anything as "not in any leak".

2. **Search the SEED DOMAIN first, logs-scoped.** This is the highest-yield single call on a web
   case, because a stealer-log record is indexed by the URL the malware captured.

   ```bash
   python3 WebPivot/tools/wp_intelx.py search <seed> --logs-only
   ```

   Confirm `logs_pass: true` in the output. Without it, a zero result is a budget or entitlement
   fact, not a finding.

3. **Then the operator's email**, full two-pass — the email is the selector that carries identity
   across corpora, so the general pass (pastes, darknet, historical WHOIS) earns its unit here.

   ```bash
   python3 WebPivot/tools/wp_intelx.py search <operator-email>
   ```

4. **Then the rest, in priority order** — discovered sibling domains, support phone, payout wallet.
   Inside a collection this is automatic and budgeted:

   ```bash
   python3 WebPivot/tools/pivot_extract.py https://<seed> --intelx --case <case>
   ```

   `search_plan.selector_priority` spends the allowance domain → email → URL → phone → wallet, with
   the seed host ahead of any sibling.

5. **Open the `read_these` items ONE AT A TIME.** Never judge the corpus — judge the item. For each,
   pull what the entitlement allows and ask **whose machine is this?**

   ```bash
   python3 WebPivot/tools/wp_intelx.py selectors <systemid>   # selectors inside one item
   ```

   | Signal on the host | Reads as |
   |---|---|
   | credentials **for** the scam front-end, alongside ordinary consumer accounts; geography matches the target market | **victim** → §1.6 access-vector layer |
   | the **admin/panel** URL for the campaign | operator-side, but alone it is weak — a victim can reach a panel too |
   | the **registrar / hosting / DNS** account the case domains were bought through | operator |
   | the **CMS / FTP / SFTP** entries for the case hosts | operator (builder-side residue) |
   | a bulk-mail or SMS console, the exchange or payment account | operator |
   | a *second, unrelated* scam's panel on the same host | operator (portfolio) |

   **Two or three back-office rows on one host is the finding.** One panel URL is not.

6. **Harvest what the item legitimately gives you, and re-collect.** Non-public URLs (`/admin`,
   staging hosts, a CMS path) are **collection targets** — feed them back through `pivot_extract`.
   New emails and subdomains from `phonebook` are the same: leads, not conclusions.

7. **Corroborate before it attributes anything.** A single log item is strong but it is one source.
   Tie it to an independent artifact class — registrant, TLS, tracker, hosting window — before the
   assessment says *operator*. See §2 (same-kit vs same-operator) and §3 (confidence).

8. **Write it up with the negatives stated.** Record which selectors got a logs pass and which did
   not (`logs_coverage` in the run's `intelx` block). "No stealer-log sighting for the seed apex and
   the registrant address, both queried on <date>" is a finding. "Nothing in IntelX" — from a
   keyless or budget-capped run — is not.

## Handling (non-negotiable)

These are **real victim credentials**. Cite the item's metadata only — systemid, bucket, date, and
the host or URL that matched. **Never** paste a password, cookie, token or session artifact into a
case file, an assessment, a ticket or a chat. If the *existence* of a credential is the finding,
state that it exists and where it was seen; that is the entire evidentiary content. Victim
identities go to the affected provider or to law enforcement, not into the operator assessment.

## Rejections to write down explicitly

- **Corpus co-membership is not an operator link.** Two selectors in the log corpus share a
  population of millions of infected machines. `clustering_policy` fails closed on this by design.
- **A breach-dump hit is a date.** Skim it, take the date, move on. It is not exposure of anything
  the address didn't already tell you.
- **A victim's machine is not the operator's.** Holding a credential *for* the scam site is the
  common case and it is a victim artifact. Require the **back office**, not the front end.
